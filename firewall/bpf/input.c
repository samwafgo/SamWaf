// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// SamWAF 的本机入站封禁程序。只挂 LOCAL_IN，保留原 INPUT 的作用域；不拦转发流量。
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_GROUPS 64
#define MAX_RULES 262144
#define NF_ACCEPT 1
#define NF_DROP 0

struct sk_buff;
struct nf_hook_state;
struct bpf_nf_ctx { const struct nf_hook_state *state; struct sk_buff *skb; };
extern int bpf_dynptr_from_skb(struct __sk_buff *skb, __u64 flags,
                             struct bpf_dynptr *ptr) __ksym;

// 前 64 位是地址族与 TCP 目标端口；端口 0 表示该来源的所有入站协议。
struct rule_key {
    __u32 prefix;
    __u32 family;
    __u16 port;
    __u16 reserved;
    __u8 address[16];
};
// 到期时间使用 BOOTTIME，包含挂起时间；0 为永久。prefix 支持过期长前缀回退。
struct rule_value { __u64 expires; __u32 prefix; __u32 reserved; };
struct rule_map {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_RULES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct rule_key);
    __type(value, struct rule_value);
} rule_template SEC(".maps");
// 各封禁来源使用独立内层表。全量替换只交换一个指针，避免读到半张订阅名单。
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, MAX_GROUPS);
    __type(key, __u32);
    __array(values, struct rule_map);
} ban_groups SEC(".maps") = { .values = { [0] = &rule_template } };
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} active_groups SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_count SEC(".maps");

// 控制层已将祖先网段的最长期限合并进子前缀，所以热路径只需一次 LPM 查询。
// 这同时避免过期长前缀遮住有效短前缀，以及逐包回退 128 层的最坏开销。
static __noinline int blocked(void *rules, struct rule_key *key, __u64 now) {
    struct rule_value *value = bpf_map_lookup_elem(rules, key);
    return value && (!value->expires || value->expires > now);
}

// 回调状态放在本次程序栈中，不使用可能被同 CPU 另一个报文覆盖的共享临时 map。
struct lookup_state {
    struct rule_key base;
    __u16 port;
    __u8 opaque;
    __u8 drop;
    __u64 active;
    __u64 now;
};

// bpf_loop 让 6.6/6.12 验证器独立验证有限来源遍历，避免 64 份展开叠加 IPv6 分支爆炸。
static long visit_group(__u32 group, void *context) {
    struct lookup_state *state = context;
    if (group >= MAX_GROUPS || !(state->active & (1ULL << group))) return 0;
    void *rules = bpf_map_lookup_elem(&ban_groups, &group);
    if (!rules) return 0;
    struct rule_key key = state->base;
    if (blocked(rules, &key, state->now)) goto drop;
    if (state->port) {
        key = state->base;
        key.port = state->port;
        if (blocked(rules, &key, state->now)) goto drop;
    }
    if (state->opaque) {
        key = state->base;
        key.family |= 256;
        if (blocked(rules, &key, state->now)) goto drop;
    }
    return 0;
drop:
    state->drop = 1;
    return 1;
}

// 扩展头也使用有限回调，老 LTS 验证器不必枚举 16 层协议分支的所有排列。
struct extension_state {
    struct bpf_dynptr *packet;
    __u32 offset;
    __u8 protocol;
    __u8 opaque;
};

// 返回 1 表示解析完成/失败停止；失败仅标记已受限来源的保守拒绝路径。
static long visit_extension(__u32 index, void *context) {
    struct extension_state *state = context;
    __u8 protocol = state->protocol;
    if (index >= 16 || (protocol != 0 && protocol != 43 && protocol != 60 && protocol != 51 && protocol != 44)) return 1;
    __u8 extension[8];
    if (state->offset > 65535 || bpf_dynptr_read(extension, 8, state->packet, state->offset, 0)) {
        state->protocol = 0; state->opaque = 1; return 1;
    }
    if (protocol == 44 && (extension[2] || (extension[3] & 0xf8))) {
        state->protocol = 0; state->opaque = 1; return 1;
    }
    __u32 length = protocol == 44 ? 8 : protocol == 51 ? (extension[1] + 2) * 4 : (extension[1] + 1) * 8;
    state->protocol = extension[0];
    state->offset += length;
    return 0;
}

// 先解析报文身份，再通过有限回调检查各来源；命中只更新内核计数并丢包。
SEC("netfilter")
int samwaf_input(struct bpf_nf_ctx *ctx) {
    __u32 zero = 0;
    __u64 *mask = bpf_map_lookup_elem(&active_groups, &zero);
    if (!mask || !*mask) return NF_ACCEPT;
    __u64 active = *mask;
    struct bpf_dynptr packet;
    // dynptr 正确读取线性/非线性 skb；不能把 skb->head 当作完整报文直接解引用。
    if (bpf_dynptr_from_skb((struct __sk_buff *)ctx->skb, 0, &packet)) return NF_ACCEPT;
    __u8 header[40] = {};
    if (bpf_dynptr_read(header, 20, &packet, 0, 0)) return NF_ACCEPT;
    struct rule_key base = {};
    __u32 offset;
    __u8 protocol;
    int opaque = 0;
    if ((header[0] >> 4) == 4) {
        base.family = 4;
        base.prefix = 64 + 32;
        __builtin_memcpy(base.address, &header[12], 4);
        offset = (header[0] & 15) * 4;
        if (offset < 20) return NF_ACCEPT;
        protocol = header[9];
        // 挂载时要求内核启用 IPv4/IPv6 重组，端口规则不接受未重组的后续分片。
        if (header[6] & 0x3f || header[7]) { protocol = 0; opaque = 1; }
    } else if ((header[0] >> 4) == 6) {
        if (bpf_dynptr_read(header, 40, &packet, 0, 0)) return NF_ACCEPT;
        base.family = 6;
        base.prefix = 64 + 128;
        __builtin_memcpy(base.address, &header[8], 16);
        struct extension_state extension = { .packet = &packet, .offset = 40, .protocol = header[6] };
        bpf_loop(16, visit_extension, &extension, 0);
        protocol = extension.protocol;
        offset = extension.offset;
        opaque = extension.opaque;
        if (protocol == 0 || protocol == 43 || protocol == 60 || protocol == 51 || protocol == 44) opaque = 1;
    } else return NF_ACCEPT;

    __u16 port = 0;
    if (protocol == 6) {
        __u8 tcp[4];
        if (offset <= 65535 && !bpf_dynptr_read(tcp, 4, &packet, offset, 0))
            __builtin_memcpy(&port, &tcp[2], 2);
        else opaque = 1;
    }
    struct lookup_state lookup = { .base = base, .port = port, .opaque = opaque,
                                   .active = active, .now = bpf_ktime_get_boot_ns() };
    bpf_loop(MAX_GROUPS, visit_group, &lookup, 0);
    if (!lookup.drop) return NF_ACCEPT;
    __u64 *count = bpf_map_lookup_elem(&drop_count, &zero);
    if (count) (*count)++;
    return NF_DROP;
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";
