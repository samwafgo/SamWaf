# Linux eBPF 系统封禁与共享安全状态

本改造接续 `c8d96c7` 的 L1/L2、PostgreSQL 工作。Linux 的系统封禁由内嵌 eBPF 执行，手动应用层黑名单、CC、规则封禁保持各自的作用域。

## 数据路径与边界

- 系统封禁程序类型为 `BPF_PROG_TYPE_NETFILTER`，分别挂 IPv4、IPv6 的 `LOCAL_IN`，优先级 -75。它承接原本 INPUT 的本机入站范围；不更换 XDP/TC 程序，不过滤路由转发链。
- 普通手工系统封禁覆盖该来源的本机入站协议。主机登录防护可按现有配置只作用于选定 TCP 目标端口。HTTP 代理头不会改变内核看到的网络来源。
- 手动 WAF 黑名单仍从主库编译为内存索引，支持 IP、CIDR、通配符、区间与组引用；CC 和规则临时封禁通过 PostgreSQL KV/TTL 在 HTTP 链路判定。
- Windows/macOS 保留其原生防火墙后端。Linux 运行时不调用 iptables、iptables-save、ip6tables 或 ipset；旧集合方法名仅为跨平台调用兼容。

eBPF 支持单 IPv4/IPv6 和 CIDR，禁止 `/0`。每个来源有独立 LPM 表，同一 IP 可以同时由手工、主机防护和多个情报订阅封禁。撤销某个来源不会覆盖其他来源。完整重建先写新内层表，再一次交换外层指针；增删操作只重建本来源，不重建其他来源的内核表。

IPv4/IPv6 重组通过 Netfilter link 的 `BPF_F_NETFILTER_IP_DEFRAG` 启用。程序使用 dynptr 读取非线性 skb，并有界处理 IPv6 扩展头。难以完整解析的分片/扩展头只对已经受端口封禁的来源执行保守拒绝；普通 UDP/ICMP 不受 TCP 端口规则影响。

最多 64 个来源表；每表最多 262,144 个内核键，全部来源合计最多 1,048,576 个键。端口来源按“端口数＋一个异常报文来源标记”计入键预算，最多 64 个 TCP 端口。超限返回错误，保留有效表，不通过 LRU 丢弃封禁。数据包仅遍历启用来源位，再查前缀表，不遍历名单中的每个 IP。

同一来源重叠前缀在控制阶段合并有效期限：子前缀继承覆盖它的祖先期限上界。因此过期的精确 IP 不会遮住仍有效的网段，逐包只需一次 LPM 查询。

## 持久化、恢复和控制一致性

`SAMWAF_BPF_STATE_DIR` 保存实例账本，目录 0700、文件 0600；`SAMWAF_BPF_PIN_ROOT` 保存独立 bpffs 对象。实例子目录包含状态路径和网络命名空间的摘要，多个 Worker 可重开同一组对象。程序按本实例 pin 路径重开，不需要按全局 ID 枚举其他程序。

控制变更使用进程锁及跨进程 flock：完整写入并同步 pending 意图，构建/交换来源表，再原子提交账本。控制失败返回错误；待完成意图在下一次操作重放。账本读错或丢失时，不能把内核有效策略覆盖成空表。

内核期限使用 BOOTTIME 纳秒，包含挂起时间；同一启动周期内重建其他条目保留原期限。数据库及文件账本保存绝对到期，用于重启恢复。数据面到期立即放行，空间回收和 SQL 清理不决定有效性。墙上时钟调整后的数据库核对仍以持久账本为准。

pin 让程序在 Worker 退出后继续存在，停止进程本身不会清除有效系统封禁。机器重启后，手工记录在开始监听前恢复；主机登录防护和情报来源由各自启动流程恢复。

手工系统封禁变更在数据库事务锁内修改源账本，内核发布确认后再提交。数据库与内核不是同一事务资源；中断或提交失败会返回错误，立即尝试读取已提交真相恢复，并由独立协程在故障后重试、至少每 30 秒核对一次。后台查询失败保留现有策略，不能以空结果撤销有效封禁。

原 Linux 规则没有统一的来源注释，不能通过删除整机 INPUT 或按相同 CIDR 批量猜测清理旧规则。迁移应先备份、确认旧 SamWAF 记录及其他产品的规则归属，验证 eBPF 后只撤销已经确认属于 SamWAF 的旧规则。保留 Fail2ban、云防火墙及其他服务的管理边界。

## 应用层缺口修复

原普通受保护请求串行检查全局 CC、本站 CC、旧 CC、规则封禁四个键。现在使用一次参数化查询，按 namespace、`ANY(keys)` 与数据库时钟读取整组状态。未缓存负结果，新增和撤销在数据库提交后可见。站点正文 L1/L2 命中仍先经过安全检查。

封禁查询、封禁原子写入或共享计数出错时，受保护且未获白名单豁免的业务请求返回 HTTP 503；不将其记为攻击或访客失败事件。控制台保持既有加密协议：HTTP 200、业务故障码 `BACKEND_UNAVAILABLE=-6`，避免破坏前端登录态处理。

CC/规则封禁使用原子首次写入，跨 Worker 同时触发不刷新已经确定的 TTL。解封返回后端错误；CC 解封同时清除该 IP 的共享 CC 额度，保留其他访客和独立规则封禁。

手工 WAF 黑名单写库错误直接返回，重载查询失败不投递空名单。PostgreSQL 语句级触发器在同一事务内递增名单版本。每 Worker 每秒检查一个版本号，变化后以一致只读快照重建并一次发布全部站点。它覆盖 API、批处理和 SQL 改动，修复跨 Worker 未收到本地消息，以及规则从 A 移到 B 的不同步。排队旧消息只触发重新读取当前数据库，不直接发布旧内容。

## 共享计数

新增 `samwaf_security` 应用 schema，由普通数据库 owner 安装，独立于已有 trusted KV 扩展对象的所有权。已有 `samwaf_kv v1` 无需以超级用户修改定义；角色需要数据库 schema 创建权及自身业务表的触发器管理权，不需要超级用户或 CREATEDB。

- CC 多规则使用与原实现相同的十桶近似窗口，窗口边界存在桶宽误差。
- 旧 CC 配置的平均速率采用共享令牌桶，滑动窗口采用共享时间戳窗口。
- 一次 SQL 调用完成原子计数、判定及新维度配额。既有热键只竞争自身，新维度分配按 namespace/规则配额锁定。
- 默认共享总键数 200,000、单规则 50,000；窗口 1..604800 秒，旧限流单窗口上限 1,000,000。有效窗口不按 LRU 淘汰。降级后仍不能计数时返回防护不可用，不以零计数放行。
- 维度以 SHA256 保存，避免把 Cookie/Token 原文存入计数表。窗口配置按版本隔离，滚动升级不相互重置。
- HTTP 失败与 SSH/RDP 失败使用不同键空间，通过数据库事务级咨询锁串行化同键 JSON 读改写。事件、计数和阈值戳在不同 Worker/连接池间不会覆盖。

共享计数增加配置了 CC 的请求的数据库写入成本。请求安全状态合并查询节省的往返不能作为 Redis 等价吞吐承诺。进程诊断报告共享调用/错误/拒绝统计，不把本地零键数冒充数据库全局基数。

## 原生服务部署示例

系统后端需要 Linux 6.6+、可读内核 BTF、IPv4/IPv6 Netfilter BPF 与重组支持。主运行进程使用 `CAP_BPF`、`CAP_NET_ADMIN`；低端口监听另需 `CAP_NET_BIND_SERVICE`。运行时无 clang、libbpf、bpftool 依赖，两个字节序对象随应用内嵌。

下面示例使用现有 `samwaf` 账户和 `/opt/samwaf`；先确认备份可恢复，保留原二进制、配置、四库一致快照、密钥、eBPF 账本及原防火墙导出。

```sh
install -d -m 0755 /usr/local/libexec /etc/samwaf /etc/systemd/system/samwaf.service.d
install -m 0755 deploy/samwaf-ebpf-prepare.sh /usr/local/libexec/samwaf-ebpf-prepare
install -m 0644 deploy/samwaf-ebpf-prepare.service /etc/systemd/system/
install -m 0644 deploy/samwaf-ebpf.conf /etc/systemd/system/samwaf.service.d/ebpf.conf
install -m 0600 deploy/ebpf.env.example /etc/samwaf/ebpf.env
systemctl daemon-reload
systemctl start samwaf-ebpf-prepare.service
```

确认独立 `/run/samwaf-bpf` 已挂载且归服务账户所有，替换已验证的二进制后重启 SamWAF。准备服务只负责本应用专用挂载；运行进程保留 NoNewPrivileges，不获得 CAP_SYS_ADMIN。现有严格文件系统保护需放行该专用路径。环境文件不含 PostgreSQL 口令。

Docker 系统层封禁还需匹配的宿主内核、BPF/NET_ADMIN 能力、独立 bpffs 可见性与正确网络命名空间。普通端口映射容器的系统封禁作用于其容器网络，不等于整机 SSH/RDP 防护。Docker 镜像/Compose 的实际验收应单独执行。

## 维护与回退

维护命令在数据库、密钥和管理端初始化前执行。先载入该实例的 eBPF 路径环境：

```sh
set -a
. /etc/samwaf/ebpf.env
set +a
/opt/samwaf/SamWafLinuxArm64 ebpf status --output json
```

状态读取不会初始化内核后端。`published_sources` 表示启用位图中的来源表数，内核另按条目期限判断；丢包计数是当前内核对象的累计值。

需要回退程序时先停止 SamWAF，使用仍保留的新二进制摘除本实例链接，再恢复经过验证的旧二进制和配置：

```sh
systemctl stop samwaf
/opt/samwaf/SamWafLinuxArm64 ebpf detach --force
# 此后按已验证快照恢复旧程序/配置及匹配的旧规则，再启动服务。
```

detach 只处理本实例固定 pin，保留持久账本，不清理其他安全产品的规则。回退到旧内核程序格式或更换 eBPF 对象时，采用同样的受控停服流程；Netfilter link 不支持原地替换程序，不能把无法验证的旧程序当作新程序继续使用。

## 验证入口

- `firewall/ebpf_linux_test.go`：IPv4/IPv6、CIDR 重叠、端口范围、有效策略保留、到期、独立进程重开、状态与 scoped detach。
- `firewall/kernel_packet_linux_test.go`：二层注入的 IPv4/IPv6 分片、IPv6 扩展头、UDP 完整重组与作用域。
- `service/waf_service/system_ban_ebpf_linux_test.go`：真实 PostgreSQL 事务＋实际收包，覆盖新增、启停、地址迁移、SQL/账本故障、独立来源、到期和启动恢复。
- `cache/postgres_security_test.go`、`wafipban/shared_record_test.go`：独立连接池并发计数、故障、回滚、配额及计数键空间隔离。
- `wafenginecore/ip_block_sync_test.go`：两个引擎、事务版本、跨站点迁移、不可变旧快照及失败不清空。
- `.github/scripts/test-ebpf.sh`：root 仅用于挂载、隔离和原始流量生成；另以 UID/GID 65534、BPF/NET_ADMIN 和 NoNewPrivileges 运行控制与服务测试。临时 PostgreSQL 仅监听 Unix socket，peer 认证角色为非超级用户、无 CREATEDB，结束后删除临时集群。

源码对象再生成：安装 clang 与 libbpf 开发头后执行 `sh firewall/bpf/generate.sh`。生成设置了调试路径映射，不把开发机绝对路径嵌入发布对象。

内核 C 程序提供 BSD-2-Clause/GPL-2.0 双许可，随附 BSD 许可文本；Go 应用代码遵循仓库原有许可。
