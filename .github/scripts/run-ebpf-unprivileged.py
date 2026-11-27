#!/usr/bin/env python3
"""用实际服务权限运行隔离测试：清空补充组，仅保留 BPF/NET_ADMIN 并启用 NoNewPrivileges。"""
import os
import sys

# 直接使用内核 setgroups，避免部分 musl capsh 的组名解析依赖 sysconf 返回固定缓冲区大小。
os.setgroups([])
arguments = [
    "capsh", "--keep=1", "--gid=65534", "--uid=65534",
    "--inh=cap_bpf,cap_net_admin", "--addamb=cap_bpf,cap_net_admin",
    "--no-new-privs", "--shell=/bin/sh", "--", "-c", 'exec "$@"',
    "samwaf-ebpf-tests", *sys.argv[1:],
]
os.execvp(arguments[0], arguments)
