#!/bin/sh
# 由一次性 root 服务准备本应用独立的 bpffs；SamWAF 运行进程不需要 CAP_SYS_ADMIN。
set -eu
task_bpf_user=${SAMWAF_BPF_USER:-samwaf}
task_bpf_mount=${SAMWAF_BPF_PIN_ROOT:-/run/samwaf-bpf}
task_bpf_state=${SAMWAF_BPF_STATE_DIR:-/opt/samwaf/data/ebpf}
[ "$(id -u)" = 0 ] || { echo 'eBPF filesystem preparation requires root' >&2; exit 1; }
case "$task_bpf_mount" in /run/samwaf-bpf|/run/samwaf-bpf-*) ;; *) echo 'Use a dedicated /run/samwaf-bpf mount' >&2; exit 1 ;; esac
case "$task_bpf_state" in /*) ;; *) echo 'State directory must be absolute' >&2; exit 1 ;; esac
[ "$task_bpf_state" != / ] && [ ! -L "$task_bpf_state" ] && [ ! -L "$task_bpf_mount" ] || exit 1
task_bpf_uid=$(id -u "$task_bpf_user")
task_bpf_gid=$(id -g "$task_bpf_user")
mkdir -p "$task_bpf_mount"
if mountpoint -q "$task_bpf_mount"; then
    [ "$(findmnt -n -o FSTYPE -T "$task_bpf_mount")" = bpf ] || { echo 'Target already belongs to another filesystem' >&2; exit 1; }
else
    # 不把其他服务的已有文件隐藏在新挂载下面。
    [ -z "$(find "$task_bpf_mount" -mindepth 1 -maxdepth 1 -print -quit)" ] || { echo 'Mount directory is not empty' >&2; exit 1; }
    mount -t bpf -o mode=0700,nosuid,nodev,noexec samwaf-bpf "$task_bpf_mount"
fi
# 只修改该专用挂载根和状态叶目录，不改 /sys/fs/bpf 的共享权限或其他程序的 pin。
chown "$task_bpf_uid:$task_bpf_gid" "$task_bpf_mount"
chmod 0700 "$task_bpf_mount"
install -d -m 0700 -o "$task_bpf_uid" -g "$task_bpf_gid" "$task_bpf_state"
printf 'SamWAF dedicated eBPF filesystem is ready.\n'
