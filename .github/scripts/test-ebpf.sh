#!/bin/sh
# 真正的网络测试只在独立 netns/mountns 执行；临时 PostgreSQL 仅监听 Unix socket 并使用 peer。
set -eu
task_harness_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
if [ "${1:-}" = inside ]; then
    task_test_root=$2
    task_test_mode=$3
    task_bin_root="$task_test_root/$task_test_mode"
    cd "$task_bin_root"
    mount --make-rprivate /
    mount -t bpf bpf /sys/fs/bpf
    ip link set lo up
    # AF_PACKET 用本机来源模拟外部 ingress；只在隔离命名空间放开相应的来源路由检查。
    sysctl -q -w net.ipv4.conf.lo.accept_local=1 net.ipv4.conf.lo.route_localnet=1 >/dev/null
    ip -6 addr add fd00:57::2/128 dev lo nodad
    export SAMWAF_TEST_EBPF=isolated-netns
    if [ "$task_test_mode" = limited ]; then
        chown 65534:65534 /sys/fs/bpf
        python3 "$task_test_root/run-unprivileged.py" "$task_bin_root/firewall.test" -test.run '^TestEBPFKernelDataplane$' -test.v
        export SAMWAF_TEST_PG_CACHE_DSN="host=$task_test_root/socket port=$SAMWAF_EBPF_TEST_PORT dbname=samwaf_ebpf_limited user=nobody sslmode=disable"
        exec python3 "$task_test_root/run-unprivileged.py" "$task_bin_root/service.test" -test.run '^TestSystemBanEBPFPostgresLifecycle$' -test.v
    fi
    "$task_bin_root/firewall.test" -test.run '^TestEBPFKernelDataplane$' -test.v
    export SAMWAF_TEST_PG_CACHE_DSN="host=$task_test_root/socket port=$SAMWAF_EBPF_TEST_PORT dbname=samwaf_ebpf_root user=root sslmode=disable"
    exec "$task_bin_root/service.test" -test.run '^TestSystemBanEBPFPostgresLifecycle$' -test.v
fi

[ "$(id -u)" = 0 ] || { echo 'Run this isolated test harness with sudo.' >&2; exit 1; }
[ -n "${FIREWALL_TEST_BIN:-}" ] && [ -n "${SERVICE_TEST_BIN:-}" ] || exit 1
task_test_root=$(mktemp -d /tmp/samwaf-ebpf-test.XXXXXX)
task_pg_started=0
if command -v initdb >/dev/null 2>&1; then task_pg_bin=$(dirname "$(command -v initdb)"); else task_pg_bin=$(find /usr/lib/postgresql -path '*/bin/initdb' -print | sort -Vr | head -n1); task_pg_bin=$(dirname "$task_pg_bin"); fi
cleanup() {
    task_test_result=$?
    trap - EXIT INT TERM
    if [ "$task_pg_started" = 1 ]; then su postgres -s /bin/sh -c "'$task_pg_bin/pg_ctl' -D '$task_test_root/pgdata' -m fast -w stop" >/dev/null 2>&1 || task_test_result=1; fi
    # 只删除本脚本 mktemp 生成的专用目录，不触碰 PostgreSQL 默认集群或用户工作区。
    case "$task_test_root" in /tmp/samwaf-ebpf-test.*) rm -rf "$task_test_root" ;; *) exit 1 ;; esac
    exit "$task_test_result"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
chmod 0755 "$task_test_root"
cp "$task_harness_dir/run-ebpf-unprivileged.py" "$task_test_root/run-unprivileged.py"
chmod 0644 "$task_test_root/run-unprivileged.py"
for task_test_mode in root limited; do
    mkdir "$task_test_root/$task_test_mode"
    cp "$FIREWALL_TEST_BIN" "$task_test_root/$task_test_mode/firewall.test"
    cp "$SERVICE_TEST_BIN" "$task_test_root/$task_test_mode/service.test"
    chmod 0755 "$task_test_root/$task_test_mode" "$task_test_root/$task_test_mode/firewall.test" "$task_test_root/$task_test_mode/service.test"
done
chown -R 65534:65534 "$task_test_root/limited"
mkdir "$task_test_root/pgdata" "$task_test_root/socket"
chown postgres:postgres "$task_test_root/pgdata" "$task_test_root/socket"
chmod 0777 "$task_test_root/socket"
su postgres -s /bin/sh -c "cd '$task_test_root' && '$task_pg_bin/initdb' -D '$task_test_root/pgdata' --auth-local=peer --auth-host=reject --no-instructions" >/dev/null
SAMWAF_EBPF_TEST_PORT=$((42000 + $$ % 5000))
export SAMWAF_EBPF_TEST_PORT
su postgres -s /bin/sh -c "'$task_pg_bin/pg_ctl' -D '$task_test_root/pgdata' -l '$task_test_root/pgdata/server.log' -o '-h \"\" -p $SAMWAF_EBPF_TEST_PORT -k $task_test_root/socket' -w start" >/dev/null
task_pg_started=1
cat > "$task_test_root/setup.sql" <<'SQL'
CREATE ROLE root LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE nobody LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE DATABASE samwaf_ebpf_root OWNER root;
CREATE DATABASE samwaf_ebpf_limited OWNER nobody;
SQL
chmod 0644 "$task_test_root/setup.sql"
su postgres -s /bin/sh -c "'$task_pg_bin/psql' -h '$task_test_root/socket' -p $SAMWAF_EBPF_TEST_PORT -U postgres -d postgres -v ON_ERROR_STOP=1 -f '$task_test_root/setup.sql'" >/dev/null
# root 覆盖原始分片报文生成；受限进程只持有实际运行所需的两个能力和 NoNewPrivileges。
unshare -n -m -- sh "$0" inside "$task_test_root" root
unshare -n -m -- sh "$0" inside "$task_test_root" limited
