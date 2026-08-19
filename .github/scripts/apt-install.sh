#!/usr/bin/env bash
# 统一的 apt 安装入口，解决 CI 偶发卡死在 apt 步骤上的问题。
#
# 背景：GitHub runner 上 apt 有两个"无限等"的坑
#   1) 网络：apt 默认没有连接超时，Azure 镜像抽风时会一直挂在 "0% [Connecting to ...]"
#   2) 锁：dpkg 锁被后台的 unattended-upgrades / apt-daily 占用时，apt 默认无限等待
# 本脚本给两者都加上上限，并做 3 次重试 + 换源兜底。
#
# 用法: bash .github/scripts/apt-install.sh gcc-mingw-w64-x86-64 build-essential
set -uo pipefail

if [ "$#" -eq 0 ]; then
  echo "[apt] 没有传入包名，跳过"
  exit 0
fi

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1

APT_OPTS=(
  -o Acquire::Retries=3
  -o Acquire::http::Timeout=20
  -o Acquire::https::Timeout=20
  -o Acquire::ForceIPv4=true      # 规避 runner 上 IPv6 连接挂死
  -o DPkg::Lock::Timeout=120      # 锁最多等 2 分钟，而不是永远
  -o Dpkg::Use-Pty=0
)

# ---- 1. runner 镜像自带的包直接跳过，多数情况下整步变成 no-op ----
MISSING=()
for p in "$@"; do
  if dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "ok installed"; then
    echo "[apt] 已安装，跳过: $p"
  else
    MISSING+=("$p")
  fi
done
if [ "${#MISSING[@]}" -eq 0 ]; then
  echo "[apt] 依赖全部就绪，无需执行 apt"
  exit 0
fi
echo "[apt] 待安装: ${MISSING[*]}"

# ---- 2. 停掉后台自动更新，避免它抢 dpkg 锁 ----
sudo systemctl stop unattended-upgrades.service apt-daily.service apt-daily-upgrade.service >/dev/null 2>&1 || true
sudo systemctl disable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true

run_apt() { # run_apt <超时秒数> <apt-get 参数...>
  local secs="$1"; shift
  sudo timeout -k 10 "$secs" apt-get "${APT_OPTS[@]}" "$@"
}

for attempt in 1 2 3; do
  echo "[apt] 第 ${attempt}/3 次尝试"
  if run_apt 240 update && run_apt 420 install -y "${MISSING[@]}"; then
    echo "[apt] 安装成功: ${MISSING[*]}"
    exit 0
  fi
  echo "[apt] 第 ${attempt} 次失败或超时"
  # 上一次可能被 timeout 打断在 dpkg 中途，先修复状态
  sudo timeout -k 10 120 dpkg --configure -a >/dev/null 2>&1 || true
  # 第 2 次起换官方主源，规避 Azure 镜像抽风
  if [ "$attempt" -eq 2 ]; then
    echo "[apt] 切换到 archive.ubuntu.com 主源后重试"
    sudo sed -i 's|https\?://azure.archive.ubuntu.com/ubuntu|http://archive.ubuntu.com/ubuntu|g' \
      /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources >/dev/null 2>&1 || true
  fi
  sleep 5
done

echo "[apt] 3 次尝试仍未成功: ${MISSING[*]}" >&2
exit 1
