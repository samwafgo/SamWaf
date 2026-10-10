#!/usr/bin/env bash
# 拉取管理端前端 dist 并写版本戳 public/web_frontend.txt。
# 版本来源由 public/web_frontend.conf 控制：version=latest（默认）取最新 Release，
# version=v1.3.315 钉死特定版本；sha256= 非空时校验压缩包。
# 只改当前工作区，不产生任何提交。用法：bash .github/scripts/fetch_web_dist.sh
set -euo pipefail

cd "$(dirname "$0")/../.."

CONF="public/web_frontend.conf"
STAMP="public/web_frontend.txt"

read_conf() {
  if [[ -f "$CONF" ]]; then
    sed -n "s/^$1[[:space:]]*=[[:space:]]*//p" "$CONF" | tr -d '\r' | head -n1
  fi
}

repo=$(read_conf repo); repo=${repo:-samwafgo/SamWafWeb}
version=$(read_conf version); version=${version:-latest}
sha256=$(read_conf sha256)

BASE="https://github.com/${repo}/releases"
if [[ "$version" == "latest" ]]; then
  # 只取第一跳重定向（releases/latest → releases/download/<tag>）：
  # 跟到底会落到带签名的 release-assets URL，里面已不含 tag（不调 GitHub API，避开限流）
  resolved=$(curl -sI -o /dev/null -w '%{redirect_url}' --retry 3 --retry-all-errors --connect-timeout 15 --max-time 60 "${BASE}/latest/download/dist.tar.gz")
  tag=$(printf '%s' "$resolved" | sed -n 's#.*/download/\([^/]*\)/.*#\1#p')
  if [[ -z "$tag" ]]; then
    echo "ERROR: 无法从重定向解析前端版本：$resolved" >&2
    exit 1
  fi
  url="${BASE}/download/${tag}/dist.tar.gz"
else
  # 钉版：tag 统一带 v 前缀；先探测存在性，404 给清晰报错
  [[ "$version" == v* ]] || version="v${version}"
  tag="$version"
  url="${BASE}/download/${tag}/dist.tar.gz"
  code=$(curl -sIL -o /dev/null -w '%{http_code}' --retry 3 --retry-all-errors --connect-timeout 15 --max-time 60 "$url" || echo 000)
  if [[ "$code" != "200" ]]; then
    echo "ERROR: 前端版本 ${tag} 不存在或不可访问（HTTP ${code}）：$url" >&2
    exit 1
  fi
fi

echo "==> SamWafWeb 前端：${repo} @ ${tag}"
curl -fSL --retry 3 --retry-all-errors --connect-timeout 15 --max-time 300 "$url" -o dist.tar.gz

if [[ -n "$sha256" ]]; then
  actual=$( (sha256sum dist.tar.gz 2>/dev/null || shasum -a 256 dist.tar.gz) | awk '{print $1}' )
  if [[ "$actual" != "$sha256" ]]; then
    echo "ERROR: SHA256 校验失败（期望 ${sha256}，实际 ${actual}）" >&2
    exit 1
  fi
fi

tar -zxf dist.tar.gz
rm -f dist.tar.gz
if [[ ! -d dist ]]; then
  echo "ERROR: 压缩包内没有顶层 dist/ 目录，前端产物布局可能变了" >&2
  exit 1
fi
rm -rf public/dist
mv -f dist public
touch public/dist/.gitkeep

{
  echo "repo=${repo}"
  echo "version=${tag}"
  echo "url=${url}"
  echo "fetched=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$STAMP"
echo "==> 版本戳已写入 ${STAMP}：version=${tag}"
