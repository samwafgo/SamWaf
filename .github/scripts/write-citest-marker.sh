#!/usr/bin/env bash
# 生成 CI 测试构建标记文件 README-CITEST.txt，并同步写一份到 Actions 运行摘要。
#
# 为什么需要它：CI 构建出来的包，版本号会刻意对齐 GitHub Releases 上的最新版本
# （否则测试者一启动就被"先升正式版、再升测试版"推着连升好几次，根本测不到本次构建的代码）。
# 版本号既然和线上一致，就必须在别处把"这是测试包"讲清楚：包里放这个说明文件，
# 程序内则靠版本名的 citest- 前缀区分。
#
# 用法：
#   OUT_DIR=out VERSION=v1.3.24-beta.4 VERSION_NAME=citest-20260806-run12-abc1234 \
#     bash .github/scripts/write-citest-marker.sh
set -e

OUT_DIR="${OUT_DIR:-.}"
mkdir -p "$OUT_DIR"
MARKER="$OUT_DIR/README-CITEST.txt"

cat > "$MARKER" <<EOF
==================================================
 SamWaf CI 测试构建 (CI TEST BUILD — NOT A RELEASE)
==================================================
本包由 GitHub Actions 工作流 "${GITHUB_WORKFLOW:-unknown}" 自动构建，仅用于单独测试，
请勿用于生产环境。

版本号   : ${VERSION:-unknown}   (与 GitHub Releases 最新版本保持一致)
版本名   : ${VERSION_NAME:-unknown}
提交     : ${GITHUB_SHA:-unknown}
触发     : ${GITHUB_EVENT_NAME:-unknown} / ${GITHUB_REF:-unknown}
Run 链接 : ${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-samwafgo/SamWaf}/actions/runs/${GITHUB_RUN_ID:-0}

说明：
1) 版本号故意对齐线上最新发布版本，是为了让你下载后不会被"先升正式版、再升测试版"
   连续推着升级，从而能真正测到本次构建的代码。
2) 因此界面上看不到升级提示属于预期行为；界面左下角显示的版本名以 citest- 开头，
   即代表这是测试构建。
3) 想回到正式版，请到 https://github.com/samwafgo/SamWaf/releases 手动下载。
EOF

cat "$MARKER"
if [ -n "$GITHUB_STEP_SUMMARY" ]; then
  {
    echo '```text'
    cat "$MARKER"
    echo '```'
  } >> "$GITHUB_STEP_SUMMARY"
fi
