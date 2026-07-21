#!/bin/bash
# ==============================================================================
# SamWaf 安装 / 更新 / 卸载脚本
#
# 特性：
#   1. 多下载源自动测速择优（官方 update.samwaf.com / GitHub / Gitee）
#   2. 跨源一致性完整性校验（防止下载到被篡改或过期的可执行文件）
#
# 安全校验模型（默认 consensus 跨源一致性）：
#   · 官方来源（update.samwaf.com，算 1 个主机）：
#       - /latest/latest.json      → 该版本发布包(tar.gz)的权威 SHA256（正式版稳定通道）；
#       - /samwaf_update/<plat>.json → 该版本可执行文件的权威 SHA256（App 自升级同端点）。
#   · 跨源佐证：从 GitHub 与 Gitee 拉取 checksums.txt，取同一发布包的 SHA256。
#   · 一致性：官方latest / GitHub / Gitee 三者对同一压缩包给出的 SHA256 必须完全一致，
#     任一不一致即判定源污染并中止；并要求至少两个「相互独立的主机」为发布物背书。
#   · 最终安装的可执行文件：压缩包 SHA256 == 跨源一致值；若拿到官方二进制锚点，
#     解包后的可执行文件 SHA256 还须 == 该锚点。
#   注：update.samwaf.com/latest 现由 sync_release_go 保鲜，提供与 GitHub/Gitee 逐字节
#       相同的版本化压缩包；latest.json 不可用时自动回退到 samwaf_update/<ver>/<plat>.gz。
#   无论从哪个镜像下载，过期或被篡改的文件都会被拒绝并自动切换下一个源。
#
# 环境变量（可选）：
#   SAMWAF_SOURCE=official|github|gitee   强制指定下载源，跳过测速
#   SAMWAF_VERIFY=consensus|anchor        校验强度（默认 consensus；anchor 仅用官方清单）
#   SAMWAF_INSECURE_TLS=1                 关闭 TLS 证书校验（仅限老旧系统，内容仍有哈希校验）
#
# 说明：Atomgit（https://atomgit.com/SamSafe/SamWaf）的发布包下载需要登录鉴权，
#       无法匿名脚本下载，故不参与自动测速，仅作为手动下载链接展示。
# ==============================================================================
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
LANG=en_US.UTF-8

# 定义颜色常量
NC='\033[0m'        # 重置颜色
GREEN='\033[0;32m'  # 成功
RED='\033[0;31m'    # 错误
BLUE='\033[0;34m'   # 信息
YELLOW='\033[0;33m' # 警告

log_info() { echo -e "${BLUE}$*${NC}"; }
log_ok()   { echo -e "${GREEN}$*${NC}"; }
log_warn() { echo -e "${YELLOW}$*${NC}"; }
log_err()  { echo -e "${RED}$*${NC}"; }

# 检查是否为root权限
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}🔐 检测到未使用 root 权限，尝试使用 sudo 重新运行...${NC}"
    exec sudo -E bash "$0" "$@"
    exit 1
fi

# ------------------------------------------------------------------ 常量与全局
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
setup_path="${SCRIPT_DIR}/SamWaf"
ARCH=$(uname -m)

OFFICIAL_BASE="https://update.samwaf.com"
GITHUB_BASE="https://github.com/samwafgo/SamWaf"
GITEE_BASE="https://gitee.com/samwaf/SamWaf"
ATOMGIT_PAGE="https://atomgit.com/SamSafe/SamWaf"

# 运行期变量（由各函数填充）
EXEC_NAME=""          # 可执行文件名 SamWafLinux64 / SamWafLinuxArm64
PLAT_JSON=""          # linux-amd64 / linux-arm64
OS_ARCH=""            # Linux_x86_64 / Linux_arm64（发布包命名用）
VERSION=""            # 例如 v1.3.22
MANIFEST_BIN_SHA=""   # samwaf_update 清单中的可执行文件 SHA256（hex）
L_TAR_SHA=""          # /latest/latest.json 中本平台压缩包 SHA256（hex）
LATEST_JSON_OK=0      # /latest/latest.json 是否可用（官方稳定通道已保鲜）
CK_TAR_SHA=""         # 跨源一致的发布压缩包 SHA256（hex）
CONSENSUS_HOSTS=0     # 提供一致压缩包校验和的来源数量（官方latest/GitHub/Gitee）
GH_CK_OK=0            # GitHub checksums 是否可用
GT_CK_OK=0            # Gitee  checksums 是否可用
VERIFIED_BIN=""       # 校验通过的可执行文件路径
USED_SOURCE=""        # 实际使用的下载源
USED_BIN_SHA=""       # 实际安装的二进制 SHA256

VERIFY_MODE="${SAMWAF_VERIFY:-consensus}"
FORCE_SOURCE="${SAMWAF_SOURCE:-}"
WORKDIR=""

have() { command -v "$1" >/dev/null 2>&1; }

cleanup() { [ -n "$WORKDIR" ] && rm -rf "$WORKDIR" 2>/dev/null; }
trap cleanup EXIT

# 依赖检查
function check_deps() {
    local missing=""
    have tar || missing="$missing tar"
    have gzip || missing="$missing gzip"
    if ! have curl && ! have wget; then missing="$missing curl/wget"; fi
    if ! have sha256sum && ! have shasum && ! have openssl; then missing="$missing sha256sum/openssl"; fi
    if ! have base64; then missing="$missing base64"; fi
    if [ -n "$missing" ]; then
        log_err "❌ 缺少必要依赖:$missing，请先安装后重试"
        exit 1
    fi
}

# 下载：DL <url> <outfile>  （跟随重定向 + 重试；保持 TLS 校验，除非显式关闭）
function DL() {
    local url="$1" out="$2" insecure=""
    [ "$SAMWAF_INSECURE_TLS" = "1" ] && insecure="1"
    if have curl; then
        if [ -n "$insecure" ]; then
            curl -fsSL -k --connect-timeout 10 --max-time 900 --retry 2 -o "$out" "$url"
        else
            curl -fsSL --connect-timeout 10 --max-time 900 --retry 2 -o "$out" "$url"
        fi
    else
        if [ -n "$insecure" ]; then
            wget --no-check-certificate -q --tries=3 --timeout=900 -O "$out" "$url"
        else
            wget -q --tries=3 --timeout=900 -O "$out" "$url"
        fi
    fi
}

# 计算文件 SHA256（hex）
function sha256_of() {
    if have sha256sum; then sha256sum "$1" | awk '{print $1}';
    elif have shasum; then shasum -a 256 "$1" | awk '{print $1}';
    else openssl dgst -sha256 "$1" | awk '{print $NF}'; fi
}

# base64 → hex
function b64_to_hex() {
    if have od; then
        printf '%s' "$1" | base64 -d 2>/dev/null | od -An -v -tx1 | tr -d ' \n'
    elif have xxd; then
        printf '%s' "$1" | base64 -d 2>/dev/null | xxd -p | tr -d '\n'
    else
        printf '%s' "$1" | base64 -d 2>/dev/null | hexdump -v -e '/1 "%02x"'
    fi
}

# 从 checksums.txt 中解析当前平台发布包的哈希（按平台标记匹配，排除 DEBUG）
function ck_hash() {
    grep "SamWaf_${OS_ARCH} " "$1" 2>/dev/null | grep -vi debug | grep -i 'tar.gz' | head -1 | awk '{print $1}'
}

# 从 latest.json 中解析当前平台压缩包的 sha256（文件名含 OS_ARCH 且非 DEBUG）
function l_hash() {
    awk -v tok="$OS_ARCH" '
        /"name"[[:space:]]*:/ {
            if (index($0, tok) && $0 !~ /[Dd][Ee][Bb][Uu][Gg]/) hit=1; else hit=0
        }
        hit && /"sha256"[[:space:]]*:/ {
            line=$0
            sub(/.*"sha256"[[:space:]]*:[[:space:]]*"/, "", line)
            sub(/".*/, "", line)
            print line
            exit
        }
    ' "$1"
}

# 初始化架构相关变量
function init_arch_exec() {
    if [[ "$ARCH" == "x86_64" ]]; then
        EXEC_NAME="SamWafLinux64"; PLAT_JSON="linux-amd64"; OS_ARCH="Linux_x86_64"
    elif [[ "$ARCH" == "aarch64" ]] || [[ "$ARCH" == "arm64" ]]; then
        EXEC_NAME="SamWafLinuxArm64"; PLAT_JSON="linux-arm64"; OS_ARCH="Linux_arm64"
    else
        log_err "❌ 不支持的架构: $ARCH"
        exit 1
    fi
}

# 组装各源的下载 URL
#   official：/latest 清单可用时下载版本化 tar.gz（与 git 逐字节相同）；
#            否则回退到 samwaf_update 的裸二进制 gz。
function src_download_url() {
    case "$1" in
        official)
            if [ "$LATEST_JSON_OK" = "1" ]; then
                echo "${OFFICIAL_BASE}/latest/SamWaf_${OS_ARCH}.${VERSION}.tar.gz"
            else
                echo "${OFFICIAL_BASE}/samwaf_update/${VERSION}/${PLAT_JSON}.gz"
            fi ;;
        github)   echo "${GITHUB_BASE}/releases/download/${VERSION}/SamWaf_${OS_ARCH}.${VERSION}.tar.gz" ;;
        gitee)    echo "${GITEE_BASE}/releases/download/${VERSION}/SamWaf_${OS_ARCH}.${VERSION}.tar.gz" ;;
    esac
}
# 源产物类型：official 视 /latest 可用性为 tar 或 gz；其余为 tar.gz
function src_kind() {
    case "$1" in
        official) [ "$LATEST_JSON_OK" = "1" ] && echo tar || echo gz ;;
        *) echo tar ;;
    esac
}

# 拉取 /latest/latest.json：正式版稳定通道自描述清单（版本 + 压缩包 SHA256）
function fetch_latest_manifest() {
    LATEST_JSON_OK=0; L_TAR_SHA=""
    local f="$WORKDIR/latest.json"
    DL "${OFFICIAL_BASE}/latest/latest.json" "$f" 2>/dev/null || return
    local ver hash
    ver=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$f" | head -1)
    hash=$(l_hash "$f")
    [ -n "$ver" ] && VERSION="$ver"
    if [ ${#hash} -eq 64 ]; then
        L_TAR_SHA="$hash"; LATEST_JSON_OK=1
        log_ok "🔐 已获取官方 /latest 清单: ${VERSION} (tar sha256=${L_TAR_SHA:0:16}...)"
    fi
}

# 拉取 samwaf_update 清单：填充 VERSION（若未定）与 MANIFEST_BIN_SHA（可执行文件锚点）
function fetch_manifest() {
    local f="$WORKDIR/manifest.json"
    if DL "${OFFICIAL_BASE}/samwaf_update/${PLAT_JSON}.json" "$f" 2>/dev/null; then
        local ver b64
        ver=$(sed -n 's/.*"Version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$f" | head -1)
        b64=$(sed -n 's/.*"Sha256"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$f" | head -1)
        [ -z "$VERSION" ] && [ -n "$ver" ] && VERSION="$ver"
        if [ -n "$b64" ]; then
            local hex; hex=$(b64_to_hex "$b64")
            if [ ${#hex} -eq 64 ]; then MANIFEST_BIN_SHA="$hex"; fi
        fi
    fi
    if [ -n "$MANIFEST_BIN_SHA" ]; then
        log_ok "🔐 已获取官方清单锚点: ${VERSION} (sha256=${MANIFEST_BIN_SHA:0:16}...)"
    else
        log_warn "⚠️ 官方清单不可用，将依赖 GitHub/Gitee 校验和"
    fi
}

# 官方清单不可用时，从 git 源发现最新版本号
function discover_version_from_git() {
    local f="$WORKDIR/rel.json" tag=""
    if DL "https://gitee.com/api/v5/repos/samwaf/SamWaf/releases/latest" "$f" 2>/dev/null; then
        tag=$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$f" | head -1)
    fi
    if [ -z "$tag" ] && DL "https://api.github.com/repos/samwafgo/SamWaf/releases/latest" "$f" 2>/dev/null; then
        tag=$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$f" | head -1)
    fi
    [ -n "$tag" ] && VERSION="$tag"
}

# 建立跨源一致性：汇总 官方latest / GitHub / Gitee 三者的压缩包 SHA256 并比对
function establish_consensus() {
    CK_TAR_SHA=""; CONSENSUS_HOSTS=0; GH_CK_OK=0; GT_CK_OK=0
    local verNoV="${VERSION#v}"
    local gh="$WORKDIR/ck_gh.txt" gt="$WORKDIR/ck_gt.txt" hgh="" hgt=""
    DL "${GITHUB_BASE}/releases/download/${VERSION}/SamWaf_${verNoV}_checksums.txt" "$gh" 2>/dev/null && hgh=$(ck_hash "$gh")
    DL "${GITEE_BASE}/releases/download/${VERSION}/SamWaf_${verNoV}_checksums.txt"  "$gt" 2>/dev/null && hgt=$(ck_hash "$gt")
    [ -n "$hgh" ] && GH_CK_OK=1
    [ -n "$hgt" ] && GT_CK_OK=1

    # 汇总所有可用的压缩包哈希（官方 latest.json / GitHub / Gitee）
    local vals=() names=()
    [ -n "$L_TAR_SHA" ] && { vals+=("$L_TAR_SHA"); names+=("官方latest"); }
    [ -n "$hgh" ]       && { vals+=("$hgh");       names+=("GitHub"); }
    [ -n "$hgt" ]       && { vals+=("$hgt");       names+=("Gitee"); }

    CONSENSUS_HOSTS=${#vals[@]}
    if [ "$CONSENSUS_HOSTS" -eq 0 ]; then
        log_warn "⚠️ 官方latest / GitHub / Gitee 压缩包校验和均不可用"
        return
    fi
    local base="${vals[0]}" i j
    for i in "${!vals[@]}"; do
        if [ "${vals[$i]}" != "$base" ]; then
            log_err "🚨 压缩包校验和跨源不一致，疑似源污染，已中止！"
            for j in "${!vals[@]}"; do log_err "   ${names[$j]}: ${vals[$j]}"; done
            exit 1
        fi
    done
    CK_TAR_SHA="$base"
    if [ "$CONSENSUS_HOSTS" -ge 2 ]; then
        log_ok "🤝 跨源压缩包校验和一致（${CONSENSUS_HOSTS} 源：${names[*]}） (sha256=${base:0:16}...)"
    else
        log_warn "⚠️ 仅 ${names[0]} 提供压缩包校验和（单源）"
    fi
}

# 校验准备：确定版本、锚点、一致性校验和，并执行安全策略闸门
function prepare_verification() {
    fetch_latest_manifest       # 官方 /latest 压缩包锚点（正式版稳定通道）
    fetch_manifest              # 官方 samwaf_update 可执行文件锚点
    [ -z "$VERSION" ] && discover_version_from_git
    if [ -z "$VERSION" ]; then
        log_err "❌ 无法确定最新版本号（所有源均不可达）"
        exit 1
    fi
    log_info "📦 目标版本: ${VERSION}"

    establish_consensus

    # 相互独立的可信主机数（update.samwaf.com 的两个清单只算 1 个主机）
    local official_ok=0
    if [ -n "$L_TAR_SHA" ] || [ -n "$MANIFEST_BIN_SHA" ]; then official_ok=1; fi
    local distinct_hosts=$((official_ok + GH_CK_OK + GT_CK_OK))

    if [ "$VERIFY_MODE" = "anchor" ]; then
        if [ -z "$MANIFEST_BIN_SHA" ] && [ -z "$L_TAR_SHA" ]; then
            log_err "❌ anchor 模式需要官方清单(/latest 或 samwaf_update)，但均不可用。"
            log_err "   可改用 SAMWAF_VERIFY=consensus 或稍后重试。"
            exit 1
        fi
        return 0
    fi

    # consensus 模式（默认）：至少两个相互独立的主机为发布物背书
    if [ -z "$CK_TAR_SHA" ] && [ -z "$MANIFEST_BIN_SHA" ]; then
        log_err "❌ 无任何可信校验基准（官方清单与 GitHub/Gitee 校验和均缺失），已中止。"
        exit 1
    fi
    if [ "$distinct_hosts" -lt 2 ]; then
        log_err "❌ 仅 ${distinct_hosts} 个可信来源可达，无法建立跨源一致性，已中止。"
        log_err "   请确保能访问 update.samwaf.com 与 GitHub/Gitee 中的至少两个；"
        log_err "   或设置 SAMWAF_VERIFY=anchor（不推荐）后重试。"
        exit 1
    fi
}

# 测速：probe <url> -> 输出首字节耗时（秒），不可达输出 999
# 说明：以“首字节耗时(TTFB)+HTTP 状态码”判定可达性，忽略 curl 退出码——
#       部分 CDN 不支持 Range，会整包返回并触发 --max-time，但只要拿到 TTFB
#       即视为可达，避免把“可用但非秒开”的镜像误判为不可达。
function probe() {
    local url="$1" out code sec
    have curl || { echo 500; return; }
    out=$(curl -o /dev/null -sL -k --connect-timeout 3 --max-time 8 -r 0-0 \
          -w '%{http_code} %{time_starttransfer}' "$url" 2>/dev/null)
    code=${out%% *}; sec=${out##* }
    if [[ "$code" =~ ^[23] ]] && [ -n "$sec" ] && [ "$sec" != "0.000000" ]; then
        echo "$sec"
    else
        echo 999
    fi
}

# 依测速对候选源排序（快者在前）；支持强制指定
function order_sources() {
    local candidates=("$@")
    if [ -n "$FORCE_SOURCE" ]; then
        local ok=0 c
        for c in "${candidates[@]}"; do [ "$c" = "$FORCE_SOURCE" ] && ok=1; done
        if [ "$ok" = "1" ]; then
            log_info "📌 已按 SAMWAF_SOURCE 强制使用下载源: $FORCE_SOURCE" >&2
            echo "$FORCE_SOURCE"; return
        else
            log_warn "⚠️ 指定的源 [$FORCE_SOURCE] 当前不可用，回退为自动测速" >&2
        fi
    fi
    if ! have curl; then
        printf '%s\n' "${candidates[@]}"   # 无 curl 无法测速，按默认顺序
        return
    fi
    log_info "⏱️ 正在测速各下载源..." >&2
    local s u t
    for s in "${candidates[@]}"; do
        u=$(src_download_url "$s")
        t=$(probe "$u")
        if [ "$t" = "999" ]; then
            log_warn "   [$s] 不可达" >&2
        else
            printf '   [%-8s] 首字节 %ss\n' "$s" "$t" >&2
        fi
        echo "$t $s"
    done | sort -n | awk '{print $2}'
}

# 依次尝试各源，下载并校验，成功后设置 VERIFIED_BIN
function acquire_verified_binary() {
    local CANDIDATES
    if [ -n "$MANIFEST_BIN_SHA" ] || [ "$LATEST_JSON_OK" = "1" ]; then
        CANDIDATES=(official github gitee)
    else
        CANDIDATES=(github gitee)
    fi

    local order; order=$(order_sources "${CANDIDATES[@]}")
    [ -z "$order" ] && { log_err "❌ 无可用下载源"; return 1; }

    local s u kind tmp bin th bh
    for s in $order; do
        u=$(src_download_url "$s"); kind=$(src_kind "$s")
        log_info "⬇️ 尝试从 [$s] 下载: $u"
        tmp="$WORKDIR/dl_${s}"
        if ! DL "$u" "$tmp"; then log_warn "   [$s] 下载失败，切换下一个源"; continue; fi

        bin="$WORKDIR/bin_${s}"
        if [ "$kind" = "tar" ]; then
            if [ -n "$CK_TAR_SHA" ]; then
                th=$(sha256_of "$tmp")
                if [ "$th" != "$CK_TAR_SHA" ]; then
                    log_warn "   [$s] 压缩包校验和不匹配（过期/被篡改），跳过"; continue
                fi
            fi
            if ! tar xzf "$tmp" -C "$WORKDIR" "$EXEC_NAME" 2>/dev/null; then
                log_warn "   [$s] 解压失败（未找到 $EXEC_NAME）"; continue
            fi
            mv -f "$WORKDIR/$EXEC_NAME" "$bin"
        else
            if ! gzip -dc "$tmp" > "$bin" 2>/dev/null; then
                log_warn "   [$s] 解压失败"; continue
            fi
        fi

        bh=$(sha256_of "$bin")
        if [ -n "$MANIFEST_BIN_SHA" ] && [ "$bh" != "$MANIFEST_BIN_SHA" ]; then
            log_warn "   [$s] 可执行文件哈希与官方清单不符（过期/被篡改），跳过"; continue
        fi
        if [ -z "$MANIFEST_BIN_SHA" ] && [ -z "$CK_TAR_SHA" ]; then
            log_err "   无任何校验基准，拒绝安装"; return 1
        fi

        VERIFIED_BIN="$bin"; USED_SOURCE="$s"; USED_BIN_SHA="$bh"
        log_ok "✅ [$s] 下载并校验通过 (sha256=${bh:0:16}...)"
        return 0
    done

    log_err "❌ 所有下载源均失败或未通过校验"
    return 1
}

# 部署已校验的可执行文件到安装目录并托管服务
function deploy_binary() {
    mkdir -p "${setup_path}"
    install -m 0755 "$VERIFIED_BIN" "${setup_path}/${EXEC_NAME}"
    chown -R root:root "${setup_path}"
    ( cd "${setup_path}" && ./"${EXEC_NAME}" install && ./"${EXEC_NAME}" start )
}

# 检查是否已安装
function check_installed() {
    if [ -f "${setup_path}/SamWafLinux64" ] || [ -f "${setup_path}/SamWafLinuxArm64" ]; then
        return 0
    fi
    return 1
}

# 停止服务
function stop_service() {
    if [ -f "${setup_path}/${EXEC_NAME}" ]; then
        log_info "🛑 停止服务..."
        "${setup_path}/${EXEC_NAME}" stop 2>/dev/null
    fi
}

# 卸载SamWaf
function uninstall_samwaf() {
    log_info "Uninstalling SamWaf..."
    init_arch_exec
    stop_service
    "${setup_path}/${EXEC_NAME}" uninstall 2>/dev/null
    log_ok "✅ SamWaf uninstalled successfully"
    log_info "📁 SamWaf files are still located at: ${setup_path}"
    log_err "⚠️ 危险操作: 如果确认要删除，请自行手工执行以下命令（此操作不可恢复）:"
    echo -e "    rm -rf \"${setup_path}\""
    exit 0
}

# 安装SamWaf
function install_samwaf() {
    log_info "📥 Installing SamWaf..."
    log_info "📁 Installation directory: ${setup_path}"
    check_deps
    init_arch_exec
    WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/samwaf.XXXXXX")
    prepare_verification
    acquire_verified_binary || exit 1
    deploy_binary
    show_info
}

# 更新SamWaf
function update_samwaf() {
    log_info "🔄 Updating SamWaf..."
    if ! check_installed; then
        log_err "❌ 未检测到 SamWaf 安装，请先执行安装"
        exit 1
    fi
    check_deps
    init_arch_exec
    WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/samwaf.XXXXXX")
    prepare_verification
    acquire_verified_binary || exit 1
    stop_service
    deploy_binary
    log_ok "✅ SamWaf 更新完成（版本 ${VERSION}，来源 ${USED_SOURCE}）"
}

# 显示信息
function show_info() {
    ipv4_address=$(curl -4 -sS --connect-timeout 4 -m 5 http://myexternalip.com/raw 2>/dev/null)
    local_ip=$(ip addr | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -E -v "^127\.|^255\.|^0\." | head -n 1)

    log_ok "✅ SamWaf installed successfully!"
    echo -e "=================================================================="
    echo -e "📋 SamWaf管理信息"
    echo -e "=================================================================="
    echo -e " 🏷️ 安装版本: ${VERSION}"
    echo -e " 🌐 下载来源: ${USED_SOURCE}   🔐 校验模式: ${VERIFY_MODE}"
    [ -n "$USED_BIN_SHA" ] && echo -e " 🧾 已校验哈希: ${USED_BIN_SHA}"
    [ "$ipv4_address" ] && echo -e " 🌐 外网管理地址: http://${ipv4_address}:26666"
    [ "$local_ip" ] && echo -e " 🏠 内网管理地址: http://${local_ip}:26666"
    echo -e " 👤 默认用户名: admin"
    echo -e " 🔑 初始密码: 自v1.3.21版本起密码为随机生成，请查看文件 ${setup_path}/data/initial_password.txt"
    echo -e "              (更早版本默认密码为 admin868)"
    echo -e " ⚠️  首次登录后请立即修改密码"
    echo -e ""
    echo -e " 📁 安装目录: ${setup_path}"
    echo -e " 🔧 服务管理: cd ${setup_path} && ./${EXEC_NAME} [start|stop]"
    echo -e " 🗑️ 卸载命令: bash $(basename "$0") uninstall"
    echo -e " 🔄 更新命令: bash $(basename "$0") update"
    echo -e " 📣 欢迎关注 SamWaf 开源防火墙公众号，获取最新版本信息与技术教程"
    echo -e "    公众号名称：${GREEN}SamWaf开源防火墙${NC}"
    echo -e " 🔗 Gitee:   ${GITEE_BASE}"
    echo -e " 🔗 GitHub:  ${GITHUB_BASE}"
    echo -e " 🔗 Atomgit: ${ATOMGIT_PAGE} （需登录下载）"
    echo -e "=================================================================="
}

# ------------------------------------------------------------------------ 主程序
case "$1" in
    uninstall)
        uninstall_samwaf
        ;;
    update)
        # 允许第二个参数覆盖下载源，例如: bash install_samwaf.sh update gitee
        [ -n "$2" ] && FORCE_SOURCE="$2"
        update_samwaf
        ;;
    *)
        # 首参可为 install 或空；第二参数可覆盖下载源，例如: install gitee
        if [ "$1" = "install" ] && [ -n "$2" ]; then FORCE_SOURCE="$2"; fi
        if [ "$1" != "install" ] && [ -n "$1" ]; then FORCE_SOURCE="$1"; fi
        if check_installed; then
            log_ok "✅ SamWaf 已安装，无需重复安装"
            echo -e "📁 安装目录: ${setup_path}"
            echo -e "如需更新请执行: bash $(basename "$0") update"
            echo -e "如需卸载请执行: bash $(basename "$0") uninstall"
        else
            install_samwaf
        fi
        ;;
esac
