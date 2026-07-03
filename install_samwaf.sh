#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
LANG=en_US.UTF-8

# 定义颜色常量
NC='\033[0m'        # 重置颜色
GREEN='\033[0;32m'  # 成功
RED='\033[0;31m'    # 错误
BLUE='\033[0;34m'   # 信息

# 检查是否为root权限 
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[0;33m🔐 检测到未使用 root 权限，尝试使用 sudo 重新运行...\033[0m"
    exec sudo bash "$0" "$@"
    exit 1
fi

# 获取当前脚本所在目录，在此目录下创建SamWaf目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
setup_path="${SCRIPT_DIR}/SamWaf"
ARCH=$(uname -m)

# 初始化架构与执行文件名
function init_arch_exec() {
    if [[ "$ARCH" == "x86_64" ]]; then
        exec_name="SamWafLinux64"
        url="https://update.samwaf.com/latest/SamWaf_Linux_x86_64.tar.gz"
    elif [[ "$ARCH" == "aarch64" ]] || [[ "$ARCH" == "arm64" ]]; then
        exec_name="SamWafLinuxArm64"
        url="https://update.samwaf.com/latest/SamWaf_Linux_arm64.tar.gz"
    else
        echo -e "${RED}❌ 不支持的架构: $ARCH${NC}"
        exit 1
    fi
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
    if [ -f "${setup_path}/${exec_name}" ]; then
        echo -e "${BLUE}🛑 停止服务...${NC}"
        ${setup_path}/${exec_name} stop
    fi
}

# 卸载SamWaf
function uninstall_samwaf() {
    echo -e "${BLUE}Uninstalling SamWaf...${NC}"
    init_arch_exec
    stop_service
    ${setup_path}/${exec_name} uninstall 2>/dev/null 
    echo -e "${GREEN}✅ SamWaf uninstalled successfully${NC}"
	echo -e "${BLUE}📁 SamWaf files are still located at: ${setup_path}${NC}" 
    echo -e "${RED}⚠️ 危险操作: 如果确认要删除，请自行手工执行以下命令（此操作不可恢复）:${NC}"
    echo -e "    rm -rf \"${setup_path}\""
    exit 0
}

# 安装SamWaf
function install_samwaf() {
    echo -e "${BLUE}📥 Installing SamWaf...${NC}"
    echo -e "${BLUE}📁 Installation directory: ${setup_path}${NC}"
    init_arch_exec
    mkdir -p ${setup_path}
    temp_file="/tmp/samwaf.tar.gz"
    echo -e "${BLUE}📥 Downloading from ${url}...${NC}"
    wget --no-check-certificate -O "${temp_file}" "${url}" || {
        echo -e "${RED}❌ Download failed${NC}"
        exit 1
    }
    echo -e "${BLUE}📦 Extracting...${NC}"
    tar xzf "${temp_file}" -C ${setup_path} || {
        echo -e "${RED}❌ Extract failed${NC}"
        exit 1
    }
	# ✅ 统一所有权限为 root
    chown -R root:root "${setup_path}"
    chmod +x ${setup_path}/${exec_name}
    cd ${setup_path}
    ./${exec_name} install
    ./${exec_name} start
    rm -f "${temp_file}"
    show_info
}

# 更新SamWaf
function update_samwaf() {
    echo -e "${BLUE}🔄 Updating SamWaf...${NC}"
    if ! check_installed; then
        echo -e "${RED}❌ 未检测到 SamWaf 安装，请先执行安装${NC}"
        exit 1
    fi
    init_arch_exec
    stop_service
    temp_file="/tmp/samwaf_update.tar.gz"
    echo -e "${BLUE}⬇️ 下载最新版本...${NC}"
    wget --no-check-certificate -O "${temp_file}" "${url}" || {
        echo -e "${RED}❌ 下载失败${NC}"
        exit 1
    }
    echo -e "${BLUE}📦 解压并替换...${NC}"
    tar xzf "${temp_file}" -C ${setup_path} || {
        echo -e "${RED}❌ 解压失败${NC}"
        exit 1
    }
	# ✅ 统一所有权限为 root
    chown -R root:root "${setup_path}"
    chmod +x ${setup_path}/${exec_name}
    cd ${setup_path}
    ./${exec_name} install
    ./${exec_name} start
    rm -f "${temp_file}"
    echo -e "${GREEN}✅ SamWaf 更新完成${NC}"
}

# 显示信息
function show_info() {
    ipv4_address=$(curl -4 -sS --connect-timeout 4 -m 5 http://myexternalip.com/raw 2>/dev/null)
    local_ip=$(ip addr | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -E -v "^127\.|^255\.|^0\." | head -n 1)

    echo -e "${GREEN}✅ SamWaf installed successfully!${NC}"
    echo -e "=================================================================="
    echo -e "📋 SamWaf管理信息"
    echo -e "=================================================================="
    [ "$ipv4_address" ] && echo -e " 🌐 外网管理地址: http://${ipv4_address}:26666"
    [ "$local_ip" ] && echo -e " 🏠 内网管理地址: http://${local_ip}:26666"
    echo -e " 👤 默认用户名: admin"
    echo -e " 🔑 初始密码: v1.3.21-beta.8 之后的版本为随机生成，请查看文件 ${setup_path}/data/initial_password.txt"
    echo -e "              (v1.3.21-beta.8 及更早版本默认密码为 admin868)"
    echo -e " ⚠️  首次登录后请立即修改密码"
    echo -e ""
    echo -e " 📁 安装目录: ${setup_path}"
    echo -e " 🔧 服务管理: cd ${setup_path} && ./${exec_name} [start|stop]"
    echo -e " 🗑️ 卸载命令: bash $(basename $0) uninstall"
    echo -e " 🔄 更新命令: bash $(basename $0) update"
    echo -e " 🔗 Gitee: https://gitee.com/samwaf/SamWaf"
    echo -e " 🔗 GitHub: https://github.com/samwafgo/SamWaf"
    echo -e "=================================================================="
}

# 主程序
case "$1" in
    uninstall)
        uninstall_samwaf
        ;;
    update)
        update_samwaf
        ;;
    *)
        if check_installed; then
            echo -e "${GREEN}✅ SamWaf 已安装，无需重复安装${NC}"
            echo -e "📁 安装目录: ${setup_path}"
            echo -e "如需更新请执行: bash $(basename $0) update"
            echo -e "如需卸载请执行: bash $(basename $0) uninstall"
        else
            install_samwaf
        fi
        ;;
esac