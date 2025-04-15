#!/bin/bash

# ==============================================================================
# 服务器初始化与管理脚本 V2.15
#
# 更新日志 (V2.15):
# - [修复] 回退并简化 setup_fail2ban 函数逻辑，严格按照用户验证的步骤安装、启动、启用服务，移除初始配置调用。
# - [保留] configure_fail2ban 函数（菜单选项 3.2）用于用户手动调整配置。
# - [保留] V2.14 中修复的 update_or_add_config 函数，用于手动配置。
# - [保留] V2.10 以来对公钥导入、y/n 确认、菜单选项等的改进。
#
# 更新日志 (V2.14):
# - [修复] 重写 update_or_add_config 函数，使用更可靠的 awk+sed 逻辑先删除再添加，防止重复配置项错误。(V2.15保留此修复)
#
# 更新日志 (V2.13):
# - [修复] 再次优化 Fail2ban 启动逻辑：调整配置、重载、重启顺序，增加延时。(V2.15已回退此复杂逻辑)
# - [修复] 从 configure_fail2ban 函数中移除 restart 命令，由调用者负责重启。(V2.15保留此修改)
#
# 更新日志 (V2.12):
# - [修复] 恢复 update_or_add_config 函数为更简单的 sed 实现，解决 V2.11 中的 awk 语法错误。(V2.14已再次修复)
#
# 更新日志 (V2.11):
# - [修复] 调整 Fail2ban 安装和启动逻辑：确保 rsyslog 重启后等待，再配置和启动 Fail2ban。(V2.15已回退此复杂逻辑)
# - [修复] Fail2ban 配置中为 sshd jail 添加明确的 journalmatch 规则，提高日志定位准确性。(移至手动配置)
#
# 更新日志 (V2.10):
# - [修复] 再次优化 SSH 公钥导入功能：改用 read -r 读取单行输入，加强清理和调试输出。(V2.15保留此修复)
#
# 更新日志 (V2.9):
# - [修复] Fail2ban 安装时自动安装依赖 rsyslog (针对 Debian 12 等系统)。(V2.15保留)
# - [修复] 优化 SSH 公钥粘贴读取逻辑，去除首尾空白和可能存在的引号。(V2.15保留)
# - [修复] 修正 SSH 公钥验证的正则表达式，使其能正确处理带注释的公钥。(V2.15保留)
#
# 更新日志 (V2.8):
# - [优化] 将所有 yes/no 确认修改为 y/n (回车默认为 Yes)。(V2.15保留)
# - [优化] 将所有菜单的返回/退出选项统一为 0。(V2.15保留)
# - [新增] SSH 密钥配置增加“粘贴公钥”选项，脚本自动添加并设置权限。(V2.15保留)
# - [修复] Fail2ban 配置中为 sshd jail 明确添加 backend = systemd。(移至手动配置)
#
# 功能:
# ... (功能列表保持不变) ...
# ==============================================================================

# --- 全局变量 ---
# ... (全局变量保持不变) ...
CF_API_TOKEN=""
DOMAIN=""
EMAIL="your@mail.com" # 固定邮箱
CERT_PATH_PREFIX="/root/cert"
CERT_PATH=""
CLOUDFLARE_CREDENTIALS=""
DEPLOY_HOOK_SCRIPT=""
DDNS_SCRIPT_PATH=""
DDNS_FREQUENCY=5
RECORD_TYPE=""
DETECTED_IPV4=""
DETECTED_IPV6=""
SELECTED_IP=""
ZONE_ID=""
ZONE_NAME=""
CF_API="https://api.cloudflare.com/client/v4"
NGINX_CONF_PATH=""
LOCAL_PROXY_PASS=""
BACKEND_PROTOCOL="http"
INSTALL_NGINX="no"
NGINX_HTTP_PORT=80
NGINX_HTTPS_PORT=443
CONFIG_DIR="${CERT_PATH_PREFIX}/.managed_domains"
CURRENT_SSH_PORT=$(sshd -T | grep -i "^port" | awk '{print $2}' | head -n 1)
DEFAULT_SSH_PORT=22
FAIL2BAN_JAIL_LOCAL="/etc/fail2ban/jail.local"
SSHD_CONFIG="/etc/ssh/sshd_config"

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- 函数定义 ---

# 清理并退出 (主要用于 trap)
cleanup_and_exit() {
    # 尝试删除临时文件（如果存在）
    rm -f "${FAIL2BAN_JAIL_LOCAL}.tmp.$$" 2>/dev/null
    echo -e "${RED}发生错误，脚本意外终止。${NC}"
    exit 1
}

# 错误处理陷阱
trap 'cleanup_and_exit' ERR SIGINT SIGTERM

# 检查命令是否存在
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 检查是否以 root 身份运行
check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo -e "${RED}[✗] 此脚本需要以 root 权限运行。请使用 sudo 或切换到 root 用户。${NC}"
        exit 1
    fi
    # 更新当前SSH端口变量 (可能在脚本运行期间被修改)
    CURRENT_SSH_PORT=$(grep -iE "^\s*Port\s+" $SSHD_CONFIG | tail -n 1 | awk '{print $2}')
    [[ -z "$CURRENT_SSH_PORT" ]] && CURRENT_SSH_PORT=$DEFAULT_SSH_PORT # 如果没找到则设为默认
}

# 通用确认函数 (Y/n/回车=Y)
confirm_action() {
    local prompt_msg="$1"
    local reply
    while true; do
        # -r 选项防止反斜杠被解释，-n 1 读取一个字符
        read -p "$prompt_msg [Y/n/回车默认Y]: " -n 1 -r reply
        echo # 输出换行符
        # 处理输入
        # [[ $reply =~ ^[Yy]$ ]] 匹配 Y 或 y
        # [[ -z $reply ]] 匹配回车
        if [[ $reply =~ ^[Yy]$ || -z $reply ]]; then
            return 0 # Yes 或 回车
        elif [[ $reply =~ ^[Nn]$ ]]; then
            return 1 # No
        else
            echo -e "${YELLOW}请输入 Y 或 N，或直接按回车确认。${NC}";
        fi
    done
}


# 通用包安装函数
install_package() {
    local pkg_name="$1"
    local install_cmd="apt install -y" # 默认为 Debian/Ubuntu
    # 可选: 添加对其他发行版的支持 (如 CentOS: yum install -y)
    # if command_exists yum; then install_cmd="yum install -y"; fi

    # 检查包是否已安装 (使用 dpkg -s 更可靠)
    if dpkg -s "$pkg_name" &> /dev/null; then
        echo -e "${YELLOW}[!] $pkg_name 似乎已安装。${NC}"
        return 0
    fi

    echo -e "${BLUE}[*] 正在安装 $pkg_name ...${NC}"
    export DEBIAN_FRONTEND=noninteractive
    apt update -y > /dev/null 2>&1 # 更新源信息，减少输出
    $install_cmd "$pkg_name"
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[✗] 安装 $pkg_name 失败。请检查错误信息并手动安装。${NC}"
        return 1
    else
        echo -e "${GREEN}[✓] $pkg_name 安装成功。${NC}"
        return 0
    fi
}

# --- 1. 基础工具 ---
install_common_tools() {
    echo -e "\n${CYAN}--- 1. 安装常用工具 ---${NC}"
    local tools="curl vim unzip htop net-tools socat jq expect" # expect 加入这里
    local failed=0
    for tool in $tools; do
        install_package "$tool"
        if [[ $? -ne 0 ]]; then
            failed=1
        fi
    done
    if [[ $failed -eq 0 ]]; then
        echo -e "${GREEN}[✓] 常用工具检查/安装完成。${NC}"
    else
        echo -e "${RED}[✗] 部分常用工具安装失败，请检查上面的错误信息。${NC}"
    fi
}

# --- 2. UFW 防火墙 ---
setup_ufw() {
    echo -e "\n${CYAN}--- 2.1 安装并启用 UFW 防火墙 ---${NC}"
    if ! install_package "ufw"; then return 1; fi
    # 确保 expect 已安装
    if ! command_exists expect; then
        if ! install_package "expect"; then
            echo -e "${RED}[✗] expect 工具安装失败，可能无法自动处理 UFW 启用确认。${NC}"
            # 可以选择退出或让用户手动确认
        fi
    fi


    # 设置默认规则：拒绝所有入站，允许所有出站
    echo -e "${BLUE}[*] 设置 UFW 默认规则 (deny incoming, allow outgoing)...${NC}"
    ufw default deny incoming > /dev/null
    ufw default allow outgoing > /dev/null

    # 明确允许当前 SSH 端口，防止锁死
    echo -e "${BLUE}[*] 允许当前 SSH 端口 ($CURRENT_SSH_PORT)...${NC}"
    ufw allow $CURRENT_SSH_PORT/tcp comment "SSH Access (Current)" > /dev/null

    # 启用 UFW
    echo -e "${YELLOW}[!] 准备启用 UFW。这将断开除 SSH ($CURRENT_SSH_PORT) 外的所有连接。${NC}"
    if confirm_action "确认启用 UFW 吗?"; then
        # 使用 expect 来处理可能的 y/n 确认 (如果 expect 可用)
        if command_exists expect; then
            expect -c "
            set timeout 10
            spawn ufw enable
            expect {
                \"Command may disrupt existing ssh connections. Proceed with operation (y|n)?\" { send \"y\r\"; exp_continue }
                eof
            }
            " > /dev/null
        else
            # 如果 expect 不可用，尝试直接启用，可能需要用户手动交互
            ufw enable
        fi
        # 检查状态
        if ufw status | grep -q "Status: active"; then
            echo -e "${GREEN}[✓] UFW 已成功启用。${NC}"
            ufw status verbose # 显示当前状态
        else
            echo -e "${RED}[✗] UFW 启用失败。请检查错误信息。${NC}"
            return 1
        fi
    else
        echo -e "${YELLOW}UFW 未启用。${NC}"
    fi
}

add_ufw_rule() {
    echo -e "\n${CYAN}--- 2.2 添加 UFW 规则 ---${NC}"
    local port protocol comment rule

    # 获取端口
    while true; do
        read -p "请输入要开放的端口号 (例如 80, 443, 8080): " port
        if [[ "$port" =~ ^[0-9]+$ && "$port" -gt 0 && "$port" -le 65535 ]]; then
            break
        else
            echo -e "${YELLOW}无效的端口号。请输入 1-65535 之间的数字。${NC}"
        fi
    done

    # 获取协议
    while true; do
        read -p "请选择协议 [1] TCP (默认) [2] UDP : " proto_choice
        if [[ -z "$proto_choice" || "$proto_choice" == "1" ]]; then
            protocol="tcp"
            break
        elif [[ "$proto_choice" == "2" ]]; then
            protocol="udp"
            break
        else
            echo -e "${YELLOW}无效输入，请输入 1 或 2。${NC}"
        fi
    done

    # 获取备注
    read -p "请输入端口用途备注 (例如 'Web Server HTTP', 'Game Server UDP'): " comment
    [[ -z "$comment" ]] && comment="Rule added by script" # 提供默认备注

    # 构建规则并添加
    rule="${port}/${protocol}"
    echo -e "${BLUE}[*] 准备添加规则: ufw allow ${rule} comment '${comment}'${NC}"
    if confirm_action "确认添加此规则吗?"; then
        ufw allow $rule comment "$comment"
        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}[✓] 规则已添加。请运行 '查看 UFW 规则' 确认。${NC}"
            # 提示重载 (如果需要立即生效)
            # ufw reload
        else
            echo -e "${RED}[✗] 添加规则失败。${NC}"
        fi
    else
        echo -e "${YELLOW}操作已取消。${NC}"
    fi
}

view_ufw_rules() {
    echo -e "\n${CYAN}--- 2.3 查看 UFW 规则 ---${NC}"
    if ! command_exists ufw; then
        echo -e "${YELLOW}[!] UFW 未安装。${NC}"
        return
    fi
    echo -e "${BLUE}当前 UFW 状态和规则:${NC}"
    ufw status verbose # 使用 verbose 显示更详细信息，包括默认策略
    echo -e "\n${BLUE}带编号的规则列表 (用于删除):${NC}"
    ufw status numbered
}

manage_ufw() {
    while true; do
        echo -e "\n${CYAN}--- UFW 防火墙管理 ---${NC}"
        echo -e " ${YELLOW}1.${NC} 安装并启用 UFW (设置默认规则, 允许当前SSH)"
        echo -e " ${YELLOW}2.${NC} 添加允许规则 (开放端口)"
        echo -e " ${YELLOW}3.${NC} 查看当前 UFW 规则"
        echo -e " ${YELLOW}0.${NC} 返回主菜单"
        read -p "请输入选项 [0-3]: " ufw_choice

        case $ufw_choice in
            1) setup_ufw ;;
            2) add_ufw_rule ;;
            3) view_ufw_rules ;;
            0) break ;;
            *) echo -e "${RED}无效选项。${NC}" ;;
        esac
        [[ $ufw_choice != 0 ]] && read -p "按 Enter键 继续..."
    done
}


# --- 3. Fail2ban ---
# V2.15: 简化安装逻辑，遵循用户反馈
setup_fail2ban() {
    echo -e "\n${CYAN}--- 3.1 安装并启用 Fail2ban ---${NC}"
    # 1. 安装 fail2ban
    if ! install_package "fail2ban"; then
        echo -e "${RED}[✗] Fail2ban 安装失败，无法继续。${NC}"
        return 1
    fi
    # 2. 安装 rsyslog (Debian 12 需要)
    if ! install_package "rsyslog"; then
        echo -e "${YELLOW}[!] rsyslog 安装失败，Fail2ban 可能无法正常工作。${NC}"
    else
        # 确保 rsyslog 服务运行并重启
        echo -e "${BLUE}[*] 启用并重启 rsyslog 服务...${NC}"
        systemctl enable rsyslog > /dev/null 2>&1
        systemctl restart rsyslog
        echo -e "${BLUE}[*] 等待 rsyslog 初始化...${NC}"
        sleep 2
    fi

    # 3. 启动 fail2ban
    echo -e "${BLUE}[*] 启动 Fail2ban 服务...${NC}"
    systemctl start fail2ban
    sleep 2 # 短暂等待

    # 4. 启用 fail2ban 开机自启
    echo -e "${BLUE}[*] 启用 Fail2ban 开机自启...${NC}"
    systemctl enable fail2ban > /dev/null

    # 5. 检查状态
    if systemctl is-active --quiet fail2ban; then
        echo -e "${GREEN}[✓] Fail2ban 服务已成功启动并启用。${NC}"
        echo -e "${YELLOW}[!] Fail2ban 已使用默认配置启动。您可以通过选项 2 手动调整配置。${NC}"
    else
        echo -e "${RED}[✗] Fail2ban 服务启动失败。请检查 'systemctl status fail2ban' 和日志。${NC}"
        echo -e "${YELLOW}   尝试查看日志: journalctl -u fail2ban -n 50 --no-pager ${NC}"
        return 1
    fi
}

# 更新或创建配置项的辅助函数 (V2.14: 使用更可靠的 awk+sed 删除再添加逻辑)
update_or_add_config() {
    local file="$1"
    local section="$2" # 例如 sshd (without brackets)
    local key="$3"
    local value="$4"
    local section_header_regex="^\s*\[${section}\]"
    local temp_file="${file}.tmp.$$" # Temporary file with PID

    # 确保 section header 存在
    if ! grep -qE "$section_header_regex" "$file"; then
        echo -e "${BLUE}[!] Section [${section}] not found in ${file}, adding it.${NC}"
        # Section 不存在，在文件末尾添加
        echo -e "\n[${section}]" >> "$file"
        # 并且直接添加 key = value
        echo "${key} = ${value}" >> "$file"
        return 0 # 完成添加
    fi

    # Section 存在，处理 key
    # 使用 awk 在 section 范围内删除所有匹配的 key 行 (注释或未注释)
    # Escape key for awk regex safety
    local escaped_key_for_awk=$(sed 's/[][\/.*^$?+|()]/\\&/g' <<<"$key")
    local key_match_regex_awk="^\s*#?\s*${escaped_key_for_awk}\s*="

    awk -v section_re="$section_header_regex" -v key_re="$key_match_regex_awk" '
    BEGIN { in_section = 0 }
    # Found the target section header
    $0 ~ section_re { print; in_section = 1; next }
    # Found the start of a different section while in target section
    /^\s*\[/ && in_section { in_section = 0 }
    # Outside the target section, print the line
    !in_section { print; next }
    # Inside the target section, if line matches the key, skip it (delete)
    in_section && $0 ~ key_re { next }
    # Inside the target section, print other lines
    in_section { print }
    ' "$file" > "$temp_file"

    # Check if awk succeeded
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[✗] Error processing config file with awk (deleting ${key}).${NC}"
        rm -f "$temp_file" 2>/dev/null
        return 1
    fi

    # 再在 section header 后添加新的 key = value
    # 使用 sed 的 'a' (append) 命令
    # Escape backslashes first, then other special chars for sed 'a' command
    local escaped_value_for_add=$(echo "$value" | sed -e 's/\\/\\\\/g' -e 's/[\/&]/\\&/g' -e 's/$/\\/' -e '$s/\\$//' | tr -d '\n')
    # Add the line after the section header line found by the regex
    # Need to handle case where section header is the last line
    if ! sed -i "/${section_header_regex}/a ${key} = ${escaped_value_for_add}" "$temp_file"; then
         echo -e "${RED}[✗] Error processing config file with sed (adding ${key}).${NC}"
         rm -f "$temp_file" 2>/dev/null
         return 1
    fi

    # Replace original file
    mv "$temp_file" "$file"
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[✗] Error replacing config file ${file}.${NC}"
        # Attempt to restore from backup? Or notify user.
        rm -f "$temp_file" 2>/dev/null # Clean up temp file on error
        return 1
    fi

    # Clean up just in case trap doesn't fire
    rm -f "$temp_file" 2>/dev/null
    return 0
}


# V2.15: configure_fail2ban 用于手动配置，不再在 setup 中调用
configure_fail2ban() {
    echo -e "\n${CYAN}--- 3.2 配置 Fail2ban (SSH 防护) ---${NC}"
    if ! command_exists fail2ban-client && ! command_exists fail2ban-server && [[ ! -f /usr/bin/fail2ban-server ]]; then
        echo -e "${YELLOW}[!] Fail2ban 未安装或未找到。请先安装。${NC}"
        return 1
    fi

    local ssh_port maxretry bantime current_maxretry current_bantime current_backend current_journalmatch

    # 获取当前配置 (如果 jail.local 存在)
    if [[ -f "$FAIL2BAN_JAIL_LOCAL" ]]; then
        # 使用更健壮的方式获取配置值，处理空格和注释
        current_maxretry=$(awk -F '=' '/^\s*\[sshd\]/{f=1} /^\s*\[/{if(f)f=0} f && /^\s*maxretry\s*=/{gsub(/^[ \t]+|[ \t]+$|#.*$/, "", $2); print $2; exit}' $FAIL2BAN_JAIL_LOCAL | tail -n 1)
        current_bantime=$(awk -F '=' '/^\s*\[sshd\]/{f=1} /^\s*\[/{if(f)f=0} f && /^\s*bantime\s*=/{gsub(/^[ \t]+|[ \t]+$|#.*$/, "", $2); print $2; exit}' $FAIL2BAN_JAIL_LOCAL | tail -n 1)
        current_backend=$(awk -F '=' '/^\s*\[sshd\]/{f=1} /^\s*\[/{if(f)f=0} f && /^\s*backend\s*=/{gsub(/^[ \t]+|[ \t]+$|#.*$/, "", $2); print $2; exit}' $FAIL2BAN_JAIL_LOCAL | tail -n 1)
        # Extract journalmatch value carefully
        current_journalmatch=$(awk '/^\s*\[sshd\]/{f=1} /^\s*\[/ && f{f=0} f && /^\s*journalmatch\s*=/{match($0, /=\s*(.*)/); val=substr($0, RSTART+1, RLENGTH-1); sub(/^[ \t]+|[ \t]+$|#.*$/, "", val); print val; exit}' $FAIL2BAN_JAIL_LOCAL | tail -n 1)
    fi
    # 设置默认值，如果未获取到当前值
    [[ -z "$current_maxretry" ]] && current_maxretry=5
    [[ -z "$current_bantime" ]] && current_bantime="10m" # 默认 10 分钟
    [[ -z "$current_backend" ]] && current_backend="systemd" # 默认使用 systemd
    # V2.11: Default journalmatch rule
    local default_journalmatch="_SYSTEMD_UNIT=sshd.service + _COMM=sshd"
    [[ -z "$current_journalmatch" ]] && current_journalmatch="$default_journalmatch"


    # 获取用户输入
    read -p "请输入 SSH 端口 (当前: $CURRENT_SSH_PORT): " ssh_port_input
    ssh_port=${ssh_port_input:-$CURRENT_SSH_PORT} # 如果为空则使用当前值

    read -p "请输入最大重试次数 (当前: $current_maxretry): " maxretry_input
    maxretry=${maxretry_input:-$current_maxretry}

    read -p "请输入封禁时间 (例如 60m, 1h, 1d, -1 表示永久, 当前: $current_bantime): " bantime_input
    bantime=${bantime_input:-$current_bantime}

    # 验证输入
    if ! [[ "$ssh_port" =~ ^[0-9]+$ && "$ssh_port" -gt 0 && "$ssh_port" -le 65535 ]]; then
        echo -e "${RED}[✗] 无效的 SSH 端口。${NC}"; return 1
    fi
    if ! [[ "$maxretry" =~ ^[0-9]+$ && "$maxretry" -gt 0 ]]; then
        echo -e "${RED}[✗] 最大重试次数必须是正整数。${NC}"; return 1
    fi
    # bantime 格式较灵活，这里不做严格校验

    echo -e "${BLUE}[*] 准备更新 Fail2ban 配置 (${FAIL2BAN_JAIL_LOCAL}):${NC}"
    echo "  SSH 端口: $ssh_port"
    echo "  最大重试: $maxretry"
    echo "  封禁时间: $bantime"
    echo "  日志后端: $current_backend" # 显示将使用的后端
    echo "  Journal 匹配: $current_journalmatch" # V2.11: Show journalmatch

    if confirm_action "确认更新配置吗?"; then
        # 确保 jail.local 文件存在
        if [[ ! -f "$FAIL2BAN_JAIL_LOCAL" ]]; then
            echo -e "${BLUE}[*] 创建 ${FAIL2BAN_JAIL_LOCAL} 文件...${NC}"
            # 创建基础结构
            cat > "$FAIL2BAN_JAIL_LOCAL" <<EOF
[DEFAULT]
# Ban hosts for 10 minutes:
bantime = 10m
# Override /etc/fail2ban/jail.d/00-firewalld.conf:
banaction = ufw

[sshd]
enabled = true
# 其他配置将由脚本添加/更新
EOF
        fi

        # 使用辅助函数更新或添加配置项
        update_or_add_config "$FAIL2BAN_JAIL_LOCAL" "sshd" "enabled" "true" || return 1
        update_or_add_config "$FAIL2BAN_JAIL_LOCAL" "sshd" "port" "$ssh_port" || return 1
        update_or_add_config "$FAIL2BAN_JAIL_LOCAL" "sshd" "maxretry" "$maxretry" || return 1
        update_or_add_config "$FAIL2BAN_JAIL_LOCAL" "sshd" "bantime" "$bantime" || return 1
        update_or_add_config "$FAIL2BAN_JAIL_LOCAL" "sshd" "backend" "$current_backend" || return 1
        # V2.11: Add journalmatch
        update_or_add_config "$FAIL2BAN_JAIL_LOCAL" "sshd" "journalmatch" "$current_journalmatch" || return 1

        echo -e "${GREEN}[✓] Fail2ban 配置已写入 ${FAIL2BAN_JAIL_LOCAL}。${NC}"

        # V2.15: 尝试 reload 配置
        if command_exists fail2ban-client; then
            echo -e "${BLUE}[*] 尝试重新加载 Fail2ban 配置...${NC}"
            if fail2ban-client reload sshd; then # Reload specific jail
                 echo -e "${GREEN}[✓] Fail2ban sshd 配置重新加载成功。${NC}"
            else
                 echo -e "${YELLOW}[!] Fail2ban 配置重新加载失败，可能需要重启服务才能生效。${NC}"
            fi
        else
             echo -e "${YELLOW}[!] fail2ban-client 未找到，跳过配置重载。${NC}"
        fi
        return 0 # 配置成功
    else
        echo -e "${YELLOW}操作已取消。${NC}"
        return 1 # 配置取消
    fi
}

view_fail2ban_status() {
    echo -e "\n${CYAN}--- 3.3 查看 Fail2ban 状态 (SSH) ---${NC}"
    if ! command_exists fail2ban-client; then
        echo -e "${YELLOW}[!] Fail2ban 未安装。${NC}"
        return 1
    fi

    echo -e "${BLUE}Fail2ban SSH jail 状态:${NC}"
    fail2ban-client status sshd

    echo -e "\n${BLUE}查看 Fail2ban 日志 (最近 20 条):${NC}"
    # 尝试 journalctl，如果失败则尝试读取默认日志文件
    if command_exists journalctl; then
        journalctl -u fail2ban -n 20 --no-pager --quiet
    elif [[ -f /var/log/fail2ban.log ]]; then
        tail -n 20 /var/log/fail2ban.log
    else
        echo -e "${YELLOW}无法找到 Fail2ban 日志。${NC}"
    fi
}

manage_fail2ban() {
     while true; do
        echo -e "\n${CYAN}--- Fail2ban 入侵防御管理 ---${NC}"
        echo -e " ${YELLOW}1.${NC} 安装并启用 Fail2ban (使用系统默认配置)"
        echo -e " ${YELLOW}2.${NC} 手动配置 Fail2ban (SSH 端口, 重试次数, 封禁时间等)"
        echo -e " ${YELLOW}3.${NC} 查看 Fail2ban 状态 (SSH jail, 日志)"
        echo -e " ${YELLOW}0.${NC} 返回主菜单"
        read -p "请输入选项 [0-3]: " f2b_choice

        case $f2b_choice in
            1) setup_fail2ban ;;
            2)
               # V2.15: Configure first, then restart if config succeeded
               if configure_fail2ban; then
                   echo -e "${BLUE}[*] 重启 Fail2ban 服务以应用手动配置...${NC}"
                   systemctl restart fail2ban
                   sleep 2
                   if systemctl is-active --quiet fail2ban; then
                       echo -e "${GREEN}[✓] Fail2ban 服务已重启。${NC}"
                   else
                       echo -e "${RED}[✗] Fail2ban 服务重启失败。${NC}"
                   fi
               fi
               ;;
            3) view_fail2ban_status ;;
            0) break ;;
            *) echo -e "${RED}无效选项。${NC}" ;;
        esac
        [[ $f2b_choice != 0 ]] && read -p "按 Enter键 继续..."
    done
}

# --- 4. SSH 安全 ---
change_ssh_port() {
    echo -e "\n${CYAN}--- 4.1 更改 SSH 端口 ---${NC}"
    local new_port old_port

    old_port=$CURRENT_SSH_PORT
    echo "当前 SSH 端口是: $old_port"

    # 获取新端口
    while true; do
        read -p "请输入新的 SSH 端口号 (建议 10000-65535): " new_port
        if [[ "$new_port" =~ ^[0-9]+$ && "$new_port" -gt 0 && "$new_port" -le 65535 ]]; then
            if [[ "$new_port" -eq "$old_port" ]]; then
                echo -e "${YELLOW}新端口与当前端口相同，无需更改。${NC}"
                return
            fi
            break
        else
            echo -e "${YELLOW}无效的端口号。请输入 1-65535 之间的数字。${NC}"
        fi
    done

    echo -e "${RED}[!] 警告：更改 SSH 端口需要确保新端口在防火墙中已开放！${NC}"
    echo "脚本将尝试执行以下操作："
    echo "  1. 在 UFW 中允许新端口 $new_port/tcp (如果 UFW 已启用)。"
    echo "  2. 修改 SSH 配置文件 ($SSHD_CONFIG)。"
    echo "  3. 重启 SSH 服务。"
    echo "  4. 在 UFW 中删除旧端口 $old_port/tcp 的规则 (如果存在)。"
    echo "  5. 更新 Fail2ban 配置以监控新端口 (如果 Fail2ban 已安装)。"
    echo -e "${YELLOW}在重启 SSH 服务后，您需要使用新端口重新连接！例如: ssh user@host -p $new_port ${NC}"

    if ! confirm_action "确认要将 SSH 端口从 $old_port 更改为 $new_port 吗?"; then
        echo "操作已取消。"
        return
    fi

    # 1. 更新 UFW (如果启用) - 先允许新端口
    if command_exists ufw && ufw status | grep -q "Status: active"; then
        echo -e "${BLUE}[*] 在 UFW 中允许新端口 $new_port/tcp ...${NC}"
        ufw allow $new_port/tcp comment "SSH Access (New)" > /dev/null
        if [[ $? -ne 0 ]]; then
             echo -e "${RED}[✗] UFW 允许新端口失败！中止操作以防锁死。${NC}"
             return 1
        fi
         echo -e "${GREEN}[✓] UFW 已允许新端口 $new_port/tcp。${NC}"
    else
        echo -e "${YELLOW}[!] UFW 未安装或未启用，跳过防火墙规则添加。请手动确保端口可访问！${NC}"
    fi

    # 2. 修改 SSH 配置
    echo -e "${BLUE}[*] 修改 SSH 配置文件 ($SSHD_CONFIG)...${NC}"
    # 先备份
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak_port_$(date +%F_%T)"
    # 修改 Port
    update_or_add_config "$SSHD_CONFIG" "" "Port" "$new_port"
    if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 修改 SSH 配置文件失败。${NC}"; return 1; fi
    echo -e "${GREEN}[✓] SSH 配置文件已修改。${NC}"

    # 3. 重启 SSH 服务
    echo -e "${BLUE}[*] 重启 SSH 服务...${NC}"
    echo -e "${YELLOW}服务重启后，当前连接可能会断开。请使用新端口 $new_port 重新连接。${NC}"
    systemctl restart sshd
    # 暂停几秒钟给服务启动时间
    sleep 3
    # 检查服务状态
    if systemctl is-active --quiet sshd; then
        echo -e "${GREEN}[✓] SSH 服务已成功重启。${NC}"
        # 更新当前端口变量
        CURRENT_SSH_PORT=$new_port
    else
        echo -e "${RED}[✗] SSH 服务重启失败！请立即检查 SSH 配置 (${SSHD_CONFIG}) 和服务状态 ('systemctl status sshd')。${NC}"
        echo -e "${RED}   旧配置已备份为 ${SSHD_CONFIG}.bak_port_* 。${NC}"
        echo -e "${RED}   防火墙规则可能未完全更新。${NC}"
        # 尝试恢复备份？或者让用户手动处理
        return 1
    fi

    # 4. 更新 UFW (如果启用) - 删除旧端口规则
    if command_exists ufw && ufw status | grep -q "Status: active"; then
        echo -e "${BLUE}[*] 在 UFW 中删除旧端口 $old_port/tcp 的规则...${NC}"
        # 注意：ufw delete 不支持 comment，需要精确匹配规则
        # 尝试删除 'allow port/tcp' 和 'allow port'
        ufw delete allow $old_port/tcp > /dev/null 2>&1
        ufw delete allow $old_port > /dev/null 2>&1 # 某些旧规则可能没有协议
        echo -e "${GREEN}[✓] 尝试删除旧 UFW 规则完成 (如果存在)。${NC}"
        # ufw status # 可以取消注释以显示最新规则
    fi

    # 5. 更新 Fail2ban 配置 (如果安装)
    if command_exists fail2ban-client; then
        echo -e "${BLUE}[*] 更新 Fail2ban 配置以监控新端口 $new_port ...${NC}"
        # 调用配置函数，它会使用最新的 CURRENT_SSH_PORT
        if configure_fail2ban; then # Configure first
            # V2.15: Restart fail2ban after configuration change
            echo -e "${BLUE}[*] 重启 Fail2ban 服务以应用新端口...${NC}"
            systemctl restart fail2ban
            sleep 2
            if systemctl is-active --quiet fail2ban; then
                echo -e "${GREEN}[✓] Fail2ban 服务已重启。${NC}"
            else
                 echo -e "${RED}[✗] Fail2ban 服务重启失败。${NC}"
            fi
        else
             echo -e "${RED}[✗] Fail2ban 配置更新失败。${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Fail2ban 未安装，跳过其配置更新。${NC}"
    fi

    echo -e "${GREEN}[✓] SSH 端口更改完成。请记住使用新端口 $new_port 登录。${NC}"
}

create_sudo_user() {
    echo -e "\n${CYAN}--- 4.2 创建新的 Sudo 用户 ---${NC}"
    local username

    # 获取用户名
    while true; do
        read -p "请输入新用户名: " username
        if [[ -z "$username" ]]; then
            echo -e "${YELLOW}用户名不能为空。${NC}"
        elif id "$username" &>/dev/null; then
            echo -e "${YELLOW}用户 '$username' 已存在。${NC}"
        elif [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then # 基本用户名校验
            break
        else
            echo -e "${YELLOW}无效的用户名格式 (建议使用小写字母、数字、下划线、连字符，并以字母或下划线开头)。${NC}"
        fi
    done

    # 添加用户并设置密码
    echo -e "${BLUE}[*] 添加用户 '$username' 并设置密码...${NC}"
    adduser "$username" # adduser 会交互式提示设置密码和信息
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[✗] 添加用户失败。${NC}"
        return 1
    fi

    # 添加到 sudo 组
    echo -e "${BLUE}[*] 将用户 '$username' 添加到 sudo 组...${NC}"
    usermod -aG sudo "$username"
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[✗] 添加到 sudo 组失败。${NC}"
        # 用户已创建，但没有 sudo 权限
        return 1
    fi

    echo -e "${GREEN}[✓] 用户 '$username' 创建成功并已添加到 sudo 组。${NC}"
    echo -e "${YELLOW}请使用新用户登录并测试 sudo权限 (例如 'sudo whoami')。${NC}"
    echo -e "${YELLOW}建议在新用户能够正常登录并使用 sudo 后，再考虑禁用 root 登录。${NC}"
}

disable_root_login() {
    echo -e "\n${CYAN}--- 4.3 禁用 Root 用户 SSH 登录 ---${NC}"
    echo -e "${RED}[!] 警告：禁用 Root 登录前，请确保您已创建具有 Sudo 权限的普通用户，并且该用户可以正常通过 SSH 登录！${NC}"

    if ! confirm_action "确认要禁止 Root 用户通过 SSH 登录吗?"; then
        echo "操作已取消。"
        return
    fi

    echo -e "${BLUE}[*] 修改 SSH 配置文件 ($SSHD_CONFIG) 以禁用 Root 登录...${NC}"
    # 备份
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak_root_$(date +%F_%T)"
    # 修改 PermitRootLogin
    update_or_add_config "$SSHD_CONFIG" "" "PermitRootLogin" "no"
    if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 修改 SSH 配置文件失败。${NC}"; return 1; fi


    echo -e "${BLUE}[*] 重启 SSH 服务以应用更改...${NC}"
    systemctl restart sshd
    sleep 2
    if systemctl is-active --quiet sshd; then
        echo -e "${GREEN}[✓] Root 用户 SSH 登录已禁用。${NC}"
    else
        echo -e "${RED}[✗] SSH 服务重启失败！请检查配置。Root 登录可能仍被允许。${NC}"
        echo -e "${RED}   旧配置已备份为 ${SSHD_CONFIG}.bak_root_* 。${NC}"
        return 1
    fi
}

# 添加公钥到 authorized_keys 的辅助函数 (V2.10 优化)
add_public_key() {
    local target_user="$1"
    local user_home
    local ssh_dir
    local auth_keys_file
    local pub_key_input
    local pub_key_cleaned

    # 检查用户是否存在
    if ! id "$target_user" &>/dev/null; then
        echo -e "${RED}[✗] 用户 '$target_user' 不存在。${NC}"
        return 1
    fi

    user_home=$(eval echo ~$target_user) # 获取用户家目录
    if [[ ! -d "$user_home" ]]; then
        echo -e "${RED}[✗] 找不到用户 '$target_user' 的家目录: $user_home ${NC}"
        return 1
    fi

    ssh_dir="${user_home}/.ssh"
    auth_keys_file="${ssh_dir}/authorized_keys"

    echo -e "${BLUE}[*] 请【一次性】粘贴您的【单行公钥】内容 (例如 'ssh-ed25519 AAA... comment')，然后按 Enter 键:${NC}"
    # 使用 read -r 读取单行输入
    read -r pub_key_input

    if [[ -z "$pub_key_input" ]]; then
        echo -e "${YELLOW}未输入任何内容，操作取消。${NC}"
        return 1
    fi

    # 清理输入：去除首尾空白，去除可能粘贴进来的单引号或双引号
    pub_key_cleaned=$(echo "$pub_key_input" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e "s/^'//" -e "s/'$//" -e 's/^"//' -e 's/"$//')

    # 增加调试输出
    # echo "DEBUG: Cleaned key for validation: '$pub_key_cleaned'"

    # 修正后的公钥格式校验 (允许末尾有注释)
    # V2.11: Regex updated to handle different ecdsa curves more accurately
    local key_regex="^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp(256|384|521))\s+AAAA[0-9A-Za-z+/]+[=]{0,3}(\s+.*)?$"
    if ! [[ "$pub_key_cleaned" =~ $key_regex ]]; then
        echo -e "${RED}[✗] 输入的内容似乎不是有效的 SSH 公钥格式。操作取消。${NC}"
        echo -e "${YELLOW}   公钥通常以 'ssh-rsa', 'ssh-ed25519' 或 'ecdsa-...' 开头，后跟一长串基于 Base64 的字符。${NC}"
        echo -e "${YELLOW}   清理后的输入为: '$pub_key_cleaned' ${NC}" # 显示清理后的内容帮助调试
        return 1
    fi

    echo -e "${BLUE}[*] 准备将以下公钥添加到用户 '$target_user' 的 ${auth_keys_file} 文件中:${NC}"
    echo -e "${CYAN}${pub_key_cleaned}${NC}"

    if ! confirm_action "确认添加吗?"; then
        echo "操作已取消。"
        return 1
    fi

    # 创建 .ssh 目录和 authorized_keys 文件（如果不存在），并设置权限
    echo -e "${BLUE}[*] 确保目录和文件存在并设置权限...${NC}"
    mkdir -p "$ssh_dir"
    touch "$auth_keys_file"
    chmod 700 "$ssh_dir"
    chmod 600 "$auth_keys_file"
    # 确保所有权正确
    chown -R "${target_user}:${target_user}" "$ssh_dir"

    # 检查公钥是否已存在 (精确匹配清理后的内容)
    # 使用 grep -F 进行固定字符串匹配，防止公钥中的特殊字符被解释
    if grep -qF "$pub_key_cleaned" "$auth_keys_file"; then
        echo -e "${YELLOW}[!] 此公钥似乎已存在于 ${auth_keys_file} 中，无需重复添加。${NC}"
        return 0
    fi

    # 追加公钥到文件
    echo "$pub_key_cleaned" >> "$auth_keys_file"
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}[✓] 公钥已成功添加到 ${auth_keys_file}。${NC}"
        return 0
    else
        echo -e "${RED}[✗] 将公钥写入文件失败。${NC}"
        return 1
    fi
}


configure_ssh_keys() {
    echo -e "\n${CYAN}--- 4.4 配置 SSH 密钥登录 (禁用密码登录) ---${NC}"

    local key_config_choice
    while true; do
        echo -e "请选择操作:"
        echo -e "  ${YELLOW}1.${NC} 添加公钥 (粘贴公钥内容让脚本添加)"
        echo -e "  ${YELLOW}2.${NC} 禁用 SSH 密码登录 ${RED}(高风险! 请确保密钥已添加并测试成功)${NC}"
        echo -e "  ${YELLOW}0.${NC} 返回 SSH 安全菜单"
        read -p "请输入选项 [0-2]: " key_config_choice

        case $key_config_choice in
            1)
                local target_user
                read -p "请输入要为其添加公钥的用户名: " target_user
                if [[ -n "$target_user" ]]; then
                    add_public_key "$target_user"
                else
                    echo -e "${YELLOW}用户名不能为空。${NC}"
                fi
                read -p "按 Enter键 继续..."
                ;;
            2)
                echo -e "${RED}[!] 警告：这是高风险操作！在禁用密码登录前，请务必完成以下步骤：${NC}"
                echo -e "${YELLOW}  1. 在您的本地计算机上生成 SSH 密钥对 (例如使用 'ssh-keygen')。${NC}"
                echo -e "${YELLOW}  2. 使用上面的【选项1】或其他方法，将您的【公钥】复制到服务器上目标用户的 ~/.ssh/authorized_keys 文件中。${NC}"
                echo -e "${YELLOW}  3. 【重要】在禁用密码登录【之前】，打开一个新的终端窗口，尝试使用【密钥】登录服务器，确保可以成功登录！${NC}"

                if ! confirm_action "您是否已经完成上述所有步骤，并确认可以通过密钥成功登录?"; then
                    echo "操作已取消。请先确保密钥设置正确并可成功登录。"
                    continue # 返回循环，让用户重新选择
                fi

                echo -e "${BLUE}[*] 修改 SSH 配置文件 ($SSHD_CONFIG) 以启用密钥登录并禁用密码登录...${NC}"
                # 备份
                cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak_key_$(date +%F_%T)"

                # 确保 PubkeyAuthentication 为 yes (通常默认是)
                update_or_add_config "$SSHD_CONFIG" "" "PubkeyAuthentication" "yes" # 在全局部分设置
                if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 修改 SSH 配置文件失败 (PubkeyAuthentication)。${NC}"; continue; fi


                # 禁用 PasswordAuthentication
                update_or_add_config "$SSHD_CONFIG" "" "PasswordAuthentication" "no"
                 if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 修改 SSH 配置文件失败 (PasswordAuthentication)。${NC}"; continue; fi

                # 可选：禁用 ChallengeResponseAuthentication (也与密码相关)
                update_or_add_config "$SSHD_CONFIG" "" "ChallengeResponseAuthentication" "no"
                 if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 修改 SSH 配置文件失败 (ChallengeResponseAuthentication)。${NC}"; continue; fi

                # 可选：禁用 UsePAM (如果仅用密钥，通常可以禁用，但需谨慎测试)
                # update_or_add_config "$SSHD_CONFIG" "" "UsePAM" "no"
                echo -e "${YELLOW}[!] UsePAM 设置未修改，保持默认。${NC}"

                echo -e "${BLUE}[*] 重启 SSH 服务以应用更改...${NC}"
                systemctl restart sshd
                sleep 2
                if systemctl is-active --quiet sshd; then
                    echo -e "${GREEN}[✓] SSH 已配置为仅允许密钥登录，密码登录已禁用。${NC}"
                    echo -e "${RED}请立即尝试使用密钥重新登录以确认！如果无法登录，您可能需要通过控制台或其他方式恢复备份配置 (${SSHD_CONFIG}.bak_key_*)。${NC}"
                else
                    echo -e "${RED}[✗] SSH 服务重启失败！请检查配置。密码登录可能仍然启用。${NC}"
                    echo -e "${RED}   旧配置已备份为 ${SSHD_CONFIG}.bak_key_* 。${NC}"
                    # return 1 # 不退出函数，让用户可以返回菜单
                fi
                read -p "按 Enter键 继续..."
                ;;
            0) break ;; # 退出循环返回 SSH 菜单
            *) echo -e "${RED}无效选项。${NC}" ;;
        esac
    done

}

manage_ssh_security() {
     while true; do
        echo -e "\n${CYAN}--- SSH 安全管理 ---${NC}"
        echo -e " 当前 SSH 端口: ${YELLOW}${CURRENT_SSH_PORT}${NC}"
        echo -e " ${YELLOW}1.${NC} 更改 SSH 端口 (自动更新 UFW, Fail2ban)"
        echo -e " ${YELLOW}2.${NC} 创建新的 Sudo 用户"
        echo -e " ${YELLOW}3.${NC} 禁用 Root 用户 SSH 登录"
        echo -e " ${YELLOW}4.${NC} 配置 SSH 密钥登录与密码禁用"
        echo -e " ${YELLOW}0.${NC} 返回主菜单"
        read -p "请输入选项 [0-4]: " ssh_choice

        case $ssh_choice in
            1) change_ssh_port ;;
            2) create_sudo_user ;;
            3) disable_root_login ;;
            4) configure_ssh_keys ;;
            0) break ;;
            *) echo -e "${RED}无效选项。${NC}" ;;
        esac
        [[ $ssh_choice != 0 ]] && read -p "按 Enter键 继续..."
        check_root # 每次操作后重新检查 SSH 端口
    done
}


# --- 5. Web 服务 (Let's Encrypt + Cloudflare + Nginx) ---
# (这部分函数基本保持不变，仅调整菜单入口)
# get_user_input_initial, update_paths_for_domain, create_cf_credentials, detect_public_ip,
# select_record_type, get_zone_id, manage_cloudflare_record, request_certificate,
# copy_certificate, setup_nginx_proxy, create_ddns_script, setup_cron_jobs,
# save_domain_config, load_domain_config, list_configured_domains, delete_domain_config,
# add_new_domain

# --- 原有函数保持不变 (仅列出函数名，代码省略以保持简洁) ---
get_user_input_initial() {
    # 重置可能影响本次设置的全局变量 (EMAIL 除外)
    DOMAIN="" CF_API_TOKEN="" DDNS_FREQUENCY=5 RECORD_TYPE="" SELECTED_IP="" ZONE_ID="" ZONE_NAME="" LOCAL_PROXY_PASS="" BACKEND_PROTOCOL="http" INSTALL_NGINX="no" NGINX_HTTP_PORT=80 NGINX_HTTPS_PORT=443

    echo -e "${BLUE}[*] 请输入首次设置所需信息:${NC}"
    echo -e "${YELLOW}Let's Encrypt 注册邮箱已固定为: ${EMAIL}${NC}" # 提示用户邮箱已固定
    while [[ -z "$DOMAIN" ]]; do read -p "请输入您要申请/管理的域名 (例如 my.example.com): " DOMAIN; done
    # 校验域名格式 (简单校验)
    if ! [[ "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}[✗] 域名格式似乎不正确。${NC}"; exit 1;
    fi
    # 检查域名是否已存在配置
    if [[ -f "${CONFIG_DIR}/${DOMAIN}.conf" ]]; then
        echo -e "${YELLOW}[!] 域名 ${DOMAIN} 的配置已存在。如果您想修改，请先删除旧配置。${NC}"
        exit 1
    fi
    while [[ -z "$CF_API_TOKEN" ]]; do read -p "请输入您的 Cloudflare API Token: " CF_API_TOKEN; done
    # 不再提示输入邮箱
    while true; do
        read -p "请输入 DDNS 自动更新频率 (分钟, 输入 0 禁用 DDNS, 默认 5): " freq_input
        if [[ -z "$freq_input" ]]; then DDNS_FREQUENCY=5; echo -e "DDNS 更新频率设置为: ${GREEN}5 分钟${NC}"; break;
        elif [[ "$freq_input" =~ ^[0-9]+$ ]]; then
            DDNS_FREQUENCY=$freq_input
            if [[ "$DDNS_FREQUENCY" -eq 0 ]]; then echo -e "${YELLOW}DDNS 功能已禁用。${NC}"; else echo -e "DDNS 更新频率设置为: ${GREEN}${DDNS_FREQUENCY} 分钟${NC}"; fi; break;
        else echo -e "${YELLOW}请输入一个非负整数。${NC}"; fi
    done
    # 更新基于域名的路径变量
    update_paths_for_domain "$DOMAIN"
}

update_paths_for_domain() {
    local current_domain="$1"
    # 证书存放路径
    CERT_PATH="${CERT_PATH_PREFIX}/${current_domain}"
    # Cloudflare 凭证文件
    CLOUDFLARE_CREDENTIALS="/root/.cloudflare-${current_domain}.ini"
    # 证书续期钩子脚本
    DEPLOY_HOOK_SCRIPT="/root/cert-renew-hook-${current_domain}.sh"
    # DDNS 更新脚本
    DDNS_SCRIPT_PATH="/usr/local/bin/cf_ddns_update_${current_domain}.sh"
    # Nginx 配置文件
    NGINX_CONF_PATH="/etc/nginx/sites-available/${current_domain}.conf"
}

create_cf_credentials() {
    echo -e "${BLUE}[*] 创建 Cloudflare API 凭证文件...${NC}"
    # 确保目录存在
    mkdir -p "$(dirname "$CLOUDFLARE_CREDENTIALS")"
    # 写入凭证信息
    cat > "$CLOUDFLARE_CREDENTIALS" <<EOF
# Cloudflare API credentials used by Certbot for domain: ${DOMAIN}
dns_cloudflare_api_token = $CF_API_TOKEN
EOF
    # 设置文件权限为 600，仅所有者可读写
    chmod 600 "$CLOUDFLARE_CREDENTIALS"
    echo -e "${GREEN}[✓] 凭证文件创建成功: ${CLOUDFLARE_CREDENTIALS}${NC}"
}

detect_public_ip() {
    echo -e "${BLUE}[*] 检测公网 IP 地址...${NC}"
    # 尝试多个源获取 IPv4 地址，设置超时时间
    DETECTED_IPV4=$(curl -4s --max-time 5 https://api.ipify.org || curl -4s --max-time 5 https://ifconfig.me/ip || echo "")
    # 尝试多个源获取 IPv6 地址，设置超时时间
    DETECTED_IPV6=$(curl -6s --max-time 5 https://api64.ipify.org || curl -6s --max-time 5 https://ifconfig.me/ip || echo "")
    echo "检测结果:"
    if [[ -n "$DETECTED_IPV4" ]]; then echo -e "  - IPv4: ${GREEN}$DETECTED_IPV4${NC}"; else echo -e "  - IPv4: ${RED}未检测到${NC}"; fi
    if [[ -n "$DETECTED_IPV6" ]]; then echo -e "  - IPv6: ${GREEN}$DETECTED_IPV6${NC}"; else echo -e "  - IPv6: ${RED}未检测到${NC}"; fi
    # 如果 IPv4 和 IPv6 都没检测到，则报错退出
    if [[ -z "$DETECTED_IPV4" && -z "$DETECTED_IPV6" ]]; then echo -e "${RED}[✗] 无法检测到任何公网 IP 地址。脚本无法继续。${NC}"; exit 1; fi
}

select_record_type() {
    echo -e "${BLUE}[*] 请选择要使用的 DNS 记录类型和 IP 地址:${NC}"
    options=() ips=() types=()
    # 如果检测到 IPv4，添加到选项
    if [[ -n "$DETECTED_IPV4" ]]; then options+=("IPv4 (A 记录) - ${DETECTED_IPV4}"); ips+=("$DETECTED_IPV4"); types+=("A"); fi
    # 如果检测到 IPv6，添加到选项
    if [[ -n "$DETECTED_IPV6" ]]; then options+=("IPv6 (AAAA 记录) - ${DETECTED_IPV6}"); ips+=("$DETECTED_IPV6"); types+=("AAAA"); fi
    options+=("退出")

    # 使用 select 让用户选择
    select opt in "${options[@]}"; do
        choice_index=$((REPLY - 1)) # REPLY 是 select 命令内置变量，表示用户输入的序号
        if [[ "$opt" == "退出" ]]; then echo "用户选择退出。"; exit 0;
        # 检查用户选择是否在有效范围内
        elif [[ $choice_index -ge 0 && $choice_index -lt ${#ips[@]} ]]; then
            RECORD_TYPE=${types[$choice_index]}; SELECTED_IP=${ips[$choice_index]}
            echo -e "已选择: ${GREEN}${RECORD_TYPE} - $SELECTED_IP${NC}"; break # 选择成功，跳出循环
        else echo "无效选项 $REPLY"; fi
    done
    # 如果循环结束还没有选择有效的类型或 IP，则退出
    if [[ -z "$RECORD_TYPE" || -z "$SELECTED_IP" ]]; then echo -e "${RED}[✗] 未选择有效的记录类型或 IP 地址。脚本无法继续。${NC}"; exit 1; fi
}

get_zone_id() {
    echo -e "${BLUE}[*] 获取 Cloudflare Zone ID...${NC}"
    # 从完整域名中提取 Zone Name (通常是最后两部分，例如 a.b.c.com -> b.c.com)
    # 注意：对于 com.cn 这类域名，此方法可能不准确，但对大多数常见域名有效
    ZONE_NAME=$(echo "$DOMAIN" | awk -F. '{if (NF>2) print $(NF-1)"."$NF; else print $0}')
    echo "尝试获取 Zone Name: $ZONE_NAME"

    # 调用 Cloudflare API 获取 Zone 信息
    ZONE_ID_JSON=$(curl -s --max-time 10 -X GET "$CF_API/zones?name=$ZONE_NAME&status=active" \
         -H "Authorization: Bearer $CF_API_TOKEN" \
         -H "Content-Type: application/json")

    # 检查 curl 命令是否执行成功
    if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API 失败 (网络错误或超时)。${NC}"; exit 1; fi

    # 使用 jq 解析 JSON，检查 API 调用是否成功
    if [[ $(echo "$ZONE_ID_JSON" | jq -r '.success') != "true" ]]; then
        # 提取错误信息
        local error_msg=$(echo "$ZONE_ID_JSON" | jq -r '.errors[0].message // "未知 API 错误"')
        echo -e "${RED}[✗] Cloudflare API 返回错误: ${error_msg}${NC}"; exit 1;
    fi

    # 提取 Zone ID
    ZONE_ID=$(echo "$ZONE_ID_JSON" | jq -r '.result[0].id')

    # 检查是否成功获取 Zone ID
    if [[ "$ZONE_ID" == "null" || -z "$ZONE_ID" ]]; then
        echo -e "${RED}[✗] 无法找到域名 $ZONE_NAME 对应的活动 Zone ID。请检查域名和 API Token 是否正确。${NC}"; exit 1;
    fi
    echo -e "${GREEN}[✓] 找到 Zone ID: $ZONE_ID${NC}"
}

manage_cloudflare_record() {
    local action="$1" # "create" or "update" (主要用于日志信息)
    echo -e "${BLUE}[*] ${action} Cloudflare DNS 记录 ($RECORD_TYPE)...${NC}"
    echo "正在检查 $DOMAIN 的 $RECORD_TYPE 记录..."

    # 调用 API 获取指定域名和类型的 DNS 记录信息
    RECORD_INFO=$(curl -s --max-time 10 -X GET "$CF_API/zones/$ZONE_ID/dns_records?type=$RECORD_TYPE&name=$DOMAIN" \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json")

    if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (获取记录) 失败。${NC}"; exit 1; fi
    if [[ $(echo "$RECORD_INFO" | jq -r '.success') != "true" ]]; then
        echo -e "${RED}[✗] Cloudflare API 返回错误 (获取记录): $(echo "$RECORD_INFO" | jq -r '.errors[0].message // "未知 API 错误"')${NC}"; exit 1;
    fi

    # 提取记录 ID 和当前 IP
    RECORD_ID=$(echo "$RECORD_INFO" | jq -r '.result[0].id');
    CURRENT_IP=$(echo "$RECORD_INFO" | jq -r '.result[0].content')

    # 如果记录 ID 为空或 null，表示记录不存在
    if [[ "$RECORD_ID" == "null" || -z "$RECORD_ID" ]]; then
        echo "未找到 $RECORD_TYPE 记录，正在创建..."
        # 调用 API 创建新记录
        CREATE_RESULT=$(curl -s --max-time 10 -X POST "$CF_API/zones/$ZONE_ID/dns_records" \
            -H "Authorization: Bearer $CF_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"$RECORD_TYPE\",\"name\":\"$DOMAIN\",\"content\":\"$SELECTED_IP\",\"ttl\":120,\"proxied\":false}") # ttl=120 (2分钟), proxied=false (DNS only)

        if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (创建记录) 失败。${NC}"; exit 1; fi
        if [[ $(echo "$CREATE_RESULT" | jq -r '.success') == "true" ]]; then
            echo -e "${GREEN}[✓] $RECORD_TYPE 记录创建成功: $DOMAIN -> $SELECTED_IP${NC}";
        else
            echo -e "${RED}[✗] 创建 $RECORD_TYPE 记录失败: $(echo "$CREATE_RESULT" | jq -r '.errors[0].message // "未知 API 错误"')${NC}"; exit 1;
        fi
    else
        # 记录已存在
        echo "找到 $RECORD_TYPE 记录 (ID: $RECORD_ID)，当前 Cloudflare 记录 IP: $CURRENT_IP"
        # 检查当前记录的 IP 是否与选择的 IP 一致
        if [[ "$CURRENT_IP" != "$SELECTED_IP" ]]; then
            echo "IP 地址不匹配 ($CURRENT_IP != $SELECTED_IP)，正在更新..."
            # 调用 API 更新记录
            UPDATE_RESULT=$(curl -s --max-time 10 -X PUT "$CF_API/zones/$ZONE_ID/dns_records/$RECORD_ID" \
                -H "Authorization: Bearer $CF_API_TOKEN" \
                -H "Content-Type: application/json" \
                --data "{\"type\":\"$RECORD_TYPE\",\"name\":\"$DOMAIN\",\"content\":\"$SELECTED_IP\",\"ttl\":120,\"proxied\":false}")

            if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (更新记录) 失败。${NC}"; exit 1; fi
            if [[ $(echo "$UPDATE_RESULT" | jq -r '.success') == "true" ]]; then
                echo -e "${GREEN}[✓] $RECORD_TYPE 记录更新成功: $DOMAIN -> $SELECTED_IP${NC}";
            else
                echo -e "${RED}[✗] 更新 $RECORD_TYPE 记录失败: $(echo "$UPDATE_RESULT" | jq -r '.errors[0].message // "未知 API 错误"')${NC}"; exit 1;
            fi
        else
            # IP 地址一致，无需更新
            echo -e "${GREEN}[✓] $RECORD_TYPE 记录已是最新 ($CURRENT_IP)，无需更新。${NC}";
        fi
    fi
}

request_certificate() {
    echo -e "${BLUE}[*] 申请 SSL 证书 (Let's Encrypt)...${NC}"
    # 使用 certbot 和 Cloudflare DNS 插件申请证书
    # --dns-cloudflare-propagation-seconds: 等待 DNS 记录生效的时间
    # --agree-tos: 同意 Let's Encrypt 服务条款
    # --no-eff-email: 不同意 EFF 分享邮箱
    # --non-interactive: 非交互模式
    certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$CLOUDFLARE_CREDENTIALS" \
        --dns-cloudflare-propagation-seconds 60 \
        -d "$DOMAIN" \
        --email "$EMAIL" \
        --agree-tos \
        --no-eff-email \
        --non-interactive

    # 检查证书文件是否存在
    if [[ ! -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" || ! -f "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" ]]; then
        echo -e "${RED}[✗] 证书申请失败。请检查 certbot 日志 (/var/log/letsencrypt/letsencrypt.log) 获取详细信息。${NC}"; exit 1;
    fi
    echo -e "${GREEN}[✓] SSL 证书申请成功！${NC}"
}

copy_certificate() {
    echo -e "${BLUE}[*] 复制证书文件到 $CERT_PATH ...${NC}"
    mkdir -p "$CERT_PATH"
    # 使用 -L 选项复制符号链接指向的实际文件
    cp -L "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$CERT_PATH/"
    cp -L "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$CERT_PATH/"
    cp -L "/etc/letsencrypt/live/${DOMAIN}/chain.pem" "$CERT_PATH/"
    cp -L "/etc/letsencrypt/live/${DOMAIN}/cert.pem" "$CERT_PATH/"
    # 可选：设置权限，确保 Nginx 等服务可以读取
    # chmod 644 ${CERT_PATH}/*.pem
    # chown www-data:www-data ${CERT_PATH}/*.pem # 如果 Nginx 以 www-data 运行
    echo -e "${GREEN}[✓] 证书文件已复制到 $CERT_PATH ${NC}"
}

setup_nginx_proxy() {
    # 询问用户是否需要配置 Nginx
    if ! confirm_action "是否需要自动配置 Nginx 反向代理?"; then
        echo "跳过 Nginx 配置。"
        INSTALL_NGINX="no" # 确保不尝试安装 Nginx
        # 即使不配置 Nginx，也需要设置默认端口值，以便保存配置
        NGINX_HTTP_PORT=80
        NGINX_HTTPS_PORT=443
        LOCAL_PROXY_PASS="none" # 标记未配置
        BACKEND_PROTOCOL="none" # 标记未配置
        return
    fi

    # 如果用户选择 'yes'，则标记需要安装 Nginx
    INSTALL_NGINX="yes"
    # install_packages 在 add_new_domain 主流程中调用，这里不再重复调用

    # --- 获取自定义端口 ---
    while true; do
        read -p "请输入 Nginx 监听的 HTTP 端口 [默认: ${NGINX_HTTP_PORT}]: " http_port_input
        if [[ -z "$http_port_input" ]]; then
            # 用户直接回车，使用默认值
            break
        elif [[ "$http_port_input" =~ ^[0-9]+$ && "$http_port_input" -gt 0 && "$http_port_input" -le 65535 ]]; then
            # 输入有效端口号
            NGINX_HTTP_PORT=$http_port_input
            break
        else
            echo -e "${YELLOW}无效端口号。请输入 1-65535 之间的数字，或直接回车使用默认值。${NC}"
        fi
    done
    echo -e "Nginx HTTP 端口设置为: ${GREEN}${NGINX_HTTP_PORT}${NC}"

    while true; do
         read -p "请输入 Nginx 监听的 HTTPS 端口 [默认: ${NGINX_HTTPS_PORT}]: " https_port_input
         if [[ -z "$https_port_input" ]]; then
             # 用户直接回车，使用默认值
             break
         elif [[ "$https_port_input" =~ ^[0-9]+$ && "$https_port_input" -gt 0 && "$https_port_input" -le 65535 ]]; then
             # 输入有效端口号
             # 检查是否与 HTTP 端口冲突
             if [[ "$https_port_input" -eq "$NGINX_HTTP_PORT" ]]; then
                 echo -e "${YELLOW}HTTPS 端口不能与 HTTP 端口 (${NGINX_HTTP_PORT}) 相同。${NC}"
             else
                 NGINX_HTTPS_PORT=$https_port_input
                 break
             fi
         else
             echo -e "${YELLOW}无效端口号。请输入 1-65535 之间的数字，或直接回车使用默认值。${NC}"
         fi
    done
    echo -e "Nginx HTTPS 端口设置为: ${GREEN}${NGINX_HTTPS_PORT}${NC}"
    # --- 端口获取结束 ---


    # --- 使用数字选择后端协议 ---
    while true; do
        read -p "请选择后端服务 (${DOMAIN}) 使用的协议: [1] http (默认) [2] https : " proto_choice
        if [[ -z "$proto_choice" || "$proto_choice" == "1" ]]; then
            BACKEND_PROTOCOL="http"
            break
        elif [[ "$proto_choice" == "2" ]]; then
            BACKEND_PROTOCOL="https"
            break
        else
            echo -e "${YELLOW}无效输入，请输入 1 或 2。${NC}"
        fi
    done
    echo -e "后端服务协议设置为: ${GREEN}${BACKEND_PROTOCOL}${NC}"
    # --- 协议选择修改结束 ---

    # 询问后端服务地址和端口
    while [[ -z "$LOCAL_PROXY_PASS" ]]; do
        read -p "请输入 Nginx 需要反向代理的本地服务地址 (只需 IP/域名 和 端口, 例如 localhost:8080 或 192.168.1.10:3000): " addr_input
        # 简单校验格式：包含字母数字点横线，后跟冒号和数字
        if [[ "$addr_input" =~ ^[a-zA-Z0-9.-]+:[0-9]+$ ]]; then
            LOCAL_PROXY_PASS="${BACKEND_PROTOCOL}://${addr_input}"
            echo -e "将使用代理地址: ${GREEN}${LOCAL_PROXY_PASS}${NC}"
        else echo -e "${YELLOW}地址格式似乎不正确，请确保是 '地址:端口' 格式。${NC}"; LOCAL_PROXY_PASS=""; fi
    done

    echo -e "${BLUE}[*] 生成 Nginx 配置文件: $NGINX_CONF_PATH ...${NC}"
    # 确保 Nginx 配置目录存在
    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
    # 确保 Certbot http-01 验证的根目录存在
    mkdir -p /var/www/html/.well-known/acme-challenge
    # 尝试设置权限，如果 www-data 用户/组不存在，则忽略错误
    chown www-data:www-data /var/www/html -R 2>/dev/null || echo -e "${YELLOW}[!] 无法设置 /var/www/html 权限 (可能 www-data 用户/组不存在)，通常不影响 Certbot DNS 验证。${NC}"

    # --- 修复 V2.6: 在 Bash 中预处理跳转端口后缀 ---
    local redirect_suffix_bash=""
    if [[ "${NGINX_HTTPS_PORT}" -ne 443 ]]; then
        redirect_suffix_bash=":${NGINX_HTTPS_PORT}"
    fi
    # --- 修复结束 ---

    # --- Nginx 配置模板 (使用预处理的跳转后缀) ---
    cat > "$NGINX_CONF_PATH" <<EOF
server {
    # 使用自定义 HTTP 端口
    listen ${NGINX_HTTP_PORT};
    listen [::]:${NGINX_HTTP_PORT};
    server_name ${DOMAIN};

    # Certbot ACME Challenge 路径 (优先处理)
    location ~ /.well-known/acme-challenge/ {
        allow all;
        root /var/www/html; # 确保此路径存在且 Nginx 有权访问
    }

    # 其他所有请求跳转到 HTTPS
    location / {
        # 使用 301 永久重定向
        # 使用在 Bash 中预处理好的端口后缀 ${redirect_suffix_bash}
        return 301 https://\$host${redirect_suffix_bash}\$request_uri;
    }
}

server {
    # 启用 SSL 和 HTTP/2，并使用自定义 HTTPS 端口
    listen ${NGINX_HTTPS_PORT} ssl http2;
    listen [::]:${NGINX_HTTPS_PORT} ssl http2;
    server_name ${DOMAIN};

    # SSL 证书路径 (使用复制后的路径)
    ssl_certificate ${CERT_PATH}/fullchain.pem;
    ssl_certificate_key ${CERT_PATH}/privkey.pem;

    # SSL 安全配置 (参考 Mozilla Intermediate compatibility - https://ssl-config.mozilla.org/)
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m; # approx 40,000 sessions
    ssl_session_tickets off; # 禁用 session tickets，增强安全性

    # 推荐的协议和加密套件
    ssl_protocols TLSv1.2 TLSv1.3; # 推荐仅使用 TLS 1.2 和 1.3
    # 推荐的加密套件 (兼容性较好且安全)
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off; # 客户端优先选择加密套件

    # === 安全性增强 ===
    # HSTS (HTTP Strict Transport Security) - 强制浏览器始终使用 HTTPS 访问
    # max-age=15768000 秒 (大约 6 个月). 首次部署建议使用较短时间 (如 300 秒) 测试，确认无误后再加长。
    # includeSubDomains 可选，如果所有子域名也都强制 HTTPS 才添加。
    # preload 可选，如果希望加入浏览器 HSTS 预加载列表 (需要更严格的要求)。
    # 注意：如果使用非标准 HTTPS 端口，HSTS 预加载可能无法工作。
    add_header Strict-Transport-Security "max-age=15768000" always;

    # 其他可选安全头 (根据需要取消注释)
    # add_header X-Frame-Options "SAMEORIGIN" always; # 防止点击劫持
    # add_header X-Content-Type-Options "nosniff" always; # 防止 MIME 类型嗅探攻击
    # add_header Referrer-Policy "strict-origin-when-cross-origin" always; # 控制 Referer 头发送策略
    # add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';" always; # 内容安全策略 (需要仔细配置)
    # add_header Permissions-Policy "interest-cohort=()" always; # 禁用 Google FLoC 跟踪

    # OCSP Stapling (提高 SSL 握手性能，减少客户端验证延迟)
    # 需要确保 Nginx 可以访问 Let's Encrypt 的 OCSP 服务器
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate ${CERT_PATH}/chain.pem; # 需要 CA 链文件 (fullchain.pem 通常包含)
    # 使用公共 DNS 或本地 DNS
    resolver 1.1.1.1 8.8.8.8 valid=300s; # 使用 Cloudflare 和 Google DNS
    resolver_timeout 5s;

    # === 反向代理配置 ===
    location / {
        proxy_pass ${LOCAL_PROXY_PASS}; # 使用包含协议的完整后端地址

        # 设置必要的代理头，将客户端信息传递给后端
        proxy_set_header Host \$host; # 传递原始请求的 Host 头
        proxy_set_header X-Real-IP \$remote_addr; # 传递客户端真实 IP
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; # 传递经过的所有代理 IP 列表
        proxy_set_header X-Forwarded-Proto \$scheme; # 告知后端请求是 http 还是 https
        # 注意：如果 Nginx 监听非标准 HTTPS 端口，后端可能需要 X-Forwarded-Port 来正确构建 URL
        proxy_set_header X-Forwarded-Host \$host; # 某些应用可能需要
        proxy_set_header X-Forwarded-Port \$server_port; # 传递 Nginx 监听的端口

        # 如果后端是 HTTPS，可能需要以下配置
        # proxy_ssl_server_name on; # 传递 SNI (Server Name Indication) 给后端，允许多证书主机使用
        $( [[ "$BACKEND_PROTOCOL" == "https" ]] && echo '        proxy_ssl_server_name on;' )
        # 如果后端使用的是自签名证书或不受信任的 CA 证书，取消注释下一行 (会降低安全性!)
        # proxy_ssl_verify off;
        # $( [[ "$BACKEND_PROTOCOL" == "https" ]] && echo '        # proxy_ssl_verify off;' ) # 默认保持注释

        # WebSocket support (如果后端应用需要 WebSocket)
        # proxy_http_version 1.1;
        # proxy_set_header Upgrade \$http_upgrade;
        # proxy_set_header Connection "upgrade";

        # 增加超时设置 (可选，根据后端应用响应时间调整)
        # proxy_connect_timeout 60s;
        # proxy_send_timeout 60s;
        # proxy_read_timeout 60s;

        # 缓冲区设置 (可选，根据需要调整)
        # proxy_buffering on;
        # proxy_buffers 8 16k;
        # proxy_buffer_size 32k;
        # proxy_busy_buffers_size 64k;
    }

    # 可选：自定义错误页面
    # error_page 500 502 503 504 /50x.html;
    # location = /50x.html {
    #     root /usr/share/nginx/html; # 指向 Nginx 默认错误页面目录或自定义目录
    # }
}
EOF
    # --- Nginx 配置模板结束 ---

    # 创建软链接到 sites-enabled 目录以启用配置
    if [[ ! -L "/etc/nginx/sites-enabled/${DOMAIN}.conf" ]]; then
        ln -s "$NGINX_CONF_PATH" "/etc/nginx/sites-enabled/${DOMAIN}.conf"
        echo -e "${GREEN}[✓] Nginx 配置已启用 (创建软链接)。${NC}"
    else
        echo -e "${YELLOW}[!] Nginx 配置软链接已存在，跳过创建。${NC}";
    fi

    # 检查 Nginx 配置语法并尝试重载
    echo -e "${BLUE}[*] 检查 Nginx 配置并尝试重载...${NC}"
    # 使用 nginx -t -c /etc/nginx/nginx.conf 确保加载主配置文件进行测试
    if nginx -t -c /etc/nginx/nginx.conf; then
        # 配置检查通过
        systemctl reload nginx
        if systemctl is-active --quiet nginx; then
            echo -e "${GREEN}[✓] Nginx 配置检查通过并已成功重载。${NC}"
            echo -e "${YELLOW}提示：Nginx 正在监听 HTTP 端口 ${NGINX_HTTP_PORT} 和 HTTPS 端口 ${NGINX_HTTPS_PORT}。${NC}"
            # 增加防火墙提示
            if command_exists ufw && ufw status | grep -q "Status: active"; then
                 echo -e "${BLUE}[*] 尝试在 UFW 中允许 Nginx 端口 ${NGINX_HTTP_PORT} 和 ${NGINX_HTTPS_PORT}...${NC}"
                 ufw allow ${NGINX_HTTP_PORT}/tcp comment "Nginx HTTP" > /dev/null
                 ufw allow ${NGINX_HTTPS_PORT}/tcp comment "Nginx HTTPS" > /dev/null
                 echo -e "${GREEN}[✓] 已尝试添加 UFW 规则。请使用 '查看 UFW 规则' 确认。${NC}"
            elif [[ "$NGINX_HTTP_PORT" -ne 80 || "$NGINX_HTTPS_PORT" -ne 443 ]]; then
                echo -e "${YELLOW}重要提示：请确保防火墙 (如 ufw, firewalld) 允许访问您设置的自定义端口 (${NGINX_HTTP_PORT} 和 ${NGINX_HTTPS_PORT})！${NC}"
            fi
            echo -e "${YELLOW}访问时，如果 HTTPS 端口不是 443，URL 中需要包含端口号，例如: https://${DOMAIN}:${NGINX_HTTPS_PORT}${NC}"

        else
            echo -e "${RED}[✗] Nginx 重载后状态异常，请检查 Nginx 服务状态和日志。${NC}"
        fi
    else
        # 配置检查失败
        echo -e "${RED}[✗] Nginx 配置检查失败！请手动检查 ${NGINX_CONF_PATH} 文件以及 Nginx 主配置文件中的错误。${NC}"; exit 1;
    fi
}

create_ddns_script() {
    # 如果 DDNS 频率设置为 0 或负数，则不创建脚本
    if [[ "$DDNS_FREQUENCY" -le 0 ]]; then
        echo "${YELLOW}DDNS 已禁用，跳过创建 DDNS 更新脚本。${NC}";
        # 如果旧的 DDNS 脚本存在，可以选择删除它
        if [[ -f "$DDNS_SCRIPT_PATH" ]]; then
            echo "${YELLOW}检测到旧的 DDNS 脚本 $DDNS_SCRIPT_PATH，正在删除...${NC}"
            rm -f "$DDNS_SCRIPT_PATH"
        fi
        return;
    fi

    echo -e "${BLUE}[*] 创建 DDNS 更新脚本: $DDNS_SCRIPT_PATH ...${NC}"
    mkdir -p "$(dirname "$DDNS_SCRIPT_PATH")"
    # 从凭证文件中读取 API Token (避免硬编码在脚本中)
    local current_token=$(grep dns_cloudflare_api_token "$CLOUDFLARE_CREDENTIALS" | awk '{print $3}')
    if [[ -z "$current_token" ]]; then
        echo -e "${RED}[✗] 无法从 $CLOUDFLARE_CREDENTIALS 读取 API Token，无法创建 DDNS 脚本。${NC}"; return;
    fi

    # --- DDNS 更新脚本模板 ---
    cat > "$DDNS_SCRIPT_PATH" <<EOF
#!/bin/bash
# --- DDNS 更新脚本 for ${DOMAIN} (由主脚本自动生成) ---

# --- 配置 ---
# Cloudflare 凭证文件路径 (包含 API Token)
CF_CREDENTIALS_FILE="/root/.cloudflare-${DOMAIN}.ini"
# 要更新的域名
DOMAIN="${DOMAIN}"
# 要更新的记录类型 (A 或 AAAA)
RECORD_TYPE="${RECORD_TYPE}"
# Cloudflare Zone ID
ZONE_ID="${ZONE_ID}"
# Cloudflare API 地址
CF_API="https://api.cloudflare.com/client/v4"
# 日志文件路径
LOG_FILE="/var/log/cf_ddns_update_${DOMAIN}.log"
# API 请求超时时间 (秒)
TIMEOUT=10
# 获取 IP 的地址 (可以添加更多备用地址)
IPV4_URLS=("https://api.ipify.org" "https://ifconfig.me/ip" "https://ipv4.icanhazip.com")
IPV6_URLS=("https://api64.ipify.org" "https://ifconfig.me/ip" "https://ipv6.icanhazip.com")

# --- 函数 ---
log_message() {
    echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1" >> "\$LOG_FILE"
}

get_current_ip() {
    local type=\$1
    local urls
    local curl_opt
    if [[ "\$type" == "A" ]]; then
        urls=("${IPV4_URLS[@]}")
        curl_opt="-4s"
    elif [[ "\$type" == "AAAA" ]]; then
        urls=("${IPV6_URLS[@]}")
        curl_opt="-6s"
    else
        log_message "Error: Invalid record type specified: \$type"
        return 1
    fi

    local ip=""
    for url in "\${urls[@]}"; do
        ip=\$(curl \$curl_opt --max-time \$TIMEOUT "\$url" 2>/dev/null | head -n 1) # head -n 1 防止某些源返回多余信息
        if [[ -n "\$ip" ]]; then
            # 简单 IP 格式校验
            if [[ "\$type" == "A" && "\$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo "\$ip"; return 0; fi
            # IPv6 校验可以更复杂，这里简化
            if [[ "\$type" == "AAAA" && "\$ip" =~ ^([0-9a-fA-F:]+)$ && "\$ip" == *":"* ]]; then echo "\$ip"; return 0; fi
        fi
        sleep 1 # 避免请求过于频繁
    done
    log_message "Error: Failed to get current public \$type IP address from all sources."
    return 1
}

get_cf_record() {
    local cf_token=\$1
    RECORD_INFO=\$(curl -s --max-time \$TIMEOUT -X GET "\$CF_API/zones/\$ZONE_ID/dns_records?type=\$RECORD_TYPE&name=\$DOMAIN" \
        -H "Authorization: Bearer \$cf_token" \
        -H "Content-Type: application/json")

    if [[ \$? -ne 0 ]]; then log_message "Error: API call failed (Get Record - Network/Timeout)"; return 1; fi
    if [[ \$(echo "\$RECORD_INFO" | jq -r '.success') != "true" ]]; then
        local err_msg=\$(echo "\$RECORD_INFO" | jq -r '.errors[0].message // "Unknown API Error"')
        log_message "Error: API call failed (Get Record): \$err_msg"; return 1;
    fi
    echo "\$RECORD_INFO" # 将 JSON 结果输出
    return 0
}

update_cf_record() {
    local cf_token=\$1
    local record_id=\$2
    local new_ip=\$3
    UPDATE_RESULT=\$(curl -s --max-time \$TIMEOUT -X PUT "\$CF_API/zones/\$ZONE_ID/dns_records/\$record_id" \
        -H "Authorization: Bearer \$cf_token" \
        -H "Content-Type: application/json" \
        --data "{\"type\":\"\$RECORD_TYPE\",\"name\":\"\$DOMAIN\",\"content\":\"\$new_ip\",\"ttl\":120,\"proxied\":false}")

    if [[ \$? -ne 0 ]]; then log_message "Error: API call failed (Update Record - Network/Timeout)"; return 1; fi
    if [[ \$(echo "\$UPDATE_RESULT" | jq -r '.success') != "true" ]]; then
        local err_msg=\$(echo "\$UPDATE_RESULT" | jq -r '.errors[0].message // "Unknown API Error"')
        log_message "Error: API call failed (Update Record): \$err_msg"; return 1;
    fi
    return 0
}

# --- 主逻辑 ---
# 检查日志文件目录是否存在
mkdir -p \$(dirname "\$LOG_FILE")

# 从凭证文件读取 API Token
CF_API_TOKEN=\$(grep dns_cloudflare_api_token "\$CF_CREDENTIALS_FILE" | awk '{print \$3}')
if [[ -z "\$CF_API_TOKEN" ]]; then
    log_message "Error: Failed to read Cloudflare API Token from \$CF_CREDENTIALS_FILE"
    exit 1
fi

# 获取当前公网 IP
CURRENT_IP=\$(get_current_ip "\$RECORD_TYPE")
if [[ \$? -ne 0 ]]; then
    # get_current_ip 函数内部已记录错误
    exit 1
fi
# log_message "Info: Current public IP (\$RECORD_TYPE) detected: \$CURRENT_IP" # 减少日志量，只在需要更新时记录

# 获取 Cloudflare 上的 DNS 记录信息
RECORD_INFO_JSON=\$(get_cf_record "\$CF_API_TOKEN")
if [[ \$? -ne 0 ]]; then exit 1; fi

# 解析记录 ID 和 Cloudflare 上的 IP
CF_IP=\$(echo "\$RECORD_INFO_JSON" | jq -r '.result[0].content')
RECORD_ID=\$(echo "\$RECORD_INFO_JSON" | jq -r '.result[0].id')

if [[ -z "\$RECORD_ID" || "\$RECORD_ID" == "null" ]]; then
    log_message "Error: Could not find existing \$RECORD_TYPE record for \$DOMAIN on Cloudflare."
    # 这里可以选择尝试创建记录，或者直接退出报错
    exit 1
fi

if [[ -z "\$CF_IP" || "\$CF_IP" == "null" ]]; then
    log_message "Error: Failed to parse IP address from Cloudflare record for \$DOMAIN."
    exit 1
fi
# log_message "Info: Cloudflare current IP (\$RECORD_TYPE) for \$DOMAIN: \$CF_IP" # 减少日志量

# 比较 IP 地址
if [[ "\$CURRENT_IP" == "\$CF_IP" ]]; then
    # log_message "Info: IP address matches Cloudflare record (\$CURRENT_IP). No update needed." # 正常情况不输出日志
    exit 0
else
    log_message "Info: IP address mismatch. Current: \$CURRENT_IP, Cloudflare: \$CF_IP. Updating Cloudflare..."
    # 更新 Cloudflare 记录
    update_cf_record "\$CF_API_TOKEN" "\$RECORD_ID" "\$CURRENT_IP"
    if [[ \$? -eq 0 ]]; then
        log_message "Success: Cloudflare DNS record for \$DOMAIN updated successfully to \$CURRENT_IP."
        exit 0
    else
        # update_cf_record 函数内部已记录错误
        exit 1
    fi
fi

exit 0
EOF
    # --- DDNS 更新脚本模板结束 ---

    # 赋予脚本执行权限
    chmod +x "$DDNS_SCRIPT_PATH"
    echo -e "${GREEN}[✓] DDNS 更新脚本创建成功: $DDNS_SCRIPT_PATH ${NC}"
}

setup_cron_jobs() {
    echo -e "${BLUE}[*] 设置 Cron 定时任务...${NC}"

    # 1. 创建证书续期后的部署钩子脚本
    # 这个脚本会在 Certbot 成功续期证书后被调用
    echo -e "${BLUE}[*] 创建证书续期部署钩子脚本: $DEPLOY_HOOK_SCRIPT ...${NC}"
    mkdir -p "$(dirname "$DEPLOY_HOOK_SCRIPT")"
    cat > "$DEPLOY_HOOK_SCRIPT" <<EOF
#!/bin/bash
# Certbot 续期成功后执行的脚本 for ${DOMAIN} (由主脚本自动生成)

LOG_FILE="/var/log/cert_renew_${DOMAIN}.log"
CERT_PATH="${CERT_PATH}" # 使用主脚本中定义的证书副本路径
NGINX_CONF_PATH="${NGINX_CONF_PATH}" # 使用主脚本中定义的 Nginx 配置文件路径
LIVE_CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
# 从主脚本保存的配置中读取 LOCAL_PROXY_PASS
CONFIG_DIR="${CERT_PATH_PREFIX}/.managed_domains" # 确保 CONFIG_DIR 在此脚本中可用
CONFIG_FILE="${CONFIG_DIR}/${DOMAIN}.conf"
LOCAL_PROXY_PASS="none" # 默认值
if [[ -f "\$CONFIG_FILE" ]]; then
    source "\$CONFIG_FILE" # 加载配置以获取 LOCAL_PROXY_PASS
fi


log_hook() {
    echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1" >> "\$LOG_FILE"
}

# 检查日志文件目录是否存在
mkdir -p \$(dirname "\$LOG_FILE")

log_hook "Cert renewed for ${DOMAIN}. Running deploy hook..."

# 检查源证书文件是否存在
if [[ ! -f "\${LIVE_CERT_DIR}/fullchain.pem" || ! -f "\${LIVE_CERT_DIR}/privkey.pem" ]]; then
    log_hook "Error: Source certificate files not found in \${LIVE_CERT_DIR}. Cannot copy."
    exit 1
fi

# 复制新证书到指定目录
log_hook "Copying new certificates from \${LIVE_CERT_DIR} to ${CERT_PATH}..."
cp -L "\${LIVE_CERT_DIR}/fullchain.pem" "${CERT_PATH}/" && \
cp -L "\${LIVE_CERT_DIR}/privkey.pem" "${CERT_PATH}/" && \
cp -L "\${LIVE_CERT_DIR}/chain.pem" "${CERT_PATH}/" && \
cp -L "\${LIVE_CERT_DIR}/cert.pem" "${CERT_PATH}/"

if [[ \$? -ne 0 ]]; then
    log_hook "Error: Failed to copy certificate files."
    # 根据需要决定是否退出，如果 Nginx 依赖这些文件，可能需要退出
    # exit 1
else
    log_hook "Success: Certificates copied to ${CERT_PATH}."
    # 可选：设置权限
    # chmod 644 ${CERT_PATH}/*.pem
fi

# 检查 Nginx 配置文件是否存在，如果存在则重载 Nginx
# 检查 LOCAL_PROXY_PASS 是否为 'none'，如果是，则不尝试重载 Nginx
if [[ "${LOCAL_PROXY_PASS}" != "none" && -f "${NGINX_CONF_PATH}" ]] && command -v nginx >/dev/null 2>&1; then
    log_hook "Nginx config ${NGINX_CONF_PATH} exists and proxy is configured. Reloading Nginx..."
    # 先测试配置是否正确
    nginx -t -c /etc/nginx/nginx.conf # 使用主配置文件测试
    if [[ \$? -eq 0 ]]; then
        # 配置正确，执行重载
        systemctl reload nginx
        if [[ \$? -eq 0 ]]; then
            log_hook "Success: Nginx reloaded successfully."
        else
            log_hook "Error: Failed to reload Nginx. Check systemctl status nginx."
        fi
    else
        log_hook "Error: Nginx configuration test failed (nginx -t). Reload skipped. Please check Nginx config manually!"
    fi
else
    if [[ "${LOCAL_PROXY_PASS}" == "none" ]]; then
      log_hook "Nginx proxy was not configured for this domain. Skipping Nginx reload."
    elif [[ ! -f "${NGINX_CONF_PATH}" ]]; then
      log_hook "Nginx config ${NGINX_CONF_PATH} not found. Skipping Nginx reload."
    else
      log_hook "Nginx command not available. Skipping Nginx reload."
    fi
fi

log_hook "Deploy hook finished for ${DOMAIN}."
exit 0
EOF
    # --- 部署钩子脚本模板结束 ---
    chmod +x "$DEPLOY_HOOK_SCRIPT"
    echo -e "${GREEN}[✓] 证书续期部署钩子脚本创建成功: $DEPLOY_HOOK_SCRIPT ${NC}"

    # 2. 添加或更新 Cron 任务
    # 使用标记来识别和管理由本脚本添加的 Cron 任务
    CRON_TAG_RENEW="# CertRenew_${DOMAIN}"
    CRON_TAG_DDNS="# DDNSUpdate_${DOMAIN}"

    # 先移除旧的、由本脚本为该域名添加的 Cron 任务 (防止重复添加)
    (crontab -l 2>/dev/null | grep -v -F "$CRON_TAG_RENEW" | grep -v -F "$CRON_TAG_DDNS") | crontab -

    # 获取当前 Cron 内容 (移除旧任务后)
    CRON_CONTENT=$(crontab -l 2>/dev/null)

    # 构建新的证书续期 Cron 任务
    # 每天凌晨 3 点执行 certbot renew，并使用部署钩子
    # 将标准输出和错误输出追加到日志文件
    CRON_CERT_RENEW="0 3 * * * certbot renew --deploy-hook \"$DEPLOY_HOOK_SCRIPT\" >> /var/log/certbot_renew.log 2>&1 ${CRON_TAG_RENEW}"

    # 添加证书续期任务到 Cron
    echo "${CRON_CONTENT}"$'\n'"${CRON_CERT_RENEW}" | crontab -
    echo -e "${GREEN}[✓] Cron 证书续期任务已设置 (${DOMAIN})。${NC}"

    # 如果启用了 DDNS，则添加 DDNS 更新任务
    if [[ "$DDNS_FREQUENCY" -gt 0 ]]; then
        # 检查 DDNS 脚本是否存在
        if [[ -f "$DDNS_SCRIPT_PATH" ]]; then
            # 构建 DDNS 更新 Cron 任务
            # 使用 */frequency 语法每隔指定分钟执行一次
            CRON_DDNS_UPDATE="*/${DDNS_FREQUENCY} * * * * $DDNS_SCRIPT_PATH ${CRON_TAG_DDNS}"
            # 再次获取 Cron 内容 (包含证书续期任务)
            CRON_CONTENT=$(crontab -l 2>/dev/null)
            # 添加 DDNS 更新任务到 Cron
            echo "${CRON_CONTENT}"$'\n'"${CRON_DDNS_UPDATE}" | crontab -
            echo -e "${GREEN}[✓] Cron DDNS 更新任务已设置 (${DOMAIN}, 频率: ${DDNS_FREQUENCY} 分钟)。${NC}"
        else
            echo -e "${RED}[✗] DDNS 更新脚本 $DDNS_SCRIPT_PATH 未找到，无法设置 Cron 任务。${NC}"
        fi
    else
        echo -e "${YELLOW}DDNS 已禁用，未设置 DDNS 更新 Cron 任务。${NC}"
    fi
}

save_domain_config() {
    echo -e "${BLUE}[*] 保存域名 ${DOMAIN} 的配置...${NC}"
    mkdir -p "$CONFIG_DIR"
    local config_file="${CONFIG_DIR}/${DOMAIN}.conf"

    # 将需要保存的变量写入配置文件
    # 注意：API Token 会被明文保存在此文件，确保文件权限安全 (root only)
    cat > "$config_file" <<EOF
# Configuration for domain: ${DOMAIN}
# Generated by script on $(date)

DOMAIN="${DOMAIN}"
CF_API_TOKEN="${CF_API_TOKEN}"
EMAIL="${EMAIL}"
CERT_PATH="${CERT_PATH}"
CLOUDFLARE_CREDENTIALS="${CLOUDFLARE_CREDENTIALS}"
DEPLOY_HOOK_SCRIPT="${DEPLOY_HOOK_SCRIPT}"
DDNS_SCRIPT_PATH="${DDNS_SCRIPT_PATH}"
DDNS_FREQUENCY="${DDNS_FREQUENCY}"
RECORD_TYPE="${RECORD_TYPE}"
ZONE_ID="${ZONE_ID}"
NGINX_CONF_PATH="${NGINX_CONF_PATH}"
LOCAL_PROXY_PASS="${LOCAL_PROXY_PASS}"
BACKEND_PROTOCOL="${BACKEND_PROTOCOL}"
NGINX_HTTP_PORT="${NGINX_HTTP_PORT}"
NGINX_HTTPS_PORT="${NGINX_HTTPS_PORT}"
EOF
    chmod 600 "$config_file" # 确保只有 root 可读写
    echo -e "${GREEN}[✓] 配置已保存到: ${config_file}${NC}"
}

load_domain_config() {
    local domain_to_load="$1"
    local config_file="${CONFIG_DIR}/${domain_to_load}.conf"

    if [[ -f "$config_file" ]]; then
        echo -e "${BLUE}[*] 加载域名 ${domain_to_load} 的配置...${NC}"
        # 使用 source (或 .) 命令加载配置文件中的变量
        # 在子 shell 中加载，避免污染当前脚本的全局变量，除非确实需要修改它们
        ( source "$config_file"; \
          # 验证是否成功加载了关键变量
          if [[ -z "$DOMAIN" || -z "$CF_API_TOKEN" || -z "$ZONE_ID" ]]; then \
             echo -e "${RED}[✗] 配置文件 ${config_file} 似乎不完整或加载失败。${NC}"; \
             exit 1; \
          fi )
        if [[ $? -eq 0 ]]; then
            # 如果需要在当前脚本中使用这些变量，则再次 source
             source "$config_file"
             echo -e "${GREEN}[✓] 配置加载成功。${NC}"
             return 0 # 返回成功码
        else
             return 1 # 子 shell 中加载失败
        fi
    else
        echo -e "${RED}[✗] 找不到域名 ${domain_to_load} 的配置文件: ${config_file}${NC}"
        return 1 # 返回错误码
    fi
}

list_configured_domains() {
    echo -e "${BLUE}[*] 当前已配置的 Web 服务域名列表:${NC}"
    mkdir -p "$CONFIG_DIR" # 确保目录存在
    local domains=()
    local i=1
    # 查找配置文件并提取域名
    for config_file in "${CONFIG_DIR}"/*.conf; do
        # 检查是否找到文件以及文件是否可读
        if [[ -f "$config_file" && -r "$config_file" ]]; then
            local domain_name=$(basename "$config_file" .conf)
            echo -e "  ${CYAN}[$i]${NC} $domain_name"
            domains+=("$domain_name")
            ((i++))
        fi
    done

    if [[ ${#domains[@]} -eq 0 ]]; then
        echo -e "${YELLOW}  未找到任何已配置的 Web 服务域名。${NC}"
        return 1 # 返回错误码表示没有域名
    fi
    # 将域名数组返回给调用者（通过全局变量或另一种方式）
    # 这里我们直接在函数内使用，或者让调用者重新扫描
    return 0 # 返回成功码
}

delete_domain_config() {
    echo -e "${RED}[!] 删除 Web 服务域名配置是一个危险操作，将移除相关证书、脚本和配置！${NC}"
    echo -e "${YELLOW}此操作不会删除 Cloudflare 上的 DNS 记录。${NC}"
    list_configured_domains
    if [[ $? -ne 0 ]]; then return; fi # 如果没有域名，直接返回

    local domains=()
    # 再次获取域名列表，这次存入数组
    for config_file in "${CONFIG_DIR}"/*.conf; do
        if [[ -f "$config_file" && -r "$config_file" ]]; then
            domains+=("$(basename "$config_file" .conf)")
        fi
    done

    local choice
    while true; do
        read -p "请输入要删除的域名的序号 (输入 '0' 退出): " choice
        if [[ "$choice" == "0" ]]; then echo "取消删除操作。"; return; fi
        # 检查输入是否为数字且在有效范围内
        if [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#domains[@]} ]]; then
            local index=$((choice - 1))
            DOMAIN_TO_DELETE=${domains[$index]}
            break # 选择有效，跳出循环
        else
            echo -e "${YELLOW}无效的序号，请重新输入。${NC}"
        fi
    done

    echo -e "${RED}你确定要删除域名 ${DOMAIN_TO_DELETE} 的所有本地配置吗？${NC}"

    if ! confirm_action "此操作不可恢复！确认删除吗?"; then
        echo "取消删除操作。"
        return
    fi

    echo -e "${BLUE}[*] 开始删除域名 ${DOMAIN_TO_DELETE} 的本地配置...${NC}"

    # 加载该域名的配置以获取路径等信息
    if ! load_domain_config "$DOMAIN_TO_DELETE"; then
        echo -e "${RED}[✗] 无法加载 ${DOMAIN_TO_DELETE} 的配置，删除中止。可能配置已损坏或部分删除。${NC}"
        return
    fi

    # 1. 移除 Cron 任务
    echo -e "${BLUE}[*] 移除 Cron 任务...${NC}"
    CRON_TAG_RENEW="# CertRenew_${DOMAIN_TO_DELETE}"
    CRON_TAG_DDNS="# DDNSUpdate_${DOMAIN_TO_DELETE}"
    (crontab -l 2>/dev/null | grep -v -F "$CRON_TAG_RENEW" | grep -v -F "$CRON_TAG_DDNS") | crontab -
    echo -e "${GREEN}[✓] Cron 任务已移除。${NC}"

    # 2. 删除 DDNS 更新脚本
    if [[ -n "$DDNS_SCRIPT_PATH" && -f "$DDNS_SCRIPT_PATH" ]]; then
        echo -e "${BLUE}[*] 删除 DDNS 更新脚本: $DDNS_SCRIPT_PATH ...${NC}"
        rm -f "$DDNS_SCRIPT_PATH"
        echo -e "${GREEN}[✓] DDNS 脚本已删除。${NC}"
    fi

    # 3. 删除证书续期部署钩子脚本
    if [[ -n "$DEPLOY_HOOK_SCRIPT" && -f "$DEPLOY_HOOK_SCRIPT" ]]; then
        echo -e "${BLUE}[*] 删除证书续期钩子脚本: $DEPLOY_HOOK_SCRIPT ...${NC}"
        rm -f "$DEPLOY_HOOK_SCRIPT"
        echo -e "${GREEN}[✓] 续期钩子脚本已删除。${NC}"
    fi

    # 4. 删除 Nginx 配置和软链接 (如果存在且已配置)
    local nginx_enabled_link="/etc/nginx/sites-enabled/${DOMAIN_TO_DELETE}.conf"
    if [[ "$LOCAL_PROXY_PASS" != "none" && (-f "$NGINX_CONF_PATH" || -L "$nginx_enabled_link") ]]; then
        echo -e "${BLUE}[*] 删除 Nginx 配置...${NC}"
        # 先删除软链接
        if [[ -L "$nginx_enabled_link" ]]; then
            rm -f "$nginx_enabled_link"
            echo -e "${GREEN}[✓] Nginx sites-enabled 软链接已删除。${NC}"
        fi
        # 再删除主配置文件
        if [[ -f "$NGINX_CONF_PATH" ]]; then
            rm -f "$NGINX_CONF_PATH"
            echo -e "${GREEN}[✓] Nginx sites-available 配置文件已删除。${NC}"
        fi
        # 检查 Nginx 配置并重载
        echo -e "${BLUE}[*] 检查并重载 Nginx 配置...${NC}"
        if command_exists nginx; then
            if nginx -t -c /etc/nginx/nginx.conf; then
                systemctl reload nginx
                echo -e "${GREEN}[✓] Nginx 已重载。${NC}"
            else
                echo -e "${RED}[✗] Nginx 配置检查失败！请手动检查 Nginx 配置。${NC}"
            fi
        else
             echo -e "${YELLOW}[!] Nginx 未安装，跳过重载。${NC}"
        fi
    elif [[ "$LOCAL_PROXY_PASS" == "none" ]]; then
         echo -e "${YELLOW}[!] 此域名的 Nginx 未配置，跳过删除。${NC}"
    fi


    # 5. 删除 Cloudflare 凭证文件
    if [[ -n "$CLOUDFLARE_CREDENTIALS" && -f "$CLOUDFLARE_CREDENTIALS" ]]; then
        echo -e "${BLUE}[*] 删除 Cloudflare 凭证文件: $CLOUDFLARE_CREDENTIALS ...${NC}"
        rm -f "$CLOUDFLARE_CREDENTIALS"
        echo -e "${GREEN}[✓] Cloudflare 凭证文件已删除。${NC}"
    fi

    # 6. 删除复制的证书目录
    if [[ -n "$CERT_PATH" && -d "$CERT_PATH" ]]; then
        echo -e "${BLUE}[*] 删除证书副本目录: $CERT_PATH ...${NC}"
        rm -rf "$CERT_PATH"
        echo -e "${GREEN}[✓] 证书副本目录已删除。${NC}"
    fi

    # 7. 删除 Let's Encrypt 证书 (使用 certbot)
    echo -e "${BLUE}[*] 删除 Let's Encrypt 证书 (certbot)...${NC}"
    if command_exists certbot; then
        certbot delete --cert-name "${DOMAIN_TO_DELETE}" --non-interactive
        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}[✓] Let's Encrypt 证书已删除。${NC}"
        else
            # Certbot delete 可能会因为证书不存在而报错，这不一定是问题
            echo -e "${YELLOW}[!] 使用 certbot 删除证书时遇到问题 (可能证书已不存在)。${NC}"
            # echo -e "${RED}[✗] 使用 certbot 删除证书失败。请尝试手动运行 'certbot delete --cert-name ${DOMAIN_TO_DELETE}'。${NC}"
        fi
    else
        echo -e "${YELLOW}[!] certbot 命令未找到，无法自动删除 Let's Encrypt 证书。${NC}"
        echo -e "${YELLOW}   请手动清理 /etc/letsencrypt/live/${DOMAIN_TO_DELETE}, /etc/letsencrypt/archive/${DOMAIN_TO_DELETE}, /etc/letsencrypt/renewal/${DOMAIN_TO_DELETE}.conf ${NC}"
    fi

    # 8. 删除保存的配置文件
    local config_file_to_delete="${CONFIG_DIR}/${DOMAIN_TO_DELETE}.conf"
    if [[ -f "$config_file_to_delete" ]]; then
        echo -e "${BLUE}[*] 删除脚本配置文件: $config_file_to_delete ...${NC}"
        rm -f "$config_file_to_delete"
        echo -e "${GREEN}[✓] 脚本配置文件已删除。${NC}"
    fi

    echo -e "${GREEN}[✓] 域名 ${DOMAIN_TO_DELETE} 的所有相关本地配置已成功删除！${NC}"
}

add_new_domain() {
    echo -e "\n${CYAN}--- 5.1 添加新 Web 服务域名配置 ---${NC}"
    # 1. 获取用户输入
    get_user_input_initial

    # 2. 确认是否配置 Nginx 并设置相关变量
    setup_nginx_proxy # 此函数内部会设置 INSTALL_NGINX, NGINX_HTTP_PORT, NGINX_HTTPS_PORT, LOCAL_PROXY_PASS, BACKEND_PROTOCOL

    # 3. 安装必要的包 (包括 Nginx 如果需要)
    install_packages # 根据 INSTALL_NGINX 决定是否安装 Nginx

    # 4. 创建 Cloudflare 凭证文件
    create_cf_credentials

    # 5. 检测 IP 地址
    detect_public_ip

    # 6. 选择记录类型和 IP
    select_record_type

    # 7. 获取 Zone ID
    get_zone_id

    # 8. 管理 Cloudflare DNS 记录 (创建或更新)
    manage_cloudflare_record "设置"

    # 9. 申请 Let's Encrypt 证书
    request_certificate

    # 10. 复制证书文件
    copy_certificate

    # 11. 创建 DDNS 更新脚本 (如果需要)
    create_ddns_script

    # 12. 设置 Cron 任务 (证书续期和 DDNS)
    setup_cron_jobs

    # 13. 保存配置
    save_domain_config

    echo -e "${GREEN}--- 域名 ${DOMAIN} 配置完成！ ---${NC}"
}

manage_web_service() {
     while true; do
        echo -e "\n${CYAN}--- Web 服务管理 (LE + CF + Nginx) ---${NC}"
        echo -e " ${YELLOW}1.${NC} 添加新域名并配置证书/Nginx/DDNS"
        echo -e " ${YELLOW}2.${NC} 查看已配置的域名列表"
        echo -e " ${YELLOW}3.${NC} 删除已配置的域名及其本地设置"
        echo -e " ${YELLOW}0.${NC} 返回主菜单"
        read -p "请输入选项 [0-3]: " web_choice

        case $web_choice in
            1) add_new_domain ;;
            2) list_configured_domains ;;
            3) delete_domain_config ;;
            0) break ;;
            *) echo -e "${RED}无效选项。${NC}" ;;
        esac
        [[ $web_choice != 0 ]] && read -p "按 Enter键 继续..."
    done
}


# --- 主菜单 ---
show_main_menu() {
    check_root # 每次显示菜单前更新 SSH 端口等信息
    echo -e "\n${CYAN}=======================================================${NC}"
    echo -e "${CYAN}           服务器初始化与管理脚本 V2.15          ${NC}"
    echo -e "${CYAN}=======================================================${NC}"
    echo -e " ${BLUE}--- 系统与安全 ---${NC}"
    echo -e "  ${YELLOW}1.${NC} 安装常用工具 (vim, htop, net-tools 等)"
    echo -e "  ${YELLOW}2.${NC} UFW 防火墙管理"
    echo -e "  ${YELLOW}3.${NC} Fail2ban 入侵防御管理"
    echo -e "  ${YELLOW}4.${NC} SSH 安全管理 (端口: ${YELLOW}${CURRENT_SSH_PORT}${NC})"
    echo -e "\n ${BLUE}--- Web 服务 ---${NC}"
    echo -e "  ${YELLOW}5.${NC} Web 服务管理 (Let's Encrypt + Cloudflare + Nginx)"
    echo -e "\n ${BLUE}--- 其他 ---${NC}"
    echo -e "  ${YELLOW}0.${NC} 退出脚本"
    echo -e "${CYAN}=======================================================${NC}"
    read -p "请输入选项 [0-5]: " main_choice
}

# --- 脚本入口 ---

# 检查 expect 是否安装，UFW enable 需要它
# 将 expect 安装移到 install_common_tools 中
# if ! command_exists expect; then
#    install_package "expect"
# fi


while true; do
    show_main_menu
    case $main_choice in
        1) install_common_tools ;;
        2) manage_ufw ;;
        3) manage_fail2ban ;;
        4) manage_ssh_security ;;
        5) manage_web_service ;;
        0) echo "退出脚本。" ; exit 0 ;;
        *) echo -e "${RED}无效选项，请输入 0 到 5 之间的数字。${NC}" ;;
    esac
    # 除了退出选项，其他选项执行后都暂停等待用户确认
    if [[ "$main_choice" != "0" ]]; then
         read -p "按 Enter键 返回主菜单..."
    fi
done

exit 0
