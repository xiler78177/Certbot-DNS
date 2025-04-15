#!/bin/bash

# ==============================================================================
# 服务器初始化与管理脚本 V2.21
#
# 更新日志 (V2.21):
# - [新增] UFW 管理菜单增加 "删除规则" 选项 (基于编号)。
# - [新增] 实现 `delete_ufw_rule` 函数。
# - [优化] UFW 查看规则函数现在是删除规则的前置步骤。
#
# 更新日志 (V2.20 - Fail2ban 重构):
# - [重构] 合并 Fail2ban 安装与配置流程到 `install_and_configure_fail2ban` 函数。
# - [重构] 安装/配置时，强制停止/卸载旧 Fail2ban 并删除 jail.local，确保全新状态。
# - [重构] 安装时直接提示用户输入 SSH 端口、尝试次数、封禁时间。
# - [重构] 使用 heredoc 直接生成 `/etc/fail2ban/jail.local` 文件。
# - [重构] 菜单选项 3.1 现在是 "安装或重新配置 Fail2ban"。
# - [移除] 旧的 `setup_fail2ban` 和 `configure_fail2ban` 函数。
# - [修改] `change_ssh_port` 不再自动配置 Fail2ban，改为提示用户手动重配。
#
# (...) 其他旧版本日志省略 (...)
# ==============================================================================

# --- 全局变量 ---
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
SSHD_CONFIG="/etc/ssh/sshd_config"
DEFAULT_SSH_PORT=22
# Try to get current port reliably
CURRENT_SSH_PORT=$(grep -iE "^\s*Port\s+" "$SSHD_CONFIG" | tail -n 1 | awk '{print $2}' 2>/dev/null || echo "$DEFAULT_SSH_PORT")
[[ -z "$CURRENT_SSH_PORT" || ! "$CURRENT_SSH_PORT" =~ ^[0-9]+$ ]] && CURRENT_SSH_PORT="$DEFAULT_SSH_PORT" # Fallback

FAIL2BAN_JAIL_LOCAL="/etc/fail2ban/jail.local"


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
    # 可以在这里添加其他需要清理的临时文件
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
    local detected_port=$(grep -iE "^\s*Port\s+" "$SSHD_CONFIG" | tail -n 1 | awk '{print $2}' 2>/dev/null || echo "$DEFAULT_SSH_PORT")
    [[ -z "$detected_port" || ! "$detected_port" =~ ^[0-9]+$ ]] && detected_port="$DEFAULT_SSH_PORT" # Fallback
    CURRENT_SSH_PORT="$detected_port"
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
        return 1 # 返回错误码，表示无法查看
    fi
    if ! ufw status | grep -q "Status: active"; then
        echo -e "${YELLOW}[!] UFW 当前未启用。${NC}"
        # 即使未启用，也显示 numbered 规则，可能用户想删除旧规则
        # return 1 # 或者在这里返回错误
    fi

    echo -e "${BLUE}当前 UFW 状态和规则:${NC}"
    ufw status verbose # 使用 verbose 显示更详细信息，包括默认策略
    echo -e "\n${BLUE}带编号的规则列表 (用于删除):${NC}"
    ufw status numbered
    return 0 # 返回成功码
}

# V2.21: 新增删除 UFW 规则函数
delete_ufw_rule() {
    echo -e "\n${CYAN}--- 2.4 删除 UFW 规则 ---${NC}"
    # 先显示带编号的规则，让用户知道删哪个
    if ! view_ufw_rules; then
        # 如果 view_ufw_rules 返回错误 (例如 UFW 未安装)，则无法继续删除
        return 1
    fi

    local rule_number
    while true; do
        read -p "请输入要删除的规则的编号 (来自上面的列表，输入 0 取消): " rule_number
        if [[ "$rule_number" == "0" ]]; then
            echo -e "${YELLOW}操作已取消。${NC}"
            return 1
        # 验证输入是否为正整数
        elif [[ "$rule_number" =~ ^[1-9][0-9]*$ ]]; then
            break # 输入有效，跳出循环
        else
            echo -e "${YELLOW}无效的编号。请输入规则列表中的正整数编号。${NC}"
        fi
    done

    # 再次确认删除操作
    echo -e "${RED}[!] 准备删除规则编号 #${rule_number}。${NC}"
    if confirm_action "确认删除此规则吗?"; then
        # 使用 expect 处理可能的 y/n 确认
        if command_exists expect; then
             expect -c "
             set timeout 10
             spawn ufw delete $rule_number
             expect {
                 \"Proceed with operation (y|n)?\" { send \"y\r\"; exp_continue }
                 eof
             }
             "
        else
            # 如果 expect 不可用，尝试直接删除，可能需要用户手动交互
            ufw delete "$rule_number"
        fi

        # 检查命令执行结果 ($? 在 expect 块后可能不准确，最好用 ufw status 验证)
        # 简单的延迟后重新显示规则来确认
        sleep 1
        echo -e "${BLUE}[*] 尝试删除规则 #${rule_number} 完成。正在刷新规则列表...${NC}"
        ufw status numbered
        # 这里无法完美判断是否真的删除成功，因为 ufw delete 即使编号不存在也不会返回错误码
        # 只能提示用户检查上面的列表
        echo -e "${GREEN}[✓] 删除操作已执行。请检查上面的列表确认规则是否已移除。${NC}"
    else
        echo -e "${YELLOW}操作已取消。${NC}"
    fi
}


manage_ufw() {
    while true; do
        echo -e "\n${CYAN}--- UFW 防火墙管理 ---${NC}"
        echo -e " ${YELLOW}1.${NC} 安装并启用 UFW (设置默认规则, 允许当前SSH)"
        echo -e " ${YELLOW}2.${NC} 添加允许规则 (开放端口)"
        echo -e " ${YELLOW}3.${NC} 查看当前 UFW 规则 (带编号)"
        echo -e " ${YELLOW}4.${NC} 删除规则 (按编号)" # 新增选项
        echo -e " ${YELLOW}0.${NC} 返回主菜单"
        read -p "请输入选项 [0-4]: " ufw_choice # 更新范围

        case $ufw_choice in
            1) setup_ufw ;;
            2) add_ufw_rule ;;
            3) view_ufw_rules ;;
            4) delete_ufw_rule ;; # 调用新函数
            0) break ;;
            *) echo -e "${RED}无效选项。${NC}" ;;
        esac
        [[ $ufw_choice != 0 ]] && read -p "按 Enter键 继续..."
    done
}


# --- 3. Fail2ban ---

# 更新或创建配置项的辅助函数 (保留给 SSH 配置使用)
update_or_add_config() {
    local file="$1"
    local section="$2" # 例如 sshd (without brackets)
    local key="$3"
    local value="$4"
    local section_header_regex="^\s*\[${section}\]"
    # Add processing for global config (no section header)
    if [[ -z "$section" ]]; then
        section_header_regex="^$" # Match anything (effectively handles global)
    fi
    local temp_file="${file}.tmp.$$" # Temporary file with PID

    # If section is empty (global setting)
    if [[ -z "$section" ]]; then
         # For global settings, just grep for the key directly
        local escaped_key_for_grep=$(sed 's/[][\/.*^$?+|()]/\\&/g' <<<"$key")
        local key_match_regex_grep="^\s*#?\s*${escaped_key_for_grep}\s+" # Match key at start of line, allows comment

        # Delete existing lines matching the key (commented or not)
        sed "/${key_match_regex_grep}/d" "$file" > "$temp_file"
        if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] Error processing global config with sed (deleting ${key}).${NC}"; rm -f "$temp_file" 2>/dev/null; return 1; fi

        # Append the new key = value at the end
        echo "${key} ${value}" >> "$temp_file"
        if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] Error processing global config with echo (adding ${key}).${NC}"; rm -f "$temp_file" 2>/dev/null; return 1; fi

    else
        # Process settings within a specific section [section]
        # Ensure section header exists
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

        if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] Error processing config file with awk (deleting ${key}).${NC}"; rm -f "$temp_file" 2>/dev/null; return 1; fi

        # 再在 section header 后添加新的 key = value
        local escaped_value_for_add=$(echo "$value" | sed -e 's/\\/\\\\/g' -e 's/[\/&]/\\&/g' -e 's/$/\\/' -e '$s/\\$//' | tr -d '\n')
        if ! sed -i "/${section_header_regex}/a ${key} = ${escaped_value_for_add}" "$temp_file"; then
             echo -e "${RED}[✗] Error processing config file with sed (adding ${key}).${NC}"; rm -f "$temp_file" 2>/dev/null; return 1;
        fi
    fi # End of section vs global processing

    # Replace original file
    mv "$temp_file" "$file"
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[✗] Error replacing config file ${file}.${NC}"; rm -f "$temp_file" 2>/dev/null; return 1;
    fi

    # Clean up just in case trap doesn't fire
    rm -f "$temp_file" 2>/dev/null
    return 0
}


# V2.20: New function combining installation and configuration
install_and_configure_fail2ban() {
    echo -e "\n${CYAN}--- 3.1 安装或重新配置 Fail2ban ---${NC}"

    # 1. 清理旧环境 (确保幂等性)
    echo -e "${BLUE}[*] 停止并卸载可能存在的旧 Fail2ban 版本，清理旧配置...${NC}"
    systemctl stop fail2ban > /dev/null 2>&1
    apt purge fail2ban -y > /dev/null 2>&1
    rm -f "$FAIL2BAN_JAIL_LOCAL" # 删除旧的本地配置文件

    # 2. 安装 fail2ban 和依赖
    echo -e "${BLUE}[*] 安装 Fail2ban...${NC}"
    if ! install_package "fail2ban"; then
        echo -e "${RED}[✗] Fail2ban 安装失败，无法继续。${NC}"
        return 1
    fi
    # 3. 安装 rsyslog (Debian 12 等需要)
    echo -e "${BLUE}[*] 安装/检查 rsyslog...${NC}"
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

    # 4. 获取用户配置
    echo -e "${BLUE}[*] 请输入 Fail2ban 配置参数:${NC}"
    local f2b_ssh_port maxretry bantime
    local default_maxretry=5
    local default_bantime="10m"
    local default_backend="systemd"
    local default_journalmatch="_SYSTEMD_UNIT=sshd.service + _COMM=sshd"

    # 获取 SSH 端口 (默认为当前系统 SSH 端口)
    read -p "请输入要监控的 SSH 端口 [默认: $CURRENT_SSH_PORT]: " ssh_port_input
    f2b_ssh_port=${ssh_port_input:-$CURRENT_SSH_PORT} # 如果为空则使用当前值

    # 获取最大重试次数
    read -p "请输入最大重试次数 [默认: $default_maxretry]: " maxretry_input
    maxretry=${maxretry_input:-$default_maxretry}

    # 获取封禁时间
    read -p "请输入封禁时间 (例如 60m, 1h, 1d, -1 表示永久) [默认: $default_bantime]: " bantime_input
    bantime=${bantime_input:-$default_bantime}

    # 验证输入
    if ! [[ "$f2b_ssh_port" =~ ^[0-9]+$ && "$f2b_ssh_port" -gt 0 && "$f2b_ssh_port" -le 65535 ]]; then
        echo -e "${RED}[✗] 无效的 SSH 端口: $f2b_ssh_port。${NC}"; return 1
    fi
    if ! [[ "$maxretry" =~ ^[0-9]+$ && "$maxretry" -gt 0 ]]; then
        echo -e "${RED}[✗] 最大重试次数必须是正整数。${NC}"; return 1
    fi
    # bantime 格式较灵活，这里不做严格校验

    # 5. 生成 jail.local 配置文件
    echo -e "${BLUE}[*] 生成 Fail2ban 配置文件 (${FAIL2BAN_JAIL_LOCAL})...${NC}"
    # 使用 cat 和 heredoc 创建配置文件
    cat > "$FAIL2BAN_JAIL_LOCAL" <<EOF
# Fail2ban local configuration file
# Generated by script on $(date)

[DEFAULT]
# Default ban time
bantime = ${bantime}

# Use UFW for banning action (ensure UFW is installed and configured)
# Other options: iptables-multiport, nftables-multiport, etc.
banaction = ufw

# Whitelist localhost
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
# Specify the port to monitor
port = ${f2b_ssh_port}
# Maximum number of failed login attempts
maxretry = ${maxretry}
# Ban time for this specific jail (overrides DEFAULT if needed)
# bantime = 1h
# Log backend (systemd recommended for modern systems)
backend = ${default_backend}
# Journald match filter (if using systemd backend)
journalmatch = ${default_journalmatch}
# Filter file (default sshd filter is usually fine)
# filter = sshd
EOF

    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[✗] 创建 ${FAIL2BAN_JAIL_LOCAL} 文件失败。${NC}"
        return 1
    fi
    chmod 644 "$FAIL2BAN_JAIL_LOCAL" # Set appropriate permissions

    echo -e "${GREEN}[✓] Fail2ban 配置文件已生成。${NC}"
    echo "  SSH 端口: $f2b_ssh_port"
    echo "  最大重试: $maxretry"
    echo "  封禁时间: $bantime"

    # 6. 启用并启动 Fail2ban 服务
    echo -e "${BLUE}[*] 启用 Fail2ban 开机自启...${NC}"
    systemctl enable fail2ban > /dev/null
    echo -e "${BLUE}[*] 启动 Fail2ban 服务...${NC}"
    systemctl start fail2ban
    sleep 2 # 短暂等待

    # 7. 检查状态
    if systemctl is-active --quiet fail2ban; then
        echo -e "${GREEN}[✓] Fail2ban 服务已成功启动并启用。${NC}"
    else
        echo -e "${RED}[✗] Fail2ban 服务启动失败。请检查 'systemctl status fail2ban' 和日志。${NC}"
        echo -e "${YELLOW}   尝试查看日志: journalctl -u fail2ban -n 50 --no-pager ${NC}"
        echo -e "${YELLOW}   也请检查生成的配置文件: ${FAIL2BAN_JAIL_LOCAL}${NC}"
        return 1
    fi
    return 0
}

view_fail2ban_status() {
    echo -e "\n${CYAN}--- 3.2 查看 Fail2ban 状态 (SSH) ---${NC}" # Renumbered menu option
    if ! command_exists fail2ban-client; then
        if dpkg -s fail2ban &> /dev/null; then
             echo -e "${YELLOW}[!] fail2ban-client 命令未找到，但包似乎已安装。请检查 Fail2ban 服务是否运行。${NC}"
        else
             echo -e "${YELLOW}[!] Fail2ban 未安装。${NC}"
        fi
        return 1
    fi

    if ! systemctl is-active --quiet fail2ban; then
         echo -e "${YELLOW}[!] Fail2ban 服务当前未运行。${NC}"
         echo -e "${YELLOW}   尝试启动: systemctl start fail2ban${NC}"
         echo -e "${YELLOW}   查看状态: systemctl status fail2ban${NC}"
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
        echo -e " ${YELLOW}1.${NC} 安装或重新配置 Fail2ban (推荐)"
        echo -e " ${YELLOW}2.${NC} 查看 Fail2ban 状态 (SSH jail, 日志)"
        # Removed old option 2 (manual config)
        echo -e " ${YELLOW}0.${NC} 返回主菜单"
        read -p "请输入选项 [0-2]: " f2b_choice

        case $f2b_choice in
            1) install_and_configure_fail2ban ;;
            2) view_fail2ban_status ;;
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
    echo "  5. 提示重新配置 Fail2ban 以监控新端口 (如果 Fail2ban 已安装)。" # Changed step 5
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
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak_port_$(date +%F_%T)"
    update_or_add_config "$SSHD_CONFIG" "" "Port" "$new_port" # Use helper for SSH config
    if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 修改 SSH 配置文件失败。${NC}"; return 1; fi
    echo -e "${GREEN}[✓] SSH 配置文件已修改。${NC}"

    # 3. 重启 SSH 服务
    echo -e "${BLUE}[*] 重启 SSH 服务...${NC}"
    echo -e "${YELLOW}服务重启后，当前连接可能会断开。请使用新端口 $new_port 重新连接。${NC}"
    systemctl restart sshd
    sleep 3
    if systemctl is-active --quiet sshd; then
        echo -e "${GREEN}[✓] SSH 服务已成功重启。${NC}"
        # 更新全局变量
        CURRENT_SSH_PORT=$new_port
    else
        echo -e "${RED}[✗] SSH 服务重启失败！请立即检查 SSH 配置 (${SSHD_CONFIG}) 和服务状态 ('systemctl status sshd')。${NC}"
        echo -e "${RED}   旧配置已备份为 ${SSHD_CONFIG}.bak_port_* 。${NC}"; return 1
    fi

    # 4. 更新 UFW (如果启用) - 删除旧端口规则
    if command_exists ufw && ufw status | grep -q "Status: active"; then
        echo -e "${BLUE}[*] 在 UFW 中删除旧端口 $old_port/tcp 的规则...${NC}"
        ufw delete allow $old_port/tcp > /dev/null 2>&1
        ufw delete allow $old_port > /dev/null 2>&1 # 某些旧规则可能没有协议
        echo -e "${GREEN}[✓] 尝试删除旧 UFW 规则完成 (如果存在)。${NC}"
    fi

    # 5. 更新 Fail2ban 配置提示 (V2.20: User must re-run config)
    if command_exists fail2ban-client || dpkg -s fail2ban &>/dev/null; then
         echo -e "\n${YELLOW}[!] SSH 端口已更改为 $new_port。${NC}"
         echo -e "${YELLOW}    如果您正在使用 Fail2ban，请务必返回 Fail2ban 菜单，选择 ${CYAN}'1. 安装或重新配置 Fail2ban'${YELLOW}，${NC}"
         echo -e "${YELLOW}    并在提示时输入新的 SSH 端口 ${CYAN}${new_port}${YELLOW} 以确保 Fail2ban 正确监控。${NC}"
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

    # 修正后的公钥格式校验 (允许末尾有注释)
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
        check_root # 每次显示菜单前更新 SSH 端口
        echo -e "\n${CYAN}--- SSH 安全管理 ---${NC}"
        echo -e " 当前 SSH 端口: ${YELLOW}${CURRENT_SSH_PORT}${NC}"
        echo -e " ${YELLOW}1.${NC} 更改 SSH 端口 (需手动重配 Fail2ban)"
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
    done
}

# --- 5. Web 服务 (Let's Encrypt + Cloudflare + Nginx) ---
# (这部分函数基本保持不变)
install_packages() {
    echo -e "${BLUE}[*] 安装 Certbot 及其 Cloudflare 插件...${NC}"
    if ! install_package "certbot"; then exit 1; fi
    if ! install_package "python3-certbot-dns-cloudflare"; then exit 1; fi

    # 根据 INSTALL_NGINX 决定是否安装 Nginx
    if [[ "$INSTALL_NGINX" == "yes" ]]; then
        echo -e "${BLUE}[*] 安装 Nginx...${NC}"
        if ! install_package "nginx"; then exit 1; fi
    else
         echo -e "${YELLOW}[!] 跳过 Nginx 安装 (用户未选择配置)。${NC}"
    fi
    # 确保 jq 已安装 (常用工具部分已包含，这里可省略或作为备用)
    # install_package "jq"
}
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
    mkdir -p "$(dirname "$CLOUDFLARE_CREDENTIALS")"
    cat > "$CLOUDFLARE_CREDENTIALS" <<EOF
# Cloudflare API credentials used by Certbot for domain: ${DOMAIN}
dns_cloudflare_api_token = $CF_API_TOKEN
EOF
    chmod 600 "$CLOUDFLARE_CREDENTIALS"
    echo -e "${GREEN}[✓] 凭证文件创建成功: ${CLOUDFLARE_CREDENTIALS}${NC}"
}
detect_public_ip() {
    echo -e "${BLUE}[*] 检测公网 IP 地址...${NC}"
    DETECTED_IPV4=$(curl -4s --max-time 5 https://api.ipify.org || curl -4s --max-time 5 https://ifconfig.me/ip || echo "")
    DETECTED_IPV6=$(curl -6s --max-time 5 https://api64.ipify.org || curl -6s --max-time 5 https://ifconfig.me/ip || echo "")
    echo "检测结果:"
    if [[ -n "$DETECTED_IPV4" ]]; then echo -e "  - IPv4: ${GREEN}$DETECTED_IPV4${NC}"; else echo -e "  - IPv4: ${RED}未检测到${NC}"; fi
    if [[ -n "$DETECTED_IPV6" ]]; then echo -e "  - IPv6: ${GREEN}$DETECTED_IPV6${NC}"; else echo -e "  - IPv6: ${RED}未检测到${NC}"; fi
    if [[ -z "$DETECTED_IPV4" && -z "$DETECTED_IPV6" ]]; then echo -e "${RED}[✗] 无法检测到任何公网 IP 地址。脚本无法继续。${NC}"; exit 1; fi
}
select_record_type() {
    echo -e "${BLUE}[*] 请选择要使用的 DNS 记录类型和 IP 地址:${NC}"
    options=() ips=() types=()
    if [[ -n "$DETECTED_IPV4" ]]; then options+=("IPv4 (A 记录) - ${DETECTED_IPV4}"); ips+=("$DETECTED_IPV4"); types+=("A"); fi
    if [[ -n "$DETECTED_IPV6" ]]; then options+=("IPv6 (AAAA 记录) - ${DETECTED_IPV6}"); ips+=("$DETECTED_IPV6"); types+=("AAAA"); fi
    options+=("退出")
    select opt in "${options[@]}"; do
        choice_index=$((REPLY - 1))
        if [[ "$opt" == "退出" ]]; then echo "用户选择退出。"; exit 0;
        elif [[ $choice_index -ge 0 && $choice_index -lt ${#ips[@]} ]]; then
            RECORD_TYPE=${types[$choice_index]}; SELECTED_IP=${ips[$choice_index]}
            echo -e "已选择: ${GREEN}${RECORD_TYPE} - $SELECTED_IP${NC}"; break
        else echo "无效选项 $REPLY"; fi
    done
    if [[ -z "$RECORD_TYPE" || -z "$SELECTED_IP" ]]; then echo -e "${RED}[✗] 未选择有效的记录类型或 IP 地址。脚本无法继续。${NC}"; exit 1; fi
}
get_zone_id() {
    echo -e "${BLUE}[*] 获取 Cloudflare Zone ID...${NC}"
    ZONE_NAME=$(echo "$DOMAIN" | awk -F. '{if (NF>2) print $(NF-1)"."$NF; else print $0}')
    echo "尝试获取 Zone Name: $ZONE_NAME"
    ZONE_ID_JSON=$(curl -s --max-time 10 -X GET "$CF_API/zones?name=$ZONE_NAME&status=active" \
         -H "Authorization: Bearer $CF_API_TOKEN" \
         -H "Content-Type: application/json")
    if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API 失败 (网络错误或超时)。${NC}"; exit 1; fi
    if [[ $(echo "$ZONE_ID_JSON" | jq -r '.success') != "true" ]]; then
        local error_msg=$(echo "$ZONE_ID_JSON" | jq -r '.errors[0].message // "未知 API 错误"')
        echo -e "${RED}[✗] Cloudflare API 返回错误: ${error_msg}${NC}"; exit 1;
    fi
    ZONE_ID=$(echo "$ZONE_ID_JSON" | jq -r '.result[0].id')
    if [[ "$ZONE_ID" == "null" || -z "$ZONE_ID" ]]; then
        echo -e "${RED}[✗] 无法找到域名 $ZONE_NAME 对应的活动 Zone ID。请检查域名和 API Token 是否正确。${NC}"; exit 1;
    fi
    echo -e "${GREEN}[✓] 找到 Zone ID: $ZONE_ID${NC}"
}
manage_cloudflare_record() {
    local action="$1"
    echo -e "${BLUE}[*] ${action} Cloudflare DNS 记录 ($RECORD_TYPE)...${NC}"
    echo "正在检查 $DOMAIN 的 $RECORD_TYPE 记录..."
    RECORD_INFO=$(curl -s --max-time 10 -X GET "$CF_API/zones/$ZONE_ID/dns_records?type=$RECORD_TYPE&name=$DOMAIN" \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json")
    if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (获取记录) 失败。${NC}"; exit 1; fi
    if [[ $(echo "$RECORD_INFO" | jq -r '.success') != "true" ]]; then
        echo -e "${RED}[✗] Cloudflare API 返回错误 (获取记录): $(echo "$RECORD_INFO" | jq -r '.errors[0].message // "未知 API 错误"')${NC}"; exit 1;
    fi
    RECORD_ID=$(echo "$RECORD_INFO" | jq -r '.result[0].id');
    CURRENT_IP=$(echo "$RECORD_INFO" | jq -r '.result[0].content')
    if [[ "$RECORD_ID" == "null" || -z "$RECORD_ID" ]]; then
        echo "未找到 $RECORD_TYPE 记录，正在创建..."
        CREATE_RESULT=$(curl -s --max-time 10 -X POST "$CF_API/zones/$ZONE_ID/dns_records" \
            -H "Authorization: Bearer $CF_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"$RECORD_TYPE\",\"name\":\"$DOMAIN\",\"content\":\"$SELECTED_IP\",\"ttl\":120,\"proxied\":false}")
        if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (创建记录) 失败。${NC}"; exit 1; fi
        if [[ $(echo "$CREATE_RESULT" | jq -r '.success') == "true" ]]; then
            echo -e "${GREEN}[✓] $RECORD_TYPE 记录创建成功: $DOMAIN -> $SELECTED_IP${NC}";
        else echo -e "${RED}[✗] 创建 $RECORD_TYPE 记录失败: $(echo "$CREATE_RESULT" | jq -r '.errors[0].message // "未知 API 错误"')${NC}"; exit 1; fi
    else
        echo "找到 $RECORD_TYPE 记录 (ID: $RECORD_ID)，当前 Cloudflare 记录 IP: $CURRENT_IP"
        if [[ "$CURRENT_IP" != "$SELECTED_IP" ]]; then
            echo "IP 地址不匹配 ($CURRENT_IP != $SELECTED_IP)，正在更新..."
            UPDATE_RESULT=$(curl -s --max-time 10 -X PUT "$CF_API/zones/$ZONE_ID/dns_records/$RECORD_ID" \
                -H "Authorization: Bearer $CF_API_TOKEN" \
                -H "Content-Type: application/json" \
                --data "{\"type\":\"$RECORD_TYPE\",\"name\":\"$DOMAIN\",\"content\":\"$SELECTED_IP\",\"ttl\":120,\"proxied\":false}")
            if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (更新记录) 失败。${NC}"; exit 1; fi
            if [[ $(echo "$UPDATE_RESULT" | jq -r '.success') == "true" ]]; then
                echo -e "${GREEN}[✓] $RECORD_TYPE 记录更新成功: $DOMAIN -> $SELECTED_IP${NC}";
            else echo -e "${RED}[✗] 更新 $RECORD_TYPE 记录失败: $(echo "$UPDATE_RESULT" | jq -r '.errors[0].message // "未知 API 错误"')${NC}"; exit 1; fi
        else echo -e "${GREEN}[✓] $RECORD_TYPE 记录已是最新 ($CURRENT_IP)，无需更新。${NC}"; fi
    fi
}
request_certificate() {
    echo -e "${BLUE}[*] 申请 SSL 证书 (Let's Encrypt)...${NC}"
    certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$CLOUDFLARE_CREDENTIALS" \
        --dns-cloudflare-propagation-seconds 60 \
        -d "$DOMAIN" \
        --email "$EMAIL" \
        --agree-tos \
        --no-eff-email \
        --non-interactive
    if [[ ! -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" || ! -f "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" ]]; then
        echo -e "${RED}[✗] 证书申请失败。请检查 certbot 日志 (/var/log/letsencrypt/letsencrypt.log) 获取详细信息。${NC}"; exit 1;
    fi
    echo -e "${GREEN}[✓] SSL 证书申请成功！${NC}"
}
copy_certificate() {
    echo -e "${BLUE}[*] 复制证书文件到 $CERT_PATH ...${NC}"
    mkdir -p "$CERT_PATH"
    cp -L "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$CERT_PATH/"
    cp -L "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$CERT_PATH/"
    cp -L "/etc/letsencrypt/live/${DOMAIN}/chain.pem" "$CERT_PATH/"
    cp -L "/etc/letsencrypt/live/${DOMAIN}/cert.pem" "$CERT_PATH/"
    echo -e "${GREEN}[✓] 证书文件已复制到 $CERT_PATH ${NC}"
}
setup_nginx_proxy() {
    if ! confirm_action "是否需要自动配置 Nginx 反向代理?"; then
        echo "跳过 Nginx 配置。"
        INSTALL_NGINX="no"; NGINX_HTTP_PORT=80; NGINX_HTTPS_PORT=443; LOCAL_PROXY_PASS="none"; BACKEND_PROTOCOL="none"; return
    fi
    INSTALL_NGINX="yes"
    while true; do read -p "请输入 Nginx 监听的 HTTP 端口 [默认: ${NGINX_HTTP_PORT}]: " http_port_input
        if [[ -z "$http_port_input" ]]; then break;
        elif [[ "$http_port_input" =~ ^[0-9]+$ && "$http_port_input" -gt 0 && "$http_port_input" -le 65535 ]]; then NGINX_HTTP_PORT=$http_port_input; break;
        else echo -e "${YELLOW}无效端口号。${NC}"; fi; done
    echo -e "Nginx HTTP 端口设置为: ${GREEN}${NGINX_HTTP_PORT}${NC}"
    while true; do read -p "请输入 Nginx 监听的 HTTPS 端口 [默认: ${NGINX_HTTPS_PORT}]: " https_port_input
         if [[ -z "$https_port_input" ]]; then break;
         elif [[ "$https_port_input" =~ ^[0-9]+$ && "$https_port_input" -gt 0 && "$https_port_input" -le 65535 ]]; then
             if [[ "$https_port_input" -eq "$NGINX_HTTP_PORT" ]]; then echo -e "${YELLOW}HTTPS 端口不能与 HTTP 端口 (${NGINX_HTTP_PORT}) 相同。${NC}"; else NGINX_HTTPS_PORT=$https_port_input; break; fi
         else echo -e "${YELLOW}无效端口号。${NC}"; fi; done
    echo -e "Nginx HTTPS 端口设置为: ${GREEN}${NGINX_HTTPS_PORT}${NC}"
    while true; do read -p "请选择后端服务 (${DOMAIN}) 使用的协议: [1] http (默认) [2] https : " proto_choice
        if [[ -z "$proto_choice" || "$proto_choice" == "1" ]]; then BACKEND_PROTOCOL="http"; break;
        elif [[ "$proto_choice" == "2" ]]; then BACKEND_PROTOCOL="https"; break;
        else echo -e "${YELLOW}无效输入，请输入 1 或 2。${NC}"; fi; done
    echo -e "后端服务协议设置为: ${GREEN}${BACKEND_PROTOCOL}${NC}"
    while [[ -z "$LOCAL_PROXY_PASS" ]]; do read -p "请输入 Nginx 需要反向代理的本地服务地址 (IP/域名:端口, e.g., localhost:8080): " addr_input
        if [[ "$addr_input" =~ ^[a-zA-Z0-9.-]+:[0-9]+$ ]]; then LOCAL_PROXY_PASS="${BACKEND_PROTOCOL}://${addr_input}"; echo -e "将使用代理地址: ${GREEN}${LOCAL_PROXY_PASS}${NC}";
        else echo -e "${YELLOW}地址格式似乎不正确，请确保是 '地址:端口' 格式。${NC}"; LOCAL_PROXY_PASS=""; fi; done
    echo -e "${BLUE}[*] 生成 Nginx 配置文件: $NGINX_CONF_PATH ...${NC}"
    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /var/www/html/.well-known/acme-challenge
    chown www-data:www-data /var/www/html -R 2>/dev/null || echo -e "${YELLOW}[!] 无法设置 /var/www/html 权限。${NC}"
    local redirect_suffix_bash=""; [[ "${NGINX_HTTPS_PORT}" -ne 443 ]] && redirect_suffix_bash=":${NGINX_HTTPS_PORT}"
    cat > "$NGINX_CONF_PATH" <<EOF
server {
    listen ${NGINX_HTTP_PORT}; listen [::]:${NGINX_HTTP_PORT}; server_name ${DOMAIN};
    location ~ /.well-known/acme-challenge/ { allow all; root /var/www/html; }
    location / { return 301 https://\$host${redirect_suffix_bash}\$request_uri; }
}
server {
    listen ${NGINX_HTTPS_PORT} ssl http2; listen [::]:${NGINX_HTTPS_PORT} ssl http2; server_name ${DOMAIN};
    ssl_certificate ${CERT_PATH}/fullchain.pem; ssl_certificate_key ${CERT_PATH}/privkey.pem;
    ssl_session_timeout 1d; ssl_session_cache shared:SSL:10m; ssl_session_tickets off;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    add_header Strict-Transport-Security "max-age=15768000" always;
    ssl_stapling on; ssl_stapling_verify on; ssl_trusted_certificate ${CERT_PATH}/chain.pem;
    resolver 1.1.1.1 8.8.8.8 valid=300s; resolver_timeout 5s;
    location / {
        proxy_pass ${LOCAL_PROXY_PASS};
        proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host; proxy_set_header X-Forwarded-Port \$server_port;
        $( [[ "$BACKEND_PROTOCOL" == "https" ]] && echo '        proxy_ssl_server_name on;' )
        # proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; # WebSocket
    }
}
EOF
    if [[ ! -L "/etc/nginx/sites-enabled/${DOMAIN}.conf" ]]; then
        ln -s "$NGINX_CONF_PATH" "/etc/nginx/sites-enabled/${DOMAIN}.conf"; echo -e "${GREEN}[✓] Nginx 配置已启用。${NC}";
    else echo -e "${YELLOW}[!] Nginx 配置软链接已存在。${NC}"; fi
    echo -e "${BLUE}[*] 检查 Nginx 配置并尝试重载...${NC}"
    if nginx -t -c /etc/nginx/nginx.conf; then
        systemctl reload nginx
        if systemctl is-active --quiet nginx; then
            echo -e "${GREEN}[✓] Nginx 配置检查通过并已成功重载。${NC}"
            echo -e "${YELLOW}提示：Nginx 正在监听 HTTP ${NGINX_HTTP_PORT} 和 HTTPS ${NGINX_HTTPS_PORT}。${NC}"
            if command_exists ufw && ufw status | grep -q "Status: active"; then
                 echo -e "${BLUE}[*] 尝试在 UFW 中允许 Nginx 端口...${NC}"
                 ufw allow ${NGINX_HTTP_PORT}/tcp comment "Nginx HTTP" > /dev/null
                 ufw allow ${NGINX_HTTPS_PORT}/tcp comment "Nginx HTTPS" > /dev/null
                 echo -e "${GREEN}[✓] 已尝试添加 UFW 规则。${NC}"
            elif [[ "$NGINX_HTTP_PORT" -ne 80 || "$NGINX_HTTPS_PORT" -ne 443 ]]; then
                echo -e "${YELLOW}重要提示：请确保防火墙允许访问自定义端口 (${NGINX_HTTP_PORT} 和 ${NGINX_HTTPS_PORT})！${NC}"
            fi
            if [[ "$NGINX_HTTPS_PORT" -ne 443 ]]; then echo -e "${YELLOW}访问时，URL 中需包含端口号: https://${DOMAIN}:${NGINX_HTTPS_PORT}${NC}"; fi
        else echo -e "${RED}[✗] Nginx 重载后状态异常。${NC}"; fi
    else echo -e "${RED}[✗] Nginx 配置检查失败！${NC}"; exit 1; fi
}
create_ddns_script() {
    if [[ "$DDNS_FREQUENCY" -le 0 ]]; then echo "${YELLOW}DDNS 已禁用，跳过创建脚本。${NC}"; if [[ -f "$DDNS_SCRIPT_PATH" ]]; then echo "${YELLOW}删除旧 DDNS 脚本...${NC}"; rm -f "$DDNS_SCRIPT_PATH"; fi; return; fi
    echo -e "${BLUE}[*] 创建 DDNS 更新脚本: $DDNS_SCRIPT_PATH ...${NC}"
    mkdir -p "$(dirname "$DDNS_SCRIPT_PATH")"
    local current_token=$(grep dns_cloudflare_api_token "$CLOUDFLARE_CREDENTIALS" | awk '{print $3}'); if [[ -z "$current_token" ]]; then echo -e "${RED}[✗] 无法读取 API Token。${NC}"; return; fi
    cat > "$DDNS_SCRIPT_PATH" <<EOF
#!/bin/bash
# DDNS Update Script for ${DOMAIN}
CF_CREDENTIALS_FILE="/root/.cloudflare-${DOMAIN}.ini"; DOMAIN="${DOMAIN}"; RECORD_TYPE="${RECORD_TYPE}"; ZONE_ID="${ZONE_ID}"
CF_API="https://api.cloudflare.com/client/v4"; LOG_FILE="/var/log/cf_ddns_update_${DOMAIN}.log"; TIMEOUT=10
IPV4_URLS=("https://api.ipify.org" "https://ifconfig.me/ip"); IPV6_URLS=("https://api64.ipify.org" "https://ifconfig.me/ip")
log_message() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1" >> "\$LOG_FILE"; }
get_current_ip() { local type=\$1 url ip; local urls; local opt; if [[ "\$type" == "A" ]]; then urls=("\${IPV4_URLS[@]}"); opt="-4s"; else urls=("\${IPV6_URLS[@]}"); opt="-6s"; fi; for url in "\${urls[@]}"; do ip=\$(curl \$opt --max-time \$TIMEOUT "\$url" 2>/dev/null | head -n 1); if [[ -n "\$ip" ]]; then if [[ "\$type" == "A" && "\$ip" =~ ^[0-9.]+$ ]]; then echo "\$ip"; return 0; fi; if [[ "\$type" == "AAAA" && "\$ip" == *":"* ]]; then echo "\$ip"; return 0; fi; fi; sleep 1; done; log_message "Error: Failed to get current \$type IP."; return 1; }
get_cf_record() { local t=\$1; RI=\$(curl -s --max-time \$TIMEOUT -X GET "\$CF_API/zones/\$ZONE_ID/dns_records?type=\$RECORD_TYPE&name=\$DOMAIN" -H "Authorization: Bearer \$t" -H "Content-Type: application/json"); if [[ \$? -ne 0 || \$(echo "\$RI" | jq -r '.success') != "true" ]]; then log_message "Error: API failed (Get Record): \$(echo "\$RI" | jq -r '.errors[0].message')"; return 1; fi; echo "\$RI"; return 0; }
update_cf_record() { local t=\$1 id=\$2 ip=\$3; UR=\$(curl -s --max-time \$TIMEOUT -X PUT "\$CF_API/zones/\$ZONE_ID/dns_records/\$id" -H "Authorization: Bearer \$t" -H "Content-Type: application/json" --data "{\"type\":\"\$RECORD_TYPE\",\"name\":\"\$DOMAIN\",\"content\":\"\$ip\",\"ttl\":120,\"proxied\":false}"); if [[ \$? -ne 0 || \$(echo "\$UR" | jq -r '.success') != "true" ]]; then log_message "Error: API failed (Update Record): \$(echo "\$UR" | jq -r '.errors[0].message')"; return 1; fi; return 0; }
mkdir -p \$(dirname "\$LOG_FILE"); TOKEN=\$(grep dns_cloudflare_api_token "\$CF_CREDENTIALS_FILE" | awk '{print \$3}'); if [[ -z "\$TOKEN" ]]; then log_message "Error: Failed to read API Token."; exit 1; fi
CUR_IP=\$(get_current_ip "\$RECORD_TYPE"); if [[ \$? -ne 0 ]]; then exit 1; fi; R_JSON=\$(get_cf_record "\$TOKEN"); if [[ \$? -ne 0 ]]; then exit 1; fi
CF_IP=\$(echo "\$R_JSON" | jq -r '.result[0].content'); R_ID=\$(echo "\$R_JSON" | jq -r '.result[0].id'); if [[ -z "\$R_ID" || "\$R_ID" == "null" ]]; then log_message "Error: Could not find record for \$DOMAIN."; exit 1; fi; if [[ -z "\$CF_IP" || "\$CF_IP" == "null" ]]; then log_message "Error: Failed to parse CF IP."; exit 1; fi
if [[ "\$CUR_IP" == "\$CF_IP" ]]; then exit 0; else log_message "Info: IP mismatch (\$CUR_IP != \$CF_IP). Updating..."; update_cf_record "\$TOKEN" "\$R_ID" "\$CUR_IP"; if [[ \$? -eq 0 ]]; then log_message "Success: Record updated to \$CUR_IP."; exit 0; else exit 1; fi; fi; exit 0
EOF
    chmod +x "$DDNS_SCRIPT_PATH"; echo -e "${GREEN}[✓] DDNS 更新脚本创建成功: $DDNS_SCRIPT_PATH ${NC}"
}
setup_cron_jobs() {
    echo -e "${BLUE}[*] 设置 Cron 定时任务...${NC}"
    echo -e "${BLUE}[*] 创建证书续期部署钩子脚本: $DEPLOY_HOOK_SCRIPT ...${NC}"
    mkdir -p "$(dirname "$DEPLOY_HOOK_SCRIPT")"
    cat > "$DEPLOY_HOOK_SCRIPT" <<EOF
#!/bin/bash
# Certbot Deploy Hook for ${DOMAIN}
LOG_FILE="/var/log/cert_renew_${DOMAIN}.log"; CERT_PATH="${CERT_PATH}"; NGINX_CONF_PATH="${NGINX_CONF_PATH}"; LIVE_CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
CONFIG_DIR="${CERT_PATH_PREFIX}/.managed_domains"; CONFIG_FILE="${CONFIG_DIR}/${DOMAIN}.conf"; LOCAL_PROXY_PASS="none"
[[ -f "\$CONFIG_FILE" ]] && source "\$CONFIG_FILE"
log_hook() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1" >> "\$LOG_FILE"; }
mkdir -p \$(dirname "\$LOG_FILE"); log_hook "Cert renewed for ${DOMAIN}. Running deploy hook..."
if [[ ! -f "\${LIVE_CERT_DIR}/fullchain.pem" || ! -f "\${LIVE_CERT_DIR}/privkey.pem" ]]; then log_hook "Error: Source certs not found."; exit 1; fi
log_hook "Copying new certificates to ${CERT_PATH}..."; cp -L "\${LIVE_CERT_DIR}/fullchain.pem" "${CERT_PATH}/" && cp -L "\${LIVE_CERT_DIR}/privkey.pem" "${CERT_PATH}/" && cp -L "\${LIVE_CERT_DIR}/chain.pem" "${CERT_PATH}/" && cp -L "\${LIVE_CERT_DIR}/cert.pem" "${CERT_PATH}/"
if [[ \$? -ne 0 ]]; then log_hook "Error: Failed to copy certificates."; else log_hook "Success: Certificates copied."; fi
if [[ "${LOCAL_PROXY_PASS}" != "none" && -f "${NGINX_CONF_PATH}" ]] && command -v nginx >/dev/null 2>&1; then log_hook "Reloading Nginx..."; nginx -t -c /etc/nginx/nginx.conf && systemctl reload nginx && log_hook "Success: Nginx reloaded." || log_hook "Error: Nginx reload failed."; else log_hook "Skipping Nginx reload (Not configured or Nginx not found)."; fi
log_hook "Deploy hook finished."; exit 0
EOF
    chmod +x "$DEPLOY_HOOK_SCRIPT"; echo -e "${GREEN}[✓] 证书续期部署钩子脚本创建成功: $DEPLOY_HOOK_SCRIPT ${NC}"
    CRON_TAG_RENEW="# CertRenew_${DOMAIN}"; CRON_TAG_DDNS="# DDNSUpdate_${DOMAIN}"
    (crontab -l 2>/dev/null | grep -v -F "$CRON_TAG_RENEW" | grep -v -F "$CRON_TAG_DDNS") | crontab -
    CRON_CONTENT=$(crontab -l 2>/dev/null)
    CRON_CERT_RENEW="0 3 * * * certbot renew --deploy-hook \"$DEPLOY_HOOK_SCRIPT\" >> /var/log/certbot_renew.log 2>&1 ${CRON_TAG_RENEW}"
    echo "${CRON_CONTENT}"$'\n'"${CRON_CERT_RENEW}" | crontab - ; echo -e "${GREEN}[✓] Cron 证书续期任务已设置 (${DOMAIN})。${NC}"
    if [[ "$DDNS_FREQUENCY" -gt 0 ]]; then
        if [[ -f "$DDNS_SCRIPT_PATH" ]]; then
            CRON_DDNS_UPDATE="*/${DDNS_FREQUENCY} * * * * $DDNS_SCRIPT_PATH ${CRON_TAG_DDNS}"
            CRON_CONTENT=$(crontab -l 2>/dev/null); echo "${CRON_CONTENT}"$'\n'"${CRON_DDNS_UPDATE}" | crontab -
            echo -e "${GREEN}[✓] Cron DDNS 更新任务已设置 (${DOMAIN}, 频率: ${DDNS_FREQUENCY} 分钟)。${NC}"
        else echo -e "${RED}[✗] DDNS 更新脚本 $DDNS_SCRIPT_PATH 未找到。${NC}"; fi
    else echo -e "${YELLOW}DDNS 已禁用，未设置 Cron 任务。${NC}"; fi
}
save_domain_config() {
    echo -e "${BLUE}[*] 保存域名 ${DOMAIN} 的配置...${NC}"
    mkdir -p "$CONFIG_DIR"; local config_file="${CONFIG_DIR}/${DOMAIN}.conf"
    cat > "$config_file" <<EOF
# Configuration for domain: ${DOMAIN} ($(date))
DOMAIN="${DOMAIN}"; CF_API_TOKEN="${CF_API_TOKEN}"; EMAIL="${EMAIL}"; CERT_PATH="${CERT_PATH}"
CLOUDFLARE_CREDENTIALS="${CLOUDFLARE_CREDENTIALS}"; DEPLOY_HOOK_SCRIPT="${DEPLOY_HOOK_SCRIPT}"
DDNS_SCRIPT_PATH="${DDNS_SCRIPT_PATH}"; DDNS_FREQUENCY="${DDNS_FREQUENCY}"; RECORD_TYPE="${RECORD_TYPE}"
ZONE_ID="${ZONE_ID}"; NGINX_CONF_PATH="${NGINX_CONF_PATH}"; LOCAL_PROXY_PASS="${LOCAL_PROXY_PASS}"
BACKEND_PROTOCOL="${BACKEND_PROTOCOL}"; NGINX_HTTP_PORT="${NGINX_HTTP_PORT}"; NGINX_HTTPS_PORT="${NGINX_HTTPS_PORT}"
EOF
    chmod 600 "$config_file"; echo -e "${GREEN}[✓] 配置已保存到: ${config_file}${NC}"
}
load_domain_config() {
    local domain_to_load="$1"; local config_file="${CONFIG_DIR}/${domain_to_load}.conf"
    if [[ -f "$config_file" ]]; then echo -e "${BLUE}[*] 加载域名 ${domain_to_load} 的配置...${NC}"; ( source "$config_file"; if [[ -z "$DOMAIN" || -z "$CF_API_TOKEN" || -z "$ZONE_ID" ]]; then echo -e "${RED}[✗] 配置文件 ${config_file} 不完整。${NC}"; exit 1; fi ); if [[ $? -eq 0 ]]; then source "$config_file"; echo -e "${GREEN}[✓] 配置加载成功。${NC}"; return 0; else return 1; fi
    else echo -e "${RED}[✗] 找不到配置文件: ${config_file}${NC}"; return 1; fi
}
list_configured_domains() {
    echo -e "${BLUE}[*] 当前已配置的 Web 服务域名列表:${NC}"
    mkdir -p "$CONFIG_DIR"; local domains=(); local i=1
    for config_file in "${CONFIG_DIR}"/*.conf; do
        if [[ -f "$config_file" && -r "$config_file" ]]; then
            local domain_name=$(basename "$config_file" .conf)
            echo -e "  ${CYAN}[$i]${NC} $domain_name"; domains+=("$domain_name"); ((i++)); fi; done
    if [[ ${#domains[@]} -eq 0 ]]; then echo -e "${YELLOW}  未找到任何已配置的 Web 服务域名。${NC}"; return 1; fi
    return 0
}
delete_domain_config() {
    echo -e "${RED}[!] 删除 Web 服务域名配置将移除相关证书、脚本和 Nginx 配置！${NC}"
    echo -e "${YELLOW}此操作不会删除 Cloudflare DNS 记录。${NC}"; list_configured_domains; if [[ $? -ne 0 ]]; then return; fi
    local domains=(); for cf in "${CONFIG_DIR}"/*.conf; do [[ -f "$cf" && -r "$cf" ]] && domains+=("$(basename "$cf" .conf)"); done
    local choice; while true; do read -p "请输入要删除的域名的序号 (输入 '0' 退出): " choice
        if [[ "$choice" == "0" ]]; then echo "取消删除。"; return; fi
        if [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#domains[@]} ]]; then local index=$((choice - 1)); DOMAIN_TO_DELETE=${domains[$index]}; break; else echo -e "${YELLOW}无效序号。${NC}"; fi; done
    echo -e "${RED}确定要删除域名 ${DOMAIN_TO_DELETE} 的所有本地配置吗？${NC}"
    if ! confirm_action "此操作不可恢复！确认删除吗?"; then echo "取消删除。"; return; fi
    echo -e "${BLUE}[*] 开始删除 ${DOMAIN_TO_DELETE} 的本地配置...${NC}"
    if ! load_domain_config "$DOMAIN_TO_DELETE"; then echo -e "${RED}[✗] 无法加载配置，删除中止。${NC}"; return; fi
    echo -e "${BLUE}[*] 移除 Cron 任务...${NC}"; CRON_TAG_RENEW="# CertRenew_${DOMAIN_TO_DELETE}"; CRON_TAG_DDNS="# DDNSUpdate_${DOMAIN_TO_DELETE}"; (crontab -l 2>/dev/null | grep -v -F "$CRON_TAG_RENEW" | grep -v -F "$CRON_TAG_DDNS") | crontab -; echo -e "${GREEN}[✓] Cron 任务已移除。${NC}"
    if [[ -n "$DDNS_SCRIPT_PATH" && -f "$DDNS_SCRIPT_PATH" ]]; then echo -e "${BLUE}[*] 删除 DDNS 脚本...${NC}"; rm -f "$DDNS_SCRIPT_PATH"; echo -e "${GREEN}[✓] DDNS 脚本已删除。${NC}"; fi
    if [[ -n "$DEPLOY_HOOK_SCRIPT" && -f "$DEPLOY_HOOK_SCRIPT" ]]; then echo -e "${BLUE}[*] 删除续期钩子脚本...${NC}"; rm -f "$DEPLOY_HOOK_SCRIPT"; echo -e "${GREEN}[✓] 续期钩子脚本已删除。${NC}"; fi
    local nginx_enabled_link="/etc/nginx/sites-enabled/${DOMAIN_TO_DELETE}.conf"
    if [[ "$LOCAL_PROXY_PASS" != "none" && (-f "$NGINX_CONF_PATH" || -L "$nginx_enabled_link") ]]; then echo -e "${BLUE}[*] 删除 Nginx 配置...${NC}"
        if [[ -L "$nginx_enabled_link" ]]; then rm -f "$nginx_enabled_link"; echo -e "${GREEN}[✓] Nginx enabled link 已删除。${NC}"; fi
        if [[ -f "$NGINX_CONF_PATH" ]]; then rm -f "$NGINX_CONF_PATH"; echo -e "${GREEN}[✓] Nginx available conf 已删除。${NC}"; fi
        echo -e "${BLUE}[*] 重载 Nginx 配置...${NC}"; if command_exists nginx; then if nginx -t -c /etc/nginx/nginx.conf; then systemctl reload nginx; echo -e "${GREEN}[✓] Nginx 已重载。${NC}"; else echo -e "${RED}[✗] Nginx 配置检查失败！${NC}"; fi; else echo -e "${YELLOW}[!] Nginx 未安装。${NC}"; fi
    elif [[ "$LOCAL_PROXY_PASS" == "none" ]]; then echo -e "${YELLOW}[!] Nginx 未配置，跳过删除。${NC}"; fi
    if [[ -n "$CLOUDFLARE_CREDENTIALS" && -f "$CLOUDFLARE_CREDENTIALS" ]]; then echo -e "${BLUE}[*] 删除 CF 凭证...${NC}"; rm -f "$CLOUDFLARE_CREDENTIALS"; echo -e "${GREEN}[✓] CF 凭证已删除。${NC}"; fi
    if [[ -n "$CERT_PATH" && -d "$CERT_PATH" ]]; then echo -e "${BLUE}[*] 删除证书副本...${NC}"; rm -rf "$CERT_PATH"; echo -e "${GREEN}[✓] 证书副本已删除。${NC}"; fi
    echo -e "${BLUE}[*] 删除 Let's Encrypt 证书...${NC}"; if command_exists certbot; then certbot delete --cert-name "${DOMAIN_TO_DELETE}" --non-interactive; if [[ $? -eq 0 ]]; then echo -e "${GREEN}[✓] LE 证书已删除。${NC}"; else echo -e "${YELLOW}[!] Certbot 删除证书时出错 (可能已不存在)。${NC}"; fi; else echo -e "${YELLOW}[!] certbot 未找到，请手动清理 LE 文件。${NC}"; fi
    local config_file_to_delete="${CONFIG_DIR}/${DOMAIN_TO_DELETE}.conf"; if [[ -f "$config_file_to_delete" ]]; then echo -e "${BLUE}[*] 删除脚本配置...${NC}"; rm -f "$config_file_to_delete"; echo -e "${GREEN}[✓] 脚本配置已删除。${NC}"; fi
    echo -e "${GREEN}[✓] 域名 ${DOMAIN_TO_DELETE} 的本地配置已删除！${NC}"
}
add_new_domain() {
    echo -e "\n${CYAN}--- 5.1 添加新 Web 服务域名配置 ---${NC}"
    get_user_input_initial
    setup_nginx_proxy
    install_packages # 安装 Nginx (如果需要) 和 Certbot
    create_cf_credentials
    detect_public_ip
    select_record_type
    get_zone_id
    manage_cloudflare_record "设置"
    request_certificate
    copy_certificate
    create_ddns_script
    setup_cron_jobs
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
    echo -e "${CYAN}        服务器初始化与管理脚本 V2.21 (UFW增强)        ${NC}"
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
while true; do
    show_main_menu
    case $main_choice in
        1) install_common_tools ;;
        2) manage_ufw ;;
        3) manage_fail2ban ;; # 调用新的 Fail2ban 管理菜单
        4) manage_ssh_security ;;
        5) manage_web_service ;;
        0) echo "退出脚本。" ; exit 0 ;;
        *) echo -e "${RED}无效选项，请输入 0 到 5 之间的数字。${NC}" ;;
    esac
    if [[ "$main_choice" != "0" ]]; then
         read -p "按 Enter键 返回主菜单..."
    fi
done

exit 0
