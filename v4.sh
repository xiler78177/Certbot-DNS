#!/bin/bash

# ==============================================================================
# 服务器初始化与管理脚本 (v7.2 - Gemini-Mod)
#
# 更新日志 v7.2:
# 1. [核心修复] 彻底解决 Backspace 键无法删除并显示 "^H" 的问题。
#    (添加了 stty erase '^H' 强制映射删除键)
# 2. [功能保持] 包含 v7.1 的所有功能：详细系统信息、Web 服务增强、SSH 密码修改等。
# ==============================================================================

# --- 全局变量 ---
CF_API_TOKEN=""
DOMAIN=""
EMAIL="your@mail.com" # 固定邮箱 - Let's Encrypt 注册使用
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
LOCAL_PROXY_PASS="" # 存储 Nginx proxy_pass 的目标地址 (包含协议)
BACKEND_PROTOCOL="http" # 后端协议 (http 或 https)
NGINX_HTTP_PORT=80
NGINX_HTTPS_PORT=443
CONFIG_DIR="${CERT_PATH_PREFIX}/.managed_domains" # 存储各域名配置的目录
SSHD_CONFIG="/etc/ssh/sshd_config"
DEFAULT_SSH_PORT=22
CURRENT_SSH_PORT=$(grep -iE "^\s*Port\s+" "$SSHD_CONFIG" | tail -n 1 | awk '{print $2}')
# 验证检测到的端口是否为数字，否则使用默认值
if ! [[ "$CURRENT_SSH_PORT" =~ ^[0-9]+$ ]]; then
    echo -e "${YELLOW}[!] 无法自动检测当前 SSH 端口，将使用默认端口 22。${NC}"
    CURRENT_SSH_PORT=$DEFAULT_SSH_PORT
fi
FAIL2BAN_JAIL_LOCAL="/etc/fail2ban/jail.local"
RESOLV_CONF="/etc/resolv.conf"
SYSTEMD_RESOLVED_CONF="/etc/systemd/resolved.conf"

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- 关键修复：解决 Backspace 键显示 ^H 的问题 ---
# 1. stty sane: 重置终端为合理状态
# 2. stty erase '^H': 强制将 Backspace (Ctrl+H) 映射为删除动作
stty sane
stty erase '^H'

# --- 函数定义 ---

# 清理并退出 (主要用于 trap 捕获意外中断信号)
cleanup_and_exit() {
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
    # 重新检测 SSH 端口
    local detected_port
    detected_port=$(grep -iE "^\s*Port\s+" "$SSHD_CONFIG" | tail -n 1 | awk '{print $2}')
    if [[ "$detected_port" =~ ^[0-9]+$ ]]; then
        CURRENT_SSH_PORT=$detected_port
    else
        if ! [[ "$CURRENT_SSH_PORT" =~ ^[0-9]+$ ]]; then
             CURRENT_SSH_PORT=$DEFAULT_SSH_PORT
        fi
    fi
}

# 通用确认函数 (Y/n/回车=Y)
confirm_action() {
    local prompt_msg="$1"
    local reply
    while true; do
        read -p "$prompt_msg [Y/n/回车默认Y]: " -n 1 -r reply
        echo # 换行
        if [[ $reply =~ ^[Yy]$ || -z $reply ]]; then return 0; # Yes
        elif [[ $reply =~ ^[Nn]$ ]]; then return 1; # No
        else echo -e "${YELLOW}请输入 Y 或 N，或直接按回车确认。${NC}"; fi
    done
}


# 通用包安装函数 (使用 apt)
install_package() {
    local pkg_name="$1"
    local install_cmd="apt install -y"

    if dpkg -s "$pkg_name" &> /dev/null; then
        echo -e "${YELLOW}[!] $pkg_name 似乎已安装。${NC}"
        return 0
    fi

    echo -e "${BLUE}[*] 正在使用 apt 安装 $pkg_name ...${NC}"
    export DEBIAN_FRONTEND=noninteractive
    apt update -y > /dev/null 2>&1
    $install_cmd "$pkg_name"
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[✗] 使用 apt 安装 $pkg_name 失败。请检查错误信息并手动安装。${NC}"
        return 1
    else
        echo -e "${GREEN}[✓] $pkg_name 使用 apt 安装成功。${NC}"
        return 0
    fi
}

# --- 2. 基础工具 ---
install_common_tools() {
    echo -e "\n${CYAN}--- 2. 安装基础依赖工具 ---${NC}"
    # 移除 expect，因为它不再被 UFW 部分使用
    local tools="curl jq unzip"
    local failed=0
    local installed_count=0
    local already_installed_count=0

    echo -e "${BLUE}[*] 检查并安装基础工具: ${tools}...${NC}"
    for tool in $tools; do
        if dpkg -s "$tool" &> /dev/null; then
            echo -e "${YELLOW}[!] $tool 似乎已安装。${NC}"
            already_installed_count=$((already_installed_count + 1))
        else
            install_package "$tool"
            if [[ $? -ne 0 ]]; then failed=1; else installed_count=$((installed_count + 1)); fi
        fi
    done

    # 检查 snapd
    echo -e "${BLUE}[*] 检查 snapd 是否安装...${NC}"
    if ! command_exists snap; then
        echo -e "${YELLOW}[!] snap 命令未找到。尝试安装 snapd...${NC}"
        install_package "snapd"
        if ! command_exists snap; then echo -e "${RED}[✗] snapd 安装失败。Certbot 可能无法通过 Snap 安装。${NC}";
        else echo -e "${GREEN}[✓] snapd 安装成功。${NC}"; sleep 2; fi
    else echo -e "${GREEN}[✓] snap 命令已找到。${NC}"; fi

    echo -e "\n${CYAN}--- 基础工具安装总结 ---${NC}"
    echo -e "  新安装: ${GREEN}${installed_count}${NC} 个"
    echo -e "  已存在: ${YELLOW}${already_installed_count}${NC} 个"
    if [[ $failed -eq 0 ]]; then echo -e "${GREEN}[✓] 基础工具检查/安装完成。${NC}";
    else echo -e "${RED}[✗] 部分基础工具安装失败，请检查上面的错误信息。${NC}"; fi
}

# --- 3. UFW 防火墙 ---
setup_ufw() {
    echo -e "\n${CYAN}--- 3.1 安装并启用 UFW 防火墙 ---${NC}"
    if ! install_package "ufw"; then return 1; fi

    if systemctl is-active --quiet firewalld; then
        echo -e "${RED}[✗] 检测到 firewalld 正在运行。UFW 不能与 firewalld 同时运行。${NC}"
        echo -e "${YELLOW}   请先禁用 firewalld: 'sudo systemctl stop firewalld && sudo systemctl disable firewalld'${NC}"
        return 1
    fi

    echo -e "${BLUE}[*] 设置 UFW 默认规则 (deny incoming, allow outgoing)...${NC}"
    ufw default deny incoming > /dev/null
    ufw default allow outgoing > /dev/null
    echo -e "${BLUE}[*] 允许当前 SSH 端口 ($CURRENT_SSH_PORT)...${NC}"
    ufw allow $CURRENT_SSH_PORT/tcp comment "SSH Access (Current)" > /dev/null

    local extra_ports_input; local extra_ports_array
    read -p "是否需要额外开放其他端口 (例如 80 443 8080，用空格隔开) [留空则跳过]: " extra_ports_input
    if [[ -n "$extra_ports_input" ]]; then
        read -a extra_ports_array <<< "$extra_ports_input"
        echo -e "${BLUE}[*] 尝试开放额外端口: ${extra_ports_array[*]} (默认TCP)...${NC}"
        for port in "${extra_ports_array[@]}"; do
            if [[ "$port" =~ ^[0-9]+$ && "$port" -gt 0 && "$port" -le 65535 ]]; then
                ufw allow $port/tcp comment "Extra port added during setup" > /dev/null
                if [[ $? -eq 0 ]]; then echo -e "  ${GREEN}[✓] 端口 $port/tcp 已添加规则。${NC}";
                else echo -e "  ${RED}[✗] 添加端口 $port/tcp 规则失败。${NC}"; fi
            else echo -e "  ${YELLOW}[!] '$port' 不是有效的端口号，已跳过。${NC}"; fi
        done
    fi

    echo -e "${YELLOW}[!] 准备启用 UFW。这将断开除已允许端口外的所有连接。${NC}"
    echo -e "${YELLOW}   您可能需要在下一个提示中输入 'y' 来确认。${NC}"
    ufw enable
    local ufw_enable_status=$?

    if [[ $ufw_enable_status -eq 0 ]] && ufw status | grep -q "Status: active"; then
        echo -e "${GREEN}[✓] UFW 已成功启用。${NC}"
        ufw status verbose
    else
        echo -e "${RED}[✗] UFW 启用失败。请检查上面的错误信息或 UFW 日志。${NC}"
        return 1
    fi
    return 0
}

# 批量添加 UFW 规则 (优化版)
add_ufw_rule() {
    echo -e "\n${CYAN}--- 3.2 批量添加 UFW 允许规则 (TCP) ---${NC}"
    echo -e "${YELLOW}提示: 请输入一个或多个端口号，用空格隔开 (例如: 80 443 8888)${NC}"
    
    local ports_input
    local ports_array
    
    # 1. 获取输入
    read -p "请输入端口号: " ports_input
    
    # 检查是否为空
    if [[ -z "$ports_input" ]]; then
        echo -e "${YELLOW}未输入任何端口，操作已取消。${NC}"
        return
    fi
    
    # 2. 将输入分割为数组 (以空格为分隔符)
    read -a ports_array <<< "$ports_input"
    
    echo -e "${BLUE}[*] 正在处理端口 (默认 TCP): ${ports_array[*]} ...${NC}"
    
    # 3. 循环处理每个端口
    for port in "${ports_array[@]}"; do
        # 校验端口合法性 (必须是 1-65535 的纯数字)
        if [[ "$port" =~ ^[0-9]+$ && "$port" -gt 0 && "$port" -le 65535 ]]; then
            # 执行添加命令 (默认使用 /tcp，并添加备注)
            ufw allow "$port/tcp" comment "Manual-Add-$port" > /dev/null
            
            if [[ $? -eq 0 ]]; then
                echo -e "  ${GREEN}[✓] 端口 $port/tcp 已成功开放。${NC}"
            else
                echo -e "  ${RED}[✗] 端口 $port/tcp 添加失败。${NC}"
            fi
        else
            echo -e "  ${YELLOW}[!] '$port' 无效，已跳过 (请输入 1-65535 的数字)。${NC}"
        fi
    done
    
    echo -e "\n${BLUE}批量操作执行完毕。${NC}"
    # 自动展示结果
    view_ufw_rules 
}

delete_ufw_rule() {
    echo -e "\n${CYAN}--- 3.4 删除 UFW 规则 ---${NC}"
    if ! command_exists ufw || ! ufw status | grep -q "Status: active"; then echo -e "${YELLOW}[!] UFW 未安装或未启用。${NC}"; return; fi
    echo -e "${BLUE}当前 UFW 规则列表 (带编号):${NC}"; ufw status numbered
    local nums_input; local nums_array=(); local valid_nums=(); local num
    local highest_num=$(ufw status numbered | grep '^\[ *[0-9]\+ *\]' | sed -e 's/^\[ *//' -e 's/ *\].*//' | sort -n | tail -n 1)
    if ! [[ "$highest_num" =~ ^[0-9]+$ ]]; then echo -e "${RED}[✗] 无法确定最大规则编号。请检查 'ufw status numbered' 的输出。${NC}"; return 1; fi
    read -p "请输入要删除的规则编号 (用空格隔开，例如 '1 3 5'): " nums_input; if [[ -z "$nums_input" ]]; then echo -e "${YELLOW}未输入任何编号，操作取消。${NC}"; return; fi
    local cleaned_input=$(echo "$nums_input" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e "s/^'//" -e "s/'$//" -e 's/^"//' -e 's/"$//'); read -a nums_array <<< "$cleaned_input"
    for num in "${nums_array[@]}"; do if [[ "$num" =~ ^[1-9][0-9]*$ ]]; then if [[ "$num" -le "$highest_num" ]]; then valid_nums+=("$num"); else echo -e "${YELLOW}[!] 规则编号 '$num' 超出最大范围 ($highest_num)，已忽略。${NC}"; fi; else echo -e "${YELLOW}[!] '$num' 不是有效的规则编号，已忽略。${NC}"; fi; done
    if [[ ${#valid_nums[@]} -eq 0 ]]; then echo -e "${YELLOW}没有有效的规则编号被选中，操作取消。${NC}"; return; fi
    IFS=$'\n' sorted_nums=($(sort -nr <<<"${valid_nums[*]}")); unset IFS

    echo -e "${BLUE}[*] 准备删除以下规则编号: ${sorted_nums[*]} ${NC}"
    echo -e "${YELLOW}   您可能需要在下一个提示中为每个规则输入 'y' 来确认删除。${NC}"

    local delete_failed=0
    for num_to_delete in "${sorted_nums[@]}"; do
        echo -n "  尝试删除规则 $num_to_delete ... "
        ufw delete $num_to_delete
        local delete_status=$?
        if [[ $delete_status -eq 0 ]]; then
             echo -e "${GREEN}命令执行完毕。${NC}"
        else
             echo -e "${RED}命令执行失败 (状态码: $delete_status)。${NC}"
             delete_failed=1
        fi
    done

    echo -e "\n${BLUE}删除命令执行完毕。请再次查看规则列表确认结果。${NC}"
    if [[ $delete_failed -ne 0 ]]; then
        echo -e "${RED}[✗] 部分删除命令执行失败。${NC}"
    fi
    view_ufw_rules
}

view_ufw_rules() {
    echo -e "\n${CYAN}--- 3.3 查看 UFW 规则 ---${NC}"
    if ! command_exists ufw; then echo -e "${YELLOW}[!] UFW 未安装。${NC}"; return; fi
    echo -e "${BLUE}当前 UFW 状态和规则:${NC}"; ufw status verbose; echo -e "\n${BLUE}带编号的规则列表 (用于删除):${NC}"; ufw status numbered
}

ufw_allow_all() {
    echo -e "\n${CYAN}--- 3.5 允许所有 UFW 入站连接 (危险) ---${NC}"; echo -e "${RED}[!] 警告：此操作将允许来自任何源的任何入站连接，会显著降低服务器安全性！${NC}"; echo -e "${YELLOW}   仅在您完全了解风险并有特定需求时（例如临时调试）才执行此操作。${NC}"; echo -e "${YELLOW}   强烈建议在完成后立即恢复默认拒绝规则 (选项 6)。${NC}"
    if ! command_exists ufw || ! ufw status | grep -q "Status: active"; then echo -e "${YELLOW}[!] UFW 未安装或未启用。无法更改默认策略。${NC}"; return; fi
    if confirm_action "您确定要将 UFW 默认入站策略更改为 ALLOW (允许所有) 吗?"; then
        echo -e "${BLUE}[*] 正在设置默认入站策略为 ALLOW...${NC}"; ufw default allow incoming; if [[ $? -eq 0 ]]; then echo -e "${GREEN}[✓] UFW 默认入站策略已设置为 ALLOW。${NC}"; echo -e "${RED}   请注意：现在所有端口都对外部开放！${NC}"; ufw status verbose; else echo -e "${RED}[✗] 设置默认入站策略失败。${NC}"; fi
    else echo -e "${YELLOW}操作已取消。${NC}"; fi
}

ufw_reset_default() {
    echo -e "\n${CYAN}--- 3.6 重置 UFW 为默认拒绝规则 ---${NC}"; echo -e "${BLUE}[*] 此操作将执行以下步骤:${NC}"; echo "  1. 设置默认入站策略为 DENY (拒绝)。"; echo "  2. 设置默认出站策略为 ALLOW (允许)。"; echo "  3. 确保当前 SSH 端口 ($CURRENT_SSH_PORT/tcp) 规则存在。"; echo "  4. 重新加载 UFW 规则。"; echo -e "${YELLOW}   注意：除了 SSH 端口外，所有其他之前手动添加的 'allow' 规则将保持不变。${NC}"
    if ! command_exists ufw; then echo -e "${YELLOW}[!] UFW 未安装。无法重置。${NC}"; return; fi
    if confirm_action "确认要将 UFW 重置为默认拒绝策略 (并保留 SSH 端口) 吗?"; then
        echo -e "${BLUE}[*] 设置默认入站策略为 DENY...${NC}"; ufw default deny incoming > /dev/null; echo -e "${BLUE}[*] 设置默认出站策略为 ALLOW...${NC}"; ufw default allow outgoing > /dev/null; echo -e "${BLUE}[*] 确保当前 SSH 端口 ($CURRENT_SSH_PORT/tcp) 允许...${NC}"; ufw allow $CURRENT_SSH_PORT/tcp comment "SSH Access (Current)" > /dev/null; echo -e "${BLUE}[*] 重新加载 UFW 规则...${NC}"; ufw reload > /dev/null
        if [[ $? -eq 0 ]]; then echo -e "${GREEN}[✓] UFW 已成功重置为默认拒绝策略并重新加载。${NC}"; ufw status verbose; else echo -e "${RED}[✗] UFW 重置或重新加载失败。${NC}"; fi
    else echo -e "${YELLOW}操作已取消。${NC}"; fi
}

uninstall_ufw() {
    echo -e "\n${RED}--- 警告：即将卸载 UFW 防火墙 ---${NC}"
    echo -e "${YELLOW}[!] 此操作会移除 UFW 及其所有规则，您的服务器将完全暴露在公网！${NC}"
    if ! command_exists ufw; then echo -e "${YELLOW}[!] UFW 未安装，无需卸载。${NC}"; return 0; fi
    if ! confirm_action "您确定要卸载 UFW 吗？"; then echo -e "${YELLOW}操作已取消。${NC}"; return 0; fi
    echo -e "${BLUE}[*] 正在禁用 UFW...${NC}"; ufw disable; if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 禁用 UFW 失败。请手动执行 'sudo ufw disable'。${NC}"; return 1; fi
    echo -e "${BLUE}[*] 正在彻底移除 UFW...${NC}"; apt remove --purge ufw -y; if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 卸载 UFW 失败。请手动执行 'sudo apt remove --purge ufw'。${NC}"; return 1; fi
    echo -e "${GREEN}[✓] UFW 已成功卸载。${NC}"; return 0
}

manage_ufw() {
    while true; do echo -e "\n${CYAN}--- UFW 防火墙管理 ---${NC}"; echo -e " ${YELLOW}1.${NC} 安装并启用 UFW (手动确认启用)"; echo -e " ${YELLOW}2.${NC} 批量添加允许规则 (TCP, 简洁模式)"; echo -e " ${YELLOW}3.${NC} 查看当前 UFW 规则"; echo -e " ${YELLOW}4.${NC} 删除 UFW 规则 (手动确认删除)"; echo -e " ${YELLOW}5.${NC} ${RED}允许所有入站连接 (危险!)${NC}"; echo -e " ${YELLOW}6.${NC} 重置为默认拒绝规则 (保留 SSH)"; echo -e " ${YELLOW}7.${NC} ${RED}卸载 UFW 防火墙 (高危!)${NC}"; echo -e " ${YELLOW}0.${NC} 返回主菜单"; read -p "请输入选项 [0-7]: " ufw_choice
        case $ufw_choice in 1) setup_ufw ;; 2) add_ufw_rule ;; 3) view_ufw_rules ;; 4) delete_ufw_rule ;; 5) ufw_allow_all ;; 6) ufw_reset_default ;; 7) uninstall_ufw ;; 0) break ;; *) echo -e "${RED}无效选项。${NC}" ;; esac
        [[ $ufw_choice != 0 ]] && read -p "按 Enter键 继续..."
    done
}


# --- 4. Fail2ban ---
setup_fail2ban() {
    echo -e "\n${CYAN}--- 4.1 安装并配置 Fail2ban ---${NC}"
    if ! install_package "fail2ban"; then echo -e "${RED}[✗] Fail2ban 安装失败，无法继续。${NC}"; return 1; fi
    if ! install_package "rsyslog"; then echo -e "${YELLOW}[!] rsyslog 安装失败，Fail2ban 可能无法正常工作。${NC}";
    else echo -e "${BLUE}[*] 启用并重启 rsyslog 服务...${NC}"; systemctl enable rsyslog > /dev/null 2>&1; systemctl restart rsyslog; echo -e "${BLUE}[*] 等待 rsyslog 初始化...${NC}"; sleep 2; fi
    echo -e "${BLUE}[*] 进行 Fail2ban 初始配置 (${FAIL2BAN_JAIL_LOCAL})...${NC}"
    if ! configure_fail2ban; then echo -e "${RED}[✗] Fail2ban 初始配置失败。${NC}"; return 1; fi
    echo -e "${GREEN}[✓] Fail2ban 初始配置已写入 ${FAIL2BAN_JAIL_LOCAL}。${NC}"
    echo -e "${BLUE}[*] 启用并重启 Fail2ban 服务...${NC}"; systemctl enable fail2ban > /dev/null; systemctl restart fail2ban; sleep 3
    if systemctl is-active --quiet fail2ban; then echo -e "${GREEN}[✓] Fail2ban 服务已成功启动并启用。${NC}";
    else echo -e "${RED}[✗] Fail2ban 服务启动失败。请检查 'systemctl status fail2ban' 和日志。${NC}"; echo -e "${YELLOW}   尝试查看日志: journalctl -u fail2ban -n 50 --no-pager ${NC}"; return 1; fi
    return 0
}

update_or_add_config() {
    local file="$1"; local section="$2"; local key="$3"; local value="$4"; local section_header_regex="^\s*\[${section}\]"; local temp_file_del="${file}.tmp_del.$$" ; local temp_file_add="${file}.tmp_add.$$"
    if [[ -n "$section" ]] && ! grep -qE "$section_header_regex" "$file"; then echo -e "${YELLOW}[!] 段落 [${section}] 在 ${file} 中未找到，将在末尾添加。${NC}"; echo -e "\n[${section}]" >> "$file"; fi
    local escaped_key_for_grep=$(sed 's/[.^$*]/\\&/g' <<< "$key"); local key_match_regex_grep="^\s*#?\s*${escaped_key_for_grep}\s*="; grep -vE "$key_match_regex_grep" "$file" > "$temp_file_del"; local grep_status=$?
    if [[ $grep_status -gt 1 ]]; then echo -e "${RED}[✗] 使用 grep -v 处理配置文件时出错 (删除 ${key})。状态码: $grep_status${NC}"; rm -f "$temp_file_del" 2>/dev/null; return 1; fi
    local escaped_value_for_awk=$(echo "$value" | sed 's/\\/\\\\/g'); local new_line
    if [[ "$file" == "$SSHD_CONFIG" ]]; then new_line="${key} ${escaped_value_for_awk}"; else new_line="${key} = ${escaped_value_for_awk}"; fi
    if [[ -n "$section" ]]; then awk -v section_re="$section_header_regex" -v new_line="${new_line}" '$0 ~ section_re { print; print new_line; added=1; next } { print } END { if (!added) { print "\n[" section "]\n" new_line } }' "$temp_file_del" > "$temp_file_add";
    else cat "$temp_file_del" > "$temp_file_add"; echo "$new_line" >> "$temp_file_add"; fi
    if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 使用 awk/cat 处理配置文件时出错 (添加 ${key})。${NC}"; rm -f "$temp_file_del" "$temp_file_add" 2>/dev/null; return 1; fi
    mv "$temp_file_add" "$file"; if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 替换配置文件 ${file} 失败。${NC}"; rm -f "$temp_file_del" "$temp_file_add" 2>/dev/null; return 1; fi
    rm -f "$temp_file_del" 2>/dev/null; return 0
}

configure_fail2ban() {
    echo -e "\n${CYAN}--- 配置 Fail2ban (SSH 防护) ---${NC}"; local ssh_port maxretry bantime backend journalmatch
    read -p "请输入要监控的 SSH 端口 (当前: $CURRENT_SSH_PORT): " ssh_port_input; ssh_port=${ssh_port_input:-$CURRENT_SSH_PORT}
    read -p "请输入最大重试次数 [默认 5]: " maxretry_input; maxretry=${maxretry_input:-5}
    read -p "请输入封禁时间 (例如 60m, 1h, 1d, -1 表示永久) [默认 10m]: " bantime_input; bantime=${bantime_input:-"10m"}
    backend="systemd"; journalmatch="_SYSTEMD_UNIT=sshd.service + _COMM=sshd"
    if ! [[ "$ssh_port" =~ ^[0-9]+$ && "$ssh_port" -gt 0 && "$ssh_port" -le 65535 ]]; then echo -e "${RED}[✗] 无效的 SSH 端口。${NC}"; return 1; fi
    if ! [[ "$maxretry" =~ ^[0-9]+$ && "$maxretry" -gt 0 ]]; then echo -e "${RED}[✗] 最大重试次数必须是正整数。${NC}"; return 1; fi
    echo -e "${BLUE}[*] 准备使用以下配置覆盖 ${FAIL2BAN_JAIL_LOCAL}:${NC}"; echo "  [sshd]"; echo "  enabled = true"; echo "  port = $ssh_port"; echo "  maxretry = $maxretry"; echo "  bantime = $bantime"; echo "  backend = $backend"; echo "  journalmatch = $journalmatch"
    if confirm_action "确认使用此配置覆盖 jail.local 吗?"; then
        cat > "$FAIL2BAN_JAIL_LOCAL" <<EOF
# Configuration generated by script $(date)
[DEFAULT]
bantime = 10m
banaction = ufw
[sshd]
enabled = true
port = $ssh_port
maxretry = $maxretry
bantime = $bantime
backend = $backend
journalmatch = $journalmatch
EOF
        if [[ $? -eq 0 ]]; then chmod 644 "$FAIL2BAN_JAIL_LOCAL"; echo -e "${GREEN}[✓] Fail2ban 配置已写入 ${FAIL2BAN_JAIL_LOCAL}。${NC}"; return 0; else echo -e "${RED}[✗] 写入 Fail2ban 配置文件失败。${NC}"; return 1; fi
    else echo -e "${YELLOW}操作已取消。${NC}"; return 1; fi
}

view_fail2ban_status() {
    echo -e "\n${CYAN}--- 4.3 查看 Fail2ban 状态 (SSH) ---${NC}"; if ! command_exists fail2ban-client; then echo -e "${YELLOW}[!] Fail2ban 未安装。${NC}"; return 1; fi
    echo -e "${BLUE}Fail2ban SSH jail 状态:${NC}"; fail2ban-client status sshd; echo -e "\n${BLUE}查看 Fail2ban 日志 (最近 20 条):${NC}"
    if command_exists journalctl; then journalctl -u fail2ban -n 20 --no-pager --quiet; elif [[ -f /var/log/fail2ban.log ]]; then tail -n 20 /var/log/fail2ban.log; else echo -e "${YELLOW}无法找到 Fail2ban 日志。${NC}"; fi; return 0
}

uninstall_fail2ban() {
    echo -e "\n${RED}--- 警告：即将卸载 Fail2ban 入侵防御 ---${NC}"
    echo -e "${YELLOW}[!] 此操作会移除 Fail2ban 服务，您的 SSH 等服务将不再受到自动暴力破解防御。${NC}"
    if ! command_exists fail2ban-client; then echo -e "${YELLOW}[!] Fail2ban 未安装，无需卸载。${NC}"; return 0; fi
    if ! confirm_action "您确定要卸载 Fail2ban 吗？"; then echo -e "${YELLOW}操作已取消。${NC}"; return 0; fi
    echo -e "${BLUE}[*] 正在停止并禁用 Fail2ban 服务...${NC}"; systemctl stop fail2ban > /dev/null 2>&1; systemctl disable fail2ban > /dev/null 2>&1
    echo -e "${BLUE}[*] 正在彻底移除 Fail2ban...${NC}"; apt remove --purge fail2ban -y; if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 卸载 Fail2ban 失败。请手动执行 'sudo apt remove --purge fail2ban'。${NC}"; return 1; fi
    if [[ -f "$FAIL2BAN_JAIL_LOCAL" ]]; then echo -e "${BLUE}[*] 删除脚本生成的配置文件: ${FAIL2BAN_JAIL_LOCAL}...${NC}"; rm -f "$FAIL2BAN_JAIL_LOCAL"; fi
    echo -e "${GREEN}[✓] Fail2ban 已成功卸载。${NC}"; return 0
}

manage_fail2ban() {
     while true; do echo -e "\n${CYAN}--- Fail2ban 入侵防御管理 ---${NC}"; echo -e " ${YELLOW}1.${NC} 安装并配置 Fail2ban (交互式设置 SSH 防护)"; echo -e " ${YELLOW}2.${NC} 重新配置 Fail2ban (覆盖 jail.local, 重启服务)"; echo -e " ${YELLOW}3.${NC} 查看 Fail2ban 状态 (SSH jail, 日志)"; echo -e " ${YELLOW}4.${NC} ${RED}卸载 Fail2ban${NC}"; echo -e " ${YELLOW}0.${NC} 返回主菜单"; read -p "请输入选项 [0-4]: " f2b_choice
        case $f2b_choice in 1) setup_fail2ban ;; 2) if configure_fail2ban; then echo -e "${BLUE}[*] 重启 Fail2ban 服务以应用新配置...${NC}"; systemctl restart fail2ban; sleep 2; if systemctl is-active --quiet fail2ban; then echo -e "${GREEN}[✓] Fail2ban 服务已重启。${NC}"; else echo -e "${RED}[✗] Fail2ban 服务重启失败。${NC}"; fi; fi ;; 3) view_fail2ban_status ;; 4) uninstall_fail2ban ;; 0) break ;; *) echo -e "${RED}无效选项。${NC}" ;; esac
        [[ $f2b_choice != 0 ]] && read -p "按 Enter键 继续..."
    done
}

# --- 5. SSH 安全 ---
change_ssh_port() {
    echo -e "\n${CYAN}--- 5.1 更改 SSH 端口 ---${NC}"; local new_port old_port; old_port=$CURRENT_SSH_PORT; echo "当前 SSH 端口是: $old_port"
    while true; do read -p "请输入新的 SSH 端口号 (建议 10000-65535): " new_port; if [[ "$new_port" =~ ^[0-9]+$ && "$new_port" -gt 0 && "$new_port" -le 65535 ]]; then if [[ "$new_port" -eq "$old_port" ]]; then echo -e "${YELLOW}新端口与当前端口相同，无需更改。${NC}"; return; fi; break; else echo -e "${YELLOW}无效的端口号。请输入 1-65535 之间的数字。${NC}"; fi; done
    echo -e "${RED}[!] 警告：更改 SSH 端口需要确保新端口在防火墙中已开放！${NC}"; echo "脚本将尝试执行以下操作："; echo "  1. 在 UFW 中允许新端口 $new_port/tcp (如果 UFW 已启用)。"; echo "  2. 修改 SSH 配置文件 ($SSHD_CONFIG)。"; echo "  3. 重启 SSH 服务。"; echo "  4. 在 UFW 中删除旧端口 $old_port/tcp 的规则 (如果存在)。"; echo "  5. 重新配置 Fail2ban 以监控新端口 (如果 Fail2ban 已安装)。"; echo -e "${YELLOW}在重启 SSH 服务后，您需要使用新端口重新连接！例如: ssh user@host -p $new_port ${NC}"
    if ! confirm_action "确认要将 SSH 端口从 $old_port 更改为 $new_port 吗?"; then echo "操作已取消。"; return; fi
    if command_exists ufw && ufw status | grep -q "Status: active"; then echo -e "${BLUE}[*] 在 UFW 中允许新端口 $new_port/tcp ...${NC}"; ufw allow $new_port/tcp comment "SSH Access (New)" > /dev/null; if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] UFW 允许新端口失败！中止操作以防锁死。${NC}"; return 1; fi; echo -e "${GREEN}[✓] UFW 已允许新端口 $new_port/tcp。${NC}"; else echo -e "${YELLOW}[!] UFW 未安装或未启用，跳过防火墙规则添加。请手动确保端口可访问！${NC}"; fi
    echo -e "${BLUE}[*] 修改 SSH 配置文件 ($SSHD_CONFIG)...${NC}"; cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak_port_$(date +%F_%T)"; if update_or_add_config "$SSHD_CONFIG" "" "Port" "$new_port"; then echo -e "${GREEN}[✓] SSH 配置文件已修改。${NC}"; else echo -e "${RED}[✗] 修改 SSH 配置文件失败。${NC}"; return 1; fi
    echo -e "${BLUE}[*] 重启 SSH 服务...${NC}"; echo -e "${YELLOW}服务重启后，当前连接可能会断开。请使用新端口 $new_port 重新连接。${NC}"; systemctl restart sshd; sleep 3
    if systemctl is-active --quiet sshd; then echo -e "${GREEN}[✓] SSH 服务已成功重启。${NC}"; CURRENT_SSH_PORT=$new_port; else echo -e "${RED}[✗] SSH 服务重启失败！请立即检查 SSH 配置 (${SSHD_CONFIG}) 和服务状态 ('systemctl status sshd')。${NC}"; echo -e "${RED}   旧配置已备份为 ${SSHD_CONFIG}.bak_port_* 。${NC}"; return 1; fi
    if command_exists ufw && ufw status | grep -q "Status: active"; then echo -e "${BLUE}[*] 在 UFW 中删除旧端口 $old_port/tcp 的规则...${NC}"; ufw delete allow $old_port/tcp > /dev/null 2>&1; ufw delete allow $old_port > /dev/null 2>&1; echo -e "${GREEN}[✓] 尝试删除旧 UFW 规则完成 (如果存在)。${NC}"; fi
    if command_exists fail2ban-client; then echo -e "${BLUE}[*] 重新配置 Fail2ban 以监控新端口 $new_port ...${NC}"; if configure_fail2ban; then echo -e "${BLUE}[*] 重启 Fail2ban 服务以应用新端口...${NC}"; systemctl restart fail2ban; sleep 2; if systemctl is-active --quiet fail2ban; then echo -e "${GREEN}[✓] Fail2ban 服务已重启。${NC}"; else echo -e "${RED}[✗] Fail2ban 服务重启失败。${NC}"; fi; else echo -e "${RED}[✗] Fail2ban 配置更新失败。${NC}"; fi; else echo -e "${YELLOW}[!] Fail2ban 未安装，跳过其配置更新。${NC}"; fi
    echo -e "${GREEN}[✓] SSH 端口更改完成。请记住使用新端口 $new_port 登录。${NC}"; return 0
}

create_sudo_user() {
    echo -e "\n${CYAN}--- 5.2 创建新的 Sudo 用户 ---${NC}"; local username
    while true; do read -p "请输入新用户名: " username; if [[ -z "$username" ]]; then echo -e "${YELLOW}用户名不能为空。${NC}"; elif id "$username" &>/dev/null; then echo -e "${YELLOW}用户 '$username' 已存在。${NC}"; elif [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then break; else echo -e "${YELLOW}无效的用户名格式 (建议使用小写字母、数字、下划线、连字符，并以字母或下划线开头)。${NC}"; fi; done
    echo -e "${BLUE}[*] 添加用户 '$username' 并设置密码...${NC}"; adduser "$username"; if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 添加用户失败。${NC}"; return 1; fi
    echo -e "${BLUE}[*] 将用户 '$username' 添加到 sudo 组...${NC}"; usermod -aG sudo "$username"; if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 添加到 sudo 组失败。${NC}"; return 1; fi
    echo -e "${GREEN}[✓] 用户 '$username' 创建成功并已添加到 sudo 组。${NC}"; echo -e "${YELLOW}请使用新用户登录并测试 sudo权限 (例如 'sudo whoami')。${NC}"; echo -e "${YELLOW}建议在新用户能够正常登录并使用 sudo 后，再考虑禁用 root 登录。${NC}"; return 0
}

disable_root_login() {
    echo -e "\n${CYAN}--- 5.3 禁用 Root 用户 SSH 登录 ---${NC}"; echo -e "${RED}[!] 警告：禁用 Root 登录前，请确保您已创建具有 Sudo 权限的普通用户，并且该用户可以正常通过 SSH 登录！${NC}"
    if ! confirm_action "确认要禁止 Root 用户通过 SSH 登录吗?"; then echo "操作已取消。"; return; fi
    echo -e "${BLUE}[*] 修改 SSH 配置文件 ($SSHD_CONFIG) 以禁用 Root 登录...${NC}"; cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak_root_$(date +%F_%T)"; if ! update_or_add_config "$SSHD_CONFIG" "" "PermitRootLogin" "no"; then echo -e "${RED}[✗] 修改 SSH 配置文件失败 (PermitRootLogin)。${NC}"; return 1; fi
    echo -e "${BLUE}[*] 重启 SSH 服务以应用更改...${NC}"; systemctl restart sshd; sleep 2; if systemctl is-active --quiet sshd; then echo -e "${GREEN}[✓] Root 用户 SSH 登录已禁用。${NC}"; else echo -e "${RED}[✗] SSH 服务重启失败！请检查配置。Root 登录可能仍被允许。${NC}"; echo -e "${RED}   旧配置已备份为 ${SSHD_CONFIG}.bak_root_* 。${NC}"; return 1; fi; return 0
}

add_public_key() {
    local target_user="$1"; local user_home; local ssh_dir; local auth_keys_file; local pub_key_input; local pub_key_cleaned
    if ! id "$target_user" &>/dev/null; then echo -e "${RED}[✗] 用户 '$target_user' 不存在。${NC}"; return 1; fi
    user_home=$(eval echo ~$target_user); if [[ ! -d "$user_home" ]]; then echo -e "${YELLOW}[!] 用户 '$target_user' 的家目录 ($user_home) 不存在。尝试创建...${NC}"; mkdir -p "$user_home"; chown "${target_user}:${target_user}" "$user_home"; if [[ ! -d "$user_home" ]]; then echo -e "${RED}[✗] 创建家目录失败。${NC}"; return 1; fi; fi
    ssh_dir="${user_home}/.ssh"; auth_keys_file="${ssh_dir}/authorized_keys"
    echo -e "${BLUE}[*] 请【一次性】粘贴您的【单行公钥】内容 (例如 'ssh-ed25519 AAA... comment')，然后按 Enter 键:${NC}"; read -r pub_key_input; if [[ -z "$pub_key_input" ]]; then echo -e "${YELLOW}未输入任何内容，操作取消。${NC}"; return 1; fi
    pub_key_cleaned=$(echo "$pub_key_input" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e "s/^'//" -e "s/'$//" -e 's/^"//' -e 's/"$//')
    local key_regex="^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp(256|384|521))\s+AAAA[0-9A-Za-z+/]+[=]{0,3}(\s+.*)?$"; if ! [[ "$pub_key_cleaned" =~ $key_regex ]]; then echo -e "${RED}[✗] 输入的内容似乎不是有效的 SSH 公钥格式。操作取消。${NC}"; echo -e "${YELLOW}   公钥通常以 'ssh-rsa', 'ssh-ed25519' 或 'ecdsa-...' 开头，后跟一长串 Base64 字符。${NC}"; echo -e "${YELLOW}   清理后的输入为: '$pub_key_cleaned' ${NC}"; return 1; fi
    echo -e "${BLUE}[*] 准备将以下公钥添加到用户 '$target_user' 的 ${auth_keys_file} 文件中:${NC}"; echo -e "${CYAN}${pub_key_cleaned}${NC}"; if ! confirm_action "确认添加吗?"; then echo "操作已取消。"; return 1; fi
    echo -e "${BLUE}[*] 确保目录和文件存在并设置权限...${NC}"; mkdir -p "$ssh_dir"; touch "$auth_keys_file"; chmod 700 "$ssh_dir"; chmod 600 "$auth_keys_file"; chown -R "${target_user}:${target_user}" "$ssh_dir"
    if grep -qF "$pub_key_cleaned" "$auth_keys_file"; then echo -e "${YELLOW}[!] 此公钥似乎已存在于 ${auth_keys_file} 中，无需重复添加。${NC}"; return 0; fi
    echo "$pub_key_cleaned" >> "$auth_keys_file"; if [[ $? -eq 0 ]]; then echo -e "${GREEN}[✓] 公钥已成功添加到 ${auth_keys_file}。${NC}"; return 0; else echo -e "${RED}[✗] 将公钥写入文件失败。${NC}"; return 1; fi
}

configure_ssh_keys() {
    echo -e "\n${CYAN}--- 5.4 配置 SSH 密钥登录 (禁用密码登录) ---${NC}"; local key_config_choice
    while true; do echo -e "请选择操作:"; echo -e "  ${YELLOW}1.${NC} 添加公钥 (粘贴公钥内容让脚本添加)"; echo -e "  ${YELLOW}2.${NC} 禁用 SSH 密码登录 ${RED}(高风险! 请确保密钥已添加并测试成功)${NC}"; echo -e "  ${YELLOW}0.${NC} 返回 SSH 安全菜单"; read -p "请输入选项 [0-2]: " key_config_choice
        case $key_config_choice in 1) local target_user; read -p "请输入要为其添加公钥的用户名: " target_user; if [[ -n "$target_user" ]]; then add_public_key "$target_user"; else echo -e "${YELLOW}用户名不能为空。${NC}"; fi; read -p "按 Enter键 继续..."; ;; 2) echo -e "${RED}[!] 警告：这是高风险操作！在禁用密码登录前，请务必完成以下步骤：${NC}"; echo -e "${YELLOW}  1. 在您的本地计算机上生成 SSH 密钥对 (例如使用 'ssh-keygen')。${NC}"; echo -e "${YELLOW}  2. 使用上面的【选项1】或其他方法，将您的【公钥】复制到服务器上目标用户的 ~/.ssh/authorized_keys 文件中。${NC}"; echo -e "${YELLOW}  3. 【重要】在禁用密码登录【之前】，打开一个新的终端窗口，尝试使用【密钥】登录服务器，确保可以成功登录！${NC}"; if ! confirm_action "您是否已经完成上述所有步骤，并确认可以通过密钥成功登录?"; then echo "操作已取消。请先确保密钥设置正确并可成功登录。"; continue; fi; echo -e "${BLUE}[*] 修改 SSH 配置文件 ($SSHD_CONFIG) 以启用密钥登录并禁用密码登录...${NC}"; cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak_key_$(date +%F_%T)"; if ! update_or_add_config "$SSHD_CONFIG" "" "PubkeyAuthentication" "yes"; then echo -e "${RED}[✗] 修改 SSH 配置文件失败 (PubkeyAuthentication)。${NC}"; continue; fi; if ! update_or_add_config "$SSHD_CONFIG" "" "PasswordAuthentication" "no"; then echo -e "${RED}[✗] 修改 SSH 配置文件失败 (PasswordAuthentication)。${NC}"; continue; fi; if ! update_or_add_config "$SSHD_CONFIG" "" "ChallengeResponseAuthentication" "no"; then echo -e "${RED}[✗] 修改 SSH 配置文件失败 (ChallengeResponseAuthentication)。${NC}"; continue; fi; echo -e "${YELLOW}[!] UsePAM 设置未修改，保持默认。${NC}"; echo -e "${BLUE}[*] 重启 SSH 服务以应用更改...${NC}"; systemctl restart sshd; sleep 2; if systemctl is-active --quiet sshd; then echo -e "${GREEN}[✓] SSH 已配置为仅允许密钥登录，密码登录已禁用。${NC}"; echo -e "${RED}请立即尝试使用密钥重新登录以确认！如果无法登录，您可能需要通过控制台或其他方式恢复备份配置 (${SSHD_CONFIG}.bak_key_*)。${NC}"; else echo -e "${RED}[✗] SSH 服务重启失败！请检查配置。密码登录可能仍然启用。${NC}"; echo -e "${RED}   旧配置已备份为 ${SSHD_CONFIG}.bak_key_* 。${NC}"; fi; read -p "按 Enter键 继续..."; ;; 0) break ;; *) echo -e "${RED}无效选项。${NC}" ;; esac
    done
}

# 修改用户登录密码
change_ssh_password() {
    echo -e "\n${CYAN}--- 5.5 修改 SSH 登录密码 ---${NC}"
    local target_user
    
    read -p "请输入要修改密码的用户名 (留空默认 root): " target_user
    target_user=${target_user:-root}

    if ! id "$target_user" &>/dev/null; then
        echo -e "${RED}[✗] 用户 '$target_user' 不存在。${NC}"
        return 1
    fi

    echo -e "${BLUE}[*] 正在修改用户 ${YELLOW}$target_user${BLUE} 的密码...${NC}"
    echo -e "${YELLOW}提示: 输入密码时屏幕不会显示任何字符，输入完毕后按回车即可。${NC}"
    
    passwd "$target_user"
    
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}[✓] 用户 '$target_user' 的密码修改成功！${NC}"
        echo -e "${YELLOW}请记住您的新密码，下次登录时生效。${NC}"
    else
        echo -e "${RED}[✗] 密码修改失败。可能是两次输入不一致或太简单。${NC}"
    fi
}

# SSH 安全管理菜单
manage_ssh_security() {
     while true; do
        echo -e "\n${CYAN}--- 5. SSH 安全管理 ---${NC}"
        echo -e " 当前 SSH 端口: ${YELLOW}${CURRENT_SSH_PORT}${NC}"
        echo -e " ${YELLOW}1.${NC} 更改 SSH 端口 (自动更新 UFW, Fail2ban)"
        echo -e " ${YELLOW}2.${NC} 创建新的 Sudo 用户"
        echo -e " ${YELLOW}3.${NC} 禁用 Root 用户 SSH 登录"
        echo -e " ${YELLOW}4.${NC} 配置 SSH 密钥登录与密码禁用"
        echo -e " ${YELLOW}5.${NC} 修改 SSH 登录密码"
        echo -e " ${YELLOW}0.${NC} 返回主菜单"
        read -p "请输入选项 [0-5]: " ssh_choice

        case $ssh_choice in
            1) change_ssh_port ;;
            2) create_sudo_user ;;
            3) disable_root_login ;;
            4) configure_ssh_keys ;;
            5) change_ssh_password ;;
            0) break ;;
            *) echo -e "${RED}无效选项。${NC}" ;;
        esac
        [[ $ssh_choice != 0 ]] && read -p "按 Enter键 继续..."
        check_root
    done
}

# --- 9. Web 服务 (Let's Encrypt + Cloudflare + Nginx) ---

install_or_update_certbot() {
    echo -e "${BLUE}[*] 检查 Certbot 安装情况并优先使用 apt 版本...${NC}"
    local apt_certbot_pkg="certbot"
    local apt_cf_plugin_pkg="python3-certbot-dns-cloudflare"
    local snap_certbot_name="certbot"
    local snap_cf_plugin_name="certbot-dns-cloudflare"

    if dpkg -s "$apt_certbot_pkg" &> /dev/null && dpkg -s "$apt_cf_plugin_pkg" &> /dev/null; then
        echo -e "${GREEN}[✓] Certbot 和 Cloudflare 插件 (apt) 已安装。${NC}"
        return 0
    else
        echo -e "${BLUE}[*] 尝试使用 apt 安装 Certbot 及其 Cloudflare 插件...${NC}"
        if install_package "$apt_certbot_pkg" && install_package "$apt_cf_plugin_pkg"; then
            echo -e "${GREEN}[✓] Certbot 和 Cloudflare 插件 (apt) 安装成功。${NC}"
            return 0
        else
            echo -e "${YELLOW}[!] apt 安装失败。尝试使用 snap 安装...${NC}"
        fi
    fi

    if command_exists snap; then
        echo -e "${BLUE}[*] 尝试使用 Snap 安装 Certbot...${NC}"
        if snap install --classic "$snap_certbot_name"; then
            echo -e "${GREEN}[✓] Certbot (Snap) 安装成功。${NC}"
            echo -e "${BLUE}[*] 检查/安装 Certbot Cloudflare 插件 (Snap)...${NC}"
            if snap install "$snap_cf_plugin_name"; then
                echo -e "${GREEN}[✓] Cloudflare 插件 (Snap) 安装成功。${NC}"
                echo -e "${BLUE}[*] 尝试连接 Certbot 插件...${NC}"
                snap connect "$snap_certbot_name:plugin" "$snap_cf_plugin_name" &>/dev/null || echo -e "${YELLOW}[!] 无法自动连接插件，可能需要手动执行: sudo snap connect certbot:plugin certbot-dns-cloudflare ${NC}"
                snap connect "$snap_cf_plugin_name:snapd-access" "$snap_certbot_name:snapd-access" &>/dev/null || true;
                if ! command_exists certbot; then
                    echo -e "${BLUE}[*] 创建 certbot 软链接...${NC}"
                    ln -sf /snap/bin/certbot /usr/bin/certbot
                fi
                snap set certbot trust-plugin-with-root=ok
                return 0
            else
                echo -e "${RED}[✗] Cloudflare 插件 (Snap) 安装失败！证书申请将失败。${NC}"
                return 1
            fi
        else
            echo -e "${RED}[✗] Certbot (Snap) 安装失败。${NC}"
            return 1
        fi
    else
        echo -e "${RED}[✗] snap 命令不可用，且 apt 安装失败。无法安装 Certbot。${NC}"
        return 1
    fi
    echo -e "${RED}[✗] Certbot 最终未能成功安装。请手动安装 Certbot 及其 Cloudflare 插件。${NC}"
    return 1
}

get_user_input_initial() {
    DOMAIN="" CF_API_TOKEN="" DDNS_FREQUENCY=5 RECORD_TYPE="" SELECTED_IP="" ZONE_ID="" ZONE_NAME="" LOCAL_PROXY_PASS="" BACKEND_PROTOCOL="http" NGINX_HTTP_PORT=80 NGINX_HTTPS_PORT=443
    echo -e "${BLUE}[*] 请输入首次设置所需信息:${NC}"; echo -e "${YELLOW}Let's Encrypt 注册邮箱已固定为: ${EMAIL}${NC}"
    while [[ -z "$DOMAIN" ]]; do read -p "请输入您要申请/管理的域名 (例如 my.example.com): " DOMAIN; done
    if ! [[ "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then echo -e "${RED}[✗] 域名格式似乎不正确。${NC}"; return 1; fi
    if [[ -f "${CONFIG_DIR}/${DOMAIN}.conf" ]]; then echo -e "${YELLOW}[!] 域名 ${DOMAIN} 的配置已存在。如果您想修改，请先删除旧配置 (选项 9-3)。${NC}"; return 1; fi
    while [[ -z "$CF_API_TOKEN" ]]; do read -p "请输入您的 Cloudflare API Token (确保有 Zone:Read, DNS:Edit 权限): " CF_API_TOKEN; done
    while true; do read -p "请输入 DDNS 自动更新频率 (分钟, 输入 0 禁用 DDNS, 默认 5): " freq_input; if [[ -z "$freq_input" ]]; then DDNS_FREQUENCY=5; echo -e "DDNS 更新频率设置为: ${GREEN}5 分钟${NC}"; break; elif [[ "$freq_input" =~ ^[0-9]+$ ]]; then DDNS_FREQUENCY=$freq_input; if [[ "$DDNS_FREQUENCY" -eq 0 ]]; then echo -e "${YELLOW}DDNS 功能已禁用。${NC}"; else echo -e "DDNS 更新频率设置为: ${GREEN}${DDNS_FREQUENCY} 分钟${NC}"; fi; break; else echo -e "${YELLOW}请输入一个非负整数。${NC}"; fi; done
    update_paths_for_domain "$DOMAIN"; return 0
}

update_paths_for_domain() {
    local current_domain="$1"
    CERT_PATH="${CERT_PATH_PREFIX}/${current_domain}"
    CLOUDFLARE_CREDENTIALS="/root/.cloudflare-${current_domain}.ini"
    DEPLOY_HOOK_SCRIPT="/root/cert-renew-hook-${current_domain}.sh"
    DDNS_SCRIPT_PATH="/usr/local/bin/cf_ddns_update_${current_domain}.sh"
    NGINX_CONF_PATH="/etc/nginx/sites-available/${current_domain}.conf"
}

create_cf_credentials() {
    echo -e "${BLUE}[*] 创建 Cloudflare API Token 凭证文件...${NC}"; mkdir -p "$(dirname "$CLOUDFLARE_CREDENTIALS")"
    cat > "$CLOUDFLARE_CREDENTIALS" <<EOF
# Cloudflare API credentials used by Certbot for domain: ${DOMAIN}
# Generated by script: $(date)
# Using API Token authentication method
dns_cloudflare_api_token = $CF_API_TOKEN
EOF
    chmod 600 "$CLOUDFLARE_CREDENTIALS"; if [[ $? -eq 0 ]]; then echo -e "${GREEN}[✓] 凭证文件创建成功: ${CLOUDFLARE_CREDENTIALS}${NC}"; return 0; else echo -e "${RED}[✗] 创建凭证文件失败 (权限设置?)。${NC}"; return 1; fi
}

detect_public_ip() {
    echo -e "${BLUE}[*] 检测公网 IP 地址...${NC}"; DETECTED_IPV4=$(curl -4s --max-time 5 https://api.ipify.org || curl -4s --max-time 5 https://ifconfig.me/ip || curl -4s --max-time 5 https://ipv4.icanhazip.com || echo ""); DETECTED_IPV6=$(curl -6s --max-time 5 https://api64.ipify.org || curl -6s --max-time 5 https://ifconfig.me/ip || curl -6s --max-time 5 https://ipv6.icanhazip.com || echo ""); echo "检测结果:"; if [[ -n "$DETECTED_IPV4" ]]; then echo -e "  - IPv4: ${GREEN}$DETECTED_IPV4${NC}"; else echo -e "  - IPv4: ${RED}未检测到${NC}"; fi; if [[ -n "$DETECTED_IPV6" ]]; then echo -e "  - IPv6: ${GREEN}$DETECTED_IPV6${NC}"; else echo -e "  - IPv6: ${RED}未检测到${NC}"; fi
    if [[ -z "$DETECTED_IPV4" && -z "$DETECTED_IPV6" ]]; then echo -e "${RED}[✗] 无法检测到任何公网 IP 地址。请检查网络连接。脚本无法继续。${NC}"; return 1; fi; return 0
}

select_record_type() {
    echo -e "${BLUE}[*] 请选择要使用的 DNS 记录类型和 IP 地址:${NC}"; options=(); ips=(); types=(); if [[ -n "$DETECTED_IPV4" ]]; then options+=("IPv4 (A 记录) - ${DETECTED_IPV4}"); ips+=("$DETECTED_IPV4"); types+=("A"); fi; if [[ -n "$DETECTED_IPV6" ]]; then options+=("IPv6 (AAAA 记录) - ${DETECTED_IPV6}"); ips+=("$DETECTED_IPV6"); types+=("AAAA"); fi; options+=("退出")
    select opt in "${options[@]}"; do choice_index=$((REPLY - 1)); if [[ "$opt" == "退出" ]]; then echo "用户选择退出。"; return 1; elif [[ $choice_index -ge 0 && $choice_index -lt ${#ips[@]} ]]; then RECORD_TYPE=${types[$choice_index]}; SELECTED_IP=${ips[$choice_index]}; echo -e "已选择: ${GREEN}${RECORD_TYPE} - $SELECTED_IP${NC}"; break; else echo "无效选项 $REPLY"; fi; done
    if [[ -z "$RECORD_TYPE" || -z "$SELECTED_IP" ]]; then echo -e "${RED}[✗] 未选择有效的记录类型或 IP 地址。脚本无法继续。${NC}"; return 1; fi; return 0
}

get_zone_id() {
    echo -e "${BLUE}[*] 获取 Cloudflare Zone ID...${NC}"; ZONE_NAME=$(echo "$DOMAIN" | awk -F. '{if (NF>2) print $(NF-1)"."$NF; else print $0}'); echo "尝试获取 Zone Name: $ZONE_NAME"
    ZONE_ID_JSON=$(curl -s --max-time 10 -X GET "$CF_API/zones?name=$ZONE_NAME&status=active" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json"); if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API 失败 (网络错误或超时)。${NC}"; return 1; fi
    if ! echo "$ZONE_ID_JSON" | jq -e '.success == true' > /dev/null; then local error_msg=$(echo "$ZONE_ID_JSON" | jq -r '.errors[0].message // "未知 API 错误"'); echo -e "${RED}[✗] Cloudflare API 返回错误: ${error_msg}${NC}"; return 1; fi
    ZONE_ID=$(echo "$ZONE_ID_JSON" | jq -r '.result[0].id'); if [[ "$ZONE_ID" == "null" || -z "$ZONE_ID" ]]; then echo -e "${RED}[✗] 无法找到域名 $ZONE_NAME 对应的活动 Zone ID。请检查域名和 API Token 是否正确且有 Zone:Read 权限。${NC}"; return 1; fi
    echo -e "${GREEN}[✓] 找到 Zone ID: $ZONE_ID${NC}"; return 0
}

manage_cloudflare_record() {
    local action="$1"; local force_proxy_status="false"; echo -e "${BLUE}[*] ${action} Cloudflare DNS 记录 ($RECORD_TYPE) 并确保代理关闭...${NC}"; echo "正在检查 $DOMAIN 的 $RECORD_TYPE 记录..."
    local RECORD_INFO=$(curl -s --max-time 10 -X GET "$CF_API/zones/$ZONE_ID/dns_records?type=$RECORD_TYPE&name=$DOMAIN" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json"); if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (获取记录) 失败。${NC}"; return 1; fi; if ! echo "$RECORD_INFO" | jq -e '.success == true' > /dev/null; then echo -e "${RED}[✗] Cloudflare API 返回错误 (获取记录): $(echo "$RECORD_INFO" | jq -r '.errors[0].message // "未知 API 错误"')${NC}"; return 1; fi
    local RECORD_ID=$(echo "$RECORD_INFO" | jq -r '.result[0].id'); local CURRENT_IP=$(echo "$RECORD_INFO" | jq -r '.result[0].content'); local CURRENT_PROXIED=$(echo "$RECORD_INFO" | jq -r '.result[0].proxied')
    if [[ "$RECORD_ID" == "null" || -z "$RECORD_ID" ]]; then echo "未找到 $RECORD_TYPE 记录，正在创建 (代理状态: ${force_proxy_status})..."; local CREATE_RESULT=$(curl -s --max-time 10 -X POST "$CF_API/zones/$ZONE_ID/dns_records" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" --data "{\"type\":\"$RECORD_TYPE\",\"name\":\"$DOMAIN\",\"content\":\"$SELECTED_IP\",\"ttl\":120,\"proxied\":${force_proxy_status}}"); if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (创建记录) 失败。${NC}"; return 1; fi; if echo "$CREATE_RESULT" | jq -e '.success == true' > /dev/null; then echo -e "${GREEN}[✓] $RECORD_TYPE 记录创建成功: $DOMAIN -> $SELECTED_IP (代理: ${force_proxy_status})${NC}"; else echo -e "${RED}[✗] 创建 $RECORD_TYPE 记录失败: $(echo "$CREATE_RESULT" | jq -r '.errors[0].message // "未知 API 错误"')${NC}"; return 1; fi
    else echo "找到 $RECORD_TYPE 记录 (ID: $RECORD_ID)，当前 IP: $CURRENT_IP, 当前代理: $CURRENT_PROXIED"; if [[ "$CURRENT_IP" != "$SELECTED_IP" || "$CURRENT_PROXIED" != "$force_proxy_status" ]]; then echo "IP 或代理状态不符，正在更新 (目标 IP: $SELECTED_IP, 目标代理: ${force_proxy_status})..."; local UPDATE_RESULT=$(curl -s --max-time 10 -X PUT "$CF_API/zones/$ZONE_ID/dns_records/$RECORD_ID" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" --data "{\"type\":\"$RECORD_TYPE\",\"name\":\"$DOMAIN\",\"content\":\"$SELECTED_IP\",\"ttl\":120,\"proxied\":${force_proxy_status}}"); if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (更新记录) 失败。${NC}"; return 1; fi; if echo "$UPDATE_RESULT" | jq -e '.success == true' > /dev/null; then echo -e "${GREEN}[✓] $RECORD_TYPE 记录更新成功: $DOMAIN -> $SELECTED_IP (代理: ${force_proxy_status})${NC}"; else echo -e "${RED}[✗] 更新 $RECORD_TYPE 记录失败: $(echo "$UPDATE_RESULT" | jq -r '.errors[0].message // "未知 API 错误"')${NC}"; return 1; fi; else echo -e "${GREEN}[✓] $RECORD_TYPE 记录已是最新 ($CURRENT_IP, 代理: ${force_proxy_status})，无需更新。${NC}"; fi; fi; return 0
}

enable_cloudflare_proxy() {
    local domain_to_proxy="$1"; echo -e "${BLUE}[*] 尝试为域名 $domain_to_proxy 开启 Cloudflare 代理 (橙色云朵)...${NC}"
    if [[ -z "$ZONE_ID" || -z "$RECORD_TYPE" || -z "$CF_API_TOKEN" || -z "$SELECTED_IP" || -z "$domain_to_proxy" ]]; then echo -e "${RED}[✗] 缺少必要信息 (Zone ID, Record Type, Token, IP, Domain)，无法开启代理。${NC}"; return 1; fi
    local RECORD_INFO=$(curl -s --max-time 10 -X GET "$CF_API/zones/$ZONE_ID/dns_records?type=$RECORD_TYPE&name=$domain_to_proxy" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json"); if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (获取记录 ID) 失败。${NC}"; return 1; fi; if ! echo "$RECORD_INFO" | jq -e '.success == true' > /dev/null; then echo -e "${RED}[✗] Cloudflare API 返回错误 (获取记录 ID): $(echo "$RECORD_INFO" | jq -r '.errors[0].message // "未知 API 错误"')${NC}"; return 1; fi; local RECORD_ID=$(echo "$RECORD_INFO" | jq -r '.result[0].id'); if [[ "$RECORD_ID" == "null" || -z "$RECORD_ID" ]]; then echo -e "${RED}[✗] 未找到域名 $domain_to_proxy 的 $RECORD_TYPE 记录，无法开启代理。${NC}"; return 1; fi
    echo "正在更新记录 $RECORD_ID，设置 proxied=true ..."; local UPDATE_RESULT=$(curl -s --max-time 10 -X PUT "$CF_API/zones/$ZONE_ID/dns_records/$RECORD_ID" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" --data "{\"type\":\"$RECORD_TYPE\",\"name\":\"$domain_to_proxy\",\"content\":\"$SELECTED_IP\",\"ttl\":120,\"proxied\":true}")
    if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (设置代理) 失败。${NC}"; return 1; fi; if echo "$UPDATE_RESULT" | jq -e '.success == true' > /dev/null; then echo -e "${GREEN}[✓] 成功为 $domain_to_proxy ($RECORD_TYPE) 开启 Cloudflare 代理。${NC}"; return 0; else echo -e "${RED}[✗] 开启 Cloudflare 代理失败: $(echo "$UPDATE_RESULT" | jq -r '.errors[0].message // "未知 API 错误"')${NC}"; return 1; fi
}

request_certificate() {
    echo -e "${BLUE}[*] 申请 SSL 证书 (Let's Encrypt)...${NC}"; local certbot_cmd=$(command -v certbot)
    "$certbot_cmd" certonly --dns-cloudflare --dns-cloudflare-credentials "$CLOUDFLARE_CREDENTIALS" --dns-cloudflare-propagation-seconds 60 -d "$DOMAIN" --email "$EMAIL" --agree-tos --no-eff-email --non-interactive --logs-dir /var/log/letsencrypt
    local cert_status=$?; if [[ $cert_status -ne 0 ]]; then echo -e "${RED}[✗] Certbot 命令执行失败 (退出码: $cert_status)。${NC}"; echo -e "${RED}   请检查 certbot 日志 (/var/log/letsencrypt/letsencrypt.log) 获取详细信息。${NC}"; if [[ -f /var/log/letsencrypt/letsencrypt.log ]]; then echo -e "${YELLOW}--- 最近的 Certbot 日志 ---${NC}"; tail -n 15 /var/log/letsencrypt/letsencrypt.log; echo -e "${YELLOW}--------------------------${NC}"; fi; return 1; fi
    if [[ ! -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" || ! -f "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" ]]; then echo -e "${RED}[✗] 证书文件在预期路径 (/etc/letsencrypt/live/${DOMAIN}/) 未找到，即使 Certbot 命令成功。${NC}"; echo -e "${RED}   请再次检查 Certbot 日志。${NC}"; return 1; fi
    echo -e "${GREEN}[✓] SSL 证书申请成功！${NC}"; return 0
}

copy_certificate() {
    echo -e "${BLUE}[*] 复制证书文件到 $CERT_PATH (为 3x-ui 等面板兼容)...${NC}"; mkdir -p "$CERT_PATH"
    if cp -L "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "${CERT_PATH}/fullchain.pem" && \
       cp -L "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "${CERT_PATH}/privkey.pem"; then
        echo -e "${GREEN}[✓] 证书文件已复制到 $CERT_PATH ${NC}";
        return 0
    else
        echo -e "${RED}[✗] 复制证书文件失败。请检查源文件是否存在以及目标路径权限。${NC}"
        return 1
    fi
}

create_nginx_ssl_snippet() {
    local snippet_path="/etc/nginx/snippets/ssl-params.conf"
    if [[ -f "$snippet_path" ]]; then return 0; fi
    echo -e "${BLUE}[*] 创建 Nginx SSL 参数文件: ${snippet_path} ...${NC}"
    mkdir -p "$(dirname "$snippet_path")"
    cat > "$snippet_path" <<EOF
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
add_header Strict-Transport-Security "max-age=15768000" always;
ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 8.8.8.8 valid=300s;
resolver_timeout 5s;
EOF
    return 0
}

setup_nginx_proxy() {
    if ! confirm_action "是否需要自动配置 Nginx 反向代理?"; then echo "跳过 Nginx 配置。"; NGINX_HTTP_PORT=80; NGINX_HTTPS_PORT=443; LOCAL_PROXY_PASS="none"; BACKEND_PROTOCOL="none"; return 0; fi
    while true; do read -p "请输入 Nginx 监听的 HTTP 端口 [默认: ${NGINX_HTTP_PORT}]: " http_port_input; if [[ -z "$http_port_input" ]]; then break; elif [[ "$http_port_input" =~ ^[0-9]+$ && "$http_port_input" -gt 0 && "$http_port_input" -le 65535 ]]; then NGINX_HTTP_PORT=$http_port_input; break; else echo -e "${YELLOW}无效端口号。${NC}"; fi; done
    while true; do read -p "请输入 Nginx 监听的 HTTPS 端口 [默认: ${NGINX_HTTPS_PORT}]: " https_port_input; if [[ -z "$https_port_input" ]]; then break; elif [[ "$https_port_input" =~ ^[0-9]+$ && "$https_port_input" -gt 0 && "$https_port_input" -le 65535 ]]; then if [[ "$https_port_input" -eq "$NGINX_HTTP_PORT" ]]; then echo -e "${YELLOW}HTTPS 端口不能与 HTTP 端口相同。${NC}"; else NGINX_HTTPS_PORT=$https_port_input; break; fi; else echo -e "${YELLOW}无效端口号。${NC}"; fi; done
    while true; do read -p "请选择后端服务 (${DOMAIN}) 使用的协议: [1] http (默认) [2] https : " proto_choice; if [[ -z "$proto_choice" || "$proto_choice" == "1" ]]; then BACKEND_PROTOCOL="http"; break; elif [[ "$proto_choice" == "2" ]]; then BACKEND_PROTOCOL="https"; break; else echo -e "${YELLOW}无效输入。${NC}"; fi; done
    local addr_input=""; while [[ -z "$LOCAL_PROXY_PASS" ]]; do read -p "请输入 Nginx 需要反向代理的本地服务地址 (只需 IP/域名 和 端口, 例如 localhost:8080): " addr_input; if [[ "$addr_input" =~ ^(\[([0-9a-fA-F:]+)\]|([a-zA-Z0-9.-]+)):([0-9]+)$ ]]; then LOCAL_PROXY_PASS="${BACKEND_PROTOCOL}://${addr_input}"; echo -e "将使用代理地址: ${GREEN}${LOCAL_PROXY_PASS}${NC}"; else echo -e "${YELLOW}地址格式不正确。${NC}"; LOCAL_PROXY_PASS=""; fi; done
    
    create_nginx_ssl_snippet || return 1
    echo -e "${BLUE}[*] 生成 Nginx 配置文件: $NGINX_CONF_PATH ...${NC}"; mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled; mkdir -p /var/www/html/.well-known/acme-challenge; chown www-data:www-data /var/www/html -R 2>/dev/null
    
    local redirect_suffix_bash=""; if [[ "${NGINX_HTTPS_PORT}" -ne 443 ]]; then redirect_suffix_bash=":${NGINX_HTTPS_PORT}"; fi
    cat > "$NGINX_CONF_PATH" <<EOF
server {
    listen ${NGINX_HTTP_PORT};
    listen [::]:${NGINX_HTTP_PORT};
    server_name ${DOMAIN};
    location ~ /.well-known/acme-challenge/ { allow all; root /var/www/html; }
    location / { return 301 https://\$host${redirect_suffix_bash}\$request_uri; }
}
server {
    listen ${NGINX_HTTPS_PORT} ssl http2;
    listen [::]:${NGINX_HTTPS_PORT} ssl http2;
    server_name ${DOMAIN};
    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/${DOMAIN}/chain.pem;
    include /etc/nginx/snippets/ssl-params.conf;
    location / {
        proxy_pass ${LOCAL_PROXY_PASS};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        $( [[ "$BACKEND_PROTOCOL" == "https" ]] && echo 'proxy_ssl_server_name on;' )
    }
}
EOF
    local enabled_link="/etc/nginx/sites-enabled/${DOMAIN}.conf"; if [[ -L "$enabled_link" ]]; then rm -f "$enabled_link"; fi; ln -s "$NGINX_CONF_PATH" "$enabled_link"; if [[ $? -eq 0 ]]; then echo -e "${GREEN}[✓] Nginx 配置已启用。${NC}"; else echo -e "${RED}[✗] 创建 Nginx 配置软链接失败。${NC}"; return 1; fi
    return 0
}

create_ddns_script() {
    if [[ "$DDNS_FREQUENCY" -le 0 ]]; then echo "${YELLOW}DDNS 已禁用，跳过创建。${NC}"; if [[ -f "$DDNS_SCRIPT_PATH" ]]; then rm -f "$DDNS_SCRIPT_PATH"; fi; return 0; fi
    echo -e "${BLUE}[*] 创建 DDNS 更新脚本 (v4.1): $DDNS_SCRIPT_PATH ...${NC}"; mkdir -p "$(dirname "$DDNS_SCRIPT_PATH")"
    local current_token; if [[ -f "$CLOUDFLARE_CREDENTIALS" ]]; then current_token=$(grep dns_cloudflare_api_token "$CLOUDFLARE_CREDENTIALS" | awk '{print $3}'); fi; if [[ -z "$current_token" ]]; then echo -e "${RED}[✗] 无法读取 API Token。${NC}"; return 1; fi

    cat > "$DDNS_SCRIPT_PATH" <<EOF
#!/bin/bash
CF_CREDENTIALS_FILE="${CLOUDFLARE_CREDENTIALS}"
DOMAIN="${DOMAIN}"
RECORD_TYPE="${RECORD_TYPE}"
ZONE_ID="${ZONE_ID}"
CF_API="https://api.cloudflare.com/client/v4"
LOG_FILE="/var/log/cf_ddns_update_${DOMAIN}.log"
TIMEOUT=10
IPV4_URLS=("https://api.ipify.org" "https://ifconfig.me/ip" "https://ipv4.icanhazip.com")
IPV6_URLS=("https://api64.ipify.org" "https://ifconfig.me/ip" "https://ipv6.icanhazip.com")
log_message() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1" >> "\$LOG_FILE"; }
get_current_ip() {
    local type=\$1; local curl_opt; local curl_ua="Bash-DDNS-Script/1.0"; local ip=""; local raw_output=""
    if [[ "\$type" == "A" ]]; then curl_opt="-4"; for url in "\${IPV4_URLS[@]}"; do raw_output=\$(curl \$curl_opt --user-agent "\$curl_ua" --max-time \$TIMEOUT "\$url" 2>/dev/null | head -n 1); ip=\$(echo "\$raw_output" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'); if [[ -n "\$ip" && "\$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo "\$ip"; return 0; fi; sleep 1; done
    elif [[ "\$type" == "AAAA" ]]; then curl_opt="-6"; for url in "\${IPV6_URLS[@]}"; do raw_output=\$(curl \$curl_opt --user-agent "\$curl_ua" --max-time \$TIMEOUT "\$url" 2>/dev/null | head -n 1); ip=\$(echo "\$raw_output" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'); if [[ -n "\$ip" && "\$ip" =~ ^([0-9a-fA-F:]+)$ && "\$ip" == *":"* ]]; then echo "\$ip"; return 0; fi; sleep 1; done
    else return 1; fi
    log_message "错误：无法获取 \$type IP 地址。"; return 1
}
get_cf_record() {
    local cf_token=\$1; RECORD_INFO=\$(curl -s --max-time \$TIMEOUT -X GET "\$CF_API/zones/\$ZONE_ID/dns_records?type=\$RECORD_TYPE&name=\$DOMAIN" -H "Authorization: Bearer \$cf_token" -H "Content-Type: application/json"); if [[ \$? -ne 0 ]]; then return 1; fi; if ! echo "\$RECORD_INFO" | jq -e '.success == true' > /dev/null; then log_message "API错误: \$(echo "\$RECORD_INFO" | jq -r '.errors[0].message')"; return 1; fi; echo "\$RECORD_INFO"; return 0
}
update_cf_record() {
    local cf_token=\$1; local record_id=\$2; local new_ip=\$3; local current_proxied_status=\$4; if [[ "\$current_proxied_status" != "true" && "\$current_proxied_status" != "false" ]]; then current_proxied_status="false"; fi
    UPDATE_RESULT=\$(curl -s --max-time \$TIMEOUT -X PUT "\$CF_API/zones/\$ZONE_ID/dns_records/\$record_id" -H "Authorization: Bearer \$cf_token" -H "Content-Type: application/json" --data "{\"type\":\"\$RECORD_TYPE\",\"name\":\"\$DOMAIN\",\"content\":\"\$new_ip\",\"ttl\":120,\"proxied\":\${current_proxied_status}}"); if [[ \$? -ne 0 ]]; then return 1; fi; if ! echo "\$UPDATE_RESULT" | jq -e '.success == true' > /dev/null; then log_message "API错误: \$(echo "\$UPDATE_RESULT" | jq -r '.errors[0].message')"; return 1; fi; return 0
}
mkdir -p \$(dirname "\$LOG_FILE"); if [[ ! -f "\$CF_CREDENTIALS_FILE" ]]; then exit 1; fi; CF_API_TOKEN=\$(grep dns_cloudflare_api_token "\$CF_CREDENTIALS_FILE" | awk '{print \$3}'); if [[ -z "\$CF_API_TOKEN" ]]; then exit 1; fi
CURRENT_IP=\$(get_current_ip "\$RECORD_TYPE"); if [[ \$? -ne 0 ]]; then exit 1; fi; RECORD_INFO_JSON=\$(get_cf_record "\$CF_API_TOKEN"); if [[ \$? -ne 0 ]]; then exit 1; fi
CF_IP=\$(echo "\$RECORD_INFO_JSON" | jq -r '.result[0].content'); RECORD_ID=\$(echo "\$RECORD_INFO_JSON" | jq -r '.result[0].id'); CF_PROXIED=\$(echo "\$RECORD_INFO_JSON" | jq -r '.result[0].proxied')
if [[ -z "\$RECORD_ID" || "\$RECORD_ID" == "null" ]]; then exit 1; fi; if [[ -z "\$CF_PROXIED" || "\$CF_PROXIED" == "null" ]]; then CF_PROXIED="false"; fi
if [[ "\$CURRENT_IP" != "\$CF_IP" ]]; then log_message "IP不匹配 ($CURRENT_IP vs $CF_IP). 更新中..."; update_cf_record "\$CF_API_TOKEN" "\$RECORD_ID" "\$CURRENT_IP" "\$CF_PROXIED"; if [[ \$? -eq 0 ]]; then log_message "成功更新。"; else log_message "更新失败。"; fi; fi
exit 0
EOF
    chmod +x "$DDNS_SCRIPT_PATH"; echo -e "${GREEN}[✓] DDNS 更新脚本 (v4.1) 创建成功。${NC}"; return 0
}

setup_cron_jobs() {
    echo -e "${BLUE}[*] 设置 Cron 定时任务...${NC}"; echo -e "${BLUE}[*] 创建增强版证书续期部署钩子: $DEPLOY_HOOK_SCRIPT ...${NC}"; mkdir -p "$(dirname "$DEPLOY_HOOK_SCRIPT")"
    
    cat > "$DEPLOY_HOOK_SCRIPT" <<EOF
#!/bin/bash
# [v7.0] 增强版证书续期部署钩子 for ${DOMAIN}
# Certbot 续期成功后触发

LOG_FILE="/var/log/cert_renew_${DOMAIN}.log"
CONFIG_FILE="${CERT_PATH_PREFIX}/.managed_domains/${DOMAIN}.conf"
LIVE_CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
CERT_PATH="${CERT_PATH}"
LOCAL_PROXY_PASS="none"

log_hook() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1" >> "\$LOG_FILE"; }
mkdir -p \$(dirname "\$LOG_FILE")
log_hook ">>> 开始执行部署钩子 <<<"

# 1. 复制证书 (兼容面板)
if [[ ! -d "\$CERT_PATH" ]]; then mkdir -p "\$CERT_PATH"; fi
if cp -L "\${LIVE_CERT_DIR}/fullchain.pem" "${CERT_PATH}/fullchain.pem" && \
   cp -L "\${LIVE_CERT_DIR}/privkey.pem" "${CERT_PATH}/privkey.pem"; then
    log_hook "SUCCESS: 证书已复制到 \$CERT_PATH"
else
    log_hook "ERROR: 证书复制失败!"
fi

# 2. 检查 Nginx 并重载
if [[ -f "\$CONFIG_FILE" ]]; then source "\$CONFIG_FILE"; fi

if [[ "\${LOCAL_PROXY_PASS}" != "none" ]] && command -v nginx >/dev/null 2>&1; then
    # 测试配置
    if nginx -t -c /etc/nginx/nginx.conf >/dev/null 2>&1; then
        if systemctl reload nginx; then
            log_hook "SUCCESS: Nginx 配置测试通过并已重载。"
        else
            log_hook "ERROR: Nginx 重载失败 (systemctl reload nginx failed)."
        fi
    else
        log_hook "CRITICAL: Nginx 配置测试失败！跳过重载以避免服务中断。"
    fi
else
    log_hook "INFO: 未配置 Nginx 代理或 Nginx 未安装，跳过重载。"
fi
log_hook ">>> 部署钩子结束 <<<"
exit 0
EOF
    chmod +x "$DEPLOY_HOOK_SCRIPT"; echo -e "${GREEN}[✓] 部署钩子脚本创建成功。${NC}"
    CRON_TAG_RENEW="# CertRenew_${DOMAIN}"; CRON_TAG_DDNS="# DDNSUpdate_${DOMAIN}"; local CRON_CONTENT
    (crontab -l 2>/dev/null | grep -v -F "$CRON_TAG_RENEW" | grep -v -F "$CRON_TAG_DDNS") | crontab -; CRON_CONTENT=$(crontab -l 2>/dev/null)
    local certbot_cmd=$(command -v certbot); if [[ -z "$certbot_cmd" ]]; then certbot_cmd="certbot"; fi
    CRON_CERT_RENEW="0 3 * * * $certbot_cmd renew --deploy-hook \"$DEPLOY_HOOK_SCRIPT\" >> /var/log/certbot_renew.log 2>&1 ${CRON_TAG_RENEW}"; echo "${CRON_CONTENT}"$'\n'"${CRON_CERT_RENEW}" | crontab -; echo -e "${GREEN}[✓] Cron 证书续期任务已设置。${NC}"
    if [[ "$DDNS_FREQUENCY" -gt 0 && -f "$DDNS_SCRIPT_PATH" ]]; then CRON_DDNS_UPDATE="*/${DDNS_FREQUENCY} * * * * $DDNS_SCRIPT_PATH ${CRON_TAG_DDNS}"; CRON_CONTENT=$(crontab -l 2>/dev/null); echo "${CRON_CONTENT}"$'\n'"${CRON_DDNS_UPDATE}" | crontab -; echo -e "${GREEN}[✓] Cron DDNS 更新任务已设置。${NC}"; fi
    return 0
}

save_domain_config() {
    echo -e "${BLUE}[*] 保存配置...${NC}"; mkdir -p "$CONFIG_DIR"; local config_file="${CONFIG_DIR}/${DOMAIN}.conf"
    cat > "$config_file" <<EOF
# Generated by script on $(date)
DOMAIN="${DOMAIN}"; CF_API_TOKEN="${CF_API_TOKEN}"; EMAIL="${EMAIL}"; CERT_PATH="${CERT_PATH}"; CLOUDFLARE_CREDENTIALS="${CLOUDFLARE_CREDENTIALS}"; DEPLOY_HOOK_SCRIPT="${DEPLOY_HOOK_SCRIPT}"; DDNS_SCRIPT_PATH="${DDNS_SCRIPT_PATH}"; DDNS_FREQUENCY="${DDNS_FREQUENCY}"; RECORD_TYPE="${RECORD_TYPE}"; ZONE_ID="${ZONE_ID}"; NGINX_CONF_PATH="${NGINX_CONF_PATH}"; LOCAL_PROXY_PASS="${LOCAL_PROXY_PASS}"; BACKEND_PROTOCOL="${BACKEND_PROTOCOL}"; NGINX_HTTP_PORT="${NGINX_HTTP_PORT}"; NGINX_HTTPS_PORT="${NGINX_HTTPS_PORT}"
EOF
    chmod 600 "$config_file"; echo -e "${GREEN}[✓] 配置已保存。${NC}"
}

list_configured_domains() {
    echo -e "\n${CYAN}--- 当前已配置的 Web 服务域名列表 ---${NC}"
    mkdir -p "$CONFIG_DIR"
    if ! ls "${CONFIG_DIR}"/*.conf 1> /dev/null 2>&1; then echo -e "${YELLOW}未找到任何已配置的 Web 服务域名。${NC}"; return 1; fi
    local i=1
    for config_file in "${CONFIG_DIR}"/*.conf; do
        if [[ -f "$config_file" && -r "$config_file" ]]; then
            source "$config_file"
            echo -e " ${YELLOW}[$i]${NC} -------------------------------------"
            echo -e "     ${CYAN}Domain:${NC}         ${GREEN}${DOMAIN}${NC}"
            if [[ "$LOCAL_PROXY_PASS" != "none" ]]; then
                echo -e "     ${CYAN}Proxy Target:${NC}   ${GREEN}${LOCAL_PROXY_PASS}${NC}"
                echo -e "     ${CYAN}Listening Port:${NC} ${GREEN}${NGINX_HTTPS_PORT} (HTTPS)${NC}"
            else echo -e "     ${CYAN}Proxy Target:${NC}   ${YELLOW}未配置 Nginx 代理${NC}"; fi
            ((i++))
        fi
    done
    echo -e "     -------------------------------------"
    return 0
}

delete_domain_config() {
    echo -e "${RED}[!] 删除 Web 服务域名配置是一个危险操作！${NC}"; list_configured_domains; if [[ $? -ne 0 ]]; then return; fi; local domains=(); for config_file in "${CONFIG_DIR}"/*.conf; do if [[ -f "$config_file" && -r "$config_file" ]]; then domains+=("$(basename "$config_file" .conf)"); fi; done; local choice; local DOMAIN_TO_DELETE
    while true; do read -p "请输入要删除的域名的序号 (输入 '0' 退出): " choice; if [[ "$choice" == "0" ]]; then echo "取消删除操作。"; return; fi; if [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#domains[@]} ]]; then local index=$((choice - 1)); DOMAIN_TO_DELETE=${domains[$index]}; break; else echo -e "${YELLOW}无效的序号。${NC}"; fi; done
    echo -e "${RED}确认删除域名 ${DOMAIN_TO_DELETE} 的所有本地配置吗？${NC}"; if ! confirm_action "此操作不可恢复！"; then return; fi
    echo -e "${BLUE}[*] 开始删除...${NC}"; local config_file_to_load="${CONFIG_DIR}/${DOMAIN_TO_DELETE}.conf"; if [[ -f "$config_file_to_load" ]]; then source "$config_file_to_load"; else echo -e "${RED}[✗] 找不到配置文件，删除中止。${NC}"; return 1; fi
    CRON_TAG_RENEW="# CertRenew_${DOMAIN_TO_DELETE}"; CRON_TAG_DDNS="# DDNSUpdate_${DOMAIN_TO_DELETE}"; (crontab -l 2>/dev/null | grep -v -F "$CRON_TAG_RENEW" | grep -v -F "$CRON_TAG_DDNS") | crontab -
    if [[ -n "$DDNS_SCRIPT_PATH" ]]; then rm -f "$DDNS_SCRIPT_PATH"; fi; if [[ -n "$DEPLOY_HOOK_SCRIPT" ]]; then rm -f "$DEPLOY_HOOK_SCRIPT"; fi
    local nginx_enabled_link="/etc/nginx/sites-enabled/${DOMAIN_TO_DELETE}.conf"; if [[ "$LOCAL_PROXY_PASS" != "none" ]]; then if [[ -L "$nginx_enabled_link" ]]; then rm -f "$nginx_enabled_link"; fi; if [[ -f "$NGINX_CONF_PATH" ]]; then rm -f "$NGINX_CONF_PATH"; fi; if command_exists nginx; then systemctl reload nginx; fi; fi
    if [[ -n "$CLOUDFLARE_CREDENTIALS" ]]; then rm -f "$CLOUDFLARE_CREDENTIALS"; fi; if [[ -n "$CERT_PATH" ]]; then rm -rf "$CERT_PATH"; fi
    if command_exists certbot; then local certbot_cmd=$(command -v certbot); "$certbot_cmd" delete --cert-name "${DOMAIN_TO_DELETE}" --non-interactive --logs-dir /var/log/letsencrypt; fi
    if [[ -f "$config_file_to_load" ]]; then rm -f "$config_file_to_load"; fi
    echo -e "${GREEN}[✓] 删除完成！${NC}"; DOMAIN=""
}

check_cert_expiry() {
    echo -e "\n${CYAN}--- SSL 证书有效期监控 ---${NC}"
    local domains=()
    for config_file in "${CONFIG_DIR}"/*.conf; do
        [[ -f "$config_file" ]] && domains+=("$(basename "$config_file" .conf)")
    done
    
    if [[ ${#domains[@]} -eq 0 ]]; then echo -e "${YELLOW}未找到已配置的域名。${NC}"; return; fi

    printf "%-30s %-20s %-20s\n" "域名" "剩余天数" "到期日期"
    echo "------------------------------------------------------------------------"

    for domain in "${domains[@]}"; do
        local cert_file="/etc/letsencrypt/live/${domain}/fullchain.pem"
        if [[ -f "$cert_file" ]]; then
            local end_date=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2)
            if [[ -n "$end_date" ]]; then
                local end_epoch=$(date +%s -d "$end_date")
                local current_epoch=$(date +%s)
                local days_left=$(( ($end_epoch - current_epoch) / 86400 ))
                
                local color=$GREEN
                if [[ $days_left -lt 30 ]]; then color=$YELLOW; fi
                if [[ $days_left -lt 7 ]]; then color=$RED; fi
                
                printf "%-30s ${color}%-20s${NC} %-20s\n" "$domain" "${days_left} 天" "$(date -d "$end_date" +%F)"
            else
                printf "%-30s ${RED}%-20s${NC} %-20s\n" "$domain" "读取失败" "N/A"
            fi
        else
            printf "%-30s ${RED}%-20s${NC} %-20s\n" "$domain" "证书文件丢失" "N/A"
        fi
    done
    echo ""
}

manual_renew_certificate() {
    echo -e "\n${CYAN}--- 手动续期证书 ---${NC}"
    list_configured_domains; if [[ $? -ne 0 ]]; then return; fi
    local domains=(); for config_file in "${CONFIG_DIR}"/*.conf; do if [[ -f "$config_file" && -r "$config_file" ]]; then domains+=("$(basename "$config_file" .conf)"); fi; done
    local choice; local DOMAIN_TO_RENEW
    while true; do read -p "请输入序号 (0退出): " choice; if [[ "$choice" == "0" ]]; then return; fi; if [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#domains[@]} ]]; then local index=$((choice - 1)); DOMAIN_TO_RENEW=${domains[$index]}; break; else echo -e "${YELLOW}无效序号。${NC}"; fi; done

    local config_file_to_load="${CONFIG_DIR}/${DOMAIN_TO_RENEW}.conf"; if [[ ! -f "$config_file_to_load" ]]; then echo -e "${RED}配置文件丢失。${NC}"; return; fi; source "$config_file_to_load"

    echo -e "\n请选择续期模式:"
    echo -e " ${YELLOW}1.${NC} 模拟运行 (Dry Run) - 仅测试配置，不替换证书 (推荐)"
    echo -e " ${YELLOW}2.${NC} 强制续期 (Force Renew) - 无论是否到期都重签 (慎用)"
    read -p "请输入选项 [1-2]: " renew_mode

    local certbot_cmd=$(command -v certbot)
    local common_args="--cert-name ${DOMAIN_TO_RENEW} --deploy-hook ${DEPLOY_HOOK_SCRIPT} --non-interactive --logs-dir /var/log/letsencrypt"
    
    if [[ "$renew_mode" == "1" ]]; then
        echo -e "${BLUE}[*] 正在执行模拟续期...${NC}"
        "$certbot_cmd" renew --dry-run $common_args
    elif [[ "$renew_mode" == "2" ]]; then
        echo -e "${RED}[!] 正在执行强制续期...${NC}"
        "$certbot_cmd" renew --force-renewal $common_args
    else
        echo "无效选项，操作取消。"
        return
    fi
}

view_cert_renew_log() {
    echo -e "\n${CYAN}--- 最近续期日志 ---${NC}"
    list_configured_domains; if [[ $? -ne 0 ]]; then return; fi
    local domains=(); for config_file in "${CONFIG_DIR}"/*.conf; do if [[ -f "$config_file" && -r "$config_file" ]]; then domains+=("$(basename "$config_file" .conf)"); fi; done
    local choice; local DOMAIN_LOG
    while true; do read -p "请输入序号查看日志 (0退出): " choice; if [[ "$choice" == "0" ]]; then return; fi; if [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#domains[@]} ]]; then local index=$((choice - 1)); DOMAIN_LOG=${domains[$index]}; break; else echo -e "${YELLOW}无效序号。${NC}"; fi; done
    
    local log_file="/var/log/cert_renew_${DOMAIN_LOG}.log"
    if [[ -f "$log_file" ]]; then
        echo -e "${BLUE}--- ${log_file} (Last 20 lines) ---${NC}"
        tail -n 20 "$log_file"
    else
        echo -e "${YELLOW}未找到该域名的部署钩子日志文件。可能还未进行过续期。${NC}"
    fi
}

add_new_domain() {
    echo -e "\n${CYAN}--- 9.1 添加新 Web 服务域名配置 ---${NC}"
    local overall_success=0 
    if ! install_or_update_certbot; then echo -e "${RED}[✗] Certbot 环境设置失败。${NC}"; return 1; fi
    echo -e "${BLUE}[*] 检查 Nginx...${NC}"; if ! install_package "nginx"; then echo -e "${RED}[✗] Nginx 安装失败。${NC}"; return 1; fi
    get_user_input_initial || { return 1; }
    setup_nginx_proxy || { overall_success=1; }
    create_cf_credentials || { return 1; }
    detect_public_ip || { return 1; }
    select_record_type || { return 1; }
    get_zone_id || { return 1; }
    manage_cloudflare_record "设置" || { return 1; }
    if request_certificate; then
        copy_certificate || overall_success=1
        if confirm_action "是否在 Cloudflare 上开启代理（橙色云朵）？"; then enable_cloudflare_proxy "$DOMAIN" || overall_success=1; fi
        create_ddns_script || overall_success=1
        setup_cron_jobs || overall_success=1
        save_domain_config || overall_success=1
        if [[ "$LOCAL_PROXY_PASS" != "none" ]]; then
            if command_exists nginx; then
                if systemctl reload nginx; then echo -e "${GREEN}[✓] Nginx 重载成功。${NC}"; 
                else echo -e "${RED}[✗] Nginx 重载失败。${NC}"; overall_success=1; fi
            fi
        fi
    else
        echo -e "${RED}[!] 证书申请失败。${NC}"; overall_success=1
    fi
    if [[ $overall_success -eq 0 ]]; then echo -e "\n${GREEN}--- 配置完成！ ---${NC}"; return 0; else echo -e "\n${RED}--- 配置有误，请检查日志。 ---${NC}"; return 1; fi
}

manage_web_service() {
     while true; do echo -e "\n${CYAN}--- 9. Web 服务管理 (LE + CF + Nginx) ---${NC}"; 
        echo -e " ${YELLOW}1.${NC} 添加新域名并配置 (证书/代理/Nginx/DDNS)"; 
        echo -e " ${YELLOW}2.${NC} 查看域名状态 & 证书有效期"; 
        echo -e " ${YELLOW}3.${NC} 手动管理证书 (模拟/强制续期)"; 
        echo -e " ${YELLOW}4.${NC} 查看最近续期日志";
        echo -e " ${YELLOW}5.${NC} 删除域名配置"; 
        echo -e " ${YELLOW}0.${NC} 返回主菜单"; 
        read -p "请输入选项 [0-5]: " web_choice
        case $web_choice in 
            1) add_new_domain ;; 
            2) check_cert_expiry ;; 
            3) manual_renew_certificate ;; 
            4) view_cert_renew_log ;;
            5) delete_domain_config ;; 
            0) break ;; 
            *) echo -e "${RED}无效选项。${NC}" ;; 
        esac
        [[ $web_choice != 0 ]] && read -p "按 Enter键 继续..."
    done
}

# --- 6. DNS 配置管理 ---
is_systemd_resolved_active() { if [[ -L "$RESOLV_CONF" ]] && [[ "$(readlink "$RESOLV_CONF")" == "/run/systemd/resolve/resolv.conf" ]] && systemctl is-active --quiet systemd-resolved; then return 0; fi; return 1; }
wait_for_systemd_resolved() { local i=0; while [[ $i -lt 10 ]]; do if systemctl is-active --quiet systemd-resolved; then return 0; fi; sleep 1; ((i++)); done; return 1; }
view_dns_status() { echo -e "\n${CYAN}--- DNS 状态 ---${NC}"; if command_exists resolvectl && is_systemd_resolved_active; then resolvectl status; else cat "$RESOLV_CONF"; fi; }
upgrade_to_systemd_resolved() {
    if is_systemd_resolved_active; then echo -e "${GREEN}已在使用 systemd-resolved。${NC}"; return 0; fi
    if confirm_action "确定升级到 systemd-resolved 吗？"; then
        if ! install_package "systemd-resolved"; then return 1; fi
        systemctl enable systemd-resolved; systemctl start systemd-resolved
        rm -f "$RESOLV_CONF"; ln -s /run/systemd/resolve/resolv.conf "$RESOLV_CONF"
        echo -e "${GREEN}[✓] 升级完成。${NC}"
    fi
}
edit_dns_config() {
    echo -e "\n${CYAN}--- 修改 DNS ---${NC}"; local new_dns; read -p "输入 DNS (空格隔开): " new_dns
    if [[ -z "$new_dns" ]]; then return; fi
    if is_systemd_resolved_active; then
        cp "$SYSTEMD_RESOLVED_CONF" "${SYSTEMD_RESOLVED_CONF}.bak"
        awk -v dns="$new_dns" '/\[Resolve\]/{p=1;print;print "DNS=" dns;next} /^DNS=/{next} {print}' "$SYSTEMD_RESOLVED_CONF" > "${SYSTEMD_RESOLVED_CONF}.tmp" && mv "${SYSTEMD_RESOLVED_CONF}.tmp" "$SYSTEMD_RESOLVED_CONF"
        systemctl restart systemd-resolved
    else
        echo -e "nameserver $new_dns" > "$RESOLV_CONF"
    fi
    echo -e "${GREEN}[✓] DNS 已修改。${NC}"
}
manage_dns() {
     while true; do echo -e "\n${CYAN}--- 6. DNS 管理 ---${NC}"; echo -e " ${YELLOW}1.${NC} 查看状态"; echo -e " ${YELLOW}2.${NC} 修改 DNS"; echo -e " ${YELLOW}3.${NC} 升级 systemd-resolved"; echo -e " ${YELLOW}0.${NC} 返回"; read -p "选 [0-3]: " c; case $c in 1) view_dns_status ;; 2) edit_dns_config ;; 3) upgrade_to_systemd_resolved ;; 0) break ;; esac; [[ $c != 0 ]] && read -p "继续..."; done
}

# --- 7. BBR ---
enable_bbr_fq() {
    echo -e "\n${CYAN}--- 7. 开启 BBR + FQ ---${NC}"
    if confirm_action "确认修改 sysctl.conf 开启 BBR 吗？"; then
        sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
        echo -e "${GREEN}[✓] BBR 设置完成。${NC}"
    fi
}

# --- 1. 系统信息 (已恢复完整功能) ---
output_status() {
    # 总接收和总发送流量（跨网卡）
    local output=$(awk 'BEGIN { rx_total = 0; tx_total = 0 }
        $1 ~ /^(eth|ens|enp|eno)[0-9]+/ {
            rx_total += $2
            tx_total += $10
        }
        END {
            rx_units = "Bytes";
            tx_units = "Bytes";
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "K"; }
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "M"; }
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "G"; }

            if (tx_total > 1024) { tx_total /= 1024; tx_units = "K"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "M"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "G"; }

            printf("%.2f%s %.2f%s\n", rx_total, rx_units, tx_total, tx_units);
        }' /proc/net/dev)

    local rx=$(echo "$output" | awk '{print $1}')
    local tx=$(echo "$output" | awk '{print $2}')

    local cpu_info=$(lscpu | awk -F': +' '/Model name:/ {print $2; exit}')
    local cpu_usage_percent=$(awk '{u=$2+$4; t=$2+$4+$5; if (NR==1){u1=u; t1=t;} else printf "%.0f", (($2+$4-u1) * 100 / (t-t1))}' <(grep 'cpu ' /proc/stat) <(sleep 1; grep 'cpu ' /proc/stat))
    local cpu_cores=$(nproc)
    local cpu_freq=$(cat /proc/cpuinfo | grep "MHz" | head -n 1 | awk '{printf "%.1f GHz", $4/1000}')
    local mem_info=$(free -b | awk 'NR==2{printf "%.2fG/%.2fG (%.2f%%)", $3/1024/1024/1024, $2/1024/1024/1024, $3*100/$2}')
    local disk_info=$(df -h | awk '$NF=="/"{printf "%s/%s (%s)", $3, $2, $5}')
    local ipinfo=$(curl -s ipinfo.io)
    local country=$(echo "$ipinfo" | grep 'country' | awk -F': ' '{print $2}' | tr -d '",')
    local city=$(echo "$ipinfo" | grep 'city' | awk -F': ' '{print $2}' | tr -d '",')
    local isp_info=$(echo "$ipinfo" | grep 'org' | awk -F': ' '{print $2}' | tr -d '",')
    local load=$(uptime | awk '{print $(NF-2), $(NF-1), $NF}')
    local dns_addresses=$(awk '/^nameserver/{printf "%s ", $2} END {print ""}' /etc/resolv.conf)
    local cpu_arch=$(uname -m)
    local hostname=$(uname -n)
    local kernel_version=$(uname -r)
    local congestion_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control)
    local queue_algorithm=$(sysctl -n net.core.default_qdisc)
    local os_info=$(grep PRETTY_NAME /etc/os-release | cut -d '=' -f2 | tr -d '"')
    local current_time=$(date "+%Y-%m-%d %I:%M %p")
    local swap_info=$(free -m | awk 'NR==3{used=$3; total=$2; if (total == 0) {percentage=0} else {percentage=used*100/total}; printf "%dM/%dM (%d%%)", used, total, percentage}')
    local runtime=$(cat /proc/uptime | awk -F. '{run_days=int($1 / 86400);run_hours=int(($1 % 86400) / 3600);run_minutes=int(($1 % 3600) / 60); if (run_days > 0) printf("%d天 ", run_days); if (run_hours > 0) printf("%d时 ", run_hours); printf("%d分\n", run_minutes)}')
    local timezone=$(timedatectl | grep "Time zone" | awk '{print $3}')

    echo ""
    echo -e "系统信息查询"
    echo -e "${CYAN}-------------"
    echo -e "${CYAN}主机名:       ${NC}$hostname"
    echo -e "${CYAN}系统版本:     ${NC}$os_info"
    echo -e "${CYAN}Linux版本:    ${NC}$kernel_version"
    echo -e "${CYAN}-------------"
    echo -e "${CYAN}CPU架构:      ${NC}$cpu_arch"
    echo -e "${CYAN}CPU型号:      ${NC}$cpu_info"
    echo -e "${CYAN}CPU核心数:    ${NC}$cpu_cores"
    echo -e "${CYAN}CPU频率:      ${NC}$cpu_freq"
    echo -e "${CYAN}-------------"
    echo -e "${CYAN}CPU占用:      ${NC}$cpu_usage_percent%"
    echo -e "${CYAN}系统负载:     ${NC}$load"
    echo -e "${CYAN}物理内存:     ${NC}$mem_info"
    echo -e "${CYAN}虚拟内存:     ${NC}$swap_info"
    echo -e "${CYAN}硬盘占用:     ${NC}$disk_info"
    echo -e "${CYAN}-------------"
    echo -e "${CYAN}总接收:       ${NC}$rx"
    echo -e "${CYAN}总发送:       ${NC}$tx"
    echo -e "${CYAN}-------------"
    echo -e "${CYAN}网络算法:     ${NC}$congestion_algorithm $queue_algorithm"
    echo -e "${CYAN}-------------"
    echo -e "${CYAN}运营商:       ${NC}$isp_info"
    if [[ -n "$DETECTED_IPV4" ]]; then
        echo -e "${CYAN}IPv4地址:     ${NC}$DETECTED_IPV4"
    fi
    if [[ -n "$DETECTED_IPV6" ]]; then
        echo -e "${CYAN}IPv6地址:     ${NC}$DETECTED_IPV6"
    fi
    echo -e "${CYAN}DNS地址:      ${NC}$dns_addresses"
    echo -e "${CYAN}地理位置:     ${NC}$country $city"
    echo -e "${CYAN}系统时间:     ${NC}$timezone $current_time"
    echo -e "${CYAN}-------------"
    echo -e "${CYAN}运行时长:     ${NC}$runtime"
    echo ""
}
set_timedate() { timedatectl set-timezone "$1"; echo -e "${GREEN}[✓] 时区设为 $1${NC}"; }

# --- 主菜单 ---
show_main_menu() {
    check_root; local cv="未知"; if command_exists certbot; then cv=$(certbot --version 2>&1 | awk '{print $2}'); fi
    echo -e "\n${CYAN}================================================================${NC}"
    echo -e "${CYAN}     服务器管理脚本 (v7.2 - Gemini-Mod)     ${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo -e " ${BLUE}--- 系统与安全 ---${NC}"
    echo -e "  ${YELLOW}1.${NC} 系统信息查询"
    echo -e "  ${YELLOW}2.${NC} 安装基础依赖工具"
    echo -e "  ${YELLOW}3.${NC} UFW 防火墙管理"
    echo -e "  ${YELLOW}4.${NC} Fail2ban 入侵防御"
    echo -e "  ${YELLOW}5.${NC} SSH 安全管理 (端口: ${YELLOW}${CURRENT_SSH_PORT}${NC})"
    echo -e "  ${YELLOW}6.${NC} DNS 配置管理"
    echo -e "  ${YELLOW}7.${NC} 开启 BBR + FQ"
    echo -e "  ${YELLOW}8.${NC} 调整系统时区"
    echo -e "\n ${BLUE}--- Web 服务 (Certbot: ${cv}) ---${NC}"
    echo -e "  ${YELLOW}9.${NC} Web 服务管理 (Let's Encrypt + Cloudflare + Nginx)"
    echo -e "\n ${BLUE}--- 其他 ---${NC}"
    echo -e "  ${YELLOW}0.${NC} 退出脚本"
    echo -e "${CYAN}================================================================${NC}"
    read -p "请输入选项 [0-9]: " main_choice
}

# --- 脚本入口 ---
check_root
while true; do show_main_menu; case $main_choice in 
    1) output_status ;; 2) install_common_tools ;; 3) manage_ufw ;; 4) manage_fail2ban ;; 
    5) manage_ssh_security ;; 6) manage_dns ;; 7) enable_bbr_fq ;; 
    8) set_timedate "Asia/Shanghai" ;; 
    9) manage_web_service ;; 0) echo "退出。"; exit 0 ;; *) echo -e "${RED}无效选项。${NC}" ;; 
esac; if [[ "$main_choice" != "0" ]]; then read -p "按 Enter键 继续..."; fi; done
