#!/bin/bash

# ==============================================================================
# 服务器初始化与管理脚本 (v5.1 - 优化 Certbot 安装与增加卸载选项)
# 功能:
# 1.  **基础工具**: 安装常用软件包。
# 2.  **防火墙 (UFW)**: 安装、启用、管理端口规则 (增/删/查) - 新增卸载选项。
# 3.  **入侵防御 (Fail2ban)**: 安装并配置 SSH 防护、重新配置、查看状态 - 新增卸载选项。
# 4.  **SSH 安全**: 更改端口、创建 sudo 用户、禁用 root 登录、配置密钥登录。
# 5.  **Web 服务 (LE + CF + Nginx)**:
#     - 优化 Certbot 安装逻辑，优先使用 apt 以降低资源占用。
#     - 自动申请 Let's Encrypt 证书 (使用 Cloudflare DNS 验证 - API Token)。
#     - 证书申请成功后，可选自动开启 Cloudflare 代理（橙色云朵）。
#     - 支持 IPv4 (A) / IPv6 (AAAA) 记录自动检测与添加/更新。
#     - 支持 DDNS (动态域名解析)，自动更新 Cloudflare 记录 (保留代理状态)。
#     - 自动配置 Nginx 反向代理 (支持自定义端口, HTTP/HTTPS 后端)。
#     - 证书自动续期与部署 (通过 Cron)。
#     - 集中查看/删除已配置域名信息。
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


# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- 尝试修复 Backspace 问题 ---
stty sane

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

# --- 1. 基础工具 ---
install_common_tools() {
    echo -e "\n${CYAN}--- 1. 安装基础依赖工具 ---${NC}"
    # 移除 expect，因为它不再被 UFW 部分使用
    local tools="curl jq unzip"
    local failed=0
    local installed_count=0
    local already_installed_count=0

    echo -e "${BLUE}[*] 检查并安装基础工具: ${tools}...${NC}"
    for tool in $tools; do
        if dpkg -s "$tool" &> /dev/null; then
            echo -e "${YELLOW}[!] $tool 已安装。${NC}"
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

# --- 2. UFW 防火墙 (v5: 移除 expect 依赖) ---
setup_ufw() {
    echo -e "\n${CYAN}--- 2.1 安装并启用 UFW 防火墙 ---${NC}"
    # 安装 UFW
    if ! install_package "ufw"; then return 1; fi

    # 检查 firewalld 是否活动，如果活动则提示并退出
    if systemctl is-active --quiet firewalld; then
        echo -e "${RED}[✗] 检测到 firewalld 正在运行。UFW 不能与 firewalld 同时运行。${NC}"
        echo -e "${YELLOW}   请先禁用 firewalld: 'sudo systemctl stop firewalld && sudo systemctl disable firewalld'${NC}"
        return 1
    fi

    # 设置默认规则
    echo -e "${BLUE}[*] 设置 UFW 默认规则 (deny incoming, allow outgoing)...${NC}"
    ufw default deny incoming > /dev/null
    ufw default allow outgoing > /dev/null
    # 允许当前 SSH 端口
    echo -e "${BLUE}[*] 允许当前 SSH 端口 ($CURRENT_SSH_PORT)...${NC}"
    ufw allow $CURRENT_SSH_PORT/tcp comment "SSH Access (Current)" > /dev/null

    # 询问额外端口
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

    # 启用 UFW (直接调用，需要用户手动确认)
    echo -e "${YELLOW}[!] 准备启用 UFW。这将断开除已允许端口外的所有连接。${NC}"
    echo -e "${YELLOW}   您可能需要在下一个提示中输入 'y' 来确认。${NC}"
    # 直接执行 ufw enable，让用户交互
    ufw enable
    local ufw_enable_status=$? # 获取 ufw enable 的退出状态码

    # 检查退出状态码和 UFW 状态
    if [[ $ufw_enable_status -eq 0 ]] && ufw status | grep -q "Status: active"; then
        echo -e "${GREEN}[✓] UFW 已成功启用。${NC}"
        ufw status verbose # 显示详细状态
    else
        echo -e "${RED}[✗] UFW 启用失败。请检查上面的错误信息或 UFW 日志。${NC}"
        # 如果 ufw enable 命令本身失败，状态码通常非 0
        # 如果用户输入 'n' 取消，状态码通常也是 0，但 status 不会是 active
        return 1 # 启用失败返回错误
    fi
    return 0
}

add_ufw_rule() {
    echo -e "\n${CYAN}--- 2.2 添加 UFW 规则 ---${NC}"
    local port protocol comment rule
    while true; do read -p "请输入要开放的端口号 (例如 80, 443, 8080): " port; if [[ "$port" =~ ^[0-9]+$ && "$port" -gt 0 && "$port" -le 65535 ]]; then break; else echo -e "${YELLOW}无效的端口号。请输入 1-65535 之间的数字。${NC}"; fi; done
    while true; do read -p "请选择协议 [1] TCP (默认) [2] UDP : " proto_choice; if [[ -z "$proto_choice" || "$proto_choice" == "1" ]]; then protocol="tcp"; break; elif [[ "$proto_choice" == "2" ]]; then protocol="udp"; break; else echo -e "${YELLOW}无效输入，请输入 1 或 2。${NC}"; fi; done
    read -p "请输入端口用途备注 (例如 'Web Server HTTP', 'Game Server UDP'): " comment; [[ -z "$comment" ]] && comment="Rule added by script"
    rule="${port}/${protocol}"
    echo -e "${BLUE}[*] 准备添加规则: ufw allow ${rule} comment '${comment}'${NC}"
    # 直接调用 ufw allow，不需要 expect
    ufw allow $rule comment "$comment"
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}[✓] 规则已添加。请运行 '查看 UFW 规则' 确认。${NC}"
    else
        echo -e "${RED}[✗] 添加规则失败。${NC}"
    fi
}

delete_ufw_rule() {
    echo -e "\n${CYAN}--- 2.4 删除 UFW 规则 ---${NC}"
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
    # 循环删除选中的规则 (直接调用 ufw delete)
    for num_to_delete in "${sorted_nums[@]}"; do
        echo -n "  尝试删除规则 $num_to_delete ... "
        # 直接执行 ufw delete，让用户交互确认
        ufw delete $num_to_delete
        local delete_status=$? # 获取退出状态码
        if [[ $delete_status -eq 0 ]]; then
             echo -e "${GREEN}命令执行完毕 (请检查 UFW 输出确认是否成功删除)。${NC}"
             # 注意：即使用户输入 'n' 取消，ufw delete 也可能返回 0
        else
             echo -e "${RED}命令执行失败 (状态码: $delete_status)。${NC}"
             delete_failed=1
        fi
    done

    # 提示用户检查结果，因为脚本无法确切知道是否真的删除了
    echo -e "\n${BLUE}删除命令已执行完毕。请再次查看规则列表确认结果。${NC}"
    if [[ $delete_failed -ne 0 ]]; then
        echo -e "${RED}[✗] 部分删除命令执行失败。${NC}"
    fi
    view_ufw_rules # 显示更新后的规则
}

view_ufw_rules() {
    echo -e "\n${CYAN}--- 2.3 查看 UFW 规则 ---${NC}"
    if ! command_exists ufw; then echo -e "${YELLOW}[!] UFW 未安装。${NC}"; return; fi
    echo -e "${BLUE}当前 UFW 状态和规则:${NC}"; ufw status verbose; echo -e "\n${BLUE}带编号的规则列表 (用于删除):${NC}"; ufw status numbered
}

ufw_allow_all() {
    echo -e "\n${CYAN}--- 2.5 允许所有 UFW 入站连接 (危险) ---${NC}"; echo -e "${RED}[!] 警告：此操作将允许来自任何源的任何入站连接，会显著降低服务器安全性！${NC}"; echo -e "${YELLOW}   仅在您完全了解风险并有特定需求时（例如临时调试）才执行此操作。${NC}"; echo -e "${YELLOW}   强烈建议在完成后立即恢复默认拒绝规则 (选项 6)。${NC}"
    if ! command_exists ufw || ! ufw status | grep -q "Status: active"; then echo -e "${YELLOW}[!] UFW 未安装或未启用。无法更改默认策略。${NC}"; return; fi
    if confirm_action "您确定要将 UFW 默认入站策略更改为 ALLOW (允许所有) 吗?"; then
        echo -e "${BLUE}[*] 正在设置默认入站策略为 ALLOW...${NC}"; ufw default allow incoming; if [[ $? -eq 0 ]]; then echo -e "${GREEN}[✓] UFW 默认入站策略已设置为 ALLOW。${NC}"; echo -e "${RED}   请注意：现在所有端口都对外部开放！${NC}"; ufw status verbose; else echo -e "${RED}[✗] 设置默认入站策略失败。${NC}"; fi
    else echo -e "${YELLOW}操作已取消。${NC}"; fi
}

ufw_reset_default() {
    echo -e "\n${CYAN}--- 2.6 重置 UFW 为默认拒绝规则 ---${NC}"; echo -e "${BLUE}[*] 此操作将执行以下步骤:${NC}"; echo "  1. 设置默认入站策略为 DENY (拒绝)。"; echo "  2. 设置默认出站策略为 ALLOW (允许)。"; echo "  3. 确保当前 SSH 端口 ($CURRENT_SSH_PORT/tcp) 规则存在。"; echo "  4. 重新加载 UFW 规则。"; echo -e "${YELLOW}   注意：除了 SSH 端口外，所有其他之前手动添加的 'allow' 规则将保持不变。${NC}"
    if ! command_exists ufw; then echo -e "${YELLOW}[!] UFW 未安装。无法重置。${NC}"; return; fi
    if confirm_action "确认要将 UFW 重置为默认拒绝策略 (并保留 SSH 端口) 吗?"; then
        echo -e "${BLUE}[*] 设置默认入站策略为 DENY...${NC}"; ufw default deny incoming > /dev/null; echo -e "${BLUE}[*] 设置默认出站策略为 ALLOW...${NC}"; ufw default allow outgoing > /dev/null; echo -e "${BLUE}[*] 确保当前 SSH 端口 ($CURRENT_SSH_PORT/tcp) 允许...${NC}"; ufw allow $CURRENT_SSH_PORT/tcp comment "SSH Access (Current)" > /dev/null; echo -e "${BLUE}[*] 重新加载 UFW 规则...${NC}"; ufw reload > /dev/null
        if [[ $? -eq 0 ]]; then echo -e "${GREEN}[✓] UFW 已成功重置为默认拒绝策略并重新加载。${NC}"; ufw status verbose; else echo -e "${RED}[✗] UFW 重置或重新加载失败。${NC}"; fi
    else echo -e "${YELLOW}操作已取消。${NC}"; fi
}

# 新增 UFW 卸载函数
uninstall_ufw() {
    echo -e "\n${RED}--- 警告：即将卸载 UFW 防火墙 ---${NC}"
    echo -e "${YELLOW}[!] 此操作会移除 UFW 及其所有规则，您的服务器将完全暴露在公网！${NC}"
    if ! command_exists ufw; then
        echo -e "${YELLOW}[!] UFW 未安装，无需卸载。${NC}"
        return 0
    fi
    if ! confirm_action "您确定要卸载 UFW 吗？"; then
        echo -e "${YELLOW}操作已取消。${NC}"
        return 0
    fi
    echo -e "${BLUE}[*] 正在禁用 UFW...${NC}"
    ufw disable
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[✗] 禁用 UFW 失败。请手动执行 'sudo ufw disable'。${NC}"
        return 1
    fi
    echo -e "${BLUE}[*] 正在彻底移除 UFW...${NC}"
    apt remove --purge ufw -y
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[✗] 卸载 UFW 失败。请手动执行 'sudo apt remove --purge ufw'。${NC}"
        return 1
    fi
    echo -e "${GREEN}[✓] UFW 已成功卸载。${NC}"
    return 0
}

manage_ufw() {
    while true; do echo -e "\n${CYAN}--- UFW 防火墙管理 ---${NC}"; echo -e " ${YELLOW}1.${NC} 安装并启用 UFW (手动确认启用)"; echo -e " ${YELLOW}2.${NC} 添加允许规则 (开放端口)"; echo -e " ${YELLOW}3.${NC} 查看当前 UFW 规则"; echo -e " ${YELLOW}4.${NC} 删除 UFW 规则 (手动确认删除)"; echo -e " ${YELLOW}5.${NC} ${RED}允许所有入站连接 (危险!)${NC}"; echo -e " ${YELLOW}6.${NC} 重置为默认拒绝规则 (保留 SSH)"; echo -e " ${YELLOW}7.${NC} ${RED}卸载 UFW 防火墙 (高危!)${NC}"; echo -e " ${YELLOW}0.${NC} 返回主菜单"; read -p "请输入选项 [0-7]: " ufw_choice
        case $ufw_choice in 1) setup_ufw ;; 2) add_ufw_rule ;; 3) view_ufw_rules ;; 4) delete_ufw_rule ;; 5) ufw_allow_all ;; 6) ufw_reset_default ;; 7) uninstall_ufw ;; 0) break ;; *) echo -e "${RED}无效选项。${NC}" ;; esac
        [[ $ufw_choice != 0 ]] && read -p "按 Enter键 继续..."
    done
}


# --- 3. Fail2ban ---
setup_fail2ban() {
    echo -e "\n${CYAN}--- 3.1 安装并配置 Fail2ban ---${NC}"
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
    echo -e "\n${CYAN}--- 3.3 查看 Fail2ban 状态 (SSH) ---${NC}"; if ! command_exists fail2ban-client; then echo -e "${YELLOW}[!] Fail2ban 未安装。${NC}"; return 1; fi
    echo -e "${BLUE}Fail2ban SSH jail 状态:${NC}"; fail2ban-client status sshd; echo -e "\n${BLUE}查看 Fail2ban 日志 (最近 20 条):${NC}"
    if command_exists journalctl; then journalctl -u fail2ban -n 20 --no-pager --quiet; elif [[ -f /var/log/fail2ban.log ]]; then tail -n 20 /var/log/fail2ban.log; else echo -e "${YELLOW}无法找到 Fail2ban 日志。${NC}"; fi; return 0
}

# 新增 Fail2ban 卸载函数
uninstall_fail2ban() {
    echo -e "\n${RED}--- 警告：即将卸载 Fail2ban 入侵防御 ---${NC}"
    echo -e "${YELLOW}[!] 此操作会移除 Fail2ban 服务，您的 SSH 等服务将不再受到自动暴力破解防御。${NC}"
    if ! command_exists fail2ban-client; then
        echo -e "${YELLOW}[!] Fail2ban 未安装，无需卸载。${NC}"
        return 0
    fi
    if ! confirm_action "您确定要卸载 Fail2ban 吗？"; then
        echo -e "${YELLOW}操作已取消。${NC}"
        return 0
    fi
    echo -e "${BLUE}[*] 正在停止并禁用 Fail2ban 服务...${NC}"
    systemctl stop fail2ban > /dev/null 2>&1
    systemctl disable fail2ban > /dev/null 2>&1
    echo -e "${BLUE}[*] 正在彻底移除 Fail2ban...${NC}"
    apt remove --purge fail2ban -y
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[✗] 卸载 Fail2ban 失败。请手动执行 'sudo apt remove --purge fail2ban'。${NC}"
        return 1
    fi
    # 尝试删除脚本生成的配置文件
    if [[ -f "$FAIL2BAN_JAIL_LOCAL" ]]; then
        echo -e "${BLUE}[*] 删除脚本生成的配置文件: ${FAIL2BAN_JAIL_LOCAL}...${NC}"
        rm -f "$FAIL2BAN_JAIL_LOCAL"
    fi
    echo -e "${GREEN}[✓] Fail2ban 已成功卸载。${NC}"
    return 0
}

manage_fail2ban() {
     while true; do echo -e "\n${CYAN}--- Fail2ban 入侵防御管理 ---${NC}"; echo -e " ${YELLOW}1.${NC} 安装并配置 Fail2ban (交互式设置 SSH 防护)"; echo -e " ${YELLOW}2.${NC} 重新配置 Fail2ban (覆盖 jail.local, 重启服务)"; echo -e " ${YELLOW}3.${NC} 查看 Fail2ban 状态 (SSH jail, 日志)"; echo -e " ${YELLOW}4.${NC} ${RED}卸载 Fail2ban${NC}"; echo -e " ${YELLOW}0.${NC} 返回主菜单"; read -p "请输入选项 [0-4]: " f2b_choice
        case $f2b_choice in 1) setup_fail2ban ;; 2) if configure_fail2ban; then echo -e "${BLUE}[*] 重启 Fail2ban 服务以应用新配置...${NC}"; systemctl restart fail2ban; sleep 2; if systemctl is-active --quiet fail2ban; then echo -e "${GREEN}[✓] Fail2ban 服务已重启。${NC}"; else echo -e "${RED}[✗] Fail2ban 服务重启失败。${NC}"; fi; fi ;; 3) view_fail2ban_status ;; 4) uninstall_fail2ban ;; 0) break ;; *) echo -e "${RED}无效选项。${NC}" ;; esac
        [[ $f2b_choice != 0 ]] && read -p "按 Enter键 继续..."
    done
}

# --- 4. SSH 安全 ---
change_ssh_port() {
    echo -e "\n${CYAN}--- 4.1 更改 SSH 端口 ---${NC}"; local new_port old_port; old_port=$CURRENT_SSH_PORT; echo "当前 SSH 端口是: $old_port"
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
    echo -e "\n${CYAN}--- 4.2 创建新的 Sudo 用户 ---${NC}"; local username
    while true; do read -p "请输入新用户名: " username; if [[ -z "$username" ]]; then echo -e "${YELLOW}用户名不能为空。${NC}"; elif id "$username" &>/dev/null; then echo -e "${YELLOW}用户 '$username' 已存在。${NC}"; elif [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then break; else echo -e "${YELLOW}无效的用户名格式 (建议使用小写字母、数字、下划线、连字符，并以字母或下划线开头)。${NC}"; fi; done
    echo -e "${BLUE}[*] 添加用户 '$username' 并设置密码...${NC}"; adduser "$username"; if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 添加用户失败。${NC}"; return 1; fi
    echo -e "${BLUE}[*] 将用户 '$username' 添加到 sudo 组...${NC}"; usermod -aG sudo "$username"; if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 添加到 sudo 组失败。${NC}"; return 1; fi
    echo -e "${GREEN}[✓] 用户 '$username' 创建成功并已添加到 sudo 组。${NC}"; echo -e "${YELLOW}请使用新用户登录并测试 sudo权限 (例如 'sudo whoami')。${NC}"; echo -e "${YELLOW}建议在新用户能够正常登录并使用 sudo 后，再考虑禁用 root 登录。${NC}"; return 0
}
disable_root_login() {
    echo -e "\n${CYAN}--- 4.3 禁用 Root 用户 SSH 登录 ---${NC}"; echo -e "${RED}[!] 警告：禁用 Root 登录前，请确保您已创建具有 Sudo 权限的普通用户，并且该用户可以正常通过 SSH 登录！${NC}"
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
    echo -e "\n${CYAN}--- 4.4 配置 SSH 密钥登录 (禁用密码登录) ---${NC}"; local key_config_choice
    while true; do echo -e "请选择操作:"; echo -e "  ${YELLOW}1.${NC} 添加公钥 (粘贴公钥内容让脚本添加)"; echo -e "  ${YELLOW}2.${NC} 禁用 SSH 密码登录 ${RED}(高风险! 请确保密钥已添加并测试成功)${NC}"; echo -e "  ${YELLOW}0.${NC} 返回 SSH 安全菜单"; read -p "请输入选项 [0-2]: " key_config_choice
        case $key_config_choice in 1) local target_user; read -p "请输入要为其添加公钥的用户名: " target_user; if [[ -n "$target_user" ]]; then add_public_key "$target_user"; else echo -e "${YELLOW}用户名不能为空。${NC}"; fi; read -p "按 Enter键 继续..."; ;; 2) echo -e "${RED}[!] 警告：这是高风险操作！在禁用密码登录前，请务必完成以下步骤：${NC}"; echo -e "${YELLOW}  1. 在您的本地计算机上生成 SSH 密钥对 (例如使用 'ssh-keygen')。${NC}"; echo -e "${YELLOW}  2. 使用上面的【选项1】或其他方法，将您的【公钥】复制到服务器上目标用户的 ~/.ssh/authorized_keys 文件中。${NC}"; echo -e "${YELLOW}  3. 【重要】在禁用密码登录【之前】，打开一个新的终端窗口，尝试使用【密钥】登录服务器，确保可以成功登录！${NC}"; if ! confirm_action "您是否已经完成上述所有步骤，并确认可以通过密钥成功登录?"; then echo "操作已取消。请先确保密钥设置正确并可成功登录。"; continue; fi; echo -e "${BLUE}[*] 修改 SSH 配置文件 ($SSHD_CONFIG) 以启用密钥登录并禁用密码登录...${NC}"; cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak_key_$(date +%F_%T)"; if ! update_or_add_config "$SSHD_CONFIG" "" "PubkeyAuthentication" "yes"; then echo -e "${RED}[✗] 修改 SSH 配置文件失败 (PubkeyAuthentication)。${NC}"; continue; fi; if ! update_or_add_config "$SSHD_CONFIG" "" "PasswordAuthentication" "no"; then echo -e "${RED}[✗] 修改 SSH 配置文件失败 (PasswordAuthentication)。${NC}"; continue; fi; if ! update_or_add_config "$SSHD_CONFIG" "" "ChallengeResponseAuthentication" "no"; then echo -e "${RED}[✗] 修改 SSH 配置文件失败 (ChallengeResponseAuthentication)。${NC}"; continue; fi; echo -e "${YELLOW}[!] UsePAM 设置未修改，保持默认。${NC}"; echo -e "${BLUE}[*] 重启 SSH 服务以应用更改...${NC}"; systemctl restart sshd; sleep 2; if systemctl is-active --quiet sshd; then echo -e "${GREEN}[✓] SSH 已配置为仅允许密钥登录，密码登录已禁用。${NC}"; echo -e "${RED}请立即尝试使用密钥重新登录以确认！如果无法登录，您可能需要通过控制台或其他方式恢复备份配置 (${SSHD_CONFIG}.bak_key_*)。${NC}"; else echo -e "${RED}[✗] SSH 服务重启失败！请检查配置。密码登录可能仍然启用。${NC}"; echo -e "${RED}   旧配置已备份为 ${SSHD_CONFIG}.bak_key_* 。${NC}"; fi; read -p "按 Enter键 继续..."; ;; 0) break ;; *) echo -e "${RED}无效选项。${NC}" ;; esac
    done
}
manage_ssh_security() {
     while true; do echo -e "\n${CYAN}--- SSH 安全管理 ---${NC}"; echo -e " 当前 SSH 端口: ${YELLOW}${CURRENT_SSH_PORT}${NC}"; echo -e " ${YELLOW}1.${NC} 更改 SSH 端口 (自动更新 UFW, Fail2ban)"; echo -e " ${YELLOW}2.${NC} 创建新的 Sudo 用户"; echo -e " ${YELLOW}3.${NC} 禁用 Root 用户 SSH 登录"; echo -e " ${YELLOW}4.${NC} 配置 SSH 密钥登录与密码禁用"; echo -e " ${YELLOW}0.${NC} 返回主菜单"; read -p "请输入选项 [0-4]: " ssh_choice
        case $ssh_choice in 1) change_ssh_port ;; 2) create_sudo_user ;; 3) disable_root_login ;; 4) configure_ssh_keys ;; 0) break ;; *) echo -e "${RED}无效选项。${NC}" ;; esac
        [[ $ssh_choice != 0 ]] && read -p "按 Enter键 继续..."; check_root
    done
}

# --- 5. Web 服务 (Let's Encrypt + Cloudflare + Nginx) ---

# 处理 Certbot 安装/更新 (v5.1: 优化逻辑，优先 apt)
install_or_update_certbot() {
    echo -e "${BLUE}[*] 检查 Certbot 安装情况并优先使用 apt 版本...${NC}"
    local apt_certbot_pkg="certbot"
    local apt_cf_plugin_pkg="python3-certbot-dns-cloudflare"
    local snap_certbot_name="certbot"
    local snap_cf_plugin_name="certbot-dns-cloudflare"

    # 1. 尝试使用 apt 安装
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
            # apt 安装失败，继续到 snap 逻辑
        fi
    fi

    # 2. 如果 apt 失败，尝试使用 snap
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
                # 创建软链接，确保 certbot 命令可用
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

# 获取 Web 服务配置的初始用户输入
get_user_input_initial() {
    DOMAIN="" CF_API_TOKEN="" DDNS_FREQUENCY=5 RECORD_TYPE="" SELECTED_IP="" ZONE_ID="" ZONE_NAME="" LOCAL_PROXY_PASS="" BACKEND_PROTOCOL="http" NGINX_HTTP_PORT=80 NGINX_HTTPS_PORT=443
    echo -e "${BLUE}[*] 请输入首次设置所需信息:${NC}"; echo -e "${YELLOW}Let's Encrypt 注册邮箱已固定为: ${EMAIL}${NC}"
    while [[ -z "$DOMAIN" ]]; do read -p "请输入您要申请/管理的域名 (例如 my.example.com): " DOMAIN; done
    if ! [[ "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then echo -e "${RED}[✗] 域名格式似乎不正确。${NC}"; return 1; fi
    if [[ -f "${CONFIG_DIR}/${DOMAIN}.conf" ]]; then echo -e "${YELLOW}[!] 域名 ${DOMAIN} 的配置已存在。如果您想修改，请先删除旧配置 (选项 5-3)。${NC}"; return 1; fi
    while [[ -z "$CF_API_TOKEN" ]]; do read -p "请输入您的 Cloudflare API Token (确保有 Zone:Read, DNS:Edit 权限): " CF_API_TOKEN; done
    while true; do read -p "请输入 DDNS 自动更新频率 (分钟, 输入 0 禁用 DDNS, 默认 5): " freq_input; if [[ -z "$freq_input" ]]; then DDNS_FREQUENCY=5; echo -e "DDNS 更新频率设置为: ${GREEN}5 分钟${NC}"; break; elif [[ "$freq_input" =~ ^[0-9]+$ ]]; then DDNS_FREQUENCY=$freq_input; if [[ "$DDNS_FREQUENCY" -eq 0 ]]; then echo -e "${YELLOW}DDNS 功能已禁用。${NC}"; else echo -e "DDNS 更新频率设置为: ${GREEN}${DDNS_FREQUENCY} 分钟${NC}"; fi; break; else echo -e "${YELLOW}请输入一个非负整数。${NC}"; fi; done
    update_paths_for_domain "$DOMAIN"; return 0
}

# 根据当前域名更新相关文件路径变量
update_paths_for_domain() {
    local current_domain="$1"; CERT_PATH="${CERT_PATH_PREFIX}/${current_domain}"; CLOUDFLARE_CREDENTIALS="/root/.cloudflare-${current_domain}.ini"; DEPLOY_HOOK_SCRIPT="/root/cert-renew-hook-${current_domain}.sh"; DDNS_SCRIPT_PATH="/usr/local/bin/cf_ddns_update_${current_domain}.sh"; NGINX_CONF_PATH="/etc/nginx/sites-available/${current_domain}.conf"
}

# 创建 Cloudflare API Token 凭证文件 (用于 Certbot)
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

# 检测公网 IP 地址 (IPv4 和 IPv6)
detect_public_ip() {
    echo -e "${BLUE}[*] 检测公网 IP 地址...${NC}"; DETECTED_IPV4=$(curl -4s --max-time 5 https://api.ipify.org || curl -4s --max-time 5 https://ifconfig.me/ip || curl -4s --max-time 5 https://ipv4.icanhazip.com || echo ""); DETECTED_IPV6=$(curl -6s --max-time 5 https://api64.ipify.org || curl -6s --max-time 5 https://ifconfig.me/ip || curl -6s --max-time 5 https://ipv6.icanhazip.com || echo ""); echo "检测结果:"; if [[ -n "$DETECTED_IPV4" ]]; then echo -e "  - IPv4: ${GREEN}$DETECTED_IPV4${NC}"; else echo -e "  - IPv4: ${RED}未检测到${NC}"; fi; if [[ -n "$DETECTED_IPV6" ]]; then echo -e "  - IPv6: ${GREEN}$DETECTED_IPV6${NC}"; else echo -e "  - IPv6: ${RED}未检测到${NC}"; fi
    if [[ -z "$DETECTED_IPV4" && -z "$DETECTED_IPV6" ]]; then echo -e "${RED}[✗] 无法检测到任何公网 IP 地址。请检查网络连接。脚本无法继续。${NC}"; return 1; fi; return 0
}

# 让用户选择使用哪个 IP 地址和记录类型 (A 或 AAAA)
select_record_type() {
    echo -e "${BLUE}[*] 请选择要使用的 DNS 记录类型和 IP 地址:${NC}"; options=(); ips=(); types=(); if [[ -n "$DETECTED_IPV4" ]]; then options+=("IPv4 (A 记录) - ${DETECTED_IPV4}"); ips+=("$DETECTED_IPV4"); types+=("A"); fi; if [[ -n "$DETECTED_IPV6" ]]; then options+=("IPv6 (AAAA 记录) - ${DETECTED_IPV6}"); ips+=("$DETECTED_IPV6"); types+=("AAAA"); fi; options+=("退出")
    select opt in "${options[@]}"; do choice_index=$((REPLY - 1)); if [[ "$opt" == "退出" ]]; then echo "用户选择退出。"; return 1; elif [[ $choice_index -ge 0 && $choice_index -lt ${#ips[@]} ]]; then RECORD_TYPE=${types[$choice_index]}; SELECTED_IP=${ips[$choice_index]}; echo -e "已选择: ${GREEN}${RECORD_TYPE} - $SELECTED_IP${NC}"; break; else echo "无效选项 $REPLY"; fi; done
    if [[ -z "$RECORD_TYPE" || -z "$SELECTED_IP" ]]; then echo -e "${RED}[✗] 未选择有效的记录类型或 IP 地址。脚本无法继续。${NC}"; return 1; fi; return 0
}

# 获取 Cloudflare Zone ID
get_zone_id() {
    echo -e "${BLUE}[*] 获取 Cloudflare Zone ID...${NC}"; ZONE_NAME=$(echo "$DOMAIN" | awk -F. '{if (NF>2) print $(NF-1)"."$NF; else print $0}'); echo "尝试获取 Zone Name: $ZONE_NAME"
    ZONE_ID_JSON=$(curl -s --max-time 10 -X GET "$CF_API/zones?name=$ZONE_NAME&status=active" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json"); if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API 失败 (网络错误或超时)。${NC}"; return 1; fi
    if ! echo "$ZONE_ID_JSON" | jq -e '.success == true' > /dev/null; then local error_msg=$(echo "$ZONE_ID_JSON" | jq -r '.errors[0].message // "未知 API 错误"'); echo -e "${RED}[✗] Cloudflare API 返回错误: ${error_msg}${NC}"; return 1; fi
    ZONE_ID=$(echo "$ZONE_ID_JSON" | jq -r '.result[0].id'); if [[ "$ZONE_ID" == "null" || -z "$ZONE_ID" ]]; then echo -e "${RED}[✗] 无法找到域名 $ZONE_NAME 对应的活动 Zone ID。请检查域名和 API Token 是否正确且有 Zone:Read 权限。${NC}"; return 1; fi
    echo -e "${GREEN}[✓] 找到 Zone ID: $ZONE_ID${NC}"; return 0
}

# 管理 Cloudflare DNS 记录 (创建或更新, 强制 proxied=false)
manage_cloudflare_record() {
    local action="$1"; local force_proxy_status="false"; echo -e "${BLUE}[*] ${action} Cloudflare DNS 记录 ($RECORD_TYPE) 并确保代理关闭...${NC}"; echo "正在检查 $DOMAIN 的 $RECORD_TYPE 记录..."
    local RECORD_INFO=$(curl -s --max-time 10 -X GET "$CF_API/zones/$ZONE_ID/dns_records?type=$RECORD_TYPE&name=$DOMAIN" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json"); if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (获取记录) 失败。${NC}"; return 1; fi; if ! echo "$RECORD_INFO" | jq -e '.success == true' > /dev/null; then echo -e "${RED}[✗] Cloudflare API 返回错误 (获取记录): $(echo "$RECORD_INFO" | jq -r '.errors[0].message // "未知 API 错误"')${NC}"; return 1; fi
    local RECORD_ID=$(echo "$RECORD_INFO" | jq -r '.result[0].id'); local CURRENT_IP=$(echo "$RECORD_INFO" | jq -r '.result[0].content'); local CURRENT_PROXIED=$(echo "$RECORD_INFO" | jq -r '.result[0].proxied')
    if [[ "$RECORD_ID" == "null" || -z "$RECORD_ID" ]]; then echo "未找到 $RECORD_TYPE 记录，正在创建 (代理状态: ${force_proxy_status})..."; local CREATE_RESULT=$(curl -s --max-time 10 -X POST "$CF_API/zones/$ZONE_ID/dns_records" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" --data "{\"type\":\"$RECORD_TYPE\",\"name\":\"$DOMAIN\",\"content\":\"$SELECTED_IP\",\"ttl\":120,\"proxied\":${force_proxy_status}}"); if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (创建记录) 失败。${NC}"; return 1; fi; if echo "$CREATE_RESULT" | jq -e '.success == true' > /dev/null; then echo -e "${GREEN}[✓] $RECORD_TYPE 记录创建成功: $DOMAIN -> $SELECTED_IP (代理: ${force_proxy_status})${NC}"; else echo -e "${RED}[✗] 创建 $RECORD_TYPE 记录失败: $(echo "$CREATE_RESULT" | jq -r '.errors[0].message // "未知 API 错误"')${NC}"; return 1; fi
    else echo "找到 $RECORD_TYPE 记录 (ID: $RECORD_ID)，当前 IP: $CURRENT_IP, 当前代理: $CURRENT_PROXIED"; if [[ "$CURRENT_IP" != "$SELECTED_IP" || "$CURRENT_PROXIED" != "$force_proxy_status" ]]; then echo "IP 或代理状态不符，正在更新 (目标 IP: $SELECTED_IP, 目标代理: ${force_proxy_status})..."; local UPDATE_RESULT=$(curl -s --max-time 10 -X PUT "$CF_API/zones/$ZONE_ID/dns_records/$RECORD_ID" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" --data "{\"type\":\"$RECORD_TYPE\",\"name\":\"$DOMAIN\",\"content\":\"$SELECTED_IP\",\"ttl\":120,\"proxied\":${force_proxy_status}}"); if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (更新记录) 失败。${NC}"; return 1; fi; if echo "$UPDATE_RESULT" | jq -e '.success == true' > /dev/null; then echo -e "${GREEN}[✓] $RECORD_TYPE 记录更新成功: $DOMAIN -> $SELECTED_IP (代理: ${force_proxy_status})${NC}"; else echo -e "${RED}[✗] 更新 $RECORD_TYPE 记录失败: $(echo "$UPDATE_RESULT" | jq -r '.errors[0].message // "未知 API 错误"')${NC}"; return 1; fi; else echo -e "${GREEN}[✓] $RECORD_TYPE 记录已是最新 ($CURRENT_IP, 代理: ${force_proxy_status})，无需更新。${NC}"; fi; fi; return 0
}

# 开启 Cloudflare 代理状态
enable_cloudflare_proxy() {
    local domain_to_proxy="$1"; echo -e "${BLUE}[*] 尝试为域名 $domain_to_proxy 开启 Cloudflare 代理 (橙色云朵)...${NC}"
    if [[ -z "$ZONE_ID" || -z "$RECORD_TYPE" || -z "$CF_API_TOKEN" || -z "$SELECTED_IP" || -z "$domain_to_proxy" ]]; then echo -e "${RED}[✗] 缺少必要信息 (Zone ID, Record Type, Token, IP, Domain)，无法开启代理。${NC}"; return 1; fi
    local RECORD_INFO=$(curl -s --max-time 10 -X GET "$CF_API/zones/$ZONE_ID/dns_records?type=$RECORD_TYPE&name=$domain_to_proxy" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json"); if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (获取记录 ID) 失败。${NC}"; return 1; fi; if ! echo "$RECORD_INFO" | jq -e '.success == true' > /dev/null; then echo -e "${RED}[✗] Cloudflare API 返回错误 (获取记录 ID): $(echo "$RECORD_INFO" | jq -r '.errors[0].message // "未知 API 错误"')${NC}"; return 1; fi; local RECORD_ID=$(echo "$RECORD_INFO" | jq -r '.result[0].id'); if [[ "$RECORD_ID" == "null" || -z "$RECORD_ID" ]]; then echo -e "${RED}[✗] 未找到域名 $domain_to_proxy 的 $RECORD_TYPE 记录，无法开启代理。${NC}"; return 1; fi
    echo "正在更新记录 $RECORD_ID，设置 proxied=true ..."; local UPDATE_RESULT=$(curl -s --max-time 10 -X PUT "$CF_API/zones/$ZONE_ID/dns_records/$RECORD_ID" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" --data "{\"type\":\"$RECORD_TYPE\",\"name\":\"$domain_to_proxy\",\"content\":\"$SELECTED_IP\",\"ttl\":120,\"proxied\":true}") # 设置 proxied 为 true
    if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (设置代理) 失败。${NC}"; return 1; fi; if echo "$UPDATE_RESULT" | jq -e '.success == true' > /dev/null; then echo -e "${GREEN}[✓] 成功为 $domain_to_proxy ($RECORD_TYPE) 开启 Cloudflare 代理。${NC}"; return 0; else echo -e "${RED}[✗] 开启 Cloudflare 代理失败: $(echo "$UPDATE_RESULT" | jq -r '.errors[0].message // "未知 API 错误"')${NC}"; return 1; fi
}

# 申请 Let's Encrypt 证书
request_certificate() {
    echo -e "${BLUE}[*] 申请 SSL 证书 (Let's Encrypt)...${NC}"; local certbot_cmd=$(command -v certbot)
    "$certbot_cmd" certonly --dns-cloudflare --dns-cloudflare-credentials "$CLOUDFLARE_CREDENTIALS" --dns-cloudflare-propagation-seconds 60 -d "$DOMAIN" --email "$EMAIL" --agree-tos --no-eff-email --non-interactive --logs-dir /var/log/letsencrypt
    local cert_status=$?; if [[ $cert_status -ne 0 ]]; then echo -e "${RED}[✗] Certbot 命令执行失败 (退出码: $cert_status)。${NC}"; echo -e "${RED}   请检查 certbot 日志 (/var/log/letsencrypt/letsencrypt.log) 获取详细信息。${NC}"; if [[ -f /var/log/letsencrypt/letsencrypt.log ]]; then echo -e "${YELLOW}--- 最近的 Certbot 日志 ---${NC}"; tail -n 15 /var/log/letsencrypt/letsencrypt.log; echo -e "${YELLOW}--------------------------${NC}"; fi; return 1; fi
    if [[ ! -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" || ! -f "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" ]]; then echo -e "${RED}[✗] 证书文件在预期路径 (/etc/letsencrypt/live/${DOMAIN}/) 未找到，即使 Certbot 命令成功。${NC}"; echo -e "${RED}   请再次检查 Certbot 日志。${NC}"; return 1; fi
    echo -e "${GREEN}[✓] SSL 证书申请成功！${NC}"; return 0
}

# 复制证书文件到指定目录
copy_certificate() {
    echo -e "${BLUE}[*] 复制证书文件到 $CERT_PATH ...${NC}"; mkdir -p "$CERT_PATH"
    if cp -L "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$CERT_PATH/" && cp -L "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$CERT_PATH/" && cp -L "/etc/letsencrypt/live/${DOMAIN}/chain.pem" "$CERT_PATH/" && cp -L "/etc/letsencrypt/live/${DOMAIN}/cert.pem" "$CERT_PATH/"; then echo -e "${GREEN}[✓] 证书文件已复制到 $CERT_PATH ${NC}"; return 0; else echo -e "${RED}[✗] 复制证书文件失败。请检查源文件是否存在以及目标路径权限。${NC}"; return 1; fi
}

# 配置 Nginx 反向代理
setup_nginx_proxy() {
    if ! confirm_action "是否需要自动配置 Nginx 反向代理?"; then echo "跳过 Nginx 配置。"; NGINX_HTTP_PORT=80; NGINX_HTTPS_PORT=443; LOCAL_PROXY_PASS="none"; BACKEND_PROTOCOL="none"; return 0; fi
    while true; do read -p "请输入 Nginx 监听的 HTTP 端口 [默认: ${NGINX_HTTP_PORT}]: " http_port_input; if [[ -z "$http_port_input" ]]; then break; elif [[ "$http_port_input" =~ ^[0-9]+$ && "$http_port_input" -gt 0 && "$http_port_input" -le 65535 ]]; then NGINX_HTTP_PORT=$http_port_input; break; else echo -e "${YELLOW}无效端口号。请输入 1-65535 之间的数字，或直接回车使用默认值。${NC}"; fi; done; echo -e "Nginx HTTP 端口设置为: ${GREEN}${NGINX_HTTP_PORT}${NC}"
    while true; do read -p "请输入 Nginx 监听的 HTTPS 端口 [默认: ${NGINX_HTTPS_PORT}]: " https_port_input; if [[ -z "$https_port_input" ]]; then break; elif [[ "$https_port_input" =~ ^[0-9]+$ && "$https_port_input" -gt 0 && "$https_port_input" -le 65535 ]]; then if [[ "$https_port_input" -eq "$NGINX_HTTP_PORT" ]]; then echo -e "${YELLOW}HTTPS 端口不能与 HTTP 端口 (${NGINX_HTTP_PORT}) 相同。${NC}"; else NGINX_HTTPS_PORT=$https_port_input; break; fi; else echo -e "${YELLOW}无效端口号。请输入 1-65535 之间的数字，或直接回车使用默认值。${NC}"; fi; done; echo -e "Nginx HTTPS 端口设置为: ${GREEN}${NGINX_HTTPS_PORT}${NC}"
    while true; do read -p "请选择后端服务 (${DOMAIN}) 使用的协议: [1] http (默认) [2] https : " proto_choice; if [[ -z "$proto_choice" || "$proto_choice" == "1" ]]; then BACKEND_PROTOCOL="http"; break; elif [[ "$proto_choice" == "2" ]]; then BACKEND_PROTOCOL="https"; break; else echo -e "${YELLOW}无效输入，请输入 1 或 2。${NC}"; fi; done; echo -e "后端服务协议设置为: ${GREEN}${BACKEND_PROTOCOL}${NC}"
    local addr_input=""; while [[ -z "$LOCAL_PROXY_PASS" ]]; do read -p "请输入 Nginx 需要反向代理的本地服务地址 (只需 IP/域名 和 端口, 例如 localhost:8080 或 [::1]:30000): " addr_input; if [[ "$addr_input" =~ ^(\[([0-9a-fA-F:]+)\]|([a-zA-Z0-9.-]+)):([0-9]+)$ ]]; then LOCAL_PROXY_PASS="${BACKEND_PROTOCOL}://${addr_input}"; echo -e "将使用代理地址: ${GREEN}${LOCAL_PROXY_PASS}${NC}"; else echo -e "${YELLOW}地址格式似乎不正确，请确保是 '地址:端口' 或 '[IPv6地址]:端口' 格式。${NC}"; LOCAL_PROXY_PASS=""; fi; done
    echo -e "${BLUE}[*] 生成 Nginx 配置文件: $NGINX_CONF_PATH ...${NC}"; mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled; mkdir -p /var/www/html/.well-known/acme-challenge; chown www-data:www-data /var/www/html -R 2>/dev/null || echo -e "${YELLOW}[!] 无法设置 /var/www/html 权限 (可能 www-data 用户/组不存在)。${NC}"
    local redirect_suffix_bash=""; if [[ "${NGINX_HTTPS_PORT}" -ne 443 ]]; then redirect_suffix_bash=":${NGINX_HTTPS_PORT}"; fi
    cat > "$NGINX_CONF_PATH" <<EOF
server { listen ${NGINX_HTTP_PORT}; listen [::]:${NGINX_HTTP_PORT}; server_name ${DOMAIN}; location ~ /.well-known/acme-challenge/ { allow all; root /var/www/html; } location / { return 301 https://\$host${redirect_suffix_bash}\$request_uri; } }
server { listen ${NGINX_HTTPS_PORT} ssl http2; listen [::]:${NGINX_HTTPS_PORT} ssl http2; server_name ${DOMAIN}; ssl_certificate ${CERT_PATH}/fullchain.pem; ssl_certificate_key ${CERT_PATH}/privkey.pem; ssl_session_timeout 1d; ssl_session_cache shared:SSL:10m; ssl_session_tickets off; ssl_protocols TLSv1.2 TLSv1.3; ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384; ssl_prefer_server_ciphers off; add_header Strict-Transport-Security "max-age=15768000" always; ssl_stapling on; ssl_stapling_verify on; ssl_trusted_certificate ${CERT_PATH}/chain.pem; resolver 1.1.1.1 8.8.8.8 valid=300s; resolver_timeout 5s; location / { proxy_pass ${LOCAL_PROXY_PASS}; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto \$scheme; proxy_set_header X-Forwarded-Host \$host; proxy_set_header X-Forwarded-Port \$server_port; $( [[ "$BACKEND_PROTOCOL" == "https" ]] && echo '        proxy_ssl_server_name on;' ) } }
EOF
    local enabled_link="/etc/nginx/sites-enabled/${DOMAIN}.conf"; if [[ -L "$enabled_link" ]]; then echo -e "${YELLOW}[!] Nginx 配置软链接已存在，将重新创建。${NC}"; rm -f "$enabled_link"; fi; ln -s "$NGINX_CONF_PATH" "$enabled_link"; if [[ $? -eq 0 ]]; then echo -e "${GREEN}[✓] Nginx 配置已启用 (创建软链接)。${NC}"; else echo -e "${RED}[✗] 创建 Nginx 配置软链接失败。${NC}"; return 1; fi
    echo -e "${GREEN}[✓] Nginx 配置文件已生成并启用: ${NGINX_CONF_PATH}${NC}"; echo -e "${YELLOW}[!] Nginx 配置将在证书申请成功后进行测试和重载。${NC}"; return 0
}

# 创建 DDNS 更新脚本 (v4.1: 修复 URL 列表处理 Bug)
create_ddns_script() {
    if [[ "$DDNS_FREQUENCY" -le 0 ]]; then echo "${YELLOW}DDNS 已禁用，跳过创建 DDNS 更新脚本。${NC}"; if [[ -f "$DDNS_SCRIPT_PATH" ]]; then echo "${YELLOW}检测到旧的 DDNS 脚本 $DDNS_SCRIPT_PATH，正在删除...${NC}"; rm -f "$DDNS_SCRIPT_PATH"; fi; return 0; fi
    echo -e "${BLUE}[*] 创建 DDNS 更新脚本 (v4.1): $DDNS_SCRIPT_PATH ...${NC}"; mkdir -p "$(dirname "$DDNS_SCRIPT_PATH")"
    local current_token; if [[ -f "$CLOUDFLARE_CREDENTIALS" ]]; then current_token=$(grep dns_cloudflare_api_token "$CLOUDFLARE_CREDENTIALS" | awk '{print $3}'); fi; if [[ -z "$current_token" ]]; then echo -e "${RED}[✗] 无法从 $CLOUDFLARE_CREDENTIALS 读取 API Token，无法创建 DDNS 脚本。${NC}"; return 1; fi

    # DDNS 更新脚本模板 (修复了 get_current_ip 中的 URL 循环)
    cat > "$DDNS_SCRIPT_PATH" <<EOF
#!/bin/bash
# --- DDNS 更新脚本 for ${DOMAIN} (v4.1 - 修复 URL 列表 Bug & 保留代理状态) ---

# --- 配置 ---
CF_CREDENTIALS_FILE="${CLOUDFLARE_CREDENTIALS}"
DOMAIN="${DOMAIN}"
RECORD_TYPE="${RECORD_TYPE}"
ZONE_ID="${ZONE_ID}"
CF_API="https://api.cloudflare.com/client/v4"
LOG_FILE="/var/log/cf_ddns_update_${DOMAIN}.log"
TIMEOUT=10
# 定义 IP 查询 URL 列表
IPV4_URLS=("https://api.ipify.org" "https://ifconfig.me/ip" "https://ipv4.icanhazip.com")
IPV6_URLS=("https://api64.ipify.org" "https://ifconfig.me/ip" "https://ipv6.icanhazip.com")

# --- 函数 ---
log_message() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1" >> "\$LOG_FILE"; }

# 获取当前公网 IP (修复了 URL 循环)
get_current_ip() {
    local type=\$1; local curl_opt; local curl_ua="Bash-DDNS-Script/1.0"; local ip=""; local raw_output=""
    if [[ "\$type" == "A" ]]; then curl_opt="-4"; for url in "\${IPV4_URLS[@]}"; do log_message "调试：正在查询 \$url (IPv4)..."; raw_output=\$(curl \$curl_opt --user-agent "\$curl_ua" --max-time \$TIMEOUT "\$url" | head -n 1); local curl_exit_status=\$?; if [[ \$curl_exit_status -ne 0 ]]; then log_message "警告：curl 命令执行 \$url 失败，退出状态码 \$curl_exit_status。"; fi; ip=\$(echo "\$raw_output" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'); log_message "调试：从 \$url 收到 (原始): '\$raw_output' / (处理后): '\$ip'"; if [[ -n "\$ip" ]]; then if [[ "\$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then log_message "调试：找到有效的 IPv4: \$ip"; echo "\$ip"; return 0; fi; log_message "警告：从 \$url 收到非空响应但验证失败: '\$ip'"; else log_message "调试：从 \$url 收到空响应。"; fi; sleep 1; done
    elif [[ "\$type" == "AAAA" ]]; then curl_opt="-6"; for url in "\${IPV6_URLS[@]}"; do log_message "调试：正在查询 \$url (IPv6)..."; raw_output=\$(curl \$curl_opt --user-agent "\$curl_ua" --max-time \$TIMEOUT "\$url" | head -n 1); local curl_exit_status=\$?; if [[ \$curl_exit_status -ne 0 ]]; then log_message "警告：curl 命令执行 \$url 失败，退出状态码 \$curl_exit_status。"; fi; ip=\$(echo "\$raw_output" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'); log_message "调试：从 \$url 收到 (原始): '\$raw_output' / (处理后): '\$ip'"; if [[ -n "\$ip" ]]; then if [[ "\$ip" =~ ^([0-9a-fA-F:]+)$ && "\$ip" == *":"* ]]; then log_message "调试：找到有效的 IPv6: \$ip"; echo "\$ip"; return 0; fi; log_message "警告：从 \$url 收到非空响应但验证失败: '\$ip'"; else log_message "调试：从 \$url 收到空响应。"; fi; sleep 1; done
    else log_message "错误：指定的记录类型无效: \$type"; return 1; fi
    log_message "错误：尝试所有 URL 后，未能从所有来源获取当前的公共 \$type IP 地址。"; return 1
}

# 获取 Cloudflare DNS 记录信息
get_cf_record() {
    local cf_token=\$1; RECORD_INFO=\$(curl -s --max-time \$TIMEOUT -X GET "\$CF_API/zones/\$ZONE_ID/dns_records?type=\$RECORD_TYPE&name=\$DOMAIN" -H "Authorization: Bearer \$cf_token" -H "Content-Type: application/json"); if [[ \$? -ne 0 ]]; then log_message "错误：API 调用失败 (获取记录 - 网络/超时)"; return 1; fi; if ! echo "\$RECORD_INFO" | jq -e '.success == true' > /dev/null; then local err_msg=\$(echo "\$RECORD_INFO" | jq -r '.errors[0].message // "未知 API 错误"'); log_message "错误：API 调用失败 (获取记录): \$err_msg"; return 1; fi
    echo "\$RECORD_INFO"; return 0
}

# 更新 Cloudflare DNS 记录 (v4: 接受代理状态参数)
update_cf_record() {
    local cf_token=\$1; local record_id=\$2; local new_ip=\$3; local current_proxied_status=\$4; if [[ "\$current_proxied_status" != "true" && "\$current_proxied_status" != "false" ]]; then log_message "警告：无效的代理状态 '\$current_proxied_status'，将强制设为 false。"; current_proxied_status="false"; fi
    log_message "调试：准备更新记录 \$record_id，IP: \$new_ip，代理状态: \$current_proxied_status"
    UPDATE_RESULT=\$(curl -s --max-time \$TIMEOUT -X PUT "\$CF_API/zones/\$ZONE_ID/dns_records/\$record_id" -H "Authorization: Bearer \$cf_token" -H "Content-Type: application/json" --data "{\"type\":\"\$RECORD_TYPE\",\"name\":\"\$DOMAIN\",\"content\":\"\$new_ip\",\"ttl\":120,\"proxied\":\${current_proxied_status}}")
    if [[ \$? -ne 0 ]]; then log_message "错误：API 调用失败 (更新记录 - 网络/超时)"; return 1; fi; if ! echo "\$UPDATE_RESULT" | jq -e '.success == true' > /dev/null; then local err_msg=\$(echo "\$UPDATE_RESULT" | jq -r '.errors[0].message // "未知 API 错误"'); log_message "错误：API 调用失败 (更新记录): \$err_msg"; return 1; fi; return 0
}

# --- DDNS 脚本主逻辑 ---
mkdir -p \$(dirname "\$LOG_FILE"); if [[ ! -f "\$CF_CREDENTIALS_FILE" ]]; then log_message "错误：找不到 Cloudflare 凭证文件: \$CF_CREDENTIALS_FILE"; exit 1; fi; CF_API_TOKEN=\$(grep dns_cloudflare_api_token "\$CF_CREDENTIALS_FILE" | awk '{print \$3}'); if [[ -z "\$CF_API_TOKEN" ]]; then log_message "错误：无法从 \$CF_CREDENTIALS_FILE 读取 Cloudflare API Token"; exit 1; fi
CURRENT_IP=\$(get_current_ip "\$RECORD_TYPE"); if [[ \$? -ne 0 ]]; then exit 1; fi; RECORD_INFO_JSON=\$(get_cf_record "\$CF_API_TOKEN"); if [[ \$? -ne 0 ]]; then exit 1; fi
CF_IP=\$(echo "\$RECORD_INFO_JSON" | jq -r '.result[0].content'); RECORD_ID=\$(echo "\$RECORD_INFO_JSON" | jq -r '.result[0].id'); CF_PROXIED=\$(echo "\$RECORD_INFO_JSON" | jq -r '.result[0].proxied')
if [[ -z "\$RECORD_ID" || "\$RECORD_ID" == "null" ]]; then log_message "错误：无法在 Cloudflare 上找到 \$DOMAIN 的 \$RECORD_TYPE 记录。"; exit 1; fi; if [[ -z "\$CF_IP" || "\$CF_IP" == "null" ]]; then log_message "错误：无法从 Cloudflare 记录中解析 IP 地址 (\$DOMAIN)。"; exit 1; fi; if [[ -z "\$CF_PROXIED" || "\$CF_PROXIED" == "null" ]]; then log_message "警告：无法从 Cloudflare 记录中解析代理状态 (\$DOMAIN)，将默认为 false。"; CF_PROXIED="false"; fi
if [[ "\$CURRENT_IP" == "\$CF_IP" ]]; then exit 0; else log_message "信息：IP 地址不匹配。当前: \$CURRENT_IP, Cloudflare: \$CF_IP。正在更新 Cloudflare (代理状态将保持为: \$CF_PROXIED)..."; update_cf_record "\$CF_API_TOKEN" "\$RECORD_ID" "\$CURRENT_IP" "\$CF_PROXIED"; if [[ \$? -eq 0 ]]; then log_message "成功：Cloudflare DNS 记录 (\$DOMAIN) 已成功更新为 \$CURRENT_IP (代理状态: \$CF_PROXIED)。"; exit 0; else exit 1; fi; fi
exit 0
EOF
    # --- DDNS 更新脚本模板结束 ---
    chmod +x "$DDNS_SCRIPT_PATH"; echo -e "${GREEN}[✓] DDNS 更新脚本 (v4.1) 创建成功: $DDNS_SCRIPT_PATH ${NC}"; return 0
}

# 设置 Cron 定时任务 (证书续期和 DDNS)
setup_cron_jobs() {
    echo -e "${BLUE}[*] 设置 Cron 定时任务...${NC}"; echo -e "${BLUE}[*] 创建证书续期部署钩子脚本: $DEPLOY_HOOK_SCRIPT ...${NC}"; mkdir -p "$(dirname "$DEPLOY_HOOK_SCRIPT")"
    cat > "$DEPLOY_HOOK_SCRIPT" <<EOF
#!/bin/bash
LOG_FILE="/var/log/cert_renew_${DOMAIN}.log"; CERT_PATH="${CERT_PATH}"; NGINX_CONF_PATH="${NGINX_CONF_PATH}"; LIVE_CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"; CONFIG_DIR="${CERT_PATH_PREFIX}/.managed_domains"; CONFIG_FILE="${CONFIG_DIR}/${DOMAIN}.conf"; LOCAL_PROXY_PASS="none"
if [[ -f "\$CONFIG_FILE" ]]; then source "\$CONFIG_FILE"; fi
log_hook() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1" >> "\$LOG_FILE"; }; mkdir -p \$(dirname "\$LOG_FILE"); log_hook "证书已为 ${DOMAIN} 续期。正在运行部署钩子..."
if [[ ! -f "\${LIVE_CERT_DIR}/fullchain.pem" || ! -f "\${LIVE_CERT_DIR}/privkey.pem" ]]; then log_hook "错误：在 \${LIVE_CERT_DIR} 中找不到源证书文件。无法复制。"; exit 1; fi
log_hook "正在从 \${LIVE_CERT_DIR} 复制新证书到 ${CERT_PATH}..."; if cp -L "\${LIVE_CERT_DIR}/fullchain.pem" "${CERT_PATH}/" && cp -L "\${LIVE_CERT_DIR}/privkey.pem" "${CERT_PATH}/" && cp -L "\${LIVE_CERT_DIR}/chain.pem" "${CERT_PATH}/" && cp -L "\${LIVE_CERT_DIR}/cert.pem" "${CERT_PATH}/"; then log_hook "成功：证书已复制到 ${CERT_PATH}。"; else log_hook "错误：复制证书文件失败。"; fi
if [[ "${LOCAL_PROXY_PASS}" != "none" ]] && [[ -n "${NGINX_CONF_PATH}" ]] && [[ -f "${NGINX_CONF_PATH}" ]] && command -v nginx >/dev/null 2>&1; then log_hook "Nginx 配置文件 ${NGINX_CONF_PATH} 存在且已配置代理。正在重载 Nginx..."; if nginx -t -c /etc/nginx/nginx.conf; then if systemctl reload nginx; then log_hook "成功：Nginx 已成功重载。"; else log_hook "错误：重载 Nginx 失败。请检查 'systemctl status nginx' 和 'journalctl -u nginx'。"; fi; else log_hook "错误：Nginx 配置测试失败 (nginx -t)。跳过重载。请手动检查 Nginx 配置！"; fi; else if [[ "${LOCAL_PROXY_PASS}" == "none" ]]; then log_hook "此域名未配置 Nginx 代理。跳过 Nginx 重载。"; elif [[ ! -f "${NGINX_CONF_PATH}" ]]; then log_hook "找不到 Nginx 配置文件 ${NGINX_CONF_PATH}。跳过 Nginx 重载。"; else log_hook "找不到 nginx 命令或未配置 Nginx。跳过 Nginx 重载。"; fi; fi
log_hook "为 ${DOMAIN} 执行的部署钩子已完成。"; exit 0
EOF
    chmod +x "$DEPLOY_HOOK_SCRIPT"; echo -e "${GREEN}[✓] 证书续期部署钩子脚本创建成功: $DEPLOY_HOOK_SCRIPT ${NC}"
    CRON_TAG_RENEW="# CertRenew_${DOMAIN}"; CRON_TAG_DDNS="# DDNSUpdate_${DOMAIN}"; local CRON_CONTENT
    (crontab -l 2>/dev/null | grep -v -F "$CRON_TAG_RENEW" | grep -v -F "$CRON_TAG_DDNS") | crontab -; CRON_CONTENT=$(crontab -l 2>/dev/null)
    local certbot_cmd=$(command -v certbot); if [[ -z "$certbot_cmd" ]]; then echo -e "${RED}[✗] 找不到 certbot 命令。证书续期 Cron 任务可能失败。${NC}"; certbot_cmd="certbot"; fi
    CRON_CERT_RENEW="0 3 * * * $certbot_cmd renew --deploy-hook \"$DEPLOY_HOOK_SCRIPT\" >> /var/log/certbot_renew.log 2>&1 ${CRON_TAG_RENEW}"; echo "${CRON_CONTENT}"$'\n'"${CRON_CERT_RENEW}" | crontab -; echo -e "${GREEN}[✓] Cron 证书续期任务已设置 (${DOMAIN})。${NC}"
    if [[ "$DDNS_FREQUENCY" -gt 0 ]]; then if [[ -f "$DDNS_SCRIPT_PATH" ]]; then CRON_DDNS_UPDATE="*/${DDNS_FREQUENCY} * * * * $DDNS_SCRIPT_PATH ${CRON_TAG_DDNS}"; CRON_CONTENT=$(crontab -l 2>/dev/null); echo "${CRON_CONTENT}"$'\n'"${CRON_DDNS_UPDATE}" | crontab -; echo -e "${GREEN}[✓] Cron DDNS 更新任务已设置 (${DOMAIN}, 频率: ${DDNS_FREQUENCY} 分钟)。${NC}"; else echo -e "${RED}[✗] DDNS 更新脚本 $DDNS_SCRIPT_PATH 未找到，无法设置 Cron 任务。${NC}"; fi; else echo -e "${YELLOW}DDNS 已禁用，未设置 DDNS 更新 Cron 任务。${NC}"; fi
    return 0
}

# 保存当前域名的配置变量到文件
save_domain_config() {
    echo -e "${BLUE}[*] 保存域名 ${DOMAIN} 的配置...${NC}"; mkdir -p "$CONFIG_DIR"; local config_file="${CONFIG_DIR}/${DOMAIN}.conf"
    cat > "$config_file" <<EOF
# Configuration for domain: ${DOMAIN}
# Generated by script on $(date)
DOMAIN="${DOMAIN}"; CF_API_TOKEN="${CF_API_TOKEN}"; EMAIL="${EMAIL}"; CERT_PATH="${CERT_PATH}"; CLOUDFLARE_CREDENTIALS="${CLOUDFLARE_CREDENTIALS}"; DEPLOY_HOOK_SCRIPT="${DEPLOY_HOOK_SCRIPT}"; DDNS_SCRIPT_PATH="${DDNS_SCRIPT_PATH}"; DDNS_FREQUENCY="${DDNS_FREQUENCY}"; RECORD_TYPE="${RECORD_TYPE}"; ZONE_ID="${ZONE_ID}"; NGINX_CONF_PATH="${NGINX_CONF_PATH}"; LOCAL_PROXY_PASS="${LOCAL_PROXY_PASS}"; BACKEND_PROTOCOL="${BACKEND_PROTOCOL}"; NGINX_HTTP_PORT="${NGINX_HTTP_PORT}"; NGINX_HTTPS_PORT="${NGINX_HTTPS_PORT}"
EOF
    chmod 600 "$config_file"; echo -e "${GREEN}[✓] 配置已保存到: ${config_file}${NC}"
}

# 列出已配置的 Web 服务域名
list_configured_domains() {
    echo -e "${BLUE}[*] 当前已配置的 Web 服务域名列表:${NC}"; mkdir -p "$CONFIG_DIR"; local domains=(); local i=1
    for config_file in "${CONFIG_DIR}"/*.conf; do if [[ -f "$config_file" && -r "$config_file" ]]; then local domain_name=$(basename "$config_file" .conf); echo -e "  ${CYAN}[$i]${NC} $domain_name"; domains+=("$domain_name"); ((i++)); fi; done
    if [[ ${#domains[@]} -eq 0 ]]; then echo -e "${YELLOW}  未找到任何已配置的 Web 服务域名。${NC}"; return 1; fi; return 0
}

# 删除指定域名的配置和相关文件/任务
delete_domain_config() {
    echo -e "${RED}[!] 删除 Web 服务域名配置是一个危险操作，将移除相关证书、脚本和配置！${NC}"; echo -e "${YELLOW}此操作不会删除 Cloudflare 上的 DNS 记录。${NC}"; list_configured_domains; if [[ $? -ne 0 ]]; then return; fi; local domains=(); for config_file in "${CONFIG_DIR}"/*.conf; do if [[ -f "$config_file" && -r "$config_file" ]]; then domains+=("$(basename "$config_file" .conf)"); fi; done; local choice; local DOMAIN_TO_DELETE
    while true; do read -p "请输入要删除的域名的序号 (输入 '0' 退出): " choice; if [[ "$choice" == "0" ]]; then echo "取消删除操作。"; return; fi; if [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#domains[@]} ]]; then local index=$((choice - 1)); DOMAIN_TO_DELETE=${domains[$index]}; break; else echo -e "${YELLOW}无效的序号，请重新输入。${NC}"; fi; done
    echo -e "${RED}你确定要删除域名 ${DOMAIN_TO_DELETE} 的所有本地配置吗？${NC}"; if ! confirm_action "此操作不可恢复！确认删除吗?"; then echo "取消删除操作。"; return; fi
    echo -e "${BLUE}[*] 开始删除域名 ${DOMAIN_TO_DELETE} 的本地配置...${NC}"; local config_file_to_load="${CONFIG_DIR}/${DOMAIN_TO_DELETE}.conf"
    if [[ -f "$config_file_to_load" ]]; then echo -e "${BLUE}[*] 加载 ${DOMAIN_TO_DELETE} 的配置用于删除...${NC}"; source "$config_file_to_load"; echo -e "${GREEN}[✓] 配置加载成功。${NC}"; else echo -e "${RED}[✗] 找不到 ${DOMAIN_TO_DELETE} 的配置文件，删除中止。可能配置已损坏或部分删除。${NC}"; return 1; fi
    echo -e "${BLUE}[*] 移除 Cron 任务...${NC}"; CRON_TAG_RENEW="# CertRenew_${DOMAIN_TO_DELETE}"; CRON_TAG_DDNS="# DDNSUpdate_${DOMAIN_TO_DELETE}"; (crontab -l 2>/dev/null | grep -v -F "$CRON_TAG_RENEW" | grep -v -F "$CRON_TAG_DDNS") | crontab -; echo -e "${GREEN}[✓] Cron 任务已移除。${NC}"
    if [[ -n "$DDNS_SCRIPT_PATH" && -f "$DDNS_SCRIPT_PATH" ]]; then echo -e "${BLUE}[*] 删除 DDNS 更新脚本: $DDNS_SCRIPT_PATH ...${NC}"; rm -f "$DDNS_SCRIPT_PATH"; echo -e "${GREEN}[✓] DDNS 脚本已删除。${NC}"; fi
    if [[ -n "$DEPLOY_HOOK_SCRIPT" && -f "$DEPLOY_HOOK_SCRIPT" ]]; then echo -e "${BLUE}[*] 删除证书续期钩子脚本: $DEPLOY_HOOK_SCRIPT ...${NC}"; rm -f "$DEPLOY_HOOK_SCRIPT"; echo -e "${GREEN}[✓] 续期钩子脚本已删除。${NC}"; fi
    local nginx_enabled_link="/etc/nginx/sites-enabled/${DOMAIN_TO_DELETE}.conf"; if [[ "$LOCAL_PROXY_PASS" != "none" ]] && [[ -n "$NGINX_CONF_PATH" ]] && (-f "$NGINX_CONF_PATH" || -L "$nginx_enabled_link"); then echo -e "${BLUE}[*] 删除 Nginx 配置...${NC}"; if [[ -L "$nginx_enabled_link" ]]; then rm -f "$nginx_enabled_link"; echo -e "${GREEN}[✓] Nginx sites-enabled 软链接已删除。${NC}"; fi; if [[ -f "$NGINX_CONF_PATH" ]]; then rm -f "$NGINX_CONF_PATH"; echo -e "${GREEN}[✓] Nginx sites-available 配置文件已删除。${NC}"; fi; echo -e "${BLUE}[*] 检查并重载 Nginx 配置...${NC}"; if command_exists nginx; then if nginx -t -c /etc/nginx/nginx.conf; then systemctl reload nginx; echo -e "${GREEN}[✓] Nginx 已重载。${NC}"; else echo -e "${RED}[✗] Nginx 配置检查失败！请手动检查 Nginx 配置。${NC}"; fi; else echo -e "${YELLOW}[!] Nginx 未安装，跳过重载。${NC}"; fi; elif [[ "$LOCAL_PROXY_PASS" == "none" ]]; then echo -e "${YELLOW}[!] 此域名的 Nginx 未配置，跳过删除。${NC}"; fi
    if [[ -n "$CLOUDFLARE_CREDENTIALS" && -f "$CLOUDFLARE_CREDENTIALS" ]]; then echo -e "${BLUE}[*] 删除 Cloudflare 凭证文件: $CLOUDFLARE_CREDENTIALS ...${NC}"; rm -f "$CLOUDFLARE_CREDENTIALS"; echo -e "${GREEN}[✓] Cloudflare 凭证文件已删除。${NC}"; fi
    if [[ -n "$CERT_PATH" && -d "$CERT_PATH" ]]; then echo -e "${BLUE}[*] 删除证书副本目录: $CERT_PATH ...${NC}"; rm -rf "$CERT_PATH"; echo -e "${GREEN}[✓] 证书副本目录已删除。${NC}"; fi
    echo -e "${BLUE}[*] 删除 Let's Encrypt 证书 (certbot)...${NC}"; if command_exists certbot; then local certbot_cmd=$(command -v certbot); "$certbot_cmd" delete --cert-name "${DOMAIN_TO_DELETE}" --non-interactive --logs-dir /var/log/letsencrypt; echo -e "${GREEN}[✓] 已尝试使用 certbot 删除证书。${NC}"; else echo -e "${YELLOW}[!] certbot 命令未找到，无法自动删除 Let's Encrypt 证书。${NC}"; echo -e "${YELLOW}   请手动清理 /etc/letsencrypt/... ${NC}"; fi
    if [[ -f "$config_file_to_load" ]]; then echo -e "${BLUE}[*] 删除脚本配置文件: $config_file_to_load ...${NC}"; rm -f "$config_file_to_load"; echo -e "${GREEN}[✓] 脚本配置文件已删除。${NC}"; fi
    echo -e "${GREEN}[✓] 域名 ${DOMAIN_TO_DELETE} 的所有相关本地配置已成功删除！${NC}"; DOMAIN="" CF_API_TOKEN="" EMAIL="your@mail.com" CERT_PATH="" CLOUDFLARE_CREDENTIALS="" DEPLOY_HOOK_SCRIPT="" DDNS_SCRIPT_PATH="" DDNS_FREQUENCY=5 RECORD_TYPE="" ZONE_ID="" NGINX_CONF_PATH="" LOCAL_PROXY_PASS="" BACKEND_PROTOCOL="http" NGINX_HTTP_PORT=80 NGINX_HTTPS_PORT=443
}

# 添加新 Web 服务域名的主流程 (v5.1)
add_new_domain() {
    echo -e "\n${CYAN}--- 5.1 添加新 Web 服务域名配置 ---${NC}"
    local overall_success=0 # 0 = success, 1 = failure

    # 0. 确保 Certbot 和 Nginx 已安装
    if ! install_or_update_certbot; then echo -e "${RED}[✗] Certbot 环境设置失败，无法继续。${NC}"; return 1; fi
    echo -e "${BLUE}[*] 检查并安装 Nginx...${NC}"; if ! install_package "nginx"; then echo -e "${RED}[✗] Nginx 安装失败，无法继续配置 Web 服务。${NC}"; return 1; fi

    # --- 开始配置流程 ---
    get_user_input_initial || { echo -e "${RED}[✗] 获取用户输入失败。${NC}"; return 1; }
    setup_nginx_proxy || { echo -e "${RED}[✗] Nginx 代理配置步骤失败。${NC}"; overall_success=1; }
    create_cf_credentials || { echo -e "${RED}[✗] 创建 Cloudflare 凭证失败。${NC}"; return 1; }
    detect_public_ip || { echo -e "${RED}[✗] 检测公网 IP 失败。${NC}"; return 1; }
    select_record_type || { echo -e "${RED}[✗] 选择记录类型失败。${NC}"; return 1; }
    get_zone_id || { echo -e "${RED}[✗] 获取 Cloudflare Zone ID 失败。${NC}"; return 1; }
    # 确保 DNS 记录存在且代理关闭，为证书申请做准备
    manage_cloudflare_record "设置" || { echo -e "${RED}[✗] 设置 Cloudflare DNS 记录失败。${NC}"; return 1; }

    # --- 证书申请与后续步骤 ---
    if request_certificate; then
        # 证书申请成功
        copy_certificate || overall_success=1
        # 询问并开启 Cloudflare 代理
        if confirm_action "证书申请成功！是否要在 Cloudflare 上为此域名开启代理（橙色云朵）？"; then
            enable_cloudflare_proxy "$DOMAIN" || overall_success=1
        else echo -e "${YELLOW}用户选择不开启 Cloudflare 代理。${NC}"; fi
        # 创建 DDNS 脚本 (使用修复后的模板)
        create_ddns_script || overall_success=1
        setup_cron_jobs || overall_success=1
        save_domain_config || overall_success=1

        # 测试并重载 Nginx (如果配置了 Nginx)
        if [[ "$LOCAL_PROXY_PASS" != "none" ]]; then
            echo -e "\n${BLUE}[*] 检查 Nginx 配置并尝试重载 (证书已申请/复制)...${NC}"
            if ! command_exists nginx; then echo -e "${RED}[✗] Nginx 命令未找到。无法测试或重载配置。${NC}"; overall_success=1;
            else
                nginx_test_output=$(nginx -t -c /etc/nginx/nginx.conf 2>&1); nginx_test_status=$?
                if [[ $nginx_test_status -eq 0 ]]; then
                    if systemctl reload nginx && systemctl is-active --quiet nginx; then
                        echo -e "${GREEN}[✓] Nginx 配置检查通过并已成功重载。${NC}"; echo -e "${YELLOW}提示：Nginx 正在监听 HTTP 端口 ${NGINX_HTTP_PORT} 和 HTTPS 端口 ${NGINX_HTTPS_PORT}。${NC}"
                        if command_exists ufw && ufw status | grep -q "Status: active"; then echo -e "${BLUE}[*] 尝试在 UFW 中允许 Nginx 端口 ${NGINX_HTTP_PORT} 和 ${NGINX_HTTPS_PORT}...${NC}"; ufw allow ${NGINX_HTTP_PORT}/tcp comment "Nginx HTTP (${DOMAIN})" > /dev/null; ufw allow ${NGINX_HTTPS_PORT}/tcp comment "Nginx HTTPS (${DOMAIN})" > /dev/null; echo -e "${GREEN}[✓] 已尝试添加 UFW 规则。请使用 '查看 UFW 规则' 确认。${NC}";
                        elif [[ "$NGINX_HTTP_PORT" -ne 80 || "$NGINX_HTTPS_PORT" -ne 443 ]]; then echo -e "${YELLOW}重要提示：请确保防火墙允许访问您设置的自定义端口 (${NGINX_HTTP_PORT} 和 ${NGINX_HTTPS_PORT})！${NC}"; fi
                        echo -e "${YELLOW}访问时，如果 HTTPS 端口不是 443，URL 中需要包含端口号，例如: https://${DOMAIN}:${NGINX_HTTPS_PORT}${NC}"
                    else echo -e "${RED}[✗] Nginx 重载后状态异常，请检查 Nginx 服务状态和日志。${NC}"; overall_success=1; fi
                else
                    echo -e "${RED}[✗] Nginx 配置检查失败 (nginx -t 返回错误)! Nginx 未重载。${NC}"; echo -e "${RED}--- Nginx 错误信息 ---${NC}"; echo -e "${YELLOW}${nginx_test_output}${NC}"; echo -e "${RED}-----------------------${NC}"; echo -e "${RED}请检查错误信息中提到的文件。通常这是由于 /etc/nginx/sites-enabled/ 中存在旧的、无效的配置文件引起的。${NC}"; echo -e "${RED}请手动清理无效配置 (例如 'sudo rm /etc/nginx/sites-enabled/your-old-site.conf')，然后重试 'sudo nginx -t'。${NC}"; overall_success=1;
                fi
            fi
        else echo -e "${YELLOW}[!] 未配置 Nginx 反向代理，跳过 Nginx 测试和重载。${NC}"; fi
    else
        # 证书申请失败
        echo -e "${RED}[!] 由于证书申请失败，后续步骤将被跳过。${NC}"; if [[ "$LOCAL_PROXY_PASS" != "none" ]]; then echo -e "${YELLOW}[!] 尝试清理未使用的 Nginx 配置...${NC}"; rm -f "/etc/nginx/sites-enabled/${DOMAIN}.conf"; rm -f "$NGINX_CONF_PATH"; fi; rm -f "$CLOUDFLARE_CREDENTIALS"; overall_success=1
    fi

    if [[ $overall_success -eq 0 ]]; then echo -e "\n${GREEN}--- 域名 ${DOMAIN} 配置完成！ ---${NC}"; return 0;
    else echo -e "\n${RED}--- 域名 ${DOMAIN} 配置过程中遇到错误，请检查上面的日志。 ---${NC}"; return 1; fi
}

# Web 服务管理主菜单
manage_web_service() {
     while true; do echo -e "\n${CYAN}--- Web 服务管理 (LE + CF + Nginx) ---${NC}"; echo -e " ${YELLOW}1.${NC} 添加新域名并配置 (证书/代理/Nginx/DDNS)"; echo -e " ${YELLOW}2.${NC} 查看已配置的域名列表"; echo -e " ${YELLOW}3.${NC} 删除已配置的域名及其本地设置"; echo -e " ${YELLOW}0.${NC} 返回主菜单"; read -p "请输入选项 [0-3]: " web_choice
        case $web_choice in 1) add_new_domain ;; 2) list_configured_domains ;; 3) delete_domain_config ;; 0) break ;; *) echo -e "${RED}无效选项。${NC}" ;; esac
        [[ $web_choice != 0 ]] && read -p "按 Enter键 继续..."
    done
}

# --- 主菜单 ---
show_main_menu() {
    check_root; local certbot_vsn="未知"; if command_exists certbot; then certbot_vsn=$(certbot --version 2>&1 | awk '{print $2}'); fi
    echo -e "\n${CYAN}=======================================================${NC}"; echo -e "${CYAN}     服务器初始化与管理脚本 (v5.1)     ${NC}"; echo -e "${CYAN}=======================================================${NC}"; echo -e " ${BLUE}--- 系统与安全 ---${NC}"; echo -e "  ${YELLOW}1.${NC} 安装基础依赖工具 (curl, jq, unzip, snapd)"; echo -e "  ${YELLOW}2.${NC} UFW 防火墙管理"; echo -e "  ${YELLOW}3.${NC} Fail2ban 入侵防御管理"; echo -e "  ${YELLOW}4.${NC} SSH 安全管理 (端口: ${YELLOW}${CURRENT_SSH_PORT}${NC})"; echo -e "\n ${BLUE}--- Web 服务 (Certbot: ${certbot_vsn}) ---${NC}"; echo -e "  ${YELLOW}5.${NC} Web 服务管理 (Let's Encrypt + Cloudflare + Nginx)"; echo -e "\n ${BLUE}--- 其他 ---${NC}"; echo -e "  ${YELLOW}0.${NC} 退出脚本"; echo -e "${CYAN}=======================================================${NC}"; read -p "请输入选项 [0-5]: " main_choice
}

# --- 脚本入口 ---
check_root
while true; do show_main_menu; case $main_choice in 1) install_common_tools ;; 2) manage_ufw ;; 3) manage_fail2ban ;; 4) manage_ssh_security ;; 5) manage_web_service ;; 0) echo "退出脚本。" ; exit 0 ;; *) echo -e "${RED}无效选项，请输入 0 到 5 之间的数字。${NC}" ;; esac; if [[ "$main_choice" != "0" ]]; then read -p "按 Enter键 继续..."; fi; done
exit 0
