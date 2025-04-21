#!/bin/bash

# ==============================================================================
# 服务器初始化与管理脚本 (v3 - 包含 DDNS 修复)
# 功能:
# 1.  **基础工具**: 安装常用软件包。
# 2.  **防火墙 (UFW)**: 安装、启用、管理端口规则 (增/删/查)。
# 3.  **入侵防御 (Fail2ban)**: 安装并配置 SSH 防护、重新配置、查看状态。
# 4.  **SSH 安全**: 更改端口、创建 sudo 用户、禁用 root 登录、配置密钥登录。
# 5.  **Web 服务 (LE + CF + Nginx)**:
#     - 优先使用 Snap 安装/更新 Certbot 以提高兼容性。
#     - 自动申请 Let's Encrypt 证书 (使用 Cloudflare DNS 验证 - API Token)。
#     - 支持 IPv4 (A) / IPv6 (AAAA) 记录自动检测与添加/更新。
#     - 支持 DDNS (动态域名解析)，自动更新 Cloudflare 记录 (包含 IP 检测修复)。
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
# 在某些终端下，backspace 可能无法正常工作，stty sane 尝试重置终端设置
stty sane

# --- 函数定义 ---

# 清理并退出 (主要用于 trap 捕获意外中断信号)
cleanup_and_exit() {
    # 尝试删除临时文件（如果存在）
    rm -f "${FAIL2BAN_JAIL_LOCAL}.tmp.$$" 2>/dev/null
    echo -e "${RED}发生错误，脚本意外终止。${NC}"
    exit 1
}

# 错误处理陷阱，捕获 ERR (命令执行错误), SIGINT (Ctrl+C), SIGTERM (终止信号)
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
    # 脚本运行过程中 SSH 端口可能被修改，因此需要重新检测
    local detected_port
    detected_port=$(grep -iE "^\s*Port\s+" "$SSHD_CONFIG" | tail -n 1 | awk '{print $2}')
    if [[ "$detected_port" =~ ^[0-9]+$ ]]; then
        CURRENT_SSH_PORT=$detected_port
    else
        # 如果检测失败或不是数字，保持上一次的值或默认值
        if ! [[ "$CURRENT_SSH_PORT" =~ ^[0-9]+$ ]]; then
             CURRENT_SSH_PORT=$DEFAULT_SSH_PORT
        fi
    fi
}

# 通用确认函数 (Y/n/回车=Y)
confirm_action() {
    local prompt_msg="$1" # 提示信息作为第一个参数传入
    local reply
    while true; do
        # -p 显示提示信息，-n 1 读取一个字符，-r 禁止反斜杠转义
        read -p "$prompt_msg [Y/n/回车默认Y]: " -n 1 -r reply
        echo # 输出换行符，使界面更整洁
        # 处理输入: 匹配 Y 或 y (不区分大小写)，或匹配空输入 (直接回车)
        if [[ $reply =~ ^[Yy]$ || -z $reply ]]; then
            return 0 # 返回 0 表示确认 (Yes)
        # 匹配 N 或 n
        elif [[ $reply =~ ^[Nn]$ ]]; then
            return 1 # 返回 1 表示取消 (No)
        # 其他无效输入
        else
            echo -e "${YELLOW}请输入 Y 或 N，或直接按回车确认。${NC}";
        fi
    done
}


# 通用包安装函数 (使用 apt)
install_package() {
    local pkg_name="$1"
    local install_cmd="apt install -y" # 默认为 Debian/Ubuntu

    # 检查包是否已安装 (使用 dpkg -s 比 command_exists 更准确)
    if dpkg -s "$pkg_name" &> /dev/null; then
        echo -e "${YELLOW}[!] $pkg_name 似乎已安装。${NC}"
        return 0 # 已安装，返回成功
    fi

    echo -e "${BLUE}[*] 正在使用 apt 安装 $pkg_name ...${NC}"
    # 设置为非交互模式，避免安装过程中断需要用户输入
    export DEBIAN_FRONTEND=noninteractive
    # 更新源信息 (减少输出)
    apt update -y > /dev/null 2>&1
    # 执行安装
    $install_cmd "$pkg_name"
    # 检查安装是否成功
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[✗] 使用 apt 安装 $pkg_name 失败。请检查错误信息并手动安装。${NC}"
        return 1 # 安装失败，返回错误码
    else
        echo -e "${GREEN}[✓] $pkg_name 使用 apt 安装成功。${NC}"
        return 0 # 安装成功，返回成功码
    fi
}

# --- 1. 基础工具 ---
install_common_tools() {
    echo -e "\n${CYAN}--- 1. 安装基础依赖工具 ---${NC}"
    # 需要安装的工具列表
    local tools="curl jq expect unzip"
    local failed=0
    local installed_count=0
    local already_installed_count=0

    echo -e "${BLUE}[*] 检查并安装基础工具: ${tools}...${NC}"
    for tool in $tools; do
        # 检查是否已安装
        if dpkg -s "$tool" &> /dev/null; then
            echo -e "${YELLOW}[!] $tool 已安装。${NC}"
            already_installed_count=$((already_installed_count + 1))
        else
            # 调用安装函数进行安装
            install_package "$tool"
            if [[ $? -ne 0 ]]; then
                failed=1 # 标记安装失败
            else
                installed_count=$((installed_count + 1))
            fi
        fi
    done

    # 检查 snapd (用于 Certbot)
    echo -e "${BLUE}[*] 检查 snapd 是否安装...${NC}"
    if ! command_exists snap; then
        echo -e "${YELLOW}[!] snap 命令未找到。尝试安装 snapd...${NC}"
        install_package "snapd"
        if ! command_exists snap; then
            echo -e "${RED}[✗] snapd 安装失败。Certbot 可能无法通过 Snap 安装。${NC}"
            # 不标记为失败，允许脚本继续尝试 apt 安装 Certbot
        else
            echo -e "${GREEN}[✓] snapd 安装成功。${NC}"
            sleep 2 # 给 snapd 一点时间初始化
        fi
    else
        echo -e "${GREEN}[✓] snap 命令已找到。${NC}"
    fi


    # 输出安装总结
    echo -e "\n${CYAN}--- 基础工具安装总结 ---${NC}"
    echo -e "  新安装: ${GREEN}${installed_count}${NC} 个"
    echo -e "  已存在: ${YELLOW}${already_installed_count}${NC} 个"
    if [[ $failed -eq 0 ]]; then
        echo -e "${GREEN}[✓] 基础工具检查/安装完成。${NC}"
    else
        echo -e "${RED}[✗] 部分基础工具安装失败，请检查上面的错误信息。${NC}"
    fi
}

# --- 2. UFW 防火墙 ---
setup_ufw() {
    echo -e "\n${CYAN}--- 2.1 安装并启用 UFW 防火墙 ---${NC}"
    # 安装 UFW
    if ! install_package "ufw"; then return 1; fi # 如果安装失败则返回
    # 确保 expect 已安装，用于自动应答 ufw enable 的确认提示
    if ! command_exists expect; then
        if ! install_package "expect"; then
            echo -e "${RED}[✗] expect 工具安装失败，可能无法自动处理 UFW 启用确认。${NC}"
            # 即使 expect 安装失败，也继续尝试启用 UFW，但可能需要用户手动确认
        fi
    fi

    # 设置默认规则：拒绝所有入站，允许所有出站
    echo -e "${BLUE}[*] 设置 UFW 默认规则 (deny incoming, allow outgoing)...${NC}"
    ufw default deny incoming > /dev/null
    ufw default allow outgoing > /dev/null

    # 明确允许当前 SSH 端口，防止启用防火墙后无法连接
    echo -e "${BLUE}[*] 允许当前 SSH 端口 ($CURRENT_SSH_PORT)...${NC}"
    ufw allow $CURRENT_SSH_PORT/tcp comment "SSH Access (Current)" > /dev/null

    # 询问是否需要额外开放端口
    local extra_ports_input
    local extra_ports_array
    read -p "是否需要额外开放其他端口 (例如 80 443 8080，用空格隔开) [留空则跳过]: " extra_ports_input
    if [[ -n "$extra_ports_input" ]]; then
        read -a extra_ports_array <<< "$extra_ports_input" # 将输入分割到数组
        echo -e "${BLUE}[*] 尝试开放额外端口: ${extra_ports_array[*]} (默认TCP)...${NC}"
        for port in "${extra_ports_array[@]}"; do
            # 验证端口号是否有效
            if [[ "$port" =~ ^[0-9]+$ && "$port" -gt 0 && "$port" -le 65535 ]]; then
                ufw allow $port/tcp comment "Extra port added during setup" > /dev/null
                if [[ $? -eq 0 ]]; then
                    echo -e "  ${GREEN}[✓] 端口 $port/tcp 已添加规则。${NC}"
                else
                    echo -e "  ${RED}[✗] 添加端口 $port/tcp 规则失败。${NC}"
                fi
            else
                echo -e "  ${YELLOW}[!] '$port' 不是有效的端口号，已跳过。${NC}"
            fi
        done
    fi

    # 启用 UFW
    echo -e "${YELLOW}[!] 准备启用 UFW。这将断开除已允许端口外的所有连接。${NC}"
    if confirm_action "确认启用 UFW 吗?"; then
        # 如果 expect 可用，使用它自动应答确认提示
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
            # expect 不可用，直接尝试启用，可能需要用户手动输入 'y'
            ufw enable
        fi
        # 检查 UFW 状态是否为 active
        if ufw status | grep -q "Status: active"; then
            echo -e "${GREEN}[✓] UFW 已成功启用。${NC}"
            ufw status verbose # 显示详细状态
        else
            echo -e "${RED}[✗] UFW 启用失败。请检查错误信息。${NC}"
            return 1 # 启用失败返回错误
        fi
    else
        echo -e "${YELLOW}UFW 未启用。${NC}"
    fi
    return 0 # 启用成功或未启用都算正常完成此步骤
}

add_ufw_rule() {
    echo -e "\n${CYAN}--- 2.2 添加 UFW 规则 ---${NC}"
    local port protocol comment rule

    # 获取端口号并验证
    while true; do
        read -p "请输入要开放的端口号 (例如 80, 443, 8080): " port
        if [[ "$port" =~ ^[0-9]+$ && "$port" -gt 0 && "$port" -le 65535 ]]; then
            break
        else
            echo -e "${YELLOW}无效的端口号。请输入 1-65535 之间的数字。${NC}"
        fi
    done

    # 获取协议并验证
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

    # 获取备注 (可选)
    read -p "请输入端口用途备注 (例如 'Web Server HTTP', 'Game Server UDP'): " comment
    [[ -z "$comment" ]] && comment="Rule added by script" # 提供默认备注

    # 构建规则并添加
    rule="${port}/${protocol}"
    echo -e "${BLUE}[*] 准备添加规则: ufw allow ${rule} comment '${comment}'${NC}"
    if confirm_action "确认添加此规则吗?"; then
        ufw allow $rule comment "$comment"
        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}[✓] 规则已添加。请运行 '查看 UFW 规则' 确认。${NC}"
        else
            echo -e "${RED}[✗] 添加规则失败。${NC}"
        fi
    else
        echo -e "${YELLOW}操作已取消。${NC}"
    fi
}

delete_ufw_rule() {
    echo -e "\n${CYAN}--- 2.4 删除 UFW 规则 ---${NC}"
    # 检查 UFW 是否安装并启用
    if ! command_exists ufw || ! ufw status | grep -q "Status: active"; then
        echo -e "${YELLOW}[!] UFW 未安装或未启用。${NC}"
        return
    fi

    # 显示带编号的规则列表
    echo -e "${BLUE}当前 UFW 规则列表 (带编号):${NC}"
    ufw status numbered

    local nums_input
    local nums_array=()
    local valid_nums=()
    local num
    # 获取最大规则编号 (兼容不同输出格式)
    local highest_num=$(ufw status numbered | grep '^\[ *[0-9]\+ *\]' | sed -e 's/^\[ *//' -e 's/ *\].*//' | sort -n | tail -n 1)

    # 检查是否成功获取最大编号
    if ! [[ "$highest_num" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}[✗] 无法确定最大规则编号。请检查 'ufw status numbered' 的输出。${NC}"
        return 1
    fi

    # 获取用户要删除的编号
    read -p "请输入要删除的规则编号 (用空格隔开，例如 '1 3 5'): " nums_input
    if [[ -z "$nums_input" ]]; then
        echo -e "${YELLOW}未输入任何编号，操作取消。${NC}"
        return
    fi

    # 清理输入并分割到数组
    local cleaned_input=$(echo "$nums_input" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e "s/^'//" -e "s/'$//" -e 's/^"//' -e 's/"$//')
    read -a nums_array <<< "$cleaned_input"

    # 验证输入的编号是否有效
    for num in "${nums_array[@]}"; do
        if [[ "$num" =~ ^[1-9][0-9]*$ ]]; then # 必须是正整数
            if [[ "$num" -le "$highest_num" ]]; then # 不能超过最大编号
                valid_nums+=("$num")
            else
                 echo -e "${YELLOW}[!] 规则编号 '$num' 超出最大范围 ($highest_num)，已忽略。${NC}"
            fi
        else
            echo -e "${YELLOW}[!] '$num' 不是有效的规则编号，已忽略。${NC}"
        fi
    done

    # 如果没有有效的编号被选中，则取消操作
    if [[ ${#valid_nums[@]} -eq 0 ]]; then
        echo -e "${YELLOW}没有有效的规则编号被选中，操作取消。${NC}"
        return
    fi

    # 对编号进行降序排序，防止删除时序号变化导致错误
    IFS=$'\n' sorted_nums=($(sort -nr <<<"${valid_nums[*]}"))
    unset IFS

    # 确认删除操作
    echo -e "${BLUE}[*] 准备删除以下规则编号: ${sorted_nums[*]} ${NC}"
    if confirm_action "确认删除这些规则吗?"; then
        local delete_failed=0
        # 循环删除选中的规则
        for num_to_delete in "${sorted_nums[@]}"; do
            echo -n "  删除规则 $num_to_delete ... "
            # 使用 expect 自动确认 'y'
            if command_exists expect; then
                 expect -c "
                 set timeout 10
                 spawn ufw delete $num_to_delete
                 expect {
                     \"Proceed with operation (y|n)?\" { send \"y\r\"; exp_continue }
                     eof
                 }
                 " > /dev/null
                 # 假设 expect 执行成功，因为获取 ufw delete 的退出状态比较麻烦
                 echo -e "${GREEN}已执行删除命令。${NC}"
            else
                # 无 expect，尝试直接删除，可能需要手动确认
                ufw delete $num_to_delete
                if [[ $? -eq 0 ]]; then
                     echo -e "${GREEN}成功。${NC}"
                else
                     echo -e "${RED}失败。${NC}"
                     delete_failed=1
                fi
            fi
        done
        if [[ $delete_failed -eq 0 ]]; then
             echo -e "${GREEN}[✓] 选定的规则已删除 (或已尝试删除)。${NC}"
        else
             echo -e "${RED}[✗] 部分规则删除失败。${NC}"
        fi
        echo -e "${BLUE}请再次查看规则列表确认结果。${NC}"
        view_ufw_rules # 显示更新后的规则
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
    ufw status verbose # 显示详细信息
    echo -e "\n${BLUE}带编号的规则列表 (用于删除):${NC}"
    ufw status numbered
}

# 新增：允许所有 UFW 入站连接 (危险操作)
ufw_allow_all() {
    echo -e "\n${CYAN}--- 2.5 允许所有 UFW 入站连接 (危险) ---${NC}"
    echo -e "${RED}[!] 警告：此操作将允许来自任何源的任何入站连接，会显著降低服务器安全性！${NC}"
    echo -e "${YELLOW}   仅在您完全了解风险并有特定需求时（例如临时调试）才执行此操作。${NC}"
    echo -e "${YELLOW}   强烈建议在完成后立即恢复默认拒绝规则 (选项 6)。${NC}"

    # 检查 UFW 是否安装并启用
    if ! command_exists ufw || ! ufw status | grep -q "Status: active"; then
        echo -e "${YELLOW}[!] UFW 未安装或未启用。无法更改默认策略。${NC}"
        return
    fi

    # 再次确认危险操作
    if confirm_action "您确定要将 UFW 默认入站策略更改为 ALLOW (允许所有) 吗?"; then
        echo -e "${BLUE}[*] 正在设置默认入站策略为 ALLOW...${NC}"
        ufw default allow incoming
        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}[✓] UFW 默认入站策略已设置为 ALLOW。${NC}"
            echo -e "${RED}   请注意：现在所有端口都对外部开放！${NC}"
            ufw status verbose # 显示更新后的状态
        else
            echo -e "${RED}[✗] 设置默认入站策略失败。${NC}"
        fi
    else
        echo -e "${YELLOW}操作已取消。${NC}"
    fi
}

# 新增：重置 UFW 为默认拒绝规则 (保留 SSH)
ufw_reset_default() {
    echo -e "\n${CYAN}--- 2.6 重置 UFW 为默认拒绝规则 ---${NC}"
    echo -e "${BLUE}[*] 此操作将执行以下步骤:${NC}"
    echo "  1. 设置默认入站策略为 DENY (拒绝)。"
    echo "  2. 设置默认出站策略为 ALLOW (允许)。"
    echo "  3. 确保当前 SSH 端口 ($CURRENT_SSH_PORT/tcp) 规则存在。"
    echo "  4. 重新加载 UFW 规则。"
    echo -e "${YELLOW}   注意：除了 SSH 端口外，所有其他之前手动添加的 'allow' 规则将保持不变。${NC}"

    if ! command_exists ufw; then
        echo -e "${YELLOW}[!] UFW 未安装。无法重置。${NC}"
        return
    fi

    if confirm_action "确认要将 UFW 重置为默认拒绝策略 (并保留 SSH 端口) 吗?"; then
        echo -e "${BLUE}[*] 设置默认入站策略为 DENY...${NC}"
        ufw default deny incoming > /dev/null
        echo -e "${BLUE}[*] 设置默认出站策略为 ALLOW...${NC}"
        ufw default allow outgoing > /dev/null
        echo -e "${BLUE}[*] 确保当前 SSH 端口 ($CURRENT_SSH_PORT/tcp) 允许...${NC}"
        ufw allow $CURRENT_SSH_PORT/tcp comment "SSH Access (Current)" > /dev/null
        echo -e "${BLUE}[*] 重新加载 UFW 规则...${NC}"
        ufw reload > /dev/null
        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}[✓] UFW 已成功重置为默认拒绝策略并重新加载。${NC}"
            ufw status verbose # 显示更新后的状态
        else
            echo -e "${RED}[✗] UFW 重置或重新加载失败。${NC}"
        fi
    else
        echo -e "${YELLOW}操作已取消。${NC}"
    fi
}


manage_ufw() {
    while true; do
        echo -e "\n${CYAN}--- UFW 防火墙管理 ---${NC}"
        echo -e " ${YELLOW}1.${NC} 安装并启用 UFW (设置默认规则, 允许当前SSH, 可选额外端口)"
        echo -e " ${YELLOW}2.${NC} 添加允许规则 (开放端口)"
        echo -e " ${YELLOW}3.${NC} 查看当前 UFW 规则"
        echo -e " ${YELLOW}4.${NC} 删除 UFW 规则 (按编号)"
        echo -e " ${YELLOW}5.${NC} ${RED}允许所有入站连接 (危险!)${NC}"
        echo -e " ${YELLOW}6.${NC} 重置为默认拒绝规则 (保留 SSH)"
        echo -e " ${YELLOW}0.${NC} 返回主菜单"
        read -p "请输入选项 [0-6]: " ufw_choice

        case $ufw_choice in
            1) setup_ufw ;;
            2) add_ufw_rule ;;
            3) view_ufw_rules ;;
            4) delete_ufw_rule ;;
            5) ufw_allow_all ;;
            6) ufw_reset_default ;;
            0) break ;;
            *) echo -e "${RED}无效选项。${NC}" ;;
        esac
        # 暂停等待用户按 Enter 继续
        [[ $ufw_choice != 0 ]] && read -p "按 Enter键 继续..."
    done
}


# --- 3. Fail2ban ---
setup_fail2ban() {
    echo -e "\n${CYAN}--- 3.1 安装并配置 Fail2ban ---${NC}"
    # 1. 安装 fail2ban
    if ! install_package "fail2ban"; then
        echo -e "${RED}[✗] Fail2ban 安装失败，无法继续。${NC}"
        return 1
    fi
    # 2. 安装 rsyslog (某些系统如 Debian 12 需要它来提供日志给 Fail2ban)
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

    # 3. 进行 Fail2ban 初始配置 (调用配置函数)
    echo -e "${BLUE}[*] 进行 Fail2ban 初始配置 (${FAIL2BAN_JAIL_LOCAL})...${NC}"
    if ! configure_fail2ban; then # configure_fail2ban 负责写入配置
        echo -e "${RED}[✗] Fail2ban 初始配置失败。${NC}"
        return 1
    fi
    echo -e "${GREEN}[✓] Fail2ban 初始配置已写入 ${FAIL2BAN_JAIL_LOCAL}。${NC}"

    # 4. 启用并重启 Fail2ban 服务
    echo -e "${BLUE}[*] 启用并重启 Fail2ban 服务...${NC}"
    systemctl enable fail2ban > /dev/null
    systemctl restart fail2ban
    sleep 3 # 增加延时等待 fail2ban 启动

    # 5. 检查服务状态
    if systemctl is-active --quiet fail2ban; then
        echo -e "${GREEN}[✓] Fail2ban 服务已成功启动并启用。${NC}"
    else
        echo -e "${RED}[✗] Fail2ban 服务启动失败。请检查 'systemctl status fail2ban' 和日志。${NC}"
        echo -e "${YELLOW}   尝试查看日志: journalctl -u fail2ban -n 50 --no-pager ${NC}"
        return 1
    fi
    return 0
}

# 更新或创建配置项的辅助函数 (用于 jail.local 和 sshd_config)
update_or_add_config() {
    local file="$1"      # 配置文件路径
    local section="$2"   # 配置段名 (例如 sshd, 为空表示全局)
    local key="$3"       # 配置项键名
    local value="$4"     # 配置项值
    local section_header_regex="^\s*\[${section}\]" # 匹配段头 [section] 的正则表达式
    local temp_file_del="${file}.tmp_del.$$" # 删除旧行的临时文件
    local temp_file_add="${file}.tmp_add.$$" # 添加新行的临时文件

    # 如果指定了 section，确保 section header 存在
    if [[ -n "$section" ]] && ! grep -qE "$section_header_regex" "$file"; then
        # 对于 jail.local，如果 section 不存在，通常不应自动添加，除非是 DEFAULT 或 sshd
        # 对于 sshd_config，没有 section 概念
        # 简化处理：如果指定了 section 且不存在，则在文件末尾添加
        echo -e "${YELLOW}[!] 段落 [${section}] 在 ${file} 中未找到，将在末尾添加。${NC}"
        echo -e "\n[${section}]" >> "$file"
    fi

    # 1. 删除所有匹配的 key 行 (注释或未注释)
    # 对 key 中的正则表达式特殊字符进行转义
    local escaped_key_for_grep=$(sed 's/[.^$*]/\\&/g' <<< "$key")
    # 构造精确匹配 key 的正则表达式 (行首，可选空格，可选#，可选空格，key，可选空格，=)
    local key_match_regex_grep="^\s*#?\s*${escaped_key_for_grep}\s*="
    grep -vE "$key_match_regex_grep" "$file" > "$temp_file_del"
    local grep_status=$?
    # grep -v 在删除所有行时返回1，只有>1才表示错误
    if [[ $grep_status -gt 1 ]]; then
         echo -e "${RED}[✗] 使用 grep -v 处理配置文件时出错 (删除 ${key})。状态码: $grep_status${NC}"
         rm -f "$temp_file_del" 2>/dev/null
         return 1
    fi

    # 2. 添加新行
    # 对 value 中的反斜杠进行转义，以便 awk 正确打印
    local escaped_value_for_awk=$(echo "$value" | sed 's/\\/\\\\/g')
    # 对于 sshd_config，key 和 value 之间通常是空格，而不是 =
    # 对于 jail.local，通常是 key = value
    # 统一使用 key = value 格式写入，对 sshd_config 可能需要调整
    # --> 修正：根据文件类型决定格式
    local new_line
    if [[ "$file" == "$SSHD_CONFIG" ]]; then
        new_line="${key} ${escaped_value_for_awk}" # sshd_config 使用空格
    else
        new_line="${key} = ${escaped_value_for_awk}" # jail.local 等使用 =
    fi

    # 如果指定了 section，在 section 之后添加新行
    if [[ -n "$section" ]]; then
        awk -v section_re="$section_header_regex" -v new_line="${new_line}" '
        $0 ~ section_re { print; print new_line; added=1; next } # 匹配段头，打印段头和新行
        { print } # 打印其他行
        END { if (!added) { print "\n[" section "]\n" new_line } } # 如果段落未找到(理论上不应发生)，在末尾添加
        ' "$temp_file_del" > "$temp_file_add"
    else
    # 如果 section 为空 (全局，如 sshd_config)，在文件末尾添加新行
        cat "$temp_file_del" > "$temp_file_add"
        echo "$new_line" >> "$temp_file_add"
    fi

     if [[ $? -ne 0 ]]; then
         echo -e "${RED}[✗] 使用 awk/cat 处理配置文件时出错 (添加 ${key})。${NC}"
         rm -f "$temp_file_del" "$temp_file_add" 2>/dev/null
         return 1
    fi

    # 3. 替换原文件
    mv "$temp_file_add" "$file"
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[✗] 替换配置文件 ${file} 失败。${NC}"
        rm -f "$temp_file_del" "$temp_file_add" 2>/dev/null # 出错时清理临时文件
        return 1
    fi

    rm -f "$temp_file_del" 2>/dev/null # 清理第一个临时文件
    return 0 # 成功
}

# 配置 Fail2ban (覆盖 jail.local)
configure_fail2ban() {
    echo -e "\n${CYAN}--- 配置 Fail2ban (SSH 防护) ---${NC}"

    local ssh_port maxretry bantime backend journalmatch

    # 获取用户输入
    read -p "请输入要监控的 SSH 端口 (当前: $CURRENT_SSH_PORT): " ssh_port_input
    ssh_port=${ssh_port_input:-$CURRENT_SSH_PORT} # 如果用户直接回车，使用当前端口

    read -p "请输入最大重试次数 [默认 5]: " maxretry_input
    maxretry=${maxretry_input:-5} # 默认 5 次

    read -p "请输入封禁时间 (例如 60m, 1h, 1d, -1 表示永久) [默认 10m]: " bantime_input
    bantime=${bantime_input:-"10m"} # 默认 10 分钟

    # 固定使用 systemd backend (适用于现代 systemd 系统)
    backend="systemd"
    # 使用推荐的 journalmatch 过滤 systemd 日志
    journalmatch="_SYSTEMD_UNIT=sshd.service + _COMM=sshd"

    # 验证输入
    if ! [[ "$ssh_port" =~ ^[0-9]+$ && "$ssh_port" -gt 0 && "$ssh_port" -le 65535 ]]; then
        echo -e "${RED}[✗] 无效的 SSH 端口。${NC}"; return 1
    fi
    if ! [[ "$maxretry" =~ ^[0-9]+$ && "$maxretry" -gt 0 ]]; then
        echo -e "${RED}[✗] 最大重试次数必须是正整数。${NC}"; return 1
    fi

    # 显示准备写入的配置
    echo -e "${BLUE}[*] 准备使用以下配置覆盖 ${FAIL2BAN_JAIL_LOCAL}:${NC}"
    echo "  [sshd]"
    echo "  enabled = true"
    echo "  port = $ssh_port"
    echo "  maxretry = $maxretry"
    echo "  bantime = $bantime"
    echo "  backend = $backend"
    echo "  journalmatch = $journalmatch"

    # 确认操作
    if confirm_action "确认使用此配置覆盖 jail.local 吗?"; then
        # 创建或覆盖 jail.local 文件
        # 使用 cat 和 EOF 来写入多行配置
        cat > "$FAIL2BAN_JAIL_LOCAL" <<EOF
# Configuration generated by script $(date)
# DO NOT EDIT OTHER SECTIONS MANUALLY IF USING THIS SCRIPT FOR [sshd]

[DEFAULT]
# Default ban time for other jails (if any)
bantime = 10m
# Use ufw for banning actions (确保 UFW 已安装并启用)
banaction = ufw
# Optionally, add other DEFAULT settings here if needed

[sshd]
enabled = true
port = $ssh_port
maxretry = $maxretry
bantime = $bantime
backend = $backend
journalmatch = $journalmatch

# Add other jails below this line if needed, but they won't be managed by this script's [sshd] config function.

EOF
        # 检查写入是否成功
        if [[ $? -eq 0 ]]; then
            chmod 644 "$FAIL2BAN_JAIL_LOCAL" # 设置合适的权限
            echo -e "${GREEN}[✓] Fail2ban 配置已写入 ${FAIL2BAN_JAIL_LOCAL}。${NC}"
            return 0 # 配置成功
        else
            echo -e "${RED}[✗] 写入 Fail2ban 配置文件失败。${NC}"
            return 1 # 配置失败
        fi
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

    # 显示 sshd jail 的状态
    echo -e "${BLUE}Fail2ban SSH jail 状态:${NC}"
    fail2ban-client status sshd

    # 显示最近的 Fail2ban 日志
    echo -e "\n${BLUE}查看 Fail2ban 日志 (最近 20 条):${NC}"
    # 优先使用 journalctl
    if command_exists journalctl; then
        journalctl -u fail2ban -n 20 --no-pager --quiet
    # 否则尝试读取默认日志文件
    elif [[ -f /var/log/fail2ban.log ]]; then
        tail -n 20 /var/log/fail2ban.log
    else
        echo -e "${YELLOW}无法找到 Fail2ban 日志。${NC}"
    fi
    return 0
}

manage_fail2ban() {
     while true; do
        echo -e "\n${CYAN}--- Fail2ban 入侵防御管理 ---${NC}"
        echo -e " ${YELLOW}1.${NC} 安装并配置 Fail2ban (交互式设置 SSH 防护)"
        echo -e " ${YELLOW}2.${NC} 重新配置 Fail2ban (覆盖 jail.local, 重启服务)"
        echo -e " ${YELLOW}3.${NC} 查看 Fail2ban 状态 (SSH jail, 日志)"
        echo -e " ${YELLOW}0.${NC} 返回主菜单"
        read -p "请输入选项 [0-3]: " f2b_choice

        case $f2b_choice in
            1) setup_fail2ban ;;
            2)
               # 重新配置并重启服务
               if configure_fail2ban; then # 如果配置成功
                   echo -e "${BLUE}[*] 重启 Fail2ban 服务以应用新配置...${NC}"
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

    # 获取新端口号并验证
    while true; do
        read -p "请输入新的 SSH 端口号 (建议 10000-65535): " new_port
        if [[ "$new_port" =~ ^[0-9]+$ && "$new_port" -gt 0 && "$new_port" -le 65535 ]]; then
            if [[ "$new_port" -eq "$old_port" ]]; then
                echo -e "${YELLOW}新端口与当前端口相同，无需更改。${NC}"
                return # 无需更改，直接返回
            fi
            break # 端口有效且不同，跳出循环
        else
            echo -e "${YELLOW}无效的端口号。请输入 1-65535 之间的数字。${NC}"
        fi
    done

    # 显示警告和操作步骤
    echo -e "${RED}[!] 警告：更改 SSH 端口需要确保新端口在防火墙中已开放！${NC}"
    echo "脚本将尝试执行以下操作："
    echo "  1. 在 UFW 中允许新端口 $new_port/tcp (如果 UFW 已启用)。"
    echo "  2. 修改 SSH 配置文件 ($SSHD_CONFIG)。"
    echo "  3. 重启 SSH 服务。"
    echo "  4. 在 UFW 中删除旧端口 $old_port/tcp 的规则 (如果存在)。"
    echo "  5. 重新配置 Fail2ban 以监控新端口 (如果 Fail2ban 已安装)。"
    echo -e "${YELLOW}在重启 SSH 服务后，您需要使用新端口重新连接！例如: ssh user@host -p $new_port ${NC}"

    # 确认操作
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
             return 1 # 失败则中止
        fi
         echo -e "${GREEN}[✓] UFW 已允许新端口 $new_port/tcp。${NC}"
    else
        echo -e "${YELLOW}[!] UFW 未安装或未启用，跳过防火墙规则添加。请手动确保端口可访问！${NC}"
    fi

    # 2. 修改 SSH 配置
    echo -e "${BLUE}[*] 修改 SSH 配置文件 ($SSHD_CONFIG)...${NC}"
    # 先备份
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak_port_$(date +%F_%T)"
    # 使用辅助函数修改 Port 指令 (全局，无 section)
    if update_or_add_config "$SSHD_CONFIG" "" "Port" "$new_port"; then
        echo -e "${GREEN}[✓] SSH 配置文件已修改。${NC}"
    else
        echo -e "${RED}[✗] 修改 SSH 配置文件失败。${NC}";
        # 考虑恢复备份
        # cp "${SSHD_CONFIG}.bak_port_*" "$SSHD_CONFIG" # 示例恢复
        return 1; # 失败则中止
    fi

    # 3. 重启 SSH 服务
    echo -e "${BLUE}[*] 重启 SSH 服务...${NC}"
    echo -e "${YELLOW}服务重启后，当前连接可能会断开。请使用新端口 $new_port 重新连接。${NC}"
    systemctl restart sshd
    sleep 3 # 等待服务启动
    # 检查服务状态
    if systemctl is-active --quiet sshd; then
        echo -e "${GREEN}[✓] SSH 服务已成功重启。${NC}"
        # 更新脚本内部记录的当前端口
        CURRENT_SSH_PORT=$new_port
    else
        echo -e "${RED}[✗] SSH 服务重启失败！请立即检查 SSH 配置 (${SSHD_CONFIG}) 和服务状态 ('systemctl status sshd')。${NC}"
        echo -e "${RED}   旧配置已备份为 ${SSHD_CONFIG}.bak_port_* 。${NC}"
        echo -e "${RED}   防火墙规则可能未完全更新。${NC}"
        return 1 # 重启失败则中止
    fi

    # 4. 更新 UFW (如果启用) - 删除旧端口规则
    if command_exists ufw && ufw status | grep -q "Status: active"; then
        echo -e "${BLUE}[*] 在 UFW 中删除旧端口 $old_port/tcp 的规则...${NC}"
        # ufw delete 不支持按备注删除，尝试直接删除端口/协议
        ufw delete allow $old_port/tcp > /dev/null 2>&1
        ufw delete allow $old_port > /dev/null 2>&1 # 尝试删除不带协议的规则
        echo -e "${GREEN}[✓] 尝试删除旧 UFW 规则完成 (如果存在)。${NC}"
    fi

    # 5. 更新 Fail2ban 配置 (如果安装)
    if command_exists fail2ban-client; then
        echo -e "${BLUE}[*] 重新配置 Fail2ban 以监控新端口 $new_port ...${NC}"
        # 调用配置函数，它会使用更新后的 CURRENT_SSH_PORT
        if configure_fail2ban; then # 先配置
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
    return 0
}

create_sudo_user() {
    echo -e "\n${CYAN}--- 4.2 创建新的 Sudo 用户 ---${NC}"
    local username

    # 获取用户名并验证
    while true; do
        read -p "请输入新用户名: " username
        if [[ -z "$username" ]]; then
            echo -e "${YELLOW}用户名不能为空。${NC}"
        elif id "$username" &>/dev/null; then # 检查用户是否已存在
            echo -e "${YELLOW}用户 '$username' 已存在。${NC}"
        elif [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then # 基本用户名格式校验
            break
        else
            echo -e "${YELLOW}无效的用户名格式 (建议使用小写字母、数字、下划线、连字符，并以字母或下划线开头)。${NC}"
        fi
    done

    # 添加用户并设置密码 (adduser 会交互式提示)
    echo -e "${BLUE}[*] 添加用户 '$username' 并设置密码...${NC}"
    adduser "$username"
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[✗] 添加用户失败。${NC}"
        return 1
    fi

    # 添加到 sudo 组 (Debian/Ubuntu 默认的 sudo 组名)
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
    return 0
}

disable_root_login() {
    echo -e "\n${CYAN}--- 4.3 禁用 Root 用户 SSH 登录 ---${NC}"
    echo -e "${RED}[!] 警告：禁用 Root 登录前，请确保您已创建具有 Sudo 权限的普通用户，并且该用户可以正常通过 SSH 登录！${NC}"

    # 再次确认操作
    if ! confirm_action "确认要禁止 Root 用户通过 SSH 登录吗?"; then
        echo "操作已取消。"
        return
    fi

    echo -e "${BLUE}[*] 修改 SSH 配置文件 ($SSHD_CONFIG) 以禁用 Root 登录...${NC}"
    # 备份
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak_root_$(date +%F_%T)"
    # 修改 PermitRootLogin 为 no
    if ! update_or_add_config "$SSHD_CONFIG" "" "PermitRootLogin" "no"; then
       echo -e "${RED}[✗] 修改 SSH 配置文件失败 (PermitRootLogin)。${NC}"; return 1;
    fi

    # 重启 SSH 服务
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
    return 0
}

# 添加公钥到指定用户的 authorized_keys 文件
add_public_key() {
    local target_user="$1" # 目标用户名
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

    # 获取用户家目录
    user_home=$(eval echo ~$target_user)
    if [[ ! -d "$user_home" ]]; then
        # 如果家目录不存在，尝试创建
        echo -e "${YELLOW}[!] 用户 '$target_user' 的家目录 ($user_home) 不存在。尝试创建...${NC}"
        mkdir -p "$user_home"
        chown "${target_user}:${target_user}" "$user_home" # 设置正确的所有权
        if [[ ! -d "$user_home" ]]; then
             echo -e "${RED}[✗] 创建家目录失败。${NC}"
             return 1
        fi
    fi

    ssh_dir="${user_home}/.ssh"
    auth_keys_file="${ssh_dir}/authorized_keys"

    # 获取用户粘贴的公钥
    echo -e "${BLUE}[*] 请【一次性】粘贴您的【单行公钥】内容 (例如 'ssh-ed25519 AAA... comment')，然后按 Enter 键:${NC}"
    read -r pub_key_input # 使用 read -r 读取完整一行

    if [[ -z "$pub_key_input" ]]; then
        echo -e "${YELLOW}未输入任何内容，操作取消。${NC}"
        return 1
    fi

    # 清理输入：去除首尾空白和可能粘贴进来的引号
    pub_key_cleaned=$(echo "$pub_key_input" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e "s/^'//" -e "s/'$//" -e 's/^"//' -e 's/"$//')

    # 校验公钥格式 (基本校验)
    local key_regex="^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp(256|384|521))\s+AAAA[0-9A-Za-z+/]+[=]{0,3}(\s+.*)?$"
    if ! [[ "$pub_key_cleaned" =~ $key_regex ]]; then
        echo -e "${RED}[✗] 输入的内容似乎不是有效的 SSH 公钥格式。操作取消。${NC}"
        echo -e "${YELLOW}   公钥通常以 'ssh-rsa', 'ssh-ed25519' 或 'ecdsa-...' 开头，后跟一长串 Base64 字符。${NC}"
        echo -e "${YELLOW}   清理后的输入为: '$pub_key_cleaned' ${NC}" # 显示清理后的内容帮助调试
        return 1
    fi

    # 显示准备添加的公钥并确认
    echo -e "${BLUE}[*] 准备将以下公钥添加到用户 '$target_user' 的 ${auth_keys_file} 文件中:${NC}"
    echo -e "${CYAN}${pub_key_cleaned}${NC}"
    if ! confirm_action "确认添加吗?"; then
        echo "操作已取消。"
        return 1
    fi

    # 创建 .ssh 目录和 authorized_keys 文件（如果不存在），并设置严格权限
    echo -e "${BLUE}[*] 确保目录和文件存在并设置权限...${NC}"
    mkdir -p "$ssh_dir"
    touch "$auth_keys_file"
    chmod 700 "$ssh_dir"      # 只有所有者可读写执行
    chmod 600 "$auth_keys_file" # 只有所有者可读写
    chown -R "${target_user}:${target_user}" "$ssh_dir" # 确保所有权正确

    # 检查公钥是否已存在 (精确匹配)
    if grep -qF "$pub_key_cleaned" "$auth_keys_file"; then
        echo -e "${YELLOW}[!] 此公钥似乎已存在于 ${auth_keys_file} 中，无需重复添加。${NC}"
        return 0 # 已存在也算成功
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

# 配置 SSH 密钥登录并禁用密码登录
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
            1) # 添加公钥
                local target_user
                read -p "请输入要为其添加公钥的用户名: " target_user
                if [[ -n "$target_user" ]]; then
                    add_public_key "$target_user"
                else
                    echo -e "${YELLOW}用户名不能为空。${NC}"
                fi
                read -p "按 Enter键 继续..."
                ;;
            2) # 禁用密码登录
                echo -e "${RED}[!] 警告：这是高风险操作！在禁用密码登录前，请务必完成以下步骤：${NC}"
                echo -e "${YELLOW}  1. 在您的本地计算机上生成 SSH 密钥对 (例如使用 'ssh-keygen')。${NC}"
                echo -e "${YELLOW}  2. 使用上面的【选项1】或其他方法，将您的【公钥】复制到服务器上目标用户的 ~/.ssh/authorized_keys 文件中。${NC}"
                echo -e "${YELLOW}  3. 【重要】在禁用密码登录【之前】，打开一个新的终端窗口，尝试使用【密钥】登录服务器，确保可以成功登录！${NC}"

                # 强制用户确认已完成准备工作
                if ! confirm_action "您是否已经完成上述所有步骤，并确认可以通过密钥成功登录?"; then
                    echo "操作已取消。请先确保密钥设置正确并可成功登录。"
                    continue # 返回循环，让用户重新选择
                fi

                echo -e "${BLUE}[*] 修改 SSH 配置文件 ($SSHD_CONFIG) 以启用密钥登录并禁用密码登录...${NC}"
                # 备份
                cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak_key_$(date +%F_%T)"

                # 确保 PubkeyAuthentication 为 yes (通常默认是)
                if ! update_or_add_config "$SSHD_CONFIG" "" "PubkeyAuthentication" "yes"; then echo -e "${RED}[✗] 修改 SSH 配置文件失败 (PubkeyAuthentication)。${NC}"; continue; fi

                # 禁用 PasswordAuthentication
                if ! update_or_add_config "$SSHD_CONFIG" "" "PasswordAuthentication" "no"; then echo -e "${RED}[✗] 修改 SSH 配置文件失败 (PasswordAuthentication)。${NC}"; continue; fi

                # 禁用 ChallengeResponseAuthentication (也与密码/键盘交互相关)
                if ! update_or_add_config "$SSHD_CONFIG" "" "ChallengeResponseAuthentication" "no"; then echo -e "${RED}[✗] 修改 SSH 配置文件失败 (ChallengeResponseAuthentication)。${NC}"; continue; fi

                # 可选：禁用 UsePAM (如果仅用密钥，通常可以禁用，但需谨慎测试，可能影响其他认证方式)
                # update_or_add_config "$SSHD_CONFIG" "" "UsePAM" "no"
                echo -e "${YELLOW}[!] UsePAM 设置未修改，保持默认。${NC}"

                # 重启 SSH 服务
                echo -e "${BLUE}[*] 重启 SSH 服务以应用更改...${NC}"
                systemctl restart sshd
                sleep 2
                if systemctl is-active --quiet sshd; then
                    echo -e "${GREEN}[✓] SSH 已配置为仅允许密钥登录，密码登录已禁用。${NC}"
                    echo -e "${RED}请立即尝试使用密钥重新登录以确认！如果无法登录，您可能需要通过控制台或其他方式恢复备份配置 (${SSHD_CONFIG}.bak_key_*)。${NC}"
                else
                    echo -e "${RED}[✗] SSH 服务重启失败！请检查配置。密码登录可能仍然启用。${NC}"
                    echo -e "${RED}   旧配置已备份为 ${SSHD_CONFIG}.bak_key_* 。${NC}"
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
        check_root # 每次操作后重新检查 SSH 端口，以防万一
    done
}


# --- 5. Web 服务 (Let's Encrypt + Cloudflare + Nginx) ---

# 处理 Certbot 安装/更新 (优先 Snap)
install_or_update_certbot_snap() {
    echo -e "${BLUE}[*] 检查 Certbot 安装情况并优先使用 Snap 版本...${NC}"
    local certbot_path certbot_installer="" cf_plugin_snap_name="certbot-dns-cloudflare"

    # 检查 certbot 命令是否存在及其路径
    if command_exists certbot; then
        certbot_path=$(command -v certbot)
        if [[ "$certbot_path" == /snap/* ]]; then # 判断是否为 Snap 安装
            echo -e "${GREEN}[✓] 检测到 Certbot (Snap) 已安装在 $certbot_path。${NC}"
            certbot_installer="snap"
        elif [[ "$certbot_path" == /usr/bin/* || "$certbot_path" == /usr/local/bin/* ]]; then # 判断是否为 apt 或其他方式安装
             echo -e "${YELLOW}[!] 检测到 Certbot (非 Snap) 已安装在 $certbot_path。此版本可能在旧系统上不兼容 Cloudflare API Token。${NC}"
             certbot_installer="apt/other"
        else
             echo -e "${YELLOW}[!] 检测到 Certbot 在未知路径 $certbot_path。${NC}"
             certbot_installer="unknown"
        fi
    else
        echo -e "${YELLOW}[!] 未检测到 Certbot。${NC}"
        certbot_installer="none"
    fi

    # 如果存在非 Snap 版本，询问用户是否替换
    if [[ "$certbot_installer" == "apt/other" ]]; then
        if command_exists snap; then # 检查 snap 命令是否存在
            if confirm_action "是否尝试移除当前 Certbot 并安装推荐的 Snap 版本以提高兼容性？"; then
                echo -e "${BLUE}[*] 正在尝试移除 apt 版本的 Certbot 及 Cloudflare 插件...${NC}"
                apt remove -y certbot python3-certbot-* # 移除 certbot 及相关插件
                apt autoremove -y > /dev/null 2>&1 # 清理不再需要的依赖
                echo -e "${BLUE}[*] 开始安装 Certbot (Snap)...${NC}"
                # 通过 Snap 安装 Certbot 核心
                if snap install --classic certbot; then
                    # 创建软链接，确保脚本能通过 /usr/bin/certbot 找到命令
                    ln -sf /snap/bin/certbot /usr/bin/certbot
                    # 允许插件以 root 身份运行
                    snap set certbot trust-plugin-with-root=ok
                    echo -e "${GREEN}[✓] Certbot (Snap) 安装成功。${NC}"
                    certbot_installer="snap" # 标记为 Snap 安装
                else
                    echo -e "${RED}[✗] Certbot (Snap) 安装失败。请检查 snap 错误。脚本将继续，但证书申请可能失败。${NC}"
                    certbot_installer="failed" # 标记为安装失败
                fi
            else
                 echo -e "${YELLOW}用户选择不替换为 Snap 版本。将继续使用当前版本，但 Cloudflare 认证可能失败。${NC}"
            fi
        else
             echo -e "${YELLOW}[!] Snap 命令不可用，无法自动替换为 Snap 版本。将继续使用当前版本。${NC}"
        fi
    fi

    # 如果没有安装 Certbot，尝试使用 Snap 安装
    if [[ "$certbot_installer" == "none" ]]; then
        if command_exists snap; then
             echo -e "${BLUE}[*] 尝试使用 Snap 安装 Certbot...${NC}"
             if snap install --classic certbot; then
                 ln -sf /snap/bin/certbot /usr/bin/certbot
                 snap set certbot trust-plugin-with-root=ok
                 echo -e "${GREEN}[✓] Certbot (Snap) 安装成功。${NC}"
                 certbot_installer="snap"
             else
                 echo -e "${RED}[✗] Certbot (Snap) 安装失败。${NC}"
                 # 回退到 apt 安装
                 echo -e "${YELLOW}[!] Snap 安装失败，尝试使用 apt 安装 Certbot...${NC}"
                 if install_package "certbot"; then certbot_installer="apt/other"; fi
             fi
        else
             # Snap 不可用，尝试 apt 安装
             echo -e "${YELLOW}[!] Snap 命令不可用，尝试使用 apt 安装 Certbot...${NC}"
             if install_package "certbot"; then certbot_installer="apt/other"; fi
        fi
    fi

    # 确保 Cloudflare 插件已安装 (根据 Certbot 的安装方式)
    if [[ "$certbot_installer" == "snap" ]]; then
        echo -e "${BLUE}[*] 检查/安装 Certbot Cloudflare 插件 (Snap)...${NC}"
        # 检查 Snap 插件是否已安装
        if ! snap list | grep -q "$cf_plugin_snap_name"; then
           if snap install "$cf_plugin_snap_name"; then
               echo -e "${GREEN}[✓] Cloudflare 插件 (Snap) 安装成功。${NC}"
           else
               echo -e "${RED}[✗] Cloudflare 插件 (Snap) 安装失败！证书申请将失败。${NC}"
               return 1 # 插件安装失败则中止
           fi
        else
           echo -e "${GREEN}[✓] Cloudflare 插件 (Snap) 已安装。${NC}"
        fi
        # 尝试连接插件 (有时需要)
        echo -e "${BLUE}[*] 尝试连接 Certbot 插件...${NC}"
        snap connect certbot:plugin certbot-dns-cloudflare &>/dev/null || echo -e "${YELLOW}[!] 无法自动连接插件，可能需要手动执行: sudo snap connect certbot:plugin certbot-dns-cloudflare ${NC}"
        snap connect certbot-dns-cloudflare:snapd-access certbot:snapd-access &>/dev/null || true # 尝试连接，忽略错误

    elif [[ "$certbot_installer" == "apt/other" ]]; then
         # 如果是 apt 安装的 Certbot，安装对应的 apt 插件
         echo -e "${BLUE}[*] 检查/安装 Certbot Cloudflare 插件 (apt)...${NC}"
         install_package "python3-certbot-dns-cloudflare" || { echo -e "${RED}[✗] Cloudflare 插件 (apt) 安装失败！证书申请将失败。${NC}"; return 1; }
    elif [[ "$certbot_installer" == "failed" || "$certbot_installer" == "none" || "$certbot_installer" == "unknown" ]]; then
         # Certbot 未成功安装
         echo -e "${RED}[✗] Certbot 未能成功安装或识别。无法继续 Web 服务配置。${NC}"
         return 1
    fi

    # 最后再次检查 Certbot 命令是否真的可用
    if ! command_exists certbot; then
        echo -e "${RED}[✗] Certbot 命令最终仍未找到！请手动安装 Certbot 及其 Cloudflare 插件。${NC}"
        return 1
    fi
    echo -e "${GREEN}[✓] Certbot 环境检查完成。${NC}"
    return 0 # Certbot 环境设置成功
}


# 获取 Web 服务配置的初始用户输入
get_user_input_initial() {
    # 重置相关全局变量
    DOMAIN="" CF_API_TOKEN="" DDNS_FREQUENCY=5 RECORD_TYPE="" SELECTED_IP="" ZONE_ID="" ZONE_NAME="" LOCAL_PROXY_PASS="" BACKEND_PROTOCOL="http" NGINX_HTTP_PORT=80 NGINX_HTTPS_PORT=443

    echo -e "${BLUE}[*] 请输入首次设置所需信息:${NC}"
    echo -e "${YELLOW}Let's Encrypt 注册邮箱已固定为: ${EMAIL}${NC}" # 提示固定邮箱
    while [[ -z "$DOMAIN" ]]; do read -p "请输入您要申请/管理的域名 (例如 my.example.com): " DOMAIN; done
    # 简单校验域名格式
    if ! [[ "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}[✗] 域名格式似乎不正确。${NC}"; return 1;
    fi
    # 检查此域名的配置是否已存在
    if [[ -f "${CONFIG_DIR}/${DOMAIN}.conf" ]]; then
        echo -e "${YELLOW}[!] 域名 ${DOMAIN} 的配置已存在。如果您想修改，请先删除旧配置 (选项 5-3)。${NC}"
        return 1
    fi
    # 获取 Cloudflare API Token
    while [[ -z "$CF_API_TOKEN" ]]; do read -p "请输入您的 Cloudflare API Token (确保有 Zone:Read, DNS:Edit 权限): " CF_API_TOKEN; done
    # 获取 DDNS 更新频率
    while true; do
        read -p "请输入 DDNS 自动更新频率 (分钟, 输入 0 禁用 DDNS, 默认 5): " freq_input
        if [[ -z "$freq_input" ]]; then DDNS_FREQUENCY=5; echo -e "DDNS 更新频率设置为: ${GREEN}5 分钟${NC}"; break;
        elif [[ "$freq_input" =~ ^[0-9]+$ ]]; then
            DDNS_FREQUENCY=$freq_input
            if [[ "$DDNS_FREQUENCY" -eq 0 ]]; then echo -e "${YELLOW}DDNS 功能已禁用。${NC}"; else echo -e "DDNS 更新频率设置为: ${GREEN}${DDNS_FREQUENCY} 分钟${NC}"; fi; break;
        else echo -e "${YELLOW}请输入一个非负整数。${NC}"; fi
    done
    # 根据域名更新相关路径变量
    update_paths_for_domain "$DOMAIN"
    return 0 # 输入成功
}

# 根据当前域名更新相关文件路径变量
update_paths_for_domain() {
    local current_domain="$1"
    CERT_PATH="${CERT_PATH_PREFIX}/${current_domain}"
    CLOUDFLARE_CREDENTIALS="/root/.cloudflare-${current_domain}.ini"
    DEPLOY_HOOK_SCRIPT="/root/cert-renew-hook-${current_domain}.sh"
    DDNS_SCRIPT_PATH="/usr/local/bin/cf_ddns_update_${current_domain}.sh"
    NGINX_CONF_PATH="/etc/nginx/sites-available/${current_domain}.conf"
}

# 创建 Cloudflare API Token 凭证文件 (用于 Certbot)
create_cf_credentials() {
    echo -e "${BLUE}[*] 创建 Cloudflare API Token 凭证文件...${NC}"
    mkdir -p "$(dirname "$CLOUDFLARE_CREDENTIALS")" # 确保目录存在
    # 写入 Token (这是 Certbot Cloudflare 插件推荐的方式)
    cat > "$CLOUDFLARE_CREDENTIALS" <<EOF
# Cloudflare API credentials used by Certbot for domain: ${DOMAIN}
# Generated by script: $(date)
# Using API Token authentication method
dns_cloudflare_api_token = $CF_API_TOKEN
EOF
    # 设置严格的文件权限，只有 root 可读写
    chmod 600 "$CLOUDFLARE_CREDENTIALS"
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}[✓] 凭证文件创建成功: ${CLOUDFLARE_CREDENTIALS}${NC}"
        return 0
    else
        echo -e "${RED}[✗] 创建凭证文件失败 (权限设置?)。${NC}"
        return 1
    fi
}

# 检测公网 IP 地址 (IPv4 和 IPv6)
detect_public_ip() {
    echo -e "${BLUE}[*] 检测公网 IP 地址...${NC}"
    # 尝试从多个源获取 IPv4，设置超时
    DETECTED_IPV4=$(curl -4s --max-time 5 https://api.ipify.org || curl -4s --max-time 5 https://ifconfig.me/ip || curl -4s --max-time 5 https://ipv4.icanhazip.com || echo "")
    # 尝试从多个源获取 IPv6，设置超时
    DETECTED_IPV6=$(curl -6s --max-time 5 https://api64.ipify.org || curl -6s --max-time 5 https://ifconfig.me/ip || curl -6s --max-time 5 https://ipv6.icanhazip.com || echo "")
    echo "检测结果:"
    if [[ -n "$DETECTED_IPV4" ]]; then echo -e "  - IPv4: ${GREEN}$DETECTED_IPV4${NC}"; else echo -e "  - IPv4: ${RED}未检测到${NC}"; fi
    if [[ -n "$DETECTED_IPV6" ]]; then echo -e "  - IPv6: ${GREEN}$DETECTED_IPV6${NC}"; else echo -e "  - IPv6: ${RED}未检测到${NC}"; fi
    # 如果两者都未检测到，则报错
    if [[ -z "$DETECTED_IPV4" && -z "$DETECTED_IPV6" ]]; then
        echo -e "${RED}[✗] 无法检测到任何公网 IP 地址。请检查网络连接。脚本无法继续。${NC}";
        return 1;
    fi
    return 0
}

# 让用户选择使用哪个 IP 地址和记录类型 (A 或 AAAA)
select_record_type() {
    echo -e "${BLUE}[*] 请选择要使用的 DNS 记录类型和 IP 地址:${NC}"
    options=() ips=() types=() # 初始化选项数组
    # 如果检测到 IPv4，添加到选项
    if [[ -n "$DETECTED_IPV4" ]]; then options+=("IPv4 (A 记录) - ${DETECTED_IPV4}"); ips+=("$DETECTED_IPV4"); types+=("A"); fi
    # 如果检测到 IPv6，添加到选项
    if [[ -n "$DETECTED_IPV6" ]]; then options+=("IPv6 (AAAA 记录) - ${DETECTED_IPV6}"); ips+=("$DETECTED_IPV6"); types+=("AAAA"); fi
    options+=("退出") # 添加退出选项

    # 使用 select 命令显示菜单让用户选择
    select opt in "${options[@]}"; do
        choice_index=$((REPLY - 1)) # REPLY 是 select 命令内置变量，表示用户输入的序号
        if [[ "$opt" == "退出" ]]; then echo "用户选择退出。"; return 1; # 选择退出则返回错误
        # 检查选择是否在有效 IP 选项范围内
        elif [[ $choice_index -ge 0 && $choice_index -lt ${#ips[@]} ]]; then
            RECORD_TYPE=${types[$choice_index]}; SELECTED_IP=${ips[$choice_index]}
            echo -e "已选择: ${GREEN}${RECORD_TYPE} - $SELECTED_IP${NC}"; break # 选择成功，跳出循环
        else echo "无效选项 $REPLY"; fi # 无效输入，循环继续
    done
    # 如果循环结束仍未选择有效 IP (理论上不应发生，除非 select 出错)
    if [[ -z "$RECORD_TYPE" || -z "$SELECTED_IP" ]]; then echo -e "${RED}[✗] 未选择有效的记录类型或 IP 地址。脚本无法继续。${NC}"; return 1; fi
    return 0 # 选择成功
}

# 获取 Cloudflare Zone ID
get_zone_id() {
    echo -e "${BLUE}[*] 获取 Cloudflare Zone ID...${NC}"
    # 从完整域名中提取可能的 Zone Name (通常是最后两部分)
    ZONE_NAME=$(echo "$DOMAIN" | awk -F. '{if (NF>2) print $(NF-1)"."$NF; else print $0}')
    echo "尝试获取 Zone Name: $ZONE_NAME"

    # 调用 Cloudflare API 获取 Zone 信息 (使用 Bearer Token)
    ZONE_ID_JSON=$(curl -s --max-time 10 -X GET "$CF_API/zones?name=$ZONE_NAME&status=active" \
         -H "Authorization: Bearer $CF_API_TOKEN" \
         -H "Content-Type: application/json")

    # 检查 curl 命令是否成功
    if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API 失败 (网络错误或超时)。${NC}"; return 1; fi

    # 使用 jq 解析 JSON，检查 API 调用是否成功 (success 字段是否为 true)
    # jq -e 选项在找到匹配项时返回 0，否则返回非 0，适合脚本判断
    if ! echo "$ZONE_ID_JSON" | jq -e '.success == true' > /dev/null; then
        local error_msg=$(echo "$ZONE_ID_JSON" | jq -r '.errors[0].message // "未知 API 错误"')
        echo -e "${RED}[✗] Cloudflare API 返回错误: ${error_msg}${NC}"; return 1;
    fi

    # 提取 Zone ID
    ZONE_ID=$(echo "$ZONE_ID_JSON" | jq -r '.result[0].id')

    # 检查是否成功获取 Zone ID
    if [[ "$ZONE_ID" == "null" || -z "$ZONE_ID" ]]; then
        echo -e "${RED}[✗] 无法找到域名 $ZONE_NAME 对应的活动 Zone ID。请检查域名和 API Token 是否正确且有 Zone:Read 权限。${NC}"; return 1;
    fi
    echo -e "${GREEN}[✓] 找到 Zone ID: $ZONE_ID${NC}"
    return 0 # 获取成功
}

# 管理 Cloudflare DNS 记录 (创建或更新)
manage_cloudflare_record() {
    local action="$1" # 操作描述 (例如 "设置")
    echo -e "${BLUE}[*] ${action} Cloudflare DNS 记录 ($RECORD_TYPE)...${NC}"
    echo "正在检查 $DOMAIN 的 $RECORD_TYPE 记录..."

    # 调用 API 获取指定域名和类型的 DNS 记录信息
    RECORD_INFO=$(curl -s --max-time 10 -X GET "$CF_API/zones/$ZONE_ID/dns_records?type=$RECORD_TYPE&name=$DOMAIN" \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json")

    if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (获取记录) 失败。${NC}"; return 1; fi
    if ! echo "$RECORD_INFO" | jq -e '.success == true' > /dev/null; then
        echo -e "${RED}[✗] Cloudflare API 返回错误 (获取记录): $(echo "$RECORD_INFO" | jq -r '.errors[0].message // "未知 API 错误"')${NC}"; return 1;
    fi

    # 提取记录 ID 和当前 Cloudflare 上的 IP
    RECORD_ID=$(echo "$RECORD_INFO" | jq -r '.result[0].id');
    CURRENT_IP=$(echo "$RECORD_INFO" | jq -r '.result[0].content')

    # 如果记录 ID 为空或 null，表示记录不存在，需要创建
    if [[ "$RECORD_ID" == "null" || -z "$RECORD_ID" ]]; then
        echo "未找到 $RECORD_TYPE 记录，正在创建..."
        # 调用 API 创建新记录 (TTL=120秒, proxied=false 即 DNS Only)
        CREATE_RESULT=$(curl -s --max-time 10 -X POST "$CF_API/zones/$ZONE_ID/dns_records" \
            -H "Authorization: Bearer $CF_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"$RECORD_TYPE\",\"name\":\"$DOMAIN\",\"content\":\"$SELECTED_IP\",\"ttl\":120,\"proxied\":false}")

        if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (创建记录) 失败。${NC}"; return 1; fi
        if echo "$CREATE_RESULT" | jq -e '.success == true' > /dev/null; then
            echo -e "${GREEN}[✓] $RECORD_TYPE 记录创建成功: $DOMAIN -> $SELECTED_IP${NC}";
        else
            echo -e "${RED}[✗] 创建 $RECORD_TYPE 记录失败: $(echo "$CREATE_RESULT" | jq -r '.errors[0].message // "未知 API 错误"')${NC}"; return 1;
        fi
    else
        # 记录已存在
        echo "找到 $RECORD_TYPE 记录 (ID: $RECORD_ID)，当前 Cloudflare 记录 IP: $CURRENT_IP"
        # 检查 Cloudflare 上的 IP 是否与当前选择的 IP 一致
        if [[ "$CURRENT_IP" != "$SELECTED_IP" ]]; then
            echo "IP 地址不匹配 ($CURRENT_IP != $SELECTED_IP)，正在更新..."
            # 调用 API 更新记录
            UPDATE_RESULT=$(curl -s --max-time 10 -X PUT "$CF_API/zones/$ZONE_ID/dns_records/$RECORD_ID" \
                -H "Authorization: Bearer $CF_API_TOKEN" \
                -H "Content-Type: application/json" \
                --data "{\"type\":\"$RECORD_TYPE\",\"name\":\"$DOMAIN\",\"content\":\"$SELECTED_IP\",\"ttl\":120,\"proxied\":false}")

            if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (更新记录) 失败。${NC}"; return 1; fi
            if echo "$UPDATE_RESULT" | jq -e '.success == true' > /dev/null; then
                echo -e "${GREEN}[✓] $RECORD_TYPE 记录更新成功: $DOMAIN -> $SELECTED_IP${NC}";
            else
                echo -e "${RED}[✗] 更新 $RECORD_TYPE 记录失败: $(echo "$UPDATE_RESULT" | jq -r '.errors[0].message // "未知 API 错误"')${NC}"; return 1;
            fi
        else
            # IP 地址一致，无需更新
            echo -e "${GREEN}[✓] $RECORD_TYPE 记录已是最新 ($CURRENT_IP)，无需更新。${NC}";
        fi
    fi
    return 0 # DNS 记录设置/检查成功
}

# 申请 Let's Encrypt 证书
request_certificate() {
    echo -e "${BLUE}[*] 申请 SSL 证书 (Let's Encrypt)...${NC}"
    # 使用 certbot 和 Cloudflare DNS 插件申请证书
    # --dns-cloudflare-propagation-seconds: 等待 DNS 记录生效的时间 (秒)
    local certbot_cmd=$(command -v certbot) # 获取 certbot 完整路径
    "$certbot_cmd" certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$CLOUDFLARE_CREDENTIALS" \
        --dns-cloudflare-propagation-seconds 60 \
        -d "$DOMAIN" \
        --email "$EMAIL" \
        --agree-tos \
        --no-eff-email \
        --non-interactive \
        --logs-dir /var/log/letsencrypt # 明确日志目录

    # 检查 Certbot 命令退出状态
    local cert_status=$?
    if [[ $cert_status -ne 0 ]]; then
         echo -e "${RED}[✗] Certbot 命令执行失败 (退出码: $cert_status)。${NC}"
         echo -e "${RED}   请检查 certbot 日志 (/var/log/letsencrypt/letsencrypt.log) 获取详细信息。${NC}"
         # 显示最近的日志帮助调试
         if [[ -f /var/log/letsencrypt/letsencrypt.log ]]; then
             echo -e "${YELLOW}--- 最近的 Certbot 日志 ---${NC}"
             tail -n 15 /var/log/letsencrypt/letsencrypt.log
             echo -e "${YELLOW}--------------------------${NC}"
         fi
         return 1 # 返回失败
    fi

    # 检查证书文件是否生成成功
    if [[ ! -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" || ! -f "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" ]]; then
        echo -e "${RED}[✗] 证书文件在预期路径 (/etc/letsencrypt/live/${DOMAIN}/) 未找到，即使 Certbot 命令成功。${NC}";
        echo -e "${RED}   请再次检查 Certbot 日志。${NC}"
        return 1;
    fi
    echo -e "${GREEN}[✓] SSL 证书申请成功！${NC}"
    return 0 # 证书申请成功
}

# 复制证书文件到指定目录
copy_certificate() {
    echo -e "${BLUE}[*] 复制证书文件到 $CERT_PATH ...${NC}"
    mkdir -p "$CERT_PATH" # 确保目标目录存在
    # 使用 -L 复制符号链接指向的实际文件
    if cp -L "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$CERT_PATH/" && \
       cp -L "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$CERT_PATH/" && \
       cp -L "/etc/letsencrypt/live/${DOMAIN}/chain.pem" "$CERT_PATH/" && \
       cp -L "/etc/letsencrypt/live/${DOMAIN}/cert.pem" "$CERT_PATH/"; then
        # 可选：设置权限，确保 Nginx 等服务可以读取
        # chmod 644 ${CERT_PATH}/*.pem
        # chown www-data:www-data ${CERT_PATH}/*.pem # 如果 Nginx 以 www-data 运行
        echo -e "${GREEN}[✓] 证书文件已复制到 $CERT_PATH ${NC}"
        return 0 # 复制成功
    else
        echo -e "${RED}[✗] 复制证书文件失败。请检查源文件是否存在以及目标路径权限。${NC}"
        return 1 # 复制失败
    fi
}

# 配置 Nginx 反向代理
setup_nginx_proxy() {
    # 询问用户是否需要配置 Nginx
    if ! confirm_action "是否需要自动配置 Nginx 反向代理?"; then
        echo "跳过 Nginx 配置。"
        # 即使不配置，也设置默认值以便保存
        NGINX_HTTP_PORT=80
        NGINX_HTTPS_PORT=443
        LOCAL_PROXY_PASS="none" # 标记未配置
        BACKEND_PROTOCOL="none"
        return 0 # 跳过不算错误
    fi

    # Nginx 安装应已在 add_new_domain 中完成
    # 获取 Nginx 监听端口
    while true; do
        read -p "请输入 Nginx 监听的 HTTP 端口 [默认: ${NGINX_HTTP_PORT}]: " http_port_input
        if [[ -z "$http_port_input" ]]; then break; # 使用默认值
        elif [[ "$http_port_input" =~ ^[0-9]+$ && "$http_port_input" -gt 0 && "$http_port_input" -le 65535 ]]; then
            NGINX_HTTP_PORT=$http_port_input; break;
        else echo -e "${YELLOW}无效端口号。请输入 1-65535 之间的数字，或直接回车使用默认值。${NC}"; fi
    done
    echo -e "Nginx HTTP 端口设置为: ${GREEN}${NGINX_HTTP_PORT}${NC}"

    while true; do
         read -p "请输入 Nginx 监听的 HTTPS 端口 [默认: ${NGINX_HTTPS_PORT}]: " https_port_input
         if [[ -z "$https_port_input" ]]; then break; # 使用默认值
         elif [[ "$https_port_input" =~ ^[0-9]+$ && "$https_port_input" -gt 0 && "$https_port_input" -le 65535 ]]; then
             if [[ "$https_port_input" -eq "$NGINX_HTTP_PORT" ]]; then # 检查端口冲突
                 echo -e "${YELLOW}HTTPS 端口不能与 HTTP 端口 (${NGINX_HTTP_PORT}) 相同。${NC}"
             else NGINX_HTTPS_PORT=$https_port_input; break; fi
         else echo -e "${YELLOW}无效端口号。请输入 1-65535 之间的数字，或直接回车使用默认值。${NC}"; fi
    done
    echo -e "Nginx HTTPS 端口设置为: ${GREEN}${NGINX_HTTPS_PORT}${NC}"

    # 选择后端协议
    while true; do
        read -p "请选择后端服务 (${DOMAIN}) 使用的协议: [1] http (默认) [2] https : " proto_choice
        if [[ -z "$proto_choice" || "$proto_choice" == "1" ]]; then BACKEND_PROTOCOL="http"; break;
        elif [[ "$proto_choice" == "2" ]]; then BACKEND_PROTOCOL="https"; break;
        else echo -e "${YELLOW}无效输入，请输入 1 或 2。${NC}"; fi
    done
    echo -e "后端服务协议设置为: ${GREEN}${BACKEND_PROTOCOL}${NC}"

    # 获取后端服务地址和端口
    local addr_input="" # 声明为局部变量
    while [[ -z "$LOCAL_PROXY_PASS" ]]; do
        read -p "请输入 Nginx 需要反向代理的本地服务地址 (只需 IP/域名 和 端口, 例如 localhost:8080 或 192.168.1.10:3000): " addr_input
        # 校验格式：支持 hostname:port, IPv4:port, [IPv6]:port
        if [[ "$addr_input" =~ ^(\[([0-9a-fA-F:]+)\]|([a-zA-Z0-9.-]+)):([0-9]+)$ ]]; then
            # 根据选择的后端协议构建完整的 proxy_pass 目标
            LOCAL_PROXY_PASS="${BACKEND_PROTOCOL}://${addr_input}"
            echo -e "将使用代理地址: ${GREEN}${LOCAL_PROXY_PASS}${NC}"
        else echo -e "${YELLOW}地址格式似乎不正确，请确保是 '地址:端口' 或 '[IPv6地址]:端口' 格式。${NC}"; LOCAL_PROXY_PASS=""; fi # 格式错误则清空，循环继续
    done

    # 生成 Nginx 配置文件
    echo -e "${BLUE}[*] 生成 Nginx 配置文件: $NGINX_CONF_PATH ...${NC}"
    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled # 确保目录存在
    mkdir -p /var/www/html/.well-known/acme-challenge # 确保 Certbot http-01 验证目录存在 (虽然 DNS 验证不需要)
    # 尝试设置权限，忽略错误
    chown www-data:www-data /var/www/html -R 2>/dev/null || echo -e "${YELLOW}[!] 无法设置 /var/www/html 权限 (可能 www-data 用户/组不存在)。${NC}"

    # 预处理 HTTPS 跳转的端口后缀 (如果不是标准 443)
    local redirect_suffix_bash=""
    if [[ "${NGINX_HTTPS_PORT}" -ne 443 ]]; then
        redirect_suffix_bash=":${NGINX_HTTPS_PORT}"
    fi

    # Nginx 配置模板
    cat > "$NGINX_CONF_PATH" <<EOF
server {
    # HTTP listener
    listen ${NGINX_HTTP_PORT};
    listen [::]:${NGINX_HTTP_PORT};
    server_name ${DOMAIN};

    # ACME challenge location (for potential future http-01 renewal)
    location ~ /.well-known/acme-challenge/ {
        allow all;
        root /var/www/html;
    }

    # Redirect all other HTTP requests to HTTPS
    location / {
        return 301 https://\$host${redirect_suffix_bash}\$request_uri;
    }
}

server {
    # HTTPS listener
    listen ${NGINX_HTTPS_PORT} ssl http2;
    listen [::]:${NGINX_HTTPS_PORT} ssl http2;
    server_name ${DOMAIN};

    # SSL certificate paths (using copied certs)
    ssl_certificate ${CERT_PATH}/fullchain.pem;
    ssl_certificate_key ${CERT_PATH}/privkey.pem;

    # SSL security settings (Mozilla Intermediate)
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Security Headers
    add_header Strict-Transport-Security "max-age=15768000" always; # ~6 months HSTS
    # add_header X-Frame-Options "SAMEORIGIN" always;
    # add_header X-Content-Type-Options "nosniff" always;
    # add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    # add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';" always; # Requires careful tuning
    # add_header Permissions-Policy "interest-cohort=()" always;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate ${CERT_PATH}/chain.pem;
    resolver 1.1.1.1 8.8.8.8 valid=300s; # Use public DNS resolvers
    resolver_timeout 5s;

    # Reverse Proxy configuration
    location / {
        proxy_pass ${LOCAL_PROXY_PASS}; # Target backend service

        # Pass client information to backend
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;

        # Settings for HTTPS backend
        $( [[ "$BACKEND_PROTOCOL" == "https" ]] && echo '        proxy_ssl_server_name on;' )
        # $( [[ "$BACKEND_PROTOCOL" == "https" ]] && echo '        # proxy_ssl_verify off;' ) # Uncomment if backend uses self-signed cert (INSECURE)

        # WebSocket support (uncomment if needed)
        # proxy_http_version 1.1;
        # proxy_set_header Upgrade \$http_upgrade;
        # proxy_set_header Connection "upgrade";

        # Optional timeouts
        # proxy_connect_timeout 60s;
        # proxy_send_timeout 60s;
        # proxy_read_timeout 60s;
    }
}
EOF

    # 创建软链接启用配置
    local enabled_link="/etc/nginx/sites-enabled/${DOMAIN}.conf"
    if [[ -L "$enabled_link" ]]; then
        echo -e "${YELLOW}[!] Nginx 配置软链接已存在，将重新创建。${NC}";
        rm -f "$enabled_link" # 删除旧链接
    fi
    ln -s "$NGINX_CONF_PATH" "$enabled_link"
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}[✓] Nginx 配置已启用 (创建软链接)。${NC}"
    else
         echo -e "${RED}[✗] 创建 Nginx 配置软链接失败。${NC}"
         return 1 # 链接失败则返回错误
    fi

    echo -e "${GREEN}[✓] Nginx 配置文件已生成并启用: ${NGINX_CONF_PATH}${NC}"
    echo -e "${YELLOW}[!] Nginx 配置将在证书申请成功后进行测试和重载。${NC}"
    return 0 # Nginx 配置生成成功
}

# 创建 DDNS 更新脚本
create_ddns_script() {
    # 如果 DDNS 频率为 0 或负数，则跳过
    if [[ "$DDNS_FREQUENCY" -le 0 ]]; then
        echo "${YELLOW}DDNS 已禁用，跳过创建 DDNS 更新脚本。${NC}";
        # 删除可能存在的旧脚本
        if [[ -f "$DDNS_SCRIPT_PATH" ]]; then
            echo "${YELLOW}检测到旧的 DDNS 脚本 $DDNS_SCRIPT_PATH，正在删除...${NC}"
            rm -f "$DDNS_SCRIPT_PATH"
        fi
        return 0;
    fi

    echo -e "${BLUE}[*] 创建 DDNS 更新脚本: $DDNS_SCRIPT_PATH ...${NC}"
    mkdir -p "$(dirname "$DDNS_SCRIPT_PATH")" # 确保目录存在
    # 从凭证文件中读取 API Token
    local current_token
    if [[ -f "$CLOUDFLARE_CREDENTIALS" ]]; then
        current_token=$(grep dns_cloudflare_api_token "$CLOUDFLARE_CREDENTIALS" | awk '{print $3}')
    fi
    if [[ -z "$current_token" ]]; then
        echo -e "${RED}[✗] 无法从 $CLOUDFLARE_CREDENTIALS 读取 API Token，无法创建 DDNS 脚本。${NC}"; return 1;
    fi

    # DDNS 更新脚本模板 (包含 get_current_ip 修复)
    cat > "$DDNS_SCRIPT_PATH" <<EOF
#!/bin/bash
# --- DDNS 更新脚本 for ${DOMAIN} (由主脚本自动生成) ---

# --- 配置 ---
# Cloudflare 凭证文件路径 (包含 API Token)
# 注意：此脚本需要能够读取此文件！
CF_CREDENTIALS_FILE="${CLOUDFLARE_CREDENTIALS}"
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
    # 将时间和消息追加到日志文件
    echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1" >> "\$LOG_FILE"
}

# 获取当前公网 IP (包含修复和调试日志)
get_current_ip() {
    local type=\$1
    local urls
    local curl_opt
    local curl_ua="Bash-DDNS-Script/1.0" # 定义 User Agent

    if [[ "\$type" == "A" ]]; then
        urls=("${IPV4_URLS[@]}")
        curl_opt="-4" # 移除了 -s (静默)
    elif [[ "\$type" == "AAAA" ]]; then
        urls=("${IPV6_URLS[@]}")
        curl_opt="-6" # 移除了 -s (静默)
    else
        log_message "错误：指定的记录类型无效: \$type" # 中文错误信息
        return 1
    fi

    local ip=""
    local raw_output="" # 用于存储原始输出的变量
    for url in "\${urls[@]}"; do
        log_message "调试：正在查询 \$url ..." # 记录正在查询哪个URL
        # 执行 curl，捕获标准输出到 raw_output，允许标准错误输出（会进入cron日志或手动执行输出）
        # 移除了 2>/dev/null
        raw_output=\$(curl \$curl_opt --user-agent "\$curl_ua" --max-time \$TIMEOUT "\$url" | head -n 1)
        local curl_exit_status=\$? # 捕获 curl 的退出状态码

        if [[ \$curl_exit_status -ne 0 ]]; then
             log_message "警告：curl 命令执行 \$url 失败，退出状态码 \$curl_exit_status。"
             # 现在的标准错误可能会显示在 cron 日志或手动执行的输出中
        fi

        # 去除原始输出的首尾空格
        ip=\$(echo "\$raw_output" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

        log_message "调试：从 \$url 收到 (原始): '\$raw_output' / (处理后): '\$ip'" # 记录原始和处理后的输出

        if [[ -n "\$ip" ]]; then
            # 简单的 IP 格式验证
            if [[ "\$type" == "A" && "\$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                log_message "调试：找到有效的 IPv4: \$ip" # 中文调试信息
                echo "\$ip"
                return 0
            fi
            # IPv6 验证
            if [[ "\$type" == "AAAA" && "\$ip" =~ ^([0-9a-fA-F:]+)$ && "\$ip" == *":"* ]]; then
                 log_message "调试：找到有效的 IPv6: \$ip" # 中文调试信息
                 echo "\$ip"
                 return 0
            fi
            # 如果 IP 不为空但验证失败，记录警告
            log_message "警告：从 \$url 收到非空响应但验证失败: '\$ip'" # 中文警告信息
        else
             log_message "调试：从 \$url 收到空响应。" # 中文调试信息
        fi
        sleep 1 # 避免过于频繁地请求服务
    done
    log_message "错误：尝试所有 URL 后，未能从所有来源获取当前的公共 \$type IP 地址。" # 中文错误信息
    return 1
}


# 获取 Cloudflare DNS 记录信息
get_cf_record() {
    local cf_token=\$1
    RECORD_INFO=\$(curl -s --max-time \$TIMEOUT -X GET "\$CF_API/zones/\$ZONE_ID/dns_records?type=\$RECORD_TYPE&name=\$DOMAIN" \
        -H "Authorization: Bearer \$cf_token" \
        -H "Content-Type: application/json")

    if [[ \$? -ne 0 ]]; then log_message "错误：API 调用失败 (获取记录 - 网络/超时)"; return 1; fi
    # 使用 jq -e 进行脚本检查
    if ! echo "\$RECORD_INFO" | jq -e '.success == true' > /dev/null; then
        local err_msg=\$(echo "\$RECORD_INFO" | jq -r '.errors[0].message // "未知 API 错误"')
        log_message "错误：API 调用失败 (获取记录): \$err_msg"; return 1;
    fi
    echo "\$RECORD_INFO" # 将 JSON 结果输出
    return 0
}

# 更新 Cloudflare DNS 记录
update_cf_record() {
    local cf_token=\$1
    local record_id=\$2
    local new_ip=\$3
    UPDATE_RESULT=\$(curl -s --max-time \$TIMEOUT -X PUT "\$CF_API/zones/\$ZONE_ID/dns_records/\$record_id" \
        -H "Authorization: Bearer \$cf_token" \
        -H "Content-Type: application/json" \
        --data "{\"type\":\"\$RECORD_TYPE\",\"name\":\"\$DOMAIN\",\"content\":\"\$new_ip\",\"ttl\":120,\"proxied\":false}")

    if [[ \$? -ne 0 ]]; then log_message "错误：API 调用失败 (更新记录 - 网络/超时)"; return 1; fi
    if ! echo "\$UPDATE_RESULT" | jq -e '.success == true' > /dev/null; then
        local err_msg=\$(echo "\$UPDATE_RESULT" | jq -r '.errors[0].message // "未知 API 错误"')
        log_message "错误：API 调用失败 (更新记录): \$err_msg"; return 1;
    fi
    return 0
}

# --- DDNS 脚本主逻辑 ---
# 确保日志目录存在
mkdir -p \$(dirname "\$LOG_FILE")

# 从凭证文件读取 API Token
if [[ ! -f "\$CF_CREDENTIALS_FILE" ]]; then
    log_message "错误：找不到 Cloudflare 凭证文件: \$CF_CREDENTIALS_FILE"
    exit 1
fi
CF_API_TOKEN=\$(grep dns_cloudflare_api_token "\$CF_CREDENTIALS_FILE" | awk '{print \$3}')
if [[ -z "\$CF_API_TOKEN" ]]; then
    log_message "错误：无法从 \$CF_CREDENTIALS_FILE 读取 Cloudflare API Token"
    exit 1
fi

# 获取当前公网 IP
CURRENT_IP=\$(get_current_ip "\$RECORD_TYPE")
if [[ \$? -ne 0 ]]; then
    # get_current_ip 函数内部已记录错误
    exit 1
fi

# 获取 Cloudflare 上的 DNS 记录信息
RECORD_INFO_JSON=\$(get_cf_record "\$CF_API_TOKEN")
if [[ \$? -ne 0 ]]; then exit 1; fi

# 解析记录 ID 和 Cloudflare 上的 IP
CF_IP=\$(echo "\$RECORD_INFO_JSON" | jq -r '.result[0].content')
RECORD_ID=\$(echo "\$RECORD_INFO_JSON" | jq -r '.result[0].id')

# 检查是否成功获取记录 ID 和 IP
if [[ -z "\$RECORD_ID" || "\$RECORD_ID" == "null" ]]; then
    log_message "错误：无法在 Cloudflare 上找到 \$DOMAIN 的 \$RECORD_TYPE 记录。"
    exit 1
fi
if [[ -z "\$CF_IP" || "\$CF_IP" == "null" ]]; then
    log_message "错误：无法从 Cloudflare 记录中解析 IP 地址 (\$DOMAIN)。"
    exit 1
fi

# 比较 IP 地址
if [[ "\$CURRENT_IP" == "\$CF_IP" ]]; then
    # IP 地址一致，无需更新 (正常情况不记录日志，减少噪音)
    # log_message "Info: IP address matches Cloudflare record (\$CURRENT_IP). No update needed."
    exit 0
else
    # IP 地址不匹配，需要更新
    log_message "信息：IP 地址不匹配。当前: \$CURRENT_IP, Cloudflare: \$CF_IP。正在更新 Cloudflare..." # 中文信息
    # 更新 Cloudflare 记录
    update_cf_record "\$CF_API_TOKEN" "\$RECORD_ID" "\$CURRENT_IP"
    if [[ \$? -eq 0 ]]; then
        log_message "成功：Cloudflare DNS 记录 (\$DOMAIN) 已成功更新为 \$CURRENT_IP。" # 中文信息
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
    return 0 # 创建成功
}

# 设置 Cron 定时任务 (证书续期和 DDNS)
setup_cron_jobs() {
    echo -e "${BLUE}[*] 设置 Cron 定时任务...${NC}"

    # 1. 创建证书续期后的部署钩子脚本
    echo -e "${BLUE}[*] 创建证书续期部署钩子脚本: $DEPLOY_HOOK_SCRIPT ...${NC}"
    mkdir -p "$(dirname "$DEPLOY_HOOK_SCRIPT")" # 确保目录存在
    # 钩子脚本内容
    cat > "$DEPLOY_HOOK_SCRIPT" <<EOF
#!/bin/bash
# Certbot 续期成功后执行的脚本 for ${DOMAIN} (由主脚本自动生成)

# 定义日志文件和相关路径 (这些变量会被主脚本中的值替换)
LOG_FILE="/var/log/cert_renew_${DOMAIN}.log"
CERT_PATH="${CERT_PATH}"
NGINX_CONF_PATH="${NGINX_CONF_PATH}"
LIVE_CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
CONFIG_DIR="${CERT_PATH_PREFIX}/.managed_domains"
CONFIG_FILE="${CONFIG_DIR}/${DOMAIN}.conf"
LOCAL_PROXY_PASS="none" # 默认值

# 从保存的配置文件中加载变量 (特别是 LOCAL_PROXY_PASS)
if [[ -f "\$CONFIG_FILE" ]]; then
    source "\$CONFIG_FILE"
fi

# 日志记录函数
log_hook() {
    echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1" >> "\$LOG_FILE"
}

# 确保日志目录存在
mkdir -p \$(dirname "\$LOG_FILE")

log_hook "证书已为 ${DOMAIN} 续期。正在运行部署钩子..." # 中文日志

# 检查源证书文件是否存在
if [[ ! -f "\${LIVE_CERT_DIR}/fullchain.pem" || ! -f "\${LIVE_CERT_DIR}/privkey.pem" ]]; then
    log_hook "错误：在 \${LIVE_CERT_DIR} 中找不到源证书文件。无法复制。" # 中文日志
    exit 1
fi

# 复制新证书到目标目录
log_hook "正在从 \${LIVE_CERT_DIR} 复制新证书到 ${CERT_PATH}..." # 中文日志
if cp -L "\${LIVE_CERT_DIR}/fullchain.pem" "${CERT_PATH}/" && \
   cp -L "\${LIVE_CERT_DIR}/privkey.pem" "${CERT_PATH}/" && \
   cp -L "\${LIVE_CERT_DIR}/chain.pem" "${CERT_PATH}/" && \
   cp -L "\${LIVE_CERT_DIR}/cert.pem" "${CERT_PATH}/"; then
    log_hook "成功：证书已复制到 ${CERT_PATH}。" # 中文日志
    # 可选：设置权限
    # chmod 644 ${CERT_PATH}/*.pem
else
    log_hook "错误：复制证书文件失败。" # 中文日志
    # exit 1 # 根据需要决定是否退出
fi

# 如果配置了 Nginx 代理，则重载 Nginx
if [[ "${LOCAL_PROXY_PASS}" != "none" ]] && [[ -n "${NGINX_CONF_PATH}" ]] && [[ -f "${NGINX_CONF_PATH}" ]] && command -v nginx >/dev/null 2>&1; then
    log_hook "Nginx 配置文件 ${NGINX_CONF_PATH} 存在且已配置代理。正在重载 Nginx..." # 中文日志
    # 先测试配置
    if nginx -t -c /etc/nginx/nginx.conf; then
        # 配置正确，执行重载
        if systemctl reload nginx; then
            log_hook "成功：Nginx 已成功重载。" # 中文日志
        else
            log_hook "错误：重载 Nginx 失败。请检查 'systemctl status nginx' 和 'journalctl -u nginx'。" # 中文日志
        fi
    else
        log_hook "错误：Nginx 配置测试失败 (nginx -t)。跳过重载。请手动检查 Nginx 配置！" # 中文日志
    fi
else
    # 记录不重载 Nginx 的原因
    if [[ "${LOCAL_PROXY_PASS}" == "none" ]]; then
      log_hook "此域名未配置 Nginx 代理。跳过 Nginx 重载。" # 中文日志
    elif [[ ! -f "${NGINX_CONF_PATH}" ]]; then
      log_hook "找不到 Nginx 配置文件 ${NGINX_CONF_PATH}。跳过 Nginx 重载。" # 中文日志
    else
      log_hook "找不到 nginx 命令或未配置 Nginx。跳过 Nginx 重载。" # 中文日志
    fi
fi

log_hook "为 ${DOMAIN} 执行的部署钩子已完成。" # 中文日志
exit 0
EOF
    # --- 部署钩子脚本模板结束 ---
    chmod +x "$DEPLOY_HOOK_SCRIPT" # 添加执行权限
    echo -e "${GREEN}[✓] 证书续期部署钩子脚本创建成功: $DEPLOY_HOOK_SCRIPT ${NC}"

    # 2. 添加或更新 Cron 任务
    # 使用特定标记管理脚本添加的任务
    CRON_TAG_RENEW="# CertRenew_${DOMAIN}"
    CRON_TAG_DDNS="# DDNSUpdate_${DOMAIN}"
    local CRON_CONTENT

    # 先移除旧的、由此脚本为该域名添加的 Cron 任务
    (crontab -l 2>/dev/null | grep -v -F "$CRON_TAG_RENEW" | grep -v -F "$CRON_TAG_DDNS") | crontab -

    # 获取清理后的 Cron 内容
    CRON_CONTENT=$(crontab -l 2>/dev/null)

    # 构建证书续期任务 (每天凌晨 3 点运行)
    local certbot_cmd=$(command -v certbot) # 获取 certbot 路径
    if [[ -z "$certbot_cmd" ]]; then
       echo -e "${RED}[✗] 找不到 certbot 命令。证书续期 Cron 任务可能失败。${NC}"
       certbot_cmd="certbot" # 使用默认名称作为后备
    fi
    CRON_CERT_RENEW="0 3 * * * $certbot_cmd renew --deploy-hook \"$DEPLOY_HOOK_SCRIPT\" >> /var/log/certbot_renew.log 2>&1 ${CRON_TAG_RENEW}"

    # 添加证书续期任务
    echo "${CRON_CONTENT}"$'\n'"${CRON_CERT_RENEW}" | crontab -
    echo -e "${GREEN}[✓] Cron 证书续期任务已设置 (${DOMAIN})。${NC}"

    # 如果启用了 DDNS，添加 DDNS 更新任务
    if [[ "$DDNS_FREQUENCY" -gt 0 ]]; then
        if [[ -f "$DDNS_SCRIPT_PATH" ]]; then
            # 构建 DDNS 任务 (每隔 DDNS_FREQUENCY 分钟运行)
            CRON_DDNS_UPDATE="*/${DDNS_FREQUENCY} * * * * $DDNS_SCRIPT_PATH ${CRON_TAG_DDNS}"
            # 再次获取 Cron 内容 (包含证书续期任务)
            CRON_CONTENT=$(crontab -l 2>/dev/null)
            # 添加 DDNS 更新任务
            echo "${CRON_CONTENT}"$'\n'"${CRON_DDNS_UPDATE}" | crontab -
            echo -e "${GREEN}[✓] Cron DDNS 更新任务已设置 (${DOMAIN}, 频率: ${DDNS_FREQUENCY} 分钟)。${NC}"
        else
            echo -e "${RED}[✗] DDNS 更新脚本 $DDNS_SCRIPT_PATH 未找到，无法设置 Cron 任务。${NC}"
        fi
    else
        echo -e "${YELLOW}DDNS 已禁用，未设置 DDNS 更新 Cron 任务。${NC}"
    fi
    return 0 # Cron 设置完成
}

# 保存当前域名的配置变量到文件
save_domain_config() {
    echo -e "${BLUE}[*] 保存域名 ${DOMAIN} 的配置...${NC}"
    mkdir -p "$CONFIG_DIR" # 确保配置目录存在
    local config_file="${CONFIG_DIR}/${DOMAIN}.conf"

    # 将相关变量写入配置文件
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
    chmod 600 "$config_file" # 设置权限，仅 root 可读写
    echo -e "${GREEN}[✓] 配置已保存到: ${config_file}${NC}"
}

# 从文件加载指定域名的配置 (未使用，删除时直接读取)
# load_domain_config() { ... }

# 列出已配置的 Web 服务域名
list_configured_domains() {
    echo -e "${BLUE}[*] 当前已配置的 Web 服务域名列表:${NC}"
    mkdir -p "$CONFIG_DIR" # 确保目录存在
    local domains=() # 用于存储域名列表的数组
    local i=1
    # 遍历配置文件
    for config_file in "${CONFIG_DIR}"/*.conf; do
        # 检查是否是文件且可读
        if [[ -f "$config_file" && -r "$config_file" ]]; then
            local domain_name=$(basename "$config_file" .conf) # 从文件名提取域名
            echo -e "  ${CYAN}[$i]${NC} $domain_name"
            domains+=("$domain_name") # 添加到数组
            ((i++))
        fi
    done

    # 如果没有找到任何配置
    if [[ ${#domains[@]} -eq 0 ]]; then
        echo -e "${YELLOW}  未找到任何已配置的 Web 服务域名。${NC}"
        return 1 # 返回错误码
    fi
    return 0 # 返回成功码
}

# 删除指定域名的配置和相关文件/任务
delete_domain_config() {
    echo -e "${RED}[!] 删除 Web 服务域名配置是一个危险操作，将移除相关证书、脚本和配置！${NC}"
    echo -e "${YELLOW}此操作不会删除 Cloudflare 上的 DNS 记录。${NC}"
    # 先列出可删除的域名
    list_configured_domains
    if [[ $? -ne 0 ]]; then return; fi # 如果没有域名，直接返回

    local domains=()
    # 再次获取域名列表到数组
    for config_file in "${CONFIG_DIR}"/*.conf; do
        if [[ -f "$config_file" && -r "$config_file" ]]; then
            domains+=("$(basename "$config_file" .conf)")
        fi
    done

    local choice
    local DOMAIN_TO_DELETE # 声明为局部变量
    # 让用户选择要删除的域名序号
    while true; do
        read -p "请输入要删除的域名的序号 (输入 '0' 退出): " choice
        if [[ "$choice" == "0" ]]; then echo "取消删除操作。"; return; fi
        # 验证输入是否为有效序号
        if [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#domains[@]} ]]; then
            local index=$((choice - 1))
            DOMAIN_TO_DELETE=${domains[$index]} # 获取选中的域名
            break # 选择有效，跳出循环
        else
            echo -e "${YELLOW}无效的序号，请重新输入。${NC}"
        fi
    done

    # 最终确认删除操作
    echo -e "${RED}你确定要删除域名 ${DOMAIN_TO_DELETE} 的所有本地配置吗？${NC}"
    if ! confirm_action "此操作不可恢复！确认删除吗?"; then
        echo "取消删除操作。"
        return
    fi

    echo -e "${BLUE}[*] 开始删除域名 ${DOMAIN_TO_DELETE} 的本地配置...${NC}"

    # 加载该域名的配置以获取文件路径等信息
    local config_file_to_load="${CONFIG_DIR}/${DOMAIN_TO_DELETE}.conf"
    if [[ -f "$config_file_to_load" ]]; then
        echo -e "${BLUE}[*] 加载 ${DOMAIN_TO_DELETE} 的配置用于删除...${NC}"
        # 直接 source 到当前作用域以获取变量值
        source "$config_file_to_load"
        echo -e "${GREEN}[✓] 配置加载成功。${NC}"
    else
         echo -e "${RED}[✗] 找不到 ${DOMAIN_TO_DELETE} 的配置文件，删除中止。可能配置已损坏或部分删除。${NC}"
        return 1
    fi

    # --- 开始执行删除操作 ---
    # 1. 移除 Cron 任务
    echo -e "${BLUE}[*] 移除 Cron 任务...${NC}"
    CRON_TAG_RENEW="# CertRenew_${DOMAIN_TO_DELETE}"
    CRON_TAG_DDNS="# DDNSUpdate_${DOMAIN_TO_DELETE}"
    (crontab -l 2>/dev/null | grep -v -F "$CRON_TAG_RENEW" | grep -v -F "$CRON_TAG_DDNS") | crontab -
    echo -e "${GREEN}[✓] Cron 任务已移除。${NC}"

    # 2. 删除 DDNS 更新脚本 (使用加载的路径变量 DDNS_SCRIPT_PATH)
    if [[ -n "$DDNS_SCRIPT_PATH" && -f "$DDNS_SCRIPT_PATH" ]]; then
        echo -e "${BLUE}[*] 删除 DDNS 更新脚本: $DDNS_SCRIPT_PATH ...${NC}"
        rm -f "$DDNS_SCRIPT_PATH"
        echo -e "${GREEN}[✓] DDNS 脚本已删除。${NC}"
    fi

    # 3. 删除证书续期部署钩子脚本 (使用加载的路径变量 DEPLOY_HOOK_SCRIPT)
    if [[ -n "$DEPLOY_HOOK_SCRIPT" && -f "$DEPLOY_HOOK_SCRIPT" ]]; then
        echo -e "${BLUE}[*] 删除证书续期钩子脚本: $DEPLOY_HOOK_SCRIPT ...${NC}"
        rm -f "$DEPLOY_HOOK_SCRIPT"
        echo -e "${GREEN}[✓] 续期钩子脚本已删除。${NC}"
    fi

    # 4. 删除 Nginx 配置和软链接 (如果配置了 Nginx)
    local nginx_enabled_link="/etc/nginx/sites-enabled/${DOMAIN_TO_DELETE}.conf"
    # 使用加载的 LOCAL_PROXY_PASS 和 NGINX_CONF_PATH 判断是否配置了 Nginx
    if [[ "$LOCAL_PROXY_PASS" != "none" ]] && [[ -n "$NGINX_CONF_PATH" ]] && (-f "$NGINX_CONF_PATH" || -L "$nginx_enabled_link"); then
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

    # 5. 删除 Cloudflare 凭证文件 (使用加载的路径变量 CLOUDFLARE_CREDENTIALS)
    if [[ -n "$CLOUDFLARE_CREDENTIALS" && -f "$CLOUDFLARE_CREDENTIALS" ]]; then
        echo -e "${BLUE}[*] 删除 Cloudflare 凭证文件: $CLOUDFLARE_CREDENTIALS ...${NC}"
        # shred -u "$CLOUDFLARE_CREDENTIALS" 2>/dev/null || rm -f "$CLOUDFLARE_CREDENTIALS" # 安全删除 (可选)
        rm -f "$CLOUDFLARE_CREDENTIALS"
        echo -e "${GREEN}[✓] Cloudflare 凭证文件已删除。${NC}"
    fi

    # 6. 删除复制的证书目录 (使用加载的路径变量 CERT_PATH)
    if [[ -n "$CERT_PATH" && -d "$CERT_PATH" ]]; then
        echo -e "${BLUE}[*] 删除证书副本目录: $CERT_PATH ...${NC}"
        rm -rf "$CERT_PATH"
        echo -e "${GREEN}[✓] 证书副本目录已删除。${NC}"
    fi

    # 7. 删除 Let's Encrypt 证书 (使用 certbot delete)
    echo -e "${BLUE}[*] 删除 Let's Encrypt 证书 (certbot)...${NC}"
    if command_exists certbot; then
        local certbot_cmd=$(command -v certbot)
        "$certbot_cmd" delete --cert-name "${DOMAIN_TO_DELETE}" --non-interactive --logs-dir /var/log/letsencrypt
        # 忽略 certbot delete 的退出码，因为它在证书不存在时也会报错
        echo -e "${GREEN}[✓] 已尝试使用 certbot 删除证书。${NC}"
    else
        echo -e "${YELLOW}[!] certbot 命令未找到，无法自动删除 Let's Encrypt 证书。${NC}"
        echo -e "${YELLOW}   请手动清理 /etc/letsencrypt/live/${DOMAIN_TO_DELETE}, /etc/letsencrypt/archive/${DOMAIN_TO_DELETE}, /etc/letsencrypt/renewal/${DOMAIN_TO_DELETE}.conf ${NC}"
    fi

    # 8. 删除保存的配置文件 (使用原始路径)
    if [[ -f "$config_file_to_load" ]]; then
        echo -e "${BLUE}[*] 删除脚本配置文件: $config_file_to_load ...${NC}"
        rm -f "$config_file_to_load"
        echo -e "${GREEN}[✓] 脚本配置文件已删除。${NC}"
    fi

    echo -e "${GREEN}[✓] 域名 ${DOMAIN_TO_DELETE} 的所有相关本地配置已成功删除！${NC}"
    # 清理全局变量，防止影响下一次操作
    DOMAIN="" CF_API_TOKEN="" EMAIL="your@mail.com" CERT_PATH="" CLOUDFLARE_CREDENTIALS="" DEPLOY_HOOK_SCRIPT="" DDNS_SCRIPT_PATH="" DDNS_FREQUENCY=5 RECORD_TYPE="" ZONE_ID="" NGINX_CONF_PATH="" LOCAL_PROXY_PASS="" BACKEND_PROTOCOL="http" NGINX_HTTP_PORT=80 NGINX_HTTPS_PORT=443
}

# 添加新 Web 服务域名的主流程
add_new_domain() {
    echo -e "\n${CYAN}--- 5.1 添加新 Web 服务域名配置 ---${NC}"
    local overall_success=0 # 跟踪整体成功状态, 0 = success, 1 = failure

    # 0. 确保 Certbot (优先 Snap) 和插件已安装
    if ! install_or_update_certbot_snap; then
        echo -e "${RED}[✗] Certbot 环境设置失败，无法继续。${NC}"; return 1;
    fi

    # 检查并安装 Nginx
    echo -e "${BLUE}[*] 检查并安装 Nginx...${NC}"
    if ! install_package "nginx"; then
        echo -e "${RED}[✗] Nginx 安装失败，无法继续配置 Web 服务。${NC}"; return 1;
    fi

    # --- 开始配置流程 ---
    # 使用 || { ...; overall_success=1; } 在关键步骤失败时标记失败，但可能继续执行后续清理或非关键步骤
    # 使用 || { ...; return 1; } 在关键步骤失败时直接中止函数

    # 1. 获取用户输入
    get_user_input_initial || { echo -e "${RED}[✗] 获取用户输入失败。${NC}"; return 1; }

    # 2. 配置 Nginx (如果用户选择) - 生成文件并链接
    # 即使失败也继续尝试获取证书，但标记失败
    setup_nginx_proxy || { echo -e "${RED}[✗] Nginx 代理配置步骤失败。${NC}"; overall_success=1; }

    # 3. 创建 Cloudflare 凭证文件 (关键步骤)
    create_cf_credentials || { echo -e "${RED}[✗] 创建 Cloudflare 凭证失败。${NC}"; return 1; }

    # 5. 检测 IP 地址 (关键步骤)
    detect_public_ip || { echo -e "${RED}[✗] 检测公网 IP 失败。${NC}"; return 1; }

    # 6. 选择记录类型和 IP (关键步骤)
    select_record_type || { echo -e "${RED}[✗] 选择记录类型失败。${NC}"; return 1; }

    # 7. 获取 Zone ID (关键步骤)
    get_zone_id || { echo -e "${RED}[✗] 获取 Cloudflare Zone ID 失败。${NC}"; return 1; }

    # 8. 管理 Cloudflare DNS 记录 (关键步骤)
    manage_cloudflare_record "设置" || { echo -e "${RED}[✗] 设置 Cloudflare DNS 记录失败。${NC}"; return 1; }

    # --- 证书申请与后续步骤 ---
    if request_certificate; then
        # 证书申请成功，执行后续步骤
        copy_certificate || overall_success=1 # 复制失败不中止，但标记
        create_ddns_script || overall_success=1 # DDNS 失败不中止，但标记
        setup_cron_jobs || overall_success=1 # Cron 失败不中止，但标记
        save_domain_config || overall_success=1 # 保存配置失败不中止，但标记

        # 测试并重载 Nginx (如果配置了 Nginx)
        if [[ "$LOCAL_PROXY_PASS" != "none" ]]; then
            echo -e "\n${BLUE}[*] 检查 Nginx 配置并尝试重载 (证书已申请/复制)...${NC}"
            if ! command_exists nginx; then
                echo -e "${RED}[✗] Nginx 命令未找到。无法测试或重载配置。${NC}"
                overall_success=1
            else
                # 捕获 nginx -t 的输出和状态码
                nginx_test_output=$(nginx -t -c /etc/nginx/nginx.conf 2>&1)
                nginx_test_status=$?

                if [[ $nginx_test_status -eq 0 ]]; then
                    # 配置检查通过
                    if systemctl reload nginx && systemctl is-active --quiet nginx; then
                        echo -e "${GREEN}[✓] Nginx 配置检查通过并已成功重载。${NC}"
                        # 显示防火墙和访问提示
                        echo -e "${YELLOW}提示：Nginx 正在监听 HTTP 端口 ${NGINX_HTTP_PORT} 和 HTTPS 端口 ${NGINX_HTTPS_PORT}。${NC}"
                        if command_exists ufw && ufw status | grep -q "Status: active"; then
                            echo -e "${BLUE}[*] 尝试在 UFW 中允许 Nginx 端口 ${NGINX_HTTP_PORT} 和 ${NGINX_HTTPS_PORT}...${NC}"
                            ufw allow ${NGINX_HTTP_PORT}/tcp comment "Nginx HTTP (${DOMAIN})" > /dev/null
                            ufw allow ${NGINX_HTTPS_PORT}/tcp comment "Nginx HTTPS (${DOMAIN})" > /dev/null
                            echo -e "${GREEN}[✓] 已尝试添加 UFW 规则。请使用 '查看 UFW 规则' 确认。${NC}"
                        elif [[ "$NGINX_HTTP_PORT" -ne 80 || "$NGINX_HTTPS_PORT" -ne 443 ]]; then
                            echo -e "${YELLOW}重要提示：请确保防火墙 (如 ufw, firewalld) 允许访问您设置的自定义端口 (${NGINX_HTTP_PORT} 和 ${NGINX_HTTPS_PORT})！${NC}"
                        fi
                        echo -e "${YELLOW}访问时，如果 HTTPS 端口不是 443，URL 中需要包含端口号，例如: https://${DOMAIN}:${NGINX_HTTPS_PORT}${NC}"
                    else
                        echo -e "${RED}[✗] Nginx 重载后状态异常，请检查 Nginx 服务状态和日志。${NC}"
                        overall_success=1
                    fi
                else
                    # 配置检查失败
                    echo -e "${RED}[✗] Nginx 配置检查失败 (nginx -t 返回错误)! Nginx 未重载。${NC}"
                    echo -e "${RED}--- Nginx 错误信息 ---${NC}"
                    echo -e "${YELLOW}${nginx_test_output}${NC}" # 显示 Nginx 错误输出
                    echo -e "${RED}-----------------------${NC}"
                    echo -e "${RED}请检查错误信息中提到的文件。通常这是由于 /etc/nginx/sites-enabled/ 中存在旧的、无效的配置文件引起的。${NC}"
                    echo -e "${RED}请手动清理无效配置 (例如 'sudo rm /etc/nginx/sites-enabled/your-old-site.conf')，然后重试 'sudo nginx -t'。${NC}"
                    overall_success=1
                fi
            fi
        else
             echo -e "${YELLOW}[!] 未配置 Nginx 反向代理，跳过 Nginx 测试和重载。${NC}"
        fi
    else
        # 证书申请失败
        echo -e "${RED}[!] 由于证书申请失败，后续步骤 (复制证书, DDNS脚本, Cron任务, Nginx重载, 保存配置) 将被跳过。${NC}"
        # 尝试清理本次生成的 Nginx 配置和凭证文件
        if [[ "$LOCAL_PROXY_PASS" != "none" ]]; then
             echo -e "${YELLOW}[!] 尝试清理未使用的 Nginx 配置...${NC}"
             rm -f "/etc/nginx/sites-enabled/${DOMAIN}.conf"
             rm -f "$NGINX_CONF_PATH"
        fi
        rm -f "$CLOUDFLARE_CREDENTIALS"
        overall_success=1 # 标记整体失败
    fi

    # 根据整体成功状态输出最终信息
    if [[ $overall_success -eq 0 ]]; then
        echo -e "\n${GREEN}--- 域名 ${DOMAIN} 配置完成！ ---${NC}"
        return 0
    else
         echo -e "\n${RED}--- 域名 ${DOMAIN} 配置过程中遇到错误，请检查上面的日志。 ---${NC}"
         return 1
    fi
}

# Web 服务管理主菜单
manage_web_service() {
     while true; do
        echo -e "\n${CYAN}--- Web 服务管理 (LE + CF + Nginx) ---${NC}"
        echo -e " ${YELLOW}1.${NC} 添加新域名并配置证书/Nginx/DDNS (优先使用 Snap Certbot)"
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
    check_root # 确保 SSH 端口等信息最新
    # 尝试获取 Certbot 版本信息
    local certbot_vsn="未知"
    if command_exists certbot; then
        certbot_vsn=$(certbot --version 2>&1 | awk '{print $2}')
    fi
    # 显示主菜单
    echo -e "\n${CYAN}=======================================================${NC}"
    echo -e "${CYAN}     服务器初始化与管理脚本 (Compat Mod v2.17+)     ${NC}" # 标记版本
    echo -e "${CYAN}=======================================================${NC}"
    echo -e " ${BLUE}--- 系统与安全 ---${NC}"
    echo -e "  ${YELLOW}1.${NC} 安装基础依赖工具 (curl, jq, expect, unzip, snapd)"
    echo -e "  ${YELLOW}2.${NC} UFW 防火墙管理"
    echo -e "  ${YELLOW}3.${NC} Fail2ban 入侵防御管理"
    echo -e "  ${YELLOW}4.${NC} SSH 安全管理 (端口: ${YELLOW}${CURRENT_SSH_PORT}${NC})"
    echo -e "\n ${BLUE}--- Web 服务 (Certbot: ${certbot_vsn}) ---${NC}" # 显示 Certbot 版本
    echo -e "  ${YELLOW}5.${NC} Web 服务管理 (Let's Encrypt + Cloudflare + Nginx)"
    echo -e "\n ${BLUE}--- 其他 ---${NC}"
    echo -e "  ${YELLOW}0.${NC} 退出脚本"
    echo -e "${CYAN}=======================================================${NC}"
    read -p "请输入选项 [0-5]: " main_choice
}

# --- 脚本入口 ---

# 初始检查 Root 权限
check_root

# 主循环，显示菜单并处理用户选择
while true; do
    show_main_menu
    case $main_choice in
        1) install_common_tools ;;
        2) manage_ufw ;;
        3) manage_fail2ban ;;
        4) manage_ssh_security ;;
        5) manage_web_service ;;
        0) echo "退出脚本。" ; exit 0 ;; # 退出
        *) echo -e "${RED}无效选项，请输入 0 到 5 之间的数字。${NC}" ;;
    esac
    # 除退出外，暂停等待用户确认
    if [[ "$main_choice" != "0" ]]; then
         read -p "按 Enter键 继续..."
    fi
done

exit 0
