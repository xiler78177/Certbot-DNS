#!/bin/bash

# ==============================================================================
# 服务器初始化与管理脚本 (v11.3 - The Bulletproof Edition)
#
# 更新日志 v11.3 (基于深度 Code Review 终极加固):
# 1. [防崩] prepare_web_env 内部安装命令全量增加错误捕获 (if ! cmd)，
#    防止 snap install 失败直接触发 ERR trap 导致脚本闪退。
# 2. [逻辑] add_new_domain 调用增加 || return 1，确保环境准备失败时优雅返回。
# 3. [兼容] reinstall_common_tools 将 snapd 移出强制列表，允许在容器中安装失败。
# ==============================================================================

# --- 基础环境修复 ---
if [[ -t 0 ]]; then
    stty sane
    stty erase '^H'
fi

# 开启错误追踪 (函数内错误也会触发 trap)
set -o errtrace

# --- 全局变量定义 ---
CF_API_TOKEN=""
DOMAIN=""
EMAIL="your@mail.com" # 固定邮箱
CERT_PATH_PREFIX="/root/cert"
CONFIG_DIR="${CERT_PATH_PREFIX}/.managed_domains"
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
NGINX_HTTP_PORT=80
NGINX_HTTPS_PORT=443
SSHD_CONFIG="/etc/ssh/sshd_config"
DEFAULT_SSH_PORT=22
CURRENT_SSH_PORT=$(grep -iE "^\s*Port\s+" "$SSHD_CONFIG" 2>/dev/null | tail -n 1 | awk '{print $2}')
[[ "$CURRENT_SSH_PORT" =~ ^[0-9]+$ ]] || CURRENT_SSH_PORT=$DEFAULT_SSH_PORT
FAIL2BAN_JAIL_LOCAL="/etc/fail2ban/jail.local"
RESOLV_CONF="/etc/resolv.conf"
SYSTEMD_RESOLVED_CONF="/etc/systemd/resolved.conf"
APT_UPDATED=0

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ==============================================================================
# 工具函数
# ==============================================================================

cleanup_and_exit() {
    rm -f "${FAIL2BAN_JAIL_LOCAL}.tmp.$$" 2>/dev/null
    echo -e "${RED}脚本发生错误或被中断，已退出。${NC}"
    exit 1
}
trap 'cleanup_and_exit' ERR SIGINT SIGTERM

command_exists() { command -v "$1" >/dev/null 2>&1; }

is_systemd() {
    if command_exists systemctl && [[ -d /run/systemd/system ]]; then return 0; else return 1; fi
}

check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then echo -e "${RED}[✗] 请使用 sudo 运行。${NC}"; exit 1; fi
}

confirm_action() {
    local prompt_msg="$1"
    local reply
    while true; do
        read -p "$prompt_msg [Y/n]: " -n 1 -r reply
        echo
        if [[ $reply =~ ^[Yy]$ || -z $reply ]]; then return 0;
        elif [[ $reply =~ ^[Nn]$ ]]; then return 1;
        else echo -e "${YELLOW}请输入 Y 或 N。${NC}"; fi
    done
}

update_apt_cache() {
    if [[ $APT_UPDATED -eq 0 ]]; then
        echo -e "${BLUE}[*] 更新软件源缓存...${NC}"
        apt-get update -y >/dev/null 2>&1
        APT_UPDATED=1
    fi
}

install_package() {
    local pkg_name="$1"
    local silent="$2"
    if dpkg -s "$pkg_name" &> /dev/null; then
        [[ "$silent" != "silent" ]] && echo -e "${YELLOW}[!] $pkg_name 已安装。${NC}"
        return 0
    fi
    [[ "$silent" != "silent" ]] && echo -e "${BLUE}[*] 安装 $pkg_name ...${NC}"
    update_apt_cache
    export DEBIAN_FRONTEND=noninteractive
    if ! apt-get install -y "$pkg_name" >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] 尝试修复依赖...${NC}"
        apt-get install -f -y >/dev/null 2>&1
        if ! apt-get install -y "$pkg_name" >/dev/null 2>&1; then
            echo -e "${RED}[✗] 安装 $pkg_name 失败。${NC}"; return 1
        fi
    fi
    [[ "$silent" != "silent" ]] && echo -e "${GREEN}[✓] 安装成功。${NC}"
    return 0
}

auto_install_dependencies() {
    local tools="curl wget jq unzip openssl ca-certificates iproute2"
    for tool in $tools; do
        if ! dpkg -s "$tool" &> /dev/null; then install_package "$tool" "silent"; fi
    done
    # Snapd 可选，失败不退出
    if ! command_exists snap; then install_package "snapd" "silent" || true; fi
}

reinstall_common_tools() {
    echo -e "\n${CYAN}--- 2. 手动重装依赖 ---${NC}"
    APT_UPDATED=0
    update_apt_cache
    # [修复] 移除 snapd，避免在容器中失败导致整个重装过程中断
    local tools="curl wget jq unzip openssl ca-certificates ufw fail2ban nginx iproute2"
    for tool in $tools; do install_package "$tool"; done
    
    # 单独处理 snapd (允许失败)
    echo -e "${BLUE}[*] 尝试安装 Snapd (可选)...${NC}"
    install_package "snapd" || echo -e "${YELLOW}[!] Snapd 安装失败 (环境不支持?)，跳过。${NC}"
    
    echo -e "${GREEN}[✓] 依赖检查完成。${NC}"
}

# ==============================================================================
# 功能模块：系统信息
# ==============================================================================

output_status() {
    DETECTED_IPV4=$(curl -s --max-time 3 https://api.ipify.org || echo "")
    DETECTED_IPV6=$(curl -s --max-time 3 https://api64.ipify.org || echo "")

    local output=$(awk 'BEGIN { rx_total = 0; tx_total = 0 }
        $1 ~ /^(eth|ens|enp|eno)[0-9]+/ { rx_total += $2; tx_total += $10 }
        END {
            rx_units = "Bytes"; tx_units = "Bytes";
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "K"; }
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "M"; }
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "G"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "K"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "M"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "G"; }
            printf("%.2f%s %.2f%s\n", rx_total, rx_units, tx_total, tx_units);
        }' /proc/net/dev 2>/dev/null || echo "0 0")

    local rx=$(echo "$output" | awk '{print $1}')
    local tx=$(echo "$output" | awk '{print $2}')

    local cpu_info=$(lscpu | awk -F': +' '/Model name:/ {print $2; exit}' || echo "Unknown")
    local cpu_usage_percent=$(awk '{u=$2+$4; t=$2+$4+$5; if (NR==1){u1=u; t1=t;} else printf "%.0f", (($2+$4-u1) * 100 / (t-t1))}' <(grep 'cpu ' /proc/stat) <(sleep 1; grep 'cpu ' /proc/stat) || echo "0")
    local cpu_cores=$(nproc || echo "1")
    local cpu_freq=$(cat /proc/cpuinfo | grep "MHz" | head -n 1 | awk '{printf "%.1f GHz", $4/1000}' || echo "N/A")
    local mem_info=$(free -b | awk 'NR==2{printf "%.2fG/%.2fG (%.2f%%)", $3/1024/1024/1024, $2/1024/1024/1024, $3*100/$2}' || echo "N/A")
    local swap_info=$(free -m | awk 'NR==3{used=$3; total=$2; if (total == 0) {percentage=0} else {percentage=used*100/total}; printf "%dM/%dM (%d%%)", used, total, percentage}' || echo "N/A")
    local disk_info=$(df -h | awk '$NF=="/"{printf "%s/%s (%s)", $3, $2, $5}' || echo "N/A")
    
    local ipinfo=$(curl -s --max-time 5 ipinfo.io || echo "")
    local country=$(echo "$ipinfo" | grep 'country' | awk -F': ' '{print $2}' | tr -d '",' || echo "N/A")
    local city=$(echo "$ipinfo" | grep 'city' | awk -F': ' '{print $2}' | tr -d '",' || echo "N/A")
    local isp_info=$(echo "$ipinfo" | grep 'org' | awk -F': ' '{print $2}' | tr -d '",' || echo "N/A")
    
    local load=$(uptime | awk '{print $(NF-2), $(NF-1), $NF}' || echo "N/A")
    local dns_addresses=$(awk '/^nameserver/{printf "%s ", $2} END {print ""}' /etc/resolv.conf || echo "N/A")
    local cpu_arch=$(uname -m)
    local hostname=$(uname -n)
    local kernel_version=$(uname -r)
    local congestion_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "N/A")
    local queue_algorithm=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "N/A")
    local os_info=$(grep PRETTY_NAME /etc/os-release | cut -d '=' -f2 | tr -d '"' || echo "Linux")
    local current_time=$(date "+%Y-%m-%d %I:%M %p")
    local runtime=$(cat /proc/uptime | awk -F. '{run_days=int($1 / 86400);run_hours=int(($1 % 86400) / 3600);run_minutes=int(($1 % 3600) / 60); if (run_days > 0) printf("%d天 ", run_days); if (run_hours > 0) printf("%d时 ", run_hours); printf("%d分\n", run_minutes)}' || echo "N/A")
    
    local timezone="UTC"
    if command_exists timedatectl; then
        timezone=$(timedatectl | grep "Time zone" | awk '{print $3}' || echo "UTC")
    fi

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

# ==============================================================================
# 功能模块：UFW 防火墙
# ==============================================================================

setup_ufw() {
    echo -e "\n${CYAN}--- 3.1 安装并启用 UFW ---${NC}"
    install_package "ufw"
    if is_systemd && systemctl is-active --quiet firewalld; then
        echo -e "${RED}[!] 检测到 firewalld 正在运行，请先禁用它。${NC}"; return 1
    fi
    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null
    ufw allow $CURRENT_SSH_PORT/tcp comment "SSH-Access" >/dev/null
    echo -e "${YELLOW}[?] 启用防火墙可能断开 SSH。${NC}"
    if confirm_action "确认启用 UFW 吗?"; then
        echo "y" | ufw enable
        echo -e "${GREEN}[✓] UFW 已启用。${NC}"
        ufw status verbose || echo "状态查询失败"
    fi
}

add_ufw_rule() {
    echo -e "\n${CYAN}--- 3.2 批量添加端口 ---${NC}"
    read -p "请输入端口号 (空格隔开): " ports
    [[ -z "$ports" ]] && return
    for port in $ports; do
        if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -le 65535 ]; then
            ufw allow "$port/tcp" comment "Manual-Add-$port" >/dev/null
            echo -e "${GREEN}[✓] 端口 $port/tcp 已开放。${NC}"
        else
            echo -e "${RED}[✗] 端口 $port 无效。${NC}"
        fi
    done
    view_ufw_rules 
}

view_ufw_rules() { 
    if ! command_exists ufw; then echo -e "${YELLOW}未安装 UFW。${NC}"; return; fi
    ufw status numbered || echo -e "${YELLOW}UFW 未运行。${NC}"
}

delete_ufw_rule() {
    echo -e "\n${CYAN}--- 3.4 删除规则 ---${NC}"
    if ! command_exists ufw; then echo -e "${RED}[!] UFW 未安装。${NC}"; return; fi
    if ! ufw status >/dev/null 2>&1; then echo -e "${RED}[!] UFW 未运行。${NC}"; return; fi
    ufw status numbered
    read -p "请输入删除的编号 (空格隔开): " nums
    [[ -z "$nums" ]] && return
    for num in $(echo "$nums" | tr ' ' '\n' | sort -nr); do
        echo "y" | ufw delete $num >/dev/null 2>&1
        echo -e "${GREEN}[✓] 规则 $num 已删除。${NC}"
    done
    ufw status numbered || true
}

ufw_allow_all() {
    if confirm_action "${RED}警告：这将允许所有入站连接！确定吗？${NC}"; then
        ufw default allow incoming; echo -e "${GREEN}[✓] 已设置为允许所有入站。${NC}"
    fi
}

ufw_reset_default() {
    if confirm_action "确认重置防火墙 (保留 SSH)?"; then
        ufw default deny incoming >/dev/null
        ufw default allow outgoing >/dev/null
        ufw allow $CURRENT_SSH_PORT/tcp comment "SSH-Access" >/dev/null
        ufw reload >/dev/null
        echo -e "${GREEN}[✓] 重置完成。${NC}"
    fi
}

uninstall_ufw() {
    if confirm_action "${RED}确定要卸载 UFW 吗？${NC}"; then
        ufw disable
        apt-get remove --purge ufw -y
        echo -e "${GREEN}[✓] UFW 已卸载。${NC}"
    fi
}

manage_ufw() {
    while true; do
        echo -e "\n${CYAN}--- 防火墙管理 (UFW) ---${NC}"
        echo "1. 安装/启用 UFW"; echo "2. 添加端口规则"; echo "3. 查看当前规则"; echo "4. 删除规则"; echo -e "${RED}5. 允许所有入站${NC}"; echo "6. 重置默认规则"; echo -e "${RED}7. 卸载 UFW${NC}"; echo "0. 返回"
        read -p "选择: " c
        case $c in
            1) setup_ufw ;; 2) add_ufw_rule ;; 3) view_ufw_rules ;; 4) delete_ufw_rule ;;
            5) ufw_allow_all ;; 6) ufw_reset_default ;; 7) uninstall_ufw ;; 0) break ;;
            *) echo "无效选项" ;;
        esac
        [[ $c != 0 ]] && read -p "按 Enter 继续..."
    done
}

# ==============================================================================
# 功能模块：Fail2ban
# ==============================================================================

setup_fail2ban() {
    echo -e "\n${CYAN}--- 4.1 安装 Fail2ban ---${NC}"
    install_package "fail2ban" "silent"
    install_package "rsyslog" "silent"
    if is_systemd; then systemctl enable rsyslog >/dev/null 2>&1 || true; systemctl restart rsyslog || true; fi
    echo -e "${BLUE}[*] 生成配置文件...${NC}"
    configure_fail2ban
    if is_systemd; then
        systemctl enable fail2ban >/dev/null || true
        systemctl restart fail2ban || echo -e "${YELLOW}[!] 启动失败，请检查日志。${NC}"
        if systemctl is-active --quiet fail2ban; then echo -e "${GREEN}[✓] Fail2ban 运行正常。${NC}"; fi
    else echo -e "${YELLOW}[!] 非 Systemd 环境，请手动启动 Fail2ban。${NC}"; fi
}

configure_fail2ban() {
    local ssh_port maxretry bantime
    read -p "监控 SSH 端口 [$CURRENT_SSH_PORT]: " ssh_port; ssh_port=${ssh_port:-$CURRENT_SSH_PORT}
    read -p "最大重试次数 [5]: " maxretry; maxretry=${maxretry:-5}
    read -p "封禁时间 (如 10m, 1h) [10m]: " bantime; bantime=${bantime:-"10m"}
    local backend_conf="backend = auto"
    local journal_conf=""
    if is_systemd; then
        backend_conf="backend = systemd"
        journal_conf="journalmatch = _SYSTEMD_UNIT=sshd.service + _COMM=sshd"
    fi
    cat > "$FAIL2BAN_JAIL_LOCAL" <<EOF
[DEFAULT]
bantime = 10m
banaction = ufw
[sshd]
enabled = true
port = $ssh_port
maxretry = $maxretry
bantime = $bantime
$backend_conf
$journal_conf
EOF
    chmod 644 "$FAIL2BAN_JAIL_LOCAL"
    echo -e "${GREEN}[✓] 配置已写入。${NC}"
}

view_fail2ban() {
    echo -e "\n${CYAN}--- Fail2ban 状态 ---${NC}"
    if command_exists fail2ban-client; then fail2ban-client status sshd || echo -e "${YELLOW}未运行。${NC}"; else echo -e "${YELLOW}未安装。${NC}"; fi
    echo -e "\n${BLUE}日志预览:${NC}"
    if [[ -f /var/log/fail2ban.log ]]; then tail -n 10 /var/log/fail2ban.log; fi
}

uninstall_fail2ban() {
    if confirm_action "卸载 Fail2ban?"; then
        if is_systemd; then systemctl stop fail2ban || true; systemctl disable fail2ban || true; fi
        apt-get remove --purge fail2ban -y
        rm -f "$FAIL2BAN_JAIL_LOCAL"
        echo -e "${GREEN}[✓] 已卸载。${NC}"
    fi
}

manage_fail2ban() {
    while true; do
        echo -e "\n${CYAN}--- Fail2ban 防护 ---${NC}"
        echo "1. 安装/重置配置"; echo "2. 修改配置参数"; echo "3. 查看状态/日志"; echo -e "${RED}4. 卸载 Fail2ban${NC}"; echo "0. 返回"
        read -p "选择: " c
        case $c in 
            1) setup_fail2ban ;; 
            2) configure_fail2ban && (is_systemd && systemctl restart fail2ban || true) ;; 
            3) view_fail2ban ;; 4) uninstall_fail2ban ;; 0) break ;; *) echo -e "${RED}无效选项。${NC}" ;;
        esac
        [[ $c != 0 ]] && read -p "按 Enter 继续..."
    done
}

# ==============================================================================
# 功能模块：SSH 安全
# ==============================================================================

update_sshd() {
    local key="$1"; local val="$2"
    if grep -qE "^\s*#?\s*${key}\s" "$SSHD_CONFIG"; then
        sed -i -E "s|^\s*#?\s*${key}\s+.*|${key} ${val}|" "$SSHD_CONFIG"
    else echo "${key} ${val}" >> "$SSHD_CONFIG"; fi
}

change_ssh_port() {
    echo -e "\n${CYAN}--- 5.1 修改 SSH 端口 ---${NC}"
    read -p "新端口号 (当前 $CURRENT_SSH_PORT): " port
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then 
        echo -e "${RED}[✗] 无效端口。${NC}"; return
    fi
    
    if command_exists ufw && ufw status | grep -q "Status: active"; then
        ufw allow "$port/tcp" comment "SSH-New" >/dev/null
        echo -e "${GREEN}[✓] UFW 已放行新端口 $port。${NC}"
    fi
    
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"
    update_sshd "Port" "$port"
    
    if is_systemd; then
        if systemctl restart sshd; then
            echo -e "${GREEN}[✓] SSH 重启成功。请使用新端口 $port 连接。${NC}"
            CURRENT_SSH_PORT=$port
        else
            echo -e "${RED}[✗] 重启失败！正在还原配置...${NC}"
            mv "${SSHD_CONFIG}.bak" "$SSHD_CONFIG"
            systemctl restart sshd || true
        fi
    else
        echo -e "${GREEN}[✓] 配置文件已修改。${NC}"
        echo -e "${YELLOW}[!] 非 Systemd 环境，请手动重启 SSH 服务或重启容器。${NC}"
        CURRENT_SSH_PORT=$port
        echo -e "${BLUE}[i] 脚本端口记录已更新。${NC}"
    fi
}

create_user() {
    read -p "新用户名: " user
    if [[ -z "$user" ]]; then return; fi
    adduser "$user"
    usermod -aG sudo "$user"
    echo -e "${GREEN}[✓] 用户 $user 已创建。${NC}"
}

disable_root() {
    if confirm_action "确认禁用 Root 远程登录?"; then
        update_sshd "PermitRootLogin" "no"
        if is_systemd; then systemctl restart sshd || true; fi
        echo -e "${GREEN}[✓] Root 远程登录已禁用。${NC}"
    fi
}

config_keys() {
    echo -e "\n${CYAN}--- SSH 密钥管理 ---${NC}"
    echo "1. 导入公钥"; echo "2. 禁用密码登录 (危险)"; read -p "选择: " c
    if [[ "$c" == "1" ]]; then
        read -p "用户名: " user
        if ! id "$user" >/dev/null 2>&1; then echo "用户不存在"; return; fi
        read -p "粘贴公钥: " pubkey
        if [[ -n "$pubkey" ]]; then
            local dir="/home/$user/.ssh"
            [[ "$user" == "root" ]] && dir="/root/.ssh"
            mkdir -p "$dir"; echo "$pubkey" >> "$dir/authorized_keys"
            chmod 700 "$dir"; chmod 600 "$dir/authorized_keys"; chown -R "$user:$user" "$dir"
            echo -e "${GREEN}[✓] 公钥已添加。${NC}"
        fi
    elif [[ "$c" == "2" ]]; then
        if confirm_action "确认已测试密钥登录成功？"; then
            update_sshd "PasswordAuthentication" "no"; update_sshd "PubkeyAuthentication" "yes"
            if is_systemd; then systemctl restart sshd || true; fi
            echo -e "${GREEN}[✓] 密码登录已禁用。${NC}"
        fi
    fi
}

change_pwd() {
    read -p "用户名 (默认 root): " user; user=${user:-root}
    echo -e "${BLUE}正在修改 $user 的密码...${NC}"
    passwd "$user"
}

manage_ssh_security() {
    while true; do
        echo -e "\n${CYAN}--- SSH 安全管理 (端口: $CURRENT_SSH_PORT) ---${NC}"
        echo "1. 修改 SSH 端口"; echo "2. 创建 Sudo 用户"; echo "3. 禁用 Root 登录"; echo "4. 密钥/密码设置"; echo "5. 修改用户密码"; echo "0. 返回"
        read -p "选择: " c
        case $c in 1) change_ssh_port ;; 2) create_user ;; 3) disable_root ;; 4) config_keys ;; 5) change_pwd ;; 0) break ;; esac
        [[ $c != 0 ]] && read -p "按 Enter 继续..."
        check_root # 刷新端口
    done
}

# ==============================================================================
# 功能模块：DNS & BBR & 时区
# ==============================================================================

view_current_dns() {
    echo -e "\n${BLUE}[*] 当前 /etc/resolv.conf 内容:${NC}"
    cat /etc/resolv.conf
    if is_systemd && systemctl is-active --quiet systemd-resolved; then
        echo -e "\n${BLUE}[*] Systemd-resolved 状态:${NC}"
        if command_exists resolvectl; then resolvectl status | grep "DNS Servers" -A 2 || true; fi
    fi
}

edit_dns_config() {
    echo -e "\n${CYAN}--- 修改 DNS 配置 ---${NC}"
    echo -e "${YELLOW}请输入新的 DNS IP (多个用空格隔开，如 1.1.1.1 8.8.8.8)${NC}"
    echo -e "${YELLOW}输入 0 或留空 则取消修改${NC}"
    read -p "DNS: " dns_ips
    if [[ -z "$dns_ips" || "$dns_ips" == "0" ]]; then echo "已取消"; return; fi
    
    echo -e "${BLUE}[*] 备份并应用...${NC}"
    cp /etc/resolv.conf /etc/resolv.conf.bak
    local tmp=$(mktemp)
    for ip in $dns_ips; do echo "nameserver $ip" >> "$tmp"; done
    cat "$tmp" > /etc/resolv.conf
    rm -f "$tmp"
    
    if is_systemd && systemctl is-active --quiet systemd-resolved; then
        sed -i '/^DNS=/d' /etc/systemd/resolved.conf
        echo "DNS=$dns_ips" >> /etc/systemd/resolved.conf
        systemctl restart systemd-resolved || true
    fi
    echo -e "${GREEN}[✓] DNS 已修改。${NC}"
    cat /etc/resolv.conf
}

manage_dns() {
    while true; do
        echo -e "\n${CYAN}--- DNS 配置管理 ---${NC}"
        echo "1. 查看当前 DNS"; echo "2. 修改 DNS 配置"; echo "0. 返回"
        read -p "选择: " c
        case $c in 1) view_current_dns ;; 2) edit_dns_config ;; 0) break ;; *) echo "无效选项" ;; esac
        [[ $c != 0 ]] && read -p "按 Enter 继续..."
    done
}

enable_bbr_fq() {
    echo -e "\n${CYAN}--- 开启 BBR + FQ 加速 ---${NC}"
    if confirm_action "确认修改内核参数开启 BBR + FQ?"; then
        sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
        echo -e "${GREEN}[✓] BBR 设置完成。${NC}"
    fi
}

set_timezone() {
    while true; do
        echo -e "\n${CYAN}--- 时区设置 ---${NC}"
        if command_exists timedatectl; then echo "当前: $(timedatectl | grep "Time zone" | awk '{print $3}')"; else echo "当前: $(date)"; fi
        echo "1. 上海 (Asia/Shanghai)"; echo "2. 香港 (Asia/Hong_Kong)"; echo "3. 东京 (Asia/Tokyo)"; echo "4. 伦敦 (Europe/London)"; echo "5. 纽约 (America/New_York)"; echo "6. UTC"; echo "0. 返回"
        read -p "选择: " c
        case $c in
            1) tz="Asia/Shanghai" ;; 2) tz="Asia/Hong_Kong" ;; 3) tz="Asia/Tokyo" ;;
            4) tz="Europe/London" ;; 5) tz="America/New_York" ;; 6) tz="UTC" ;;
            0) break ;; *) echo "无效"; continue ;;
        esac
        if command_exists timedatectl; then timedatectl set-timezone "$tz"; else rm -f /etc/localtime; ln -sf /usr/share/zoneinfo/$tz /etc/localtime; fi
        echo -e "${GREEN}[✓] 时区已设为 $tz${NC}"
    done
}

# ==============================================================================
# 功能模块：Web 服务 (Nginx + SSL) [核心]
# ==============================================================================

prepare_web_env() {
    if ! command_exists nginx; then install_package "nginx"; fi
    if is_systemd; then systemctl enable --now nginx >/dev/null 2>&1 || true; fi
    if ! command_exists certbot; then
        echo -e "${BLUE}[*] 安装 Certbot...${NC}"
        update_apt_cache
        # [防崩] 使用 if ! ... 防止 set -o errtrace 触发 trap
        if ! apt-get install -y certbot python3-certbot-dns-cloudflare; then
            echo -e "${YELLOW}[!] apt 安装失败，尝试 snap...${NC}"
            install_package "snapd" "silent" || true
            if command_exists snap; then
                # 显式允许失败，避免 trap
                if ! snap install --classic certbot; then echo -e "${RED}[✗] Snap Certbot 安装失败。${NC}"; return 1; fi
                if ! snap install certbot-dns-cloudflare; then echo -e "${RED}[✗] Snap Plugin 安装失败。${NC}"; return 1; fi
                snap connect certbot:plugin certbot-dns-cloudflare
                ln -sf /snap/bin/certbot /usr/bin/certbot
            else
                echo -e "${RED}[✗] 无法安装 Certbot (Apt/Snap 均失败)。${NC}"; return 1
            fi
        fi
    fi
}

get_cf_token() {
    DOMAIN=""; CF_API_TOKEN=""; LOCAL_PROXY_PASS=""
    while [[ -z "$DOMAIN" ]]; do read -p "请输入域名: " DOMAIN; done
    if [[ -f "${CONFIG_DIR}/${DOMAIN}.conf" ]]; then echo -e "${YELLOW}配置已存在。请先删除旧配置。${NC}"; return 1; fi
    while [[ -z "$CF_API_TOKEN" ]]; do read -s -p "请输入 Cloudflare API Token (输入不回显): " CF_API_TOKEN; echo ""; done
    mkdir -p "${CERT_PATH_PREFIX}/${DOMAIN}"
    CLOUDFLARE_CREDENTIALS="/root/.cloudflare-${DOMAIN}.ini"
    echo "dns_cloudflare_api_token = $CF_API_TOKEN" > "$CLOUDFLARE_CREDENTIALS"
    chmod 600 "$CLOUDFLARE_CREDENTIALS"
    CERT_PATH="${CERT_PATH_PREFIX}/${DOMAIN}"
    return 0
}

ask_nginx_params() {
    if ! confirm_action "是否配置 Nginx 反向代理?"; then return 1; fi
    while true; do read -p "HTTP 端口 [80]: " p; if [[ -z "$p" ]]; then NGINX_HTTP_PORT=80; break; elif [[ "$p" =~ ^[0-9]+$ ]]; then NGINX_HTTP_PORT=$p; break; fi; done
    while true; do read -p "HTTPS 端口 [443]: " p; if [[ -z "$p" ]]; then NGINX_HTTPS_PORT=443; break; elif [[ "$p" =~ ^[0-9]+$ ]]; then NGINX_HTTPS_PORT=$p; break; fi; done
    echo -e "${YELLOW}提示: 反代 3x-ui/X-UI 面板内部通常选 http${NC}"
    read -p "后端协议 [1] http (默认) [2] https : " proto
    BACKEND_PROTOCOL=$([[ "$proto" == "2" ]] && echo "https" || echo "http")
    while [[ -z "$LOCAL_PROXY_PASS" ]]; do
        read -p "反代目标地址 (如 127.0.0.1:10000): " inp
        if [[ "$inp" =~ ^[0-9]+$ ]]; then echo -e "${YELLOW}[!] 检测到纯端口号，自动补全为 127.0.0.1:$inp${NC}"; inp="127.0.0.1:$inp"; fi
        if [[ "$inp" =~ ^(\[.*\]|[a-zA-Z0-9.-]+):[0-9]+$ ]]; then LOCAL_PROXY_PASS="${BACKEND_PROTOCOL}://${inp}"; echo -e "目标地址确认: ${GREEN}${LOCAL_PROXY_PASS}${NC}"; else echo -e "${YELLOW}地址格式错误 (应为 IP:Port)${NC}"; fi
    done
    return 0
}

apply_nginx_config() {
    local ssl_snip="/etc/nginx/snippets/ssl-params.conf"
    if [[ ! -f "$ssl_snip" ]]; then
        mkdir -p "$(dirname "$ssl_snip")"
        echo "ssl_session_timeout 1d; ssl_session_cache shared:SSL:10m; ssl_protocols TLSv1.2 TLSv1.3; ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384; ssl_prefer_server_ciphers off; add_header Strict-Transport-Security \"max-age=15768000\" always;" > "$ssl_snip"
    fi
    echo -e "${BLUE}[*] 生成 Nginx 配置文件...${NC}"
    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
    NGINX_CONF_PATH="/etc/nginx/sites-available/${DOMAIN}.conf"
    local redir_suf=""; if [[ "${NGINX_HTTPS_PORT}" -ne 443 ]]; then redir_suf=":${NGINX_HTTPS_PORT}"; fi
    cat > "$NGINX_CONF_PATH" <<EOF
# Generated by server-manage.sh (v11.3) for ${DOMAIN}
server {
    listen ${NGINX_HTTP_PORT};
    listen [::]:${NGINX_HTTP_PORT};
    server_name ${DOMAIN};
    location ~ /.well-known/acme-challenge/ { allow all; root /var/www/html; }
    location / { return 301 https://\$host${redir_suf}\$request_uri; }
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
    }
}
EOF
    ln -sf "$NGINX_CONF_PATH" "/etc/nginx/sites-enabled/${DOMAIN}.conf"
    echo -e "${BLUE}[*] 检查 Nginx 配置 (nginx -t)...${NC}"
    if nginx -t; then
        if is_systemd; then systemctl reload nginx || systemctl restart nginx || echo -e "${YELLOW}[!] 重载失败，请检查日志。${NC}"; else nginx -s reload || nginx || echo -e "${YELLOW}[!] 重载失败。${NC}"; fi
        echo -e "${GREEN}[✓] Nginx 服务更新完成。${NC}"
    else echo -e "${RED}[✗] Nginx 配置错误！未重载。请手动检查文件。${NC}"; return 1; fi
}

add_new_domain() {
    echo -e "\n${CYAN}--- 添加域名配置 (SSL + Nginx) ---${NC}"
    # [逻辑] 增加 || return 1，环境准备失败直接返回
    prepare_web_env || return 1
    get_cf_token || return 1
    local do_nginx="n"; if ask_nginx_params; then do_nginx="y"; fi
    echo -e "${BLUE}[*] 申请证书 (Let's Encrypt)...${NC}"
    if certbot certonly --dns-cloudflare --dns-cloudflare-credentials "$CLOUDFLARE_CREDENTIALS" --dns-cloudflare-propagation-seconds 60 -d "$DOMAIN" --email "$EMAIL" --agree-tos --no-eff-email --non-interactive; then
        echo -e "${GREEN}[✓] 证书申请成功。${NC}"
        cp -L "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "${CERT_PATH}/fullchain.pem"
        cp -L "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "${CERT_PATH}/privkey.pem"
        if [[ "$do_nginx" == "y" ]]; then apply_nginx_config; fi
        DEPLOY_HOOK_SCRIPT="/root/cert-renew-hook-${DOMAIN}.sh"
        cat > "$DEPLOY_HOOK_SCRIPT" <<EOF
#!/bin/bash
LOG_FILE="/var/log/cert_renew_${DOMAIN}.log"
log() { echo "[\$(date)] \$1" >> "\$LOG_FILE"; }
mkdir -p "${CERT_PATH}"
cp -L "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "${CERT_PATH}/fullchain.pem"
cp -L "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "${CERT_PATH}/privkey.pem"
log "Cert copied."
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet nginx; then systemctl reload nginx && log "Nginx reloaded (Systemd)" || true; fi
    if systemctl is-active --quiet x-ui; then systemctl restart x-ui && log "x-ui restarted" || true; fi
    if systemctl is-active --quiet 3x-ui; then systemctl restart 3x-ui && log "3x-ui restarted" || true; fi
else
    if command -v nginx >/dev/null 2>&1; then nginx -s reload && log "Nginx reloaded (Native)" || true; fi
fi
EOF
        chmod +x "$DEPLOY_HOOK_SCRIPT"
        mkdir -p "$CONFIG_DIR"; chmod 700 "$CONFIG_DIR"
        echo "DOMAIN=\"${DOMAIN}\"; CERT_PATH=\"${CERT_PATH}\"; DEPLOY_HOOK_SCRIPT=\"${DEPLOY_HOOK_SCRIPT}\"" > "${CONFIG_DIR}/${DOMAIN}.conf"
        chmod 600 "${CONFIG_DIR}/${DOMAIN}.conf"
        (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --deploy-hook \"$DEPLOY_HOOK_SCRIPT\" >> /var/log/certbot_renew.log 2>&1") | sort -u | crontab -
        echo -e "${GREEN}[✓] 域名配置全部完成！${NC}"
    else
        echo -e "${RED}[✗] 证书申请失败。${NC}"; rm -f "$CLOUDFLARE_CREDENTIALS"
    fi
}

check_cert_expiry() {
    echo -e "\n${CYAN}--- 证书监控 ---${NC}"
    for conf in "${CONFIG_DIR}"/*.conf; do
        [[ -f "$conf" ]] || continue
        source "$conf"
        local cert="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
        if [[ -f "$cert" ]]; then
            local end_date=$(openssl x509 -enddate -noout -in "$cert" | cut -d= -f2)
            local days=$(( ($(date +%s -d "$end_date") - $(date +%s)) / 86400 ))
            echo -e "域名: ${GREEN}${DOMAIN}${NC} | 剩余: ${YELLOW}${days}天${NC} | 到期: ${end_date}"
        else echo -e "域名: ${DOMAIN} | ${RED}证书丢失${NC}"; fi
    done
}

manual_renew() {
    echo -e "\n${CYAN}--- 手动续期 ---${NC}"
    local i=1; local domains=()
    for conf in "${CONFIG_DIR}"/*.conf; do
        [[ -f "$conf" ]] || continue
        source "$conf"
        echo "[$i] $DOMAIN"; domains+=("$DOMAIN"); ((i++))
    done
    if [[ ${#domains[@]} -eq 0 ]]; then echo "无配置"; return; fi
    read -p "选择: " idx
    local domain=${domains[$((idx-1))]}
    [[ -z "$domain" ]] && return
    echo "1. 模拟 (Dry Run)  2. 强制 (Force)"
    read -p "选项: " opt
    local hook="/root/cert-renew-hook-${domain}.sh"
    [[ "$opt" == "1" ]] && certbot renew --cert-name "$domain" --dry-run --deploy-hook "$hook"
    [[ "$opt" == "2" ]] && certbot renew --cert-name "$domain" --force-renewal --deploy-hook "$hook"
}

delete_config() {
    echo -e "\n${CYAN}--- 删除配置 ---${NC}"
    echo -e "${YELLOW}请手动执行以下步骤以防止误删:${NC}"
    echo "1. certbot delete --cert-name <域名>"
    echo "2. rm /etc/nginx/sites-enabled/<域名>.conf"
    echo "3. rm ${CONFIG_DIR}/<域名>.conf"
}

manage_web_service() {
    while true; do echo -e "\n${CYAN}--- Web 服务管理 ---${NC}"; echo "1. 添加域名"; echo "2. 证书状态"; echo "3. 手动续期"; echo "4. 删除配置"; echo "0. 返回"; read -p "选项: " c
        case $c in 1) add_new_domain ;; 2) check_cert_expiry ;; 3) manual_renew ;; 4) delete_config ;; 0) break ;; *) echo "无效" ;; esac; [[ $c != 0 ]] && read -p "按 Enter 继续..."
    done
}

# --- 主程序循环 ---
check_root
auto_install_dependencies

while true; do
    echo -e "\n${CYAN}=== 服务器管理脚本 (v11.3 Bulletproof) ===${NC}"
    echo -e " ${YELLOW}1.${NC} 系统信息查询"
    echo -e " ${YELLOW}2.${NC} 手动重装/修复依赖"
    echo -e " ${YELLOW}3.${NC} UFW 防火墙管理"
    echo -e " ${YELLOW}4.${NC} Fail2ban 入侵防御"
    echo -e " ${YELLOW}5.${NC} SSH 安全管理 (端口: ${YELLOW}${CURRENT_SSH_PORT}${NC})"
    echo -e " ${YELLOW}6.${NC} DNS 配置管理"
    echo -e " ${YELLOW}7.${NC} 开启 BBR + FQ"
    echo -e " ${YELLOW}8.${NC} 调整系统时区"
    echo -e " ${YELLOW}9.${NC} Web 服务 (SSL/Nginx)"
    echo -e " ${YELLOW}0.${NC} 退出脚本"
    read -p "请输入选项: " choice
    
    case $choice in
        1) output_status ;; 2) reinstall_common_tools ;; 3) manage_ufw ;; 4) manage_fail2ban ;; 5) manage_ssh_security ;;
        6) manage_dns ;; 7) enable_bbr_fq ;; 8) set_timezone ;; 9) manage_web_service ;; 0) echo "再见。"; exit 0 ;;
        *) echo "无效选项" ;;
    esac
    [[ $choice != 0 ]] && read -p "按 Enter 键继续..."
done
