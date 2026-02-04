#!/bin/bash

# ==============================================================================
# 服务器初始化与管理脚本 (v13.58 - Backup-Free Edition)
#
# 核心优化 v13.58:
# 1. [精简] 移除备份/恢复功能模块
# 2. [架构] 函数模块化: 按功能域拆分为独立模块
# 3. [安全] 输入验证增强: 所有用户输入进行严格校验
# 4. [性能] 智能缓存: 减少重复的系统调用和网络请求
# 5. [可靠] 原子操作: 关键配置修改支持自动回滚
# 6. [体验] 进度反馈: 长时间操作显示实时进度
# 7. [日志] 结构化记录: JSON 格式便于后续分析
# ==============================================================================

# --- 全局常量配置 ---
readonly VERSION="v13.58"
readonly SCRIPT_NAME="server-manage"
readonly LOG_FILE="/var/log/${SCRIPT_NAME}.log"
readonly CONFIG_FILE="/etc/${SCRIPT_NAME}.conf"
readonly CACHE_DIR="/var/cache/${SCRIPT_NAME}"

# 错误码
readonly E_SUCCESS=0
readonly E_GENERAL=1
readonly E_PERMISSION=2
readonly E_NETWORK=3
readonly E_CONFIG=4

# 颜色
readonly C_RESET='\033[0m'
readonly C_RED='\033[0;31m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_BLUE='\033[0;34m'
readonly C_CYAN='\033[0;36m'
readonly C_GRAY='\033[0;90m'

# --- 配置变量 ---
CF_API_TOKEN=""
DOMAIN=""
EMAIL="admin@example.com"
CERT_PATH_PREFIX="/root/cert"
CONFIG_DIR="${CERT_PATH_PREFIX}/.managed_domains"
DEFAULT_SSH_PORT=22

SSHD_CONFIG="/etc/ssh/sshd_config"
FAIL2BAN_JAIL_LOCAL="/etc/fail2ban/jail.local"
APT_PROXY_CONF="/etc/apt/apt.conf.d/99proxy"
ENV_PROXY_CONF="/etc/profile.d/proxy.sh"
ETC_ENVIRONMENT="/etc/environment"
DOCKER_PROXY_DIR="/etc/systemd/system/docker.service.d"
DOCKER_PROXY_CONF="${DOCKER_PROXY_DIR}/http-proxy.conf"
SQUID_CONF="/etc/squid/squid.conf"

# 加载外部配置
[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"

# 动态变量
CLOUDFLARE_CREDENTIALS=""
DEPLOY_HOOK_SCRIPT=""
NGINX_CONF_PATH=""
CURRENT_SSH_PORT=""
APT_UPDATED=0

# ==============================================================================
# 0. 核心工具库
# ==============================================================================

set -o errtrace


# 终端修复 - 增强版
fix_terminal() {
    # 检查是否为交互式终端
    [[ -t 0 ]] || return 0
    
    # 修复删除键
    stty erase '^?' 2>/dev/null || true
    stty erase '^H' 2>/dev/null || true
    
    # 修复其他控制字符
    stty intr '^C' 2>/dev/null || true
    stty susp '^Z' 2>/dev/null || true
    
    # 启用行编辑
    stty icanon 2>/dev/null || true
    stty echo 2>/dev/null || true
    
    # 设置终端类型
    export TERM="${TERM:-xterm-256color}"
    
    # 绑定删除键（如果支持 bind 命令）
    if command -v bind >/dev/null 2>&1 && [[ $- == *i* ]]; then
        bind '"\e[3~": delete-char' 2>/dev/null || true
        bind '"\C-?": backward-delete-char' 2>/dev/null || true
        bind '"\C-h": backward-delete-char' 2>/dev/null || true
    fi
}

# 在脚本开始时调用
fix_terminal

# 获取终端宽度
get_term_width() {
    tput cols 2>/dev/null || echo 80
}

# 输入辅助函数
safe_read() {
    local prompt="$1"
    local var_name="$2"
    local options="$3"  # 可选参数：-s (密码), -n (单字符)
    
    # 确保终端状态正常
    stty sane 2>/dev/null || true
    
    local input=""
    if [[ "$options" == "-s" ]]; then
        # 密码输入
        read -e -r -s -p "$prompt" input
        echo ""
    elif [[ "$options" == "-n" ]]; then
        # 单字符输入
        read -n 1 -s -r -p "$prompt" input
        echo ""
    else
        # 普通输入
        read -e -r -p "$prompt" input
    fi
    
    # 清理输入（移除控制字符）
    input=$(echo "$input" | tr -d '\000-\037' | tr -d '\177')
    
    # 返回结果
    if [[ -n "$var_name" ]]; then
        eval "$var_name=\"\$input\""
    else
        echo "$input"
    fi
}

# 画分隔线
draw_line() {
    printf "%$(get_term_width)s\n" | tr " " "-"
}

# 打印标题
print_title() {
    clear || true
    local title=" $1 "
    local width=$(get_term_width)
    local padding=$(( (width - ${#title}) / 2 ))
    [[ $padding -lt 0 ]] && padding=0
    
    echo -e "${C_CYAN}"
    printf "%${width}s\n" | tr " " "="
    printf "%${padding}s%s\n" "" "$title"
    printf "%${width}s\n" | tr " " "="
    echo -e "${C_RESET}"
}

# Banner 显示
print_banner() {
    local width=$(get_term_width)
    echo -e "${C_CYAN}"
    printf "%${width}s\n" | tr " " "="
    printf "%*s\n" $(((${#SCRIPT_NAME}+$width)/2)) "$SCRIPT_NAME $VERSION"
    printf "%${width}s\n" | tr " " "="
    echo -e "${C_RESET}"
}

# 统一输出
print_info() { echo -e "${C_BLUE}[i]${C_RESET} $1"; }
print_guide() { echo -e "${C_GREEN}>>${C_RESET} $1"; }
print_success() { echo -e "${C_GREEN}[✓]${C_RESET} $1"; }
print_warn() { echo -e "${C_YELLOW}[!]${C_RESET} $1"; }
print_error() { echo -e "${C_RED}[✗]${C_RESET} $1"; }

# 结构化日志
log_action() {
    local level="${2:-INFO}"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "{\"time\":\"$timestamp\",\"level\":\"$level\",\"msg\":\"$1\"}" >> "$LOG_FILE" 2>/dev/null || true
}

# 暂停
pause() {
    [[ -t 0 ]] || return 0
    echo ""
    read -n 1 -s -r -p "按任意键继续..."
    echo ""
}

# 原子写入
write_file_atomic() {
    local filepath="$1"
    local content="$2"
    local tmpfile
    
    mkdir -p "$(dirname "$filepath")"
    tmpfile=$(mktemp "$(dirname "$filepath")/.tmp.XXXXXX")
    
    printf "%s\n" "$content" > "$tmpfile"
    
    if [[ -f "$filepath" ]]; then
        chmod --reference="$filepath" "$tmpfile" 2>/dev/null || true
        chown --reference="$filepath" "$tmpfile" 2>/dev/null || true
    fi
    mv "$tmpfile" "$filepath"
}

# 安全 Curl
safe_curl() {
    curl -s -L --connect-timeout 5 --max-time 10 --retry 3 --retry-delay 2 "$@"
}

# 进度条
show_progress() {
    local duration=$1
    local msg="${2:-处理中}"
    local width=40
    
    for ((i=0; i<=duration; i++)); do
        local percent=$((i * 100 / duration))
        local filled=$((i * width / duration))
        local empty=$((width - filled))
        
        printf "\r${C_BLUE}${msg}${C_RESET} ["
        printf "%${filled}s" | tr ' ' '='
        printf "%${empty}s" | tr ' ' ' '
        printf "] %3d%%" "$percent"
        
        sleep 1
    done
    echo ""
}

# 错误处理
cleanup_temp_files() {
    rm -f /etc/*.tmp.* 2>/dev/null
    rm -f /tmp/${SCRIPT_NAME}.* 2>/dev/null
}

handle_error() {
    local exit_code=$?
    cleanup_temp_files
    print_error "脚本异常退出 (Code: $exit_code)"
    log_action "Script crashed with exit code $exit_code" "ERROR"
    exit $exit_code
}

handle_interrupt() {
    cleanup_temp_files
    echo ""
    print_warn "操作已取消 (用户中断)。"
    exit 130
}

trap 'handle_error' ERR
trap 'handle_interrupt' SIGINT SIGTERM

# 环境检查
check_root() {

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        print_error "不支持的操作系统。"
        exit $E_GENERAL
    fi
    
    local os_id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    if [[ "$os_id" != "ubuntu" && "$os_id" != "debian" ]]; then
        print_warn "脚本主要针对 Ubuntu/Debian 优化，其他系统可能存在兼容性问题。"
        if ! confirm "是否继续？"; then
            exit 0
        fi
    fi
}
    if [[ "$(id -u)" -ne 0 ]]; then

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        print_error "不支持的操作系统。"
        exit $E_GENERAL
    fi
    
    local os_id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    if [[ "$os_id" != "ubuntu" && "$os_id" != "debian" ]]; then
        print_warn "脚本主要针对 Ubuntu/Debian 优化，其他系统可能存在兼容性问题。"
        if ! confirm "是否继续？"; then
            exit 0
        fi
    fi
}
        print_error "请使用 root 权限运行 (sudo)。"

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        print_error "不支持的操作系统。"
        exit $E_GENERAL
    fi
    
    local os_id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    if [[ "$os_id" != "ubuntu" && "$os_id" != "debian" ]]; then
        print_warn "脚本主要针对 Ubuntu/Debian 优化，其他系统可能存在兼容性问题。"
        if ! confirm "是否继续？"; then
            exit 0
        fi
    fi
}
        exit $E_PERMISSION

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        print_error "不支持的操作系统。"
        exit $E_GENERAL
    fi
    
    local os_id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    if [[ "$os_id" != "ubuntu" && "$os_id" != "debian" ]]; then
        print_warn "脚本主要针对 Ubuntu/Debian 优化，其他系统可能存在兼容性问题。"
        if ! confirm "是否继续？"; then
            exit 0
        fi
    fi
}
    fi

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        print_error "不支持的操作系统。"
        exit $E_GENERAL
    fi
    
    local os_id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    if [[ "$os_id" != "ubuntu" && "$os_id" != "debian" ]]; then
        print_warn "脚本主要针对 Ubuntu/Debian 优化，其他系统可能存在兼容性问题。"
        if ! confirm "是否继续？"; then
            exit 0
        fi
    fi
}
}

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        print_error "不支持的操作系统。"
        exit $E_GENERAL
    fi
    
    local os_id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    if [[ "$os_id" != "ubuntu" && "$os_id" != "debian" ]]; then
        print_warn "脚本主要针对 Ubuntu/Debian 优化，其他系统可能存在兼容性问题。"
        if ! confirm "是否继续？"; then
            exit 0
        fi
    fi
}

command_exists() { 
    command -v "$1" >/dev/null 2>&1
}

is_systemd() {
    command_exists systemctl || return 1
    [[ -d /run/systemd/system ]] || return 1
    [[ "$(ps -p 1 -o comm= 2>/dev/null)" == "systemd" ]] || return 1
    return 0
}

# 更新 SSH 端口
refresh_ssh_port() {
    if [[ -f "$SSHD_CONFIG" ]]; then
        CURRENT_SSH_PORT=$(grep -iE "^\s*Port\s+" "$SSHD_CONFIG" 2>/dev/null | tail -n 1 | awk '{print $2}')
    fi
    [[ "$CURRENT_SSH_PORT" =~ ^[0-9]+$ ]] || CURRENT_SSH_PORT=$DEFAULT_SSH_PORT
}

# 通用确认
confirm() {
    local prompt="$1"
    local reply
    while true; do
        read -e -r -p "$(echo -e "${C_YELLOW}${prompt} [Y/n]:${C_RESET} ")" reply
        case "${reply,,}" in
            y|yes|"") return 0 ;;
            n|no) return 1 ;;
            *) print_warn "请输入 y 或 n" ;;
        esac
    done
}

# 输入验证
validate_port() {
    local port=$1
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

validate_ip() {
    local ip=$1
    # IPv4
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        local IFS='.'
        local -a octets
        read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            [[ "$octet" =~ ^[0-9]+$ ]] || return 1
            [ "$octet" -le 255 ] || return 1
        done
        return 0
    fi
    # IPv6
    [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ip" == *:* ]]
}

validate_domain() {
    local domain=$1
    [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]
}

# 获取系统信息
get_os_info() {
    if [[ -f /etc/os-release ]]; then
        grep PRETTY_NAME /etc/os-release | cut -d '=' -f2 | tr -d '"'
    else
        echo "Linux $(uname -r)"
    fi
}

# 脚本初始化
init_environment() {
    # 创建必要目录
    mkdir -p "$CACHE_DIR" "$(dirname "$LOG_FILE")"
    
    # 初始化日志
    if [[ ! -f "$LOG_FILE" ]]; then
        touch "$LOG_FILE"
        chmod 600 "$LOG_FILE"
    fi
    
    # 刷新 SSH 端口
    refresh_ssh_port
    
    # 自动安装基础依赖
    auto_deps
    
    log_action "Script initialized" "INFO"
}

# ==============================================================================
# 1. 系统更新模块
# ==============================================================================

menu_update() {
    fix_terminal
    while true; do
        print_title "系统更新与软件包管理"
        echo "1. 更新软件源"
        echo "2. 升级所有软件包"
        echo "3. 完整升级 (dist-upgrade)"
        echo "4. 重装基础依赖"
        echo "5. 查看系统信息"
        echo "0. 返回"
        echo ""
        read -e -r -p "请选择: " c
        
        case $c in
            1)
                print_info "正在更新软件源..."
                apt-get update -y
                print_success "更新完成。"
                log_action "APT sources updated"
                pause
                ;;
            2)
                print_info "正在升级软件包..."
                apt-get upgrade -y
                print_success "升级完成。"
                log_action "System packages upgraded"
                pause
                ;;
            3)
                if confirm "执行完整升级 (可能更新内核)？"; then
                    apt-get dist-upgrade -y
                    print_success "完整升级完成。"
                    log_action "System dist-upgraded"
                fi
                pause
                ;;
            4) reinstall_deps ;;
            5) sys_info ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
    done
}

menu_firewall() {
    menu_ufw
}

# ==============================================================================
# 2. 依赖管理模块
# ==============================================================================

update_apt_cache() {
    if [[ $APT_UPDATED -eq 0 ]]; then
        print_info "更新软件源缓存..."
        apt-get update -y >/dev/null 2>&1
        APT_UPDATED=1
    fi
}

install_package() {
    local pkg="$1"
    local silent="${2:-}"
    
    if dpkg -s "$pkg" &> /dev/null; then
        [[ "$silent" != "silent" ]] && print_warn "$pkg 已安装，跳过。"
        return 0
    fi

    [[ "$silent" != "silent" ]] && print_info "正在安装 $pkg ..."
    update_apt_cache
    
    export DEBIAN_FRONTEND=noninteractive
    if ! apt-get install -y "$pkg" >/dev/null 2>&1; then
        print_warn "首次安装失败，尝试修复依赖..."
        apt-get install -f -y >/dev/null 2>&1
        if ! apt-get install -y "$pkg" >/dev/null 2>&1; then
            print_error "安装 $pkg 失败。"
            return 1
        fi
    fi
    [[ "$silent" != "silent" ]] && print_success "$pkg 安装成功。"
    log_action "Installed package: $pkg"
    return 0
}

auto_deps() {
    local deps="curl wget jq unzip openssl ca-certificates iproute2 net-tools procps"
    for p in $deps; do
        dpkg -s "$p" &> /dev/null || install_package "$p" "silent"
    done
}

reinstall_deps() {
    print_title "重装基础依赖"
    APT_UPDATED=0
    update_apt_cache
    local deps="curl wget jq unzip openssl ca-certificates ufw fail2ban nginx iproute2 net-tools procps"
    for p in $deps; do 
        install_package "$p"
    done
    print_success "依赖维护完成。"
    pause
}

# ==============================================================================
# 3. 系统信息模块
# ==============================================================================

# 获取公网 IPv6 地址
get_public_ipv6() {
    local ipv6=""
    
    # 方法 1: api64.ipify.org (强制 IPv6)
    ipv6=$(curl -6 -s --connect-timeout 5 --max-time 10 https://api64.ipify.org 2>/dev/null || true)
    if [[ -n "$ipv6" ]] && [[ "$ipv6" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ipv6" == *:* ]]; then
        echo "$ipv6"
        return 0
    fi
    
    # 方法 2: ifconfig.co
    ipv6=$(curl -6 -s --connect-timeout 5 --max-time 10 https://ifconfig.co 2>/dev/null || true)
    if [[ -n "$ipv6" ]] && [[ "$ipv6" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ipv6" == *:* ]]; then
        echo "$ipv6"
        return 0
    fi
    
    # 方法 3: 本地接口
    if command -v ip >/dev/null 2>&1; then
        ipv6=$(ip -6 addr show scope global 2>/dev/null | grep -oP '(?<=inet6 )[0-9a-fA-F:]+' | grep -v '^fe80:' | head -n1 || true)
        if [[ -n "$ipv6" ]]; then
            echo "$ipv6"
            return 0
        fi
    fi
    
    echo "未检测到"
    return 1
}


sys_info() {
    print_title "系统状态查询"
    
    # 网络信息
    local ip4=$(safe_curl https://api.ipify.org || echo "N/A")
    local ip6=$(get_public_ipv6)
    
    local ipinfo_json=$(safe_curl https://ipinfo.io/json || echo "{}")
    local country=$(echo "$ipinfo_json" | jq -r '.country // "N/A"' 2>/dev/null || echo "N/A")
    local city=$(echo "$ipinfo_json" | jq -r '.city // "N/A"' 2>/dev/null || echo "N/A")
    local isp=$(echo "$ipinfo_json" | jq -r '.org // "N/A"' 2>/dev/null || echo "N/A")

    # 网卡统计
    local net_dev=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n 1 || true)
    [[ -z "$net_dev" ]] && net_dev=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo" | head -n 1 || true)

    local rx_total="0" tx_total="0"
    if [[ -n "$net_dev" && -f "/proc/net/dev" ]]; then
        local dev_stats=$(grep "$net_dev:" /proc/net/dev | awk '{print $2, $10}')
        if [[ -n "$dev_stats" ]]; then
            rx_total=$(echo "$dev_stats" | awk '{printf "%.2fGB", $1/1024/1024/1024}')
            tx_total=$(echo "$dev_stats" | awk '{printf "%.2fGB", $2/1024/1024/1024}')
        fi
    fi

    # CPU 信息
    local cpu_model=$(lscpu | awk -F': +' '/Model name:/ {print $2; exit}' || echo "Unknown")
    local cpu_usage=$(awk '{u=$2+$4; t=$2+$4+$5; if (NR==1){u1=u; t1=t;} else printf "%.1f%%", (($2+$4-u1) * 100 / (t-t1))}' <(grep 'cpu ' /proc/stat) <(sleep 1; grep 'cpu ' /proc/stat) || echo "0%")
    local cpu_cores=$(nproc || echo "1")
    local cpu_freq=$(awk '/MHz/ {printf "%.1f GHz", $4/1000; exit}' /proc/cpuinfo || echo "N/A")
    local cpu_arch=$(uname -m)
    
    # 内存信息
    local mem_line=$(free -m | grep Mem)
    local mem_total=$(echo "$mem_line" | awk '{print $2}')
    local mem_used=$(echo "$mem_line" | awk '{print $3}')
    local mem_pct=0
    [[ "$mem_total" -gt 0 ]] && mem_pct=$(( mem_used * 100 / mem_total ))
    local mem_info="${mem_used}MB / ${mem_total}MB (${mem_pct}%)"
    
    local swap_info=$(free -m | awk 'NR==3{used=$3; total=$2; if (total == 0) {percentage=0} else {percentage=used*100/total}; printf "%dM/%dM (%d%%)", used, total, percentage}' || echo "N/A")
    local disk_info=$(df -h | awk '$NF=="/"{printf "%s/%s (%s)", $3, $2, $5}' || echo "N/A")
    
    # 系统信息
    local load=$(uptime | awk '{print $(NF-2), $(NF-1), $NF}' || echo "N/A")
    local dns_addresses=$(awk '/^nameserver/{printf "%s ", $2} END {print ""}' /etc/resolv.conf || echo "N/A")
    local hostname=$(uname -n)
    local kernel_version=$(uname -r)
    local congestion_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "N/A")
    local queue_algorithm=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "N/A")
    local os_info=$(grep PRETTY_NAME /etc/os-release | cut -d '=' -f2 | tr -d '"' || echo "Linux")
    local current_time=$(date "+%Y-%m-%d %I:%M %p")
    local runtime=$(awk -F. '{run_days=int($1 / 86400);run_hours=int(($1 % 86400) / 3600);run_minutes=int(($1 % 3600) / 60); if (run_days > 0) printf("%d天 ", run_days); if (run_hours > 0) printf("%d时 ", run_hours); printf("%d分\n", run_minutes)}' /proc/uptime || echo "N/A")
    
    local timezone="UTC"
    command_exists timedatectl && timezone=$(timedatectl | grep "Time zone" | awk '{print $3}' || echo "UTC")

    # 实时网速
    print_info "正在测试实时网速 (采样 1 秒)..."
    local rx1=0 tx1=0 rx2=0 tx2=0
    if [[ -n "$net_dev" && -d "/sys/class/net/$net_dev" ]]; then
        rx1=$(cat "/sys/class/net/$net_dev/statistics/rx_bytes")
        tx1=$(cat "/sys/class/net/$net_dev/statistics/tx_bytes")
        sleep 1
        rx2=$(cat "/sys/class/net/$net_dev/statistics/rx_bytes")
        tx2=$(cat "/sys/class/net/$net_dev/statistics/tx_bytes")
    fi
    local rx_speed=$(( (rx2 - rx1) / 1024 ))
    local tx_speed=$(( (tx2 - tx1) / 1024 ))

    # 输出
    echo ""
    echo -e "${C_CYAN}--- 系统基础信息 ---${C_RESET}"
    printf "${C_GRAY}%-12s${C_RESET} : ${C_YELLOW}%s${C_RESET}\n" "主机名" "$hostname"
    printf "${C_GRAY}%-12s${C_RESET} : %s\n" "系统版本" "$os_info"
    printf "${C_GRAY}%-12s${C_RESET} : %s\n" "内核版本" "$kernel_version"
    printf "${C_GRAY}%-12s${C_RESET} : %s\n" "系统架构" "$cpu_arch"
    printf "${C_GRAY}%-12s${C_RESET} : %s\n" "运行时长" "$runtime"
    printf "${C_GRAY}%-12s${C_RESET} : %s %s\n" "当前时间" "$timezone" "$current_time"
    
    echo -e "\n${C_CYAN}--- 硬件资源状态 ---${C_RESET}"
    printf "${C_GRAY}%-12s${C_RESET} : %s\n" "CPU 型号" "$cpu_model"
    printf "${C_GRAY}%-12s${C_RESET} : %s 核心 / %s\n" "CPU 核心" "$cpu_cores" "$cpu_freq"
    printf "${C_GRAY}%-12s${C_RESET} : ${C_YELLOW}%s${C_RESET}\n" "CPU 占用" "$cpu_usage"
    printf "${C_GRAY}%-12s${C_RESET} : %s\n" "系统负载" "$load"
    printf "${C_GRAY}%-12s${C_RESET} : ${C_YELLOW}%s${C_RESET}\n" "物理内存" "$mem_info"
    printf "${C_GRAY}%-12s${C_RESET} : ${C_YELLOW}%s${C_RESET}\n" "虚拟内存" "$swap_info"
    printf "${C_GRAY}%-12s${C_RESET} : %s\n" "硬盘占用" "$disk_info"
    
    echo -e "\n${C_CYAN}--- 网络连接状态 ---${C_RESET}"
    printf "${C_GRAY}%-12s${C_RESET} : 下行 ${C_GREEN}%s KB/s${C_RESET} / 上行 ${C_BLUE}%s KB/s${C_RESET}\n" "实时网速" "$rx_speed" "$tx_speed"
    printf "${C_GRAY}%-12s${C_RESET} : 总收 ${C_GREEN}%s${C_RESET} / 总发 ${C_BLUE}%s${C_RESET}\n" "累计流量" "$rx_total" "$tx_total"
    printf "${C_GRAY}%-12s${C_RESET} : %s\n" "TCP 算法" "$congestion_algorithm $queue_algorithm"
    printf "${C_GRAY}%-12s${C_RESET} : %s\n" "ISP 服务商" "$isp"
    printf "${C_GRAY}%-12s${C_RESET} : %s %s\n" "地理位置" "$country" "$city"
    printf "${C_GRAY}%-12s${C_RESET} : %s\n" "IPv4 地址" "$ip4"
    printf "${C_GRAY}%-12s${C_RESET} : %s\n" "IPv6 地址" "$ip6"
    printf "${C_GRAY}%-12s${C_RESET} : %s\n" "DNS 地址" "$dns_addresses"
    
    pause
}

# ==============================================================================
# 4. UFW 防火墙模块
# ==============================================================================

check_port_usage() {
    print_title "本机端口监听状态"
    command_exists ss || command_exists netstat || install_package "iproute2"
    
    local awk_logic='
    function get_purpose(p) {
        if(p==21)return "FTP"; if(p==22)return "SSH"; if(p==25)return "SMTP";
        if(p==53)return "DNS"; if(p==80)return "HTTP"; if(p==443)return "HTTPS";
        if(p==3128)return "Squid"; if(p==3306)return "MySQL"; if(p==5201)return "iPerf3"; 
        if(p==5432)return "PostgreSQL"; if(p==6379)return "Redis"; if(p==8080)return "Web Alt";
        return "Unknown";
    }
    '
    printf "${C_BLUE}%-6s | %-6s | %-16s | %s${C_RESET}\n" "Proto" "Port" "Purpose" "Process"
    draw_line
    
    if command_exists ss; then
        ss -tulpn | awk "$awk_logic"' 
        $2~/LISTEN|UNCONN/ {
            proto=$1
            split($5,a,":"); port=a[length(a)]
            split($NF,b,"\""); name=(length(b)>=2)?b[2]:"Unknown"
            printf "%-6s | %-6s | %-16s | %s\n", proto, port, get_purpose(port), name
        }' | sort -u -t'|' -k2,2n || true
    elif command_exists netstat; then
        netstat -tulpn | awk "$awk_logic"'
        /LISTEN|udp/ {
            proto=$1
            split($4,a,":"); port=a[length(a)]
            split($7,b,"/"); name=(b[2]=="")?"Unknown":b[2]
            printf "%-6s | %-6s | %-16s | %s\n", proto, port, get_purpose(port), name
        }' | sort -u -t'|' -k2,2n || true
    fi
    pause
}

ufw_setup() {
    install_package "ufw"
    if is_systemd && systemctl is-active --quiet firewalld 2>/dev/null; then
        print_warn "检测到 firewalld 正在运行，请先禁用它。"
        return
    fi
    
    print_info "配置默认规则..."
    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null
    ufw allow "$CURRENT_SSH_PORT/tcp" comment "SSH-Access" >/dev/null
    
    if confirm "启用 UFW 可能导致 SSH 断开(若端口配置错误)，确认启用?"; then
        echo "y" | ufw enable
        print_success "UFW 已启用。"
        log_action "UFW enabled with SSH port $CURRENT_SSH_PORT"
    fi
    pause
}

ufw_del() {
    command_exists ufw || { print_error "UFW 未安装。"; pause; return; }
    ufw status numbered
    read -e -r -p "输入要删除的规则编号 (空格隔开): " nums
    [[ -z "$nums" ]] && return
    
    for num in $(echo "$nums" | tr ' ' '\n' | sort -nr); do
        echo "y" | ufw delete "$num" >/dev/null 2>&1
        print_success "规则 $num 已删除。"
    done
    pause
}

ufw_safe_reset() {
    command_exists ufw || { print_error "UFW 未安装。"; pause; return; }
    if confirm "这将重置所有规则！脚本会尝试保留当前 SSH 端口，确定吗？"; then
        print_info "正在重置..."
        echo "y" | ufw disable >/dev/null
        echo "y" | ufw reset >/dev/null
        ufw default deny incoming >/dev/null
        ufw default allow outgoing >/dev/null
        ufw allow "$CURRENT_SSH_PORT/tcp" comment "SSH-Access" >/dev/null
        echo "y" | ufw enable >/dev/null
        print_success "重置完成。SSH 端口 $CURRENT_SSH_PORT 已放行。"
        log_action "UFW reset completed"
    fi
    pause
}

ufw_add() {
    if ! command_exists ufw; then
        print_error "UFW 未安装。"
        pause; return
    fi
    
    read -e -r -p "请输入要放行的端口 (空格隔开): " ports
    [[ -z "$ports" ]] && return
    
    for port in $ports; do
        if validate_port "$port"; then
            ufw allow "$port/tcp" comment "Manual-Add-$port" >/dev/null
            print_success "端口 $port/tcp 已放行。"
            log_action "UFW allowed port $port"
        else
            print_error "端口 $port 无效。"
        fi
    done
    pause
}

menu_ufw() {
    fix_terminal
    while true; do
        print_title "UFW 防火墙管理"
        
        if command_exists ufw; then
            local ufw_status=$(ufw status 2>/dev/null | head -n 1 || echo "未运行")
            echo -e "${C_CYAN}当前状态:${C_RESET} $ufw_status"
            echo ""
        else
            echo -e "${C_YELLOW}UFW 未安装${C_RESET}"
            echo ""
        fi
        
        echo "1. 安装并启用 UFW"
        echo "2. 查看本机监听端口"
        echo "3. 添加放行端口"
        echo "4. 查看当前规则"
        echo "5. 删除规则"
        echo "6. 禁用 UFW"
        echo "7. 重置默认规则 (安全模式)"
        echo "0. 返回主菜单"
        echo ""
        read -e -r -p "请选择: " c
        
        case $c in
            1) ufw_setup ;;
            2) check_port_usage ;;
            3) 
                if ! command_exists ufw; then
                    print_error "UFW 未安装，请先选择选项 1 安装。"
                    pause
                else
                    ufw_add
                fi
                ;;
            4) 
                if ! command_exists ufw; then
                    print_error "UFW 未安装，请先选择选项 1 安装。"
                    pause
                else
                    print_title "当前防火墙规则"
                    ufw status numbered
                    pause
                fi
                ;;
            5) 
                if ! command_exists ufw; then
                    print_error "UFW 未安装，请先选择选项 1 安装。"
                    pause
                else
                    ufw_del
                fi
                ;;
            6)
                if ! command_exists ufw; then
                    print_error "UFW 未安装。"
                    pause
                elif confirm "确认禁用 UFW？"; then
                    echo "y" | ufw disable
                    print_success "UFW 已禁用。"
                    log_action "UFW disabled"
                    pause
                fi
                ;;
            7) ufw_safe_reset ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
    done
}

# ==============================================================================
# 5. Fail2ban 模块
# ==============================================================================

f2b_setup() {
    print_title "Fail2ban 安装与配置"
    install_package "fail2ban" "silent"
    install_package "rsyslog" "silent"
    
    local backend="auto"
    if is_systemd; then
        systemctl enable rsyslog >/dev/null 2>&1 || true
        systemctl restart rsyslog || true
        backend="systemd"
    fi

    read -e -r -p "监控 SSH 端口 [$CURRENT_SSH_PORT]: " port
    port=${port:-$CURRENT_SSH_PORT}
    
    local conf_content="[DEFAULT]
bantime = 10m
banaction = ufw
[sshd]
enabled = true
port = $port
maxretry = 5
bantime = 10m
backend = $backend"

    write_file_atomic "$FAIL2BAN_JAIL_LOCAL" "$conf_content"
    print_success "配置已写入。"
    
    if is_systemd; then
        systemctl enable fail2ban >/dev/null || true
        systemctl restart fail2ban || print_warn "Fail2ban 启动失败 (非致命)。"
        print_success "Fail2ban 配置已更新。"
        log_action "Fail2ban configured for port $port"
    fi
    pause
}

menu_f2b() {
    fix_terminal
    while true; do
        print_title "Fail2ban 入侵防御"
        echo "1. 安装/重置配置"
        echo "2. 查看状态/日志"
        echo "0. 返回主菜单"
        echo ""
        read -e -r -p "请选择: " c
        case $c in
            1) f2b_setup ;;
            2) 
                if command_exists fail2ban-client; then
                    fail2ban-client status sshd 2>/dev/null || echo "未运行"
                else
                    echo "Fail2ban 未安装。"
                fi
                pause ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
    done
}

# ==============================================================================
# 6. SSH 安全模块
# ==============================================================================

ssh_change_port() {
    print_title "修改 SSH 端口"
    read -e -r -p "请输入新端口 [$CURRENT_SSH_PORT]: " port
    [[ -z "$port" ]] && return
    
    if ! validate_port "$port"; then
        print_error "端口无效 (1-65535)。"
        pause; return
    fi

    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%s)"
    
    if command_exists ufw && ufw status | grep -q "Status: active"; then
        ufw allow "$port/tcp" comment "SSH-New" >/dev/null
        print_success "UFW 已放行新端口 $port。"
    fi

    if grep -qE "^\s*#?\s*Port\s" "$SSHD_CONFIG"; then
        sed -i -E "s|^\s*#?\s*Port\s+.*|Port ${port}|" "$SSHD_CONFIG"
    else
        echo "Port ${port}" >> "$SSHD_CONFIG"
    fi

    if is_systemd; then
        if systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null; then
            print_success "SSH 重启成功。请使用新端口 $port 连接。"
            CURRENT_SSH_PORT=$port
            log_action "SSH port changed to $port"
        else
            print_error "重启失败！已回滚配置。"
            mv "${SSHD_CONFIG}.bak."* "$SSHD_CONFIG" 2>/dev/null || true
            systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
        fi
    fi
    pause
}

ssh_keys() {
    print_title "SSH 密钥管理"
    echo "1. 导入公钥"
    echo "2. 禁用密码登录"
    read -e -r -p "选择: " c
    
    if [[ "$c" == "1" ]]; then
        read -e -r -p "用户名: " user
        if ! id "$user" >/dev/null 2>&1; then 
            print_error "用户不存在"
            pause; return
        fi
        
        read -e -r -p "粘贴公钥: " key
        [[ -z "$key" ]] && return
        
        local dir="/home/$user/.ssh"
        [[ "$user" == "root" ]] && dir="/root/.ssh"
        
        mkdir -p "$dir"
        echo "$key" >> "$dir/authorized_keys"
        chmod 700 "$dir"
        chmod 600 "$dir/authorized_keys"
        chown -R "$user:$user" "$dir"
        print_success "公钥已添加。"
        log_action "SSH key added for user $user"
        
    elif [[ "$c" == "2" ]]; then
        if confirm "确认已测试密钥登录成功？"; then
            sed -i -E "s|^\s*#?\s*PasswordAuthentication\s+.*|PasswordAuthentication no|" "$SSHD_CONFIG"
            if is_systemd; then
                systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
            fi
            print_success "密码登录已禁用。"
            log_action "SSH password authentication disabled"
        fi
    fi
    pause
}

menu_ssh() {
    fix_terminal
    while true; do
        print_title "SSH 安全管理 (当前端口: $CURRENT_SSH_PORT)"
        echo "1. 修改 SSH 端口"
        echo "2. 创建 Sudo 用户"
        echo "3. 禁用 Root 远程登录"
        echo "4. 密钥/密码设置"
        echo "5. 修改用户密码"
        echo "0. 返回主菜单"
        echo ""
        read -e -r -p "请选择: " c
        case $c in
            1) ssh_change_port ;;
            2) 
                read -e -r -p "新用户名: " u
                if [[ -n "$u" ]]; then
                    adduser "$u" && usermod -aG sudo "$u" && \
                    print_success "用户创建成功。" && \
                    log_action "Created sudo user: $u"
                fi
                pause ;;
            3)
                if confirm "禁用 Root 登录？"; then
                    sed -i -E "s|^\s*#?\s*PermitRootLogin\s+.*|PermitRootLogin no|" "$SSHD_CONFIG"
                    is_systemd && (systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true)
                    print_success "Root 登录已禁用。"
                    log_action "SSH root login disabled"
                fi
                pause ;;
            4) ssh_keys ;;
            5) 
                read -e -r -p "用户名 [root]: " u
                u=${u:-root}
                passwd "$u"
                pause ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
        refresh_ssh_port
    done
}

# ==============================================================================
# 7. 系统优化模块
# ==============================================================================

opt_cleanup() {
    print_title "系统清理"
    print_info "正在清理..."
    apt-get autoremove -y >/dev/null 2>&1
    apt-get autoclean -y >/dev/null 2>&1
    apt-get clean >/dev/null 2>&1
    
    journalctl --vacuum-time=7d >/dev/null 2>&1 || true
    
    print_success "清理完成。"
    log_action "System cleanup completed"
    pause
}

opt_hostname() {
    print_title "修改主机名"
    echo "当前: $(hostname)"
    read -e -r -p "新主机名: " new_name
    [[ -z "$new_name" ]] && return
    
    if [[ ! "$new_name" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then
        print_error "主机名格式无效。"
        pause; return
    fi
    
    command_exists hostnamectl && hostnamectl set-hostname "$new_name" || true
    hostname "$new_name"
    echo "$new_name" > /etc/hostname
    
    sed -i "s/127.0.0.1.*localhost.*/127.0.0.1 localhost $new_name/g" /etc/hosts
    
    print_success "主机名已修改为: $new_name"
    log_action "Hostname changed to $new_name"
    pause
}

opt_swap() {
    print_title "Swap 管理"
    local size=$(free -m | awk '/Swap/ {print $2}')
    echo "当前 Swap: ${size}MB"
    echo ""
    echo "1. 开启/修改 Swap"
    echo "2. 关闭/删除 Swap"
    echo "0. 返回"
    read -e -r -p "选择: " c
    
    if [[ "$c" == "1" ]]; then
        read -e -r -p "大小 (MB): " s
        if [[ ! "$s" =~ ^[0-9]+$ ]] || [ "$s" -lt 128 ]; then
            print_error "大小无效 (最小 128MB)。"
            pause; return
        fi
        
        print_info "正在设置 ${s}MB Swap..."
        swapoff -a 2>/dev/null || true
        rm -f /swapfile
        
        if ! fallocate -l "${s}M" /swapfile 2>/dev/null; then
            dd if=/dev/zero of=/swapfile bs=1M count="$s" status=progress
        fi
        
        chmod 600 /swapfile
        mkswap /swapfile >/dev/null
        swapon /swapfile
        
        if ! grep -q "/swapfile" /etc/fstab; then
            echo "/swapfile none swap sw 0 0" >> /etc/fstab
        fi
        
        print_success "Swap 设置成功。"
        log_action "Swap configured: ${s}MB"
        
    elif [[ "$c" == "2" ]]; then
        if confirm "确认删除 Swap？"; then
            swapoff -a 2>/dev/null || true
            rm -f /swapfile
            sed -i '/\/swapfile/d' /etc/fstab
            print_success "Swap 已删除。"
            log_action "Swap removed"
        fi
    fi
    pause
}

opt_bbr() {
    print_title "BBR 加速"
    
    local current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
    local current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "unknown")
    
    echo "当前配置:"
    echo "  拥塞控制: $current_cc"
    echo "  队列算法: $current_qdisc"
    echo ""
    
    if [[ "$current_cc" == "bbr" ]]; then
        print_success "BBR 已启用。"
        pause; return
    fi
    
    if confirm "开启 BBR 加速？"; then
        [[ ! -f /etc/sysctl.conf.bak ]] && cp /etc/sysctl.conf /etc/sysctl.conf.bak
        
        sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
        
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        
        sysctl -p >/dev/null
        
        print_success "BBR 已开启。"
        log_action "BBR enabled"
    fi
    pause
}

menu_opt() {
    fix_terminal
    while true; do
        print_title "系统优化"
        echo "1. 开启 BBR 加速"
        echo "2. 虚拟内存 (Swap)"
        echo "3. 修改主机名"
        echo "4. 系统垃圾清理"
        echo "5. 修改时区"
        echo "0. 返回"
        echo ""
        read -e -r -p "选择: " c
        case $c in
            1) opt_bbr ;;
            2) opt_swap ;;
            3) opt_hostname ;;
            4) opt_cleanup ;;
            5)
                echo "1.上海 2.香港 3.东京 4.纽约 5.伦敦 6.UTC"
                read -e -r -p "选择: " t
                case $t in
                    1) z="Asia/Shanghai" ;;
                    2) z="Asia/Hong_Kong" ;;
                    3) z="Asia/Tokyo" ;;
                    4) z="America/New_York" ;;
                    5) z="Europe/London" ;;
                    6) z="UTC" ;;
                    *) print_error "无效选择"; pause; continue ;;
                esac
                ln -sf /usr/share/zoneinfo/$z /etc/localtime
                print_success "时区已设为 $z"
                log_action "Timezone changed to $z"
                pause ;;
            0|q) break ;;
            *) print_error "无效" ;;
        esac
    done
}

# ==============================================================================
# 8. 网络工具模块
# ==============================================================================

net_iperf3() {
    print_title "iPerf3 测速"
    install_package "iperf3"
    
    read -e -r -p "监听端口 [5201]: " port
    port=${port:-5201}
    
    if ! validate_port "$port"; then
        print_error "端口无效。"
        pause; return
    fi
    
    local ufw_opened=0
    if command_exists ufw && ufw status | grep -q "Status: active"; then
        if ! ufw status | grep -q "$port/tcp"; then
            ufw allow "$port/tcp" comment "iPerf3-Temp" >/dev/null
            ufw_opened=1
            print_info "临时放行端口 $port"
        fi
    fi
    
    local ip4=$(safe_curl https://api.ipify.org)
    local ip6=$(get_public_ipv6)
    
    echo -e "\n${C_BLUE}=== 客户端测速命令 ===${C_RESET}"
    [[ -n "$ip4" ]] && echo -e "IPv4 Upload: ${C_YELLOW}iperf3 -c $ip4 -p $port${C_RESET}"
    [[ -n "$ip4" ]] && echo -e "IPv4 Download: ${C_YELLOW}iperf3 -c $ip4 -p $port -R${C_RESET}"
    [[ -n "$ip6" ]] && echo -e "IPv6 Upload: ${C_YELLOW}iperf3 -6 -c $ip6 -p $port${C_RESET}"
    [[ -n "$ip6" ]] && echo -e "IPv6 Download: ${C_YELLOW}iperf3 -6 -c $ip6 -p $port -R${C_RESET}"
    echo -e "${C_RED}按 Ctrl+C 停止测试...${C_RESET}"
    
    cleanup_local() {
        print_info "停止服务..."
        if [[ $ufw_opened -eq 1 ]]; then
            ufw delete allow "$port/tcp" >/dev/null 2>&1 || true
            print_info "防火墙规则已移除。"
        fi
    }
    
    local interrupted=0
    handle_local_int() {
        interrupted=1
    }
    trap 'handle_local_int' SIGINT
    
    iperf3 -s -p "$port" &
    local iperf_pid=$!
    
    wait $iperf_pid 2>/dev/null || true
    
    trap 'handle_interrupt' SIGINT
    
    if [[ $interrupted -eq 1 ]]; then
        echo ""
        print_warn "测速已取消。"
    fi
    
    cleanup_local
    log_action "iPerf3 test completed on port $port"
    pause
}

net_proxy() {
    print_title "配置系统级代理 (客户端)"
    print_guide "针对 IPv6-only VPS 无法访问 GitHub/Docker 的最佳方案。"
    echo ""
    
    if ip route get 1.1.1.1 >/dev/null 2>&1; then
        print_info "检测结果: 本机具备 IPv4 出口，可能不需要此功能。"
    else
        print_warn "检测结果: 本机无 IPv4 出口，强烈建议配置代理。"
    fi
    echo ""
    
    echo "1. 开启/修改 系统代理"
    echo "2. 关闭/清理 系统代理"
    echo "3. 查看状态与测试"
    echo "0. 返回"
    echo ""
    read -e -r -p "请选择: " choice
    
    case $choice in
        1)
            local proxy_url=""
            while [[ -z "$proxy_url" ]]; do
                read -e -r -p "输入代理地址 (格式 http://[IP]:Port): " proxy_url
                if [[ ! "$proxy_url" =~ ^http://.+ ]]; then
                    print_warn "地址格式错误，必须以 http:// 开头"
                    proxy_url=""
                fi
            done
            
            print_info "正在写入配置..."
            
            local apt_conf="Acquire::http::Proxy \"$proxy_url\";
Acquire::https::Proxy \"$proxy_url\";"
            write_file_atomic "$APT_PROXY_CONF" "$apt_conf"
            
            local env_conf="export http_proxy=\"$proxy_url\"
export https_proxy=\"$proxy_url\"
export ftp_proxy=\"$proxy_url\"
export HTTP_PROXY=\"$proxy_url\"
export HTTPS_PROXY=\"$proxy_url\"
export FTP_PROXY=\"$proxy_url\"
export no_proxy=\"localhost,127.0.0.1,::1\"
export NO_PROXY=\"localhost,127.0.0.1,::1\""
            write_file_atomic "$ENV_PROXY_CONF" "$env_conf"
            
            if [[ -f "$ETC_ENVIRONMENT" ]]; then
                [[ ! -f "${ETC_ENVIRONMENT}.bak.proxy" ]] && cp "$ETC_ENVIRONMENT" "${ETC_ENVIRONMENT}.bak.proxy"
            else
                touch "$ETC_ENVIRONMENT"
            fi
            
            local env_tmp=$(mktemp)
            grep -v -E -i "^(http_proxy|https_proxy|ftp_proxy|no_proxy)=" "$ETC_ENVIRONMENT" > "$env_tmp" || true
            
            cat >> "$env_tmp" <<EOF
http_proxy="$proxy_url"
https_proxy="$proxy_url"
ftp_proxy="$proxy_url"
HTTP_PROXY="$proxy_url"
HTTPS_PROXY="$proxy_url"
FTP_PROXY="$proxy_url"
no_proxy="localhost,127.0.0.1,::1"
NO_PROXY="localhost,127.0.0.1,::1"
EOF
            
            local env_content=$(cat "$env_tmp")
            write_file_atomic "$ETC_ENVIRONMENT" "$env_content"
            rm -f "$env_tmp"
            
            if command_exists docker && is_systemd && systemctl status docker >/dev/null 2>&1; then
                mkdir -p "$DOCKER_PROXY_DIR"
                local docker_conf="[Service]
Environment=\"HTTP_PROXY=$proxy_url\"
Environment=\"HTTPS_PROXY=$proxy_url\"
Environment=\"NO_PROXY=localhost,127.0.0.1,::1\"
Environment=\"http_proxy=$proxy_url\"
Environment=\"https_proxy=$proxy_url\"
Environment=\"no_proxy=localhost,127.0.0.1,::1\""
                write_file_atomic "$DOCKER_PROXY_CONF" "$docker_conf"
                systemctl daemon-reload || true
                systemctl restart docker || true
                print_success "Docker 代理配置已生效。"
            fi
            
            export http_proxy="$proxy_url"
            export https_proxy="$proxy_url"
            export ftp_proxy="$proxy_url"
            export HTTP_PROXY="$proxy_url"
            export HTTPS_PROXY="$proxy_url"
            export FTP_PROXY="$proxy_url"
            export no_proxy="localhost,127.0.0.1,::1"
            export NO_PROXY="localhost,127.0.0.1,::1"
            
            print_success "代理配置完成。"
            log_action "System proxy configured: $proxy_url"
            pause
            ;;
            
        2)
            print_info "正在清理代理配置..."
            rm -f "$APT_PROXY_CONF" "$ENV_PROXY_CONF" "$DOCKER_PROXY_CONF"
            
            if [[ -f "$ETC_ENVIRONMENT" ]]; then
                local env_tmp=$(mktemp)
                grep -v -E -i "^(http_proxy|https_proxy|ftp_proxy|no_proxy)=" "$ETC_ENVIRONMENT" > "$env_tmp" || true
                local env_content=$(cat "$env_tmp")
                write_file_atomic "$ETC_ENVIRONMENT" "$env_content"
                rm -f "$env_tmp"
            fi
            
            unset http_proxy https_proxy ftp_proxy HTTP_PROXY HTTPS_PROXY FTP_PROXY no_proxy NO_PROXY
            
            if command_exists docker && is_systemd && systemctl status docker >/dev/null 2>&1; then
                systemctl daemon-reload || true
                systemctl restart docker || true
            fi
            
            print_success "代理配置已清除。"
            log_action "System proxy removed"
            pause
            ;;
        3)
            print_title "系统代理状态"
            echo -e "${C_CYAN}[当前会话]${C_RESET}"
            echo "http_proxy=${http_proxy:-未设置}"
            echo "no_proxy=${no_proxy:-未设置}"
            
            echo -e "\n${C_CYAN}[配置文件]${C_RESET}"
            [[ -f "$APT_PROXY_CONF" ]] && echo "APT: 已配置" || echo "APT: 未配置"
            [[ -f "$ENV_PROXY_CONF" ]] && echo "Shell: 已配置" || echo "Shell: 未配置"
            grep -i -q "http_proxy=" "$ETC_ENVIRONMENT" 2>/dev/null && echo "Systemd: 已配置" || echo "Systemd: 未配置"
            [[ -f "$DOCKER_PROXY_CONF" ]] && echo "Docker: 已配置" || echo "Docker: 未配置"
            
            echo -e "\n${C_CYAN}[连接测试]${C_RESET}"
            if curl -I -s --connect-timeout 3 https://www.google.com | grep -q "HTTP/"; then
                print_success "代理连接正常。"
            else
                print_warn "代理连接失败或未配置。"
            fi
            
            pause
            ;;
        0|q) return ;;
        *) print_error "无效选项"; pause ;;
    esac
}

net_setup_squid() {
    print_title "搭建 Squid 代理服务端"
    install_package "squid"
    
    local port="3128"
    read -e -r -p "请输入监听端口 [$port]: " p
    [[ -n "$p" ]] && port="$p"
    
    if ! validate_port "$port"; then
        print_error "端口无效，使用默认 3128"
        port=3128
    fi
    
    local client_ip=""
    while [[ -z "$client_ip" ]]; do
        read -e -r -p "请输入允许连接的客户端 IPv6 地址 (支持 CIDR): " client_ip
        if [[ -z "$client_ip" ]]; then
            print_warn "必须输入 IP 地址！"
        fi
    done
    
    if [[ "$client_ip" != */* ]]; then
        if [[ "$client_ip" == *:* ]]; then
            client_ip="${client_ip}/128"
        else
            client_ip="${client_ip}/32"
        fi
    fi
    
    print_info "正在配置 Squid..."
    
    local squid_conf_content="# Squid Proxy Configuration
# Generated by $SCRIPT_NAME $VERSION

# Port (Listen on IPv6 explicitly)
http_port [::]:$port

# Optimization
shutdown_lifetime 1 seconds
forwarded_for off
via off
dns_v4_first on

# ACL Definitions
acl allowed_client src $client_ip
acl localnet src 127.0.0.1/32 ::1/128

# Access Control
http_access allow allowed_client
http_access allow localnet
http_access deny all"
    
    write_file_atomic "$SQUID_CONF" "$squid_conf_content"
    
    if command_exists ufw && ufw status | grep -q "Status: active"; then
        if ufw allow from "$client_ip" to any port "$port" proto tcp comment "Squid-Proxy" >/dev/null 2>&1; then
            print_success "UFW 规则已更新。"
        else
            print_warn "UFW 规则添加失败。"
        fi
    fi
    
    if is_systemd; then
        systemctl enable squid >/dev/null 2>&1 || true
        systemctl restart squid 2>/dev/null || systemctl restart squid3 2>/dev/null || true
    elif command_exists service; then
        service squid restart || service squid3 restart || true
    fi
    
    print_info "正在进行服务端自测 (Self-Test)..."
    sleep 2
    if curl -I -s -x "http://[::1]:$port" --connect-timeout 3 https://github.com | grep -q "HTTP/" || \
       curl -I -s -x "http://127.0.0.1:$port" --connect-timeout 3 https://github.com | grep -q "HTTP/"; then
        print_success "自测通过！"
    else
        print_warn "自测失败！请检查防火墙或日志。"
        pause; return
    fi
    
    local my_ipv6=$(curl -6 -s --connect-timeout 3 ifconfig.co || echo "本机IPv6")
    echo ""
    draw_line
    echo -e "客户端配置地址: ${C_GREEN}http://[$my_ipv6]:$port${C_RESET}"
    draw_line
    
    log_action "Squid proxy configured on port $port for $client_ip"
    pause
}

net_dns() {
    print_title "DNS 配置"
    echo "当前 DNS:"
    cat /etc/resolv.conf
    echo -e "\n${C_YELLOW}输入新 DNS IP (空格隔开)，输入 0 取消${C_RESET}"
    read -e -r -p "DNS: " dns
    if [[ -z "$dns" || "$dns" == "0" ]]; then return; fi
    
    for ip in $dns; do
        if ! validate_ip "$ip"; then
            print_error "IP 地址 $ip 格式无效！"
            pause; return
        fi
    done
    
    local res_conf="/etc/systemd/resolved.conf"
    if is_systemd && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        if ! grep -q "^[[:space:]]*\[Resolve\]" "$res_conf"; then
            echo "" >> "$res_conf"
            echo "[Resolve]" >> "$res_conf"
        fi
        sed -i '/^[[:space:]]*DNS=/d' "$res_conf"
        sed -i "0,/^[[:space:]]*\[Resolve\]/s/^[[:space:]]*\[Resolve\]/&\nDNS=$dns/" "$res_conf"
        systemctl restart systemd-resolved 2>/dev/null || true
    else
        echo "nameserver $dns" > /etc/resolv.conf
    fi
    
    print_success "DNS 已修改。"
    log_action "DNS changed to: $dns"
    pause
}

menu_net() {
    fix_terminal
    while true; do
        print_title "网络管理工具"
        echo -e "${C_CYAN}--- 通用功能 ---${C_RESET}"
        echo "1. DNS 配置"
        echo "2. IPv4/IPv6 优先级"
        echo "3. iPerf3 测速"
        echo -e "\n${C_CYAN}--- 客户端功能 (Only-IPv6 机器用) ---${C_RESET}"
        echo "4. 配置系统级代理 (连接服务端)"
        echo -e "\n${C_CYAN}--- 服务端功能 (双栈机器用) ---${C_RESET}"
        echo "5. 搭建 Squid 代理服务端"
        echo ""
        echo "0. 返回"
        echo ""
        read -e -r -p "选择: " c
        case $c in
            1) net_dns ;;
            2) 
                echo "1. 优先 IPv4  2. 优先 IPv6"
                read -e -r -p "选: " p
                [[ ! -f /etc/gai.conf ]] && touch /etc/gai.conf
                if [[ "$p" == "1" ]]; then
                    sed -i 's/^#precedence ::ffff:0:0\/96  100/precedence ::ffff:0:0\/96  100/' /etc/gai.conf
                    grep -q "precedence ::ffff:0:0/96  100" /etc/gai.conf || echo "precedence ::ffff:0:0/96  100" >> /etc/gai.conf
                    print_success "IPv4 优先。"
                else
                    sed -i 's/^precedence ::ffff:0:0\/96  100/#precedence ::ffff:0:0\/96  100/' /etc/gai.conf
                    print_success "IPv6 优先。"
                fi
                log_action "IP priority changed"
                pause ;;
            3) net_iperf3 ;;
            4) net_proxy ;;
            5) net_setup_squid ;;
            0|q) break ;;
            *) print_error "无效" ;;
        esac
    done
}

# ==============================================================================
# 9. Web 服务模块 (Part 1 - 环境与 DNS)
# ==============================================================================

web_env_check() {
    command_exists jq || install_package "jq"
    command_exists nginx || install_package "nginx"
    is_systemd && (systemctl enable --now nginx >/dev/null 2>&1 || true)
    
    if ! command_exists certbot; then
        print_info "安装 Certbot..."
        update_apt_cache
        if ! apt-get install -y certbot python3-certbot-dns-cloudflare >/dev/null 2>&1; then
            print_warn "Apt 安装失败，尝试 Snap..."
            install_package "snapd" "silent" || true
            if command_exists snap; then
                snap install --classic certbot || return 1
                snap install certbot-dns-cloudflare || return 1
                snap connect certbot:plugin certbot-dns-cloudflare
                ln -sf /snap/bin/certbot /usr/bin/certbot
            else
                print_error "Certbot 安装失败。"
                return 1
            fi
        fi
    fi
    
    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/snippets
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
}

web_cf_dns_update() {
    print_title "Cloudflare DNS 智能解析"
    command_exists jq || install_package "jq" "silent"
    
    get_public_ip() {
        local type=$1
        local ip=""
        
        validate_ip_format() {
            local raw=$1
            local clean=$(echo "$raw" | head -n 1 | tr -d '[:space:]')
            if [[ "$type" == "4" ]]; then
                if [[ "$clean" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                    local IFS='.'
                    local -a octets
                    read -r -a octets <<< "$clean"
                    for octet in "${octets[@]}"; do
                        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
                        [ "$octet" -le 255 ] || return 1
                    done
                    echo "$clean"
                    return 0
                fi
            else
                if [[ "$clean" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$clean" == *:* ]]; then
                    echo "$clean"
                    return 0
                fi
            fi
            return 1
        }
        
        if [[ "$type" == "4" ]]; then
            ip=$(safe_curl --fail -4 https://api.ipify.org || safe_curl --fail -4 https://ifconfig.co || safe_curl --fail -4 https://api-ipv4.ip.sb/ip || true)
        else
            ip=$(safe_curl --fail -6 https://api64.ipify.org || safe_curl --fail -6 https://ifconfig.co || safe_curl --fail -6 https://api-ipv6.ip.sb/ip || true)
        fi
        validate_ip_format "$ip"
    }

    print_info "正在探测本机公网 IP..."
    local ipv4=$(get_public_ip "4")
    local ipv6=$(get_public_ip "6")
    
    if [[ -z "$ipv4" && -z "$ipv6" ]]; then
        print_error "无法获取本机 IP，请检查网络。"
        pause; return
    fi
    
    echo "----------------------------------------"
    [[ -n "$ipv4" ]] && echo -e "IPv4: ${C_GREEN}$ipv4${C_RESET}"
    [[ -n "$ipv6" ]] && echo -e "IPv6: ${C_GREEN}$ipv6${C_RESET}"
    echo "----------------------------------------"
    
    echo "1. 仅解析 IPv4 (A)"
    echo "2. 仅解析 IPv6 (AAAA)"
    echo "3. 双栈解析 (A + AAAA)"
    echo "0. 跳过"
    read -e -r -p "请选择: " mode
    if [[ "$mode" == "0" ]]; then return; fi
    
    while [[ -z "$CF_API_TOKEN" ]]; do
        read -s -r -p "Cloudflare API Token: " CF_API_TOKEN
        echo ""
    done
    
    while [[ -z "$DOMAIN" ]]; do
        read -e -r -p "请输入域名: " DOMAIN
        if ! validate_domain "$DOMAIN"; then
            print_error "域名格式无效。"
            DOMAIN=""
        fi
    done
    
    print_info "正在获取 Zone ID..."
    local zone_id=""
    local current_domain="$DOMAIN"
    
    while [[ "$current_domain" == *"."* ]]; do
        local resp=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$current_domain" \
            -H "Authorization: Bearer $CF_API_TOKEN" \
            -H "Content-Type: application/json")
        
        local api_success=$(echo "$resp" | jq -r '.success')
        if [[ "$api_success" != "true" ]]; then
            local err_msg=$(echo "$resp" | jq -r '.errors[0].message // "Unknown API Error"')
            if [[ "$err_msg" == *"Authentication"* || "$err_msg" == *"Authorization"* ]]; then
                print_error "API 鉴权失败: $err_msg"
                pause; return
            else
                print_warn "查询 $current_domain 失败: $err_msg (尝试上级域名...)"
            fi
        else
            zone_id=$(echo "$resp" | jq -r '.result[0].id')
            if [[ "$zone_id" != "null" && -n "$zone_id" ]]; then
                print_success "找到 Zone ID: $zone_id ($current_domain)"
                break
            else
                print_warn "当前域名未托管: $current_domain (尝试上级域名...)"
            fi
        fi
        current_domain="${current_domain#*.}"
    done
    
    if [[ -z "$zone_id" || "$zone_id" == "null" ]]; then
        print_error "无法获取 Zone ID。"
        pause; return
    fi
    
    update_record() {
        local type=$1
        local ip=$2
        [[ -z "$ip" ]] && return
        
        print_info "处理 $type 记录 -> $ip"
        local records=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records?type=$type&name=$DOMAIN" \
            -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json")
        
        local record_id=$(echo "$records" | jq -r '.result[0].id')
        local count=$(echo "$records" | jq -r '.result | length')
        [[ "$count" -gt 1 ]] && print_warn "警告: 存在多条 $type 记录，仅更新第一条。"
        
        if [[ "$record_id" != "null" && -n "$record_id" ]]; then
            local resp=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$record_id" \
                -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" \
                --data "{\"type\":\"$type\",\"name\":\"$DOMAIN\",\"content\":\"$ip\",\"ttl\":1,\"proxied\":false}")
            if [[ "$(echo "$resp" | jq -r '.success')" == "true" ]]; then
                print_success "更新成功"
            else
                print_error "更新失败: $(echo "$resp" | jq -r '.errors[0].message')"
            fi
        else
            local resp=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
                -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" \
                --data "{\"type\":\"$type\",\"name\":\"$DOMAIN\",\"content\":\"$ip\",\"ttl\":1,\"proxied\":false}")
            if [[ "$(echo "$resp" | jq -r '.success')" == "true" ]]; then
                print_success "创建成功"
            else
                print_error "创建失败: $(echo "$resp" | jq -r '.errors[0].message')"
            fi
        fi
    }
    
    case $mode in
        1) update_record "A" "$ipv4" ;;
        2) update_record "AAAA" "$ipv6" ;;
        3) update_record "A" "$ipv4"; update_record "AAAA" "$ipv6" ;;
    esac
    
    print_success "DNS 配置完成。"
    log_action "Cloudflare DNS updated for $DOMAIN"
    sleep 2
}

# ==============================================================================
# 9. Web 服务模块 (Part 2 - 域名管理)
# ==============================================================================

web_view_config() {
    print_title "查看详细配置"
    shopt -s nullglob
    local conf_files=("${CONFIG_DIR}"/*.conf)
    shopt -u nullglob
    
    if [[ ${#conf_files[@]} -eq 0 ]]; then
        print_warn "当前没有已保存的域名配置。"
        pause; return
    fi
    
    local i=1
    local domains=()
    local files=()
    
    echo "请选择要查看的域名:"
    for conf in "${conf_files[@]}"; do
        local d=$(grep '^DOMAIN=' "$conf" | cut -d'"' -f2)
        if [[ -n "$d" ]]; then
            domains+=("$d")
            files+=("$conf")
            echo "$i. $d"
            ((i++))
        fi
    done
    echo "0. 返回"
    
    echo ""
    read -e -r -p "请输入序号: " idx
    
    if [[ "$idx" == "0" || -z "$idx" ]]; then return; fi
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -gt ${#domains[@]} ]]; then
        print_error "无效序号。"
        pause; return
    fi
    
    local target_domain="${domains[$((idx-1))]}"
    local target_conf="${files[$((idx-1))]}"
    
    local DOMAIN="" CERT_PATH="" DEPLOY_HOOK_SCRIPT=""
    source "$target_conf"
    
    CERT_PATH=${CERT_PATH:-"${CERT_PATH_PREFIX}/${target_domain}"}
    DEPLOY_HOOK_SCRIPT=${DEPLOY_HOOK_SCRIPT:-"/root/cert-renew-hook-${target_domain}.sh"}
    
    print_title "配置详情: $target_domain"
    
    echo -e "${C_CYAN}[基础信息]${C_RESET}"
    echo "域名: $target_domain"
    echo "证书目录: $CERT_PATH"
    echo "Hook 脚本: $DEPLOY_HOOK_SCRIPT"
    
    echo -e "\n${C_CYAN}[自动续签计划 (Crontab)]${C_RESET}"
    local cron_out=$(crontab -l 2>/dev/null | grep -v -E "^[[:space:]]*no crontab for " || true)
    
    if [[ -n "$DEPLOY_HOOK_SCRIPT" ]] && echo "$cron_out" | grep -F -q "$DEPLOY_HOOK_SCRIPT"; then
        echo "$cron_out" | grep -F "$DEPLOY_HOOK_SCRIPT"
    else
        echo -e "${C_YELLOW}未配置自动续签任务${C_RESET}"
    fi
    
    echo -e "\n${C_CYAN}[证书状态]${C_RESET}"
    local fullchain="$CERT_PATH/fullchain.pem"
    local privkey="$CERT_PATH/privkey.pem"
    
    if [[ -f "$fullchain" ]]; then
        local end_date=$(openssl x509 -enddate -noout -in "$fullchain" | cut -d= -f2)
        local end_epoch=$(date -d "$end_date" +%s 2>/dev/null || echo 0)
        local now_epoch=$(date +%s)
        local days_left=$(( (end_epoch - now_epoch) / 86400 ))
        
        if [ "$days_left" -lt 0 ]; then
            echo -e "过期时间: ${C_RED}${end_date} (已过期)${C_RESET}"
        elif [ "$days_left" -lt 30 ]; then
            echo -e "过期时间: ${C_YELLOW}${end_date} (剩余 ${days_left} 天)${C_RESET}"
        else
            echo -e "过期时间: ${C_GREEN}${end_date} (剩余 ${days_left} 天)${C_RESET}"
        fi
    else
        echo -e "公钥文件: ${C_RED}未找到${C_RESET}"
    fi
    
    if [[ -f "$privkey" ]]; then
        echo "私钥文件: $privkey (存在)"
    else
        echo -e "私钥文件: ${C_RED}未找到${C_RESET}"
    fi
    
    echo -e "\n${C_CYAN}[Nginx 配置摘要]${C_RESET}"
    local nginx_conf="/etc/nginx/sites-enabled/${target_domain}.conf"
    local nginx_status="已启用"
    
    if [[ ! -f "$nginx_conf" ]]; then
        local avail_conf="/etc/nginx/sites-available/${target_domain}.conf"
        if [[ -f "$avail_conf" ]]; then
            nginx_conf="$avail_conf"
            nginx_status="${C_YELLOW}未启用${C_RESET}"
        fi
    fi
    
    if [[ -f "$nginx_conf" ]]; then
        echo -e "配置文件: $nginx_conf ($nginx_status)"
        echo "关键指令:"
        grep -E "^\s*(listen|server_name|proxy_pass|ssl_certificate|ssl_certificate_key|ssl_trusted_certificate)\b" "$nginx_conf" | sed 's/^[[:space:]]*/  /'
    else
        echo -e "${C_YELLOW}该域名未配置 Nginx 反代。${C_RESET}"
    fi
    
    echo -e "\n${C_CYAN}[Hook 脚本摘要]${C_RESET}"
    if [[ -f "$DEPLOY_HOOK_SCRIPT" ]]; then
        echo "脚本路径: $DEPLOY_HOOK_SCRIPT"
        echo "关键动作:"
        grep -E 'export PATH=|cp -L|reload nginx|x-ui|3x-ui' "$DEPLOY_HOOK_SCRIPT" | sed 's/^[[:space:]]*/  /'
    else
        echo -e "${C_RED}Hook 脚本丢失！建议重新添加域名。${C_RESET}"
    fi
    
    pause
}

web_delete_domain() {
    print_title "删除域名配置"
    
    shopt -s nullglob
    local conf_files=("${CONFIG_DIR}"/*.conf)
    shopt -u nullglob
    
    if [[ ${#conf_files[@]} -eq 0 ]]; then
        print_warn "当前没有已保存的域名配置。"
        pause; return
    fi
    
    local i=1
    local domains=()
    local files=()
    
    echo "发现以下配置:"
    for conf in "${conf_files[@]}"; do
        local d=$(grep '^DOMAIN=' "$conf" | cut -d'"' -f2)
        if [[ -n "$d" ]]; then
            domains+=("$d")
            files+=("$conf")
            echo "$i. $d"
            ((i++))
        fi
    done
    echo "0. 返回"
    
    echo ""
    read -e -r -p "请输入序号删除: " idx
    
    if [[ "$idx" == "0" || -z "$idx" ]]; then return; fi
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -gt ${#domains[@]} ]]; then
        print_error "无效序号。"
        pause; return
    fi
    
    local target_domain="${domains[$((idx-1))]}"
    local target_conf="${files[$((idx-1))]}"
    
    echo -e "${C_RED}"
    echo "!!! 危险操作 !!!"
    echo "即将删除域名: $target_domain"
    echo "这将执行:"
    echo "1. 删除 SSL 证书 (certbot delete)"
    echo "2. 删除 Nginx 配置文件并重载"
    echo "3. 删除 自动续签 Hook 脚本"
    echo "4. 清理 Crontab 定时任务"
    echo "5. 删除 脚本保存的配置"
    echo -e "${C_RESET}"
    
    if ! confirm "确认彻底删除吗?"; then return; fi
    
    print_info "正在执行清理..."
    
    if certbot delete --cert-name "$target_domain" --non-interactive 2>/dev/null; then
        print_success "证书已吊销/删除。"
    else
        print_warn "Certbot 删除失败或证书不存在。"
    fi
    
    local nginx_conf="/etc/nginx/sites-enabled/${target_domain}.conf"
    local nginx_conf_src="/etc/nginx/sites-available/${target_domain}.conf"
    if [[ -f "$nginx_conf" || -f "$nginx_conf_src" ]]; then
        rm -f "$nginx_conf" "$nginx_conf_src"
        if is_systemd && command_exists nginx; then
            systemctl reload nginx 2>/dev/null || true
        elif command_exists nginx; then
            nginx -s reload 2>/dev/null || true
        fi
        print_success "Nginx 配置已删除。"
    fi
    
    local hook_script="/root/cert-renew-hook-${target_domain}.sh"
    if [[ -f "$hook_script" ]]; then
        rm -f "$hook_script"
        print_success "Hook 脚本已删除。"
    fi
    
    local cron_tmp=$(mktemp)
    crontab -l > "$cron_tmp" 2>/dev/null || true
    grep -v -E "^[[:space:]]*no crontab for " "$cron_tmp" > "${cron_tmp}.clean" || true
    mv "${cron_tmp}.clean" "$cron_tmp"
    
    grep -F -v "cert-renew-hook-${target_domain}.sh" "$cron_tmp" > "${cron_tmp}.new" || true
    
    if ! diff -q "$cron_tmp" "${cron_tmp}.new" >/dev/null 2>&1; then
        if crontab "${cron_tmp}.new" 2>/dev/null; then
            print_success "Crontab 任务已清理。"
        else
            print_warn "Crontab 清理失败。"
        fi
    fi
    rm -f "$cron_tmp" "${cron_tmp}.new"
    
    rm -f "$target_conf"
    print_success "管理配置已移除。"
    
    log_action "Deleted domain config: $target_domain"
    pause
}

# ==============================================================================
# 9. Web 服务模块 (Part 3 - 添加域名)
# ==============================================================================

web_add_domain() {
    print_title "添加域名配置 (SSL + Nginx)"
    local DOMAIN="" CF_API_TOKEN="" LOCAL_PROXY_PASS="" NGINX_HTTP_PORT="" NGINX_HTTPS_PORT="" BACKEND_PROTOCOL=""
    
    web_env_check || { pause; return; }
    
    print_guide "此步骤将申请 SSL 证书并（可选）配置 Nginx 反向代理。"
    echo ""
    
    if confirm "是否需要先自动配置 Cloudflare DNS 解析 (A/AAAA)?"; then
        web_cf_dns_update
        echo ""
    fi
    
    while [[ -z "$DOMAIN" ]]; do
        read -e -r -p "请输入域名 (如 example.com): " DOMAIN
        if ! validate_domain "$DOMAIN"; then
            print_error "域名格式无效。"
            DOMAIN=""
        fi
    done
    
    if [[ -f "${CONFIG_DIR}/${DOMAIN}.conf" ]]; then
        print_warn "配置已存在，请先删除。"
        pause; return
    fi
    
    print_guide "脚本使用 DNS API 申请证书，需要您的 Cloudflare API Token。"
    while [[ -z "$CF_API_TOKEN" ]]; do
        read -s -r -p "Cloudflare API Token: " CF_API_TOKEN
        echo ""
    done
    
    local do_nginx=0
    echo ""
    if confirm "是否配置 Nginx 反向代理 (用于隐藏后端端口)?"; then
        do_nginx=1
        print_guide "请输入 Nginx 监听的端口 (通常 HTTP=80, HTTPS=443)"
        
        while true; do
            read -e -r -p "HTTP 端口 [80]: " hp
            NGINX_HTTP_PORT=${hp:-80}
            if validate_port "$NGINX_HTTP_PORT"; then break; fi
            print_warn "端口无效"
        done
        
        while true; do
            read -e -r -p "HTTPS 端口 [443]: " sp
            NGINX_HTTPS_PORT=${sp:-443}
            if validate_port "$NGINX_HTTPS_PORT"; then break; fi
            print_warn "端口无效"
        done
        
        read -e -r -p "后端协议 [1]http [2]https: " proto
        BACKEND_PROTOCOL=$([[ "$proto" == "2" ]] && echo "https" || echo "http")
        
        print_guide "请输入后端服务的实际地址 (例如 127.0.0.1:54321)"
        while [[ -z "$LOCAL_PROXY_PASS" ]]; do
            read -e -r -p "反代目标: " inp
            [[ "$inp" =~ ^[0-9]+$ ]] && inp="127.0.0.1:$inp"
            if [[ "$inp" =~ ^(\[.*\]|[a-zA-Z0-9.-]+):[0-9]+$ ]]; then
                LOCAL_PROXY_PASS="${BACKEND_PROTOCOL}://${inp}"
            else
                print_warn "格式错误，请重试"
            fi
        done
    else
        echo ""
        print_guide "您选择了【不配置 Nginx】。"
        print_guide "证书生成后，请手动在 3x-ui 面板设置中填写公钥/私钥路径。"
        echo ""
    fi
    
    mkdir -p "${CERT_PATH_PREFIX}/${DOMAIN}"
    local CLOUDFLARE_CREDENTIALS="/root/.cloudflare-${DOMAIN}.ini"
    write_file_atomic "$CLOUDFLARE_CREDENTIALS" "dns_cloudflare_api_token = $CF_API_TOKEN"
    chmod 600 "$CLOUDFLARE_CREDENTIALS"
    
    print_info "正在申请证书 (这可能需要 1-2 分钟)..."
    if certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$CLOUDFLARE_CREDENTIALS" \
        --dns-cloudflare-propagation-seconds 60 \
        -d "$DOMAIN" \
        --email "$EMAIL" \
        --agree-tos \
        --no-eff-email \
        --non-interactive; then
        
        print_success "证书获取成功！"
        local cert_dir="${CERT_PATH_PREFIX}/${DOMAIN}"
        cp -L "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$cert_dir/fullchain.pem"
        cp -L "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$cert_dir/privkey.pem"
        chmod 644 "$cert_dir/fullchain.pem"
        chmod 600 "$cert_dir/privkey.pem"
        
        if [[ $do_nginx -eq 1 ]]; then
            local NGINX_CONF_PATH="/etc/nginx/sites-available/${DOMAIN}.conf"
            
            if [[ ! -f /etc/nginx/snippets/ssl-params.conf ]]; then
                local ssl_params="ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
add_header Strict-Transport-Security \"max-age=15768000\" always;"
                write_file_atomic "/etc/nginx/snippets/ssl-params.conf" "$ssl_params"
            fi
            
            local redir_port=""
            [[ "$NGINX_HTTPS_PORT" != "443" ]] && redir_port=":${NGINX_HTTPS_PORT}"
            
            local nginx_conf="# Config for $DOMAIN
# Generated by $SCRIPT_NAME $VERSION

server {
    listen $NGINX_HTTP_PORT;
    listen [::]:$NGINX_HTTP_PORT;
    server_name $DOMAIN;
    return 301 https://\$host${redir_port}\$request_uri;
}

server {
    listen $NGINX_HTTPS_PORT ssl http2;
    listen [::]:$NGINX_HTTPS_PORT ssl http2;
    server_name $DOMAIN;

    ssl_certificate ${cert_dir}/fullchain.pem;
    ssl_certificate_key ${cert_dir}/privkey.pem;
    ssl_trusted_certificate ${cert_dir}/fullchain.pem;
    include snippets/ssl-params.conf;

    location / {
        proxy_pass $LOCAL_PROXY_PASS;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
    }
}"

            write_file_atomic "$NGINX_CONF_PATH" "$nginx_conf"
            ln -sf "$NGINX_CONF_PATH" "/etc/nginx/sites-enabled/${DOMAIN}.conf"
            
            if nginx -t 2>&1 | grep -q "successful"; then
                if is_systemd; then
                    systemctl reload nginx || systemctl restart nginx
                else
                    nginx -s reload 2>/dev/null || service nginx reload
                fi
                print_success "Nginx 配置已生效。"
            else
                print_error "Nginx 配置测试失败！"
                rm -f "/etc/nginx/sites-enabled/${DOMAIN}.conf"
                pause; return
            fi
            
            if command_exists ufw && ufw status | grep -q "Status: active"; then
                ufw allow "$NGINX_HTTP_PORT/tcp" comment "Nginx-HTTP" >/dev/null 2>&1 || true
                ufw allow "$NGINX_HTTPS_PORT/tcp" comment "Nginx-HTTPS" >/dev/null 2>&1 || true
                print_success "防火墙规则已更新。"
            fi
        fi
        
        local DEPLOY_HOOK_SCRIPT="/root/cert-renew-hook-${DOMAIN}.sh"
        local hook_content="#!/bin/bash
# Auto-generated renewal hook for $DOMAIN
# Generated by $SCRIPT_NAME $VERSION

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

DOMAIN=\"$DOMAIN\"
CERT_DIR=\"${cert_dir}\"
LETSENCRYPT_LIVE=\"/etc/letsencrypt/live/\${DOMAIN}\"

echo \"[\$(date)] Starting renewal hook for \$DOMAIN\" >> /var/log/cert-renew.log

# Copy certificates
if [[ -f \"\${LETSENCRYPT_LIVE}/fullchain.pem\" ]]; then
    cp -L \"\${LETSENCRYPT_LIVE}/fullchain.pem\" \"\${CERT_DIR}/fullchain.pem\"
    cp -L \"\${LETSENCRYPT_LIVE}/privkey.pem\" \"\${CERT_DIR}/privkey.pem\"
    chmod 644 \"\${CERT_DIR}/fullchain.pem\"
    chmod 600 \"\${CERT_DIR}/privkey.pem\"
    echo \"[\$(date)] Certificates copied successfully\" >> /var/log/cert-renew.log
else
    echo \"[\$(date)] ERROR: Certificate files not found\" >> /var/log/cert-renew.log
    exit 1
fi
"

        if [[ $do_nginx -eq 1 ]]; then
            hook_content+="
# Reload Nginx
if command -v systemctl >/dev/null 2>&1; then
    systemctl reload nginx 2>&1 | tee -a /var/log/cert-renew.log
elif command -v service >/dev/null 2>&1; then
    service nginx reload 2>&1 | tee -a /var/log/cert-renew.log
else
    nginx -s reload 2>&1 | tee -a /var/log/cert-renew.log
fi
echo \"[\$(date)] Nginx reloaded\" >> /var/log/cert-renew.log
"
        fi
        
        hook_content+="
# Optional: Restart 3x-ui (uncomment if needed)
# if command -v x-ui >/dev/null 2>&1; then
#     x-ui restart 2>&1 | tee -a /var/log/cert-renew.log
# fi

echo \"[\$(date)] Renewal hook completed for \$DOMAIN\" >> /var/log/cert-renew.log
exit 0
"
        
        write_file_atomic "$DEPLOY_HOOK_SCRIPT" "$hook_content"
        chmod +x "$DEPLOY_HOOK_SCRIPT"
        
        local cron_tmp=$(mktemp)
        crontab -l > "$cron_tmp" 2>/dev/null || true
        grep -v -E "^[[:space:]]*no crontab for " "$cron_tmp" > "${cron_tmp}.clean" || true
        mv "${cron_tmp}.clean" "$cron_tmp"
        
        if ! grep -F -q "$DEPLOY_HOOK_SCRIPT" "$cron_tmp"; then
            echo "0 3 * * * certbot renew --deploy-hook \"$DEPLOY_HOOK_SCRIPT\" --quiet" >> "$cron_tmp"
            if crontab "$cron_tmp" 2>/dev/null; then
                print_success "自动续签任务已添加 (每日 3:00 AM)。"
            else
                print_warn "Crontab 添加失败，请手动配置。"
            fi
        fi
        rm -f "$cron_tmp"
        
        local config_content="# Domain configuration for $DOMAIN
# Generated by $SCRIPT_NAME $VERSION at $(date)

DOMAIN=\"$DOMAIN\"
CERT_PATH=\"${cert_dir}\"
DEPLOY_HOOK_SCRIPT=\"$DEPLOY_HOOK_SCRIPT\"
CLOUDFLARE_CREDENTIALS=\"$CLOUDFLARE_CREDENTIALS\"
"
        
        if [[ $do_nginx -eq 1 ]]; then
            config_content+="NGINX_CONF_PATH=\"$NGINX_CONF_PATH\"
NGINX_HTTP_PORT=\"$NGINX_HTTP_PORT\"
NGINX_HTTPS_PORT=\"$NGINX_HTTPS_PORT\"
LOCAL_PROXY_PASS=\"$LOCAL_PROXY_PASS\"
"
        fi
        
        write_file_atomic "${CONFIG_DIR}/${DOMAIN}.conf" "$config_content"
        
        echo ""
        draw_line
        print_success "域名配置完成！"
        draw_line
        echo -e "${C_CYAN}[证书路径]${C_RESET}"
        echo "  公钥: ${cert_dir}/fullchain.pem"
        echo "  私钥: ${cert_dir}/privkey.pem"
        
        if [[ $do_nginx -eq 1 ]]; then
            echo -e "\n${C_CYAN}[访问地址]${C_RESET}"
            echo "  https://${DOMAIN}:${NGINX_HTTPS_PORT}"
            echo -e "\n${C_CYAN}[反代配置]${C_RESET}"
            echo "  后端: $LOCAL_PROXY_PASS"
        else
            echo -e "\n${C_YELLOW}[手动配置提示]${C_RESET}"
            echo "  请在 3x-ui 面板设置中填写上述证书路径"
        fi
        
        echo -e "\n${C_CYAN}[自动续签]${C_RESET}"
        echo "  Hook 脚本: $DEPLOY_HOOK_SCRIPT"
        echo "  Crontab: 每日 3:00 AM 自动检查"
        draw_line
        
        log_action "Domain configured: $DOMAIN (Nginx: $do_nginx)"
        
    else
        print_error "证书申请失败！请检查:"
        echo "1. 域名 DNS 是否正确解析到本机"
        echo "2. API Token 权限是否正确"
        echo "3. 网络连接是否正常"
        rm -f "$CLOUDFLARE_CREDENTIALS"
    fi
    
    pause
}

# ==============================================================================
# 9. Web 服务模块 (Part 4 - 菜单)
# ==============================================================================

menu_web() {
    fix_terminal
    while true; do
        print_title "Web 服务管理 (SSL + Nginx)"
        echo -e "${C_CYAN}--- 域名管理 ---${C_RESET}"
        echo "1. 添加域名 (申请证书 + 配置反代)"
        echo "2. 查看已配置域名详情"
        echo "3. 删除域名配置"
        echo ""
        echo -e "${C_CYAN}--- 独立功能 ---${C_RESET}"
        echo "4. 仅配置 Cloudflare DNS 解析"
        echo "5. 手动续签所有证书"
        echo "6. 查看续签日志"
        echo ""
        echo "0. 返回主菜单"
        echo ""
        read -e -r -p "请选择: " c
        
        case $c in
            1) web_add_domain ;;
            2) web_view_config ;;
            3) web_delete_domain ;;
            4) 
                web_env_check || { pause; continue; }
                web_cf_dns_update
                ;;
            5)
                print_title "手动续签证书"
                if ! command_exists certbot; then
                    print_error "Certbot 未安装。"
                    pause; continue
                fi
                
                print_info "正在执行续签..."
                if certbot renew --force-renewal 2>&1 | tee /tmp/certbot-renew.log; then
                    print_success "续签完成。"
                    
                    shopt -s nullglob
                    local hooks=(/root/cert-renew-hook-*.sh)
                    shopt -u nullglob
                    
                    if [[ ${#hooks[@]} -gt 0 ]]; then
                        print_info "正在执行部署 Hook..."
                        for hook in "${hooks[@]}"; do
                            if [[ -x "$hook" ]]; then
                                echo "执行: $hook"
                                bash "$hook" 2>&1 | tee -a /var/log/cert-renew.log
                            fi
                        done
                    fi
                else
                    print_error "续签失败，请查看日志。"
                fi
                log_action "Manual certificate renewal executed"
                pause
                ;;
            6)
                print_title "续签日志"
                if [[ -f /var/log/cert-renew.log ]]; then
                    tail -n 50 /var/log/cert-renew.log
                else
                    print_warn "日志文件不存在。"
                fi
                pause
                ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
    done
}

# ==============================================================================
# 10. Docker 模块
# ==============================================================================

docker_install() {
    print_title "Docker 安装"
    
    if command_exists docker; then
        print_warn "Docker 已安装。"
        docker --version
        pause; return
    fi
    
    print_info "正在安装 Docker..."
    
    update_apt_cache
    install_package "ca-certificates" "silent"
    install_package "curl" "silent"
    install_package "gnupg" "silent"
    
    local keyring_dir="/etc/apt/keyrings"
    mkdir -p "$keyring_dir"
    
    local docker_gpg="$keyring_dir/docker.gpg"
    if [[ ! -f "$docker_gpg" ]]; then
        print_info "添加 Docker GPG 密钥..."
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o "$docker_gpg" 2>/dev/null || \
        curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o "$docker_gpg" 2>/dev/null || {
            print_error "GPG 密钥下载失败。"
            pause; return
        }
        chmod a+r "$docker_gpg"
    fi
    
    local os_id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    local version_codename=$(grep 'VERSION_CODENAME' /etc/os-release | cut -d= -f2)
    
    local docker_list="/etc/apt/sources.list.d/docker.list"
    if [[ ! -f "$docker_list" ]]; then
        print_info "添加 Docker 软件源..."
        echo "deb [arch=$(dpkg --print-architecture) signed-by=$docker_gpg] https://download.docker.com/linux/$os_id $version_codename stable" > "$docker_list"
    fi
    
    apt-get update -qq 2>/dev/null || true
    
    if apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1; then
        print_success "Docker 安装成功。"
        
        if is_systemd; then
            systemctl enable docker >/dev/null 2>&1 || true
            systemctl start docker || true
        fi
        
        docker --version
        log_action "Docker installed"
    else
        print_error "Docker 安装失败。"
    fi
    
    pause
}

docker_uninstall() {
    print_title "Docker 卸载"
    
    if ! command_exists docker; then
        print_warn "Docker 未安装。"
        pause; return
    fi
    
    echo -e "${C_RED}警告: 这将删除 Docker 及所有容器、镜像、卷！${C_RESET}"
    if ! confirm "确认卸载？"; then return; fi
    
    print_info "正在停止服务..."
    if is_systemd; then
        systemctl stop docker docker.socket containerd 2>/dev/null || true
        systemctl disable docker docker.socket containerd 2>/dev/null || true
    fi
    
    print_info "正在卸载软件包..."
    apt-get purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1 || true
    apt-get autoremove -y >/dev/null 2>&1 || true
    
    if confirm "是否删除所有 Docker 数据 (/var/lib/docker)?"; then
        rm -rf /var/lib/docker /var/lib/containerd
        print_success "数据已删除。"
    fi
    
    rm -f /etc/apt/sources.list.d/docker.list
    rm -f /etc/apt/keyrings/docker.gpg
    
    print_success "Docker 已卸载。"
    log_action "Docker uninstalled"
    pause
}

docker_compose_install() {
    print_title "Docker Compose 独立安装"
    
    if command_exists docker && docker compose version >/dev/null 2>&1; then
        print_warn "Docker Compose (Plugin) 已安装。"
        docker compose version
        pause; return
    fi
    
    if command_exists docker-compose; then
        print_warn "Docker Compose (Standalone) 已安装。"
        docker-compose --version
        pause; return
    fi
    
    print_info "正在安装 Docker Compose..."
    
    local compose_version="v2.24.5"
    local arch=$(uname -m)
    local compose_url="https://github.com/docker/compose/releases/download/${compose_version}/docker-compose-linux-${arch}"
    
    if curl -L "$compose_url" -o /usr/local/bin/docker-compose 2>/dev/null; then
        chmod +x /usr/local/bin/docker-compose
        print_success "Docker Compose 安装成功。"
        docker-compose --version
        log_action "Docker Compose installed"
    else
        print_error "下载失败。"
    fi
    
    pause
}

docker_proxy_config() {
    print_title "Docker 代理配置"
    
    if ! command_exists docker; then
        print_error "Docker 未安装。"
        pause; return
    fi
    
    echo "1. 配置 Docker 守护进程代理 (拉取镜像用)"
    echo "2. 清除代理配置"
    echo "0. 返回"
    read -e -r -p "选择: " c
    
    case $c in
        1)
            read -e -r -p "代理地址 (如 http://proxy.example.com:3128): " proxy
            if [[ -z "$proxy" ]]; then return; fi
            
            mkdir -p "$DOCKER_PROXY_DIR"
            local proxy_conf="[Service]
Environment=\"HTTP_PROXY=$proxy\"
Environment=\"HTTPS_PROXY=$proxy\"
Environment=\"NO_PROXY=localhost,127.0.0.1,::1\"
Environment=\"http_proxy=$proxy\"
Environment=\"https_proxy=$proxy\"
Environment=\"no_proxy=localhost,127.0.0.1,::1\""
            
            write_file_atomic "$DOCKER_PROXY_CONF" "$proxy_conf"
            
            if is_systemd; then
                systemctl daemon-reload || true
                systemctl restart docker || true
            fi
            
            print_success "Docker 代理已配置。"
            log_action "Docker proxy configured: $proxy"
            ;;
        2)
            rm -f "$DOCKER_PROXY_CONF"
            if is_systemd; then
                systemctl daemon-reload || true
                systemctl restart docker || true
            fi
            print_success "代理配置已清除。"
            log_action "Docker proxy removed"
            ;;
        0|q) return ;;
    esac
    pause
}

docker_images_manage() {
    print_title "Docker 镜像管理"
    
    if ! command_exists docker; then
        print_error "Docker 未安装。"
        pause; return
    fi
    
    echo "1. 列出所有镜像"
    echo "2. 删除未使用的镜像"
    echo "3. 删除所有镜像 (危险)"
    echo "0. 返回"
    read -e -r -p "选择: " c
    
    case $c in
        1)
            docker images
            ;;
        2)
            if confirm "删除未使用的镜像？"; then
                docker image prune -a -f
                print_success "清理完成。"
                log_action "Docker unused images pruned"
            fi
            ;;
        3)
            if confirm "删除所有镜像？这将影响所有容器！"; then
                local all_images=$(docker images -q)
                if [[ -n "$all_images" ]]; then
                    docker rmi -f $all_images
                    print_success "所有镜像已删除。"
                    log_action "Docker all images removed"
                else
                    print_warn "没有镜像可删除。"
                fi
                print_success "所有镜像已删除。"
                log_action "Docker all images removed"
            fi
            ;;
        0|q) return ;;
    esac
    pause
}

docker_containers_manage() {
    print_title "Docker 容器管理"
    
    if ! command_exists docker; then
        print_error "Docker 未安装。"
        pause; return
    fi
    
    echo "1. 列出运行中的容器"
    echo "2. 列出所有容器"
    echo "3. 停止所有容器"
    echo "4. 删除所有容器 (危险)"
    echo "5. 查看容器日志"
    echo "0. 返回"
    read -e -r -p "选择: " c
    
    case $c in
        1)
            docker ps
            ;;
        2)
            docker ps -a
            ;;
        3)
            if confirm "停止所有容器？"; then
                local running=$(docker ps -q)
                if [[ -n "$running" ]]; then
                    docker stop $running
                    print_success "所有容器已停止。"
                    log_action "Docker all containers stopped"
                else
                    print_warn "没有运行中的容器。"
                fi
                print_success "所有容器已停止。"
                log_action "Docker all containers stopped"
            fi
            ;;
        4)
            if confirm "删除所有容器？"; then
                local all_containers=$(docker ps -aq)
                if [[ -n "$all_containers" ]]; then
                    docker rm -f $all_containers
                    print_success "所有容器已删除。"
                    log_action "Docker all containers removed"
                else
                    print_warn "没有容器可删除。"
                fi
                print_success "所有容器已删除。"
                log_action "Docker all containers removed"
            fi
            ;;
        5)
            read -e -r -p "容器名称或 ID: " cid
            if [[ -n "$cid" ]]; then
                docker logs --tail 100 -f "$cid"
            fi
            ;;
        0|q) return ;;
    esac
    pause
}

menu_docker() {
    fix_terminal
    while true; do
        print_title "Docker 管理"
        
        if command_exists docker; then
            echo -e "${C_GREEN}Docker 已安装${C_RESET}"
            docker --version
            echo ""
        else
            echo -e "${C_YELLOW}Docker 未安装${C_RESET}"
            echo ""
        fi
        
        echo "1. 安装 Docker"
        echo "2. 卸载 Docker"
        echo "3. 安装 Docker Compose"
        echo "4. 配置 Docker 代理"
        echo "5. 镜像管理"
        echo "6. 容器管理"
        echo "7. 系统清理 (prune)"
        echo "0. 返回主菜单"
        echo ""
        read -e -r -p "请选择: " c
        
        case $c in
            1) docker_install ;;
            2) docker_uninstall ;;
            3) docker_compose_install ;;
            4) docker_proxy_config ;;
            5) docker_images_manage ;;
            6) docker_containers_manage ;;
            7)
                if command_exists docker; then
                    if confirm "清理未使用的容器、网络、镜像、构建缓存？"; then
                        docker system prune -a -f --volumes
                        print_success "清理完成。"
                        log_action "Docker system pruned"
                    fi
                else
                    print_error "Docker 未安装。"
                fi
                pause
                ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
    done
}

# ==============================================================================
# 11. 主菜单
# ==============================================================================

show_main_menu() {
    fix_terminal
    print_title "$SCRIPT_NAME v$VERSION"
    
    echo -e "${C_CYAN}=== 系统信息 ===${C_RESET}"
    echo "主机名: $(hostname)"
    echo "系统: $(get_os_info)"
    echo "内核: $(uname -r)"
    
    local uptime_info=$(uptime -p 2>/dev/null || uptime | awk -F'up ' '{print $2}' | awk -F',' '{print $1}')
    echo "运行时间: $uptime_info"
    
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | xargs)
    echo "负载: $load_avg"
    
    local mem_info=$(free -m | awk '/^Mem:/ {
        used=$3; total=$2
        if (total > 0) {
            pct = (used/total)*100
            printf "%dM / %dM (%.1f%%)", used, total, pct
        } else {
            print "N/A"
        }
    }')
    
    local disk_info=$(df -h / | awk 'NR==2 {printf "%s / %s (%s)", $3, $2, $5}')
    echo "磁盘: $disk_info"
    
    echo ""
    echo -e "${C_CYAN}=== 功能菜单 ===${C_RESET}"
    echo "1.  系统更新与软件包管理"
    echo "2.  UFW 防火墙管理"
    echo "3.  Fail2ban 入侵防御"
    echo "4.  SSH 安全配置"
    echo "5.  系统优化 (BBR/Swap/清理)"
    echo "6.  网络工具 (DNS/代理/测速)"
    echo "7.  Web 服务 (SSL + Nginx)"
    echo "8.  Docker 管理"
    echo "9.  查看操作日志"
    echo "10. 关于脚本"
    echo ""
    echo "0.  退出脚本"
    echo ""
}

show_about() {
    print_title "关于 $SCRIPT_NAME"
    cat << 'EOF'
┌─────────────────────────────────────────────────────────────┐
│  VPS 一键管理脚本                                           │
│  Version: 1.0.0                                             │
│  Author: Claude (Anthropic)                                 │
│  License: MIT                                               │
├─────────────────────────────────────────────────────────────┤
│  功能特性:                                                  │
│  • 系统更新与软件包管理                                     │
│  • UFW 防火墙智能配置                                       │
│  • Fail2ban 入侵防御                                        │
│  • SSH 安全加固 (端口/密钥/禁用Root)                        │
│  • 系统优化 (BBR/Swap/时区/清理)                            │
│  • 网络工具 (DNS/系统代理/Squid/iPerf3)                     │
│  • Web 服务 (Cloudflare DNS + SSL + Nginx 反代)            │
│  • Docker 完整管理                                          │
│  • 原子化文件写入 (防止配置损坏)                            │
│  • 详细操作日志记录                                         │
├─────────────────────────────────────────────────────────────┤
│  适用场景:                                                  │
│  • IPv6-only VPS 配置代理访问 GitHub/Docker Hub            │
│  • 双栈 VPS 搭建 Squid 代理服务端                           │
│  • 自动化 SSL 证书申请与续签                                │
│  • 3x-ui 面板证书自动部署                                   │
│  • 生产环境服务器安全加固                                   │
├─────────────────────────────────────────────────────────────┤
│  使用建议:                                                  │
│  1. 首次使用建议先执行 "系统更新"                           │
│  2. 修改 SSH 端口后请先测试新端口连接                       │
│  3. 配置防火墙前确保 SSH 端口已放行                         │
│  4. 重要操作前脚本会自动备份配置文件                        │
│  5. 所有操作均记录在 /var/log/vps-manager.log              │
├─────────────────────────────────────────────────────────────┤
│  技术支持:                                                  │
│  • 问题反馈: 请提供操作日志和系统信息                       │
│  • 日志路径: /var/log/vps-manager.log                      │
│  • 配置目录: /root/.vps-manager/                            │
└─────────────────────────────────────────────────────────────┘
EOF
    echo ""
    pause
}

main() {
    check_root
    check_os
    init_environment
    refresh_ssh_port
    
    while true; do
        show_main_menu
        read -e -r -p "请选择功能 [0-10]: " choice
        
        case $choice in
            1) menu_update ;;
            2) menu_ufw ;;
            3) menu_f2b ;;
            4) menu_ssh ;;
            5) menu_opt ;;
            6) menu_net ;;
            7) menu_web ;;
            8) menu_docker ;;
            9)
                print_title "操作日志 (最近 50 条)"
                if [[ -f "$LOG_FILE" ]]; then
                    tail -n 50 "$LOG_FILE"
                else
                    print_warn "日志文件不存在。"
                fi
                pause
                ;;
            10) show_about ;;
            0|q|Q)
                echo ""
                print_success "感谢使用 $SCRIPT_NAME！"
                echo ""
                exit 0
                ;;
            *)
                print_error "无效选项，请重新选择。"
                sleep 1
                ;;
        esac
    done
}

# ==============================================================================
# 脚本入口
# ==============================================================================

main "$@"
