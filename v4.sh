#!/bin/bash

# ==============================================================================
# 服务器初始化与管理脚本 (v13.13 - Functionality Restored)
#
# 更新日志 v13.13:
# 1. [回归] web_delete_domain: 恢复并重写了"删除配置"功能。
#    - 支持菜单选择已添加的域名。
#    - 自动执行全套清理：Certbot证书、Nginx配置、Hook脚本、Crontab任务、本地配置。
#    - 解决了之前版本只弹提示不干活的问题。
# ==============================================================================

# --- 全局常量配置 (Readonly) ---
readonly VERSION="v13.13"
readonly SCRIPT_NAME="server-manage"
readonly LOG_FILE="/var/log/${SCRIPT_NAME}.log"
readonly CONFIG_FILE="/etc/${SCRIPT_NAME}.conf"

# 颜色定义
readonly C_RESET='\033[0m'
readonly C_RED='\033[0;31m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_BLUE='\033[0;34m'
readonly C_CYAN='\033[0;36m'
readonly C_GRAY='\033[0;90m'

# --- 默认变量 ---
CF_API_TOKEN=""
DOMAIN=""
EMAIL="your@mail.com"
CERT_PATH_PREFIX="/root/cert"
CONFIG_DIR="${CERT_PATH_PREFIX}/.managed_domains"
DDNS_FREQUENCY=5
DEFAULT_SSH_PORT=22

# 关键路径变量
SSHD_CONFIG="/etc/ssh/sshd_config"
FAIL2BAN_JAIL_LOCAL="/etc/fail2ban/jail.local"

# 加载外部配置
if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
fi

# 动态变量
CLOUDFLARE_CREDENTIALS=""
DEPLOY_HOOK_SCRIPT=""
NGINX_CONF_PATH=""
CURRENT_SSH_PORT=""
APT_UPDATED=0

# ==============================================================================
# 0. 基础工具库 (Utils)
# ==============================================================================

# 错误追踪设置
set -o errtrace

# 获取终端宽度
get_term_width() {
    tput cols 2>/dev/null || echo 80
}

# 画分隔线
draw_line() {
    local width=$(get_term_width)
    printf "%${width}s\n" | tr " " "-"
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
    printf "%${padding}s%s%${padding}s\n" "" "$title" ""
    printf "%${width}s\n" | tr " " "="
    echo -e "${C_RESET}"
}

# 统一状态输出
print_info() { echo -e "${C_BLUE}[i] $1${C_RESET}"; }
print_success() { echo -e "${C_GREEN}[✓] $1${C_RESET}"; }
print_warn() { echo -e "${C_YELLOW}[!] $1${C_RESET}"; }
print_error() { echo -e "${C_RED}[✗] $1${C_RESET}"; }

# 日志记录
log_action() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

# 暂停/按键继续 (TTY检测)
pause() {
    [[ -t 0 ]] || return 0
    echo ""
    read -n 1 -s -r -p "按任意键继续..."
    echo ""
}

# 原子写入文件
write_file_atomic() {
    local filepath="$1"
    local content="$2"
    local tmpfile
    
    mkdir -p "$(dirname "$filepath")"
    tmpfile=$(mktemp "$(dirname "$filepath")/.tmp.XXXXXX")
    
    printf "%s\n" "$content" > "$tmpfile"
    
    if [[ -f "$filepath" ]]; then
        chmod --reference="$filepath" "$tmpfile"
        chown --reference="$filepath" "$tmpfile"
    fi
    mv "$tmpfile" "$filepath"
}

# 安全 Curl
safe_curl() {
    curl -s -L --connect-timeout 5 --max-time 10 --retry 3 --retry-delay 2 "$@"
}

# 错误处理
cleanup_and_exit() {
    local exit_code=$?
    rm -f "/etc/fail2ban/jail.local.tmp.$$" 2>/dev/null
    rm -f /etc/*.tmp.* 2>/dev/null
    if [[ $exit_code -ne 0 ]]; then
        print_error "脚本异常退出 (Code: $exit_code)"
        log_action "Script crashed with exit code $exit_code"
    fi
    exit $exit_code
}
trap 'cleanup_and_exit' ERR SIGINT SIGTERM

# 环境检查
check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        print_error "请使用 root 权限运行 (sudo)。"
        exit 1
    fi
}

command_exists() { command -v "$1" >/dev/null 2>&1; }

is_systemd() {
    if command_exists systemctl && [[ -d /run/systemd/system ]]; then return 0; else return 1; fi
}

# 更新 SSH 端口变量
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
        read -r -p "$(echo -e "${C_YELLOW}${prompt} [Y/n]:${C_RESET} ")" reply
        case "${reply,,}" in
            y|yes|"") return 0 ;;
            n|no) return 1 ;;
            *) print_warn "请输入 y 或 n" ;;
        esac
    done
}

# ==============================================================================
# 1. 依赖管理
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
    local silent="$2"
    
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
    return 0
}

auto_deps() {
    local deps="curl wget jq unzip openssl ca-certificates iproute2 net-tools"
    for p in $deps; do
        if ! dpkg -s "$p" &> /dev/null; then install_package "$p" "silent"; fi
    done
    if ! command_exists snap; then install_package "snapd" "silent" || true; fi
}

reinstall_deps() {
    print_title "重装基础依赖"
    APT_UPDATED=0
    update_apt_cache
    local deps="curl wget jq unzip openssl ca-certificates ufw fail2ban nginx iproute2 net-tools"
    for p in $deps; do install_package "$p"; done
    
    print_info "尝试安装 Snapd (可选)..."
    install_package "snapd" || print_warn "Snapd 安装失败 (环境不支持?)，跳过。" || true
    
    print_success "依赖维护完成。"
    pause
}

# ==============================================================================
# 2. 系统信息 (System Info - 经典详细版)
# ==============================================================================

sys_info() {
    print_title "系统状态查询"
    
    local ip4=$(safe_curl https://api.ipify.org || echo "")
    local ip6=$(safe_curl https://api64.ipify.org || echo "")
    
    local ipinfo_json=$(safe_curl https://ipinfo.io/json || echo "{}")
    local country=$(echo "$ipinfo_json" | jq -r '.country // "N/A"' 2>/dev/null || echo "N/A")
    local city=$(echo "$ipinfo_json" | jq -r '.city // "N/A"' 2>/dev/null || echo "N/A")
    local isp=$(echo "$ipinfo_json" | jq -r '.org // "N/A"' 2>/dev/null || echo "N/A")

    local net_stats=$(awk 'BEGIN {rx=0; tx=0} $1 ~ /^(eth|ens|enp|eno)[0-9]+/ {rx+=$2; tx+=$10} END {printf "%.2fGB %.2fGB", rx/1024/1024/1024, tx/1024/1024/1024}' /proc/net/dev 2>/dev/null || echo "0 0")
    local rx_total=$(echo "$net_stats" | awk '{print $1}')
    local tx_total=$(echo "$net_stats" | awk '{print $2}')

    local cpu_model=$(lscpu | awk -F': +' '/Model name:/ {print $2; exit}' || echo "Unknown")
    local cpu_usage=$(awk '{u=$2+$4; t=$2+$4+$5; if (NR==1){u1=u; t1=t;} else printf "%.1f%%", (($2+$4-u1) * 100 / (t-t1))}' <(grep 'cpu ' /proc/stat) <(sleep 1; grep 'cpu ' /proc/stat) || echo "0%")
    local cpu_cores=$(nproc || echo "1")
    local cpu_freq=$(cat /proc/cpuinfo | grep "MHz" | head -n 1 | awk '{printf "%.1f GHz", $4/1000}' || echo "N/A")
    local cpu_arch=$(uname -m)
    
    local mem_line=$(free -m | grep Mem)
    local mem_total=$(echo "$mem_line" | awk '{print $2}')
    local mem_used=$(echo "$mem_line" | awk '{print $3}')
    local mem_pct=0
    [[ "$mem_total" -gt 0 ]] && mem_pct=$(( mem_used * 100 / mem_total ))
    local mem_info="${mem_used}MB / ${mem_total}MB (${mem_pct}%)"
    
    local swap_info=$(free -m | awk 'NR==3{used=$3; total=$2; if (total == 0) {percentage=0} else {percentage=used*100/total}; printf "%dM/%dM (%d%%)", used, total, percentage}' || echo "N/A")
    local disk_info=$(df -h | awk '$NF=="/"{printf "%s/%s (%s)", $3, $2, $5}' || echo "N/A")
    
    local load=$(uptime | awk '{print $(NF-2), $(NF-1), $NF}' || echo "N/A")
    local dns_addresses=$(awk '/^nameserver/{printf "%s ", $2} END {print ""}' /etc/resolv.conf || echo "N/A")
    
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

    print_info "正在测试实时网速 (采样 1 秒)..."
    local net_dev=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n 1 || true)
    [[ -z "$net_dev" ]] && net_dev=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo" | head -n 1 || true)
    
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
# 3. UFW 防火墙模块
# ==============================================================================

check_port_usage() {
    print_title "本机端口监听状态"
    
    if ! command_exists ss && ! command_exists netstat; then
        install_package "iproute2" || install_package "net-tools"
    fi

    local awk_logic='
    function get_purpose(p) {
        if(p==21)return "FTP"; if(p==22)return "SSH"; if(p==25)return "SMTP";
        if(p==53)return "DNS"; if(p==80)return "HTTP"; if(p==443)return "HTTPS";
        if(p==3306)return "MySQL"; if(p==5201)return "iPerf3"; if(p==5432)return "PostgreSQL";
        if(p==6379)return "Redis"; if(p==8080)return "Web Alt";
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
    else
        print_error "无法获取端口信息。"
    fi
    pause
}

ufw_setup() {
    install_package "ufw"
    if is_systemd && systemctl is-active --quiet firewalld; then
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
        log_action "Enabled UFW firewall"
    fi
    pause
}

ufw_add() {
    read -r -p "请输入要放行的端口 (空格隔开): " ports
    [[ -z "$ports" ]] && return
    for port in $ports; do
        if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -le 65535 ]; then
            ufw allow "$port/tcp" comment "Manual-Add-$port" >/dev/null
            print_success "端口 $port/tcp 已放行。"
            log_action "UFW allow port $port"
        else
            print_error "端口 $port 无效。"
        fi
    done
    pause
}

ufw_del() {
    if ! command_exists ufw; then print_error "UFW 未安装。"; pause; return; fi
    if ! ufw status | grep -q "Status: active"; then print_error "UFW 未运行。"; pause; return; fi
    
    ufw status numbered
    read -r -p "输入要删除的规则编号 (空格隔开): " nums
    [[ -z "$nums" ]] && return
    
    for num in $(echo "$nums" | tr ' ' '\n' | sort -nr); do
        echo "y" | ufw delete "$num" >/dev/null 2>&1
        print_success "规则 $num 已删除。"
        log_action "UFW delete rule $num"
    done
    pause
}

ufw_safe_reset() {
    if ! command_exists ufw; then print_error "UFW 未安装。"; pause; return; fi
    
    if confirm "这将重置所有规则！脚本会尝试保留当前 SSH 端口，确定吗？"; then
        print_info "正在重置..."
        echo "y" | ufw disable >/dev/null
        echo "y" | ufw reset >/dev/null
        
        ufw default deny incoming >/dev/null
        ufw default allow outgoing >/dev/null
        ufw allow "$CURRENT_SSH_PORT/tcp" comment "SSH-Access" >/dev/null
        
        echo "y" | ufw enable >/dev/null
        ufw reload >/dev/null
        
        print_success "重置完成。SSH 端口 $CURRENT_SSH_PORT 已放行。"
        log_action "UFW reset to defaults"
    fi
    pause
}

menu_ufw() {
    while true; do
        print_title "UFW 防火墙管理"
        echo "1. 安装并启用 UFW"
        echo "2. 查看本机监听端口 (洞察模式)"
        echo "3. 添加放行端口"
        echo "4. 查看当前规则"
        echo "5. 删除规则"
        echo -e "${C_RED}6. 允许所有入站 (危险)${C_RESET}"
        echo "7. 重置默认规则 (安全模式)"
        echo -e "${C_RED}8. 卸载 UFW${C_RESET}"
        echo "0. 返回主菜单"
        echo ""
        read -r -p "请选择: " c
        case $c in
            1) ufw_setup ;; 2) check_port_usage ;; 3) ufw_add ;;
            4) ufw status numbered; pause ;; 5) ufw_del ;;
            6) confirm "允许所有入站？" && ufw default allow incoming && ufw reload && print_success "已允许所有。" && pause ;;
            7) ufw_safe_reset ;;
            8) confirm "卸载 UFW？" && (ufw disable; apt-get remove --purge ufw -y) && print_success "已卸载。" && pause ;;
            0|q) break ;; *) print_error "无效选项" ;;
        esac
    done
}

# ==============================================================================
# 4. Fail2ban 模块
# ==============================================================================

f2b_setup() {
    print_title "Fail2ban 安装与配置"
    install_package "fail2ban" "silent"
    install_package "rsyslog" "silent"
    
    local backend="auto"
    local journal=""
    if is_systemd; then
        systemctl enable rsyslog >/dev/null 2>&1 || true
        systemctl restart rsyslog || true
        backend="systemd"
        journal="journalmatch = _SYSTEMD_UNIT=sshd.service + _COMM=sshd"
    fi

    print_info "生成配置文件..."
    read -r -p "监控 SSH 端口 [$CURRENT_SSH_PORT]: " port
    port=${port:-$CURRENT_SSH_PORT}
    
    local conf_content="[DEFAULT]
bantime = 10m
banaction = ufw
[sshd]
enabled = true
port = $port
maxretry = 5
bantime = 10m
backend = $backend
$journal"

    write_file_atomic "$FAIL2BAN_JAIL_LOCAL" "$conf_content"
    print_success "配置已写入。"

    if is_systemd; then
        systemctl enable fail2ban >/dev/null || true
        systemctl restart fail2ban || print_warn "启动失败，请检查日志。"
        systemctl is-active --quiet fail2ban && print_success "Fail2ban 运行中。"
    else
        print_warn "非 Systemd 环境，请手动启动 Fail2ban。"
    fi
    log_action "Fail2ban setup completed"
    pause
}

menu_f2b() {
    while true; do
        print_title "Fail2ban 入侵防御"
        echo "1. 安装/重置配置"
        echo "2. 查看状态/日志"
        echo -e "${C_RED}3. 卸载 Fail2ban${C_RESET}"
        echo "0. 返回主菜单"
        echo ""
        read -r -p "请选择: " c
        case $c in
            1) f2b_setup ;;
            2) 
                if command_exists fail2ban-client; then
                    fail2ban-client status sshd || print_warn "未运行。"
                    echo "--- 日志末尾 ---"
                    tail -n 5 /var/log/fail2ban.log 2>/dev/null
                else
                    print_error "未安装。"
                fi
                pause ;;
            3) 
                if confirm "卸载 Fail2ban？"; then
                    is_systemd && systemctl stop fail2ban || true
                    apt-get remove --purge fail2ban -y
                    rm -f "$FAIL2BAN_JAIL_LOCAL"
                    print_success "已卸载。"
                fi
                pause ;;
            0|q) break ;; *) print_error "无效选项" ;;
        esac
    done
}

# ==============================================================================
# 5. SSH 安全模块
# ==============================================================================

ssh_change_port() {
    print_title "修改 SSH 端口"
    read -r -p "请输入新端口 [$CURRENT_SSH_PORT]: " port
    [[ -z "$port" ]] && return
    
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        print_error "端口无效 (1-65535)。"
        pause; return
    fi

    if command_exists ufw && ufw status | grep -q "Status: active"; then
        ufw allow "$port/tcp" comment "SSH-New" >/dev/null
        print_success "UFW 已放行新端口 $port。"
    fi

    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"
    if grep -qE "^\s*#?\s*Port\s" "$SSHD_CONFIG"; then
        sed -i -E "s|^\s*#?\s*Port\s+.*|Port ${port}|" "$SSHD_CONFIG"
    else
        echo "Port ${port}" >> "$SSHD_CONFIG"
    fi

    if is_systemd; then
        if systemctl restart sshd; then
            print_success "SSH 重启成功。请使用新端口 $port 连接。"
            CURRENT_SSH_PORT=$port
        else
            print_error "重启失败！已回滚配置。"
            mv "${SSHD_CONFIG}.bak" "$SSHD_CONFIG"
            systemctl restart sshd
        fi
    else
        print_success "配置已修改。检测到容器环境，请手动重启 SSH 服务。"
        CURRENT_SSH_PORT=$port
    fi
    log_action "Changed SSH port to $port"
    pause
}

ssh_keys() {
    print_title "SSH 密钥管理"
    echo "1. 导入公钥"
    echo "2. 禁用密码登录"
    read -r -p "选择: " c
    if [[ "$c" == "1" ]]; then
        read -r -p "用户名: " user
        if ! id "$user" >/dev/null 2>&1; then print_error "用户不存在"; pause; return; fi
        read -r -p "粘贴公钥: " key
        [[ -z "$key" ]] && return
        
        local dir="/home/$user/.ssh"
        [[ "$user" == "root" ]] && dir="/root/.ssh"
        mkdir -p "$dir"
        echo "$key" >> "$dir/authorized_keys"
        chmod 700 "$dir"; chmod 600 "$dir/authorized_keys"
        chown -R "$user:$user" "$dir"
        print_success "公钥已添加。"
        
    elif [[ "$c" == "2" ]]; then
        if confirm "确认已测试密钥登录成功？禁用密码登录不可逆！"; then
            sed -i -E "s|^\s*#?\s*PasswordAuthentication\s+.*|PasswordAuthentication no|" "$SSHD_CONFIG"
            sed -i -E "s|^\s*#?\s*PubkeyAuthentication\s+.*|PubkeyAuthentication yes|" "$SSHD_CONFIG"
            is_systemd && systemctl restart sshd
            print_success "密码登录已禁用。"
            log_action "Disabled SSH password auth"
        fi
    fi
    pause
}

menu_ssh() {
    while true; do
        print_title "SSH 安全管理 (当前端口: $CURRENT_SSH_PORT)"
        echo "1. 修改 SSH 端口"
        echo "2. 创建 Sudo 用户"
        echo "3. 禁用 Root 远程登录"
        echo "4. 密钥/密码设置"
        echo "5. 修改用户密码"
        echo "0. 返回主菜单"
        echo ""
        read -r -p "请选择: " c
        case $c in
            1) ssh_change_port ;;
            2) 
                read -r -p "新用户名: " u
                [[ -n "$u" ]] && adduser "$u" && usermod -aG sudo "$u" && print_success "用户创建成功。" && pause ;;
            3)
                confirm "禁用 Root 登录？" && \
                sed -i -E "s|^\s*#?\s*PermitRootLogin\s+.*|PermitRootLogin no|" "$SSHD_CONFIG" && \
                (is_systemd && systemctl restart sshd) && print_success "Root 登录已禁用。" && pause ;;
            4) ssh_keys ;;
            5) read -r -p "用户名 [root]: " u; u=${u:-root}; passwd "$u"; pause ;;
            0|q) break ;; *) print_error "无效选项" ;;
        esac
        refresh_ssh_port
    done
}

# ==============================================================================
# 6. 系统优化模块
# ==============================================================================

opt_cleanup() {
    print_title "系统清理"
    print_info "清理 apt 缓存..."
    apt-get autoremove -y; apt-get autoclean -y; apt-get clean
    print_info "清理旧日志..."
    command_exists journalctl && journalctl --vacuum-time=3d
    find /var/log -name "*.gz" -type f -delete
    print_success "清理完成。"
    pause
}

opt_hostname() {
    print_title "修改主机名"
    echo "当前: $(hostname)"
    read -r -p "新主机名: " new_name
    [[ -z "$new_name" ]] && return
    
    if command_exists hostnamectl; then hostnamectl set-hostname "$new_name" || true; fi
    hostname "$new_name"
    echo "$new_name" > /etc/hostname
    sed -i "s/127.0.0.1.*$//g" /etc/hosts
    sed -i "1i 127.0.0.1 $new_name" /etc/hosts
    print_success "主机名已修改 (重新登录生效)。"
    pause
}

opt_swap() {
    print_title "Swap 管理"
    local size=$(free -m | awk '/Swap/ {print $2}')
    echo "当前 Swap: ${size}MB"
    echo "1. 开启/修改 Swap"
    echo "2. 关闭/删除 Swap"
    read -r -p "选择: " c
    
    if [[ "$c" == "1" ]]; then
        read -r -p "大小 (MB): " s
        [[ ! "$s" =~ ^[0-9]+$ ]] && return
        print_info "正在设置..."
        swapoff -a; rm -f /swapfile
        if ! fallocate -l "${s}M" /swapfile 2>/dev/null; then dd if=/dev/zero of=/swapfile bs=1M count="$s"; fi
        chmod 600 /swapfile; mkswap /swapfile; swapon /swapfile
        if ! grep -q "/swapfile" /etc/fstab; then echo "/swapfile none swap sw 0 0" >> /etc/fstab; fi
        print_success "设置成功。"
    elif [[ "$c" == "2" ]]; then
        swapoff -a; rm -f /swapfile; sed -i '/\/swapfile/d' /etc/fstab
        print_success "已删除。"
    fi
    pause
}

menu_opt() {
    while true; do
        print_title "系统优化"
        echo "1. 开启 BBR 加速"
        echo "2. 虚拟内存 (Swap)"
        echo "3. 修改主机名"
        echo "4. 系统垃圾清理"
        echo "5. 修改时区"
        echo "0. 返回"
        echo ""
        
        # [修复] 变量重置
        local c="" z=""
        read -r -p "选择: " c
        case $c in
            1) 
                confirm "修改内核参数开启 BBR？" && \
                sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf && \
                sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf && \
                echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf && \
                echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf && \
                sysctl -p && print_success "BBR 已开启。" && pause ;;
            2) opt_swap ;; 3) opt_hostname ;; 4) opt_cleanup ;;
            5)
                echo "1.上海 2.香港 3.东京 4.纽约 5.UTC"; read -r -p "选择: " t
                case $t in 1) z="Asia/Shanghai";; 2) z="Asia/Hong_Kong";; 3) z="Asia/Tokyo";; 4) z="America/New_York";; 5) z="UTC";; esac
                [[ -n "$z" ]] && (ln -sf /usr/share/zoneinfo/$z /etc/localtime; print_success "时区已设为 $z") && pause ;;
            0|q) break ;; *) print_error "无效" ;;
        esac
    done
}

# ==============================================================================
# 7. 网络工具模块
# ==============================================================================

net_iperf3() {
    print_title "iPerf3 测速"
    install_package "iperf3"
    read -r -p "监听端口 [5201]: " port
    port=${port:-5201}
    
    local ufw_opened=0
    # [修复] UFW 状态检测修正
    if command_exists ufw && ufw status | grep -q "Status: active"; then
        if ! ufw status | grep -q "$port/tcp"; then
            ufw allow "$port/tcp" comment "iPerf3-Temp" >/dev/null
            ufw_opened=1
            print_info "临时放行端口 $port"
        fi
    fi
    
    local ip4=$(safe_curl https://api.ipify.org)
    local ip6=$(safe_curl https://api64.ipify.org)
    
    echo -e "\n${C_BLUE}=== 客户端测速命令 ===${C_RESET}"
    [[ -n "$ip4" ]] && echo -e "IPv4 Upload: ${C_YELLOW}iperf3 -c $ip4 -p $port${C_RESET}"
    [[ -n "$ip4" ]] && echo -e "IPv4 Download: ${C_YELLOW}iperf3 -c $ip4 -p $port -R${C_RESET}"
    [[ -n "$ip6" ]] && echo -e "IPv6 Upload: ${C_YELLOW}iperf3 -6 -c $ip6 -p $port${C_RESET}"
    [[ -n "$ip6" ]] && echo -e "IPv6 Download: ${C_YELLOW}iperf3 -6 -c $ip6 -p $port -R${C_RESET}"
    echo -e "${C_RED}按 Ctrl+C 停止测试...${C_RESET}"
    
    cleanup_local() {
        print_info "停止服务..."
        trap 'cleanup_and_exit' ERR SIGINT SIGTERM
        if [[ $ufw_opened -eq 1 ]]; then
            ufw delete allow "$port/tcp" >/dev/null 2>&1 || true
            print_info "防火墙规则已移除。"
        fi
    }
    trap 'cleanup_local; return' SIGINT
    
    if ! iperf3 -s -p "$port"; then print_warn "服务中断。"; fi
    cleanup_local
    pause
}

net_dns() {
    print_title "DNS 配置"
    echo "当前 DNS:"
    cat /etc/resolv.conf
    echo -e "\n${C_YELLOW}输入新 DNS IP (空格隔开)，输入 0 取消${C_RESET}"
    read -r -p "DNS: " dns
    if [[ -z "$dns" || "$dns" == "0" ]]; then return; fi
    
    # [安全] 输入校验 (仅允许 IP 格式字符)
    if [[ ! "$dns" =~ ^[0-9a-fA-F:.\ ]+$ ]]; then
        print_error "非法字符！仅允许数字、字母(Hex)、点、冒号和空格。"
        pause
        return
    fi
    
    # [逻辑] 智能处理 Systemd-resolved
    local res_conf="/etc/systemd/resolved.conf"
    if is_systemd && systemctl is-active --quiet systemd-resolved; then
        print_info "检测到 systemd-resolved，修改 resolved.conf..."
        # [增强] 确保 [Resolve] 头部存在 (兼容缩进)
        if ! grep -q "^[[:space:]]*\[Resolve\]" "$res_conf"; then
            echo "" >> "$res_conf"
            echo "[Resolve]" >> "$res_conf"
        fi
        # [硬核] 精准注入 (兼容缩进清理 & 首次定位插入)
        sed -i '/^[[:space:]]*DNS=/d' "$res_conf"
        sed -i "0,/^[[:space:]]*\[Resolve\]/s/^[[:space:]]*\[Resolve\]/&\nDNS=$dns/" "$res_conf"
        systemctl restart systemd-resolved || true
    else
        print_info "直接修改 resolv.conf..."
        cp /etc/resolv.conf /etc/resolv.conf.bak
        local tmp=$(mktemp)
        for ip in $dns; do echo "nameserver $ip" >> "$tmp"; done
        write_file_atomic "/etc/resolv.conf" "$(cat "$tmp")"
        rm -f "$tmp"
    fi
    print_success "DNS 已修改。"
    pause
}

menu_net() {
    while true; do
        print_title "网络管理工具"
        echo "1. DNS 配置"
        echo "2. IPv4/IPv6 优先级"
        echo "3. iPerf3 测速"
        echo "0. 返回"
        echo ""
        read -r -p "选择: " c
        case $c in
            1) net_dns ;;
            2) 
                echo "1. 优先 IPv4  2. 优先 IPv6"; read -r -p "选: " p
                [[ ! -f /etc/gai.conf ]] && touch /etc/gai.conf
                if [[ "$p" == "1" ]]; then
                    sed -i 's/^#precedence ::ffff:0:0\/96  100/precedence ::ffff:0:0\/96  100/' /etc/gai.conf
                    grep -q "precedence ::ffff:0:0/96  100" /etc/gai.conf || echo "precedence ::ffff:0:0/96  100" >> /etc/gai.conf
                    print_success "IPv4 优先。"
                else
                    sed -i 's/^precedence ::ffff:0:0\/96  100/#precedence ::ffff:0:0\/96  100/' /etc/gai.conf
                    print_success "IPv6 优先。"
                fi
                pause ;;
            3) net_iperf3 ;; 0|q) break ;; *) print_error "无效" ;;
        esac
    done
}

# ==============================================================================
# 8. Web 服务模块
# ==============================================================================

web_env_check() {
    if ! command_exists nginx; then install_package "nginx"; fi
    is_systemd && (systemctl enable --now nginx >/dev/null 2>&1 || true)
    
    if ! command_exists certbot; then
        print_info "安装 Certbot..."
        update_apt_cache
        if ! apt-get install -y certbot python3-certbot-dns-cloudflare; then
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
}

# [重要] 恢复交互式删除功能 (v13.13)
web_delete_domain() {
    print_title "删除域名配置"
    
    local i=1
    local domains=()
    local files=()
    
    # 启用 nullglob 避免没有文件时报错
    shopt -s nullglob
    local conf_files=("${CONFIG_DIR}"/*.conf)
    shopt -u nullglob
    
    if [[ ${#conf_files[@]} -eq 0 ]]; then
        print_warn "当前没有已保存的域名配置。"
        pause
        return
    fi
    
    echo "发现以下配置:"
    for conf in "${conf_files[@]}"; do
        # 子 shell 提取变量，防止污染
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
    read -r -p "请输入序号删除: " idx
    
    if [[ "$idx" == "0" || -z "$idx" ]]; then return; fi
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -gt ${#domains[@]} ]]; then
        print_error "无效序号。"
        pause
        return
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
    
    # 1. Certbot 删除
    if certbot delete --cert-name "$target_domain" --non-interactive; then
        print_success "证书已吊销/删除。"
    else
        print_warn "Certbot 删除失败或证书不存在。"
    fi
    
    # 2. Nginx 清理
    local nginx_conf="/etc/nginx/sites-enabled/${target_domain}.conf"
    local nginx_conf_src="/etc/nginx/sites-available/${target_domain}.conf"
    if [[ -f "$nginx_conf" || -f "$nginx_conf_src" ]]; then
        rm -f "$nginx_conf" "$nginx_conf_src"
        if is_systemd; then systemctl reload nginx; else nginx -s reload; fi
        print_success "Nginx 配置已删除。"
    fi
    
    # 3. Hook 清理
    local hook_script="/root/cert-renew-hook-${target_domain}.sh"
    if [[ -f "$hook_script" ]]; then
        rm -f "$hook_script"
        print_success "Hook 脚本已删除。"
    fi
    
    # 4. Crontab 清理
    if crontab -l 2>/dev/null | grep -q "$hook_script"; then
        crontab -l | grep -v "$hook_script" | crontab -
        print_success "Crontab 任务已清理。"
    fi
    
    # 5. 自身配置清理
    rm -f "$target_conf"
    print_success "管理配置已移除。"
    
    log_action "Deleted domain config: $target_domain"
    pause
}

web_add_domain() {
    print_title "添加域名配置 (SSL + Nginx)"
    # [隔离] 显式声明局部变量，建立沙箱
    local DOMAIN="" CF_API_TOKEN="" LOCAL_PROXY_PASS="" NGINX_HTTP_PORT="" NGINX_HTTPS_PORT="" BACKEND_PROTOCOL="" CLOUDFLARE_CREDENTIALS="" DEPLOY_HOOK_SCRIPT="" NGINX_CONF_PATH="" hp="" sp="" proto="" inp=""
    
    web_env_check || { pause; return; }
    
    while [[ -z "$DOMAIN" ]]; do read -r -p "域名: " DOMAIN; done
    if [[ -f "${CONFIG_DIR}/${DOMAIN}.conf" ]]; then print_warn "配置已存在，请先删除。"; pause; return; fi
    
    while [[ -z "$CF_API_TOKEN" ]]; do read -s -r -p "Cloudflare API Token: " CF_API_TOKEN; echo ""; done
    
    local do_nginx=0
    if confirm "配置 Nginx 反代?"; then
        do_nginx=1
        read -r -p "HTTP 端口 [80]: " hp; NGINX_HTTP_PORT=${hp:-80}
        read -r -p "HTTPS 端口 [443]: " sp; NGINX_HTTPS_PORT=${sp:-443}
        read -r -p "后端协议 [1]http [2]https: " proto
        BACKEND_PROTOCOL=$([[ "$proto" == "2" ]] && echo "https" || echo "http")
        
        while [[ -z "$LOCAL_PROXY_PASS" ]]; do
            read -r -p "反代目标 (如 127.0.0.1:10000): " inp
            [[ "$inp" =~ ^[0-9]+$ ]] && inp="127.0.0.1:$inp"
            if [[ "$inp" =~ ^(\[.*\]|[a-zA-Z0-9.-]+):[0-9]+$ ]]; then
                LOCAL_PROXY_PASS="${BACKEND_PROTOCOL}://${inp}"
            else print_warn "格式错误"; fi
        done
    fi
    
    mkdir -p "${CERT_PATH_PREFIX}/${DOMAIN}"
    CLOUDFLARE_CREDENTIALS="/root/.cloudflare-${DOMAIN}.ini"
    write_file_atomic "$CLOUDFLARE_CREDENTIALS" "dns_cloudflare_api_token = $CF_API_TOKEN"
    chmod 600 "$CLOUDFLARE_CREDENTIALS"
    
    print_info "申请证书中 (请稍候)..."
    if certbot certonly --dns-cloudflare --dns-cloudflare-credentials "$CLOUDFLARE_CREDENTIALS" --dns-cloudflare-propagation-seconds 60 -d "$DOMAIN" --email "$EMAIL" --agree-tos --no-eff-email --non-interactive; then
        print_success "证书获取成功。"
        local cert_dir="${CERT_PATH_PREFIX}/${DOMAIN}"
        cp -L "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$cert_dir/fullchain.pem"
        cp -L "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$cert_dir/privkey.pem"
        
        if [[ $do_nginx -eq 1 ]]; then
            NGINX_CONF_PATH="/etc/nginx/sites-available/${DOMAIN}.conf"
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
server {
    listen $NGINX_HTTP_PORT;
    listen [::]:$NGINX_HTTP_PORT;
    server_name $DOMAIN;
    location / { return 301 https://\$host${redir_port}\$request_uri; }
}
server {
    listen $NGINX_HTTPS_PORT ssl http2;
    listen [::]:$NGINX_HTTPS_PORT ssl http2;
    server_name $DOMAIN;
    
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/$DOMAIN/chain.pem;
    include /etc/nginx/snippets/ssl-params.conf;
    
    location / {
        proxy_pass $LOCAL_PROXY_PASS;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
    }
}"
            write_file_atomic "$NGINX_CONF_PATH" "$nginx_conf"
            ln -sf "$NGINX_CONF_PATH" "/etc/nginx/sites-enabled/${DOMAIN}.conf"
            
            if nginx -t; then
                if is_systemd; then 
                    systemctl reload nginx || systemctl restart nginx
                else 
                    nginx -s reload || nginx
                fi
                print_success "Nginx 配置生效。"
            else
                print_error "Nginx 配置错误。"
            fi
        fi
        
        DEPLOY_HOOK_SCRIPT="/root/cert-renew-hook-${DOMAIN}.sh"
        # [修复] 增加 3x-ui 重启逻辑 (v13.15 logic)
        local hook_content="#!/bin/bash
mkdir -p \"$cert_dir\"
cp -L /etc/letsencrypt/live/$DOMAIN/fullchain.pem \"$cert_dir/fullchain.pem\"
cp -L /etc/letsencrypt/live/$DOMAIN/privkey.pem \"$cert_dir/privkey.pem\"
# 权限修正 (v13.14 fix)
chmod 644 \"$cert_dir/fullchain.pem\"
chmod 644 \"$cert_dir/privkey.pem\"

# Reload Nginx
if [ -d /run/systemd/system ]; then systemctl reload nginx || true; else nginx -s reload || true; fi

# Restart 3x-ui/x-ui (Robust method v13.15)
command -v x-ui >/dev/null 2>&1 && x-ui restart || \\
command -v 3x-ui >/dev/null 2>&1 && 3x-ui restart || \\
systemctl restart x-ui 2>/dev/null || \\
systemctl restart 3x-ui 2>/dev/null || true"

        write_file_atomic "$DEPLOY_HOOK_SCRIPT" "$hook_content"
        chmod +x "$DEPLOY_HOOK_SCRIPT"
        
        mkdir -p "$CONFIG_DIR"
        chmod 700 "$CONFIG_DIR"
        write_file_atomic "${CONFIG_DIR}/${DOMAIN}.conf" "DOMAIN=\"$DOMAIN\"; CERT_PATH=\"$cert_dir\"; DEPLOY_HOOK_SCRIPT=\"$DEPLOY_HOOK_SCRIPT\""
        chmod 600 "${CONFIG_DIR}/${DOMAIN}.conf"
        
        (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --deploy-hook \"$DEPLOY_HOOK_SCRIPT\"") | sort -u | crontab -
        
        print_success "域名添加完成！"
        log_action "Added domain $DOMAIN"
    else
        print_error "证书申请失败。"
        rm -f "$CLOUDFLARE_CREDENTIALS"
    fi
    pause
}

menu_web() {
    while true; do
        print_title "Web 服务管理"
        echo "1. 添加域名 (SSL+Nginx)"
        echo "2. 证书状态监控"
        echo "3. 手动强制续期"
        echo "4. 删除配置"
        echo "0. 返回"
        echo ""
        
        # [修复] 循环前重置变量，防止污染
        local DOMAIN="" CERT_PATH="" DEPLOY_HOOK_SCRIPT=""
        
        read -r -p "选择: " c
        case $c in
            1) web_add_domain ;;
            2) 
                print_info "检查证书..."
                for conf in "${CONFIG_DIR}"/*.conf; do
                    if [[ -f "$conf" ]]; then
                        # [修复] source 前显式清空
                        DOMAIN="" CERT_PATH="" DEPLOY_HOOK_SCRIPT=""
                        source "$conf"
                        
                        local check_path="${CERT_PATH}/fullchain.pem"
                        if [[ -f "$check_path" ]]; then
                            local end_date
                            end_date=$(openssl x509 -enddate -noout -in "$check_path" | cut -d= -f2)
                            echo -e "域名: ${C_GREEN}${DOMAIN}${C_RESET} | 到期: ${end_date}"
                        else
                            echo -e "域名: ${DOMAIN} | ${C_RED}证书丢失${C_RESET}"
                        fi
                    fi
                done
                pause ;;
            3)
                print_info "正在执行 renew..."
                for conf in "${CONFIG_DIR}"/*.conf; do
                    if [[ -f "$conf" ]]; then
                        # [修复] source 前显式清空
                        DOMAIN="" CERT_PATH="" DEPLOY_HOOK_SCRIPT=""
                        source "$conf"
                        
                        if [[ -n "$DOMAIN" && -n "$DEPLOY_HOOK_SCRIPT" ]]; then
                            print_info "Renewing $DOMAIN ..."
                            certbot renew --cert-name "$DOMAIN" --deploy-hook "$DEPLOY_HOOK_SCRIPT" --force-renewal
                        fi
                    fi
                done
                pause ;;
            4) web_delete_domain ;;
            0|q) break ;; *) print_error "无效" ;;
        esac
    done
}

# ==============================================================================
# 主入口
# ==============================================================================

# CLI 参数解析
case "$1" in
    --help|-h)
        echo "Usage: ./server-manage.sh [options]"
        echo "Options:"
        echo "  --help, -h      Show this help message"
        echo "  --version, -v   Show version info"
        exit 0
        ;;
    --version|-v)
        echo "Server Manage Script $VERSION"
        exit 0
        ;;
esac

check_root
auto_deps
refresh_ssh_port

# 主菜单循环
while true; do
    print_title "Linux Server Manager ($VERSION)"
    echo "1. 系统信息查询"
    echo "2. 基础依赖维护"
    echo "3. UFW 防火墙管理"
    echo "4. Fail2ban 入侵防御"
    echo "5. SSH 安全管理"
    echo "6. 系统优化管理"
    echo "7. 网络管理工具"
    echo "8. Web 服务 (SSL/Nginx)"
    echo "0. 退出脚本"
    echo ""
    read -r -p "请输入选项: " choice
    
    case $choice in
        1) sys_info ;; 2) reinstall_deps ;; 3) menu_ufw ;; 4) menu_f2b ;; 
        5) menu_ssh ;; 6) menu_opt ;; 7) menu_net ;; 8) menu_web ;; 
        0|q) echo "Bye."; exit 0 ;;
        *) print_error "无效选项"; pause ;;
    esac
done
