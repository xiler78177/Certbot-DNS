#!/bin/bash

readonly VERSION="v13.58"
readonly SCRIPT_NAME="server-manage"
readonly LOG_FILE="/var/log/${SCRIPT_NAME}.log"
readonly CONFIG_FILE="/etc/${SCRIPT_NAME}.conf"
readonly CACHE_DIR="/var/cache/${SCRIPT_NAME}"
readonly CACHE_FILE="${CACHE_DIR}/sysinfo.cache"
readonly CACHE_TTL=300 
readonly CERT_HOOKS_DIR="/root/cert-hooks"
readonly WG_DEFAULT_PORT=50000
PLATFORM="debian"

detect_platform() {
    if [[ -f /etc/openwrt_release ]]; then
        PLATFORM="openwrt"
    elif [[ -f /etc/os-release ]]; then
        local os_id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
        case "$os_id" in
            ubuntu|debian) PLATFORM="debian" ;;
            *) command -v opkg &>/dev/null && PLATFORM="openwrt" ;;
        esac
    elif command -v opkg &>/dev/null; then
        PLATFORM="openwrt"
    fi
}
detect_platform

feature_blocked() {
    echo ""
    echo -e "${C_YELLOW}[!] 功能不可用: $1${C_RESET}"
    echo -e "${C_YELLOW}    当前系统: OpenWrt (仅支持 Web/DNS/DDNS/BBR/基础信息)${C_RESET}"
    echo ""
    read -n 1 -s -r -p "按任意键继续..."
    echo ""
}

readonly C_RESET='\033[0m'
readonly C_RED='\033[0;31m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_BLUE='\033[0;34m'
readonly C_CYAN='\033[0;36m'
readonly C_GRAY='\033[0;90m'
readonly C_DIM='\033[2m'

CF_API_TOKEN=""
DOMAIN=""
EMAIL="your@mail.com"
CERT_PATH_PREFIX="/root/cert"
CONFIG_DIR="${CERT_PATH_PREFIX}/.managed_domains"
DEFAULT_SSH_PORT=22

SSHD_CONFIG="/etc/ssh/sshd_config"
FAIL2BAN_JAIL_LOCAL="/etc/fail2ban/jail.local"
DOCKER_PROXY_DIR="/etc/systemd/system/docker.service.d"
DOCKER_PROXY_CONF="${DOCKER_PROXY_DIR}/http-proxy.conf"

[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"

CLOUDFLARE_CREDENTIALS=""
DEPLOY_HOOK_SCRIPT=""
NGINX_CONF_PATH=""
CURRENT_SSH_PORT=""
APT_UPDATED=0

CACHED_IPV4=""
CACHED_IPV6=""
CACHED_ISP=""
CACHED_LOCATION=""

DDNS_CONFIG_DIR="/etc/ddns"
DDNS_LOG="/var/log/ddns.log"

ddns_create_script() {
    mkdir -p "$DDNS_CONFIG_DIR"
        cat > /usr/local/bin/ddns-update.sh << 'EOF'
#!/bin/bash
DDNS_CONFIG_DIR="/etc/ddns"
DDNS_LOG="/var/log/ddns.log"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$DDNS_LOG"; }

get_ip() {
    local raw=""
    if [[ "$1" == "4" ]]; then
        raw=$(curl -4 -s --max-time 5 https://4.ipw.cn 2>/dev/null || \
              curl -4 -s --max-time 5 https://myip.ipip.net/ip 2>/dev/null || \
              curl -4 -s --max-time 5 https://api.ipify.org 2>/dev/null || \
              curl -4 -s --max-time 5 https://ifconfig.me 2>/dev/null)
        [[ "$raw" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && echo "$raw" || return 1
    else
        raw=$(curl -6 -s --max-time 5 https://6.ipw.cn 2>/dev/null || \
              curl -6 -s --max-time 5 https://api64.ipify.org 2>/dev/null || \
              curl -6 -s --max-time 5 https://ifconfig.me 2>/dev/null)
        [[ "$raw" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$raw" == *:* ]] && echo "$raw" || return 1
    fi
}

update_cf() {
    local domain=$1 rt=$2 ip=$3 token=$4 zone=$5 proxied=$6
    local resp=$(curl -s "https://api.cloudflare.com/client/v4/zones/$zone/dns_records?type=$rt&name=$domain" \
        -H "Authorization: Bearer $token" -H "Content-Type: application/json")
    local rid=$(echo "$resp" | jq -r '.result[0].id // empty')
    local dns_ip=$(echo "$resp" | jq -r '.result[0].content // empty')
    [[ "$ip" == "$dns_ip" ]] && return 0
    
    local method="POST" url="https://api.cloudflare.com/client/v4/zones/$zone/dns_records"
    [[ -n "$rid" ]] && { method="PUT"; url="$url/$rid"; }
    
    resp=$(curl -s -X $method "$url" -H "Authorization: Bearer $token" -H "Content-Type: application/json" \
        --data "{\"type\":\"$rt\",\"name\":\"$domain\",\"content\":\"$ip\",\"ttl\":1,\"proxied\":$proxied}")
    [[ "$(echo "$resp" | jq -r '.success')" == "true" ]] && { log "[$domain] $rt: $dns_ip -> $ip"; return 0; }
    log "[$domain] $rt update failed"; return 1
}

for conf in "$DDNS_CONFIG_DIR"/*.conf; do
    [[ -f "$conf" ]] || continue
    source "$conf"
    [[ "$DDNS_IPV4" == "true" ]] && { ip=$(get_ip 4); [[ -n "$ip" ]] && update_cf "$DDNS_DOMAIN" A "$ip" "$DDNS_TOKEN" "$DDNS_ZONE_ID" "$DDNS_PROXIED"; }
    [[ "$DDNS_IPV6" == "true" ]] && { ip=$(get_ip 6); [[ -n "$ip" ]] && update_cf "$DDNS_DOMAIN" AAAA "$ip" "$DDNS_TOKEN" "$DDNS_ZONE_ID" "$DDNS_PROXIED"; }
done
EOF
    chmod +x /usr/local/bin/ddns-update.sh
}

ddns_setup() {
    local domain=$1 token=$2 zone_id=$3 ipv4=$4 ipv6=$5 proxied=$6
    
    echo ""
    echo -e "${C_CYAN}[DDNS 动态解析配置]${C_RESET}"
    if ! confirm "是否启用 DDNS 自动更新 (IP 变化时自动更新 DNS)?"; then
        return 0
    fi
    
    read -e -r -p "检测间隔(分钟) [5]: " interval
    interval=${interval:-5}
    [[ ! "$interval" =~ ^[0-9]+$ || "$interval" -lt 1 ]] && interval=5
    
    mkdir -p "$DDNS_CONFIG_DIR"
    cat > "$DDNS_CONFIG_DIR/${domain}.conf" << EOF
DDNS_DOMAIN="$domain"
DDNS_TOKEN="$token"
DDNS_ZONE_ID="$zone_id"
DDNS_IPV4="$ipv4"
DDNS_IPV6="$ipv6"
DDNS_PROXIED="$proxied"
DDNS_INTERVAL="$interval"
EOF
    chmod 600 "$DDNS_CONFIG_DIR/${domain}.conf"
    
    ddns_create_script
    
    local min_interval=$interval
    for conf in "$DDNS_CONFIG_DIR"/*.conf; do
        [[ -f "$conf" ]] || continue
        local conf_interval=$(grep '^DDNS_INTERVAL=' "$conf" | cut -d'"' -f2)
        [[ -n "$conf_interval" && "$conf_interval" -lt "$min_interval" ]] 2>/dev/null && min_interval=$conf_interval
    done
    
    local cron_tmp=$(mktemp)
    crontab -l 2>/dev/null | grep -v "ddns-update.sh" > "$cron_tmp" || true
    echo "*/$min_interval * * * * /usr/local/bin/ddns-update.sh >/dev/null 2>&1" >> "$cron_tmp"
    crontab "$cron_tmp"; rm -f "$cron_tmp"
    
    print_success "DDNS 已启用 (每 ${interval} 分钟检测)"
    log_action "DDNS enabled: $domain interval=${interval}m"
    return 0
}

ddns_list() {
    print_title "DDNS 配置列表"
    [[ ! -d "$DDNS_CONFIG_DIR" || -z "$(ls -A "$DDNS_CONFIG_DIR" 2>/dev/null)" ]] && { print_warn "暂无 DDNS 配置"; pause; return; }
    
    printf "${C_CYAN}%-30s %-6s %-6s %-8s %s${C_RESET}\n" "域名" "IPv4" "IPv6" "代理" "间隔"
    draw_line
    for conf in "$DDNS_CONFIG_DIR"/*.conf; do
        [[ -f "$conf" ]] || continue
        source "$conf"
        printf "%-30s %-6s %-6s %-8s %s\n" "$DDNS_DOMAIN" \
            "$([[ "$DDNS_IPV4" == "true" ]] && echo "✓" || echo "-")" \
            "$([[ "$DDNS_IPV6" == "true" ]] && echo "✓" || echo "-")" \
            "$([[ "$DDNS_PROXIED" == "true" ]] && echo "开启" || echo "关闭")" \
            "${DDNS_INTERVAL}分钟"
    done
    
    echo ""
    local ip4=$(curl -4 -s --max-time 3 https://4.ipw.cn 2>/dev/null || curl -4 -s --max-time 3 https://ifconfig.me 2>/dev/null)
    local ip6=$(curl -6 -s --max-time 3 https://6.ipw.cn 2>/dev/null || curl -6 -s --max-time 3 https://ifconfig.me 2>/dev/null)
    echo -e "${C_CYAN}当前IP:${C_RESET} IPv4=${ip4:-N/A} IPv6=${ip6:-N/A}"
    pause
}
ddns_delete() {
    print_title "删除 DDNS 配置"
    [[ ! -d "$DDNS_CONFIG_DIR" || -z "$(ls -A "$DDNS_CONFIG_DIR" 2>/dev/null)" ]] && { print_warn "暂无配置"; pause; return; }
    
    local i=1 domains=() files=()
    for conf in "$DDNS_CONFIG_DIR"/*.conf; do
        [[ -f "$conf" ]] || continue
        source "$conf"; domains+=("$DDNS_DOMAIN"); files+=("$conf")
        echo "$i. $DDNS_DOMAIN"; ((i++))
    done
    echo "0. 返回"
    
    read -e -r -p "选择: " idx
    [[ "$idx" == "0" || -z "$idx" ]] && return
    [[ "$idx" =~ ^[0-9]+$ && "$idx" -le ${#domains[@]} ]] || { print_error "无效"; pause; return; }
    
    confirm "删除 ${domains[$((idx-1))]} 的 DDNS?" && {
        rm -f "${files[$((idx-1))]}"
        [[ -z "$(ls -A "$DDNS_CONFIG_DIR" 2>/dev/null)" ]] && {
            crontab -l 2>/dev/null | grep -v "ddns-update.sh" | crontab - 2>/dev/null || true
            rm -f /usr/local/bin/ddns-update.sh
        }
        print_success "已删除"; log_action "DDNS deleted: ${domains[$((idx-1))]}"
    }
    pause
}
ddns_force_update() {
    if [[ -x /usr/local/bin/ddns-update.sh ]]; then
        print_info "正在更新..."
        /usr/local/bin/ddns-update.sh
        print_success "更新完成"
        echo ""
        tail -n 10 "$DDNS_LOG" 2>/dev/null || echo "暂无日志"
    else
        print_warn "DDNS 未配置"
    fi
    pause
}

load_cache() {
    if [[ -f "$CACHE_FILE" ]]; then
        local file_mtime
        file_mtime=$(stat -c %Y "$CACHE_FILE" 2>/dev/null || stat -f %m "$CACHE_FILE" 2>/dev/null || echo 0)
        local cache_age=$(($(date +%s) - file_mtime))
        if [[ $cache_age -lt $CACHE_TTL ]]; then
            source "$CACHE_FILE" 2>/dev/null || return 1
            return 0
        fi
    fi
    return 1
}

refresh_network_cache() {
    CACHED_IPV4=$(curl -4 -s --connect-timeout 3 --max-time 5 https://4.ipw.cn 2>/dev/null || \
              curl -4 -s --connect-timeout 3 --max-time 5 https://myip.ipip.net/ip 2>/dev/null || \
              curl -4 -s --connect-timeout 3 --max-time 5 https://api.ipify.org 2>/dev/null || echo "N/A")

    CACHED_IPV6=$(curl -6 -s --connect-timeout 3 --max-time 5 https://6.ipw.cn 2>/dev/null || \
              curl -6 -s --connect-timeout 3 --max-time 5 https://api64.ipify.org 2>/dev/null)
    [[ -z "$CACHED_IPV6" || ! "$CACHED_IPV6" =~ : ]] && CACHED_IPV6="未配置"
    
    local ipinfo=$(curl -s --connect-timeout 3 --max-time 5 https://ipinfo.io/json 2>/dev/null || echo "{}")
    CACHED_ISP=$(echo "$ipinfo" | grep -o '"org"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    [[ -z "$CACHED_ISP" ]] && CACHED_ISP="N/A"
    
    local country=$(echo "$ipinfo" | grep -o '"country"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    local city=$(echo "$ipinfo" | grep -o '"city"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    CACHED_LOCATION="${country:-N/A} ${city:-}"
    
    mkdir -p "$CACHE_DIR"
    cat > "$CACHE_FILE" << EOF
CACHED_IPV4="$CACHED_IPV4"
CACHED_IPV6="$CACHED_IPV6"
CACHED_ISP="$CACHED_ISP"
CACHED_LOCATION="$CACHED_LOCATION"
EOF
    chmod 600 "$CACHE_FILE"
}
get_ip_location() {
    local ip="$1"
    if [[ "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|fe80:|::1|fc00:|fd00:) ]]; then
        echo "本地网络"
        return
    fi

    local result
    if command_exists timeout; then
        result=$(timeout 3 curl -s "http://ip-api.com/json/${ip}?lang=zh-CN&fields=status,country,regionName,city,isp" 2>/dev/null)
    else
        result=$(curl -s --max-time 3 "http://ip-api.com/json/${ip}?lang=zh-CN&fields=status,country,regionName,city,isp" 2>/dev/null)
    fi
    
    if [[ -n "$result" ]] && echo "$result" | grep -q '"status":"success"'; then
        local country=$(echo "$result" | grep -o '"country":"[^"]*"' | cut -d'"' -f4)
        local region=$(echo "$result" | grep -o '"regionName":"[^"]*"' | cut -d'"' -f4)
        local city=$(echo "$result" | grep -o '"city":"[^"]*"' | cut -d'"' -f4)
        local isp=$(echo "$result" | grep -o '"isp":"[^"]*"' | cut -d'"' -f4)
        
        local location=""
        [[ -n "$country" ]] && location="$country"
        [[ -n "$region" && "$region" != "$country" ]] && location="${location} ${region}"
        [[ -n "$city" && "$city" != "$region" ]] && location="${location} ${city}"
        [[ -n "$isp" ]] && location="${location} (${isp})"
        
        echo "${location:-未知}"
        return
    fi
    
    echo "查询失败"
}

show_dual_column_sysinfo() {
    load_cache || refresh_network_cache

    local hostname=$(hostname)
    local os_info=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2 | head -c 35)
    local kernel=$(uname -r | head -c 20)
    local arch=$(uname -m)
    
    local cpu_model=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs | head -c 25)
    local cpu_cores=$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo "1")
    local cpu_freq=$(awk '/MHz/ {printf "%.1fGHz", $4/1000; exit}' /proc/cpuinfo 2>/dev/null || echo "N/A")

    local cpu_usage
    cpu_usage=$(awk '{u=$2+$4; t=$2+$4+$5; if(NR==1){u1=u;t1=t}else{if(t-t1>0)printf "%.0f%%",(u-u1)*100/(t-t1);else print "0%"}}' \
        <(grep 'cpu ' /proc/stat) <(sleep 0.3; grep 'cpu ' /proc/stat) 2>/dev/null) || true
    [[ -z "$cpu_usage" ]] && cpu_usage="0%"
    
    local load_avg=$(awk '{printf "%.2f %.2f %.2f", $1, $2, $3}' /proc/loadavg 2>/dev/null)

    local tcp_conn=0 udp_conn=0
    if command -v ss >/dev/null 2>&1; then
        tcp_conn=$(ss -tn state established 2>/dev/null | tail -n +2 | wc -l)
        udp_conn=$(ss -un 2>/dev/null | tail -n +2 | wc -l)
    elif [[ -f /proc/net/tcp ]]; then
        tcp_conn=$(awk 'NR>1 && $4=="01"{n++}END{print n+0}' /proc/net/tcp 2>/dev/null)
        udp_conn=$(awk 'NR>1{n++}END{print n+0}' /proc/net/udp 2>/dev/null)
    fi

    local mem_info swap_info
    if command -v free >/dev/null 2>&1; then
        mem_info=$(free -m | awk '/^Mem:/ {printf "%d/%dM %.0f%%", $3, $2, ($2>0)?$3/$2*100:0}')
        swap_info=$(free -m | awk '/^Swap:/ {if($2>0) printf "%d/%dM %.0f%%", $3, $2, $3/$2*100; else print "未启用"}')
    else
        local mt=$(awk '/^MemTotal/{print int($2/1024)}' /proc/meminfo)
        local mf=$(awk '/^MemAvailable/{print int($2/1024)}' /proc/meminfo)
        local mu=$((mt - mf))
        mem_info="${mu}/${mt}M $(( mt>0 ? mu*100/mt : 0 ))%"
        swap_info="未启用"
    fi
    
    local disk_info=$(df -h / | awk 'NR==2 {printf "%s/%s %s", $3, $2, $5}')
    
    local main_if=$(ip route 2>/dev/null | awk '/default/{print $5; exit}')
    local rx_total="0B" tx_total="0B"
    if [[ -n "$main_if" ]]; then
        read -r rx_total tx_total <<< "$(awk -v iface="$main_if:" '
            function fmt(b) {
                if(b>=1073741824) return sprintf("%.2fG",b/1073741824)
                if(b>=1048576) return sprintf("%.0fM",b/1048576)
                if(b>=1024) return sprintf("%.0fK",b/1024)
                return sprintf("%dB",b)
            }
            $1==iface {print fmt($2), fmt($10)}
        ' /proc/net/dev 2>/dev/null)"
        rx_total=${rx_total:-0B}; tx_total=${tx_total:-0B}
    fi
    
    local tcp_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "N/A")
    local qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "N/A")

    local uptime_str=$(awk '{d=int($1/86400);h=int($1%86400/3600);m=int($1%3600/60);
        if(d>0)printf "%d天%d时%d分",d,h,m;else if(h>0)printf "%d时%d分",h,m;else printf "%d分",m}' /proc/uptime)
    
    local sys_time=$(date "+%m-%d %H:%M")
    local timezone=$(timedatectl 2>/dev/null | awk '/Time zone/{print $3}' || echo "UTC")

    local ssh_port=$(grep -E "^Port\s" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -z "$ssh_port" ]] && ssh_port="22"

    local ufw_st="○"; command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active" && ufw_st="●"
    local f2b_st="○"; systemctl is-active fail2ban &>/dev/null && f2b_st="●"
    local nginx_st="○"; systemctl is-active nginx &>/dev/null && nginx_st="●"
    local docker_st="○"; systemctl is-active docker &>/dev/null && docker_st="●"
    local wg_st="○"; ip link show wg0 &>/dev/null && wg_st="●"

    local W=76  # 总宽度

    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "主机:" "$hostname" "IPv4:" "$CACHED_IPV4"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "系统:" "${os_info:0:17}" "IPv6:" "${CACHED_IPV6:0:20}"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "内核:" "$kernel" "运营商:" "${CACHED_ISP:0:18}"
    
    printf "${C_DIM}%${W}s${C_RESET}\n" | tr ' ' '-'

    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "CPU:" "${cpu_model:0:17}" "内存:" "$mem_info"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "核心:" "${cpu_cores}核 @ $cpu_freq" "交换:" "$swap_info"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "负载:" "$load_avg" "硬盘:" "$disk_info"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "占用:" "$cpu_usage 连接:${tcp_conn}t/${udp_conn}u" "流量:" "↓${rx_total} ↑${tx_total}"
    
    printf "${C_DIM}%${W}s${C_RESET}\n" | tr ' ' '-'

    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "算法:" "$tcp_cc + $qdisc" "位置:" "${CACHED_LOCATION:0:18}"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "运行:" "$uptime_str" "时区:" "$timezone"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "SSH:" "端口 $ssh_port" "时间:" "$sys_time"
    
    printf "${C_DIM}%${W}s${C_RESET}\n" | tr ' ' '-'

    printf " 服务: UFW[${C_GREEN}%s${C_RESET}] F2B[${C_GREEN}%s${C_RESET}] Nginx[${C_GREEN}%s${C_RESET}] Docker[${C_GREEN}%s${C_RESET}] WG[${C_GREEN}%s${C_RESET}]\n" \
        "$ufw_st" "$f2b_st" "$nginx_st" "$docker_st" "$wg_st"

    local last_login="无记录"
    if command -v last >/dev/null 2>&1; then
        local login_line=$(last -n 10 -a -w 2>/dev/null | grep -E "^[a-zA-Z]" | grep -v -E "wtmp begins|^reboot" | head -1)
        if [[ -n "$login_line" ]]; then
            local login_user=$(echo "$login_line" | awk '{print $1}')
            local login_ip=$(echo "$login_line" | awk '{print $NF}')
            local login_time=$(echo "$login_line" | awk '{print $4, $5, $6}')
            
            if [[ -n "$login_ip" && "$login_ip" =~ ^[0-9a-f.:]+$ ]]; then
                local ip_loc=$(get_ip_location "$login_ip")
                last_login="${login_user}@${login_ip} (${ip_loc}) ${login_time}"
            else
                last_login="${login_user} ${login_time}"
            fi
        fi
    fi
    
    printf "${C_DIM}%${W}s${C_RESET}\n" | tr ' ' '-'
    printf " ${C_CYAN}%-8s${C_RESET}%s\n" "登录:" "${last_login:0:65}"
}
fix_terminal() {
    [[ -t 0 ]] || return 0
    stty erase '^?' intr '^C' susp '^Z' icanon echo 2>/dev/null || true
    export TERM="${TERM:-xterm-256color}"
}
fix_terminal

draw_line() {
    printf "%$(tput cols 2>/dev/null || echo 80)s\n" | tr " " "-"
}

print_title() {
    clear || true
    local title=" $1 "
    local width=$(tput cols 2>/dev/null || echo 80)
    local padding=$(( (width - ${#title}) / 2 ))
    [[ $padding -lt 0 ]] && padding=0
    
    echo -e "${C_CYAN}"
    printf "%${width}s\n" | tr " " "="
    printf "%${padding}s%s\n" "" "$title"
    printf "%${width}s\n" | tr " " "="
    echo -e "${C_RESET}"
}

print_info() { echo -e "${C_BLUE}[i]${C_RESET} $1"; }
print_guide() { echo -e "${C_GREEN}>>${C_RESET} $1"; }
print_success() { echo -e "${C_GREEN}[✓]${C_RESET} $1"; }
print_warn() { echo -e "${C_YELLOW}[!]${C_RESET} $1"; }
print_error() { echo -e "${C_RED}[✗]${C_RESET} $1"; }

log_action() {
    echo "{\"time\":\"$(date '+%Y-%m-%d %H:%M:%S')\",\"level\":\"${2:-INFO}\",\"msg\":\"$1\"}" >> "$LOG_FILE" 2>/dev/null || true
}

pause() {
    [[ -t 0 ]] || return 0
    echo ""
    read -n 1 -s -r -p "按任意键继续..."
    echo ""
}

write_file_atomic() {
    local filepath="$1" content="$2" tmpfile
    mkdir -p "$(dirname "$filepath")"
    tmpfile=$(mktemp "$(dirname "$filepath")/.tmp.XXXXXX")
    trap "rm -f '$tmpfile'" RETURN
    printf "%s\n" "$content" > "$tmpfile"
    if [[ -f "$filepath" ]]; then
        chmod --reference="$filepath" "$tmpfile" 2>/dev/null || true
        chown --reference="$filepath" "$tmpfile" 2>/dev/null || true
    fi
    mv "$tmpfile" "$filepath"
    trap - RETURN
}

handle_interrupt() {
    rm -f /etc/.tmp.* 2>/dev/null
    echo ""
    print_warn "操作已取消 (用户中断)。"
    exit 130
}

trap 'handle_interrupt' SIGINT SIGTERM

check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        print_error "请使用 root 权限运行 (sudo)。"
        exit 2
    fi
}

check_os() {
    if [[ "$PLATFORM" == "openwrt" ]]; then
        print_warn "检测到 OpenWrt 系统，将以精简模式运行。"
        print_info "可用功能: 系统信息 / Web服务(DNS+DDNS+证书) / BBR / 主机名 / 时区 / 日志"
        print_info "不可用: UFW / Fail2ban / Docker / Swap / iPerf3 / SSH完整管理 / apt依赖安装"
        echo ""
        sleep 2
        return 0
    fi
    if [[ ! -f /etc/os-release ]]; then
        print_error "不支持的操作系统。"
        exit 1
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

refresh_ssh_port() {
    if [[ -f "$SSHD_CONFIG" ]]; then
        CURRENT_SSH_PORT=$(grep -iE "^\s*Port\s+" "$SSHD_CONFIG" 2>/dev/null | tail -n 1 | awk '{print $2}')
    fi
    [[ "$CURRENT_SSH_PORT" =~ ^[0-9]+$ ]] || CURRENT_SSH_PORT=$DEFAULT_SSH_PORT
}

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

validate_port() {
    local port=$1
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

validate_ip() {
    local ip=$1
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
    [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ip" == *:* ]]
}

validate_domain() {
    local domain=$1
    [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]
}

init_environment() {
    mkdir -p "$CACHE_DIR" "$(dirname "$LOG_FILE")"

    if [[ ! -f "$LOG_FILE" ]]; then
        touch "$LOG_FILE"
        chmod 600 "$LOG_FILE"
    fi

    refresh_ssh_port

    if [[ "$PLATFORM" == "openwrt" ]]; then
        for p in curl jq openssl-util ca-bundle; do
            command -v "${p%%-*}" &>/dev/null 2>&1 || {
                opkg update >/dev/null 2>&1
                opkg install "$p" >/dev/null 2>&1 || true
            }
        done
    else
        auto_deps
    fi

    log_action "Script initialized (platform=$PLATFORM)" "INFO"
}

menu_update() {
    print_title "基础依赖安装"
    
    print_info "正在检查并安装基础依赖..."
    echo ""

    local ufw_was_active=0
    local f2b_was_active=0
    
    if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw_was_active=1
    fi
    if systemctl is-active fail2ban &>/dev/null; then
        f2b_was_active=1
    fi
    
    print_info "1/2 更新软件源..."
    if apt-get update -y >/dev/null 2>&1; then
        print_success "软件源更新完成"
    else
        print_warn "软件源更新失败，但继续安装"
    fi
    
    echo ""
    
    print_info "2/2 安装基础依赖包..."
    local deps="curl wget jq unzip openssl ca-certificates ufw fail2ban iproute2 net-tools procps"
    local installed=0
    local failed=0
    local new_packages=""
    
    for pkg in $deps; do
        if dpkg -s "$pkg" &>/dev/null; then
            echo "  ✓ $pkg (已安装)"
        else
            echo -n "  → 正在安装 $pkg ... "
            if (DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >/dev/null 2>&1); then
                echo -e "${C_GREEN}成功${C_RESET}"
                ((installed++)) || true
                new_packages="$new_packages $pkg"
            else
                echo -e "${C_RED}失败${C_RESET}"
                ((failed++)) || true
            fi
        fi
    done
    
    echo ""
    echo "================================================================================"
    print_success "基础依赖安装完成"
    echo "  新安装: $installed 个"
    [[ $failed -gt 0 ]] && echo -e "  ${C_RED}失败: $failed 个${C_RESET}"
    
    if [[ "$new_packages" == *"ufw"* ]] || [[ "$new_packages" == *"fail2ban"* ]]; then
        echo ""
        echo -e "${C_YELLOW}提示:${C_RESET} 检测到新安装的安全服务"
        [[ "$new_packages" == *"ufw"* ]] && echo "  - UFW 防火墙: 请通过菜单 [2] 配置后启用"
        [[ "$new_packages" == *"fail2ban"* ]] && echo "  - Fail2ban: 请通过菜单 [3] 配置后启用"
    fi
    
    if [[ $ufw_was_active -eq 1 ]]; then
        ufw --force enable >/dev/null 2>&1 || true
    fi
    if [[ $f2b_was_active -eq 1 ]]; then
        systemctl start fail2ban >/dev/null 2>&1 || true
    fi
    
    echo "================================================================================"
    
    log_action "Basic dependencies installed/checked"
    pause
}

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
    if [[ "$PLATFORM" == "openwrt" ]]; then
        if command -v "${pkg%%-*}" &>/dev/null 2>&1 || opkg list-installed 2>/dev/null | grep -q "^${pkg} "; then
            [[ "$silent" != "silent" ]] && print_warn "$pkg 已安装，跳过。"
            return 0
        fi
        [[ "$silent" != "silent" ]] && print_info "正在安装 $pkg (opkg)..."
        opkg update >/dev/null 2>&1
        if opkg install "$pkg" >/dev/null 2>&1; then
            [[ "$silent" != "silent" ]] && print_success "$pkg 安装成功。"
            log_action "Installed package (opkg): $pkg"
            return 0
        else
            print_error "安装 $pkg 失败 (opkg)。"
            return 1
        fi
    fi

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
    
    print_title "删除 UFW 规则"
    echo -e "${C_CYAN}当前放行的端口 (已过滤 Fail2ban 规则):${C_RESET}"
    echo ""
    
    ufw status | grep "ALLOW" | awk '{print $1}' | sort -t'/' -k1,1n -u
    
    echo ""
    echo -e "${C_YELLOW}格式: 端口 或 端口/协议 (如 80, 443/tcp, 53/udp)${C_RESET}"
    echo -e "${C_YELLOW}多个用空格分隔，不指定协议则同时删除 tcp 和 udp${C_RESET}"
    read -e -r -p "要删除的规则: " rules
    [[ -z "$rules" ]] && return
    
    for rule in $rules; do
        if [[ "$rule" =~ ^([0-9]+)(/tcp|/udp)?$ ]]; then
            local port="${BASH_REMATCH[1]}"
            local proto="${BASH_REMATCH[2]}"
            
            if [[ -n "$proto" ]]; then
                ufw delete allow "${port}${proto}" 2>/dev/null && print_success "已删除: ${port}${proto}" || print_warn "${port}${proto} 不存在"
            else
                ufw delete allow "${port}/tcp" 2>/dev/null && print_success "已删除: ${port}/tcp" || print_warn "${port}/tcp 不存在"
                ufw delete allow "${port}/udp" 2>/dev/null && print_success "已删除: ${port}/udp" || true
            fi
        else
            print_error "无效格式: $rule"
        fi
    done
    log_action "UFW rules deleted: $rules"
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
    command_exists ufw || { print_error "UFW 未安装。"; pause; return; }
    
    echo -e "${C_YELLOW}格式: 端口 或 端口/协议 (如 80, 443/tcp, 53/udp)${C_RESET}"
    echo -e "${C_YELLOW}多个用空格分隔，不指定协议则同时放行 tcp 和 udp${C_RESET}"
    read -e -r -p "要放行的规则: " rules
    [[ -z "$rules" ]] && return
    
    for rule in $rules; do
        if [[ "$rule" =~ ^([0-9]+)(/tcp|/udp)?$ ]]; then
            local port="${BASH_REMATCH[1]}"
            local proto="${BASH_REMATCH[2]}"
            
            if validate_port "$port"; then
                if [[ -n "$proto" ]]; then
                    ufw allow "${port}${proto}" comment "Manual-Add" >/dev/null && \
                        print_success "已放行: ${port}${proto}" || \
                        print_error "添加失败: ${port}${proto}"
                else
                    ufw allow "${port}/tcp" comment "Manual-Add" >/dev/null && \
                        print_success "已放行: ${port}/tcp" || \
                        print_error "添加失败: ${port}/tcp"
                    ufw allow "${port}/udp" comment "Manual-Add" >/dev/null && \
                        print_success "已放行: ${port}/udp" || \
                        print_error "添加失败: ${port}/udp"
                fi
                log_action "UFW allowed ${port}${proto:-/tcp+udp}"
            else
                print_error "端口无效: $port"
            fi
        else
            print_error "无效格式: $rule"
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
    if ! validate_port "$port"; then
        print_error "端口无效，使用默认值 $CURRENT_SSH_PORT"
        port=$CURRENT_SSH_PORT
    fi
    read -e -r -p "最大重试次数 (登录失败几次后封禁) [5]: " maxretry
    maxretry=${maxretry:-5}
    if ! [[ "$maxretry" =~ ^[0-9]+$ ]] || [ "$maxretry" -lt 1 ]; then
        print_warn "无效输入，使用默认值 5"
        maxretry=5
    fi
    echo ""
    echo "封禁时间选项:"
    echo "  1) 10分钟 (10m)"
    echo "  2) 30分钟 (30m)"
    echo "  3) 1小时 (1h)"
    echo "  4) 6小时 (6h)"
    echo "  5) 24小时 (24h)"
    echo "  6) 永久封禁 (-1)"
    echo "  7) 自定义"
    read -e -r -p "选择封禁时间 [1]: " bantime_choice
    
    local bantime="10m"
    case $bantime_choice in
        1|"") bantime="10m" ;;
        2) bantime="30m" ;;
        3) bantime="1h" ;;
        4) bantime="6h" ;;
        5) bantime="24h" ;;
        6) bantime="-1" ;;
        7)
            read -e -r -p "输入封禁时间 (如 10m, 1h, 24h, -1表示永久): " custom_bantime
            if [[ "$custom_bantime" =~ ^-?[0-9]+[smhd]?$ ]] || [[ "$custom_bantime" == "-1" ]]; then
                bantime="$custom_bantime"
            else
                print_warn "格式无效，使用默认值 10m"
                bantime="10m"
            fi
            ;;
        *) 
            print_warn "无效选择，使用默认值 10m"
            bantime="10m"
            ;;
    esac

    echo ""
    echo "检测时间窗口 (在此时间内达到最大重试次数则封禁):"
    echo "  1) 10分钟 (10m) - 默认"
    echo "  2) 30分钟 (30m)"
    echo "  3) 1小时 (1h)"
    echo "  4) 自定义"
    read -e -r -p "选择检测窗口 [1]: " findtime_choice
    
    local findtime="10m"
    case $findtime_choice in
        1|"") findtime="10m" ;;
        2) findtime="30m" ;;
        3) findtime="1h" ;;
        4)
            read -e -r -p "输入检测窗口 (如 10m, 1h): " custom_findtime
            if [[ "$custom_findtime" =~ ^[0-9]+[smhd]?$ ]]; then
                findtime="$custom_findtime"
            else
                print_warn "格式无效，使用默认值 10m"
                findtime="10m"
            fi
            ;;
        *) findtime="10m" ;;
    esac

    echo ""
    draw_line
    echo -e "${C_CYAN}配置摘要:${C_RESET}"
    echo "  SSH 端口:     $port"
    echo "  最大重试:     $maxretry 次"
    echo "  检测窗口:     $findtime"
    echo "  封禁时间:     $bantime"
    [[ "$bantime" == "-1" ]] && echo -e "  ${C_RED}警告: 永久封禁需要手动解封！${C_RESET}"
    draw_line
    
    if ! confirm "确认应用此配置?"; then
        print_warn "已取消配置。"
        pause
        return
    fi

    local banaction="iptables-multiport"
    if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        banaction="ufw"
    fi

    local conf_content="[DEFAULT]
bantime = $bantime
findtime = $findtime
banaction = $banaction

[sshd]
enabled = true
port = $port
maxretry = $maxretry
backend = $backend
logpath = %(sshd_log)s"



    write_file_atomic "$FAIL2BAN_JAIL_LOCAL" "$conf_content"
    print_success "配置已写入: $FAIL2BAN_JAIL_LOCAL"
    
    if is_systemd; then
        systemctl enable fail2ban >/dev/null || true
        if systemctl restart fail2ban; then
            print_success "Fail2ban 已启动。"
        else
            print_error "Fail2ban 启动失败！"
            echo "请检查日志: journalctl -u fail2ban -n 20"
        fi
        log_action "Fail2ban configured: port=$port, maxretry=$maxretry, bantime=$bantime"
    fi
    pause
}

f2b_status() {
    print_title "Fail2ban 状态"
    
    if ! command_exists fail2ban-client; then
        print_error "Fail2ban 未安装。"
        pause
        return
    fi
    
    echo -e "${C_CYAN}[服务状态]${C_RESET}"
    if is_systemd; then
        systemctl status fail2ban --no-pager -l 2>/dev/null | head -n 5 || echo "服务未运行"
    fi
    
    echo ""
    echo -e "${C_CYAN}[SSHD Jail 状态]${C_RESET}"
    fail2ban-client status sshd 2>/dev/null || echo "SSHD jail 未启用"
    
    echo ""
    echo -e "${C_CYAN}[当前封禁的 IP]${C_RESET}"
    local banned=$(fail2ban-client status sshd 2>/dev/null | grep "Banned IP" | cut -d: -f2 | xargs)
    if [[ -n "$banned" && "$banned" != "0" ]]; then
        echo "$banned" | tr ' ' '\n' | while read ip; do
            [[ -n "$ip" ]] && echo "  - $ip"
        done
    else
        echo "  (无)"
    fi
    
    pause
}

f2b_unban() {
    print_title "解封 IP 地址"
    
    if ! command_exists fail2ban-client; then
        print_error "Fail2ban 未安装。"
        pause
        return
    fi
    
    echo -e "${C_CYAN}当前封禁的 IP:${C_RESET}"
    local banned=$(fail2ban-client status sshd 2>/dev/null | grep "Banned IP" | cut -d: -f2 | xargs)
    
    if [[ -z "$banned" ]] || [[ "$banned" == "0" ]]; then
        print_warn "当前没有被封禁的 IP。"
        pause
        return
    fi
    
    echo "$banned" | tr ' ' '\n' | nl -w2 -s'. '
    echo ""
    echo "输入选项:"
    echo "  - 输入 IP 地址解封单个"
    echo "  - 输入 'all' 解封所有"
    echo "  - 输入 '0' 取消"
    
    read -e -r -p "请输入: " input
    
    if [[ "$input" == "0" || -z "$input" ]]; then
        return
    elif [[ "$input" == "all" ]]; then
        if confirm "确认解封所有 IP?"; then
            for ip in $banned; do
                fail2ban-client set sshd unbanip "$ip" 2>/dev/null && \
                    print_success "已解封: $ip" || \
                    print_error "解封失败: $ip"
            done
            log_action "Fail2ban: unbanned all IPs"
        fi
    else
        if fail2ban-client set sshd unbanip "$input" 2>/dev/null; then
            print_success "已解封: $input"
            log_action "Fail2ban: unbanned $input"
        else
            print_error "解封失败，请检查 IP 是否正确。"
        fi
    fi
    
    pause
}

f2b_view_config() {
    print_title "当前 Fail2ban 配置"
    
    if [[ -f "$FAIL2BAN_JAIL_LOCAL" ]]; then
        echo -e "${C_CYAN}配置文件: $FAIL2BAN_JAIL_LOCAL${C_RESET}"
        draw_line
        cat "$FAIL2BAN_JAIL_LOCAL"
        draw_line
    else
        print_warn "配置文件不存在，使用系统默认配置。"
        echo ""
        echo "默认配置位置: /etc/fail2ban/jail.conf"
    fi
    
    pause
}

f2b_logs() {
    print_title "Fail2ban 日志"
    
    echo "1. 查看最近 50 条日志"
    echo "2. 实时跟踪日志 (Ctrl+C 退出)"
    echo "3. 查看封禁历史"
    echo "0. 返回"
    read -e -r -p "选择: " c
    
    case $c in
        1)
            if [[ -f /var/log/fail2ban.log ]]; then
                tail -n 50 /var/log/fail2ban.log
            else
                journalctl -u fail2ban -n 50 --no-pager 2>/dev/null || echo "日志不可用"
            fi
            ;;
        2)
            print_info "按 Ctrl+C 退出..."
            if [[ -f /var/log/fail2ban.log ]]; then
                tail -f /var/log/fail2ban.log
            else
                journalctl -u fail2ban -f 2>/dev/null || echo "日志不可用"
            fi
            ;;
        3)
            echo -e "${C_CYAN}最近的封禁记录:${C_RESET}"
            if [[ -f /var/log/fail2ban.log ]]; then
                grep -E "Ban|Unban" /var/log/fail2ban.log | tail -n 30
            else
                journalctl -u fail2ban --no-pager 2>/dev/null | grep -E "Ban|Unban" | tail -n 30
            fi
            ;;
        0|"") return ;;
    esac
    
    pause
}

menu_f2b() {
    fix_terminal
    while true; do
        print_title "Fail2ban 入侵防御"

        if command_exists fail2ban-client; then
            if systemctl is-active fail2ban &>/dev/null; then
                local banned_count=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
                echo -e "${C_GREEN}状态: 运行中${C_RESET} | 当前封禁: ${banned_count:-0} 个 IP"
            else
                echo -e "${C_YELLOW}状态: 已安装但未运行${C_RESET}"
            fi
        else
            echo -e "${C_RED}状态: 未安装${C_RESET}"
        fi
        echo ""
        
        echo "1. 安装/重新配置 Fail2ban"
        echo "2. 查看状态和封禁列表"
        echo "3. 解封 IP 地址"
        echo "4. 查看当前配置"
        echo "5. 查看日志"
        echo "6. 启动/停止服务"
        echo "0. 返回主菜单"
        echo ""
        read -e -r -p "请选择: " c
        
        case $c in
            1) f2b_setup ;;
            2) f2b_status ;;
            3) f2b_unban ;;
            4) f2b_view_config ;;
            5) f2b_logs ;;
            6)
                if ! command_exists fail2ban-client; then
                    print_error "Fail2ban 未安装。"
                    pause
                    continue
                fi
                echo "1. 启动  2. 停止  3. 重启"
                read -e -r -p "选择: " sc
                case $sc in
                    1) systemctl start fail2ban && print_success "已启动" || print_error "启动失败" ;;
                    2) systemctl stop fail2ban && print_success "已停止" || print_error "停止失败" ;;
                    3) systemctl restart fail2ban && print_success "已重启" || print_error "重启失败" ;;
                esac
                pause
                ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
    done
}

ssh_change_port() {
    print_title "修改 SSH 端口"
    read -e -r -p "请输入新端口 [$CURRENT_SSH_PORT]: " port
    [[ -z "$port" ]] && return
    
    if ! validate_port "$port"; then
        print_error "端口无效 (1-65535)。"
        pause; return
    fi

    local backup_file="${SSHD_CONFIG}.bak.$(date +%s)"
    cp "$SSHD_CONFIG" "$backup_file"
    
    if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
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
            if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
                ufw delete allow "$CURRENT_SSH_PORT/tcp" 2>/dev/null || true
            fi
            CURRENT_SSH_PORT=$port
            log_action "SSH port changed to $port"
            rm -f "$backup_file"
        else
            print_error "重启失败！已回滚配置。"
            mv "$backup_file" "$SSHD_CONFIG" 2>/dev/null || true
            systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
        fi
    fi
    pause
}

opt_cleanup() {
    print_title "系统清理"
    print_info "正在清理..."
    apt-get autoremove -y >/dev/null 2>&1 || true
    apt-get autoclean -y >/dev/null 2>&1 || true
    apt-get clean >/dev/null 2>&1 || true
    
    journalctl --vacuum-time=7d >/dev/null 2>&1 || true
    
    print_success "清理完成。"
    log_action "System cleanup completed"
    pause
}

opt_hostname() {
    print_title "修改主机名"
    echo "当前: $(hostname)"
    read -e -r -p "请输入新主机名: " new_name
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

select_timezone() {
    echo "1.上海 2.香港 3.东京 4.纽约 5.伦敦 6.UTC"
    read -e -r -p "选择: " t
    local z
    case $t in
        1) z="Asia/Shanghai" ;; 2) z="Asia/Hong_Kong" ;; 3) z="Asia/Tokyo" ;;
        4) z="America/New_York" ;; 5) z="Europe/London" ;; 6) z="UTC" ;;
        *) print_error "无效选择"; return 1 ;;
    esac
    ln -sf /usr/share/zoneinfo/$z /etc/localtime
    print_success "时区已设为 $z"
    log_action "Timezone changed to $z"
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
            5) select_timezone || true; pause ;;
            0|q) break ;;
            *) print_error "无效" ;;
        esac
    done
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
        if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        if ! ufw status 2>/dev/null | grep -q "$port/tcp"; then
            ufw allow "$port/tcp" comment "iPerf3-Temp" >/dev/null
            ufw_opened=1
            print_info "临时放行端口 $port"
        fi
    fi
    
    local ip4=$(curl -4 -s -L --connect-timeout 5 --max-time 10 https://4.ipw.cn 2>/dev/null || curl -4 -s -L --connect-timeout 5 --max-time 10 https://api.ipify.org 2>/dev/null)
    local ip6=$(curl -6 -s --connect-timeout 5 --max-time 10 https://6.ipw.cn 2>/dev/null || curl -6 -s --connect-timeout 5 --max-time 10 https://api64.ipify.org 2>/dev/null)
    [[ -z "$ip6" || ! "$ip6" =~ : ]] && ip6="未检测到"
    
    echo -e "\n${C_BLUE}=== 客户端测速命令 ===${C_RESET}"
    [[ -n "$ip4" ]] && echo -e "IPv4 Upload: ${C_YELLOW}iperf3 -c $ip4 -p $port${C_RESET}"
    [[ -n "$ip4" ]] && echo -e "IPv4 Download: ${C_YELLOW}iperf3 -c $ip4 -p $port -R${C_RESET}"
    [[ -n "$ip6" && "$ip6" != "未检测到" ]] && echo -e "IPv6 Upload: ${C_YELLOW}iperf3 -6 -c $ip6 -p $port${C_RESET}"
    [[ -n "$ip6" && "$ip6" != "未检测到" ]] && echo -e "IPv6 Download: ${C_YELLOW}iperf3 -6 -c $ip6 -p $port -R${C_RESET}"
    echo -e "${C_RED}按 Ctrl+C 停止测试...${C_RESET}"

    iperf3 -s -p "$port" &
    local iperf_pid=$!

    local cleaned=0

    cleanup_iperf() {
        [[ $cleaned -eq 1 ]] && return
        cleaned=1
        
        echo ""
        print_info "正在停止 iPerf3 服务..."

        if [[ -n "$iperf_pid" ]] && kill -0 "$iperf_pid" 2>/dev/null; then
            kill "$iperf_pid" 2>/dev/null || true
            wait "$iperf_pid" 2>/dev/null || true
        fi

        pkill -f "iperf3 -s -p $port" 2>/dev/null || true

        if [[ $ufw_opened -eq 1 ]]; then
            ufw delete allow "$port/tcp" >/dev/null 2>&1 || true
            print_info "防火墙规则已移除。"
        fi
        
        print_success "iPerf3 服务已停止。"
    }

    trap 'cleanup_iperf; trap - SIGINT SIGTERM' SIGINT SIGTERM

    wait $iperf_pid 2>/dev/null || true

    trap 'handle_interrupt' SIGINT SIGTERM
    
    cleanup_iperf
    log_action "iPerf3 test completed on port $port"
    pause
}

net_dns() {
    print_title "DNS 配置"
    
    echo -e "${C_CYAN}当前 DNS:${C_RESET}"
    if is_systemd && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        resolvectl status 2>/dev/null | grep -E "DNS Servers|DNS Server" | head -5 || cat /etc/resolv.conf
    else
        cat /etc/resolv.conf
    fi
    
    echo -e "\n${C_YELLOW}输入新 DNS IP (空格隔开)，输入 0 取消${C_RESET}"
    read -e -r -p "DNS: " dns
    [[ -z "$dns" || "$dns" == "0" ]] && return
    
    for ip in $dns; do
        if ! validate_ip "$ip"; then
            print_error "IP 地址 $ip 格式无效！"
            pause; return
        fi
    done
    
    if is_systemd && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        local res_conf="/etc/systemd/resolved.conf"
        grep -q '^\[Resolve\]' "$res_conf" || echo -e "\n[Resolve]" >> "$res_conf"
        sed -i '/^DNS=/d' "$res_conf"
        sed -i '/^\[Resolve\]/a DNS='"$dns" "$res_conf"
        systemctl restart systemd-resolved
    else
        > /etc/resolv.conf
        for ip in $dns; do
            echo "nameserver $ip" >> /etc/resolv.conf
        done
    fi
    
    print_success "DNS 已修改。"
    log_action "DNS changed to: $dns"
    pause
}

menu_net() {
    fix_terminal
    while true; do
        print_title "网络管理工具"
        echo "1. DNS 配置"
        echo "2. IPv4/IPv6 优先级"
        echo "3. iPerf3 测速"
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
            0|q) break ;;
            *) print_error "无效" ;;
        esac
    done
}

web_env_check() {
    if [[ "$PLATFORM" == "openwrt" ]]; then
        for pkg in jq curl openssl-util ca-bundle; do
            command -v "${pkg%%-*}" &>/dev/null || {
                opkg update >/dev/null 2>&1
                opkg install "$pkg" >/dev/null 2>&1 || true
            }
        done
        if ! command_exists certbot; then
            print_warn "OpenWrt 上 certbot 可能不可用。"
            print_info "建议使用 opkg install acme acme-dnsapi 或手动安装 certbot。"
            if ! confirm "是否继续尝试？"; then
                return 1
            fi
        fi
        if ! command_exists nginx; then
            print_info "安装 nginx..."
            opkg update >/dev/null 2>&1
            opkg install nginx-ssl >/dev/null 2>&1 || opkg install nginx >/dev/null 2>&1 || {
                print_warn "nginx 安装失败，反代功能可能不可用"
            }
        fi
        mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/snippets 2>/dev/null || true
        mkdir -p "$CONFIG_DIR"
        chmod 700 "$CONFIG_DIR"
        return 0
    fi
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

_CF_RESULT_DOMAIN=""
_CF_RESULT_TOKEN=""

web_cf_dns_update() {
    local DOMAIN="" CF_API_TOKEN=""
    _CF_RESULT_DOMAIN=""
    _CF_RESULT_TOKEN=""
    print_title "Cloudflare DNS 智能解析"
    command_exists jq || install_package "jq" "silent"
    

    print_info "正在探测本机公网 IP..."
    local ipv4 ipv6
    ipv4=$(curl -4 -s --max-time 5 https://4.ipw.cn 2>/dev/null || curl -4 -s --max-time 5 https://ifconfig.me 2>/dev/null) || ipv4=""
    ipv6=$(curl -6 -s --max-time 5 https://6.ipw.cn 2>/dev/null || curl -6 -s --max-time 5 https://ifconfig.me 2>/dev/null) || ipv6=""

    echo "----------------------------------------"
    echo "IPv4: ${ipv4:-[✗] 未检测到}"
    echo "IPv6: ${ipv6:-[✗] 未检测到}"
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
    
    echo ""
    echo -e "${C_YELLOW}注意: 开启代理后，只有 HTTP/HTTPS 流量能通过 Cloudflare。${C_RESET}"
    echo -e "${C_YELLOW}SSH、RDP、端口转发等非 HTTP 服务将无法使用此域名访问。${C_RESET}"
    read -e -r -p "是否开启 Cloudflare 代理 (小云朵)? [y/N]: " proxy_choice
    local proxied="false"
    [[ "${proxy_choice,,}" == "y" ]] && proxied="true"
    
    update_record() {
        local type=$1
        local ip=$2
        [[ -z "$ip" ]] && return
        
        print_info "处理 $type 记录 -> $ip (代理: $proxied)"
        local records=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records?type=$type&name=$DOMAIN" \
            -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json")
        
        local record_id=$(echo "$records" | jq -r '.result[0].id')
        local count=$(echo "$records" | jq -r '.result | length')
        [[ "$count" -gt 1 ]] && print_warn "警告: 存在多条 $type 记录，仅更新第一条。"
        
        if [[ "$record_id" != "null" && -n "$record_id" ]]; then
            local resp=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$record_id" \
                -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" \
                --data "{\"type\":\"$type\",\"name\":\"$DOMAIN\",\"content\":\"$ip\",\"ttl\":1,\"proxied\":$proxied}")
            if [[ "$(echo "$resp" | jq -r '.success')" == "true" ]]; then
                print_success "更新成功"
            else
                print_error "更新失败: $(echo "$resp" | jq -r '.errors[0].message')"
            fi
        else
            local resp=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
                -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" \
                --data "{\"type\":\"$type\",\"name\":\"$DOMAIN\",\"content\":\"$ip\",\"ttl\":1,\"proxied\":$proxied}")
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

    local ddns_v4=$([[ "$mode" == "1" || "$mode" == "3" ]] && echo "true" || echo "false")
    local ddns_v6=$([[ "$mode" == "2" || "$mode" == "3" ]] && echo "true" || echo "false")
    ddns_setup "$DOMAIN" "$CF_API_TOKEN" "$zone_id" "$ddns_v4" "$ddns_v6" "$proxied"

    _CF_RESULT_DOMAIN="$DOMAIN"
    _CF_RESULT_TOKEN="$CF_API_TOKEN"

    sleep 2
}

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
    local hook_script="${CERT_HOOKS_DIR}/renew-${target_domain}.sh"
    [[ ! -f "$hook_script" ]] && hook_script="/root/cert-renew-hook-${target_domain}.sh"
    if [[ -f "$hook_script" ]]; then
        rm -f "$hook_script"
        print_success "Hook 脚本已删除。"
    fi
    shopt -s nullglob
    local remaining_hooks=("${CERT_HOOKS_DIR}"/*.sh /root/cert-renew-hook-*.sh)
    shopt -u nullglob
    if [[ ${#remaining_hooks[@]} -eq 0 ]]; then
        local cron_tmp=$(mktemp)
        crontab -l 2>/dev/null | grep -v "certbot renew" > "$cron_tmp" || true
        crontab "$cron_tmp" 2>/dev/null || true
        rm -f "$cron_tmp"
        print_success "全局续签任务已清理（无剩余域名）。"
    fi
    
    rm -f "$target_conf"
    print_success "管理配置已移除。"
    
    log_action "Deleted domain config: $target_domain"
    pause
}

web_add_domain() {
    print_title "添加域名配置 (SSL + Nginx)"
    local DOMAIN="" CF_API_TOKEN="" LOCAL_PROXY_PASS="" NGINX_HTTP_PORT="" NGINX_HTTPS_PORT="" BACKEND_PROTOCOL=""
    
    web_env_check || { pause; return; }
    
    print_guide "此步骤将申请 SSL 证书并（可选）配置 Nginx 反向代理。"
    echo ""
    
    if confirm "是否需要先自动配置 Cloudflare DNS 解析 (A/AAAA)?"; then
        web_cf_dns_update
        [[ -n "$_CF_RESULT_DOMAIN" ]] && DOMAIN="$_CF_RESULT_DOMAIN"
        [[ -n "$_CF_RESULT_TOKEN" ]] && CF_API_TOKEN="$_CF_RESULT_TOKEN"
        _CF_RESULT_DOMAIN=""
        _CF_RESULT_TOKEN=""
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
                rm -f "$NGINX_CONF_PATH"
                pause; return
            fi
            
            if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
                ufw allow "$NGINX_HTTP_PORT/tcp" comment "Nginx-HTTP" >/dev/null 2>&1 || true
                ufw allow "$NGINX_HTTPS_PORT/tcp" comment "Nginx-HTTPS" >/dev/null 2>&1 || true
                print_success "防火墙规则已更新。"
            fi
        fi
        
                mkdir -p "$CERT_HOOKS_DIR"
        local DEPLOY_HOOK_SCRIPT="${CERT_HOOKS_DIR}/renew-${DOMAIN}.sh"
        
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
echo \"[\$(date)] Renewal hook completed for \$DOMAIN\" >> /var/log/cert-renew.log
exit 0
"
        
        write_file_atomic "$DEPLOY_HOOK_SCRIPT" "$hook_content"
        chmod +x "$DEPLOY_HOOK_SCRIPT"
        
        local cron_tmp=$(mktemp)
        crontab -l 2>/dev/null | grep -v "no crontab for" > "$cron_tmp" || true
        if ! grep -q "certbot renew" "$cron_tmp"; then
            echo "0 3 * * * certbot renew --quiet; for h in ${CERT_HOOKS_DIR}/*.sh; do [ -x \"\$h\" ] && bash \"\$h\"; done" >> "$cron_tmp"
            crontab "$cron_tmp" 2>/dev/null && \
                print_success "全局自动续签任务已添加 (每日 3:00 AM)。" || \
                print_warn "Crontab 添加失败，请手动配置。"
        else
            print_info "全局续签任务已存在，无需重复添加。"
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

        if [[ -n "$CF_API_TOKEN" ]] && [[ ! -f "$DDNS_CONFIG_DIR/${DOMAIN}.conf" ]]; then
            local zone_id="" current="$DOMAIN"
            while [[ "$current" == *"."* && -z "$zone_id" ]]; do
                zone_id=$(curl -s "https://api.cloudflare.com/client/v4/zones?name=$current" \
                    -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" | jq -r '.result[0].id // empty')
                current="${current#*.}"
            done
            
            if [[ -n "$zone_id" ]]; then
                local ddns_ipv4="false" ddns_ipv6="false"
                [[ -n "$(curl -4 -s --max-time 3 https://4.ipw.cn 2>/dev/null || curl -4 -s --max-time 3 https://ifconfig.me 2>/dev/null)" ]] && ddns_ipv4="true"
                [[ -n "$(curl -6 -s --max-time 3 https://6.ipw.cn 2>/dev/null || curl -6 -s --max-time 3 https://ifconfig.me 2>/dev/null)" ]] && ddns_ipv6="true"
                ddns_setup "$DOMAIN" "$CF_API_TOKEN" "$zone_id" "$ddns_ipv4" "$ddns_ipv6" "false"
            fi
        fi
        
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

menu_web() {
    fix_terminal
    while true; do
        print_title "Web 服务管理 (SSL + Nginx + DDNS)"
        
        local cert_count=$(ls -1 "$CONFIG_DIR"/*.conf 2>/dev/null | wc -l)
        local ddns_count=$(ls -1 "$DDNS_CONFIG_DIR"/*.conf 2>/dev/null | wc -l)
        echo -e "证书域名: ${C_GREEN}${cert_count}${C_RESET} | DDNS域名: ${C_GREEN}${ddns_count}${C_RESET}"
        [[ $ddns_count -gt 0 ]] && crontab -l 2>/dev/null | grep -q "ddns-update.sh" && echo -e "DDNS状态: ${C_GREEN}运行中${C_RESET}"
        echo ""
        
        echo -e "${C_CYAN}--- 域名管理 ---${C_RESET}"
        echo "1. 添加域名 (申请证书 + 配置反代 + DDNS)"
        echo "2. 查看已配置域名详情"
        echo "3. 删除域名配置"
        echo ""
        echo -e "${C_CYAN}--- DNS & DDNS ---${C_RESET}"
        echo "4. Cloudflare DNS 解析 (支持 DDNS)"
        echo "5. 查看 DDNS 配置"
        echo "6. 删除 DDNS 配置"
        echo "7. 立即更新 DDNS"
        echo ""
        echo -e "${C_CYAN}--- 证书维护 ---${C_RESET}"
        echo "8. 手动续签所有证书"
        echo "9. 查看日志 (证书/DDNS)"
        echo ""
        echo "0. 返回主菜单"
        echo ""
        read -e -r -p "请选择: " c
        
        case $c in
            1) web_add_domain ;;
            2) web_view_config ;;
            3) web_delete_domain ;;
            4) web_env_check && web_cf_dns_update || pause ;;
            5) ddns_list ;;
            6) ddns_delete ;;
            7) ddns_force_update ;;
            8)
                print_title "手动续签证书"
                command_exists certbot || { print_error "Certbot 未安装"; pause; continue; }
                print_info "正在续签..."
                certbot renew --force-renewal 2>&1 | tee /tmp/certbot-renew.log
                shopt -s nullglob
                for hook in "${CERT_HOOKS_DIR}"/*.sh /root/cert-renew-hook-*.sh; do
                    [[ -x "$hook" ]] && bash "$hook"
                done
                shopt -u nullglob
                log_action "Manual cert renewal"
                pause
                ;;
            9)
                echo "1. 证书续签日志  2. DDNS 更新日志"
                read -e -r -p "选择: " lc
                case $lc in
                    1) [[ -f /var/log/cert-renew.log ]] && tail -n 50 /var/log/cert-renew.log || print_warn "无日志" ;;
                    2) [[ -f "$DDNS_LOG" ]] && tail -n 50 "$DDNS_LOG" || print_warn "无日志" ;;
                esac
                pause
                ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
    done
}

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
    if [[ -z "$version_codename" ]]; then
        version_codename=$(grep 'UBUNTU_CODENAME' /etc/os-release | cut -d= -f2)
    fi
    if [[ -z "$version_codename" ]]; then
        print_error "无法检测系统版本代号，Docker 源配置可能失败。"
        print_info "请手动安装 Docker: https://docs.docker.com/engine/install/"
        pause; return
    fi
    
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
    local compose_url="https://github.com/docker/compose/releases/download/${compose_version}/docker-compose-linux-$(uname -m)"
    
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

readonly WG_INTERFACE="wg0"
readonly WG_DB_DIR="/etc/wireguard/db"
readonly WG_DB_FILE="${WG_DB_DIR}/wg-data.json"
readonly WG_CONF="/etc/wireguard/${WG_INTERFACE}.conf"
readonly WG_ROLE_FILE="/etc/wireguard/.role"

wg_db_init() {
    mkdir -p "$WG_DB_DIR"
    [[ -f "$WG_DB_FILE" ]] && return 0
    cat > "$WG_DB_FILE" << 'WGEOF'
{
  "role": "",
  "server": {},
  "peers": [],
  "port_forwards": [],
  "client": {}
}
WGEOF
    chmod 600 "$WG_DB_FILE"
}

wg_db_get() { jq -r "$@" "$WG_DB_FILE" 2>/dev/null; }

wg_db_set() {
    local tmp; tmp=$(mktemp)
    if jq "$@" "$WG_DB_FILE" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$WG_DB_FILE"; chmod 600 "$WG_DB_FILE"
    else
        rm -f "$tmp"; print_error "数据库写入失败"; return 1
    fi
}

wg_get_role() {
    local role=""
    [[ -f "$WG_ROLE_FILE" ]] && role=$(cat "$WG_ROLE_FILE" 2>/dev/null)
    [[ -z "$role" && -f "$WG_DB_FILE" ]] && role=$(wg_db_get '.role // empty')
    if [[ -z "$role" && -f "$WG_DB_FILE" ]]; then
        local spk=$(wg_db_get '.server.private_key // empty')
        [[ -n "$spk" ]] && role="server"
    fi
    echo "${role:-none}"
}

wg_set_role() {
    mkdir -p /etc/wireguard
    echo "$1" > "$WG_ROLE_FILE"
    chmod 600 "$WG_ROLE_FILE"
    wg_db_set --arg r "$1" '.role = $r' 2>/dev/null || true
}

wg_is_installed() { command_exists wg && [[ -f "$WG_DB_FILE" ]]; }
wg_is_running()   { ip link show "$WG_INTERFACE" &>/dev/null; }

wg_check_installed() {
    if ! wg_is_installed; then
        print_error "WireGuard 未安装，请先执行安装。"
        pause; return 1
    fi
    return 0
}

wg_check_server() {
    wg_check_installed || return 1
    if [[ "$(wg_get_role)" != "server" ]]; then
        print_error "当前不是服务端模式，此功能仅服务端可用。"
        pause; return 1
    fi
    return 0
}

wg_install_packages() {
    print_info "安装 WireGuard 软件包..."
    if [[ "$PLATFORM" == "openwrt" ]]; then
        opkg update >/dev/null 2>&1
        for pkg in wireguard-tools qrencode; do
            install_package "$pkg" "silent" || { print_error "安装 $pkg 失败"; return 1; }
        done
    else
        update_apt_cache
        for pkg in wireguard wireguard-tools qrencode; do
            install_package "$pkg" "silent" || { print_error "安装 $pkg 失败"; return 1; }
        done
    fi
    print_success "软件包安装完成"
    return 0
}

wg_next_ip() {
    local subnet prefix used_ips
    subnet=$(wg_db_get '.server.subnet')
    prefix=$(echo "$subnet" | cut -d'/' -f1 | cut -d'.' -f1-3)
    used_ips=$(wg_db_get '.server.ip')
    local pc; pc=$(wg_db_get '.peers | length')
    local i=0
    while [[ $i -lt $pc ]]; do
        used_ips="$used_ips $(wg_db_get ".peers[$i].ip")"
        i=$((i + 1))
    done
    local next
    for next in $(seq 2 254); do
        local candidate="${prefix}.${next}"
        echo "$used_ips" | grep -qw "$candidate" || { echo "$candidate"; return 0; }
    done
    print_error "子网 IP 已耗尽"; return 1
}

wg_format_bytes() {
    local bytes=$1
    [[ -z "$bytes" || "$bytes" == "0" ]] && { echo "0 B"; return; }
    awk -v b="$bytes" 'BEGIN {
        if (b>=1073741824) printf "%.2f GB",b/1073741824
        else if (b>=1048576) printf "%.2f MB",b/1048576
        else if (b>=1024) printf "%.2f KB",b/1024
        else printf "%d B",b
    }'
}

wg_save_iptables() {
    if command_exists netfilter-persistent; then
        netfilter-persistent save 2>/dev/null
    elif command_exists iptables-save; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
        iptables-save > /etc/iptables.rules 2>/dev/null
    fi
}

_wg_pf_iptables() {
    local action=$1 proto=$2 ext_port=$3 dest_ip=$4 dest_port=$5
    local iface=$(ip route show default | awk '{print $5; exit}')
    _pf_one() {
        iptables -t nat "$action" PREROUTING -i "$iface" -p "$1" --dport "$ext_port" \
            -j DNAT --to-destination "${dest_ip}:${dest_port}" 2>/dev/null || true
        iptables "$action" FORWARD -i "$iface" -o "$WG_INTERFACE" -p "$1" \
            --dport "$dest_port" -d "$dest_ip" -j ACCEPT 2>/dev/null || true
    }
    if [[ "$proto" == "tcp+udp" ]]; then _pf_one tcp; _pf_one udp; else _pf_one "$proto"; fi
}

_wg_pf_iptables_ensure() {
    local proto=$1 ext_port=$2 dest_ip=$3 dest_port=$4
    local iface=$(ip route show default | awk '{print $5; exit}')
    _pf_ensure_one() {
        iptables -t nat -C PREROUTING -i "$iface" -p "$1" --dport "$ext_port" \
            -j DNAT --to-destination "${dest_ip}:${dest_port}" 2>/dev/null || \
        iptables -t nat -A PREROUTING -i "$iface" -p "$1" --dport "$ext_port" \
            -j DNAT --to-destination "${dest_ip}:${dest_port}" 2>/dev/null || true
        iptables -C FORWARD -i "$iface" -o "$WG_INTERFACE" -p "$1" \
            --dport "$dest_port" -d "$dest_ip" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$iface" -o "$WG_INTERFACE" -p "$1" \
            --dport "$dest_port" -d "$dest_ip" -j ACCEPT 2>/dev/null || true
    }
    if [[ "$proto" == "tcp+udp" ]]; then _pf_ensure_one tcp; _pf_ensure_one udp; else _pf_ensure_one "$proto"; fi
}

wg_rebuild_conf() {
    [[ "$(wg_get_role)" != "server" ]] && return 1
    local priv_key port subnet server_ip mask main_iface
    priv_key=$(wg_db_get '.server.private_key')
    port=$(wg_db_get '.server.port')
    subnet=$(wg_db_get '.server.subnet')
    server_ip=$(wg_db_get '.server.ip')
    mask=$(echo "$subnet" | cut -d'/' -f2)
    main_iface=$(ip route show default | awk '{print $5; exit}')

    {
        echo "[Interface]"
        echo "PrivateKey = ${priv_key}"
        echo "Address = ${server_ip}/${mask}"
        echo "ListenPort = ${port}"
        echo "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -s ${subnet} -o ${main_iface} -j MASQUERADE"
        echo "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -s ${subnet} -o ${main_iface} -j MASQUERADE"

        local pc=$(wg_db_get '.peers | length') i=0
        while [[ $i -lt $pc ]]; do
            if [[ "$(wg_db_get ".peers[$i].enabled")" == "true" ]]; then
                echo ""
                echo "[Peer]"
                echo "PublicKey = $(wg_db_get ".peers[$i].public_key")"
                echo "PresharedKey = $(wg_db_get ".peers[$i].preshared_key")"
                local peer_ip=$(wg_db_get ".peers[$i].ip")
                local is_gw=$(wg_db_get ".peers[$i].is_gateway // false")
                local lan_sub=$(wg_db_get ".peers[$i].lan_subnets // empty")

                if [[ "$is_gw" == "true" && -n "$lan_sub" ]]; then
                    echo "AllowedIPs = ${peer_ip}/32, ${lan_sub}"
                else
                    echo "AllowedIPs = ${peer_ip}/32"
                fi
            fi
            i=$((i + 1))
        done
    } > "$WG_CONF"
    chmod 600 "$WG_CONF"
}

wg_regenerate_client_confs() {
    local pc=$(wg_db_get '.peers | length')
    [[ "$pc" -eq 0 ]] && return
    local spub sep sport sdns mask
    spub=$(wg_db_get '.server.public_key')
    sep=$(wg_db_get '.server.endpoint')
    sport=$(wg_db_get '.server.port')
    sdns=$(wg_db_get '.server.dns')
    mask=$(echo "$(wg_db_get '.server.subnet')" | cut -d'/' -f2)
    mkdir -p /etc/wireguard/clients
    local i=0
    while [[ $i -lt $pc ]]; do
        local name=$(wg_db_get ".peers[$i].name")
        local is_gw=$(wg_db_get ".peers[$i].is_gateway // false")
        local dns_line="DNS = ${sdns}"
        [[ "$is_gw" == "true" ]] && dns_line=""
        local conf_content="[Interface]
PrivateKey = $(wg_db_get ".peers[$i].private_key")
Address = $(wg_db_get ".peers[$i].ip")/${mask}
${dns_line}

[Peer]
PublicKey = ${spub}
PresharedKey = $(wg_db_get ".peers[$i].preshared_key")
Endpoint = ${sep}:${sport}
AllowedIPs = $(wg_db_get ".peers[$i].client_allowed_ips")
PersistentKeepalive = 25"

        conf_content=$(echo "$conf_content" | sed '/^$/N;/^\n$/d')
        write_file_atomic "/etc/wireguard/clients/${name}.conf" "$conf_content"
        chmod 600 "/etc/wireguard/clients/${name}.conf"
        i=$((i + 1))
    done
}

wg_server_install() {
    print_title "安装 WireGuard 服务端"

    if wg_is_installed && [[ "$(wg_get_role)" == "server" ]]; then
        print_warn "WireGuard 服务端已安装。"
        wg_is_running && echo -e "  状态: ${C_GREEN}● 运行中${C_RESET}" || echo -e "  状态: ${C_RED}● 已停止${C_RESET}"
        pause; return 0
    fi

    if wg_is_installed && [[ "$(wg_get_role)" == "client" ]]; then
        print_error "当前已安装为客户端模式。如需切换为服务端，请先卸载。"
        pause; return 1
    fi

    echo ""
    print_info "[1/5] 安装软件包..."
    wg_install_packages || { pause; return 1; }

    print_info "[2/5] 配置 IP 转发..."
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    print_success "IP 转发已开启"

    print_info "[3/5] 配置服务端参数..."
    echo ""

    local wg_port
    while true; do
        read -e -r -p "WireGuard 监听端口 [${WG_DEFAULT_PORT}]: " wg_port
        wg_port=${wg_port:-$WG_DEFAULT_PORT}
        if validate_port "$wg_port"; then break; fi
        print_warn "端口无效 (1-65535)"
    done

    local wg_subnet
    while true; do
        read -e -r -p "VPN 内网子网 [10.66.66.0/24]: " wg_subnet
        wg_subnet=${wg_subnet:-10.66.66.0/24}
        [[ "$wg_subnet" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] && break
        print_warn "子网格式无效，示例: 10.66.66.0/24"
    done

    local prefix server_ip
    prefix=$(echo "$wg_subnet" | cut -d'.' -f1-3)
    server_ip="${prefix}.1"

    local wg_dns
    read -e -r -p "客户端 DNS [1.1.1.1, 8.8.8.8]: " wg_dns
    wg_dns=${wg_dns:-"1.1.1.1, 8.8.8.8"}

    local wg_endpoint default_ip
    default_ip=$(curl -4 -s --max-time 5 https://4.ipw.cn 2>/dev/null || curl -4 -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "")
    if [[ -n "$default_ip" ]]; then
        read -e -r -p "公网端点 IP/域名 [${default_ip}]: " wg_endpoint
        wg_endpoint=${wg_endpoint:-$default_ip}
    else
        while [[ -z "$wg_endpoint" ]]; do
            read -e -r -p "公网端点 IP/域名: " wg_endpoint
        done
    fi

    echo ""

    print_info "[4/5] 生成服务端密钥..."
    local server_privkey server_pubkey
    server_privkey=$(wg genkey)
    server_pubkey=$(echo "$server_privkey" | wg pubkey)
    print_success "密钥已生成"

    print_info "[5/5] 写入配置并启动..."

    wg_db_init
    wg_set_role "server"

    wg_db_set --arg pk "$server_privkey" \
              --arg pub "$server_pubkey" \
              --arg ip "$server_ip" \
              --arg sub "$wg_subnet" \
              --arg port "$wg_port" \
              --arg dns "$wg_dns" \
              --arg ep "$wg_endpoint" \
    '.server = {
        private_key: $pk,
        public_key: $pub,
        ip: $ip,
        subnet: $sub,
        port: ($port | tonumber),
        dns: $dns,
        endpoint: $ep
    }'
    
    wg_rebuild_conf

    if [[ "$PLATFORM" == "openwrt" ]]; then
        wg-quick up "$WG_INTERFACE" 2>/dev/null || true
    elif is_systemd; then
        systemctl enable "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1
        wg-quick up "$WG_INTERFACE" 2>/dev/null
    fi

    if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "${wg_port}/udp" comment "WireGuard" >/dev/null 2>&1
        print_success "UFW 已放行端口 ${wg_port}/udp"
    fi

    echo ""
    draw_line
    if wg_is_running; then
        print_success "WireGuard 服务端安装并启动成功！"
    else
        print_warn "WireGuard 已安装，但启动可能失败，请检查日志"
    fi
    echo -e "  角色:     ${C_GREEN}服务端 (Server)${C_RESET}"
    echo -e "  监听端口: ${C_GREEN}${wg_port}/udp${C_RESET}"
    echo -e "  内网子网: ${C_GREEN}${wg_subnet}${C_RESET}"
    echo -e "  服务端 IP: ${C_GREEN}${server_ip}${C_RESET}"
    echo -e "  公网端点: ${C_GREEN}${wg_endpoint}:${wg_port}${C_RESET}"
    draw_line

    log_action "WireGuard server installed: port=$wg_port subnet=$wg_subnet endpoint=$wg_endpoint"
    pause
}

wg_add_peer() {
    wg_check_server || return 1

    print_title "添加 WireGuard 设备 (Peer)"

    local peer_name
    while true; do
        read -e -r -p "设备名称 (如 phone, laptop): " peer_name
        [[ -z "$peer_name" ]] && { print_warn "名称不能为空"; continue; }
        local exists
        exists=$(wg_db_get --arg n "$peer_name" '.peers[] | select(.name == $n) | .name')
        [[ -n "$exists" ]] && { print_error "设备名 '$peer_name' 已存在"; continue; }
        [[ ! "$peer_name" =~ ^[a-zA-Z0-9_-]+$ ]] && { print_warn "名称只能包含字母、数字、下划线、连字符"; continue; }
        break
    done

    local peer_ip
    peer_ip=$(wg_next_ip) || { pause; return 1; }
    echo -e "  分配 IP: ${C_GREEN}${peer_ip}${C_RESET}"

    local peer_privkey peer_pubkey psk
    peer_privkey=$(wg genkey)
    peer_pubkey=$(echo "$peer_privkey" | wg pubkey)
    psk=$(wg genpsk)

    local is_gateway="false"
    local lan_subnets=""
    echo ""
    echo "设备类型:"
    echo "  1. 普通设备 (手机/电脑/服务器)"
    echo "  2. 网关设备 (路由器/OpenWrt，需要让其 LAN 内所有设备接入 VPN)"
    read -e -r -p "选择 [1]: " device_type
    device_type=${device_type:-1}

    if [[ "$device_type" == "2" ]]; then
        is_gateway="true"
        echo ""
        print_guide "请输入该网关后面的 LAN 网段 (将被路由到 VPN 中)"
        print_guide "示例: 192.168.1.0/24 或 10.10.100.0/24"
        print_guide "多个网段用逗号分隔: 192.168.1.0/24, 192.168.2.0/24"
        while [[ -z "$lan_subnets" ]]; do
            read -e -r -p "LAN 网段: " lan_subnets
            if [[ -z "$lan_subnets" ]]; then
                print_warn "网关设备必须指定 LAN 网段"
            elif ! echo "$lan_subnets" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+'; then
                print_warn "格式无效，示例: 10.10.100.0/24"
                lan_subnets=""
            fi
        done
    fi

    echo ""
    echo "客户端路由模式:"
    echo "  1. 全局代理 (所有流量走 VPN) - 0.0.0.0/0"
    echo "  2. 仅 VPN 内网 (只访问 VPN 内部设备)"
    if [[ "$is_gateway" == "true" ]]; then
        echo "  3. VPN 内网 + 所有网关 LAN 网段 (推荐网关设备)"
    else
        echo "  3. VPN 内网 + 指定 LAN 网段 (访问远程内网设备)"
    fi
    echo "  4. 自定义路由"
    read -e -r -p "选择 [1]: " route_mode
    route_mode=${route_mode:-1}

    local client_allowed_ips server_subnet
    server_subnet=$(wg_db_get '.server.subnet')
        case $route_mode in
        1) client_allowed_ips="0.0.0.0/0, ::/0" ;;
        2) client_allowed_ips="$server_subnet" ;;
        3)
            # 收集所有已有网关的 LAN 网段
            local all_lan_subnets=""
            local pc=$(wg_db_get '.peers | length')
            local pi=0
            while [[ $pi -lt $pc ]]; do
                local pls=$(wg_db_get ".peers[$pi].lan_subnets // empty")
                if [[ -n "$pls" ]]; then
                    [[ -n "$all_lan_subnets" ]] && all_lan_subnets="${all_lan_subnets}, "
                    all_lan_subnets="${all_lan_subnets}${pls}"
                fi
                pi=$((pi + 1))
            done
            # 当前新设备自己的 LAN 也加入（如果是网关）
            if [[ "$is_gateway" == "true" && -n "$lan_subnets" ]]; then
                [[ -n "$all_lan_subnets" ]] && all_lan_subnets="${all_lan_subnets}, "
                all_lan_subnets="${all_lan_subnets}${lan_subnets}"
            fi
            # 去掉自己的 LAN（网关不需要路由自己的 LAN 回隧道）
            if [[ "$is_gateway" == "true" && -n "$lan_subnets" ]]; then
                local other_lans=""
                local IFS_BAK="$IFS"; IFS=','
                for cidr in $all_lan_subnets; do
                    cidr=$(echo "$cidr" | xargs)
                    [[ -z "$cidr" ]] && continue
                    local dominated=false
                    local IFS2_BAK="$IFS"; IFS=','
                    for own in $lan_subnets; do
                        own=$(echo "$own" | xargs)
                        [[ "$cidr" == "$own" ]] && { dominated=true; break; }
                    done
                    IFS="$IFS2_BAK"
                    if [[ "$dominated" != "true" ]]; then
                        [[ -n "$other_lans" ]] && other_lans="${other_lans}, "
                        other_lans="${other_lans}${cidr}"
                    fi
                done
                IFS="$IFS_BAK"
                if [[ -n "$other_lans" ]]; then
                    client_allowed_ips="${server_subnet}, ${other_lans}"
                else
                    client_allowed_ips="$server_subnet"
                fi
            else
                if [[ -n "$all_lan_subnets" ]]; then
                    client_allowed_ips="${server_subnet}, ${all_lan_subnets}"
                else
                    print_warn "当前无网关设备注册 LAN 网段，仅路由 VPN 内网"
                    client_allowed_ips="$server_subnet"
                fi
            fi
            ;;
        4)
            read -e -r -p "输入允许的 IP 范围 (逗号分隔): " client_allowed_ips
            [[ -z "$client_allowed_ips" ]] && client_allowed_ips="0.0.0.0/0, ::/0"
            ;;
        *) client_allowed_ips="0.0.0.0/0, ::/0" ;;
    esac

    local spub sep sport sdns
    spub=$(wg_db_get '.server.public_key')
    sep=$(wg_db_get '.server.endpoint')
    sport=$(wg_db_get '.server.port')
    sdns=$(wg_db_get '.server.dns')

    local mask
    mask=$(echo "$server_subnet" | cut -d'/' -f2)

    local dns_line=""
    if [[ "$is_gateway" != "true" ]]; then
        dns_line="DNS = ${sdns}"
    fi

    local client_conf="[Interface]
PrivateKey = ${peer_privkey}
Address = ${peer_ip}/${mask}
${dns_line}

[Peer]
PublicKey = ${spub}
PresharedKey = ${psk}
Endpoint = ${sep}:${sport}
AllowedIPs = ${client_allowed_ips}
PersistentKeepalive = 25"

    client_conf=$(echo "$client_conf" | sed '/^$/N;/^\n$/d')

    mkdir -p /etc/wireguard/clients
    local conf_file="/etc/wireguard/clients/${peer_name}.conf"
    write_file_atomic "$conf_file" "$client_conf"
    chmod 600 "$conf_file"

    local now; now=$(date '+%Y-%m-%d %H:%M:%S')
    wg_db_set --arg name "$peer_name" \
              --arg ip "$peer_ip" \
              --arg privkey "$peer_privkey" \
              --arg pubkey "$peer_pubkey" \
              --arg psk "$psk" \
              --arg allowed "$client_allowed_ips" \
              --arg created "$now" \
              --arg gw "$is_gateway" \
              --arg lans "$lan_subnets" \
    '.peers += [{
        name: $name,
        ip: $ip,
        private_key: $privkey,
        public_key: $pubkey,
        preshared_key: $psk,
        client_allowed_ips: $allowed,
        enabled: true,
        created: $created,
        is_gateway: ($gw == "true"),
        lan_subnets: $lans
    }]'

    if [[ "$is_gateway" == "true" && -n "$lan_subnets" ]]; then
        local _pc=$(wg_db_get '.peers | length')
        local _all_lans="" _pi=0
        while [[ $_pi -lt $_pc ]]; do
            local _pls=$(wg_db_get ".peers[$_pi].lan_subnets // empty")
            [[ -n "$_pls" ]] && { [[ -n "$_all_lans" ]] && _all_lans="${_all_lans}, "; _all_lans="${_all_lans}${_pls}"; }
            _pi=$((_pi + 1))
        done
        _pi=0
        while [[ $_pi -lt $_pc ]]; do
            local _pname=$(wg_db_get ".peers[$_pi].name")
            [[ "$_pname" == "$peer_name" ]] && { _pi=$((_pi + 1)); continue; }
            local _cur_allowed=$(wg_db_get ".peers[$_pi].client_allowed_ips")
            [[ "$_cur_allowed" == *"0.0.0.0/0"* ]] && { _pi=$((_pi + 1)); continue; }
            local _is_gw=$(wg_db_get ".peers[$_pi].is_gateway // false")
            local _own_lans=$(wg_db_get ".peers[$_pi].lan_subnets // empty")
            if [[ "$_is_gw" != "true" && "$_cur_allowed" == "$server_subnet" ]]; then
                _pi=$((_pi + 1)); continue
            fi
            if [[ "$_is_gw" == "true" ]]; then
                local _other="" _IFS_BAK="$IFS"; IFS=','
                for _c in $_all_lans; do
                    _c=$(echo "$_c" | xargs); [[ -z "$_c" ]] && continue
                    local _skip=false _IFS2="$IFS"; IFS=','
                    for _o in $_own_lans; do _o=$(echo "$_o" | xargs); [[ "$_c" == "$_o" ]] && { _skip=true; break; }; done
                    IFS="$_IFS2"
                    [[ "$_skip" != "true" ]] && { [[ -n "$_other" ]] && _other="${_other}, "; _other="${_other}${_c}"; }
                done; IFS="$_IFS_BAK"
                local _new="${server_subnet}"
                [[ -n "$_other" ]] && _new="${server_subnet}, ${_other}"
                wg_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a'
            else
                local _new="${server_subnet}, ${_all_lans}"
                wg_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a'
            fi
            _pi=$((_pi + 1))
        done
    fi
    
    wg_rebuild_conf
    if wg_is_running; then
        wg syncconf "$WG_INTERFACE" <(wg-quick strip "$WG_INTERFACE") 2>/dev/null || {
            print_warn "热加载失败，尝试重启接口..."
            wg-quick down "$WG_INTERFACE" 2>/dev/null
            wg-quick up "$WG_INTERFACE" 2>/dev/null
        }
        if [[ "$is_gateway" == "true" && -n "$lan_subnets" ]]; then
            local IFS_BAK="$IFS"; IFS=','
            for cidr in $lan_subnets; do
                cidr=$(echo "$cidr" | xargs)
                [[ -n "$cidr" ]] && ip route replace "$cidr" dev "$WG_INTERFACE" 2>/dev/null && \
                    print_info "已添加路由: $cidr -> $WG_INTERFACE"
            done
            IFS="$IFS_BAK"
        fi
    fi

    wg_regenerate_client_confs

    echo ""
    draw_line
    print_success "设备 '${peer_name}' 添加成功！"
    draw_line
    echo -e "  名称: ${C_GREEN}${peer_name}${C_RESET}"
    echo -e "  IP:   ${C_GREEN}${peer_ip}${C_RESET}"
    if [[ "$is_gateway" == "true" ]]; then
        echo -e "  类型: ${C_YELLOW}网关设备${C_RESET}"
        echo -e "  LAN:  ${C_CYAN}${lan_subnets}${C_RESET}"
    else
        echo -e "  类型: 普通设备"
    fi
    echo -e "  路由: ${C_CYAN}${client_allowed_ips}${C_RESET}"
    echo -e "  配置: ${C_CYAN}${conf_file}${C_RESET}"
    draw_line
    if [[ "$is_gateway" == "true" ]]; then
        echo ""
        echo -e "${C_YELLOW}[网关设备部署指南]${C_RESET}"
        echo ""
        echo "请选择该网关设备的部署方式:"
        echo "  1. OpenWrt (uci 命令部署)"
        echo "  2. 普通 Linux 路由器 (wg-quick)"
        echo "  3. 跳过，稍后手动部署"
        read -e -r -p "选择 [1]: " gw_deploy
        gw_deploy=${gw_deploy:-1}

        if [[ "$gw_deploy" == "1" ]]; then
            local ep_host="$sep"

            echo ""
            draw_line
            echo -e "${C_CYAN}=== OpenWrt 部署命令 ===${C_RESET}"
            echo -e "${C_YELLOW}在 OpenWrt SSH 终端依次执行以下命令:${C_RESET}"
            draw_line
            local uci_allowed_lines=""
            local IFS_BAK="$IFS"
            IFS=','
            for cidr in $client_allowed_ips; do
                cidr=$(echo "$cidr" | xargs)
                [[ -n "$cidr" ]] && uci_allowed_lines="${uci_allowed_lines}uci add_list network.wg_server.allowed_ips='${cidr}'
"
            done
            IFS="$IFS_BAK"

                        cat << OPENWRT_EOF

uci delete network.wg0 2>/dev/null; true
uci delete network.wg_server 2>/dev/null; true
uci delete firewall.wg_zone 2>/dev/null; true
uci delete firewall.wg_fwd_lan 2>/dev/null; true
uci delete firewall.wg_fwd_wg 2>/dev/null; true
uci commit network 2>/dev/null; true
uci commit firewall 2>/dev/null; true
ifdown wg0 2>/dev/null; true
if ! lsmod | grep -q wireguard; then
    opkg update
    opkg install kmod-wireguard || echo '[!] kmod 安装失败，请确认固件已内置 WireGuard 或内核版本匹配'
fi
opkg update
opkg install wireguard-tools luci-proto-wireguard
uci set network.wg0=interface
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key='${peer_privkey}'
uci delete network.wg0.addresses 2>/dev/null; true
uci add_list network.wg0.addresses='${peer_ip}/${mask}'
uci set network.wg_server=wireguard_wg0
uci set network.wg_server.public_key='${spub}'
uci set network.wg_server.preshared_key='${psk}'
uci set network.wg_server.endpoint_host='${ep_host}'
uci set network.wg_server.endpoint_port='${sport}'
uci set network.wg_server.persistent_keepalive='25'
uci set network.wg_server.route_allowed_ips='1'
${uci_allowed_lines}
uci set firewall.wg_zone=zone
uci set firewall.wg_zone.name='wg'
uci set firewall.wg_zone.input='ACCEPT'
uci set firewall.wg_zone.output='ACCEPT'
uci set firewall.wg_zone.forward='ACCEPT'
uci set firewall.wg_zone.masq='1'
uci add_list firewall.wg_zone.network='wg0'

# LAN -> WG 转发 (LAN 设备访问 VPN 网络)
uci set firewall.wg_fwd_lan=forwarding
uci set firewall.wg_fwd_lan.src='lan'
uci set firewall.wg_fwd_lan.dest='wg'

# WG -> LAN 转发 (VPN 对端访问本地 LAN 设备)
uci set firewall.wg_fwd_wg=forwarding
uci set firewall.wg_fwd_wg.src='wg'
uci set firewall.wg_fwd_wg.dest='lan'
uci commit network
uci commit firewall
/etc/init.d/firewall reload
/etc/init.d/network reload

OPENWRT_EOF
            draw_line
            echo -e "${C_GREEN}复制以上全部命令到 OpenWrt SSH 终端执行即可。${C_RESET}"
            echo ""
            echo -e "${C_CYAN}验证方法:${C_RESET}"
            echo "  1. OpenWrt 上执行: wg show"
            echo "  2. LuCI 界面: Network -> Interfaces 查看 wg0 状态"
            echo "  3. LAN 设备 ping VPN 服务端: ping $(wg_db_get '.server.ip')"
            draw_line

        elif [[ "$gw_deploy" == "2" ]]; then
            echo ""
            draw_line
            echo -e "${C_CYAN}=== Linux 路由器部署步骤 ===${C_RESET}"
            draw_line
            echo "  1. 安装 WireGuard:"
            echo "     apt install wireguard  # 或对应包管理器"
            echo ""
            echo "  2. 复制配置文件到路由器:"
            echo "     scp root@$(wg_db_get '.server.endpoint'):${conf_file} /etc/wireguard/wg0.conf"
            echo ""
            echo "  3. 开启 IP 转发:"
            echo "     echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf && sysctl -p"
            echo ""
            echo "  4. 启动并设置开机自启:"
            echo "     wg-quick up wg0"
            echo "     systemctl enable wg-quick@wg0"
            echo ""
            echo "  5. 添加 iptables 转发规则 (允许 LAN 流量走 VPN):"
            echo "     iptables -A FORWARD -i eth0 -o wg0 -j ACCEPT"
            echo "     iptables -A FORWARD -i wg0 -o eth0 -j ACCEPT"
            echo "     iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE"
            draw_line
        fi

        echo ""
        echo -e "${C_YELLOW}[通用注意事项]${C_RESET}"
        echo "  • LAN 内设备无需安装任何 VPN 客户端，网关自动代理"
        echo "  • 确保 VPN 子网 ($(wg_db_get '.server.subnet')) 与 LAN 子网 (${lan_subnets}) 不冲突"
        echo "  • 其他 VPN 设备如需访问此网关的 LAN，路由模式选 3 即可"
        echo ""
    fi

    echo ""
    if confirm "是否显示客户端二维码 (手机扫码导入)?"; then
        echo ""
        echo -e "${C_CYAN}=== ${peer_name} 二维码 ===${C_RESET}"
        qrencode -t ansiutf8 < "$conf_file"
        echo ""
    fi

    if confirm "是否显示客户端配置文本?"; then
        echo ""
        echo -e "${C_CYAN}=== ${peer_name} 配置文件 ===${C_RESET}"
        cat "$conf_file"
        echo ""
    fi

    log_action "WireGuard peer added: ${peer_name} (${peer_ip}) gateway=${is_gateway} lan=${lan_subnets}"
    pause
}

wg_list_peers() {
    wg_check_server || return 1

    print_title "WireGuard 设备列表"

    local peer_count
    peer_count=$(wg_db_get '.peers | length')

    if [[ "$peer_count" -eq 0 || "$peer_count" == "null" ]]; then
        print_warn "暂无设备"
        pause; return
    fi

    local wg_dump=""
    wg_is_running && wg_dump=$(wg show "$WG_INTERFACE" dump 2>/dev/null | tail -n +2)

    printf "${C_CYAN}%-4s %-14s %-14s %-6s %-8s %-10s %-10s %s${C_RESET}\n" \
        "#" "名称" "IP" "类型" "状态" "↓接收" "↑发送" "最近握手"
    draw_line

    local i=0
    while [[ $i -lt $peer_count ]]; do
        local name ip pubkey enabled is_gw lan_sub
        name=$(wg_db_get ".peers[$i].name")
        ip=$(wg_db_get ".peers[$i].ip")
        pubkey=$(wg_db_get ".peers[$i].public_key")
        enabled=$(wg_db_get ".peers[$i].enabled")
        is_gw=$(wg_db_get ".peers[$i].is_gateway // false")

        local type_str="普通"
        [[ "$is_gw" == "true" ]] && type_str="${C_YELLOW}网关${C_RESET}"

        local status_str
        if [[ "$enabled" != "true" ]]; then
            status_str="${C_GRAY}禁用${C_RESET}"
        else
            status_str="${C_GREEN}启用${C_RESET}"
        fi

        local rx_bytes="0" tx_bytes="0" last_handshake="从未"
        if [[ -n "$wg_dump" ]]; then
            local peer_line
            peer_line=$(echo "$wg_dump" | grep "^${pubkey}" 2>/dev/null)
            if [[ -n "$peer_line" ]]; then
                rx_bytes=$(echo "$peer_line" | awk '{print $6}')
                tx_bytes=$(echo "$peer_line" | awk '{print $7}')
                local hs_epoch
                hs_epoch=$(echo "$peer_line" | awk '{print $5}')
                if [[ -n "$hs_epoch" && "$hs_epoch" != "0" ]]; then
                    local now_epoch diff
                    now_epoch=$(date +%s)
                    diff=$((now_epoch - hs_epoch))
                    if [[ $diff -lt 60 ]]; then
                        last_handshake="${diff}秒前"
                        status_str="${C_GREEN}在线${C_RESET}"
                    elif [[ $diff -lt 3600 ]]; then
                        last_handshake="$((diff / 60))分前"
                    elif [[ $diff -lt 86400 ]]; then
                        last_handshake="$((diff / 3600))时前"
                    else
                        last_handshake="$((diff / 86400))天前"
                    fi
                fi
            fi
        fi

        printf "%-4s %-14s %-14s %-6b %-8b %-10s %-10s %s\n" \
            "$((i + 1))" "$name" "$ip" "$type_str" "$status_str" \
            "$(wg_format_bytes "$rx_bytes")" "$(wg_format_bytes "$tx_bytes")" "$last_handshake"

        i=$((i + 1))
    done

    echo ""
    echo -e "${C_CYAN}共 ${peer_count} 个设备${C_RESET}"

    local gw_found=0
    local gi=0
    while [[ $gi -lt $peer_count ]]; do
        local gw_check=$(wg_db_get ".peers[$gi].is_gateway // false")
        if [[ "$gw_check" == "true" ]]; then
            if [[ $gw_found -eq 0 ]]; then
                echo ""
                echo -e "${C_CYAN}网关设备 LAN 网段:${C_RESET}"
                gw_found=1
            fi
            local gw_name=$(wg_db_get ".peers[$gi].name")
            local gw_lans=$(wg_db_get ".peers[$gi].lan_subnets // empty")
            echo -e "  ${gw_name}: ${C_GREEN}${gw_lans:-未设置}${C_RESET}"
        fi
        gi=$((gi + 1))
    done

    pause
}

show_main_menu() {
    fix_terminal
    clear

    local W=76
    printf "${C_CYAN}%${W}s${C_RESET}\n" | tr ' ' '='
    if [[ "$PLATFORM" == "openwrt" ]]; then
        printf "${C_CYAN}%*s${C_RESET}\n" $(((${#SCRIPT_NAME}+22+W)/2)) "$SCRIPT_NAME $VERSION [OpenWrt]"
    else
        printf "${C_CYAN}%*s${C_RESET}\n" $(((${#SCRIPT_NAME}+10+W)/2)) "$SCRIPT_NAME $VERSION"
    fi
    printf "${C_CYAN}%${W}s${C_RESET}\n" | tr ' ' '='

    show_dual_column_sysinfo

    printf "${C_CYAN}%${W}s${C_RESET}\n" | tr ' ' '='

    echo ""
    echo -e " ${C_CYAN}功能菜单${C_RESET}"
    echo ""

    if [[ "$PLATFORM" == "openwrt" ]]; then
        printf " %-38s %-38s\n" "$(echo -e "${C_GRAY}1. 基础依赖安装 [不可用]${C_RESET}")" "6. 网络工具 (DNS)"
        printf " %-38s %-38s\n" "$(echo -e "${C_GRAY}2. UFW 防火墙 [不可用]${C_RESET}")"    "7. Web 服务 (SSL+Nginx+DDNS)"
        printf " %-38s %-38s\n" "$(echo -e "${C_GRAY}3. Fail2ban [不可用]${C_RESET}")"       "$(echo -e "${C_GRAY}8. Docker [不可用]${C_RESET}")"
        printf " %-38s %-38s\n" "$(echo -e "${C_GRAY}4. SSH 管理 [不可用]${C_RESET}")"       "9. 查看操作日志"
        printf " %-38s %-38s\n" "5. 系统优化 (BBR/主机名/时区)"                               "10. WireGuard VPN"
        printf " %-38s\n"      "0. 退出脚本"
    else
        printf " %-38s %-38s\n" "1. 基础依赖安装" "6. 网络工具 (DNS/测速)"
        printf " %-38s %-38s\n" "2. UFW 防火墙管理" "7. Web 服务 (SSL+Nginx)"
        printf " %-38s %-38s\n" "3. Fail2ban 入侵防御" "8. Docker 管理"
        printf " %-38s %-38s\n" "4. SSH 安全配置" "9. 查看操作日志"
        printf " %-38s %-38s\n" "5. 系统优化 (BBR/Swap)" "10. WireGuard VPN"
        printf " %-38s\n" "0. 退出脚本"
    fi
    echo ""
}

wg_toggle_peer() {
    wg_check_server || return 1

    print_title "启用/禁用 WireGuard 设备"

    local peer_count
    peer_count=$(wg_db_get '.peers | length')

    if [[ "$peer_count" -eq 0 || "$peer_count" == "null" ]]; then
        print_warn "暂无设备"
        pause; return
    fi

    local i=0
    while [[ $i -lt $peer_count ]]; do
        local name ip enabled mark=""
        name=$(wg_db_get ".peers[$i].name")
        ip=$(wg_db_get ".peers[$i].ip")
        enabled=$(wg_db_get ".peers[$i].enabled")
        if [[ "$enabled" == "true" ]]; then
            mark=" ${C_GREEN}(已启用)${C_RESET}"
        else
            mark=" ${C_RED}(已禁用)${C_RESET}"
        fi
        echo -e "  $((i + 1)). ${name} (${ip})${mark}"
        i=$((i + 1))
    done
    echo "  0. 返回"
    echo ""

    read -e -r -p "选择要切换状态的设备序号: " idx
    [[ "$idx" == "0" || -z "$idx" ]] && return

    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -lt 1 || "$idx" -gt "$peer_count" ]]; then
        print_error "无效序号"
        pause; return
    fi

    local target_idx=$((idx - 1))
    local target_name target_pubkey current_state
    target_name=$(wg_db_get ".peers[$target_idx].name")
    target_pubkey=$(wg_db_get ".peers[$target_idx].public_key")
    current_state=$(wg_db_get ".peers[$target_idx].enabled")

    if [[ "$current_state" == "true" ]]; then
        if confirm "确认禁用设备 '${target_name}'？"; then
            wg_db_set --argjson idx "$target_idx" '.peers[$idx].enabled = false'
            if wg_is_running; then
                wg set "$WG_INTERFACE" peer "$target_pubkey" remove 2>/dev/null || true
            fi
            wg_rebuild_conf
            print_success "设备 '${target_name}' 已禁用"
            log_action "WireGuard peer disabled: ${target_name}"
        fi
    else
        if confirm "确认启用设备 '${target_name}'？"; then
            wg_db_set --argjson idx "$target_idx" '.peers[$idx].enabled = true'
            wg_rebuild_conf
            if wg_is_running; then
                wg syncconf "$WG_INTERFACE" <(wg-quick strip "$WG_INTERFACE") 2>/dev/null || {
                    wg-quick down "$WG_INTERFACE" 2>/dev/null
                    wg-quick up "$WG_INTERFACE" 2>/dev/null
                }
            fi
            print_success "设备 '${target_name}' 已启用"
            log_action "WireGuard peer enabled: ${target_name}"
        fi
    fi

    pause
}

wg_delete_peer() {
    wg_check_server || return 1

    print_title "删除 WireGuard 设备"

    local peer_count
    peer_count=$(wg_db_get '.peers | length')

    if [[ "$peer_count" -eq 0 || "$peer_count" == "null" ]]; then
        print_warn "暂无设备"
        pause; return
    fi

    local i=0
    while [[ $i -lt $peer_count ]]; do
        local name ip enabled mark=""
        name=$(wg_db_get ".peers[$i].name")
        ip=$(wg_db_get ".peers[$i].ip")
        enabled=$(wg_db_get ".peers[$i].enabled")
        [[ "$enabled" != "true" ]] && mark=" ${C_GRAY}(已禁用)${C_RESET}"
        echo -e "  $((i + 1)). ${name} (${ip})${mark}"
        i=$((i + 1))
    done
    echo "  0. 返回"
    echo ""

    read -e -r -p "选择要删除的设备序号: " idx
    [[ "$idx" == "0" || -z "$idx" ]] && return

    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -lt 1 || "$idx" -gt "$peer_count" ]]; then
        print_error "无效序号"
        pause; return
    fi

    local target_idx=$((idx - 1))
    local target_name target_pubkey
    target_name=$(wg_db_get ".peers[$target_idx].name")
    target_pubkey=$(wg_db_get ".peers[$target_idx].public_key")

    if ! confirm "确认删除设备 '${target_name}'？"; then
        return
    fi

        if wg_is_running; then
        wg set "$WG_INTERFACE" peer "$target_pubkey" remove 2>/dev/null || true
    fi

    local _del_gw=$(wg_db_get ".peers[$target_idx].is_gateway // false")
    local _del_lans=$(wg_db_get ".peers[$target_idx].lan_subnets // empty")

    wg_db_set --argjson idx "$target_idx" 'del(.peers[$idx])'

    if [[ "$_del_gw" == "true" && -n "$_del_lans" ]]; then
        local _pc=$(wg_db_get '.peers | length')
        local _all_lans="" _pi=0
        while [[ $_pi -lt $_pc ]]; do
            local _pls=$(wg_db_get ".peers[$_pi].lan_subnets // empty")
            [[ -n "$_pls" ]] && { [[ -n "$_all_lans" ]] && _all_lans="${_all_lans}, "; _all_lans="${_all_lans}${_pls}"; }
            _pi=$((_pi + 1))
        done
        local server_subnet=$(wg_db_get '.server.subnet')
        _pi=0
        while [[ $_pi -lt $_pc ]]; do
            local _cur=$(wg_db_get ".peers[$_pi].client_allowed_ips")
            [[ "$_cur" == *"0.0.0.0/0"* ]] && { _pi=$((_pi + 1)); continue; }
            [[ "$_cur" == "$server_subnet" ]] && { _pi=$((_pi + 1)); continue; }
            local _is_gw=$(wg_db_get ".peers[$_pi].is_gateway // false")
            local _own=$(wg_db_get ".peers[$_pi].lan_subnets // empty")
            if [[ "$_is_gw" == "true" ]]; then
                local _other="" _IFS_BAK="$IFS"; IFS=','
                for _c in $_all_lans; do
                    _c=$(echo "$_c" | xargs); [[ -z "$_c" ]] && continue
                    local _skip=false _IFS2="$IFS"; IFS=','
                    for _o in $_own; do _o=$(echo "$_o" | xargs); [[ "$_c" == "$_o" ]] && { _skip=true; break; }; done
                    IFS="$_IFS2"
                    [[ "$_skip" != "true" ]] && { [[ -n "$_other" ]] && _other="${_other}, "; _other="${_other}${_c}"; }
                done; IFS="$_IFS_BAK"
                local _new="$server_subnet"
                [[ -n "$_other" ]] && _new="${server_subnet}, ${_other}"
                wg_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a'
            else
                if [[ -n "$_all_lans" ]]; then
                    wg_db_set --argjson idx "$_pi" --arg a "${server_subnet}, ${_all_lans}" '.peers[$idx].client_allowed_ips = $a'
                else
                    wg_db_set --argjson idx "$_pi" --arg a "$server_subnet" '.peers[$idx].client_allowed_ips = $a'
                fi
            fi
            _pi=$((_pi + 1))
        done
    fi

    rm -f "/etc/wireguard/clients/${target_name}.conf"
    wg_rebuild_conf
    wg_regenerate_client_confs

    print_success "设备 '${target_name}' 已删除"
    log_action "WireGuard peer deleted: ${target_name}"
    pause
}

wg_show_peer_conf() {
    wg_check_server || return 1

    print_title "查看设备配置 / 二维码"

    local peer_count
    peer_count=$(wg_db_get '.peers | length')

    if [[ "$peer_count" -eq 0 || "$peer_count" == "null" ]]; then
        print_warn "暂无设备"
        pause; return
    fi

    local i=0
    while [[ $i -lt $peer_count ]]; do
        local name ip is_gw
        name=$(wg_db_get ".peers[$i].name")
        ip=$(wg_db_get ".peers[$i].ip")
        is_gw=$(wg_db_get ".peers[$i].is_gateway // false")
        local mark=""
        [[ "$is_gw" == "true" ]] && mark=" ${C_YELLOW}(网关)${C_RESET}"
        echo -e "  $((i + 1)). ${name} (${ip})${mark}"
        i=$((i + 1))
    done
    echo "  0. 返回"
    echo ""

    read -e -r -p "选择设备序号: " idx
    [[ "$idx" == "0" || -z "$idx" ]] && return

    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -lt 1 || "$idx" -gt "$peer_count" ]]; then
        print_error "无效序号"
        pause; return
    fi

    local target_idx=$((idx - 1))
    local target_name
    target_name=$(wg_db_get ".peers[$target_idx].name")

    local conf_file="/etc/wireguard/clients/${target_name}.conf"

    if [[ ! -f "$conf_file" ]]; then
        print_warn "配置文件不存在，正在从数据库重新生成..."

        local peer_privkey peer_ip peer_psk client_allowed_ips
        peer_privkey=$(wg_db_get ".peers[$target_idx].private_key")
        peer_ip=$(wg_db_get ".peers[$target_idx].ip")
        peer_psk=$(wg_db_get ".peers[$target_idx].preshared_key")
        client_allowed_ips=$(wg_db_get ".peers[$target_idx].client_allowed_ips")

        local spub sep sport sdns ssub mask
        spub=$(wg_db_get '.server.public_key')
        sep=$(wg_db_get '.server.endpoint')
        sport=$(wg_db_get '.server.port')
        sdns=$(wg_db_get '.server.dns')
        ssub=$(wg_db_get '.server.subnet')
        mask=$(echo "$ssub" | cut -d'/' -f2)

        local is_gw_check=$(wg_db_get ".peers[$target_idx].is_gateway // false")
        local dns_line="DNS = ${sdns}"
        [[ "$is_gw_check" == "true" ]] && dns_line=""

        local regen_content="[Interface]
PrivateKey = ${peer_privkey}
Address = ${peer_ip}/${mask}
${dns_line}

[Peer]
PublicKey = ${spub}
PresharedKey = ${peer_psk}
Endpoint = ${sep}:${sport}
AllowedIPs = ${client_allowed_ips}
PersistentKeepalive = 25"

        regen_content=$(echo "$regen_content" | sed '/^$/N;/^\n$/d')

        mkdir -p /etc/wireguard/clients
        write_file_atomic "$conf_file" "$regen_content"
        chmod 600 "$conf_file"
        print_success "配置文件已重新生成"
    fi

    echo ""
    draw_line
    echo -e "${C_CYAN}=== ${target_name} 客户端配置 ===${C_RESET}"
    draw_line
    cat "$conf_file"
    draw_line
    echo ""

    if command_exists qrencode; then
        if confirm "显示二维码 (手机扫码导入)?"; then
            echo ""
            echo -e "${C_CYAN}=== ${target_name} 二维码 ===${C_RESET}"
            qrencode -t ansiutf8 < "$conf_file"
            echo ""
        fi
    fi

    # === 网关设备: 显示 OpenWrt 部署命令 ===
    local is_gateway
    is_gateway=$(wg_db_get ".peers[$target_idx].is_gateway // false")

    if [[ "$is_gateway" == "true" ]]; then
        echo ""
        if confirm "显示 OpenWrt uci 部署命令?"; then
            local peer_privkey peer_ip peer_psk client_allowed_ips
            peer_privkey=$(wg_db_get ".peers[$target_idx].private_key")
            peer_ip=$(wg_db_get ".peers[$target_idx].ip")
            peer_psk=$(wg_db_get ".peers[$target_idx].preshared_key")
            client_allowed_ips=$(wg_db_get ".peers[$target_idx].client_allowed_ips")

            local spub sep sport ssub mask
            spub=$(wg_db_get '.server.public_key')
            sep=$(wg_db_get '.server.endpoint')
            sport=$(wg_db_get '.server.port')
            ssub=$(wg_db_get '.server.subnet')
            mask=$(echo "$ssub" | cut -d'/' -f2)

            local ep_host="$sep"

            local uci_allowed_lines=""
            local IFS_BAK="$IFS"; IFS=','
            for cidr in $client_allowed_ips; do
                cidr=$(echo "$cidr" | xargs)
                [[ -n "$cidr" ]] && uci_allowed_lines="${uci_allowed_lines}uci add_list network.wg_server.allowed_ips='${cidr}'
"
            done
            IFS="$IFS_BAK"

            echo ""
            draw_line
            echo -e "${C_CYAN}=== OpenWrt 部署命令 ===${C_RESET}"
            echo -e "${C_YELLOW}在 OpenWrt SSH 终端依次执行以下命令:${C_RESET}"
            draw_line

            cat << OPENWRT_EOF

uci delete network.wg0 2>/dev/null; true
uci delete network.wg_server 2>/dev/null; true
uci delete firewall.wg_zone 2>/dev/null; true
uci delete firewall.wg_fwd_lan 2>/dev/null; true
uci delete firewall.wg_fwd_wg 2>/dev/null; true
uci commit network 2>/dev/null; true
uci commit firewall 2>/dev/null; true
ifdown wg0 2>/dev/null; true
if ! lsmod | grep -q wireguard; then
    opkg update
    opkg install kmod-wireguard || echo '[!] kmod 安装失败，请确认固件已内置 WireGuard 或内核版本匹配'
fi
opkg update
opkg install wireguard-tools luci-proto-wireguard
uci set network.wg0=interface
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key='${peer_privkey}'
uci delete network.wg0.addresses 2>/dev/null; true
uci add_list network.wg0.addresses='${peer_ip}/${mask}'
uci set network.wg_server=wireguard_wg0
uci set network.wg_server.public_key='${spub}'
uci set network.wg_server.preshared_key='${peer_psk}'
uci set network.wg_server.endpoint_host='${ep_host}'
uci set network.wg_server.endpoint_port='${sport}'
uci set network.wg_server.persistent_keepalive='25'
uci set network.wg_server.route_allowed_ips='1'
${uci_allowed_lines}
uci set firewall.wg_zone=zone
uci set firewall.wg_zone.name='wg'
uci set firewall.wg_zone.input='ACCEPT'
uci set firewall.wg_zone.output='ACCEPT'
uci set firewall.wg_zone.forward='ACCEPT'
uci set firewall.wg_zone.masq='1'
uci add_list firewall.wg_zone.network='wg0'

# LAN -> WG 转发 (LAN 设备访问 VPN 网络)
uci set firewall.wg_fwd_lan=forwarding
uci set firewall.wg_fwd_lan.src='lan'
uci set firewall.wg_fwd_lan.dest='wg'

# WG -> LAN 转发 (VPN 对端访问本地 LAN 设备)
uci set firewall.wg_fwd_wg=forwarding
uci set firewall.wg_fwd_wg.src='wg'
uci set firewall.wg_fwd_wg.dest='lan'
uci commit network
uci commit firewall
/etc/init.d/firewall reload
/etc/init.d/network reload

OPENWRT_EOF
            draw_line
            echo -e "${C_GREEN}复制以上全部命令到 OpenWrt SSH 终端执行即可。${C_RESET}"
            echo ""
            echo -e "${C_CYAN}验证方法:${C_RESET}"
            echo "  1. OpenWrt 上执行: wg show"
            echo "  2. LuCI 界面: Network -> Interfaces 查看 wg0 状态"
            echo "  3. LAN 设备 ping VPN 服务端: ping $(wg_db_get '.server.ip')"
            draw_line
        fi
    fi

    echo ""
    echo -e "配置文件路径: ${C_CYAN}${conf_file}${C_RESET}"
    echo -e "下载命令: ${C_GRAY}scp root@服务器IP:${conf_file} ./${C_RESET}"

    pause
}

wg_generate_clash_config() {
    wg_check_server || return 1

    print_title "生成 Clash (OpenClash) WireGuard 配置"

    local peer_count
    peer_count=$(wg_db_get '.peers | length')

    if [[ "$peer_count" -eq 0 || "$peer_count" == "null" ]]; then
        print_warn "暂无设备，请先添加 Peer"
        pause; return
    fi

    echo "选择要生成 Clash 配置的设备:"
    local i=0
    while [[ $i -lt $peer_count ]]; do
        local name ip is_gw
        name=$(wg_db_get ".peers[$i].name")
        ip=$(wg_db_get ".peers[$i].ip")
        is_gw=$(wg_db_get ".peers[$i].is_gateway // false")
        local mark=""
        [[ "$is_gw" == "true" ]] && mark=" ${C_YELLOW}(网关)${C_RESET}"
        echo -e "  $((i + 1)). ${name} (${ip})${mark}"
        i=$((i + 1))
    done
    echo "  0. 返回"
    echo ""

    read -e -r -p "选择设备序号: " idx
    [[ "$idx" == "0" || -z "$idx" ]] && return
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -lt 1 || "$idx" -gt "$peer_count" ]]; then
        print_error "无效序号"; pause; return
    fi

    local ti=$((idx - 1))
    local peer_name peer_ip peer_privkey peer_psk
    peer_name=$(wg_db_get ".peers[$ti].name")
    peer_ip=$(wg_db_get ".peers[$ti].ip")
    peer_privkey=$(wg_db_get ".peers[$ti].private_key")
    peer_psk=$(wg_db_get ".peers[$ti].preshared_key")

    local server_pubkey server_endpoint server_port server_subnet server_dns
    server_pubkey=$(wg_db_get '.server.public_key')
    server_endpoint=$(wg_db_get '.server.endpoint')
    server_port=$(wg_db_get '.server.port')
    server_subnet=$(wg_db_get '.server.subnet')
    server_dns=$(wg_db_get '.server.dns' | cut -d',' -f1 | xargs)
    local mask
    mask=$(echo "$server_subnet" | cut -d'/' -f2)

    local vpn_cidrs=("$server_subnet")
    local pi=0
    while [[ $pi -lt $peer_count ]]; do
        local pls=$(wg_db_get ".peers[$pi].lan_subnets // empty")
        if [[ -n "$pls" ]]; then
            local IFS_BAK="$IFS"; IFS=','
            for cidr in $pls; do
                cidr=$(echo "$cidr" | xargs)
                [[ -n "$cidr" ]] && vpn_cidrs+=("$cidr")
            done
            IFS="$IFS_BAK"
        fi
        pi=$((pi + 1))
    done
    local unique_cidrs=($(printf '%s\n' "${vpn_cidrs[@]}" | sort -u))

    echo ""
    draw_line
    echo -e "${C_CYAN}设备信息:${C_RESET}"
    echo "  名称: $peer_name"
    echo "  VPN IP: $peer_ip/$mask"
    echo "  服务端: $server_endpoint:$server_port"
    echo "  路由网段: ${unique_cidrs[*]}"
    draw_line

    echo ""
    echo "请选择操作方式:"
    echo "  1. 生成 YAML 片段 (手动合并到现有配置)"
    echo "  2. 粘贴现有 YAML，自动注入 WireGuard 规则"
    echo "  0. 返回"
    read -e -r -p "选择 [1]: " gen_mode
    gen_mode=${gen_mode:-1}

    local wg_proxy_name="WireGuard-${peer_name}"

    local wg_proxy_yaml="  - name: \"${wg_proxy_name}\"
    type: wireguard
    server: ${server_endpoint}
    port: ${server_port}
    ip: ${peer_ip}
    private-key: \"${peer_privkey}\"
    public-key: \"${server_pubkey}\"
    pre-shared-key: \"${peer_psk}\"
    reserved: [0, 0, 0]
    udp: true
    mtu: 1280
    remote-dns-resolve: false
    dns:
      - ${server_dns}"

    local wg_rules_yaml=""
    if [[ "$server_endpoint" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        wg_rules_yaml="  - IP-CIDR,${server_endpoint}/32,DIRECT
"
    else
        wg_rules_yaml="  - DOMAIN,${server_endpoint},DIRECT
"
    fi
    for cidr in "${unique_cidrs[@]}"; do
        wg_rules_yaml="${wg_rules_yaml}  - IP-CIDR,${cidr},${wg_proxy_name}
"
    done

    local wg_group_yaml="  - name: WireGuard-VPN
    type: select
    proxies:
      - ${wg_proxy_name}
      - DIRECT"

    case $gen_mode in
        1)
            echo ""
            draw_line
            echo -e "${C_CYAN}=== 需要添加到 YAML 的内容 ===${C_RESET}"
            draw_line
            echo ""
            echo -e "${C_YELLOW}# ━━━ 第1步: 在 proxies: 段末尾添加此节点 ━━━${C_RESET}"
            echo ""
            echo "$wg_proxy_yaml"
            echo ""
            echo -e "${C_YELLOW}# ━━━ 第2步: 在 proxy-groups: 段末尾添加此分组 ━━━${C_RESET}"
            echo ""
            echo "$wg_group_yaml"
            echo ""
            echo -e "${C_YELLOW}# ━━━ 第3步: 在 rules: 段最前面添加 (必须在其他规则之前) ━━━${C_RESET}"
            echo ""
            echo -n "$wg_rules_yaml"
            echo ""
            draw_line
            echo -e "${C_CYAN}[使用说明]${C_RESET}"
            echo "  1. 服务端 IP/域名 → DIRECT: 防止 WG 握手流量被代理 (死循环)"
            echo "  2. VPN 子网 + LAN 网段 → ${wg_proxy_name}: 内网流量走 WG 隧道"
            echo "  3. 其他流量按原有规则走代理或直连"
            echo ""
            echo -e "${C_YELLOW}要求: Clash Meta (mihomo) 内核 1.14.0+${C_RESET}"
            echo -e "${C_YELLOW}OpenClash 请在设置中切换到 Meta 内核${C_RESET}"
            draw_line
            ;;
        2)
            echo ""
            echo -e "${C_CYAN}请粘贴你现有的完整 YAML 配置 (粘贴完成后按 Ctrl+D):${C_RESET}"
            local original_yaml
            original_yaml=$(cat)

            if [[ -z "$original_yaml" ]]; then
                print_error "内容为空"; pause; return
            fi

            if ! echo "$original_yaml" | grep -q "^proxies:"; then
                print_error "YAML 中未找到 'proxies:' 段，请确认格式正确"
                pause; return
            fi

            local output_file="/tmp/clash-wg-${peer_name}-$(date +%s).yaml"

            awk \
                -v proxy_node="$wg_proxy_yaml" \
                -v proxy_group="$wg_group_yaml" \
                -v rules="$wg_rules_yaml" \
                -v proxy_name="$wg_proxy_name" \
            '
            BEGIN { state="init"; proxy_done=0; group_done=0; rule_done=0 }

            /^proxies:/ {
                state = "proxies"
                print
                next
            }

            state == "proxies" && /^[a-z]/ {
                if (!proxy_done) {
                    print ""
                    print "  # === WireGuard VPN 节点 (自动生成) ==="
                    print proxy_node
                    print ""
                    proxy_done = 1
                }
                state = "init"
            }

            /^proxy-groups:/ {
                state = "groups"
                print
                next
            }

            state == "groups" && /^[a-z]/ {
                if (!group_done) {
                    print ""
                    print "  # === WireGuard VPN 分组 (自动生成) ==="
                    print proxy_group
                    print ""
                    group_done = 1
                }
                state = "init"
            }

            /^rules:/ {
                print $0
                print "  # === WireGuard VPN 路由规则 (自动生成) ==="
                printf "%s", rules
                rule_done = 1
                state = "rules"
                next
            }

            { print }

            END {
                if (!proxy_done) {
                    print ""
                    print "  # === WireGuard VPN 节点 (自动生成) ==="
                    print proxy_node
                }
                if (!group_done) {
                    print ""
                    print "  # === WireGuard VPN 分组 (自动生成) ==="
                    print proxy_group
                }
                if (!rule_done) {
                    print ""
                    print "rules:"
                    print "  # === WireGuard VPN 路由规则 (自动生成) ==="
                    printf "%s", rules
                }
            }
            ' <<< "$original_yaml" > "$output_file"

            if ! grep -q "$wg_proxy_name" "$output_file" 2>/dev/null; then
                print_warn "自动注入不完整，使用追加方式..."
                {
                    echo "$original_yaml"
                    echo ""
                    echo "# ============================================"
                    echo "# WireGuard VPN 追加内容 (请手动合并到对应段)"
                    echo "# ============================================"
                    echo ""
                    echo "# --- 添加到 proxies: 段末尾 ---"
                    echo "$wg_proxy_yaml"
                    echo ""
                    echo "# --- 添加到 proxy-groups: 段末尾 ---"
                    echo "$wg_group_yaml"
                    echo ""
                    echo "# --- 添加到 rules: 段最前面 ---"
                    echo -n "$wg_rules_yaml"
                } > "$output_file"
            fi

            echo ""
            draw_line
            echo -e "${C_GREEN}[✓] 配置已生成!${C_RESET}"
            draw_line
            echo ""
            echo -e "文件路径: ${C_CYAN}${output_file}${C_RESET}"
            echo ""

            echo "查看方式:"
            echo "  1. 在终端显示完整配置"
            echo "  2. 仅显示注入的部分"
            echo "  3. 跳过"
            read -e -r -p "选择 [3]: " view_mode
            view_mode=${view_mode:-3}

            case $view_mode in
                1)
                    echo ""
                    cat "$output_file"
                    echo ""
                    ;;
                2)
                    echo ""
                    echo -e "${C_CYAN}=== WireGuard 节点 ===${C_RESET}"
                    echo "$wg_proxy_yaml"
                    echo ""
                    echo -e "${C_CYAN}=== VPN 分组 ===${C_RESET}"
                    echo "$wg_group_yaml"
                    echo ""
                    echo -e "${C_CYAN}=== 路由规则 ===${C_RESET}"
                    echo -n "$wg_rules_yaml"
                    echo ""
                    ;;
            esac

            echo -e "${C_CYAN}下载命令:${C_RESET}"
            echo "  scp root@$(wg_db_get '.server.endpoint'):${output_file} ./clash-config.yaml"
            echo ""
            echo -e "${C_CYAN}使用方法:${C_RESET}"
            echo "  1. 下载生成的 YAML 文件"
            echo "  2. 导入到 Clash Meta / OpenClash / Stash / Clash Verge"
            echo "  3. 访问 VPN 内网 IP 时自动走 WireGuard 隧道"
            echo "  4. 其他流量按原有规则走代理"
            draw_line
            ;;
        0|"") return ;;
        *) print_error "无效选项" ;;
    esac

    echo ""
    echo -e "${C_YELLOW}[重要提示]${C_RESET}"
    echo "  • 需要 Clash Meta (mihomo) 内核 1.14.0+，不支持原版 Clash"
    echo "  • OpenClash 设置中需切换到 Meta 内核"
    echo "  • iOS Stash / macOS ClashX Meta / Windows Clash Verge 均支持"
    echo "  • 如果服务端在 NAT 后面，确保 UDP ${server_port} 端口已转发"
    echo "  • WireGuard 节点不支持走其他代理链 (不能套娃)"

    log_action "Clash WireGuard config generated for peer: ${peer_name}"
    pause
}

wg_port_forward_menu() {
    wg_check_server || return 1

    while true; do
        print_title "WireGuard 端口转发管理"

        local pf_count
        pf_count=$(wg_db_get '.port_forwards | length')

        if [[ "$pf_count" -gt 0 && "$pf_count" != "null" ]]; then
            printf "${C_CYAN}%-4s %-10s %-14s %-24s %-8s${C_RESET}\n" \
                "#" "协议" "外部端口" "转发目标" "状态"
            draw_line

            local i=0
            while [[ $i -lt $pf_count ]]; do
                local proto ext_port dest_ip dest_port enabled
                proto=$(wg_db_get ".port_forwards[$i].proto")
                ext_port=$(wg_db_get ".port_forwards[$i].ext_port")
                dest_ip=$(wg_db_get ".port_forwards[$i].dest_ip")
                dest_port=$(wg_db_get ".port_forwards[$i].dest_port")
                enabled=$(wg_db_get ".port_forwards[$i].enabled")

                local status_str
                [[ "$enabled" == "true" ]] && status_str="${C_GREEN}启用${C_RESET}" || status_str="${C_RED}禁用${C_RESET}"

                printf "%-4s %-10s %-14s %-24s %-8b\n" \
                    "$((i + 1))" "$proto" "$ext_port" "${dest_ip}:${dest_port}" "$status_str"
                i=$((i + 1))
            done
            echo ""
        else
            print_info "暂无端口转发规则"
            echo ""
        fi

        echo "  1. 添加端口转发"
        echo "  2. 删除端口转发"
        echo "  3. 启用/禁用端口转发"
        echo "  0. 返回"
        echo ""

        read -e -r -p "$(echo -e "${C_CYAN}选择操作: ${C_RESET}")" pf_choice

        case $pf_choice in
            1) wg_add_port_forward ;;
            2) wg_delete_port_forward ;;
            3) wg_toggle_port_forward ;;
            0|"") return ;;
            *) print_warn "无效选项" ;;
        esac
    done
}

wg_add_port_forward() {
    echo ""
    print_info "添加端口转发规则"
    echo ""

    echo "  1. TCP"
    echo "  2. UDP"
    echo "  3. TCP+UDP"
    read -e -r -p "协议 [1]: " proto_choice
    proto_choice=${proto_choice:-1}
    local proto
    case $proto_choice in
        1) proto="tcp" ;;
        2) proto="udp" ;;
        3) proto="tcp+udp" ;;
        *) proto="tcp" ;;
    esac

    local ext_port
    while true; do
        read -e -r -p "外部端口 (本机监听): " ext_port
        validate_port "$ext_port" && break
        print_warn "端口无效 (1-65535)"
    done

    local peer_count
    peer_count=$(wg_db_get '.peers | length')

    local dest_ip
    if [[ "$peer_count" -gt 0 ]]; then
        echo ""
        echo "选择目标设备:"
        local i=0
        while [[ $i -lt $peer_count ]]; do
            local name ip
            name=$(wg_db_get ".peers[$i].name")
            ip=$(wg_db_get ".peers[$i].ip")
            echo "  $((i + 1)). ${name} (${ip})"
            i=$((i + 1))
        done
        echo "  0. 手动输入 IP"
        echo ""
        read -e -r -p "选择: " dev_choice

        if [[ "$dev_choice" == "0" || -z "$dev_choice" ]]; then
            read -e -r -p "目标 IP: " dest_ip
        elif [[ "$dev_choice" =~ ^[0-9]+$ ]] && [[ "$dev_choice" -ge 1 && "$dev_choice" -le "$peer_count" ]]; then
            dest_ip=$(wg_db_get ".peers[$((dev_choice - 1))].ip")
        else
            print_error "无效选择"; return
        fi
    else
        read -e -r -p "目标 IP: " dest_ip
    fi

    [[ -z "$dest_ip" ]] && { print_error "目标 IP 不能为空"; return; }

    local dest_port
    read -e -r -p "目标端口 [${ext_port}]: " dest_port
    dest_port=${dest_port:-$ext_port}
    validate_port "$dest_port" || { print_error "端口无效"; return; }

    _wg_pf_iptables -A "$proto" "$ext_port" "$dest_ip" "$dest_port"
    wg_save_iptables
    wg_db_set --arg proto "$proto" \
              --arg ext "$ext_port" \
              --arg dip "$dest_ip" \
              --arg dport "$dest_port" \
    '.port_forwards += [{
        proto: $proto,
        ext_port: ($ext | tonumber),
        dest_ip: $dip,
        dest_port: ($dport | tonumber),
        enabled: true
    }]'

    if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        if [[ "$proto" == "tcp+udp" ]]; then
            ufw allow "$ext_port" comment "WG-PF" >/dev/null 2>&1
        else
            ufw allow "${ext_port}/${proto}" comment "WG-PF" >/dev/null 2>&1
        fi
    fi

    print_success "端口转发已添加: ${ext_port}/${proto} -> ${dest_ip}:${dest_port}"
    log_action "WireGuard port forward added: ${ext_port}/${proto} -> ${dest_ip}:${dest_port}"
}

wg_delete_port_forward() {
    local pf_count
    pf_count=$(wg_db_get '.port_forwards | length')

    [[ "$pf_count" -eq 0 ]] && { print_warn "暂无规则"; return; }

    echo ""
    read -e -r -p "选择要删除的规则序号: " idx
    [[ -z "$idx" ]] && return

    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -lt 1 || "$idx" -gt "$pf_count" ]]; then
        print_error "无效序号"; return
    fi

    local target_idx=$((idx - 1))
    local proto ext_port dest_ip dest_port
    proto=$(wg_db_get ".port_forwards[$target_idx].proto")
    ext_port=$(wg_db_get ".port_forwards[$target_idx].ext_port")
    dest_ip=$(wg_db_get ".port_forwards[$target_idx].dest_ip")
    dest_port=$(wg_db_get ".port_forwards[$target_idx].dest_port")

    _wg_pf_iptables -D "$proto" "$ext_port" "$dest_ip" "$dest_port"
    wg_save_iptables
    wg_db_set --argjson idx "$target_idx" 'del(.port_forwards[$idx])'

    print_success "端口转发规则已删除"
    log_action "WireGuard port forward deleted: ${ext_port}/${proto} -> ${dest_ip}:${dest_port}"
}

wg_toggle_port_forward() {
    local pf_count
    pf_count=$(wg_db_get '.port_forwards | length')
    [[ "$pf_count" -eq 0 ]] && { print_warn "暂无规则"; return; }

    echo ""
    read -e -r -p "选择要切换状态的规则序号: " idx
    [[ -z "$idx" ]] && return

    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -lt 1 || "$idx" -gt "$pf_count" ]]; then
        print_error "无效序号"; return
    fi

    local target_idx=$((idx - 1))
    local proto ext_port dest_ip dest_port current_state
    proto=$(wg_db_get ".port_forwards[$target_idx].proto")
    ext_port=$(wg_db_get ".port_forwards[$target_idx].ext_port")
    dest_ip=$(wg_db_get ".port_forwards[$target_idx].dest_ip")
    dest_port=$(wg_db_get ".port_forwards[$target_idx].dest_port")
    current_state=$(wg_db_get ".port_forwards[$target_idx].enabled")

    if [[ "$current_state" == "true" ]]; then
        _wg_pf_iptables -D "$proto" "$ext_port" "$dest_ip" "$dest_port"
        wg_db_set --argjson idx "$target_idx" '.port_forwards[$idx].enabled = false'
        print_success "端口转发已禁用: ${ext_port}/${proto}"
    else
        _wg_pf_iptables -A "$proto" "$ext_port" "$dest_ip" "$dest_port"
        wg_db_set --argjson idx "$target_idx" '.port_forwards[$idx].enabled = true'
        print_success "端口转发已启用: ${ext_port}/${proto}"
    fi
    wg_save_iptables
}

wg_modify_server() {
    wg_check_server || return 1

    print_title "修改 WireGuard 服务端配置"

    local cur_port cur_dns cur_ep
    cur_port=$(wg_db_get '.server.port')
    cur_dns=$(wg_db_get '.server.dns')
    cur_ep=$(wg_db_get '.server.endpoint')

    echo -e "  当前端口:   ${C_GREEN}${cur_port}${C_RESET}"
    echo -e "  当前 DNS:   ${C_GREEN}${cur_dns}${C_RESET}"
    echo -e "  当前端点:   ${C_GREEN}${cur_ep}${C_RESET}"
    echo ""

    local changed=false

    read -e -r -p "新监听端口 [${cur_port}]: " new_port
    new_port=${new_port:-$cur_port}
    if [[ "$new_port" != "$cur_port" ]]; then
        if validate_port "$new_port"; then
            wg_db_set --argjson p "$new_port" '.server.port = $p'
            changed=true
            print_info "端口将更改为 ${new_port}"
        else
            print_warn "端口无效，保持原值"
        fi
    fi

    read -e -r -p "新客户端 DNS [${cur_dns}]: " new_dns
    new_dns=${new_dns:-$cur_dns}
    if [[ "$new_dns" != "$cur_dns" ]]; then
        wg_db_set --arg d "$new_dns" '.server.dns = $d'
        changed=true
        print_info "DNS 将更改为 ${new_dns}"
    fi

    read -e -r -p "新公网端点 [${cur_ep}]: " new_ep
    new_ep=${new_ep:-$cur_ep}
    if [[ "$new_ep" != "$cur_ep" ]]; then
        wg_db_set --arg e "$new_ep" '.server.endpoint = $e'
        changed=true
        print_info "端点将更改为 ${new_ep}"
    fi

    if [[ "$changed" != "true" ]]; then
        print_info "未做任何更改"
        pause; return
    fi

    wg_rebuild_conf
    wg_regenerate_client_confs

    if wg_is_running; then
        wg-quick down "$WG_INTERFACE" 2>/dev/null
        wg-quick up "$WG_INTERFACE" 2>/dev/null
    fi

    if [[ "$new_port" != "$cur_port" ]]; then
        if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
            ufw delete allow "${cur_port}/udp" 2>/dev/null || true
            ufw allow "${new_port}/udp" comment "WireGuard" >/dev/null 2>&1
        fi
    fi

    print_success "服务端配置已更新"
    log_action "WireGuard server config modified: port=${new_port} dns=${new_dns} endpoint=${new_ep}"
    pause
}

wg_client_install() {
    print_title "安装 WireGuard 客户端"

    if wg_is_installed && [[ "$(wg_get_role)" == "client" ]]; then
        print_warn "WireGuard 客户端已安装。"
        wg_is_running && echo -e "  状态: ${C_GREEN}● 已连接${C_RESET}" || echo -e "  状态: ${C_RED}● 未连接${C_RESET}"
        pause; return 0
    fi

    if wg_is_installed && [[ "$(wg_get_role)" == "server" ]]; then
        print_error "当前已安装为服务端模式。如需切换为客户端，请先卸载。"
        pause; return 1
    fi

    echo ""
    print_info "[1/3] 安装软件包..."
    wg_install_packages || { pause; return 1; }

    print_info "[2/3] 导入客户端配置..."
    echo ""
    echo "请选择导入方式:"
    echo "  1. 粘贴配置内容"
    echo "  2. 指定配置文件路径"
    echo ""
    read -e -r -p "选择 [1]: " import_mode
    import_mode=${import_mode:-1}

    local conf_content=""

    case $import_mode in
        1)
            echo ""
            echo -e "${C_CYAN}请粘贴客户端配置内容 (粘贴完成后按 Ctrl+D):${C_RESET}"
            conf_content=$(cat)
            ;;
        2)
            read -e -r -p "配置文件路径: " conf_path
            if [[ ! -f "$conf_path" ]]; then
                print_error "文件不存在: ${conf_path}"
                pause; return 1
            fi
            conf_content=$(cat "$conf_path")
            ;;
        *)
            print_error "无效选择"
            pause; return 1
            ;;
    esac

    if [[ -z "$conf_content" ]]; then
        print_error "配置内容为空"
        pause; return 1
    fi

    if ! echo "$conf_content" | grep -q "\[Interface\]"; then
        print_error "配置格式无效: 缺少 [Interface] 段"
        pause; return 1
    fi

    if ! echo "$conf_content" | grep -q "\[Peer\]"; then
        print_error "配置格式无效: 缺少 [Peer] 段"
        pause; return 1
    fi

    if ! echo "$conf_content" | grep -qi "PrivateKey"; then
        print_error "配置格式无效: 缺少 PrivateKey"
        pause; return 1
    fi

    write_file_atomic "$WG_CONF" "$conf_content"
    chmod 600 "$WG_CONF"

    print_info "[3/3] 保存配置信息..."
    wg_db_init
    wg_set_role "client"

    local client_addr client_dns server_pubkey server_endpoint server_allowed
    client_addr=$(echo "$conf_content" | grep -i "^Address" | head -1 | sed 's/^[^=]*=[[:space:]]*//')
    client_dns=$(echo "$conf_content" | grep -i "^DNS" | head -1 | sed 's/^[^=]*=[[:space:]]*//')
    server_pubkey=$(echo "$conf_content" | sed -n '/\[Peer\]/,/^$/p' | grep -i "^PublicKey" | head -1 | sed 's/^[^=]*=[[:space:]]*//')
    server_endpoint=$(echo "$conf_content" | grep -i "^Endpoint" | head -1 | sed 's/^[^=]*=[[:space:]]*//')
    server_allowed=$(echo "$conf_content" | grep -i "^AllowedIPs" | head -1 | sed 's/^[^=]*=[[:space:]]*//')

    wg_db_set --arg addr "${client_addr:-unknown}" \
              --arg dns "${client_dns:-}" \
              --arg spub "${server_pubkey:-}" \
              --arg ep "${server_endpoint:-}" \
              --arg allowed "${server_allowed:-}" \
    '.client = {
        address: $addr,
        dns: $dns,
        server_pubkey: $spub,
        server_endpoint: $ep,
        allowed_ips: $allowed
    }'

    echo ""
    draw_line
    print_success "WireGuard 客户端安装完成！"
    echo -e "  角色:     ${C_GREEN}客户端 (Client)${C_RESET}"
    echo -e "  地址:     ${C_GREEN}${client_addr:-未知}${C_RESET}"
    echo -e "  服务端:   ${C_GREEN}${server_endpoint:-未知}${C_RESET}"
    draw_line

    echo ""
    if confirm "是否立即连接?"; then
        wg_client_connect
    fi

    log_action "WireGuard client installed: addr=${client_addr} endpoint=${server_endpoint}"
    pause
}

wg_client_connect() {
    if wg_is_running; then
        print_warn "WireGuard 已连接"
        return 0
    fi

    print_info "正在连接..."

    is_systemd && systemctl enable "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1
    wg-quick up "$WG_INTERFACE" 2>/dev/null

    sleep 1

    if wg_is_running; then
        print_success "WireGuard 已连接"
        log_action "WireGuard client connected"
    else
        print_error "连接失败，请检查配置"
        log_action "WireGuard client connect failed"
    fi
}

wg_client_disconnect() {
    if ! wg_is_running; then
        print_warn "WireGuard 未连接"
        return 0
    fi

    print_info "正在断开..."
    wg-quick down "$WG_INTERFACE" 2>/dev/null

    if is_systemd; then
        systemctl disable "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1
    fi

    sleep 1

    if ! wg_is_running; then
        print_success "WireGuard 已断开"
        log_action "WireGuard client disconnected"
    else
        print_error "断开失败"
    fi
}

wg_client_reconnect() {
    print_info "正在重新连接..."
    wg-quick down "$WG_INTERFACE" 2>/dev/null
    sleep 1
    wg-quick up "$WG_INTERFACE" 2>/dev/null
    sleep 1

    if wg_is_running; then
        print_success "WireGuard 已重新连接"
    else
        print_error "重新连接失败"
    fi
}

wg_client_status() {
    print_title "WireGuard 客户端状态"

    if ! wg_is_installed; then
        print_warn "WireGuard 未安装"
        pause; return
    fi

    local role
    role=$(wg_get_role)
    echo -e "  角色: ${C_GREEN}${role:-未知}${C_RESET}"

    if wg_is_running; then
        echo -e "  状态: ${C_GREEN}● 已连接${C_RESET}"
    else
        echo -e "  状态: ${C_RED}● 未连接${C_RESET}"
        pause; return
    fi

    echo ""
    draw_line

    local wg_output
    wg_output=$(wg show "$WG_INTERFACE" 2>/dev/null)

    if [[ -n "$wg_output" ]]; then
        echo "$wg_output" | while IFS= read -r line; do
            case "$line" in
                *"public key:"*)
                    echo -e "  本机公钥:   ${C_CYAN}$(echo "$line" | awk -F': ' '{print $2}')${C_RESET}" ;;
                *"listening port:"*)
                    echo -e "  监听端口:   $(echo "$line" | awk -F': ' '{print $2}')" ;;
                *"endpoint:"*)
                    echo -e "  服务端端点: ${C_GREEN}$(echo "$line" | awk -F': ' '{print $2}')${C_RESET}" ;;
                *"allowed ips:"*)
                    echo -e "  允许 IP:    $(echo "$line" | awk -F': ' '{print $2}')" ;;
                *"latest handshake:"*)
                    echo -e "  最近握手:   ${C_GREEN}$(echo "$line" | awk -F': ' '{print $2}')${C_RESET}" ;;
                *"transfer:"*)
                    echo -e "  流量统计:   $(echo "$line" | awk -F': ' '{print $2}')" ;;
                *"persistent keepalive:"*)
                    echo -e "  保活间隔:   $(echo "$line" | awk -F': ' '{print $2}')" ;;
            esac
        done
    fi

    draw_line

    echo ""
    if [[ "$role" == "client" ]]; then
        local client_info
        client_info=$(wg_db_get '.client // empty')
        if [[ -n "$client_info" ]]; then
            local addr ep
            addr=$(wg_db_get '.client.address')
            ep=$(wg_db_get '.client.server_endpoint')
            echo -e "  本机地址:   ${C_GREEN}${addr}${C_RESET}"
            echo -e "  服务端:     ${C_GREEN}${ep}${C_RESET}"
        fi

        echo ""
        print_info "连通性测试..."

        local server_vip
        server_vip=$(echo "$wg_output" | grep "allowed ips" | head -1 | awk -F': ' '{print $2}' | cut -d'/' -f1 | cut -d',' -f1 | xargs)

        if [[ "$server_vip" == "0.0.0.0" || -z "$server_vip" ]]; then
            local client_ip_base
            client_ip_base=$(wg_db_get '.client.address' | cut -d'/' -f1)
            if [[ -n "$client_ip_base" ]]; then
                server_vip=$(echo "$client_ip_base" | awk -F'.' '{print $1"."$2"."$3".1"}')
            fi
        fi

        if [[ -n "$server_vip" ]]; then
            if ping -c 2 -W 3 "$server_vip" >/dev/null 2>&1; then
                echo -e "  Ping ${server_vip}: ${C_GREEN}✓ 可达${C_RESET}"
            else
                echo -e "  Ping ${server_vip}: ${C_RED}✗ 不可达${C_RESET}"
            fi
        fi
    fi

    pause
}

wg_client_reconfig() {
    if [[ "$(wg_get_role)" != "client" ]]; then
        print_error "当前不是客户端模式"
        pause; return 1
    fi

    print_title "更换客户端配置"

    print_warn "这将替换当前的 WireGuard 配置"
    if ! confirm "确认继续?"; then
        return
    fi

    wg_is_running && wg-quick down "$WG_INTERFACE" 2>/dev/null

    echo ""
    echo "请选择导入方式:"
    echo "  1. 粘贴配置内容"
    echo "  2. 指定配置文件路径"
    echo ""
    read -e -r -p "选择 [1]: " import_mode
    import_mode=${import_mode:-1}

    local conf_content=""

    case $import_mode in
        1)
            echo ""
            echo -e "${C_CYAN}请粘贴新的客户端配置 (粘贴完成后按 Ctrl+D):${C_RESET}"
            conf_content=$(cat)
            ;;
        2)
            read -e -r -p "配置文件路径: " conf_path
            if [[ ! -f "$conf_path" ]]; then
                print_error "文件不存在: ${conf_path}"
                pause; return 1
            fi
            conf_content=$(cat "$conf_path")
            ;;
    esac

    if [[ -z "$conf_content" ]] || ! echo "$conf_content" | grep -q "\[Interface\]"; then
        print_error "配置内容无效"
        pause; return 1
    fi

    cp "$WG_CONF" "${WG_CONF}.bak.$(date +%s)" 2>/dev/null || true

    write_file_atomic "$WG_CONF" "$conf_content"
    chmod 600 "$WG_CONF"

    local client_addr server_endpoint
    client_addr=$(echo "$conf_content" | grep -i "^Address" | head -1 | sed 's/^[^=]*=[[:space:]]*//')
    server_endpoint=$(echo "$conf_content" | grep -i "^Endpoint" | head -1 | sed 's/^[^=]*=[[:space:]]*//')

    wg_db_set --arg addr "${client_addr:-unknown}" \
              --arg ep "${server_endpoint:-}" \
    '.client.address = $addr | .client.server_endpoint = $ep'

    print_success "配置已更新"

    if confirm "是否立即连接?"; then
        wg_client_connect
    fi

    log_action "WireGuard client reconfigured: addr=${client_addr} endpoint=${server_endpoint}"
    pause
}

wg_server_status() {
    wg_check_server || return 1

    print_title "WireGuard 服务端状态"

    local port subnet endpoint dns
    port=$(wg_db_get '.server.port')
    subnet=$(wg_db_get '.server.subnet')
    endpoint=$(wg_db_get '.server.endpoint')
    dns=$(wg_db_get '.server.dns')

    echo -e "  角色:     ${C_GREEN}服务端 (Server)${C_RESET}"

    if wg_is_running; then
        echo -e "  状态:     ${C_GREEN}● 运行中${C_RESET}"
    else
        echo -e "  状态:     ${C_RED}● 已停止${C_RESET}"
    fi

    echo -e "  端口:     ${port}/udp"
    echo -e "  子网:     ${subnet}"
    echo -e "  端点:     ${endpoint}"
    echo -e "  DNS:      ${dns}"
    echo ""

    local peer_count
    peer_count=$(wg_db_get '.peers | length')

    echo -e "${C_CYAN}设备列表 (${peer_count} 个):${C_RESET}"
    draw_line

    if [[ "$peer_count" -gt 0 ]]; then
        printf "${C_CYAN}%-4s %-16s %-18s %-8s %-20s %-16s${C_RESET}\n" \
            "#" "名称" "IP" "状态" "最近握手" "流量"
        draw_line

        local wg_dump=""
        wg_is_running && wg_dump=$(wg show "$WG_INTERFACE" dump 2>/dev/null | tail -n +2)

        local i=0
        while [[ $i -lt $peer_count ]]; do
            local name ip pubkey enabled
            name=$(wg_db_get ".peers[$i].name")
            ip=$(wg_db_get ".peers[$i].ip")
            pubkey=$(wg_db_get ".peers[$i].public_key")
            enabled=$(wg_db_get ".peers[$i].enabled")

            local status_str handshake_str transfer_str

            if [[ "$enabled" != "true" ]]; then
                status_str="${C_RED}禁用${C_RESET}"
                handshake_str="-"
                transfer_str="-"
            elif [[ -n "$wg_dump" ]]; then
                local peer_line
                peer_line=$(echo "$wg_dump" | grep "^${pubkey}" || true)

                if [[ -n "$peer_line" ]]; then
                    local last_hs rx tx
                    last_hs=$(echo "$peer_line" | awk '{print $5}')
                    rx=$(echo "$peer_line" | awk '{print $6}')
                    tx=$(echo "$peer_line" | awk '{print $7}')

                    if [[ "$last_hs" -gt 0 ]] 2>/dev/null; then
                        local now hs_ago
                        now=$(date +%s)
                        hs_ago=$((now - last_hs))

                        if [[ $hs_ago -lt 180 ]]; then
                            status_str="${C_GREEN}在线${C_RESET}"
                        else
                            status_str="${C_YELLOW}离线${C_RESET}"
                        fi

                        if [[ $hs_ago -lt 60 ]]; then
                            handshake_str="${hs_ago}秒前"
                        elif [[ $hs_ago -lt 3600 ]]; then
                            handshake_str="$((hs_ago / 60))分钟前"
                        elif [[ $hs_ago -lt 86400 ]]; then
                            handshake_str="$((hs_ago / 3600))小时前"
                        else
                            handshake_str="$((hs_ago / 86400))天前"
                        fi
                    else
                        status_str="${C_YELLOW}离线${C_RESET}"
                        handshake_str="从未"
                    fi

                    transfer_str="↓$(wg_format_bytes "$rx") ↑$(wg_format_bytes "$tx")"
                else
                    status_str="${C_YELLOW}离线${C_RESET}"
                    handshake_str="-"
                    transfer_str="-"
                fi
            else
                status_str="${C_GRAY}未知${C_RESET}"
                handshake_str="-"
                transfer_str="-"
            fi

            printf "%-4s %-16s %-18s %-8b %-20s %-16s\n" \
                "$((i + 1))" "$name" "$ip" "$status_str" "$handshake_str" "$transfer_str"

            i=$((i + 1))
        done
    else
        print_info "暂无设备"
    fi

    draw_line

    local pf_count
    pf_count=$(wg_db_get '.port_forwards | length')

    if [[ "$pf_count" -gt 0 ]]; then
        echo ""
        echo -e "${C_CYAN}端口转发规则 (${pf_count} 条):${C_RESET}"
        draw_line
        local j=0
        while [[ $j -lt $pf_count ]]; do
            local proto ext_port dest_ip dest_port pf_enabled
            proto=$(wg_db_get ".port_forwards[$j].proto")
            ext_port=$(wg_db_get ".port_forwards[$j].ext_port")
            dest_ip=$(wg_db_get ".port_forwards[$j].dest_ip")
            dest_port=$(wg_db_get ".port_forwards[$j].dest_port")
            pf_enabled=$(wg_db_get ".port_forwards[$j].enabled")

            local pf_status
            [[ "$pf_enabled" == "true" ]] && pf_status="${C_GREEN}●${C_RESET}" || pf_status="${C_RED}○${C_RESET}"

            echo -e "  ${pf_status} ${ext_port}/${proto} -> ${dest_ip}:${dest_port}"
            j=$((j + 1))
        done
        draw_line
    fi

    pause
}

wg_start() {
    if wg_is_running; then
        print_warn "WireGuard 已在运行"
        return 0
    fi

    if [[ ! -f "$WG_CONF" ]]; then
        print_error "配置文件不存在: ${WG_CONF}"
        return 1
    fi

    print_info "正在启动 WireGuard..."
    wg-quick up "$WG_INTERFACE" 2>/dev/null

    if is_systemd; then
        systemctl enable "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1
    fi

    sleep 1

    if wg_is_running; then
        wg_restore_port_forwards
        print_success "WireGuard 已启动"
        log_action "WireGuard started"
    else
        print_error "启动失败"
        log_action "WireGuard start failed"
    fi
}

wg_stop() {
    if ! wg_is_running; then
        print_warn "WireGuard 未在运行"
        return 0
    fi

    print_info "正在停止 WireGuard..."
    wg-quick down "$WG_INTERFACE" 2>/dev/null

    sleep 1

    if ! wg_is_running; then
        print_success "WireGuard 已停止"
        log_action "WireGuard stopped"
    else
        print_error "停止失败"
    fi
}

wg_restart() {
    print_info "正在重启 WireGuard..."
    wg_is_running && wg-quick down "$WG_INTERFACE" 2>/dev/null
    sleep 1
    wg-quick up "$WG_INTERFACE" 2>/dev/null
    sleep 1

    if wg_is_running; then
        wg_restore_port_forwards
        print_success "WireGuard 已重启"
        log_action "WireGuard restarted"
    else
        print_error "重启失败"
        log_action "WireGuard restart failed"
    fi
}

wg_restore_port_forwards() {
    local role
    role=$(wg_get_role)
    [[ "$role" != "server" ]] && return 0

    local pf_count
    pf_count=$(wg_db_get '.port_forwards | length')
    [[ "$pf_count" -eq 0 || "$pf_count" == "null" ]] && return 0

    local j=0
    while [[ $j -lt $pf_count ]]; do
        local proto ext_port dest_ip dest_port pf_enabled
        proto=$(wg_db_get ".port_forwards[$j].proto")
        ext_port=$(wg_db_get ".port_forwards[$j].ext_port")
        dest_ip=$(wg_db_get ".port_forwards[$j].dest_ip")
        dest_port=$(wg_db_get ".port_forwards[$j].dest_port")
        pf_enabled=$(wg_db_get ".port_forwards[$j].enabled")

        if [[ "$pf_enabled" == "true" ]]; then
            _wg_pf_iptables_ensure "$proto" "$ext_port" "$dest_ip" "$dest_port"
        fi

        j=$((j + 1))
    done
}

wg_uninstall() {
    print_title "卸载 WireGuard"

    if ! wg_is_installed; then
        print_warn "WireGuard 未安装"
        pause; return 0
    fi

    local role
    role=$(wg_get_role)

    echo -e "  当前角色: ${C_GREEN}${role:-未知}${C_RESET}"
    echo ""

    print_warn "此操作将完全卸载 WireGuard，包括所有配置和密钥！"
    echo ""

    if ! confirm "确认卸载 WireGuard?"; then
        return
    fi

    if ! confirm "再次确认: 所有配置将被永久删除，是否继续?"; then
        return
    fi

    echo ""
    print_info "[1/5] 停止 WireGuard..."
    if wg_is_running; then
        wg-quick down "$WG_INTERFACE" 2>/dev/null || true
    fi

    if is_systemd; then
        systemctl disable "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1 || true
    fi

    print_info "[2/5] 清理端口转发规则..."
    if [[ "$role" == "server" ]]; then
        local pf_count
        pf_count=$(wg_db_get '.port_forwards | length' 2>/dev/null)

        if [[ -n "$pf_count" && "$pf_count" -gt 0 ]] 2>/dev/null; then

            local j=0
            while [[ $j -lt $pf_count ]]; do
                local proto ext_port dest_ip dest_port
                proto=$(wg_db_get ".port_forwards[$j].proto")
                ext_port=$(wg_db_get ".port_forwards[$j].ext_port")
                dest_ip=$(wg_db_get ".port_forwards[$j].dest_ip")
                dest_port=$(wg_db_get ".port_forwards[$j].dest_port")

                _wg_pf_iptables -D "$proto" "$ext_port" "$dest_ip" "$dest_port"

                j=$((j + 1))
            done

            wg_save_iptables
        fi
    fi

    print_info "[3/5] 清理防火墙规则..."
    if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        if [[ "$role" == "server" ]]; then
            local port
            port=$(wg_db_get '.server.port' 2>/dev/null)
            [[ -n "$port" ]] && ufw delete allow "${port}/udp" 2>/dev/null || true
        fi
        ufw status numbered 2>/dev/null | grep "WG-PF" | awk -F'[][]' '{print $2}' | sort -rn | while read -r num; do
            yes | ufw delete "$num" 2>/dev/null || true
        done
    fi

    print_info "[4/5] 删除配置文件..."
    rm -f "$WG_CONF" 2>/dev/null || true
    rm -rf /etc/wireguard/clients 2>/dev/null || true
    rm -f "$WG_DB_FILE" 2>/dev/null || true
    rm -rf "$WG_DB_DIR" 2>/dev/null || true          # ← 新增
    rm -f "$WG_ROLE_FILE" 2>/dev/null || true         # ← 新增
    rm -f /etc/wireguard/*.key 2>/dev/null || true

    rmdir /etc/wireguard 2>/dev/null || true

    print_info "[5/5] 卸载软件包..."
    local remove_pkg=true

    if confirm "是否卸载 WireGuard 软件包? (选 N 仅删除配置)"; then
        case $PLATFORM in
            debian|ubuntu)
                apt-get remove -y wireguard wireguard-tools >/dev/null 2>&1 || true
                apt-get autoremove -y >/dev/null 2>&1 || true
                ;;
            centos|rhel|rocky|alma|fedora)
                if command_exists dnf; then
                    dnf remove -y wireguard-tools >/dev/null 2>&1 || true
                else
                    yum remove -y wireguard-tools >/dev/null 2>&1 || true
                fi
                ;;
            alpine)
                apk del wireguard-tools >/dev/null 2>&1 || true
                ;;
            arch|manjaro)
                pacman -Rns --noconfirm wireguard-tools >/dev/null 2>&1 || true
                ;;
            openwrt)
                opkg remove wireguard-tools luci-proto-wireguard >/dev/null 2>&1 || true
                ;;
        esac
    else
        remove_pkg=false
    fi

    if [[ "$role" == "server" ]]; then
        if confirm "是否恢复 IP 转发设置? (如果其他服务需要转发请选 N)"; then
            sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf 2>/dev/null || true
            sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
        fi
    fi

    echo ""
    draw_line
    print_success "WireGuard 已完全卸载"
    draw_line

    log_action "WireGuard uninstalled: role=${role} pkg_removed=${remove_pkg}"
    pause
}

wg_openwrt_clean_cmd() {
    print_title "OpenWrt 清空 WireGuard 配置"
    echo -e "${C_YELLOW}复制以下命令到 OpenWrt SSH 终端执行:${C_RESET}"
    echo ""
    draw_line
    cat << 'CLEANEOF'
# 停止 WireGuard 接口
ifdown wg0 2>/dev/null; true

# 删除网络配置
uci delete network.wg0 2>/dev/null; true
uci delete network.wg_server 2>/dev/null; true

# 删除防火墙配置
uci delete firewall.wg_zone 2>/dev/null; true
uci delete firewall.wg_fwd_lan 2>/dev/null; true
uci delete firewall.wg_fwd_wg 2>/dev/null; true

# 提交并重载
uci commit network
uci commit firewall
/etc/init.d/firewall reload
/etc/init.d/network reload

echo "[✓] WireGuard 配置已清空"
CLEANEOF
    draw_line
    echo ""
    echo -e "${C_CYAN}执行后可在 LuCI -> Network -> Interfaces 确认 wg0 已消失${C_RESET}"
    pause
}

wg_server_menu() {
    while true; do
        print_title "WireGuard 服务端管理"

        if wg_is_running; then
            echo -e "  状态: ${C_GREEN}● 运行中${C_RESET}    接口: ${C_CYAN}${WG_INTERFACE}${C_RESET}"
        else
            echo -e "  状态: ${C_RED}● 已停止${C_RESET}    接口: ${C_CYAN}${WG_INTERFACE}${C_RESET}"
        fi

        local peer_count
        peer_count=$(wg_db_get '.peers | length')
        echo -e "  设备数: ${C_CYAN}${peer_count}${C_RESET}"
        echo ""

        echo "  ── 设备管理 ──────────────────"
        echo "  1. 查看状态"
        echo "  2. 添加设备"
        echo "  3. 删除设备"
        echo "  4. 启用/禁用设备"
        echo "  5. 查看设备配置/二维码"
        echo "  6. 生成 Clash/OpenClash 配置"
        echo ""
        echo "  ── 端口转发 ──────────────────"
        echo "  7. 端口转发管理"
        echo ""
        echo "  ── 服务控制 ──────────────────"
        echo "  8. 启动 WireGuard"
        echo "  9. 停止 WireGuard"
        echo "  10. 重启 WireGuard"
        echo ""
        echo "  ── 系统设置 ──────────────────"
        echo "  11. 修改服务端配置"
        echo "  12. 卸载 WireGuard"
        echo "  13. 生成 OpenWrt 清空 WG 配置命令"
        echo ""
        echo "  0. 返回上级菜单"
        echo ""

        read -e -r -p "$(echo -e "${C_CYAN}选择操作: ${C_RESET}")" choice

        case $choice in
            1) wg_server_status ;;
            2) wg_add_peer ;;
            3) wg_delete_peer ;;
            4) wg_toggle_peer ;;
            5) wg_show_peer_conf ;;
            6) wg_generate_clash_config ;;
            7) wg_port_forward_menu ;;
            8) wg_start; pause ;;
            9) wg_stop; pause ;;
            10) wg_restart; pause ;;
            11) wg_modify_server ;;
            12) wg_uninstall; return ;;
            13) wg_openwrt_clean_cmd ;;
            0|"") return ;;
            *) print_warn "无效选项" ;;
        esac
    done
}

wg_client_menu() {
    while true; do
        print_title "WireGuard 客户端管理"

        if wg_is_running; then
            echo -e "  状态: ${C_GREEN}● 已连接${C_RESET}    接口: ${C_CYAN}${WG_INTERFACE}${C_RESET}"
        else
            echo -e "  状态: ${C_RED}● 未连接${C_RESET}    接口: ${C_CYAN}${WG_INTERFACE}${C_RESET}"
        fi

        local client_addr client_ep
        client_addr=$(wg_db_get '.client.address' 2>/dev/null)
        client_ep=$(wg_db_get '.client.server_endpoint' 2>/dev/null)
        [[ -n "$client_addr" && "$client_addr" != "null" ]] && echo -e "  地址: ${C_CYAN}${client_addr}${C_RESET}"
        [[ -n "$client_ep" && "$client_ep" != "null" ]] && echo -e "  服务端: ${C_CYAN}${client_ep}${C_RESET}"
        echo ""

        echo "  1. 查看连接状态"
        echo "  2. 连接"
        echo "  3. 断开"
        echo "  4. 重新连接"
        echo "  5. 更换配置"
        echo "  6. 卸载 WireGuard"
        echo ""
        echo "  0. 返回上级菜单"
        echo ""

        read -e -r -p "$(echo -e "${C_CYAN}选择操作: ${C_RESET}")" choice

        case $choice in
            1) wg_client_status ;;
            2) wg_client_connect; pause ;;
            3) wg_client_disconnect; pause ;;
            4) wg_client_reconnect; pause ;;
            5) wg_client_reconfig ;;
            6) wg_uninstall; return ;;
            0|"") return ;;
            *) print_warn "无效选项" ;;
        esac
    done
}

wg_install_menu() {
    print_title "安装 WireGuard"
    echo ""
    echo "  请选择安装模式:"
    echo ""
    echo "  1. 服务端 (Server) - 作为 VPN 服务器，管理多个客户端"
    echo "  2. 客户端 (Client) - 连接到已有的 WireGuard 服务器"
    echo ""
    echo "  0. 返回"
    echo ""

    read -e -r -p "$(echo -e "${C_CYAN}选择: ${C_RESET}")" mode

    case $mode in
        1) wg_server_install ;;
        2) wg_client_install ;;
        0|"") return ;;
        *) print_warn "无效选项" ;;
    esac
}

wg_main_menu() {
    while true; do
        if wg_is_installed; then
            local role
            role=$(wg_get_role)

            case $role in
                server) wg_server_menu; return ;;
                client) wg_client_menu; return ;;
                *)
                    if [[ -f "$WG_CONF" ]] && grep -q "ListenPort" "$WG_CONF" && grep -q "\[Peer\]" "$WG_CONF"; then
                        if grep -c "\[Peer\]" "$WG_CONF" | grep -q "^1$" && ! grep -q "PostUp" "$WG_CONF"; then
                            print_warn "检测到 WireGuard 已安装但角色未知"
                            echo "  1. 作为服务端管理"
                            echo "  2. 作为客户端管理"
                            echo "  3. 卸载重装"
                            echo "  0. 返回"
                            read -e -r -p "选择: " rc
                            case $rc in
                                1) wg_set_role "server"; continue ;;
                                2) wg_set_role "client"; continue ;;
                                3) wg_uninstall; continue ;;
                                *) return ;;
                            esac
                        else
                            wg_set_role "server"; continue
                        fi
                    elif [[ -f "$WG_CONF" ]]; then
                        wg_set_role "client"; continue
                    else
                        print_warn "WireGuard 已安装但无配置文件"
                        echo "  1. 安装为服务端"
                        echo "  2. 安装为客户端"
                        echo "  3. 卸载"
                        echo "  0. 返回"
                        read -e -r -p "选择: " rc2
                        case $rc2 in
                            1) wg_server_install; continue ;;
                            2) wg_client_install; continue ;;
                            3) wg_uninstall; continue ;;
                            *) return ;;
                        esac
                    fi
                    ;;
            esac
        else
            wg_install_menu
            wg_is_installed || return
        fi
    done
}

menu_opt_openwrt() {
    fix_terminal
    while true; do
        print_title "系统优化 (OpenWrt 精简模式)"
        echo "1. 开启 BBR 加速"
        echo "2. 修改主机名"
        echo "3. 修改时区"
        echo -e "${C_GRAY}4. 虚拟内存 Swap [不可用]${C_RESET}"
        echo -e "${C_GRAY}5. 系统垃圾清理 [不可用]${C_RESET}"
        echo "0. 返回"
        echo ""
        read -e -r -p "选择: " c
        case $c in
            1) opt_bbr ;;
            2) opt_hostname ;;
            3) select_timezone || true; pause ;;
            4) feature_blocked "虚拟内存 Swap" ;;
            5) feature_blocked "系统垃圾清理 (apt)" ;;
            0|q) break ;;
            *) print_error "无效" ;;
        esac
    done
}
menu_net_openwrt() {
    fix_terminal
    while true; do
        print_title "网络管理工具 (OpenWrt 精简模式)"
        echo "1. DNS 配置"
        echo -e "${C_GRAY}2. IPv4/IPv6 优先级 [不可用]${C_RESET}"
        echo -e "${C_GRAY}3. iPerf3 测速 [不可用]${C_RESET}"
        echo ""
        echo "0. 返回"
        echo ""
        read -e -r -p "选择: " c
        case $c in
            1) net_dns ;;
            2) feature_blocked "IPv4/IPv6 优先级 (需要 /etc/gai.conf)" ;;
            3) feature_blocked "iPerf3 测速" ;;
            0|q) break ;;
            *) print_error "无效" ;;
        esac
    done
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
            1)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    feature_blocked "基础依赖安装 (apt-get)"
                else
                    menu_update
                fi
                ;;
            2)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    feature_blocked "UFW 防火墙 (OpenWrt 请用 LuCI 或 fw4)"
                else
                    menu_ufw
                fi
                ;;
            3)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    feature_blocked "Fail2ban"
                else
                    menu_f2b
                fi
                ;;
            4)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    feature_blocked "SSH 完整管理 (OpenWrt 请用 LuCI 或编辑 /etc/config/dropbear)"
                else
                    menu_ssh
                fi
                ;;
            5)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    menu_opt_openwrt
                else
                    menu_opt
                fi
                ;;
            6)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    menu_net_openwrt
                else
                    menu_net
                fi
                ;;
            7) menu_web ;;
            8)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    feature_blocked "Docker 管理"
                else
                    menu_docker
                fi
                ;;
            9)
                print_title "操作日志 (最近 50 条)"
                if [[ -f "$LOG_FILE" ]]; then
                    tail -n 50 "$LOG_FILE"
                else
                    print_warn "日志文件不存在。"
                fi
                pause
                ;;
            10)
                wg_main_menu
                ;;
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
main "$@"
