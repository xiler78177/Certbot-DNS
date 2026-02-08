
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
readonly CACHE_FILE="${CACHE_DIR}/sysinfo.cache"
readonly CACHE_TTL=300  # 缓存有效期(秒)

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
readonly C_DIM='\033[2m'


# --- 配置变量 ---
CF_API_TOKEN=""
DOMAIN=""
EMAIL="your@mail.com"
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
# 缓存变量
CACHED_IPV4=""
CACHED_IPV6=""
CACHED_ISP=""
CACHED_LOCATION=""
CACHE_TIMESTAMP=0

# ==============================================================================
# DDNS 核心函数 (添加到脚本开头的函数区域)
# ==============================================================================

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
    [[ "$1" == "4" ]] && { curl -4 -s --max-time 5 https://api.ipify.org 2>/dev/null || curl -4 -s --max-time 5 https://ifconfig.me 2>/dev/null; } || \
    { curl -6 -s --max-time 5 https://api64.ipify.org 2>/dev/null || curl -6 -s --max-time 5 https://ifconfig.me 2>/dev/null; }
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
    return 1
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
    
    # 更新 crontab，使用最小间隔
    local min_interval=$interval
    for conf in "$DDNS_CONFIG_DIR"/*.conf; do
        [[ -f "$conf" ]] || continue
        source "$conf"
        [[ "$DDNS_INTERVAL" -lt "$min_interval" ]] && min_interval=$DDNS_INTERVAL
    done
    
    local cron_tmp=$(mktemp)
    crontab -l 2>/dev/null | grep -v "ddns-update.sh" > "$cron_tmp" || true
    echo "*/$min_interval * * * * /usr/local/bin/ddns-update.sh >/dev/null 2>&1" >> "$cron_tmp"
    crontab "$cron_tmp"; rm -f "$cron_tmp"
    
    print_success "DDNS 已启用 (每 ${interval} 分钟检测)"
    log_action "DDNS enabled: $domain interval=${interval}m"
    return 0
}

# ==============================================================================
# 修改 web_cf_dns_update 函数 - 整合 DDNS
# ==============================================================================




# ==============================================================================
# 添加 DDNS 管理函数
# ==============================================================================
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
    local ip4=$(curl -4 -s --max-time 3 ifconfig.me 2>/dev/null)
    local ip6=$(curl -6 -s --max-time 3 ifconfig.me 2>/dev/null)
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

# ==============================================================================
# 0. 核心工具库
# ==============================================================================

# ============================================
# 缓存管理
# ============================================
load_cache() {
    if [[ -f "$CACHE_FILE" ]]; then
        local cache_age=$(($(date +%s) - $(stat -c %Y "$CACHE_FILE" 2>/dev/null || echo 0)))
        if [[ $cache_age -lt $CACHE_TTL ]]; then
            source "$CACHE_FILE" 2>/dev/null || return 1
            return 0
        fi
    fi
    return 1
}

save_cache() {
    mkdir -p "$CACHE_DIR"
    cat > "$CACHE_FILE" << EOF
CACHED_IPV4="$CACHED_IPV4"
CACHED_IPV6="$CACHED_IPV6"
CACHED_ISP="$CACHED_ISP"
CACHED_LOCATION="$CACHED_LOCATION"
CACHE_TIMESTAMP=$(date +%s)
EOF
    chmod 600 "$CACHE_FILE"
}

refresh_network_cache() {
    # 获取 IPv4
    CACHED_IPV4=$(curl -4 -s --connect-timeout 3 --max-time 5 https://api.ipify.org 2>/dev/null || echo "N/A")
    
    # 获取 IPv6
    CACHED_IPV6=$(curl -6 -s --connect-timeout 3 --max-time 5 https://api64.ipify.org 2>/dev/null)
    [[ -z "$CACHED_IPV6" || ! "$CACHED_IPV6" =~ : ]] && CACHED_IPV6="未配置"
    
    # 获取 ISP 和位置
    local ipinfo=$(curl -s --connect-timeout 3 --max-time 5 https://ipinfo.io/json 2>/dev/null || echo "{}")
    CACHED_ISP=$(echo "$ipinfo" | grep -o '"org"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    [[ -z "$CACHED_ISP" ]] && CACHED_ISP="N/A"
    
    local country=$(echo "$ipinfo" | grep -o '"country"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    local city=$(echo "$ipinfo" | grep -o '"city"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    CACHED_LOCATION="${country:-N/A} ${city:-}"
    
    save_cache
}

# ============================================
# IP定位函数
# ============================================
get_ip_location() {
    local ip="$1"
    local timeout=3
    
    # 跳过内网IP
    if [[ "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.) ]]; then
        echo "本地网络"
        return
    fi
    
    # 跳过IPv6本地地址
    if [[ "$ip" =~ ^(fe80:|::1|fc00:|fd00:) ]]; then
        echo "本地网络"
        return
    fi
    
    # 尝试 ip-api.com
    local result=$(timeout $timeout curl -s "http://ip-api.com/json/${ip}?lang=zh-CN&fields=status,country,regionName,city,isp" 2>/dev/null)
    
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

# ============================================
# 系统信息显示函数
# ============================================
show_compact_sysinfo() {
    local hostname=$(hostname)
    local os_info=$(grep PRETTY_NAME /etc/os-release | cut -d '=' -f2 | tr -d '"')
    local kernel=$(uname -r)
    local arch=$(uname -m)
    
    local cpu_model=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)
    local cpu_cores=$(nproc)
    local cpu_freq=$(awk '/MHz/ {printf "%.1f GHz", $4/1000; exit}' /proc/cpuinfo 2>/dev/null || echo "N/A")
    
    local cpu_usage=$(awk '{u=$2+$4; t=$2+$4+$5; if (NR==1){u1=u; t1=t;} else printf "%.0f%%", (($2+$4-u1) * 100 / (t-t1))}' \
        <(grep 'cpu ' /proc/stat) <(sleep 0.5; grep 'cpu ' /proc/stat) 2>/dev/null || echo "0%")
    
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | xargs)
    
    local tcp_conn=$(ss -tn state established 2>/dev/null | grep -v "^State" | wc -l)
    local udp_conn=$(ss -un 2>/dev/null | grep -v "^State" | wc -l)
    
    local mem_used=$(free -m | awk '/^Mem:/ {print $3}')
    local mem_total=$(free -m | awk '/^Mem:/ {print $2}')
    local mem_percent=$(awk "BEGIN {printf \"%.2f\", ($mem_used/$mem_total)*100}")
    
    local swap_used=$(free -m | awk '/^Swap:/ {print $3}')
    local swap_total=$(free -m | awk '/^Swap:/ {print $2}')
    local swap_percent=0
    [[ $swap_total -gt 0 ]] && swap_percent=$(awk "BEGIN {printf \"%.0f\", ($swap_used/$swap_total)*100}")
    
    local disk_used=$(df -h / | awk 'NR==2 {print $3}')
    local disk_total=$(df -h / | awk 'NR==2 {print $2}')
    local disk_percent=$(df -h / | awk 'NR==2 {print $5}')
    
    local main_if=$(ip route | grep default | awk '{print $5}' | head -1)
    [[ -z "$main_if" ]] && main_if=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo" | head -1)
    
    local rx_total="0.00G" tx_total="0.00G"
    if [[ -n "$main_if" && -f "/proc/net/dev" ]]; then
        local dev_stats=$(grep "$main_if:" /proc/net/dev | awk '{print $2, $10}')
        if [[ -n "$dev_stats" ]]; then
            rx_total=$(echo "$dev_stats" | awk '{printf "%.2fG", $1/1024/1024/1024}')
            tx_total=$(echo "$dev_stats" | awk '{printf "%.2fG", $2/1024/1024/1024}')
        fi
    fi
    
    local tcp_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
    local qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "unknown")
    
    local public_ipv4=$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null || echo "N/A")
    local public_ipv6=$(curl -s --max-time 3 -6 https://api64.ipify.org 2>/dev/null || echo "未配置")
    
    local ipinfo_json=$(curl -s --max-time 3 https://ipinfo.io/json 2>/dev/null || echo "{}")
    local isp=$(echo "$ipinfo_json" | jq -r '.org // "N/A"' 2>/dev/null || echo "N/A")
    local location=$(echo "$ipinfo_json" | jq -r '"\(.country) \(.city)"' 2>/dev/null | xargs || echo "N/A")
    
    local dns_servers=$(awk '/^nameserver/{printf "%s ", $2}' /etc/resolv.conf 2>/dev/null | xargs)
    
    local timezone="UTC"
    command -v timedatectl >/dev/null 2>&1 && timezone=$(timedatectl | grep "Time zone" | awk '{print $3}' || echo "UTC")
    local current_time=$(date "+%Y-%m-%d %I:%M %p")
    
    local runtime=$(awk -F. '{
        run_days=int($1 / 86400)
        run_hours=int(($1 % 86400) / 3600)
        run_minutes=int(($1 % 3600) / 60)
        if (run_days > 0) printf("%d天 ", run_days)
        if (run_hours > 0) printf("%d时 ", run_hours)
        printf("%d分", run_minutes)
    }' /proc/uptime)
    
    local last_login_info="无记录"
    if command -v last >/dev/null 2>&1; then
        local raw_output=$(last -n 10 -a -w 2>/dev/null)
        local valid_line=$(echo "$raw_output" | grep -E "^[a-zA-Z]" | grep -v "wtmp begins" | grep -v "^reboot" | head -1)
        
        if [[ -n "$valid_line" ]]; then
            local login_user=$(echo "$valid_line" | awk '{print $1}')
            local login_ip=$(echo "$valid_line" | awk '{print $NF}')
            local login_time=$(echo "$valid_line" | awk '{print $4, $5, $6, $7}' | sed 's/still.*//' | xargs)
            
            if [[ -n "$login_ip" && "$login_ip" =~ ^[0-9a-f.:]+$ ]]; then
                if [[ "$login_ip" == *:* ]]; then
                    local display_ip=$(echo "$login_ip" | cut -d: -f1-4)"::"
                    local ip_location=$(get_ip_location "$login_ip")
                    last_login_info="${login_user} 从 ${display_ip} (${ip_location}) 于 ${login_time}"
                else
                    local ip_location=$(get_ip_location "$login_ip")
                    last_login_info="${login_user} 从 ${login_ip} (${ip_location}) 于 ${login_time}"
                fi
            else
                last_login_info="${login_user} 于 ${login_time}"
            fi
        fi
    fi
    
    local current_users=$(who | wc -l)
    
    local ssh_port=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")
    local ufw_status="未安装"
    if command -v ufw >/dev/null 2>&1; then
        ufw_status=$(ufw status 2>/dev/null | grep -q "Status: active" && echo "已启用" || echo "未启用")
    fi
    
    local f2b_status="未安装"
    if command -v fail2ban-client >/dev/null 2>&1; then
        if systemctl is-active fail2ban &>/dev/null; then
            local banned_count=$(fail2ban-client status 2>/dev/null | grep "Banned" | awk '{sum+=$NF} END {print sum+0}')
            f2b_status="运行中 (已封禁: ${banned_count} IP)"
        else
            f2b_status="未运行"
        fi
    fi
    
    local nginx_status="未安装"
    if command -v nginx >/dev/null 2>&1; then
        nginx_status=$(systemctl is-active nginx &>/dev/null && echo "运行中" || echo "未运行")
    fi
    
    echo -e "${C_CYAN}系统信息查询${C_RESET}"
    echo "-------------"
    printf "%-16s %s\n" "主机名:" "$hostname"
    printf "%-16s %s\n" "系统版本:" "$os_info"
    printf "%-16s %s\n" "Linux版本:" "$kernel"
    echo "-------------"
    printf "%-16s %s\n" "CPU架构:" "$arch"
    printf "%-16s %s\n" "CPU型号:" "$cpu_model"
    printf "%-16s %s\n" "CPU核心数:" "$cpu_cores"
    printf "%-16s %s\n" "CPU频率:" "$cpu_freq"
    echo "-------------"
    printf "%-16s %s\n" "CPU占用:" "$cpu_usage"
    printf "%-16s %s\n" "系统负载:" "$load_avg"
    printf "%-16s %s|%s\n" "TCP|UDP连接数:" "$tcp_conn" "$udp_conn"
    printf "%-16s %s/%sM (%.2f%%)\n" "物理内存:" "$mem_used" "$mem_total" "$mem_percent"
    printf "%-16s %sM/%sM (%s%%)\n" "虚拟内存:" "$swap_used" "$swap_total" "$swap_percent"
    printf "%-16s %s/%s (%s)\n" "硬盘占用:" "$disk_used" "$disk_total" "$disk_percent"
    echo "-------------"
    printf "%-16s %s\n" "总接收:" "$rx_total"
    printf "%-16s %s\n" "总发送:" "$tx_total"
    echo "-------------"
    printf "%-16s %s %s\n" "网络算法:" "$tcp_cc" "$qdisc"
    echo "-------------"
    printf "%-16s %s\n" "运营商:" "$isp"
    printf "%-16s %s\n" "IPv4地址:" "$public_ipv4"
    printf "%-16s %s\n" "IPv6地址:" "$public_ipv6"
    printf "%-16s %s\n" "DNS地址:" "$dns_servers"
    printf "%-16s %s\n" "地理位置:" "$location"
    printf "%-16s %s %s\n" "系统时间:" "$timezone" "$current_time"
    echo "-------------"
    printf "%-16s %s\n" "运行时长:" "$runtime"
    echo "-------------"
    printf "%-16s %s\n" "最近登录:" "$last_login_info"
    printf "%-16s %s\n" "当前用户数:" "$current_users"
    echo "-------------"
    printf "%-16s %s\n" "SSH端口:" "$ssh_port"
    printf "%-16s %s\n" "UFW防火墙:" "$ufw_status"
    printf "%-16s %s\n" "Fail2Ban:" "$f2b_status"
    printf "%-16s %s\n" "Nginx状态:" "$nginx_status"
}

# ============================================
# 双栏系统信息显示
# ============================================
show_dual_column_sysinfo() {
    # 尝试加载缓存
    load_cache || refresh_network_cache
    
    # ===== 收集系统信息 =====
    local hostname=$(hostname)
    local os_info=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2 | head -c 35)
    local kernel=$(uname -r | head -c 20)
    local arch=$(uname -m)
    
    local cpu_model=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs | head -c 25)
    local cpu_cores=$(nproc 2>/dev/null || echo "1")
    local cpu_freq=$(awk '/MHz/ {printf "%.1fGHz", $4/1000; exit}' /proc/cpuinfo 2>/dev/null || echo "N/A")
    
    # CPU 使用率 (快速采样)
    local cpu_usage=$(awk '{u=$2+$4; t=$2+$4+$5; if(NR==1){u1=u;t1=t}else{if(t-t1>0)printf "%.0f%%",(u-u1)*100/(t-t1);else print "0%"}}' \
        <(grep 'cpu ' /proc/stat) <(sleep 0.3; grep 'cpu ' /proc/stat) 2>/dev/null || echo "0%")
    
    local load_avg=$(awk '{printf "%.2f %.2f %.2f", $1, $2, $3}' /proc/loadavg 2>/dev/null)
    
    # 连接数
    local tcp_conn=$(ss -tn state established 2>/dev/null | tail -n +2 | wc -l)
    local udp_conn=$(ss -un 2>/dev/null | tail -n +2 | wc -l)
    
    # 内存
    local mem_info=$(free -m | awk '/^Mem:/ {printf "%d/%dM %.0f%%", $3, $2, $3/$2*100}')
    local swap_info=$(free -m | awk '/^Swap:/ {if($2>0) printf "%d/%dM %.0f%%", $3, $2, $3/$2*100; else print "未启用"}')
    
    # 磁盘
    local disk_info=$(df -h / | awk 'NR==2 {printf "%s/%s %s", $3, $2, $5}')
    
    # 网络流量
    local main_if=$(ip route 2>/dev/null | awk '/default/{print $5; exit}')
    local rx_total="0B" tx_total="0B"
    if [[ -n "$main_if" ]]; then
        local stats=$(awk -v iface="$main_if:" '$1==iface {print $2,$10}' /proc/net/dev 2>/dev/null)
        if [[ -n "$stats" ]]; then
            rx_total=$(echo "$stats" | awk '{
                if($1>=1073741824) printf "%.2fG",$1/1073741824
                else if($1>=1048576) printf "%.0fM",$1/1048576
                else if($1>=1024) printf "%.0fK",$1/1024
                else printf "%dB",$1
            }')
            tx_total=$(echo "$stats" | awk '{
                if($2>=1073741824) printf "%.2fG",$2/1073741824
                else if($2>=1048576) printf "%.0fM",$2/1048576
                else if($2>=1024) printf "%.0fK",$2/1024
                else printf "%dB",$2
            }')
        fi
    fi
    
    # 网络算法
    local tcp_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "N/A")
    local qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "N/A")
    
    # 运行时间
    local uptime_str=$(awk '{d=int($1/86400);h=int($1%86400/3600);m=int($1%3600/60);
        if(d>0)printf "%d天%d时%d分",d,h,m;else if(h>0)printf "%d时%d分",h,m;else printf "%d分",m}' /proc/uptime)
    
    # 时间
    local sys_time=$(date "+%m-%d %H:%M")
    local timezone=$(timedatectl 2>/dev/null | awk '/Time zone/{print $3}' || echo "UTC")
    
    # SSH 端口
    local ssh_port=$(grep -E "^Port\s" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -z "$ssh_port" ]] && ssh_port="22"
    
    # 服务状态 (简化符号)
    local ufw_st="○"; command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active" && ufw_st="●"
    local f2b_st="○"; systemctl is-active fail2ban &>/dev/null && f2b_st="●"
    local nginx_st="○"; systemctl is-active nginx &>/dev/null && nginx_st="●"
    local docker_st="○"; systemctl is-active docker &>/dev/null && docker_st="●"
    
    # ===== 双栏输出 =====
    local W=76  # 总宽度
    local LW=37 # 左栏宽度
    local RW=37 # 右栏宽度
    
    # 主机信息
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "主机:" "$hostname" "IPv4:" "$CACHED_IPV4"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "系统:" "${os_info:0:17}" "IPv6:" "${CACHED_IPV6:0:20}"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "内核:" "$kernel" "运营商:" "${CACHED_ISP:0:18}"
    
    printf "${C_DIM}%${W}s${C_RESET}\n" | tr ' ' '-'
    
    # CPU 和内存
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "CPU:" "${cpu_model:0:17}" "内存:" "$mem_info"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "核心:" "${cpu_cores}核 @ $cpu_freq" "交换:" "$swap_info"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "负载:" "$load_avg" "硬盘:" "$disk_info"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "占用:" "$cpu_usage 连接:${tcp_conn}t/${udp_conn}u" "流量:" "↓${rx_total} ↑${tx_total}"
    
    printf "${C_DIM}%${W}s${C_RESET}\n" | tr ' ' '-'
    
    # 网络和时间
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "算法:" "$tcp_cc + $qdisc" "位置:" "${CACHED_LOCATION:0:18}"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "运行:" "$uptime_str" "时区:" "$timezone"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "SSH:" "端口 $ssh_port" "时间:" "$sys_time"
    
    printf "${C_DIM}%${W}s${C_RESET}\n" | tr ' ' '-'
    
    # 服务状态行
    printf " 服务: UFW[${C_GREEN}%s${C_RESET}] F2B[${C_GREEN}%s${C_RESET}] Nginx[${C_GREEN}%s${C_RESET}] Docker[${C_GREEN}%s${C_RESET}]\n" \
        "$ufw_st" "$f2b_st" "$nginx_st" "$docker_st"
    
        # 上次登录信息
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
# ============================================
# 终端修复函数
# ============================================
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

# 安全 Curl
safe_curl() {
    curl -s -L --connect-timeout 5 --max-time 10 --retry 3 --retry-delay 2 "$@"
}



# 错误处理
cleanup_temp_files() {
    rm -f /etc/.tmp.* 2>/dev/null
}



handle_interrupt() {
    cleanup_temp_files
    echo ""
    print_warn "操作已取消 (用户中断)。"
    exit 130
}

trap 'handle_interrupt' SIGINT SIGTERM

# 环境检查
check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        print_error "请使用 root 权限运行 (sudo)。"
        exit $E_PERMISSION
    fi
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
    print_title "基础依赖安装"
    
    print_info "正在检查并安装基础依赖..."
    echo ""
    
    # 记录安装前的状态
    local ufw_was_active=0
    local f2b_was_active=0
    
    if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw_was_active=1
    fi
    if systemctl is-active fail2ban &>/dev/null; then
        f2b_was_active=1
    fi
    
    # 更新软件源
    print_info "1/2 更新软件源..."
    if apt-get update -y >/dev/null 2>&1; then
        print_success "软件源更新完成"
    else
        print_warn "软件源更新失败，但继续安装"
    fi
    
    echo ""
    
    # 安装基础依赖
    print_info "2/2 安装基础依赖包..."
    local deps="curl wget jq unzip openssl ca-certificates ufw fail2ban nginx iproute2 net-tools procps"
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
    
    # 显示新安装服务的配置提示
    if [[ "$new_packages" == *"ufw"* ]] || [[ "$new_packages" == *"fail2ban"* ]]; then
        echo ""
        echo -e "${C_YELLOW}提示:${C_RESET} 检测到新安装的安全服务"
        [[ "$new_packages" == *"ufw"* ]] && echo "  - UFW 防火墙: 请通过菜单 [2] 配置后启用"
        [[ "$new_packages" == *"fail2ban"* ]] && echo "  - Fail2ban: 请通过菜单 [3] 配置后启用"
    fi
    
    # 恢复之前的服务状态（如果之前是运行的）
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



# ==============================================================================
# 3. 系统信息模块
# ==============================================================================

# 获取公网 IPv6 地址
get_public_ipv6() {
    local ipv6=""
    
    # 方法 1: api64.ipify.org
    ipv6=$(curl -6 -s --connect-timeout 5 --max-time 10 https://api64.ipify.org 2>/dev/null)
    if [[ -n "$ipv6" ]] && [[ "$ipv6" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ipv6" == *:* ]]; then
        echo "$ipv6"
        return 0
    fi
    
    # 方法 2: ifconfig.co
    ipv6=$(curl -6 -s --connect-timeout 5 --max-time 10 https://ifconfig.co 2>/dev/null)
    if [[ -n "$ipv6" ]] && [[ "$ipv6" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ipv6" == *:* ]]; then
        echo "$ipv6"
        return 0
    fi
    
    # 方法 3: 本地接口
    if command -v ip >/dev/null 2>&1; then
        ipv6=$(ip -6 addr show scope global 2>/dev/null | grep -oP '(?<=inet6 )[0-9a-fA-F:]+' | grep -v '^fe80:' | head -n1)
        if [[ -n "$ipv6" ]]; then
            echo "$ipv6"
            return 0
        fi
    fi
    
    echo "未检测到"
    return 0
}


sys_info() {
    print_title "系统状态查询"
    echo ""
    show_compact_sysinfo
    echo ""
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
    
    print_title "删除 UFW 规则"
    echo -e "${C_CYAN}当前放行的端口 (已过滤 Fail2ban 规则):${C_RESET}"
    echo ""
    
    # 显示 ALLOW 规则（端口/协议）
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
                # 指定了协议
                ufw delete allow "${port}${proto}" 2>/dev/null && print_success "已删除: ${port}${proto}" || print_warn "${port}${proto} 不存在"
            else
                # 未指定协议，删除 tcp 和 udp
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
                    # 指定了协议
                    ufw allow "${port}${proto}" comment "Manual-Add" >/dev/null && \
                        print_success "已放行: ${port}${proto}" || \
                        print_error "添加失败: ${port}${proto}"
                else
                    # 未指定协议，同时添加 tcp 和 udp
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

    # SSH 端口
    read -e -r -p "监控 SSH 端口 [$CURRENT_SSH_PORT]: " port
    port=${port:-$CURRENT_SSH_PORT}
    if ! validate_port "$port"; then
        print_error "端口无效，使用默认值 $CURRENT_SSH_PORT"
        port=$CURRENT_SSH_PORT
    fi
    
    # 最大重试次数
    read -e -r -p "最大重试次数 (登录失败几次后封禁) [5]: " maxretry
    maxretry=${maxretry:-5}
    if ! [[ "$maxretry" =~ ^[0-9]+$ ]] || [ "$maxretry" -lt 1 ]; then
        print_warn "无效输入，使用默认值 5"
        maxretry=5
    fi
    
    # 封禁时间
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
    
    # 检测时间窗口
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
    
    # 显示配置摘要
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

    local conf_content="[DEFAULT]
# 封禁时间
bantime = $bantime
# 检测时间窗口
findtime = $findtime
# 封禁动作 (使用 UFW)
banaction = ufw

[sshd]
enabled = true
port = $port
# 最大重试次数
maxretry = $maxretry
# 后端检测方式
backend = $backend
# 日志路径 (auto 自动检测)
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
        
        # 显示当前状态
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

    local backup_file="${SSHD_CONFIG}.bak.$(date +%s)"
    cp "$SSHD_CONFIG" "$backup_file"
    
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
            if command_exists ufw && ufw status | grep -q "Status: active"; then
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
# ==============================================================================
# 7. 系统优化模块
# ==============================================================================

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
    [[ -n "$ip6" && "$ip6" != "未检测到" ]] && echo -e "IPv6 Upload: ${C_YELLOW}iperf3 -6 -c $ip6 -p $port${C_RESET}"
    [[ -n "$ip6" && "$ip6" != "未检测到" ]] && echo -e "IPv6 Download: ${C_YELLOW}iperf3 -6 -c $ip6 -p $port -R${C_RESET}"
    echo -e "${C_RED}按 Ctrl+C 停止测试...${C_RESET}"
    
    # 启动 iperf3 服务器
    iperf3 -s -p "$port" &
    local iperf_pid=$!
    
    # 标记是否已清理
    local cleaned=0
    
    # 清理函数
    cleanup_iperf() {
        [[ $cleaned -eq 1 ]] && return
        cleaned=1
        
        echo ""
        print_info "正在停止 iPerf3 服务..."
        
        # 杀死 iperf3 进程
        if [[ -n "$iperf_pid" ]] && kill -0 "$iperf_pid" 2>/dev/null; then
            kill "$iperf_pid" 2>/dev/null || true
            wait "$iperf_pid" 2>/dev/null || true
        fi
        
        # 清理可能残留的 iperf3 进程
        pkill -f "iperf3 -s -p $port" 2>/dev/null || true
        
        # 移除防火墙规则
        if [[ $ufw_opened -eq 1 ]]; then
            ufw delete allow "$port/tcp" >/dev/null 2>&1 || true
            print_info "防火墙规则已移除。"
        fi
        
        print_success "iPerf3 服务已停止。"
    }
    
    # 设置中断处理
    trap 'cleanup_iperf; trap - SIGINT SIGTERM' SIGINT SIGTERM
    
    # 等待 iperf3 进程
    wait $iperf_pid 2>/dev/null || true
    
    # 恢复默认中断处理
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

# 传递结果给调用者的全局变量
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
    ipv4=$(curl -4 -s --max-time 5 ifconfig.me 2>/dev/null) || ipv4=""
    ipv6=$(curl -6 -s --max-time 5 ifconfig.me 2>/dev/null) || ipv6=""

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
    
    # 询问是否开启 CDN 代理
    echo ""
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

    # DDNS 配置
    local ddns_v4=$([[ "$mode" == "1" || "$mode" == "3" ]] && echo "true" || echo "false")
    local ddns_v6=$([[ "$mode" == "2" || "$mode" == "3" ]] && echo "true" || echo "false")
    ddns_setup "$DOMAIN" "$CF_API_TOKEN" "$zone_id" "$ddns_v4" "$ddns_v6" "$proxied"

    # 传递结果给 web_add_domain
    _CF_RESULT_DOMAIN="$DOMAIN"
    _CF_RESULT_TOKEN="$CF_API_TOKEN"

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
        # 继承 DNS 配置中已输入的域名和 Token
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

        # ========== 在这里插入 DDNS 配置 ==========
        if [[ -n "$CF_API_TOKEN" ]] && [[ ! -f "$DDNS_CONFIG_DIR/${DOMAIN}.conf" ]]; then
            local zone_id="" current="$DOMAIN"
            while [[ "$current" == *"."* && -z "$zone_id" ]]; do
                zone_id=$(curl -s "https://api.cloudflare.com/client/v4/zones?name=$current" \
                    -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" | jq -r '.result[0].id // empty')
                current="${current#*.}"
            done
            
            if [[ -n "$zone_id" ]]; then
                local ddns_ipv4="false" ddns_ipv6="false"
                [[ -n "$(curl -4 -s --max-time 3 ifconfig.me 2>/dev/null)" ]] && ddns_ipv4="true"
                [[ -n "$(curl -6 -s --max-time 3 ifconfig.me 2>/dev/null)" ]] && ddns_ipv6="true"
                ddns_setup "$DOMAIN" "$CF_API_TOKEN" "$zone_id" "$ddns_ipv4" "$ddns_ipv6" "false"
            fi
        fi
        # ========== DDNS 配置结束 ==========
        
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
        print_title "Web 服务管理 (SSL + Nginx + DDNS)"
        
        # 状态显示
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
                shopt -s nullglob; for hook in /root/cert-renew-hook-*.sh; do [[ -x "$hook" ]] && bash "$hook"; done; shopt -u nullglob
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

# ==============================================================================
# 11. 主菜单
# ==============================================================================

show_main_menu() {
    fix_terminal
    clear
    
    # ========== 标题 ==========
    local W=76
    printf "${C_CYAN}%${W}s${C_RESET}\n" | tr ' ' '='
    printf "${C_CYAN}%*s${C_RESET}\n" $(((${#SCRIPT_NAME}+10+W)/2)) "$SCRIPT_NAME $VERSION"
    printf "${C_CYAN}%${W}s${C_RESET}\n" | tr ' ' '='
    
    # ========== 双栏系统信息 ==========
    show_dual_column_sysinfo
    
    printf "${C_CYAN}%${W}s${C_RESET}\n" | tr ' ' '='
    
    # ========== 功能菜单 ==========
    echo ""
    echo -e " ${C_CYAN}功能菜单${C_RESET}"
    echo ""
    printf " %-38s %-38s\n" "1. 基础依赖安装" "6. 网络工具 (DNS/测速)"
    printf " %-38s %-38s\n" "2. UFW 防火墙管理" "7. Web 服务 (SSL+Nginx)"
    printf " %-38s %-38s\n" "3. Fail2ban 入侵防御" "8. Docker 管理"
    printf " %-38s %-38s\n" "4. SSH 安全配置" "9. 查看操作日志"
    printf " %-38s %-38s\n" "5. 系统优化 (BBR/Swap)" "0. 退出脚本"
    echo ""
}

main() {
    check_root
    check_os
    init_environment
    refresh_ssh_port
    
    while true; do
        show_main_menu
        read -e -r -p "请选择功能 [0-9]: " choice
        
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
