#!/bin/bash

# ==============================================================================
# Let's Encrypt + Cloudflare + DDNS + Nginx 一键部署与管理脚本 V2.2
#
# 更新日志 (V2.2):
# - DDNS 功能变为可选 (首次设置时输入频率 0 可禁用)
# - 完成操作后返回主菜单，而不是退出脚本
# - 在“查看配置”功能中增加“删除域名配置”的选项
# - 修正 Nginx 配置检查逻辑，确保 sites-enabled 目录存在
# - 优化删除逻辑，使用 certbot delete 命令
#
# 功能:
# 1. 自动申请 Let's Encrypt 证书 (使用 Cloudflare DNS 验证)
# 2. 支持 IPv4 (A) / IPv6 (AAAA) 记录自动检测与添加/更新
# 3. 支持 DDNS (动态域名解析)，自动更新 Cloudflare 记录 (可选, 频率可自定义)
# 4. 自动配置 Nginx 反向代理 (可选, 支持 HTTP/HTTPS 后端)
# 5. 证书自动续期与部署 (通过 Cron)
# 6. 集中查看/删除已配置域名信息
# ==============================================================================

# --- 全局变量 ---
# 这些变量主要在首次设置流程中使用，并在需要时被函数覆盖
CF_API_TOKEN=""
DOMAIN=""
EMAIL=""
CERT_PATH_PREFIX="/root/cert"
CERT_PATH=""
CLOUDFLARE_CREDENTIALS=""
DEPLOY_HOOK_SCRIPT=""
DDNS_SCRIPT_PATH=""
DDNS_FREQUENCY=5 # 默认值，0 表示禁用
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
    echo -e "${RED}发生错误，脚本意外终止。${NC}"
    exit 1
}

# 错误处理陷阱
trap 'cleanup_and_exit' ERR SIGINT SIGTERM

# 检查命令是否存在
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 安装必要的包
install_packages() {
    echo -e "${BLUE}[*] 检查并安装必要的软件包...${NC}"
    PACKAGES_NEEDED="certbot python3-certbot-dns-cloudflare curl jq cron nginx openssl"
    PACKAGES_TO_INSTALL=""
    for pkg in $PACKAGES_NEEDED; do
        if ! dpkg -s $pkg &> /dev/null ; then
             PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL $pkg"
        fi
    done

    if [[ -n "$PACKAGES_TO_INSTALL" ]]; then
        echo "需要安装的包: $PACKAGES_TO_INSTALL"
        export DEBIAN_FRONTEND=noninteractive
        apt update -y
        apt install -y $PACKAGES_TO_INSTALL
    else
        echo -e "${GREEN}[✓] 所有必要的软件包已安装。${NC}"
    fi
     # 再次检查 Nginx (如果需要安装的话)
    if [[ "$INSTALL_NGINX" == "yes" ]] && ! command_exists nginx; then
        echo -e "${RED}[✗] Nginx 安装失败，请手动检查。${NC}"
        # 不退出，让用户知道问题，但可能后续 Nginx 操作会失败
    fi
}

# 获取用户输入 (首次设置)
get_user_input_initial() {
    # 重置可能影响本次设置的全局变量
    DOMAIN="" CF_API_TOKEN="" EMAIL="" DDNS_FREQUENCY=5 RECORD_TYPE="" SELECTED_IP="" ZONE_ID="" ZONE_NAME="" LOCAL_PROXY_PASS="" BACKEND_PROTOCOL="http"

    echo -e "${BLUE}[*] 请输入首次设置所需信息:${NC}"
    while [[ -z "$DOMAIN" ]]; do
        read -p "请输入您要申请/管理的域名 (例如 my.example.com): " DOMAIN
    done
    while [[ -z "$CF_API_TOKEN" ]]; do
        read -p "请输入您的 Cloudflare API Token: " CF_API_TOKEN
    done
     while [[ -z "$EMAIL" ]]; do
        read -p "请输入您的 Let's Encrypt 注册邮箱: " EMAIL
    done
    while true; do
        # 提示用户输入 0 可禁用 DDNS
        read -p "请输入 DDNS 自动更新频率 (分钟, 输入 0 禁用 DDNS, 默认 5): " freq_input
        if [[ -z "$freq_input" ]]; then
            DDNS_FREQUENCY=5
            echo -e "DDNS 更新频率设置为: ${GREEN}5 分钟${NC}"
            break
        elif [[ "$freq_input" =~ ^[0-9]+$ ]]; then # 允许输入 0
            DDNS_FREQUENCY=$freq_input
            if [[ "$DDNS_FREQUENCY" -eq 0 ]]; then
                 echo -e "${YELLOW}DDNS 功能已禁用。${NC}"
            else
                 echo -e "DDNS 更新频率设置为: ${GREEN}${DDNS_FREQUENCY} 分钟${NC}"
            fi
            break
        else
            echo -e "${YELLOW}请输入一个非负整数。${NC}"
        fi
    done

    # 更新相关路径变量 (根据域名)
    update_paths_for_domain "$DOMAIN"
}

# 根据域名更新相关路径变量
update_paths_for_domain() {
    local current_domain="$1"
    CERT_PATH="${CERT_PATH_PREFIX}/${current_domain}"
    CLOUDFLARE_CREDENTIALS="/root/.cloudflare-${current_domain}.ini"
    DEPLOY_HOOK_SCRIPT="/root/cert-renew-hook-${current_domain}.sh"
    DDNS_SCRIPT_PATH="/usr/local/bin/cf_ddns_update_${current_domain}.sh"
    NGINX_CONF_PATH="/etc/nginx/sites-available/${current_domain}.conf"
}


# 创建 Cloudflare 凭证文件
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

# 检测公网 IP 地址
detect_public_ip() {
    echo -e "${BLUE}[*] 检测公网 IP 地址...${NC}"
    DETECTED_IPV4=$(curl -4s --max-time 5 https://api.ipify.org || curl -4s --max-time 5 https://ifconfig.me/ip || echo "")
    DETECTED_IPV6=$(curl -6s --max-time 5 https://api64.ipify.org || curl -6s --max-time 5 https://ifconfig.me/ip || echo "")

    echo "检测结果:"
    if [[ -n "$DETECTED_IPV4" ]]; then echo -e "  - IPv4: ${GREEN}$DETECTED_IPV4${NC}"; else echo -e "  - IPv4: ${RED}未检测到${NC}"; fi
    if [[ -n "$DETECTED_IPV6" ]]; then echo -e "  - IPv6: ${GREEN}$DETECTED_IPV6${NC}"; else echo -e "  - IPv6: ${RED}未检测到${NC}"; fi

    if [[ -z "$DETECTED_IPV4" && -z "$DETECTED_IPV6" ]]; then
        echo -e "${RED}[✗] 无法检测到任何公网 IP 地址，请检查网络连接。${NC}"; exit 1;
    fi
}

# 选择 DNS 记录类型和 IP
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
    if [[ -z "$RECORD_TYPE" || -z "$SELECTED_IP" ]]; then echo -e "${RED}[✗] 未选择有效的记录类型或 IP 地址。${NC}"; exit 1; fi
}

# 获取 Cloudflare Zone ID
get_zone_id() {
    echo -e "${BLUE}[*] 获取 Cloudflare Zone ID...${NC}"
    ZONE_NAME=$(echo "$DOMAIN" | awk -F. '{if (NF>2) print $(NF-1)"."$NF; else print $0}')
    echo "尝试获取 Zone Name: $ZONE_NAME"
    ZONE_ID_JSON=$(curl -s --max-time 10 -X GET "$CF_API/zones?name=$ZONE_NAME&status=active" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json")
    if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API 失败。${NC}"; exit 1; fi
    if [[ $(echo "$ZONE_ID_JSON" | jq -r '.success') != "true" ]]; then
        echo -e "${RED}[✗] Cloudflare API 返回错误: $(echo "$ZONE_ID_JSON" | jq -r '.errors[0].message')${NC}"
        echo -e "${YELLOW}请检查 API Token 是否有效且具有 'Zone Read' 权限。${NC}"; exit 1;
    fi
    ZONE_ID=$(echo "$ZONE_ID_JSON" | jq -r '.result[0].id')
    if [[ "$ZONE_ID" == "null" || -z "$ZONE_ID" ]]; then
        echo -e "${RED}[✗] 无法找到域名 $ZONE_NAME 对应的活动 Zone ID。${NC}"; exit 1;
    fi
    echo -e "${GREEN}[✓] 找到 Zone ID: $ZONE_ID${NC}"
}

# 检查并创建/更新 Cloudflare DNS 记录
manage_cloudflare_record() {
    local action="$1"
    echo -e "${BLUE}[*] ${action} Cloudflare DNS 记录 ($RECORD_TYPE)...${NC}"
    echo "正在检查 $DOMAIN 的 $RECORD_TYPE 记录..."
    RECORD_INFO=$(curl -s --max-time 10 -X GET "$CF_API/zones/$ZONE_ID/dns_records?type=$RECORD_TYPE&name=$DOMAIN" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json")
    if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (获取记录) 失败。${NC}"; exit 1; fi
    if [[ $(echo "$RECORD_INFO" | jq -r '.success') != "true" ]]; then echo -e "${RED}[✗] Cloudflare API 返回错误 (获取记录): $(echo "$RECORD_INFO" | jq -r '.errors[0].message')${NC}"; exit 1; fi

    RECORD_ID=$(echo "$RECORD_INFO" | jq -r '.result[0].id')
    CURRENT_IP=$(echo "$RECORD_INFO" | jq -r '.result[0].content')

    if [[ "$RECORD_ID" == "null" || -z "$RECORD_ID" ]]; then
        echo "未找到 $RECORD_TYPE 记录，正在创建..."
        CREATE_RESULT=$(curl -s --max-time 10 -X POST "$CF_API/zones/$ZONE_ID/dns_records" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" --data "{\"type\":\"$RECORD_TYPE\",\"name\":\"$DOMAIN\",\"content\":\"$SELECTED_IP\",\"ttl\":120,\"proxied\":false}")
        if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (创建记录) 失败。${NC}"; exit 1; fi
        if [[ $(echo "$CREATE_RESULT" | jq -r '.success') == "true" ]]; then echo -e "${GREEN}[✓] $RECORD_TYPE 记录创建成功: $DOMAIN -> $SELECTED_IP${NC}";
        else echo -e "${RED}[✗] 创建 $RECORD_TYPE 记录失败: $(echo "$CREATE_RESULT" | jq -r '.errors[0].message')${NC}"; exit 1; fi
    else
        echo "找到 $RECORD_TYPE 记录 (ID: $RECORD_ID)，当前 IP: $CURRENT_IP"
        if [[ "$CURRENT_IP" != "$SELECTED_IP" ]]; then
            echo "IP 地址不匹配 ($CURRENT_IP != $SELECTED_IP)，正在更新..."
            UPDATE_RESULT=$(curl -s --max-time 10 -X PUT "$CF_API/zones/$ZONE_ID/dns_records/$RECORD_ID" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" --data "{\"type\":\"$RECORD_TYPE\",\"name\":\"$DOMAIN\",\"content\":\"$SELECTED_IP\",\"ttl\":120,\"proxied\":false}")
            if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (更新记录) 失败。${NC}"; exit 1; fi
            if [[ $(echo "$UPDATE_RESULT" | jq -r '.success') == "true" ]]; then echo -e "${GREEN}[✓] $RECORD_TYPE 记录更新成功: $DOMAIN -> $SELECTED_IP${NC}";
            else echo -e "${RED}[✗] 更新 $RECORD_TYPE 记录失败: $(echo "$UPDATE_RESULT" | jq -r '.errors[0].message')${NC}"; exit 1; fi
        else echo -e "${GREEN}[✓] $RECORD_TYPE 记录已是最新，无需更新。${NC}"; fi
    fi
}

# 申请 SSL 证书
request_certificate() {
    echo -e "${BLUE}[*] 申请 SSL 证书 (Let's Encrypt)...${NC}"
    certbot certonly --dns-cloudflare --dns-cloudflare-credentials "$CLOUDFLARE_CREDENTIALS" --dns-cloudflare-propagation-seconds 60 -d "$DOMAIN" --email "$EMAIL" --agree-tos --no-eff-email --non-interactive
    if [[ ! -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" || ! -f "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" ]]; then
        echo -e "${RED}[✗] 证书申请失败，请检查 /var/log/letsencrypt/letsencrypt.log 获取详细信息。${NC}"
        echo -e "${YELLOW}请确保 API Token 具有 Zone:Read 和 DNS:Edit 权限。${NC}"; exit 1;
    fi
    echo -e "${GREEN}[✓] SSL 证书申请成功！${NC}"
}

# 复制证书文件
copy_certificate() {
    echo -e "${BLUE}[*] 复制证书文件到 $CERT_PATH ...${NC}"
    mkdir -p "$CERT_PATH"
    cp -L "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$CERT_PATH/"
    cp -L "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$CERT_PATH/"
    cp -L "/etc/letsencrypt/live/${DOMAIN}/chain.pem" "$CERT_PATH/"
    cp -L "/etc/letsencrypt/live/${DOMAIN}/cert.pem" "$CERT_PATH/"
    echo -e "${GREEN}[✓] 证书文件已复制到 $CERT_PATH ${NC}"
}

# 配置 Nginx 反向代理
setup_nginx_proxy() {
    read -p "是否需要自动配置 Nginx 反向代理? (yes/no) [no]: " CONFIGURE_NGINX
    if [[ "$CONFIGURE_NGINX" != "yes" ]]; then echo "跳过 Nginx 配置。"; INSTALL_NGINX="no"; return; fi
    INSTALL_NGINX="yes"
    install_packages # 确保 Nginx 已安装

    while true; do
        read -p "您的后端服务 (${DOMAIN}) 使用 http 还是 https 协议? [http]: " proto_input
        if [[ -z "$proto_input" || "$proto_input" == "http" ]]; then BACKEND_PROTOCOL="http"; break;
        elif [[ "$proto_input" == "https" ]]; then BACKEND_PROTOCOL="https"; break;
        else echo -e "${YELLOW}请输入 'http' 或 'https'。${NC}"; fi
    done
    echo -e "后端服务协议设置为: ${GREEN}${BACKEND_PROTOCOL}${NC}"

    while [[ -z "$LOCAL_PROXY_PASS" ]]; do
        read -p "请输入 Nginx 需要反向代理的本地服务地址 (只需 IP/域名 和 端口, 例如 localhost:8080): " addr_input
        if [[ "$addr_input" =~ ^[a-zA-Z0-9.-]+:[0-9]+$ ]]; then
             LOCAL_PROXY_PASS="${BACKEND_PROTOCOL}://${addr_input}"
             echo -e "将使用代理地址: ${GREEN}${LOCAL_PROXY_PASS}${NC}"
        else echo -e "${YELLOW}地址格式似乎不正确，请输入 '主机名:端口' 或 'IP地址:端口'。${NC}"; LOCAL_PROXY_PASS=""; fi
    done

    echo -e "${BLUE}[*] 生成 Nginx 配置文件: $NGINX_CONF_PATH ...${NC}"
    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled # 确保目录存在

    cat > "$NGINX_CONF_PATH" <<EOF
server {
    listen 80; listen [::]:80; server_name ${DOMAIN};
    location / { return 301 https://\$host\$request_uri; }
    location ~ /.well-known/acme-challenge/ { allow all; root /var/www/html; }
}
server {
    listen 443 ssl http2; listen [::]:443 ssl http2; server_name ${DOMAIN};
    ssl_certificate ${CERT_PATH}/fullchain.pem; ssl_certificate_key ${CERT_PATH}/privkey.pem;
    ssl_session_timeout 1d; ssl_session_cache shared:SSL:10m; ssl_session_tickets off;
    ssl_protocols TLSv1.2 TLSv1.3; ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384; ssl_prefer_server_ciphers off;
    # add_header Strict-Transport-Security "max-age=63072000" always; # Optional HSTS
    location / {
        proxy_pass ${LOCAL_PROXY_PASS};
        proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto \$scheme;
        $( [[ "$BACKEND_PROTOCOL" == "https" ]] && echo 'proxy_ssl_server_name on;' )
        # $( [[ "$BACKEND_PROTOCOL" == "https" ]] && echo 'proxy_ssl_verify off;' ) # Uncomment if backend cert is untrusted
    }
}
EOF

    if [[ ! -L "/etc/nginx/sites-enabled/${DOMAIN}.conf" ]]; then
        ln -s "$NGINX_CONF_PATH" "/etc/nginx/sites-enabled/${DOMAIN}.conf"
        echo -e "${GREEN}[✓] Nginx 配置已启用。${NC}"
    else echo -e "${YELLOW}[!] Nginx 配置软链接已存在，未重新创建。${NC}"; fi

    echo -e "${BLUE}[*] 检查 Nginx 配置并尝试重载...${NC}"
    if nginx -t; then
        systemctl reload nginx
        echo -e "${GREEN}[✓] Nginx 配置检查通过并已重载。${NC}"
        echo -e "${YELLOW}提示：如果反代失败，请检查防火墙(80,443端口)、后端服务状态及 Nginx 错误日志。${NC}"
        if [[ "$BACKEND_PROTOCOL" == "https" ]]; then echo -e "${YELLOW}HTTPS 后端提示：如果后端证书不受信任，请在 Nginx 配置中取消注释 'proxy_ssl_verify off;' 并重载 Nginx。${NC}"; fi
    else echo -e "${RED}[✗] Nginx 配置检查失败！请手动检查 $NGINX_CONF_PATH 文件。${NC}"; exit 1; fi
}

# 创建 DDNS 更新脚本 (仅当 DDNS_FREQUENCY > 0)
create_ddns_script() {
    if [[ "$DDNS_FREQUENCY" -le 0 ]]; then echo "${YELLOW}DDNS 已禁用，跳过创建 DDNS 更新脚本。${NC}"; return; fi

    echo -e "${BLUE}[*] 创建 DDNS 更新脚本: $DDNS_SCRIPT_PATH ...${NC}"
    mkdir -p "$(dirname "$DDNS_SCRIPT_PATH")"
    local current_token=$(grep dns_cloudflare_api_token "$CLOUDFLARE_CREDENTIALS" | awk '{print $3}')

    cat > "$DDNS_SCRIPT_PATH" <<EOF
#!/bin/bash
# --- DDNS 更新脚本 for ${DOMAIN} (自动生成) ---
CF_CREDENTIALS_FILE="/root/.cloudflare-${DOMAIN}.ini"
DOMAIN="${DOMAIN}"
RECORD_TYPE="${RECORD_TYPE}"
ZONE_ID="${ZONE_ID}"
CF_API="https://api.cloudflare.com/client/v4"
LOG_FILE="/var/log/cf_ddns_update_${DOMAIN}.log"
CF_API_TOKEN=\$(grep dns_cloudflare_api_token "\$CF_CREDENTIALS_FILE" | awk '{print \$3}')
if [[ -z "\$CF_API_TOKEN" ]]; then echo "[\$(date)] Error: Could not read API Token" >> "\$LOG_FILE"; exit 1; fi
# echo "[\$(date)] --- DDNS Check for \$DOMAIN (\$RECORD_TYPE) ---" >> "\$LOG_FILE" # Verbose
CURRENT_IP=""
if [[ "\$RECORD_TYPE" == "A" ]]; then CURRENT_IP=\$(curl -4s --max-time 5 https://api.ipify.org || curl -4s --max-time 5 https://ifconfig.me/ip || echo "");
elif [[ "\$RECORD_TYPE" == "AAAA" ]]; then CURRENT_IP=\$(curl -6s --max-time 5 https://api64.ipify.org || curl -6s --max-time 5 https://ifconfig.me/ip || echo ""); fi
if [[ -z "\$CURRENT_IP" ]]; then echo "[\$(date)] Error: Failed get public IP (\$RECORD_TYPE)." >> "\$LOG_FILE"; exit 1; fi
RECORD_INFO=\$(curl -s --max-time 10 -X GET "\$CF_API/zones/\$ZONE_ID/dns_records?type=\$RECORD_TYPE&name=\$DOMAIN" -H "Authorization: Bearer \$CF_API_TOKEN" -H "Content-Type: application/json")
if [[ \$? -ne 0 || \$(echo "\$RECORD_INFO" | jq -r '.success') != "true" ]]; then echo "[\$(date)] Error: API error (get record): \$(echo "\$RECORD_INFO" | jq -r '.errors[0].message // "Connection failed")" >> "\$LOG_FILE"; exit 1; fi
CF_IP=\$(echo "\$RECORD_INFO" | jq -r '.result[0].content'); RECORD_ID=\$(echo "\$RECORD_INFO" | jq -r '.result[0].id')
if [[ -z "\$CF_IP" || "\$CF_IP" == "null" ]]; then echo "[\$(date)] Error: Failed get Cloudflare IP for \$DOMAIN (\$RECORD_TYPE)." >> "\$LOG_FILE"; exit 1; fi
if [[ "\$CURRENT_IP" != "\$CF_IP" ]]; then
    echo "[\$(date)] IP mismatch for \$DOMAIN. Current: \$CURRENT_IP, CF: \$CF_IP. Updating..." >> "\$LOG_FILE"
    UPDATE_RESULT=\$(curl -s --max-time 10 -X PUT "\$CF_API/zones/\$ZONE_ID/dns_records/\$RECORD_ID" -H "Authorization: Bearer \$CF_API_TOKEN" -H "Content-Type: application/json" --data "{\"type\":\"\$RECORD_TYPE\",\"name\":\"\$DOMAIN\",\"content\":\"\$CURRENT_IP\",\"ttl\":120,\"proxied\":false}")
    if [[ \$? -ne 0 || \$(echo "\$UPDATE_RESULT" | jq -r '.success') != "true" ]]; then echo "[\$(date)] Error: Failed update record: \$(echo "\$UPDATE_RESULT" | jq -r '.errors[0].message // "Connection failed")" >> "\$LOG_FILE"; exit 1;
    else echo "[\$(date)] Success: \$DOMAIN updated to \$CURRENT_IP" >> "\$LOG_FILE"; fi
# else echo "[\$(date)] IP match for \$DOMAIN." >> "\$LOG_FILE"; # Verbose
fi
exit 0
EOF
    chmod +x "$DDNS_SCRIPT_PATH"
    echo -e "${GREEN}[✓] DDNS 更新脚本创建成功: $DDNS_SCRIPT_PATH ${NC}"
}

# 设置自动任务 (证书续期和 DDNS)
setup_cron_jobs() {
    echo -e "${BLUE}[*] 设置 Cron 定时任务...${NC}"

    # 1. 创建证书续期后的部署钩子脚本
    echo -e "${BLUE}[*] 创建证书续期部署钩子脚本: $DEPLOY_HOOK_SCRIPT ...${NC}"
    mkdir -p "$(dirname "$DEPLOY_HOOK_SCRIPT")"
    cat > "$DEPLOY_HOOK_SCRIPT" <<EOF
#!/bin/bash
# Certbot 续期成功后执行的脚本 for ${DOMAIN}
LOG_FILE="/var/log/cert_renew_${DOMAIN}.log"
CERT_PATH="${CERT_PATH}"
NGINX_CONF_PATH="${NGINX_CONF_PATH}"
echo "[\$(date)] Cert renewed for ${DOMAIN}. Running deploy hook..." >> "\$LOG_FILE"
cp -L /etc/letsencrypt/live/${DOMAIN}/*.pem ${CERT_PATH}/ >> "\$LOG_FILE" 2>&1
if [[ \$? -ne 0 ]]; then echo "[\$(date)] Error: Failed copy certs." >> "\$LOG_FILE"; fi
if [[ -f "${NGINX_CONF_PATH}" ]]; then
    echo "[\$(date)] Reloading Nginx for ${DOMAIN}..." >> "\$LOG_FILE"
    nginx -t >> "\$LOG_FILE" 2>&1
    if [[ \$? -eq 0 ]]; then
        systemctl reload nginx >> "\$LOG_FILE" 2>&1
        if [[ \$? -eq 0 ]]; then echo "[\$(date)] Nginx reloaded." >> "\$LOG_FILE";
        else echo "[\$(date)] Error: Failed reload Nginx." >> "\$LOG_FILE"; fi
    else echo "[\$(date)] Error: Nginx conf test failed. Reload skipped." >> "\$LOG_FILE"; fi
fi
echo "[\$(date)] Deploy hook finished for ${DOMAIN}." >> "\$LOG_FILE"
exit 0
EOF
    chmod +x "$DEPLOY_HOOK_SCRIPT"
    echo -e "${GREEN}[✓] 证书续期部署钩子脚本创建成功: $DEPLOY_HOOK_SCRIPT ${NC}"

    # 2. 添加或更新 Cron 任务
    CRON_TAG_RENEW="# CertRenew_${DOMAIN}"
    CRON_TAG_DDNS="# DDNSUpdate_${DOMAIN}"
    # 先移除旧任务
    (crontab -l 2>/dev/null | grep -v -F "$CRON_TAG_RENEW" | grep -v -F "$CRON_TAG_DDNS") | crontab -
    # 添加新任务
    CRON_CONTENT=$(crontab -l 2>/dev/null)
    CRON_CERT_RENEW="0 3 * * * certbot renew --deploy-hook \"$DEPLOY_HOOK_SCRIPT\" >> /var/log/certbot_renew.log 2>&1 ${CRON_TAG_RENEW}"
    echo "${CRON_CONTENT}"$'\n'"${CRON_CERT_RENEW}" | crontab -
    echo -e "${GREEN}[✓] Cron 证书续期任务已设置 (${DOMAIN})。${NC}"

    if [[ "$DDNS_FREQUENCY" -gt 0 ]]; then
        CRON_DDNS_UPDATE="*/${DDNS_FREQUENCY} * * * * $DDNS_SCRIPT_PATH ${CRON_TAG_DDNS}"
        CRON_CONTENT=$(crontab -l 2>/dev/null) # 重新获取，包含上一步添加的续期任务
        echo "${CRON_CONTENT}"$'\n'"${CRON_DDNS_UPDATE}" | crontab -
        echo -e "${GREEN}[✓] Cron DDNS 更新任务已设置 (${DOMAIN}, 每 ${DDNS_FREQUENCY} 分钟)。${NC}"
    else
        echo -e "${YELLOW}DDNS 已禁用，未设置 Cron 更新任务 (${DOMAIN})。${NC}"
    fi

    echo -e "${CYAN}当前用户的 Cron 任务列表:${NC}"
    crontab -l
}

# 删除指定域名的配置
delete_domain_configuration() {
    local domain_to_delete="$1"
    echo -e "\n${RED}!!! 警告：此操作将删除域名 ${domain_to_delete} 的所有相关配置 !!!${NC}"
    echo "将执行以下操作:"
    echo "  - 使用 'certbot delete' 删除 Let's Encrypt 证书"
    echo "  - 删除本地证书副本目录: /root/cert/${domain_to_delete}"
    echo "  - 删除 Cloudflare 凭证文件: /root/.cloudflare-${domain_to_delete}.ini"
    echo "  - 删除 Nginx 配置文件和符号链接 (如果存在)"
    echo "  - 删除 DDNS 更新脚本 (如果存在)"
    echo "  - 从 Cron 中移除相关任务"
    echo -e "${RED}此操作不可恢复！${NC}"
    read -p "请再次确认是否删除 ${domain_to_delete} 的所有配置? (yes/no): " confirm_delete
    if [[ "$confirm_delete" != "yes" ]]; then
        echo "操作已取消。"
        return
    fi

    echo -e "${BLUE}[*] 开始删除域名 ${domain_to_delete} 的配置...${NC}"
    update_paths_for_domain "$domain_to_delete" # 更新路径变量以匹配要删除的域名

    # 1. 删除 Let's Encrypt 证书
    echo "正在删除 Let's Encrypt 证书..."
    if command_exists certbot; then
        certbot delete --cert-name "$domain_to_delete" --non-interactive || echo -e "${YELLOW}[!] Certbot 删除证书失败或证书不存在。${NC}"
    else
        echo -e "${YELLOW}[!] Certbot 命令未找到，无法删除 Let's Encrypt 证书。${NC}"
    fi

    # 2. 删除本地证书副本
    echo "正在删除本地证书副本目录 $CERT_PATH ..."
    if [[ -d "$CERT_PATH" ]]; then
        rm -rf "$CERT_PATH"
        echo -e "${GREEN}[✓] 本地证书副本已删除。${NC}"
    else
        echo -e "${YELLOW}[!] 本地证书副本目录未找到。${NC}"
    fi

    # 3. 删除 Cloudflare 凭证文件
    echo "正在删除 Cloudflare 凭证文件 $CLOUDFLARE_CREDENTIALS ..."
    if [[ -f "$CLOUDFLARE_CREDENTIALS" ]]; then
        rm -f "$CLOUDFLARE_CREDENTIALS"
        echo -e "${GREEN}[✓] Cloudflare 凭证文件已删除。${NC}"
    else
        echo -e "${YELLOW}[!] Cloudflare 凭证文件未找到。${NC}"
    fi

    # 4. 删除 Nginx 配置
    local nginx_conf_enabled="/etc/nginx/sites-enabled/${domain_to_delete}.conf"
    echo "正在删除 Nginx 配置 $NGINX_CONF_PATH 和 $nginx_conf_enabled ..."
    local nginx_removed=0
    if [[ -L "$nginx_conf_enabled" ]]; then
        rm -f "$nginx_conf_enabled"
        echo -e "${GREEN}[✓] Nginx 启用链接已删除。${NC}"
        nginx_removed=1
    else
        echo -e "${YELLOW}[!] Nginx 启用链接未找到。${NC}"
    fi
    if [[ -f "$NGINX_CONF_PATH" ]]; then
        rm -f "$NGINX_CONF_PATH"
        echo -e "${GREEN}[✓] Nginx 配置文件已删除。${NC}"
        nginx_removed=1
    else
        echo -e "${YELLOW}[!] Nginx 配置文件未找到。${NC}"
    fi
    # 如果删除了 Nginx 文件，尝试重载
    if [[ $nginx_removed -eq 1 ]] && command_exists nginx; then
        echo "正在尝试重载 Nginx..."
        if nginx -t; then
            systemctl reload nginx
            echo -e "${GREEN}[✓] Nginx 已重载。${NC}"
        else
            echo -e "${RED}[✗] Nginx 配置检查失败，可能需要手动处理。${NC}"
        fi
    fi

    # 5. 删除 DDNS 更新脚本
    echo "正在删除 DDNS 更新脚本 $DDNS_SCRIPT_PATH ..."
    if [[ -f "$DDNS_SCRIPT_PATH" ]]; then
        rm -f "$DDNS_SCRIPT_PATH"
        echo -e "${GREEN}[✓] DDNS 更新脚本已删除。${NC}"
    else
        echo -e "${YELLOW}[!] DDNS 更新脚本未找到。${NC}"
    fi

    # 6. 删除 Cron 任务
    echo "正在从 Cron 中移除相关任务..."
    CRON_TAG_RENEW="# CertRenew_${domain_to_delete}"
    CRON_TAG_DDNS="# DDNSUpdate_${domain_to_delete}"
    (crontab -l 2>/dev/null | grep -v -F "$CRON_TAG_RENEW" | grep -v -F "$CRON_TAG_DDNS") | crontab -
    echo -e "${GREEN}[✓] Cron 任务已移除。${NC}"

    echo -e "\n${GREEN}[✓] 域名 ${domain_to_delete} 的配置删除操作完成。${NC}"
}


# 查看所有配置并提供删除选项
view_all_configurations_and_manage() {
    echo -e "${BLUE}--- 扫描并显示所有检测到的配置 ---${NC}"
    local found_configs=0
    declare -a managed_domains # 存储找到的域名列表

    # 扫描证书目录来发现可能的域名
    if [[ -d "$CERT_PATH_PREFIX" ]]; then
        for domain_cert_dir in "$CERT_PATH_PREFIX"/*/; do
            local potential_domain=$(basename "$domain_cert_dir")
            if [[ -d "$domain_cert_dir" && "$potential_domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                managed_domains+=("$potential_domain") # 添加到数组
                ((found_configs++))
                echo -e "\n${CYAN}检测到域名 [${found_configs}]: ${potential_domain}${NC}"
                update_paths_for_domain "$potential_domain"

                # 1. 证书状态
                local cert_file="${CERT_PATH}/cert.pem"
                if [[ -f "$cert_file" ]]; then
                    local expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)
                    local expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null); local current_epoch=$(date +%s)
                    if [[ -n "$expiry_epoch" && "$expiry_epoch" -gt "$current_epoch" ]]; then echo -e "  - 证书状态: ${GREEN}有效${NC}, 到期: ${YELLOW}${expiry_date}${NC}";
                    elif [[ -n "$expiry_epoch" ]]; then echo -e "  - 证书状态: ${RED}已过期${NC} (${expiry_date})";
                    else echo -e "  - 证书状态: ${RED}无法解析${NC}"; fi
                else echo -e "  - 证书状态: ${RED}未找到 (${cert_file})${NC}"; fi

                # 2. Nginx 配置
                local nginx_enabled_link="/etc/nginx/sites-enabled/${potential_domain}.conf"
                if [[ -f "$NGINX_CONF_PATH" ]]; then
                    local proxy_pass_target=$(grep -oP 'proxy_pass\s+\K[^;]+' "$NGINX_CONF_PATH" | head -n 1)
                    local is_enabled=$( [[ -L "$nginx_enabled_link" ]] && echo "${GREEN}已启用${NC}" || echo "${YELLOW}未启用${NC}" )
                    echo -e "  - Nginx 配置: ${GREEN}找到${NC} ($is_enabled)"
                    if [[ -n "$proxy_pass_target" ]]; then echo -e "    - 反代目标: ${YELLOW}${proxy_pass_target}${NC}";
                    else echo -e "    - 反代目标: ${RED}未找到${NC}"; fi
                else echo -e "  - Nginx 配置: ${YELLOW}未找到${NC}"; fi

                # 3. DDNS 配置
                local cron_ddns_entry=$(crontab -l 2>/dev/null | grep -F "# DDNSUpdate_${potential_domain}")
                if [[ -f "$DDNS_SCRIPT_PATH" ]]; then
                     local ddns_record_type=$(grep 'RECORD_TYPE=' "$DDNS_SCRIPT_PATH" | head -n 1 | cut -d'"' -f2)
                     local cron_freq=$(echo "$cron_ddns_entry" | grep -oP '\*/\K[0-9]+' || echo "未知")
                     echo -e "  - DDNS 配置: ${GREEN}找到${NC}"
                     echo -e "    - 记录类型: ${YELLOW}${ddns_record_type:-未知}${NC}"
                     if [[ -n "$cron_ddns_entry" ]]; then echo -e "    - Cron 计划: ${GREEN}已设置${NC} (频率: ${YELLOW}${cron_freq} 分钟${NC})";
                     else echo -e "    - Cron 计划: ${RED}未找到${NC}"; fi
                elif [[ -n "$cron_ddns_entry" ]]; then # 只有 Cron 任务，脚本没了？
                     echo -e "  - DDNS 配置: ${YELLOW}仅找到 Cron 任务，脚本丢失?${NC}"
                else # 检查是否是因为设置为禁用 (频率为0)
                     # 需要一种方法来存储频率为0的信息，目前无法直接判断
                     # 假设如果脚本不存在且 Cron 任务不存在，则为禁用或未配置
                     echo -e "  - DDNS 配置: ${YELLOW}未找到或已禁用${NC}"
                fi

                # 4. 续期钩子和 Cron
                local cron_renew_entry=$(crontab -l 2>/dev/null | grep -F "# CertRenew_${potential_domain}")
                 if [[ -f "$DEPLOY_HOOK_SCRIPT" ]]; then
                     echo -e "  - 续期钩子: ${GREEN}找到${NC}"
                     if [[ -n "$cron_renew_entry" ]]; then echo -e "    - Cron 计划: ${GREEN}已设置${NC}";
                     else echo -e "    - Cron 计划: ${RED}未找到${NC}"; fi
                 else echo -e "  - 续期钩子: ${YELLOW}未找到${NC}"; fi

                 # 5. CF 凭证
                 if [[ -f "$CLOUDFLARE_CREDENTIALS" ]]; then echo -e "  - CF 凭证: ${GREEN}找到${NC}";
                 else echo -e "  - CF 凭证: ${YELLOW}未找到${NC}"; fi
            fi
        done
    fi

    if [[ $found_configs -eq 0 ]]; then
        echo -e "${YELLOW}未在 $CERT_PATH_PREFIX 下检测到任何由脚本管理的域名配置。${NC}"
        echo -e "${YELLOW}此功能依赖于 $CERT_PATH_PREFIX/<域名>/ 目录结构。${NC}"
        echo -e "\n${BLUE}--- 扫描结束 ---${NC}"
        return # 没有找到配置，直接返回
    fi
     echo -e "\n${BLUE}--- 扫描结束 ---${NC}"

    # 询问是否删除
    read -p "是否要删除以上列出的某个域名的配置? (yes/no) [no]: " wanna_delete
    if [[ "$wanna_delete" == "yes" ]]; then
        read -p "请输入要删除配置的域名 (从上面列表中选择): " domain_to_delete_input
        # 检查输入的域名是否在找到的列表中
        local domain_valid=0
        for d in "${managed_domains[@]}"; do
            if [[ "$d" == "$domain_to_delete_input" ]]; then
                domain_valid=1
                break
            fi
        done

        if [[ $domain_valid -eq 1 ]]; then
            delete_domain_configuration "$domain_to_delete_input"
        else
            echo -e "${RED}输入的域名 '$domain_to_delete_input' 不在检测到的列表中或无效。${NC}"
        fi
    fi
    # 提示修改功能未实现
    echo -e "${YELLOW}提示：目前不支持修改现有配置，如需修改，请考虑删除后重新设置。${NC}"
}


# --- 主逻辑循环 ---
while true; do
    echo -e "\n${GREEN}=== Let's Encrypt + Cloudflare + DDNS + Nginx 部署脚本 V2.2 ===${NC}"
    echo "请选择操作:"
    echo "1. 首次设置新域名 (申请证书, 配置 DDNS, Nginx)"
    echo "2. 手动触发一次 DDNS 更新检查"
    echo "3. 强制续期证书 (谨慎使用!)"
    echo "4. 查看/删除已配置域名信息"
    echo "5. 退出脚本"

    read -p "请输入选项 [1-5]: " main_choice

    case $main_choice in
        1)
            # --- 首次设置流程 ---
            get_user_input_initial
            install_packages
            create_cf_credentials
            detect_public_ip
            select_record_type
            get_zone_id
            manage_cloudflare_record "create"
            request_certificate
            copy_certificate
            setup_nginx_proxy
            # DDNS 脚本和 Cron 任务现在根据 DDNS_FREQUENCY 决定是否创建
            create_ddns_script
            setup_cron_jobs
            echo -e "\n${GREEN}[✓] 域名 ${DOMAIN} 的首次设置完成！${NC}"
            echo "按 Enter 返回主菜单..."
            read -r
            ;;
        2)
            # --- 手动更新 DDNS ---
            read -p "请输入您想手动触发 DDNS 更新的域名: " DOMAIN_FOR_DDNS
            update_paths_for_domain "$DOMAIN_FOR_DDNS"
            if [[ -f "$DDNS_SCRIPT_PATH" ]]; then
                echo "正在手动执行 DDNS 更新脚本: $DDNS_SCRIPT_PATH"
                bash "$DDNS_SCRIPT_PATH"
                echo "DDNS 更新检查完成，请查看日志 /var/log/cf_ddns_update_${DOMAIN_FOR_DDNS}.log"
            else
                echo -e "${RED}[✗] 未找到域名 ${DOMAIN_FOR_DDNS} 的 DDNS 更新脚本 ($DDNS_SCRIPT_PATH)。可能该域名未启用 DDNS 或未完成首次设置。${NC}"
            fi
            echo "按 Enter 返回主菜单..."
            read -r
            ;;
        3)
            # --- 强制续期 ---
            read -p "请输入要强制续期的域名: " DOMAIN_FOR_RENEW
            update_paths_for_domain "$DOMAIN_FOR_RENEW"

            echo -e "${YELLOW}警告：强制续期受 Let's Encrypt 频率限制。过度使用可能导致域名被暂时封禁。${NC}"
            read -p "确认要强制续期 ${DOMAIN_FOR_RENEW} 吗? (yes/no) [no]: " confirm_force_renew
            if [[ "$confirm_force_renew" == "yes" ]]; then
                local cf_creds_renew="/root/.cloudflare-${DOMAIN_FOR_RENEW}.ini"
                local deploy_hook_renew="/root/cert-renew-hook-${DOMAIN_FOR_RENEW}.sh"
                local deploy_hook_arg=""
                if [[ ! -f "$cf_creds_renew" ]]; then
                     echo -e "${RED}[✗] 未找到 Cloudflare 凭证文件 $cf_creds_renew。${NC}"
                else
                    if [[ -f "$deploy_hook_renew" ]]; then
                        deploy_hook_arg="--deploy-hook \"$deploy_hook_renew\""
                    else
                         echo -e "${YELLOW}[!] 未找到部署钩子脚本 $deploy_hook_renew，续期后可能无法自动部署。${NC}"
                    fi
                    echo "正在尝试为 $DOMAIN_FOR_RENEW 强制续期证书..."
                    certbot certonly --dns-cloudflare --dns-cloudflare-credentials "$cf_creds_renew" --dns-cloudflare-propagation-seconds 60 -d "$DOMAIN_FOR_RENEW" --force-renewal --non-interactive $deploy_hook_arg
                    echo "强制续期尝试完成。请检查 Certbot 输出和日志。"
                fi
            else
                echo "操作取消。"
            fi
            echo "按 Enter 返回主菜单..."
            read -r
            ;;
        4)
            # --- 查看/删除配置 ---
            install_packages # 确保 openssl 等工具已安装
            view_all_configurations_and_manage # 调用新的集成函数
            echo "按 Enter 返回主菜单..."
            read -r
            ;;
        5)
            echo "退出脚本。"
            exit 0 # 退出循环和脚本
            ;;
        *)
            echo -e "${RED}无效选项。${NC}"
            echo "按 Enter 返回主菜单..."
            read -r
            ;;
    esac
done

exit 0 # 理论上不会执行到这里，因为循环由选项 5 退出
