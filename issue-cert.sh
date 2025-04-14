#!/bin/bash

# ==============================================================================
# Let's Encrypt + Cloudflare + DDNS + Nginx 一键部署与管理脚本 V2.1
#
# 更新日志 (V2.1):
# - 修复 Nginx 反代 HTTPS 后端的问题 (增加后端协议选择)
# - 增加 DDNS 更新频率自定义选项 (首次设置时)
# - 增强“查看配置”功能，尝试列出所有已配置域名信息
# - 增加强制续期操作的警告
# - 优化部分提示信息
#
# 功能:
# 1. 自动申请 Let's Encrypt 证书 (使用 Cloudflare DNS 验证)
# 2. 支持 IPv4 (A) / IPv6 (AAAA) 记录自动检测与添加/更新
# 3. 支持 DDNS (动态域名解析)，自动更新 Cloudflare 记录 (频率可自定义)
# 4. 自动配置 Nginx 反向代理 (可选, 支持 HTTP/HTTPS 后端)
# 5. 证书自动续期与部署 (通过 Cron)
# 6. 集中查看已配置域名信息
# ==============================================================================

# --- 全局变量 ---
CF_API_TOKEN=""
DOMAIN=""
EMAIL="" # Let's Encrypt 注册邮箱
CERT_PATH_PREFIX="/root/cert" # 证书存放目录前缀
CERT_PATH="" # 完整的证书存放路径
CLOUDFLARE_CREDENTIALS="" # CF 凭证文件路径
DEPLOY_HOOK_SCRIPT="" # 续期部署脚本路径
DDNS_SCRIPT_PATH="" # DDNS 更新脚本路径 (根据域名变化)
DDNS_FREQUENCY=5 # DDNS 更新频率 (分钟)
RECORD_TYPE="" # DNS 记录类型 (A 或 AAAA)
DETECTED_IPV4=""
DETECTED_IPV6=""
SELECTED_IP=""
ZONE_ID=""
ZONE_NAME=""
CF_API="https://api.cloudflare.com/client/v4"
NGINX_CONF_PATH="" # Nginx 配置文件路径
LOCAL_PROXY_PASS="" # Nginx 反代目标地址
BACKEND_PROTOCOL="http" # Nginx 反代后端协议 (http/https)

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- 函数定义 ---

# 清理并退出
cleanup_and_exit() {
    echo -e "${RED}发生错误，脚本终止。${NC}"
    # 可选：添加清理逻辑
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
    # 检查 openssl 是否存在，用于读取证书信息
    PACKAGES_NEEDED="certbot python3-certbot-dns-cloudflare curl jq cron nginx openssl"
    PACKAGES_TO_INSTALL=""
    for pkg in $PACKAGES_NEEDED; do
        # 使用 dpkg 检查包是否已安装，比 command_exists 更可靠
        if ! dpkg -s $pkg &> /dev/null ; then
             # 如果包不存在，则添加到安装列表
             PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL $pkg"
        fi
    done

    if [[ -n "$PACKAGES_TO_INSTALL" ]]; then
        echo "需要安装的包: $PACKAGES_TO_INSTALL"
        # 非交互式安装，避免卡住
        export DEBIAN_FRONTEND=noninteractive
        apt update -y
        apt install -y $PACKAGES_TO_INSTALL
    else
        echo -e "${GREEN}[✓] 所有必要的软件包已安装。${NC}"
    fi
     # 再次检查 Nginx 是否安装成功（如果需要）
    if [[ "$INSTALL_NGINX" == "yes" ]] && ! command_exists nginx; then
        echo -e "${RED}[✗] Nginx 安装失败，请手动检查。${NC}"
        exit 1
    fi
}

# 获取用户输入 (首次设置)
get_user_input_initial() {
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
        read -p "请输入 DDNS 自动更新频率 (分钟, 默认 5): " freq_input
        if [[ -z "$freq_input" ]]; then
            DDNS_FREQUENCY=5
            break
        elif [[ "$freq_input" =~ ^[1-9][0-9]*$ ]]; then
            DDNS_FREQUENCY=$freq_input
            break
        else
            echo -e "${YELLOW}请输入一个正整数。${NC}"
        fi
    done
    echo -e "DDNS 更新频率设置为: ${GREEN}${DDNS_FREQUENCY} 分钟${NC}"

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
    if [[ -n "$DETECTED_IPV4" ]]; then
        echo -e "  - IPv4: ${GREEN}$DETECTED_IPV4${NC}"
    else
        echo -e "  - IPv4: ${RED}未检测到${NC}"
    fi
    if [[ -n "$DETECTED_IPV6" ]]; then
        echo -e "  - IPv6: ${GREEN}$DETECTED_IPV6${NC}"
    else
        echo -e "  - IPv6: ${RED}未检测到${NC}"
    fi

    if [[ -z "$DETECTED_IPV4" && -z "$DETECTED_IPV6" ]]; then
        echo -e "${RED}[✗] 无法检测到任何公网 IP 地址，请检查网络连接。${NC}"
        exit 1
    fi
}

# 选择 DNS 记录类型和 IP
select_record_type() {
    echo -e "${BLUE}[*] 请选择要使用的 DNS 记录类型和 IP 地址:${NC}"
    options=()
    ips=()
    types=()
    if [[ -n "$DETECTED_IPV4" ]]; then
        options+=("IPv4 (A 记录) - ${DETECTED_IPV4}")
        ips+=("$DETECTED_IPV4")
        types+=("A")
    fi
    if [[ -n "$DETECTED_IPV6" ]]; then
        options+=("IPv6 (AAAA 记录) - ${DETECTED_IPV6}")
        ips+=("$DETECTED_IPV6")
        types+=("AAAA")
    fi
    options+=("退出")

    select opt in "${options[@]}"; do
        # $REPLY 是 select 命令存储用户选择数字的变量
        choice_index=$((REPLY - 1))

        if [[ "$opt" == "退出" ]]; then
             echo "用户选择退出。"
             exit 0
        elif [[ $choice_index -ge 0 && $choice_index -lt ${#ips[@]} ]]; then
             RECORD_TYPE=${types[$choice_index]}
             SELECTED_IP=${ips[$choice_index]}
             echo -e "已选择: ${GREEN}${RECORD_TYPE} - $SELECTED_IP${NC}"
             break
        else
             echo "无效选项 $REPLY"
        fi
    done

    if [[ -z "$RECORD_TYPE" || -z "$SELECTED_IP" ]]; then
        echo -e "${RED}[✗] 未选择有效的记录类型或 IP 地址。${NC}"
        exit 1
    fi
}

# 获取 Cloudflare Zone ID
get_zone_id() {
    echo -e "${BLUE}[*] 获取 Cloudflare Zone ID...${NC}"
    # 提取根域名 (e.g., example.com from my.example.com)
    ZONE_NAME=$(echo "$DOMAIN" | awk -F. '{if (NF>2) print $(NF-1)"."$NF; else print $0}')
    echo "尝试获取 Zone Name: $ZONE_NAME"

    # 增加超时时间并处理可能的错误
    ZONE_ID_JSON=$(curl -s --max-time 10 -X GET "$CF_API/zones?name=$ZONE_NAME&status=active" \
         -H "Authorization: Bearer $CF_API_TOKEN" \
         -H "Content-Type: application/json")

    # 检查 curl 是否成功执行
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[✗] 调用 Cloudflare API 失败，请检查网络连接或 API 端点。${NC}"
        exit 1
    fi

    # 检查 API 返回是否成功
    if [[ $(echo "$ZONE_ID_JSON" | jq -r '.success') != "true" ]]; then
        error_message=$(echo "$ZONE_ID_JSON" | jq -r '.errors[0].message')
        echo -e "${RED}[✗] Cloudflare API 返回错误: ${error_message}${NC}"
        echo -e "${YELLOW}请检查 API Token 是否有效且具有 'Zone Read' 权限。${NC}"
        exit 1
    fi

    ZONE_ID=$(echo "$ZONE_ID_JSON" | jq -r '.result[0].id')

    if [[ "$ZONE_ID" == "null" || -z "$ZONE_ID" ]]; then
        echo -e "${RED}[✗] 无法找到域名 $ZONE_NAME 对应的活动 Zone ID。请检查域名拼写、Cloudflare 账户以及 API Token 权限。${NC}"
        exit 1
    fi
    echo -e "${GREEN}[✓] 找到 Zone ID: $ZONE_ID${NC}"
}

# 检查并创建/更新 Cloudflare DNS 记录
manage_cloudflare_record() {
    local action="$1" # "create" or "update"
    echo -e "${BLUE}[*] ${action} Cloudflare DNS 记录 ($RECORD_TYPE)...${NC}"

    # 检查记录是否存在
    echo "正在检查 $DOMAIN 的 $RECORD_TYPE 记录..."
    RECORD_INFO=$(curl -s --max-time 10 -X GET "$CF_API/zones/$ZONE_ID/dns_records?type=$RECORD_TYPE&name=$DOMAIN" \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json")

    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[✗] 调用 Cloudflare API (获取记录) 失败。${NC}"
        exit 1
    fi

    if [[ $(echo "$RECORD_INFO" | jq -r '.success') != "true" ]]; then
        error_message=$(echo "$RECORD_INFO" | jq -r '.errors[0].message')
        echo -e "${RED}[✗] Cloudflare API 返回错误 (获取记录): ${error_message}${NC}"
        exit 1
    fi

    RECORD_ID=$(echo "$RECORD_INFO" | jq -r '.result[0].id')
    CURRENT_IP=$(echo "$RECORD_INFO" | jq -r '.result[0].content')

    if [[ "$RECORD_ID" == "null" || -z "$RECORD_ID" ]]; then
        # 记录不存在，创建
        echo "未找到 $RECORD_TYPE 记录，正在创建..."
        CREATE_RESULT=$(curl -s --max-time 10 -X POST "$CF_API/zones/$ZONE_ID/dns_records" \
            -H "Authorization: Bearer $CF_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"$RECORD_TYPE\",\"name\":\"$DOMAIN\",\"content\":\"$SELECTED_IP\",\"ttl\":120,\"proxied\":false}") # ttl=120 (2 minutes), proxied=false for Let's Encrypt validation initially

        if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (创建记录) 失败。${NC}"; exit 1; fi

        if [[ $(echo "$CREATE_RESULT" | jq -r '.success') == "true" ]]; then
            echo -e "${GREEN}[✓] $RECORD_TYPE 记录创建成功: $DOMAIN -> $SELECTED_IP${NC}"
        else
            echo -e "${RED}[✗] 创建 $RECORD_TYPE 记录失败: $(echo "$CREATE_RESULT" | jq -r '.errors[0].message')${NC}"
            exit 1
        fi
    else
        # 记录存在，检查是否需要更新
        echo "找到 $RECORD_TYPE 记录 (ID: $RECORD_ID)，当前 IP: $CURRENT_IP"
        if [[ "$CURRENT_IP" != "$SELECTED_IP" ]]; then
            echo "IP 地址不匹配 ($CURRENT_IP != $SELECTED_IP)，正在更新..."
            UPDATE_RESULT=$(curl -s --max-time 10 -X PUT "$CF_API/zones/$ZONE_ID/dns_records/$RECORD_ID" \
                -H "Authorization: Bearer $CF_API_TOKEN" \
                -H "Content-Type: application/json" \
                --data "{\"type\":\"$RECORD_TYPE\",\"name\":\"$DOMAIN\",\"content\":\"$SELECTED_IP\",\"ttl\":120,\"proxied\":false}")

            if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (更新记录) 失败。${NC}"; exit 1; fi

            if [[ $(echo "$UPDATE_RESULT" | jq -r '.success') == "true" ]]; then
                echo -e "${GREEN}[✓] $RECORD_TYPE 记录更新成功: $DOMAIN -> $SELECTED_IP${NC}"
            else
                echo -e "${RED}[✗] 更新 $RECORD_TYPE 记录失败: $(echo "$UPDATE_RESULT" | jq -r '.errors[0].message')${NC}"
                exit 1
            fi
        else
            echo -e "${GREEN}[✓] $RECORD_TYPE 记录已是最新，无需更新。${NC}"
        fi
    fi
}

# 申请 SSL 证书
request_certificate() {
    echo -e "${BLUE}[*] 申请 SSL 证书 (Let's Encrypt)...${NC}"
    # 增加 DNS 传播等待时间至 60 秒
    certbot certonly --dns-cloudflare \
      --dns-cloudflare-credentials "$CLOUDFLARE_CREDENTIALS" \
      --dns-cloudflare-propagation-seconds 60 \
      -d "$DOMAIN" \
      --email "$EMAIL" \
      --agree-tos \
      --no-eff-email \
      --non-interactive

    # 检查证书文件是否存在
    if [[ ! -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" || ! -f "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" ]]; then
        echo -e "${RED}[✗] 证书申请失败，请检查 /var/log/letsencrypt/letsencrypt.log 获取详细信息。${NC}"
        echo -e "${YELLOW}可能的原因包括：API Token 权限不足 (需要 Zone:Read 和 DNS:Edit)、Cloudflare 防火墙规则干扰、DNS 记录未正确传播等。${NC}"
        exit 1
    fi
    echo -e "${GREEN}[✓] SSL 证书申请成功！${NC}"
}

# 复制证书文件
copy_certificate() {
    echo -e "${BLUE}[*] 复制证书文件到 $CERT_PATH ...${NC}"
    mkdir -p "$CERT_PATH"
    cp -L "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$CERT_PATH/" # 使用 -L 复制链接指向的实际文件
    cp -L "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$CERT_PATH/"
    cp -L "/etc/letsencrypt/live/${DOMAIN}/chain.pem" "$CERT_PATH/"
    cp -L "/etc/letsencrypt/live/${DOMAIN}/cert.pem" "$CERT_PATH/"
    echo -e "${GREEN}[✓] 证书文件已复制到 $CERT_PATH ${NC}"
}

# 配置 Nginx 反向代理
setup_nginx_proxy() {
    read -p "是否需要自动配置 Nginx 反向代理? (yes/no) [no]: " CONFIGURE_NGINX
    if [[ "$CONFIGURE_NGINX" != "yes" ]]; then
        echo "跳过 Nginx 配置。"
        INSTALL_NGINX="no" # 标记不需要强制安装 Nginx
        return
    fi
    INSTALL_NGINX="yes" # 标记需要检查并安装 Nginx

    # 确保 Nginx 已安装 (install_packages 会处理)
    install_packages

    # 询问后端服务协议
    while true; do
        read -p "您的后端服务 (${DOMAIN}) 使用 http 还是 https 协议? [http]: " proto_input
        if [[ -z "$proto_input" || "$proto_input" == "http" ]]; then
            BACKEND_PROTOCOL="http"
            break
        elif [[ "$proto_input" == "https" ]]; then
            BACKEND_PROTOCOL="https"
            break
        else
            echo -e "${YELLOW}请输入 'http' 或 'https'。${NC}"
        fi
    done
    echo -e "后端服务协议设置为: ${GREEN}${BACKEND_PROTOCOL}${NC}"

    # 获取后端服务地址
    while [[ -z "$LOCAL_PROXY_PASS" ]]; do
        # 提供更清晰的示例，并强调协议部分由上一步决定
        read -p "请输入 Nginx 需要反向代理的本地服务地址 (只需 IP/域名 和 端口, 例如 localhost:8080 或 127.0.0.1:3000): " addr_input
        # 简单验证格式 (IP:Port 或 Domain:Port)
        if [[ "$addr_input" =~ ^[a-zA-Z0-9.-]+:[0-9]+$ ]]; then
             # 拼接协议和地址
            LOCAL_PROXY_PASS="${BACKEND_PROTOCOL}://${addr_input}"
            echo -e "将使用代理地址: ${GREEN}${LOCAL_PROXY_PASS}${NC}"
        else
            echo -e "${YELLOW}地址格式似乎不正确，请输入 '主机名:端口' 或 'IP地址:端口'。${NC}"
            LOCAL_PROXY_PASS=""
        fi
    done

    echo -e "${BLUE}[*] 生成 Nginx 配置文件: $NGINX_CONF_PATH ...${NC}"

    # 创建 Nginx 配置目录（如果不存在）
    mkdir -p /etc/nginx/sites-available
    mkdir -p /etc/nginx/sites-enabled

    # 生成 Nginx 配置内容
    cat > "$NGINX_CONF_PATH" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    # HTTP 到 HTTPS 跳转
    location / {
        return 301 https://\$host\$request_uri;
    }

    # Certbot ACME Challenge (如果使用 http-01 验证)
    location ~ /.well-known/acme-challenge/ {
        allow all;
        root /var/www/html; # 或者 Certbot 使用的其他路径
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};

    # SSL 证书配置 (使用复制后的路径)
    ssl_certificate ${CERT_PATH}/fullchain.pem;
    ssl_certificate_key ${CERT_PATH}/privkey.pem;

    # SSL 推荐配置 (可根据需要调整)
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # HSTS (可选, 测试后取消注释)
    # add_header Strict-Transport-Security "max-age=63072000" always;

    # OCSP Stapling (可选)
    # ssl_stapling on;
    # ssl_stapling_verify on;
    # ssl_trusted_certificate ${CERT_PATH}/chain.pem;
    # resolver 8.8.8.8 8.8.4.4 valid=300s;
    # resolver_timeout 5s;

    # 反向代理配置
    location / {
        proxy_pass ${LOCAL_PROXY_PASS}; # 使用包含协议的完整地址
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme; # 告知后端是 https

        # 如果后端是 HTTPS，可能需要以下配置
        $( [[ "$BACKEND_PROTOCOL" == "https" ]] && echo 'proxy_ssl_server_name on;' ) # 传递 SNI
        # $( [[ "$BACKEND_PROTOCOL" == "https" ]] && echo 'proxy_ssl_verify off;' ) # 如果后端证书不受信任，取消注释此行 (降低安全性)

        # WebSocket support (optional)
        # proxy_http_version 1.1;
        # proxy_set_header Upgrade \$http_upgrade;
        # proxy_set_header Connection "upgrade";
    }
}
EOF

    # 创建软链接启用配置
    if [[ ! -L "/etc/nginx/sites-enabled/${DOMAIN}.conf" ]]; then
        ln -s "$NGINX_CONF_PATH" "/etc/nginx/sites-enabled/${DOMAIN}.conf"
        echo -e "${GREEN}[✓] Nginx 配置已启用。${NC}"
    else
        echo -e "${YELLOW}[!] Nginx 配置软链接已存在，未重新创建。${NC}"
    fi

    # 检查 Nginx 配置并重载
    echo -e "${BLUE}[*] 检查 Nginx 配置并尝试重载...${NC}"
    if nginx -t; then
        systemctl reload nginx
        echo -e "${GREEN}[✓] Nginx 配置检查通过并已重载。${NC}"
        echo -e "${YELLOW}如果反代仍然失败，请检查:${NC}"
        echo -e "${YELLOW}  1. 防火墙是否放行 80 和 443 端口。${NC}"
        echo -e "${YELLOW}  2. 后端服务 (${LOCAL_PROXY_PASS}) 是否正常运行。${NC}"
        echo -e "${YELLOW}  3. Nginx 错误日志 (/var/log/nginx/error.log)。${NC}"
        if [[ "$BACKEND_PROTOCOL" == "https" ]]; then
             echo -e "${YELLOW}  4. (HTTPS 后端) 如果后端证书是自签名或不受信任，请尝试在 Nginx 配置中取消注释 'proxy_ssl_verify off;' 并重载 Nginx。${NC}"
        fi
    else
        echo -e "${RED}[✗] Nginx 配置检查失败！请手动检查 $NGINX_CONF_PATH 文件。${NC}"
        # 可以选择移除错误的软链接
        # rm "/etc/nginx/sites-enabled/${DOMAIN}.conf"
        exit 1
    fi
}

# 创建 DDNS 更新脚本
create_ddns_script() {
    echo -e "${BLUE}[*] 创建 DDNS 更新脚本: $DDNS_SCRIPT_PATH ...${NC}"
    # 确保目录存在
    mkdir -p "$(dirname "$DDNS_SCRIPT_PATH")"
    # 从 CLOUDFLARE_CREDENTIALS 文件中读取 Token，避免直接写入脚本
    local current_token=$(grep dns_cloudflare_api_token "$CLOUDFLARE_CREDENTIALS" | awk '{print $3}')

    cat > "$DDNS_SCRIPT_PATH" <<EOF
#!/bin/bash

# --- DDNS 更新脚本 for ${DOMAIN} ---
# 注意：此脚本由主脚本自动生成，请勿直接修改 Token 等敏感信息。
# 如需修改 Token，请重新运行主脚本或编辑 /root/.cloudflare-${DOMAIN}.ini 文件。

CF_CREDENTIALS_FILE="/root/.cloudflare-${DOMAIN}.ini"
DOMAIN="${DOMAIN}"
RECORD_TYPE="${RECORD_TYPE}" # 使用首次设置时选择的记录类型
ZONE_ID="${ZONE_ID}" # 从主脚本获取
CF_API="https://api.cloudflare.com/client/v4"
LOG_FILE="/var/log/cf_ddns_update_${DOMAIN}.log"

# 从凭证文件读取 Token
CF_API_TOKEN=\$(grep dns_cloudflare_api_token "\$CF_CREDENTIALS_FILE" | awk '{print \$3}')

if [[ -z "\$CF_API_TOKEN" ]]; then
    echo "[\$(date)] Error: Could not read API Token from \$CF_CREDENTIALS_FILE" >> "\$LOG_FILE"
    exit 1
fi

echo "[\$(date)] --- DDNS Update Check for \$DOMAIN (\$RECORD_TYPE) ---" >> "\$LOG_FILE"

# 获取当前公网 IP
CURRENT_IP=""
if [[ "\$RECORD_TYPE" == "A" ]]; then
    CURRENT_IP=\$(curl -4s --max-time 5 https://api.ipify.org || curl -4s --max-time 5 https://ifconfig.me/ip || echo "")
elif [[ "\$RECORD_TYPE" == "AAAA" ]]; then
    CURRENT_IP=\$(curl -6s --max-time 5 https://api64.ipify.org || curl -6s --max-time 5 https://ifconfig.me/ip || echo "")
fi

if [[ -z "\$CURRENT_IP" ]]; then
    echo "[\$(date)] Error: Failed to get current public IP (\$RECORD_TYPE)." >> "\$LOG_FILE"
    exit 1
fi
# echo "[\$(date)] Current Public IP (\$RECORD_TYPE): \$CURRENT_IP" >> "\$LOG_FILE" # 减少日志噪音

# 获取 Cloudflare 上的 DNS 记录 IP
RECORD_INFO=\$(curl -s --max-time 10 -X GET "\$CF_API/zones/\$ZONE_ID/dns_records?type=\$RECORD_TYPE&name=\$DOMAIN" \
    -H "Authorization: Bearer \$CF_API_TOKEN" \
    -H "Content-Type: application/json")

if [[ \$? -ne 0 ]]; then echo "[\$(date)] Error: API call failed (get record)." >> "\$LOG_FILE"; exit 1; fi
if [[ \$(echo "\$RECORD_INFO" | jq -r '.success') != "true" ]]; then echo "[\$(date)] Error: API error (get record): \$(echo "\$RECORD_INFO" | jq -r '.errors[0].message')" >> "\$LOG_FILE"; exit 1; fi

CF_IP=\$(echo "\$RECORD_INFO" | jq -r '.result[0].content')
RECORD_ID=\$(echo "\$RECORD_INFO" | jq -r '.result[0].id')

# echo "[\$(date)] Cloudflare IP (\$RECORD_TYPE for \$DOMAIN): \$CF_IP" >> "\$LOG_FILE" # 减少日志噪音

if [[ -z "\$CF_IP" || "\$CF_IP" == "null" ]]; then
    echo "[\$(date)] Error: Failed to get Cloudflare IP for \$DOMAIN (\$RECORD_TYPE). Record might not exist." >> "\$LOG_FILE"
    # Optionally, try to create the record here if it doesn't exist
    exit 1
fi

# 比较 IP 并更新
if [[ "\$CURRENT_IP" != "\$CF_IP" ]]; then
    echo "[\$(date)] IP mismatch for \$DOMAIN. Current: \$CURRENT_IP, Cloudflare: \$CF_IP. Updating..." >> "\$LOG_FILE"
    UPDATE_RESULT=\$(curl -s --max-time 10 -X PUT "\$CF_API/zones/\$ZONE_ID/dns_records/\$RECORD_ID" \
        -H "Authorization: Bearer \$CF_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"type\":\"\$RECORD_TYPE\",\"name\":\"\$DOMAIN\",\"content\":\"\$CURRENT_IP\",\"ttl\":120,\"proxied\":false}") # Keep proxied status consistent or make it configurable

    if [[ \$? -ne 0 ]]; then echo "[\$(date)] Error: API call failed (update record)." >> "\$LOG_FILE"; exit 1; fi

    if [[ \$(echo "\$UPDATE_RESULT" | jq -r '.success') == "true" ]]; then
        echo "[\$(date)] Success: Cloudflare DNS record for \$DOMAIN updated to \$CURRENT_IP" >> "\$LOG_FILE"
    else
        ERROR_MSG=\$(echo "\$UPDATE_RESULT" | jq -r '.errors[0].message')
        echo "[\$(date)] Error: Failed to update Cloudflare DNS record for \$DOMAIN: \$ERROR_MSG" >> "\$LOG_FILE"
        exit 1
    fi
else
    # echo "[\$(date)] IP addresses match for \$DOMAIN. No update needed." >> "\$LOG_FILE" # 减少日志噪音
    : # No operation needed, just exit quietly
fi

# echo "[\$(date)] --- DDNS Update Check Complete for \$DOMAIN ---" >> "\$LOG_FILE" # 减少日志噪音
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
CERT_PATH="${CERT_PATH}" # 从主脚本获取
NGINX_CONF_PATH="${NGINX_CONF_PATH}" # 从主脚本获取

echo "[\$(date)] Cert renewed for ${DOMAIN}. Running deploy hook..." >> "\$LOG_FILE"

# 复制更新后的证书文件 (使用 -L 确保复制的是实际文件)
cp -L /etc/letsencrypt/live/${DOMAIN}/*.pem ${CERT_PATH}/ >> "\$LOG_FILE" 2>&1
if [[ \$? -ne 0 ]]; then
    echo "[\$(date)] Error: Failed to copy renewed certificates to ${CERT_PATH}." >> "\$LOG_FILE"
fi

# 如果配置了 Nginx，则重载 Nginx
if [[ -f "${NGINX_CONF_PATH}" ]]; then
    echo "[\$(date)] Reloading Nginx for ${DOMAIN}..." >> "\$LOG_FILE"
    # 检查 Nginx 配置语法
    nginx -t >> "\$LOG_FILE" 2>&1
    if [[ \$? -eq 0 ]]; then
        # 语法正确，重载 Nginx
        systemctl reload nginx >> "\$LOG_FILE" 2>&1
        if [[ \$? -eq 0 ]]; then
            echo "[\$(date)] Nginx reloaded successfully for ${DOMAIN}." >> "\$LOG_FILE"
        else
            echo "[\$(date)] Error: Failed to reload Nginx for ${DOMAIN}." >> "\$LOG_FILE"
        fi
    else
        # 语法错误，不重载
        echo "[\$(date)] Error: Nginx configuration test failed after cert renewal for ${DOMAIN}. Reload skipped." >> "\$LOG_FILE"
    fi
fi

# 添加其他需要执行的命令，例如重启其他服务
# systemctl restart your_service

echo "[\$(date)] Deploy hook finished for ${DOMAIN}." >> "\$LOG_FILE"
exit 0
EOF
    chmod +x "$DEPLOY_HOOK_SCRIPT"
    echo -e "${GREEN}[✓] 证书续期部署钩子脚本创建成功: $DEPLOY_HOOK_SCRIPT ${NC}"


    # 2. 添加或更新 Cron 任务
    # 使用特定注释标记，方便查找和删除
    CRON_TAG_RENEW="# CertRenew_${DOMAIN}"
    CRON_TAG_DDNS="# DDNSUpdate_${DOMAIN}"
    CRON_CERT_RENEW="0 3 * * * certbot renew --deploy-hook \"$DEPLOY_HOOK_SCRIPT\" >> /var/log/certbot_renew.log 2>&1 ${CRON_TAG_RENEW}"
    CRON_DDNS_UPDATE="*/${DDNS_FREQUENCY} * * * * $DDNS_SCRIPT_PATH ${CRON_TAG_DDNS}" # 使用自定义频率

    # 移除旧的相同标记的任务（如果存在）
    (crontab -l 2>/dev/null | grep -v -F "$CRON_TAG_RENEW" | grep -v -F "$CRON_TAG_DDNS") | crontab -

    # 添加新任务
    (crontab -l 2>/dev/null; echo "$CRON_CERT_RENEW"; echo "$CRON_DDNS_UPDATE") | crontab -

    echo -e "${GREEN}[✓] Cron 定时任务设置完成:${NC}"
    echo "  - 证书自动续期检查 (${DOMAIN}): 每天凌晨 3 点"
    echo "  - DDNS 自动更新 (${DOMAIN}): 每 ${DDNS_FREQUENCY} 分钟检查一次"
    echo -e "${CYAN}当前用户的 Cron 任务列表:${NC}"
    crontab -l # 显示当前用户的 crontab
}

# 查看所有配置
view_all_configurations() {
    echo -e "${BLUE}--- 扫描并显示所有检测到的配置 ---${NC}"
    local found_configs=0

    # 扫描证书目录来发现可能的域名
    if [[ -d "$CERT_PATH_PREFIX" ]]; then
        for domain_cert_dir in "$CERT_PATH_PREFIX"/*/; do
            # 提取域名
            local potential_domain=$(basename "$domain_cert_dir")
            # 简单的域名格式验证 (可能不够完美)
            if [[ "$potential_domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                echo -e "\n${CYAN}检测到域名: ${potential_domain}${NC}"
                ((found_configs++))

                # 更新路径以便查找相关文件
                update_paths_for_domain "$potential_domain"

                # 1. 检查证书状态
                local cert_file="${CERT_PATH}/cert.pem"
                if [[ -f "$cert_file" ]]; then
                    local expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)
                    local expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null)
                    local current_epoch=$(date +%s)
                    if [[ -n "$expiry_epoch" && "$expiry_epoch" -gt "$current_epoch" ]]; then
                        echo -e "  - 证书状态: ${GREEN}有效${NC}, 到期时间: ${YELLOW}${expiry_date}${NC}"
                    elif [[ -n "$expiry_epoch" ]]; then
                         echo -e "  - 证书状态: ${RED}已过期${NC} (${expiry_date})"
                    else
                         echo -e "  - 证书状态: ${RED}无法解析到期时间${NC}"
                    fi
                else
                    echo -e "  - 证书状态: ${RED}未找到证书文件 (${cert_file})${NC}"
                fi

                # 2. 检查 Nginx 配置
                if [[ -f "$NGINX_CONF_PATH" ]]; then
                    local proxy_pass_target=$(grep -oP 'proxy_pass\s+\K[^;]+' "$NGINX_CONF_PATH" | head -n 1)
                    local is_enabled=$( [[ -L "/etc/nginx/sites-enabled/${potential_domain}.conf" ]] && echo "${GREEN}已启用${NC}" || echo "${YELLOW}未启用${NC}" )
                    echo -e "  - Nginx 配置: ${GREEN}找到${NC} (${NGINX_CONF_PATH}), 状态: $is_enabled"
                    if [[ -n "$proxy_pass_target" ]]; then
                        echo -e "    - 反代目标: ${YELLOW}${proxy_pass_target}${NC}"
                    else
                        echo -e "    - 反代目标: ${RED}未在配置中找到 proxy_pass${NC}"
                    fi
                else
                    echo -e "  - Nginx 配置: ${YELLOW}未找到${NC} (${NGINX_CONF_PATH})"
                fi

                # 3. 检查 DDNS 配置
                if [[ -f "$DDNS_SCRIPT_PATH" ]]; then
                     local ddns_record_type=$(grep 'RECORD_TYPE=' "$DDNS_SCRIPT_PATH" | head -n 1 | cut -d'"' -f2)
                     local cron_ddns_entry=$(crontab -l 2>/dev/null | grep -F "# DDNSUpdate_${potential_domain}")
                     local cron_freq=$(echo "$cron_ddns_entry" | grep -oP '\*/\K[0-9]+' || echo "未知")
                     echo -e "  - DDNS 配置: ${GREEN}找到${NC} (${DDNS_SCRIPT_PATH})"
                     echo -e "    - 记录类型: ${YELLOW}${ddns_record_type:-未知}${NC}"
                     if [[ -n "$cron_ddns_entry" ]]; then
                        echo -e "    - Cron 计划: ${GREEN}已设置${NC} (频率: ${YELLOW}${cron_freq} 分钟${NC})"
                     else
                        echo -e "    - Cron 计划: ${RED}未找到${NC}"
                     fi
                else
                    echo -e "  - DDNS 配置: ${YELLOW}未找到${NC} (${DDNS_SCRIPT_PATH})"
                fi

                # 4. 检查证书续期钩子和 Cron
                 if [[ -f "$DEPLOY_HOOK_SCRIPT" ]]; then
                     local cron_renew_entry=$(crontab -l 2>/dev/null | grep -F "# CertRenew_${potential_domain}")
                     echo -e "  - 续期钩子: ${GREEN}找到${NC} (${DEPLOY_HOOK_SCRIPT})"
                     if [[ -n "$cron_renew_entry" ]]; then
                         echo -e "    - Cron 计划: ${GREEN}已设置${NC} (每日凌晨 3 点)"
                     else
                         echo -e "    - Cron 计划: ${RED}未找到${NC}"
                     fi
                 else
                     echo -e "  - 续期钩子: ${YELLOW}未找到${NC} (${DEPLOY_HOOK_SCRIPT})"
                 fi

                 # 5. 检查 CF 凭证文件
                 if [[ -f "$CLOUDFLARE_CREDENTIALS" ]]; then
                      echo -e "  - CF 凭证: ${GREEN}找到${NC} (${CLOUDFLARE_CREDENTIALS})"
                 else
                      echo -e "  - CF 凭证: ${YELLOW}未找到${NC} (${CLOUDFLARE_CREDENTIALS})"
                 fi

            fi
        done
    fi

    if [[ $found_configs -eq 0 ]]; then
        echo -e "${YELLOW}未在 $CERT_PATH_PREFIX 下检测到任何由脚本管理的域名配置。${NC}"
        echo -e "${YELLOW}此功能依赖于 $CERT_PATH_PREFIX/<域名>/ 目录结构。${NC}"
    fi
     echo -e "\n${BLUE}--- 扫描结束 ---${NC}"
}


# --- 主逻辑 ---

echo -e "${GREEN}=== Let's Encrypt + Cloudflare + DDNS + Nginx 部署脚本 V2.1 ===${NC}"
echo "请选择操作:"
echo "1. 首次设置新域名 (申请证书, 配置 DDNS, Nginx)"
echo "2. 手动触发一次 DDNS 更新检查"
echo "3. 强制续期证书 (谨慎使用!)"
echo "4. 查看所有已配置域名信息"
echo "5. 退出"

read -p "请输入选项 [1-5]: " main_choice

case $main_choice in
    1)
        # --- 首次设置流程 ---
        get_user_input_initial # 获取域名、Token、邮箱、DDNS频率
        install_packages # 先安装基础包
        create_cf_credentials # 使用当前 DOMAIN 和 CF_API_TOKEN
        detect_public_ip
        select_record_type # 选择 A 或 AAAA
        get_zone_id # 获取 Zone ID
        manage_cloudflare_record "create" # 尝试创建或更新记录
        request_certificate # 申请证书
        copy_certificate # 复制证书
        setup_nginx_proxy # Nginx 配置（可选）
        create_ddns_script # 创建 DDNS 脚本 (使用当前全局变量)
        setup_cron_jobs # 设置定时任务 (使用当前全局变量)
        # show_configuration # 单个域名的配置已在流程中显示，这里不再重复
        echo -e "\n${GREEN}[✓] 域名 ${DOMAIN} 的首次设置完成！证书、DDNS 和 Nginx（如果选择）已配置。${NC}"
        ;;
    2)
        # --- 手动更新 DDNS ---
        read -p "请输入您想手动触发 DDNS 更新的域名: " DOMAIN_FOR_DDNS
        update_paths_for_domain "$DOMAIN_FOR_DDNS" # 设置脚本路径变量
        if [[ -f "$DDNS_SCRIPT_PATH" ]]; then
            echo "正在手动执行 DDNS 更新脚本: $DDNS_SCRIPT_PATH"
            bash "$DDNS_SCRIPT_PATH"
            echo "DDNS 更新检查完成，请查看日志 /var/log/cf_ddns_update_${DOMAIN_FOR_DDNS}.log"
        else
            echo -e "${RED}[✗] 未找到域名 ${DOMAIN_FOR_DDNS} 的 DDNS 更新脚本 ($DDNS_SCRIPT_PATH)。请先完成首次设置。${NC}"
        fi
        ;;
    3)
        # --- 强制续期 ---
        read -p "请输入要强制续期的域名: " DOMAIN_FOR_RENEW
        update_paths_for_domain "$DOMAIN_FOR_RENEW" # 设置钩子脚本路径

        echo -e "${YELLOW}警告：强制续期受 Let's Encrypt 频率限制 (每个注册域名每周 5 次)。${NC}"
        echo -e "${YELLOW}       过度使用可能导致您的账户或域名被暂时阻止申请证书。${NC}"
        read -p "确认要强制续期 ${DOMAIN_FOR_RENEW} 吗? (yes/no) [no]: " confirm_force_renew
        if [[ "$confirm_force_renew" != "yes" ]]; then
            echo "操作取消。"
            exit 0
        fi

        # 检查钩子脚本是否存在
        if [[ ! -f "$DEPLOY_HOOK_SCRIPT" ]]; then
             echo -e "${YELLOW}[!] 未找到部署钩子脚本 $DEPLOY_HOOK_SCRIPT，续期后可能无法自动部署 (例如复制证书、重载 Nginx)。是否继续? (yes/no) [yes]: ${NC}"
             read -r continue_renew_no_hook
             if [[ "$continue_renew_no_hook" == "no" ]]; then
                 echo "操作取消。"
                 exit 0
             fi
             DEPLOY_HOOK_ARG="" # 不使用钩子
        else
             DEPLOY_HOOK_ARG="--deploy-hook \"$DEPLOY_HOOK_SCRIPT\""
        fi

        echo "正在尝试为 $DOMAIN_FOR_RENEW 强制续期证书..."
        # 注意：需要传递正确的凭证文件给 certbot
        local cf_creds_renew="/root/.cloudflare-${DOMAIN_FOR_RENEW}.ini"
        if [[ ! -f "$cf_creds_renew" ]]; then
             echo -e "${RED}[✗] 未找到 Cloudflare 凭证文件 $cf_creds_renew，无法进行 DNS 验证。${NC}"
             exit 1
        fi
        # 使用 certonly --force-renewal
        certbot certonly --dns-cloudflare \
            --dns-cloudflare-credentials "$cf_creds_renew" \
            --dns-cloudflare-propagation-seconds 60 \
            -d "$DOMAIN_FOR_RENEW" \
            --force-renewal \
            --non-interactive \
            $DEPLOY_HOOK_ARG # 传递钩子参数

        # certbot renew --force-renewal -d "$DOMAIN_FOR_RENEW" $DEPLOY_HOOK_ARG # renew 命令可能行为不同
        echo "强制续期尝试完成。请检查 Certbot 输出和日志 /var/log/letsencrypt/letsencrypt.log。"
        ;;
    4)
        # --- 查看所有配置 ---
        install_packages # 确保 openssl 等工具已安装
        view_all_configurations
        ;;
    5)
        echo "退出脚本。"
        exit 0
        ;;
    *)
        echo -e "${RED}无效选项。${NC}"
        exit 1
        ;;
esac

exit 0
