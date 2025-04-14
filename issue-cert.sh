#!/bin/bash

# ==============================================================================
# Let's Encrypt + Cloudflare + DDNS + Nginx 一键部署与管理脚本 V2.6
#
# 更新日志 (V2.6):
# - [修复] 再次修正 Nginx HTTP 跳转逻辑，通过在 Bash 中预处理端口后缀，彻底避免在 Nginx 配置中使用 'if' 指令，解决 'invalid condition' 错误。
# - 优化后端协议选择，使用数字 1 (http) / 2 (https)
# - 优化域名删除选择，使用数字序号
# - 将 Let's Encrypt 注册邮箱固定为 'your@mail.com'
# - 添加 Nginx 监听端口自定义功能 (HTTP/HTTPS)
#
# 功能:
# 1. 自动申请 Let's Encrypt 证书 (使用 Cloudflare DNS 验证)
# 2. 支持 IPv4 (A) / IPv6 (AAAA) 记录自动检测与添加/更新
# 3. 支持 DDNS (动态域名解析)，自动更新 Cloudflare 记录 (可选, 频率可自定义)
# 4. 自动配置 Nginx 反向代理 (可选, 支持自定义端口, HTTP/HTTPS 后端, 默认启用 HTTP/2 和 HSTS)
# 5. 证书自动续期与部署 (通过 Cron)
# 6. 集中查看/删除已配置域名信息 (通过序号选择删除)
# ==============================================================================

# --- 全局变量 ---
# Cloudflare API Token (需要用户输入)
CF_API_TOKEN=""
# 要管理的域名 (需要用户输入)
DOMAIN=""
# Let's Encrypt 注册邮箱 (固定值, 不再提示用户输入)
EMAIL="your@mail.com"
# 证书存放路径前缀
CERT_PATH_PREFIX="/root/cert"
# 具体域名的证书存放路径 (动态生成)
CERT_PATH=""
# Cloudflare 凭证文件路径 (动态生成)
CLOUDFLARE_CREDENTIALS=""
# Certbot 部署钩子脚本路径 (动态生成)
DEPLOY_HOOK_SCRIPT=""
# DDNS 更新脚本路径 (动态生成)
DDNS_SCRIPT_PATH=""
# DDNS 更新频率 (分钟), 0 表示禁用 (需要用户输入或使用默认值)
DDNS_FREQUENCY=5 # 默认值，0 表示禁用
# DNS 记录类型 (A 或 AAAA, 自动检测后选择)
RECORD_TYPE=""
# 检测到的 IPv4 地址
DETECTED_IPV4=""
# 检测到的 IPv6 地址
DETECTED_IPV6=""
# 用户选择的 IP 地址
SELECTED_IP=""
# Cloudflare Zone ID (自动获取)
ZONE_ID=""
# Cloudflare Zone Name (从域名推断)
ZONE_NAME=""
# Cloudflare API 地址
CF_API="https://api.cloudflare.com/client/v4"
# Nginx 配置文件路径 (动态生成)
NGINX_CONF_PATH=""
# Nginx 反向代理的本地目标地址 (需要用户输入)
LOCAL_PROXY_PASS=""
# 后端服务使用的协议 (http 或 https, 需要用户输入)
BACKEND_PROTOCOL="http"
# 是否需要安装 Nginx
INSTALL_NGINX="no"
# Nginx HTTP 监听端口 (可自定义)
NGINX_HTTP_PORT=80
# Nginx HTTPS 监听端口 (可自定义)
NGINX_HTTPS_PORT=443


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
    # 基础包 + Cloudflare DNS 插件 + Nginx (如果需要)
    PACKAGES_NEEDED="certbot python3-certbot-dns-cloudflare curl jq cron openssl"
    # 只有当用户选择配置 Nginx 时才添加 nginx 到检查列表
    if [[ "$INSTALL_NGINX" == "yes" ]]; then
        PACKAGES_NEEDED="$PACKAGES_NEEDED nginx"
    fi

    PACKAGES_TO_INSTALL=""
    for pkg in $PACKAGES_NEEDED; do
        # 使用 dpkg 检查包是否已安装
        if ! dpkg -s $pkg &> /dev/null ; then
             PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL $pkg"
        fi
    done

    if [[ -n "$PACKAGES_TO_INSTALL" ]]; then
        echo "需要安装的包: $PACKAGES_TO_INSTALL"
        # 设置为非交互模式，避免安装过程中需要确认
        export DEBIAN_FRONTEND=noninteractive
        apt update -y
        apt install -y $PACKAGES_TO_INSTALL
    else
        echo -e "${GREEN}[✓] 所有必要的软件包已安装。${NC}"
    fi

    # 再次检查 Nginx (如果需要安装的话)
    if [[ "$INSTALL_NGINX" == "yes" ]] && ! command_exists nginx; then
        echo -e "${RED}[✗] Nginx 安装失败，请手动检查。${NC}"
        # 这里可以选择退出脚本或继续，取决于策略
        # exit 1
    fi
}

# 获取用户输入 (首次设置)
get_user_input_initial() {
    # 重置可能影响本次设置的全局变量 (EMAIL 除外)
    DOMAIN="" CF_API_TOKEN="" DDNS_FREQUENCY=5 RECORD_TYPE="" SELECTED_IP="" ZONE_ID="" ZONE_NAME="" LOCAL_PROXY_PASS="" BACKEND_PROTOCOL="http" INSTALL_NGINX="no" NGINX_HTTP_PORT=80 NGINX_HTTPS_PORT=443

    echo -e "${BLUE}[*] 请输入首次设置所需信息:${NC}"
    echo -e "${YELLOW}Let's Encrypt 注册邮箱已固定为: ${EMAIL}${NC}" # 提示用户邮箱已固定
    while [[ -z "$DOMAIN" ]]; do read -p "请输入您要申请/管理的域名 (例如 my.example.com): " DOMAIN; done
    # 校验域名格式 (简单校验)
    if ! [[ "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}[✗] 域名格式似乎不正确。${NC}"; exit 1;
    fi
    while [[ -z "$CF_API_TOKEN" ]]; do read -p "请输入您的 Cloudflare API Token: " CF_API_TOKEN; done
    # 不再提示输入邮箱
    while true; do
        read -p "请输入 DDNS 自动更新频率 (分钟, 输入 0 禁用 DDNS, 默认 5): " freq_input
        if [[ -z "$freq_input" ]]; then DDNS_FREQUENCY=5; echo -e "DDNS 更新频率设置为: ${GREEN}5 分钟${NC}"; break;
        elif [[ "$freq_input" =~ ^[0-9]+$ ]]; then
            DDNS_FREQUENCY=$freq_input
            if [[ "$DDNS_FREQUENCY" -eq 0 ]]; then echo -e "${YELLOW}DDNS 功能已禁用。${NC}"; else echo -e "DDNS 更新频率设置为: ${GREEN}${DDNS_FREQUENCY} 分钟${NC}"; fi; break;
        else echo -e "${YELLOW}请输入一个非负整数。${NC}"; fi
    done
    # 更新基于域名的路径变量
    update_paths_for_domain "$DOMAIN"
}

# 根据域名更新相关路径变量
update_paths_for_domain() {
    local current_domain="$1"
    # 证书存放路径
    CERT_PATH="${CERT_PATH_PREFIX}/${current_domain}"
    # Cloudflare 凭证文件
    CLOUDFLARE_CREDENTIALS="/root/.cloudflare-${current_domain}.ini"
    # 证书续期钩子脚本
    DEPLOY_HOOK_SCRIPT="/root/cert-renew-hook-${current_domain}.sh"
    # DDNS 更新脚本
    DDNS_SCRIPT_PATH="/usr/local/bin/cf_ddns_update_${current_domain}.sh"
    # Nginx 配置文件
    NGINX_CONF_PATH="/etc/nginx/sites-available/${current_domain}.conf"
}


# 创建 Cloudflare 凭证文件
create_cf_credentials() {
    echo -e "${BLUE}[*] 创建 Cloudflare API 凭证文件...${NC}"
    # 确保目录存在
    mkdir -p "$(dirname "$CLOUDFLARE_CREDENTIALS")"
    # 写入凭证信息
    cat > "$CLOUDFLARE_CREDENTIALS" <<EOF
# Cloudflare API credentials used by Certbot for domain: ${DOMAIN}
dns_cloudflare_api_token = $CF_API_TOKEN
EOF
    # 设置文件权限为 600，仅所有者可读写
    chmod 600 "$CLOUDFLARE_CREDENTIALS"
    echo -e "${GREEN}[✓] 凭证文件创建成功: ${CLOUDFLARE_CREDENTIALS}${NC}"
}

# 检测公网 IP 地址
detect_public_ip() {
    echo -e "${BLUE}[*] 检测公网 IP 地址...${NC}"
    # 尝试多个源获取 IPv4 地址，设置超时时间
    DETECTED_IPV4=$(curl -4s --max-time 5 https://api.ipify.org || curl -4s --max-time 5 https://ifconfig.me/ip || echo "")
    # 尝试多个源获取 IPv6 地址，设置超时时间
    DETECTED_IPV6=$(curl -6s --max-time 5 https://api64.ipify.org || curl -6s --max-time 5 https://ifconfig.me/ip || echo "")
    echo "检测结果:"
    if [[ -n "$DETECTED_IPV4" ]]; then echo -e "  - IPv4: ${GREEN}$DETECTED_IPV4${NC}"; else echo -e "  - IPv4: ${RED}未检测到${NC}"; fi
    if [[ -n "$DETECTED_IPV6" ]]; then echo -e "  - IPv6: ${GREEN}$DETECTED_IPV6${NC}"; else echo -e "  - IPv6: ${RED}未检测到${NC}"; fi
    # 如果 IPv4 和 IPv6 都没检测到，则报错退出
    if [[ -z "$DETECTED_IPV4" && -z "$DETECTED_IPV6" ]]; then echo -e "${RED}[✗] 无法检测到任何公网 IP 地址。脚本无法继续。${NC}"; exit 1; fi
}

# 选择 DNS 记录类型和 IP
select_record_type() {
    echo -e "${BLUE}[*] 请选择要使用的 DNS 记录类型和 IP 地址:${NC}"
    options=() ips=() types=()
    # 如果检测到 IPv4，添加到选项
    if [[ -n "$DETECTED_IPV4" ]]; then options+=("IPv4 (A 记录) - ${DETECTED_IPV4}"); ips+=("$DETECTED_IPV4"); types+=("A"); fi
    # 如果检测到 IPv6，添加到选项
    if [[ -n "$DETECTED_IPV6" ]]; then options+=("IPv6 (AAAA 记录) - ${DETECTED_IPV6}"); ips+=("$DETECTED_IPV6"); types+=("AAAA"); fi
    options+=("退出")

    # 使用 select 让用户选择
    select opt in "${options[@]}"; do
        choice_index=$((REPLY - 1)) # REPLY 是 select 命令内置变量，表示用户输入的序号
        if [[ "$opt" == "退出" ]]; then echo "用户选择退出。"; exit 0;
        # 检查用户选择是否在有效范围内
        elif [[ $choice_index -ge 0 && $choice_index -lt ${#ips[@]} ]]; then
            RECORD_TYPE=${types[$choice_index]}; SELECTED_IP=${ips[$choice_index]}
            echo -e "已选择: ${GREEN}${RECORD_TYPE} - $SELECTED_IP${NC}"; break # 选择成功，跳出循环
        else echo "无效选项 $REPLY"; fi
    done
    # 如果循环结束还没有选择有效的类型或 IP，则退出
    if [[ -z "$RECORD_TYPE" || -z "$SELECTED_IP" ]]; then echo -e "${RED}[✗] 未选择有效的记录类型或 IP 地址。脚本无法继续。${NC}"; exit 1; fi
}

# 获取 Cloudflare Zone ID
get_zone_id() {
    echo -e "${BLUE}[*] 获取 Cloudflare Zone ID...${NC}"
    # 从完整域名中提取 Zone Name (通常是最后两部分，例如 a.b.c.com -> b.c.com)
    # 注意：对于 com.cn 这类域名，此方法可能不准确，但对大多数常见域名有效
    ZONE_NAME=$(echo "$DOMAIN" | awk -F. '{if (NF>2) print $(NF-1)"."$NF; else print $0}')
    echo "尝试获取 Zone Name: $ZONE_NAME"

    # 调用 Cloudflare API 获取 Zone 信息
    ZONE_ID_JSON=$(curl -s --max-time 10 -X GET "$CF_API/zones?name=$ZONE_NAME&status=active" \
         -H "Authorization: Bearer $CF_API_TOKEN" \
         -H "Content-Type: application/json")

    # 检查 curl 命令是否执行成功
    if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API 失败 (网络错误或超时)。${NC}"; exit 1; fi

    # 使用 jq 解析 JSON，检查 API 调用是否成功
    if [[ $(echo "$ZONE_ID_JSON" | jq -r '.success') != "true" ]]; then
        # 提取错误信息
        local error_msg=$(echo "$ZONE_ID_JSON" | jq -r '.errors[0].message')
        echo -e "${RED}[✗] Cloudflare API 返回错误: ${error_msg}${NC}"; exit 1;
    fi

    # 提取 Zone ID
    ZONE_ID=$(echo "$ZONE_ID_JSON" | jq -r '.result[0].id')

    # 检查是否成功获取 Zone ID
    if [[ "$ZONE_ID" == "null" || -z "$ZONE_ID" ]]; then
        echo -e "${RED}[✗] 无法找到域名 $ZONE_NAME 对应的活动 Zone ID。请检查域名和 API Token 是否正确。${NC}"; exit 1;
    fi
    echo -e "${GREEN}[✓] 找到 Zone ID: $ZONE_ID${NC}"
}

# 检查并创建/更新 Cloudflare DNS 记录
manage_cloudflare_record() {
    local action="$1" # "create" or "update" (主要用于日志信息)
    echo -e "${BLUE}[*] ${action} Cloudflare DNS 记录 ($RECORD_TYPE)...${NC}"
    echo "正在检查 $DOMAIN 的 $RECORD_TYPE 记录..."

    # 调用 API 获取指定域名和类型的 DNS 记录信息
    RECORD_INFO=$(curl -s --max-time 10 -X GET "$CF_API/zones/$ZONE_ID/dns_records?type=$RECORD_TYPE&name=$DOMAIN" \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json")

    if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (获取记录) 失败。${NC}"; exit 1; fi
    if [[ $(echo "$RECORD_INFO" | jq -r '.success') != "true" ]]; then
        echo -e "${RED}[✗] Cloudflare API 返回错误 (获取记录): $(echo "$RECORD_INFO" | jq -r '.errors[0].message')${NC}"; exit 1;
    fi

    # 提取记录 ID 和当前 IP
    RECORD_ID=$(echo "$RECORD_INFO" | jq -r '.result[0].id');
    CURRENT_IP=$(echo "$RECORD_INFO" | jq -r '.result[0].content')

    # 如果记录 ID 为空或 null，表示记录不存在
    if [[ "$RECORD_ID" == "null" || -z "$RECORD_ID" ]]; then
        echo "未找到 $RECORD_TYPE 记录，正在创建..."
        # 调用 API 创建新记录
        CREATE_RESULT=$(curl -s --max-time 10 -X POST "$CF_API/zones/$ZONE_ID/dns_records" \
            -H "Authorization: Bearer $CF_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"$RECORD_TYPE\",\"name\":\"$DOMAIN\",\"content\":\"$SELECTED_IP\",\"ttl\":120,\"proxied\":false}") # ttl=120 (2分钟), proxied=false (DNS only)

        if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (创建记录) 失败。${NC}"; exit 1; fi
        if [[ $(echo "$CREATE_RESULT" | jq -r '.success') == "true" ]]; then
            echo -e "${GREEN}[✓] $RECORD_TYPE 记录创建成功: $DOMAIN -> $SELECTED_IP${NC}";
        else
            echo -e "${RED}[✗] 创建 $RECORD_TYPE 记录失败: $(echo "$CREATE_RESULT" | jq -r '.errors[0].message')${NC}"; exit 1;
        fi
    else
        # 记录已存在
        echo "找到 $RECORD_TYPE 记录 (ID: $RECORD_ID)，当前 Cloudflare 记录 IP: $CURRENT_IP"
        # 检查当前记录的 IP 是否与选择的 IP 一致
        if [[ "$CURRENT_IP" != "$SELECTED_IP" ]]; then
            echo "IP 地址不匹配 ($CURRENT_IP != $SELECTED_IP)，正在更新..."
            # 调用 API 更新记录
            UPDATE_RESULT=$(curl -s --max-time 10 -X PUT "$CF_API/zones/$ZONE_ID/dns_records/$RECORD_ID" \
                -H "Authorization: Bearer $CF_API_TOKEN" \
                -H "Content-Type: application/json" \
                --data "{\"type\":\"$RECORD_TYPE\",\"name\":\"$DOMAIN\",\"content\":\"$SELECTED_IP\",\"ttl\":120,\"proxied\":false}")

            if [[ $? -ne 0 ]]; then echo -e "${RED}[✗] 调用 Cloudflare API (更新记录) 失败。${NC}"; exit 1; fi
            if [[ $(echo "$UPDATE_RESULT" | jq -r '.success') == "true" ]]; then
                echo -e "${GREEN}[✓] $RECORD_TYPE 记录更新成功: $DOMAIN -> $SELECTED_IP${NC}";
            else
                echo -e "${RED}[✗] 更新 $RECORD_TYPE 记录失败: $(echo "$UPDATE_RESULT" | jq -r '.errors[0].message')${NC}"; exit 1;
            fi
        else
            # IP 地址一致，无需更新
            echo -e "${GREEN}[✓] $RECORD_TYPE 记录已是最新 ($CURRENT_IP)，无需更新。${NC}";
        fi
    fi
}

# 申请 SSL 证书
request_certificate() {
    echo -e "${BLUE}[*] 申请 SSL 证书 (Let's Encrypt)...${NC}"
    # 使用 certbot 和 Cloudflare DNS 插件申请证书
    # --dns-cloudflare-propagation-seconds: 等待 DNS 记录生效的时间
    # --agree-tos: 同意 Let's Encrypt 服务条款
    # --no-eff-email: 不同意 EFF 分享邮箱
    # --non-interactive: 非交互模式
    certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$CLOUDFLARE_CREDENTIALS" \
        --dns-cloudflare-propagation-seconds 60 \
        -d "$DOMAIN" \
        --email "$EMAIL" \
        --agree-tos \
        --no-eff-email \
        --non-interactive

    # 检查证书文件是否存在
    if [[ ! -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" || ! -f "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" ]]; then
        echo -e "${RED}[✗] 证书申请失败。请检查 certbot 日志 (/var/log/letsencrypt/letsencrypt.log) 获取详细信息。${NC}"; exit 1;
    fi
    echo -e "${GREEN}[✓] SSL 证书申请成功！${NC}"
}

# 复制证书文件到指定目录
copy_certificate() {
    echo -e "${BLUE}[*] 复制证书文件到 $CERT_PATH ...${NC}"
    mkdir -p "$CERT_PATH"
    # 使用 -L 选项复制符号链接指向的实际文件
    cp -L "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$CERT_PATH/"
    cp -L "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$CERT_PATH/"
    cp -L "/etc/letsencrypt/live/${DOMAIN}/chain.pem" "$CERT_PATH/"
    cp -L "/etc/letsencrypt/live/${DOMAIN}/cert.pem" "$CERT_PATH/"
    # 可选：设置权限，确保 Nginx 等服务可以读取
    # chmod 644 ${CERT_PATH}/*.pem
    # chown www-data:www-data ${CERT_PATH}/*.pem # 如果 Nginx 以 www-data 运行
    echo -e "${GREEN}[✓] 证书文件已复制到 $CERT_PATH ${NC}"
}

# 配置 Nginx 反向代理
setup_nginx_proxy() {
    # 询问用户是否需要配置 Nginx
    read -p "是否需要自动配置 Nginx 反向代理? (yes/no) [no]: " CONFIGURE_NGINX
    if [[ "$CONFIGURE_NGINX" != "yes" ]]; then
        echo "跳过 Nginx 配置。"
        INSTALL_NGINX="no" # 确保不尝试安装 Nginx
        return
    fi

    # 如果用户选择 'yes'，则标记需要安装 Nginx
    INSTALL_NGINX="yes"
    install_packages # 确保 Nginx 已安装

    # --- 获取自定义端口 ---
    while true; do
        read -p "请输入 Nginx 监听的 HTTP 端口 [默认: ${NGINX_HTTP_PORT}]: " http_port_input
        if [[ -z "$http_port_input" ]]; then
            # 用户直接回车，使用默认值
            break
        elif [[ "$http_port_input" =~ ^[0-9]+$ && "$http_port_input" -gt 0 && "$http_port_input" -le 65535 ]]; then
            # 输入有效端口号
            NGINX_HTTP_PORT=$http_port_input
            break
        else
            echo -e "${YELLOW}无效端口号。请输入 1-65535 之间的数字，或直接回车使用默认值。${NC}"
        fi
    done
    echo -e "Nginx HTTP 端口设置为: ${GREEN}${NGINX_HTTP_PORT}${NC}"

    while true; do
         read -p "请输入 Nginx 监听的 HTTPS 端口 [默认: ${NGINX_HTTPS_PORT}]: " https_port_input
         if [[ -z "$https_port_input" ]]; then
             # 用户直接回车，使用默认值
             break
         elif [[ "$https_port_input" =~ ^[0-9]+$ && "$https_port_input" -gt 0 && "$https_port_input" -le 65535 ]]; then
             # 输入有效端口号
             # 检查是否与 HTTP 端口冲突
             if [[ "$https_port_input" -eq "$NGINX_HTTP_PORT" ]]; then
                 echo -e "${YELLOW}HTTPS 端口不能与 HTTP 端口 (${NGINX_HTTP_PORT}) 相同。${NC}"
             else
                 NGINX_HTTPS_PORT=$https_port_input
                 break
             fi
         else
             echo -e "${YELLOW}无效端口号。请输入 1-65535 之间的数字，或直接回车使用默认值。${NC}"
         fi
    done
    echo -e "Nginx HTTPS 端口设置为: ${GREEN}${NGINX_HTTPS_PORT}${NC}"
    # --- 端口获取结束 ---


    # --- 使用数字选择后端协议 ---
    while true; do
        read -p "请选择后端服务 (${DOMAIN}) 使用的协议: [1] http (默认) [2] https : " proto_choice
        if [[ -z "$proto_choice" || "$proto_choice" == "1" ]]; then
            BACKEND_PROTOCOL="http"
            break
        elif [[ "$proto_choice" == "2" ]]; then
            BACKEND_PROTOCOL="https"
            break
        else
            echo -e "${YELLOW}无效输入，请输入 1 或 2，或直接回车使用默认值 (http)。${NC}"
        fi
    done
    echo -e "后端服务协议设置为: ${GREEN}${BACKEND_PROTOCOL}${NC}"
    # --- 协议选择修改结束 ---

    # 询问后端服务地址和端口
    while [[ -z "$LOCAL_PROXY_PASS" ]]; do
        read -p "请输入 Nginx 需要反向代理的本地服务地址 (只需 IP/域名 和 端口, 例如 localhost:8080 或 192.168.1.10:3000): " addr_input
        # 简单校验格式：包含字母数字点横线，后跟冒号和数字
        if [[ "$addr_input" =~ ^[a-zA-Z0-9.-]+:[0-9]+$ ]]; then
            LOCAL_PROXY_PASS="${BACKEND_PROTOCOL}://${addr_input}"
            echo -e "将使用代理地址: ${GREEN}${LOCAL_PROXY_PASS}${NC}"
        else echo -e "${YELLOW}地址格式似乎不正确，请确保是 '地址:端口' 格式。${NC}"; LOCAL_PROXY_PASS=""; fi
    done

    echo -e "${BLUE}[*] 生成 Nginx 配置文件: $NGINX_CONF_PATH ...${NC}"
    # 确保 Nginx 配置目录存在
    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
    # 确保 Certbot http-01 验证的根目录存在
    mkdir -p /var/www/html/.well-known/acme-challenge
    # 尝试设置权限，如果 www-data 用户/组不存在，则忽略错误
    chown www-data:www-data /var/www/html -R 2>/dev/null || echo -e "${YELLOW}[!] 无法设置 /var/www/html 权限 (可能 www-data 用户/组不存在)，通常不影响 Certbot DNS 验证。${NC}"

    # --- 修复 V2.6: 在 Bash 中预处理跳转端口后缀 ---
    local redirect_suffix_bash=""
    if [[ "${NGINX_HTTPS_PORT}" -ne 443 ]]; then
        redirect_suffix_bash=":${NGINX_HTTPS_PORT}"
    fi
    # --- 修复结束 ---

    # --- Nginx 配置模板 (使用预处理的跳转后缀) ---
    cat > "$NGINX_CONF_PATH" <<EOF
server {
    # 使用自定义 HTTP 端口
    listen ${NGINX_HTTP_PORT};
    listen [::]:${NGINX_HTTP_PORT};
    server_name ${DOMAIN};

    # Certbot ACME Challenge 路径 (优先处理)
    location ~ /.well-known/acme-challenge/ {
        allow all;
        root /var/www/html; # 确保此路径存在且 Nginx 有权访问
    }

    # 其他所有请求跳转到 HTTPS
    location / {
        # 使用 301 永久重定向
        # 使用在 Bash 中预处理好的端口后缀 ${redirect_suffix_bash}
        return 301 https://\$host${redirect_suffix_bash}\$request_uri;
    }
}

server {
    # 启用 SSL 和 HTTP/2，并使用自定义 HTTPS 端口
    listen ${NGINX_HTTPS_PORT} ssl http2;
    listen [::]:${NGINX_HTTPS_PORT} ssl http2;
    server_name ${DOMAIN};

    # SSL 证书路径 (使用复制后的路径)
    ssl_certificate ${CERT_PATH}/fullchain.pem;
    ssl_certificate_key ${CERT_PATH}/privkey.pem;

    # SSL 安全配置 (参考 Mozilla Intermediate compatibility - https://ssl-config.mozilla.org/)
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m; # approx 40,000 sessions
    ssl_session_tickets off; # 禁用 session tickets，增强安全性

    # 推荐的协议和加密套件
    ssl_protocols TLSv1.2 TLSv1.3; # 推荐仅使用 TLS 1.2 和 1.3
    # 推荐的加密套件 (兼容性较好且安全)
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off; # 客户端优先选择加密套件

    # === 安全性增强 ===
    # HSTS (HTTP Strict Transport Security) - 强制浏览器始终使用 HTTPS 访问
    # max-age=15768000 秒 (大约 6 个月). 首次部署建议使用较短时间 (如 300 秒) 测试，确认无误后再加长。
    # includeSubDomains 可选，如果所有子域名也都强制 HTTPS 才添加。
    # preload 可选，如果希望加入浏览器 HSTS 预加载列表 (需要更严格的要求)。
    # 注意：如果使用非标准 HTTPS 端口，HSTS 预加载可能无法工作。
    add_header Strict-Transport-Security "max-age=15768000" always;

    # 其他可选安全头 (根据需要取消注释)
    # add_header X-Frame-Options "SAMEORIGIN" always; # 防止点击劫持
    # add_header X-Content-Type-Options "nosniff" always; # 防止 MIME 类型嗅探攻击
    # add_header Referrer-Policy "strict-origin-when-cross-origin" always; # 控制 Referer 头发送策略
    # add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';" always; # 内容安全策略 (需要仔细配置)
    # add_header Permissions-Policy "interest-cohort=()" always; # 禁用 Google FLoC 跟踪

    # OCSP Stapling (提高 SSL 握手性能，减少客户端验证延迟)
    # 需要确保 Nginx 可以访问 Let's Encrypt 的 OCSP 服务器
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate ${CERT_PATH}/chain.pem; # 需要 CA 链文件 (fullchain.pem 通常包含)
    # 使用公共 DNS 或本地 DNS
    resolver 1.1.1.1 8.8.8.8 valid=300s; # 使用 Cloudflare 和 Google DNS
    resolver_timeout 5s;

    # === 反向代理配置 ===
    location / {
        proxy_pass ${LOCAL_PROXY_PASS}; # 使用包含协议的完整后端地址

        # 设置必要的代理头，将客户端信息传递给后端
        proxy_set_header Host \$host; # 传递原始请求的 Host 头
        proxy_set_header X-Real-IP \$remote_addr; # 传递客户端真实 IP
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; # 传递经过的所有代理 IP 列表
        proxy_set_header X-Forwarded-Proto \$scheme; # 告知后端请求是 http 还是 https
        # 注意：如果 Nginx 监听非标准 HTTPS 端口，后端可能需要 X-Forwarded-Port 来正确构建 URL
        proxy_set_header X-Forwarded-Host \$host; # 某些应用可能需要
        proxy_set_header X-Forwarded-Port \$server_port; # 传递 Nginx 监听的端口

        # 如果后端是 HTTPS，可能需要以下配置
        # proxy_ssl_server_name on; # 传递 SNI (Server Name Indication) 给后端，允许多证书主机使用
        $( [[ "$BACKEND_PROTOCOL" == "https" ]] && echo '        proxy_ssl_server_name on;' )
        # 如果后端使用的是自签名证书或不受信任的 CA 证书，取消注释下一行 (会降低安全性!)
        # proxy_ssl_verify off;
        # $( [[ "$BACKEND_PROTOCOL" == "https" ]] && echo '        # proxy_ssl_verify off;' ) # 默认保持注释

        # WebSocket support (如果后端应用需要 WebSocket)
        # proxy_http_version 1.1;
        # proxy_set_header Upgrade \$http_upgrade;
        # proxy_set_header Connection "upgrade";

        # 增加超时设置 (可选，根据后端应用响应时间调整)
        # proxy_connect_timeout 60s;
        # proxy_send_timeout 60s;
        # proxy_read_timeout 60s;

        # 缓冲区设置 (可选，根据需要调整)
        # proxy_buffering on;
        # proxy_buffers 8 16k;
        # proxy_buffer_size 32k;
        # proxy_busy_buffers_size 64k;
    }

    # 可选：自定义错误页面
    # error_page 500 502 503 504 /50x.html;
    # location = /50x.html {
    #     root /usr/share/nginx/html; # 指向 Nginx 默认错误页面目录或自定义目录
    # }
}
EOF
    # --- Nginx 配置模板结束 ---

    # 创建软链接到 sites-enabled 目录以启用配置
    if [[ ! -L "/etc/nginx/sites-enabled/${DOMAIN}.conf" ]]; then
        ln -s "$NGINX_CONF_PATH" "/etc/nginx/sites-enabled/${DOMAIN}.conf"
        echo -e "${GREEN}[✓] Nginx 配置已启用 (创建软链接)。${NC}"
    else
        echo -e "${YELLOW}[!] Nginx 配置软链接已存在，跳过创建。${NC}";
    fi

    # 检查 Nginx 配置语法并尝试重载
    echo -e "${BLUE}[*] 检查 Nginx 配置并尝试重载...${NC}"
    # 使用 nginx -t -c /etc/nginx/nginx.conf 确保加载主配置文件进行测试
    if nginx -t -c /etc/nginx/nginx.conf; then
        # 配置检查通过
        systemctl reload nginx
        if systemctl is-active --quiet nginx; then
             echo -e "${GREEN}[✓] Nginx 配置检查通过并已成功重载。${NC}"
             echo -e "${YELLOW}提示：Nginx 正在监听 HTTP 端口 ${NGINX_HTTP_PORT} 和 HTTPS 端口 ${NGINX_HTTPS_PORT}。${NC}"
             # 增加防火墙提示
             if [[ "$NGINX_HTTP_PORT" -ne 80 || "$NGINX_HTTPS_PORT" -ne 443 ]]; then
                 echo -e "${YELLOW}重要提示：请确保防火墙 (如 ufw, firewalld) 允许访问您设置的自定义端口 (${NGINX_HTTP_PORT} 和 ${NGINX_HTTPS_PORT})！${NC}"
                 echo -e "${YELLOW}访问时，如果 HTTPS 端口不是 443，URL 中需要包含端口号，例如: https://${DOMAIN}:${NGINX_HTTPS_PORT}${NC}"
             fi
        else
             echo -e "${RED}[✗] Nginx 重载后状态异常，请检查 Nginx 服务状态和日志。${NC}"
        fi
    else
        # 配置检查失败
        echo -e "${RED}[✗] Nginx 配置检查失败！请手动检查 ${NGINX_CONF_PATH} 文件以及 Nginx 主配置文件中的错误。${NC}"; exit 1;
    fi
}


# 创建 DDNS 更新脚本 (仅当 DDNS_FREQUENCY > 0)
create_ddns_script() {
    # 如果 DDNS 频率设置为 0 或负数，则不创建脚本
    if [[ "$DDNS_FREQUENCY" -le 0 ]]; then
        echo "${YELLOW}DDNS 已禁用，跳过创建 DDNS 更新脚本。${NC}";
        # 如果旧的 DDNS 脚本存在，可以选择删除它
        if [[ -f "$DDNS_SCRIPT_PATH" ]]; then
            echo "${YELLOW}检测到旧的 DDNS 脚本 $DDNS_SCRIPT_PATH，正在删除...${NC}"
            rm -f "$DDNS_SCRIPT_PATH"
        fi
        return;
    fi

    echo -e "${BLUE}[*] 创建 DDNS 更新脚本: $DDNS_SCRIPT_PATH ...${NC}"
    mkdir -p "$(dirname "$DDNS_SCRIPT_PATH")"
    # 从凭证文件中读取 API Token (避免硬编码在脚本中)
    local current_token=$(grep dns_cloudflare_api_token "$CLOUDFLARE_CREDENTIALS" | awk '{print $3}')
    if [[ -z "$current_token" ]]; then
        echo -e "${RED}[✗] 无法从 $CLOUDFLARE_CREDENTIALS 读取 API Token，无法创建 DDNS 脚本。${NC}"; return;
    fi

    # --- DDNS 更新脚本模板 ---
    cat > "$DDNS_SCRIPT_PATH" <<EOF
#!/bin/bash
# --- DDNS 更新脚本 for ${DOMAIN} (由主脚本自动生成) ---

# --- 配置 ---
# Cloudflare 凭证文件路径 (包含 API Token)
CF_CREDENTIALS_FILE="/root/.cloudflare-${DOMAIN}.ini"
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
IPV4_URLS=("https://api.ipify.org" "https://ifconfig.me/ip")
IPV6_URLS=("https://api64.ipify.org" "https://ifconfig.me/ip")

# --- 函数 ---
log_message() {
    echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1" >> "\$LOG_FILE"
}

get_current_ip() {
    local type=\$1
    local urls
    local curl_opt
    if [[ "\$type" == "A" ]]; then
        urls=("${IPV4_URLS[@]}")
        curl_opt="-4s"
    elif [[ "\$type" == "AAAA" ]]; then
        urls=("${IPV6_URLS[@]}")
        curl_opt="-6s"
    else
        log_message "Error: Invalid record type specified: \$type"
        return 1
    fi

    local ip=""
    for url in "\${urls[@]}"; do
        ip=\$(curl \$curl_opt --max-time \$TIMEOUT "\$url" 2>/dev/null)
        if [[ -n "\$ip" ]]; then
            # 简单 IP 格式校验
            if [[ "\$type" == "A" && "\$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo "\$ip"; return 0; fi
            if [[ "\$type" == "AAAA" && "\$ip" =~ ^([0-9a-fA-F:]+)$ ]]; then echo "\$ip"; return 0; fi
        fi
        sleep 1 # 避免请求过于频繁
    done
    log_message "Error: Failed to get current public \$type IP address from all sources."
    return 1
}

get_cf_record() {
    local cf_token=\$1
    RECORD_INFO=\$(curl -s --max-time \$TIMEOUT -X GET "\$CF_API/zones/\$ZONE_ID/dns_records?type=\$RECORD_TYPE&name=\$DOMAIN" \
        -H "Authorization: Bearer \$cf_token" \
        -H "Content-Type: application/json")

    if [[ \$? -ne 0 ]]; then log_message "Error: API call failed (Get Record - Network/Timeout)"; return 1; fi
    if [[ \$(echo "\$RECORD_INFO" | jq -r '.success') != "true" ]]; then
        local err_msg=\$(echo "\$RECORD_INFO" | jq -r '.errors[0].message // "Unknown API Error"')
        log_message "Error: API call failed (Get Record): \$err_msg"; return 1;
    fi
    echo "\$RECORD_INFO" # 将 JSON 结果输出
    return 0
}

update_cf_record() {
    local cf_token=\$1
    local record_id=\$2
    local new_ip=\$3
    UPDATE_RESULT=\$(curl -s --max-time \$TIMEOUT -X PUT "\$CF_API/zones/\$ZONE_ID/dns_records/\$record_id" \
        -H "Authorization: Bearer \$cf_token" \
        -H "Content-Type: application/json" \
        --data "{\"type\":\"\$RECORD_TYPE\",\"name\":\"\$DOMAIN\",\"content\":\"\$new_ip\",\"ttl\":120,\"proxied\":false}")

    if [[ \$? -ne 0 ]]; then log_message "Error: API call failed (Update Record - Network/Timeout)"; return 1; fi
    if [[ \$(echo "\$UPDATE_RESULT" | jq -r '.success') != "true" ]]; then
        local err_msg=\$(echo "\$UPDATE_RESULT" | jq -r '.errors[0].message // "Unknown API Error"')
        log_message "Error: API call failed (Update Record): \$err_msg"; return 1;
    fi
    return 0
}

# --- 主逻辑 ---
# 检查日志文件目录是否存在
mkdir -p \$(dirname "\$LOG_FILE")

# 从凭证文件读取 API Token
CF_API_TOKEN=\$(grep dns_cloudflare_api_token "\$CF_CREDENTIALS_FILE" | awk '{print \$3}')
if [[ -z "\$CF_API_TOKEN" ]]; then
    log_message "Error: Failed to read Cloudflare API Token from \$CF_CREDENTIALS_FILE"
    exit 1
fi

# 获取当前公网 IP
CURRENT_IP=\$(get_current_ip "\$RECORD_TYPE")
if [[ \$? -ne 0 ]]; then
    # get_current_ip 函数内部已记录错误
    exit 1
fi
log_message "Info: Current public IP (\$RECORD_TYPE) detected: \$CURRENT_IP"

# 获取 Cloudflare 上的 DNS 记录信息
RECORD_INFO_JSON=\$(get_cf_record "\$CF_API_TOKEN")
if [[ \$? -ne 0 ]]; then exit 1; fi

# 解析记录 ID 和 Cloudflare 上的 IP
CF_IP=\$(echo "\$RECORD_INFO_JSON" | jq -r '.result[0].content')
RECORD_ID=\$(echo "\$RECORD_INFO_JSON" | jq -r '.result[0].id')

if [[ -z "\$RECORD_ID" || "\$RECORD_ID" == "null" ]]; then
    log_message "Error: Could not find existing \$RECORD_TYPE record for \$DOMAIN on Cloudflare."
    # 这里可以选择尝试创建记录，或者直接退出报错
    exit 1
fi

if [[ -z "\$CF_IP" || "\$CF_IP" == "null" ]]; then
    log_message "Error: Failed to parse IP address from Cloudflare record for \$DOMAIN."
    exit 1
fi
log_message "Info: Cloudflare current IP (\$RECORD_TYPE) for \$DOMAIN: \$CF_IP"

# 比较 IP 地址
if [[ "\$CURRENT_IP" == "\$CF_IP" ]]; then
    log_message "Info: IP address matches Cloudflare record (\$CURRENT_IP). No update needed."
    exit 0
else
    log_message "Info: IP address mismatch. Current: \$CURRENT_IP, Cloudflare: \$CF_IP. Updating Cloudflare..."
    # 更新 Cloudflare 记录
    update_cf_record "\$CF_API_TOKEN" "\$RECORD_ID" "\$CURRENT_IP"
    if [[ \$? -eq 0 ]]; then
        log_message "Success: Cloudflare DNS record for \$DOMAIN updated successfully to \$CURRENT_IP."
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
}

# 设置自动任务 (证书续期和 DDNS)
setup_cron_jobs() {
    echo -e "${BLUE}[*] 设置 Cron 定时任务...${NC}"

    # 1. 创建证书续期后的部署钩子脚本
    # 这个脚本会在 Certbot 成功续期证书后被调用
    echo -e "${BLUE}[*] 创建证书续期部署钩子脚本: $DEPLOY_HOOK_SCRIPT ...${NC}"
    mkdir -p "$(dirname "$DEPLOY_HOOK_SCRIPT")"
    cat > "$DEPLOY_HOOK_SCRIPT" <<EOF
#!/bin/bash
# Certbot 续期成功后执行的脚本 for ${DOMAIN} (由主脚本自动生成)

LOG_FILE="/var/log/cert_renew_${DOMAIN}.log"
CERT_PATH="${CERT_PATH}" # 使用主脚本中定义的证书副本路径
NGINX_CONF_PATH="${NGINX_CONF_PATH}" # 使用主脚本中定义的 Nginx 配置文件路径
LIVE_CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"

log_hook() {
    echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1" >> "\$LOG_FILE"
}

# 检查日志文件目录是否存在
mkdir -p \$(dirname "\$LOG_FILE")

log_hook "Cert renewed for ${DOMAIN}. Running deploy hook..."

# 检查源证书文件是否存在
if [[ ! -f "\${LIVE_CERT_DIR}/fullchain.pem" || ! -f "\${LIVE_CERT_DIR}/privkey.pem" ]]; then
    log_hook "Error: Source certificate files not found in \${LIVE_CERT_DIR}. Cannot copy."
    exit 1
fi

# 复制新证书到指定目录
log_hook "Copying new certificates from \${LIVE_CERT_DIR} to ${CERT_PATH}..."
cp -L "\${LIVE_CERT_DIR}/fullchain.pem" "${CERT_PATH}/" && \
cp -L "\${LIVE_CERT_DIR}/privkey.pem" "${CERT_PATH}/" && \
cp -L "\${LIVE_CERT_DIR}/chain.pem" "${CERT_PATH}/" && \
cp -L "\${LIVE_CERT_DIR}/cert.pem" "${CERT_PATH}/"

if [[ \$? -ne 0 ]]; then
    log_hook "Error: Failed to copy certificate files."
    # 根据需要决定是否退出，如果 Nginx 依赖这些文件，可能需要退出
    # exit 1
else
    log_hook "Success: Certificates copied to ${CERT_PATH}."
    # 可选：设置权限
    # chmod 644 ${CERT_PATH}/*.pem
fi

# 检查 Nginx 配置文件是否存在，如果存在则重载 Nginx
if [[ -f "${NGINX_CONF_PATH}" ]] && command -v nginx >/dev/null 2>&1; then
    log_hook "Nginx config ${NGINX_CONF_PATH} exists. Reloading Nginx..."
    # 先测试配置是否正确
    nginx -t -c /etc/nginx/nginx.conf # 使用主配置文件测试
    if [[ \$? -eq 0 ]]; then
        # 配置正确，执行重载
        systemctl reload nginx
        if [[ \$? -eq 0 ]]; then
            log_hook "Success: Nginx reloaded successfully."
        else
            log_hook "Error: Failed to reload Nginx. Check systemctl status nginx."
        fi
    else
        log_hook "Error: Nginx configuration test failed (nginx -t). Reload skipped. Please check Nginx config manually!"
    fi
else
    log_hook "Nginx config ${NGINX_CONF_PATH} not found or Nginx command not available. Skipping Nginx reload."
fi

log_hook "Deploy hook finished for ${DOMAIN}."
exit 0
EOF
    # --- 部署钩子脚本模板结束 ---
    chmod +x "$DEPLOY_HOOK_SCRIPT"
    echo -e "${GREEN}[✓] 证书续期部署钩子脚本创建成功: $DEPLOY_HOOK_SCRIPT ${NC}"

    # 2. 添加或更新 Cron 任务
    # 使用标记来识别和管理由本脚本添加的 Cron 任务
    CRON_TAG_RENEW="# CertRenew_${DOMAIN}"
    CRON_TAG_DDNS="# DDNSUpdate_${DOMAIN}"

    # 先移除旧的、由本脚本为该域名添加的 Cron 任务 (防止重复添加)
    (crontab -l 2>/dev/null | grep -v -F "$CRON_TAG_RENEW" | grep -v -F "$CRON_TAG_DDNS") | crontab -

    # 获取当前 Cron 内容 (移除旧任务后)
    CRON_CONTENT=$(crontab -l 2>/dev/null)

    # 构建新的证书续期 Cron 任务
    # 每天凌晨 3 点执行 certbot renew，并使用部署钩子
    # 将标准输出和错误输出追加到日志文件
    CRON_CERT_RENEW="0 3 * * * certbot renew --deploy-hook \"$DEPLOY_HOOK_SCRIPT\" >> /var/log/certbot_renew.log 2>&1 ${CRON_TAG_RENEW}"

    # 添加证书续期任务到 Cron
    echo "${CRON_CONTENT}"$'\n'"${CRON_CERT_RENEW}" | crontab -
    echo -e "${GREEN}[✓] Cron 证书续期任务已设置 (${DOMAIN})。${NC}"

    # 如果启用了 DDNS，则添加 DDNS 更新任务
    if [[ "$DDNS_FREQUENCY" -gt 0 ]]; then
        # 检查 DDNS 脚本是否存在
        if [[ -f "$DDNS_SCRIPT_PATH" ]]; then
            # 构建 DDNS 更新 Cron 任务
            # 使用 */frequency 语法每隔指定分钟执行一次
            CRON_DDNS_UPDATE="*/${DDNS_FREQUENCY} * * * * $DDNS_SCRIPT_PATH ${CRON_TAG_DDNS}"
            # 添加 DDNS 更新任务到 Cron
            CRON_CONTENT=$(crontab -l 2>/dev/null); echo "${CRON_CONTENT}"$'\n'"${CRON_DDNS_UPDATE}" | crontab -
            echo -e "${GREEN}[✓] Cron DDNS 更新任务已设置 (${DOMAIN}, 每 ${DDNS_FREQUENCY} 分钟)。${NC}"
        else
             echo -e "${RED}[✗] DDNS 更新脚本 ($DDNS_SCRIPT_PATH) 未找到，无法设置 Cron 任务。${NC}"
        fi
    else
        echo -e "${YELLOW}DDNS 已禁用，未设置 Cron 更新任务 (${DOMAIN})。${NC}";
    fi

    # 显示当前用户的 Cron 任务列表
    echo -e "${CYAN}当前用户的 Cron 任务列表:${NC}"; crontab -l
}

# 删除指定域名的配置
delete_domain_configuration() {
    local domain_to_delete="$1"
    echo -e "\n${RED}!!! 警告：此操作将删除域名 ${domain_to_delete} 的所有相关配置 !!!${NC}"
    echo "将执行以下操作:"
    echo "  - 删除 Let's Encrypt 证书 (使用 certbot delete)"
    echo "  - 删除本地证书副本目录 (${CERT_PATH_PREFIX}/${domain_to_delete})"
    echo "  - 删除 Cloudflare 凭证文件 (/root/.cloudflare-${domain_to_delete}.ini)"
    echo "  - 删除 Nginx 配置文件 (/etc/nginx/sites-available/${domain_to_delete}.conf)"
    echo "  - 删除 Nginx 启用链接 (/etc/nginx/sites-enabled/${domain_to_delete}.conf)"
    echo "  - 删除 DDNS 更新脚本 (/usr/local/bin/cf_ddns_update_${domain_to_delete}.sh)"
    echo "  - 删除证书续期钩子脚本 (/root/cert-renew-hook-${domain_to_delete}.sh)"
    echo "  - 从 Cron 中移除相关任务"
    echo -e "${RED}此操作不可恢复！请谨慎操作！${NC}"
    read -p "请再次确认是否删除 ${domain_to_delete} 的所有配置? (输入 'yes' 确认): " confirm_delete
    if [[ "$confirm_delete" != "yes" ]]; then echo "操作已取消。"; return; fi

    echo -e "${BLUE}[*] 开始删除域名 ${domain_to_delete} 的配置...${NC}"
    # 更新路径变量以匹配要删除的域名
    update_paths_for_domain "$domain_to_delete"

    # 1. 删除 Let's Encrypt 证书
    echo -n "[1/8] 删除 Let's Encrypt 证书..."
    if command_exists certbot; then
        # 使用 --non-interactive 避免交互提示
        certbot delete --cert-name "$domain_to_delete" --non-interactive
        if [[ $? -eq 0 ]]; then echo -e "${GREEN}[✓] Certbot 删除成功或证书不存在。${NC}";
        else echo -e "${YELLOW}[!] Certbot 删除命令执行失败 (可能需要手动检查)。${NC}"; fi
    else
        echo -e "${YELLOW}[!] Certbot 命令未找到，跳过。${NC}";
    fi

    # 2. 删除本地证书副本目录
    echo -n "[2/8] 删除本地证书副本目录 $CERT_PATH ..."
    if [[ -d "$CERT_PATH" ]]; then
        rm -rf "$CERT_PATH"
        echo -e "${GREEN}[✓] 已删除。${NC}";
    else
        echo -e "${YELLOW}[!] 未找到或已被删除。${NC}";
    fi

    # 3. 删除 Cloudflare 凭证文件
    echo -n "[3/8] 删除 CF 凭证文件 $CLOUDFLARE_CREDENTIALS ..."
    if [[ -f "$CLOUDFLARE_CREDENTIALS" ]]; then
        rm -f "$CLOUDFLARE_CREDENTIALS"
        echo -e "${GREEN}[✓] 已删除。${NC}";
    else
        echo -e "${YELLOW}[!] 未找到或已被删除。${NC}";
    fi

    # 4. 删除 Nginx 启用链接
    local nginx_conf_enabled="/etc/nginx/sites-enabled/${domain_to_delete}.conf"
    echo -n "[4/8] 删除 Nginx 启用链接 $nginx_conf_enabled ..."
    local nginx_reload_needed=0
    if [[ -L "$nginx_conf_enabled" ]]; then
        rm -f "$nginx_conf_enabled"
        echo -e "${GREEN}[✓] 已删除。${NC}";
        nginx_reload_needed=1
    else
        echo -e "${YELLOW}[!] 未找到或已被删除。${NC}";
    fi

    # 5. 删除 Nginx 配置文件
    echo -n "[5/8] 删除 Nginx 配置文件 $NGINX_CONF_PATH ..."
    if [[ -f "$NGINX_CONF_PATH" ]]; then
        rm -f "$NGINX_CONF_PATH"
        echo -e "${GREEN}[✓] 已删除。${NC}";
        nginx_reload_needed=1
    else
        echo -e "${YELLOW}[!] 未找到或已被删除。${NC}";
    fi

    # 6. 删除 DDNS 更新脚本
    echo -n "[6/8] 删除 DDNS 更新脚本 $DDNS_SCRIPT_PATH ..."
    if [[ -f "$DDNS_SCRIPT_PATH" ]]; then
        rm -f "$DDNS_SCRIPT_PATH"
        echo -e "${GREEN}[✓] 已删除。${NC}";
    else
        echo -e "${YELLOW}[!] 未找到或已被删除。${NC}";
    fi

    # 7. 删除证书续期钩子脚本
    echo -n "[7/8] 删除证书续期钩子脚本 $DEPLOY_HOOK_SCRIPT ..."
     if [[ -f "$DEPLOY_HOOK_SCRIPT" ]]; then
        rm -f "$DEPLOY_HOOK_SCRIPT"
        echo -e "${GREEN}[✓] 已删除。${NC}";
    else
        echo -e "${YELLOW}[!] 未找到或已被删除。${NC}";
    fi

    # 8. 从 Cron 中移除相关任务
    echo -n "[8/8] 从 Cron 中移除任务..."
    CRON_TAG_RENEW="# CertRenew_${domain_to_delete}"; CRON_TAG_DDNS="# DDNSUpdate_${domain_to_delete}"
    # 读取当前 crontab，过滤掉包含特定标记的行，然后写回 crontab
    (crontab -l 2>/dev/null | grep -v -F "$CRON_TAG_RENEW" | grep -v -F "$CRON_TAG_DDNS") | crontab -
    echo -e "${GREEN}[✓] Cron 任务已移除。${NC}"

    # 如果删除了 Nginx 配置，尝试重载 Nginx
    if [[ $nginx_reload_needed -eq 1 ]] && command_exists nginx; then
        echo -n "尝试重载 Nginx 配置..."
        if nginx -t -c /etc/nginx/nginx.conf; then # 使用主配置文件测试
            systemctl reload nginx
            if [[ $? -eq 0 ]]; then echo -e "${GREEN}[✓] Nginx 已成功重载。${NC}";
            else echo -e "${RED}[✗] Nginx 重载失败。${NC}"; fi
        else
            echo -e "${RED}[✗] Nginx 配置检查失败 (nginx -t)，无法重载。请手动检查 Nginx 配置。${NC}";
        fi
    fi

    echo -e "\n${GREEN}[✓] 域名 ${domain_to_delete} 的配置删除操作完成。${NC}"
}


# 查看所有配置并提供删除选项
view_all_configurations_and_manage() {
    echo -e "${BLUE}--- 扫描并显示所有检测到的配置 (${CERT_PATH_PREFIX}/*) ---${NC}"
    local found_configs=0
    declare -a managed_domains # 存储找到的域名列表

    # 检查证书存放根目录是否存在
    if [[ ! -d "$CERT_PATH_PREFIX" ]]; then
        echo -e "${YELLOW}证书根目录 ${CERT_PATH_PREFIX} 不存在。无法扫描配置。${NC}"
        return
    fi

    # 遍历证书存放根目录下的所有子目录
    for domain_cert_dir in "$CERT_PATH_PREFIX"/*/; do
        # 检查是否是一个目录
        if [[ -d "$domain_cert_dir" ]]; then
            local potential_domain=$(basename "$domain_cert_dir")
            # 简单校验目录名是否像一个域名
            if [[ "$potential_domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                managed_domains+=("$potential_domain") # 添加到域名列表
                ((found_configs++))
                echo -e "\n${CYAN}检测到域名 [${found_configs}]: ${potential_domain}${NC}"
                # 更新路径变量以检查该域名的相关文件
                update_paths_for_domain "$potential_domain"

                # 1. 检查本地证书副本状态
                local cert_file="${CERT_PATH}/cert.pem"
                local expiry_msg="${RED}证书文件未找到${NC}"
                if [[ -f "$cert_file" ]]; then
                    # 尝试读取证书过期日期
                    local expiry_date_str=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)
                    if [[ -n "$expiry_date_str" ]]; then
                        # 尝试将日期转换为秒数进行比较
                        local expiry_epoch=$(date -d "$expiry_date_str" +%s 2>/dev/null)
                        local current_epoch=$(date +%s)
                        if [[ -n "$expiry_epoch" ]]; then
                            local days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
                            if [[ "$expiry_epoch" -gt "$current_epoch" ]]; then
                                expiry_msg="${GREEN}有效${NC}, 到期: ${YELLOW}${expiry_date_str}${NC} (${days_left} 天)"
                            else
                                expiry_msg="${RED}已过期${NC} (${expiry_date_str})"
                            fi
                        else
                            expiry_msg="${RED}无法解析过期日期 (${expiry_date_str})${NC}"
                        fi
                    else
                         expiry_msg="${RED}无法读取证书过期日期${NC}"
                    fi
                fi
                echo -e "  - 本地证书: $expiry_msg"

                # 2. 检查 Nginx 配置
                local nginx_enabled_link="/etc/nginx/sites-enabled/${potential_domain}.conf"
                local nginx_msg=""
                if [[ -f "$NGINX_CONF_PATH" ]]; then
                    local proxy_pass_target=$(grep -oP 'proxy_pass\s+\K[^;]+' "$NGINX_CONF_PATH" | head -n 1)
                    # 读取监听端口
                    local http_port_in_conf=$(grep -oP 'listen\s+\K[0-9]+(?=;)' "$NGINX_CONF_PATH" | head -n 1)
                    local https_port_in_conf=$(grep -oP 'listen\s+\K[0-9]+(?=\s+ssl)' "$NGINX_CONF_PATH" | head -n 1)
                    local is_enabled_status="${RED}未启用${NC}"
                    if [[ -L "$nginx_enabled_link" ]]; then
                        is_enabled_status="${GREEN}已启用${NC}"
                    fi
                    nginx_msg="${GREEN}找到配置文件${NC} ($is_enabled_status)"
                    nginx_msg+="\n    - HTTP 端口: ${YELLOW}${http_port_in_conf:-未知}${NC}"
                    nginx_msg+="\n    - HTTPS 端口: ${YELLOW}${https_port_in_conf:-未知}${NC}"
                    if [[ -n "$proxy_pass_target" ]]; then
                        nginx_msg+="\n    - 反代目标: ${YELLOW}${proxy_pass_target}${NC}"
                    else
                        nginx_msg+="\n    - ${RED}未找到反代目标 (proxy_pass)${NC}"
                    fi
                else
                    nginx_msg="${YELLOW}未找到配置文件${NC}"
                fi
                echo -e "  - Nginx 配置: $nginx_msg"

                # 3. 检查 DDNS 配置
                local cron_ddns_entry=$(crontab -l 2>/dev/null | grep -F "# DDNSUpdate_${potential_domain}")
                local ddns_msg=""
                if [[ -f "$DDNS_SCRIPT_PATH" ]]; then
                    local ddns_record_type=$(grep 'RECORD_TYPE=' "$DDNS_SCRIPT_PATH" | head -n 1 | cut -d'"' -f2)
                    local cron_freq=$(echo "$cron_ddns_entry" | grep -oP '\*/\K[0-9]+' || echo "未知")
                    ddns_msg="${GREEN}找到 DDNS 脚本${NC}\n    - 记录类型: ${YELLOW}${ddns_record_type:-未知}${NC}"
                    if [[ -n "$cron_ddns_entry" ]]; then
                        ddns_msg+="\n    - Cron 计划: ${GREEN}已设置${NC} (频率: ${YELLOW}${cron_freq} 分钟${NC})"
                    else
                        ddns_msg+="\n    - Cron 计划: ${RED}未找到${NC}"
                    fi
                else
                    ddns_msg="${YELLOW}未找到 DDNS 脚本${NC}"
                     if [[ -n "$cron_ddns_entry" ]]; then
                        ddns_msg+=" (${YELLOW}但找到 Cron 任务?${NC})"
                    fi
                fi
                echo -e "  - DDNS 配置: $ddns_msg"

                # 4. 检查续期钩子和 Cron
                local cron_renew_entry=$(crontab -l 2>/dev/null | grep -F "# CertRenew_${potential_domain}")
                local renew_msg=""
                if [[ -f "$DEPLOY_HOOK_SCRIPT" ]]; then
                    renew_msg="${GREEN}找到续期钩子脚本${NC}"
                    if [[ -n "$cron_renew_entry" ]]; then
                        renew_msg+="\n    - Cron 计划: ${GREEN}已设置${NC}"
                    else
                        renew_msg+="\n    - Cron 计划: ${RED}未找到${NC}"
                    fi
                else
                    renew_msg="${YELLOW}未找到续期钩子脚本${NC}"
                    if [[ -n "$cron_renew_entry" ]]; then
                        renew_msg+=" (${YELLOW}但找到 Cron 任务?${NC})"
                    fi
                fi
                echo -e "  - 续期钩子: $renew_msg"

                # 5. 检查 CF 凭证文件
                local cf_cred_msg="${RED}未找到${NC}"
                if [[ -f "$CLOUDFLARE_CREDENTIALS" ]]; then cf_cred_msg="${GREEN}找到${NC}"; fi
                echo -e "  - CF 凭证: $cf_cred_msg"
            fi
        fi
    done

    if [[ $found_configs -eq 0 ]]; then
        echo -e "${YELLOW}未在 ${CERT_PATH_PREFIX} 下检测到任何符合条件的域名配置目录。${NC}"
        echo -e "\n${BLUE}--- 扫描结束 ---${NC}"
        return
    fi
    echo -e "\n${BLUE}--- 扫描结束 ---${NC}"

    # --- 使用序号选择删除 ---
    read -p "是否要删除以上列出的某个域名的配置? (yes/no) [no]: " wanna_delete
    if [[ "$wanna_delete" == "yes" ]]; then
        echo "当前检测到的域名:"
        # 再次显示带序号的列表
        for i in "${!managed_domains[@]}"; do
            echo "  $((i+1)). ${managed_domains[$i]}"
        done
        read -p "请输入要删除配置的域名【序号】(从上面列表中选择): " domain_index_to_delete

        # 验证输入是否为有效序号
        if [[ "$domain_index_to_delete" =~ ^[0-9]+$ && "$domain_index_to_delete" -ge 1 && "$domain_index_to_delete" -le ${#managed_domains[@]} ]]; then
            # 计算数组索引 (序号从 1 开始，索引从 0 开始)
            local actual_index=$((domain_index_to_delete - 1))
            # 获取对应的域名
            local domain_to_delete_name="${managed_domains[$actual_index]}"
            echo -e "您选择了序号 ${domain_index_to_delete}，对应的域名是: ${YELLOW}${domain_to_delete_name}${NC}"
            # 调用删除函数
            delete_domain_configuration "$domain_to_delete_name"
        else
            echo -e "${RED}输入的序号 '$domain_index_to_delete' 无效。请输入 1 到 ${#managed_domains[@]} 之间的数字。${NC}";
        fi
    fi
    # --- 删除选择修改结束 ---
    echo -e "${YELLOW}提示：目前脚本不支持直接修改现有配置，如需修改，请考虑删除后重新设置。${NC}"
}


# --- 主逻辑循环 ---
while true; do
    # 清屏或打印分隔符，让界面更清晰
    # clear # 或者使用下面的分隔线
    echo -e "\n${GREEN}===================================================================${NC}"
    echo -e "${GREEN}=== Let's Encrypt + Cloudflare + DDNS + Nginx 部署脚本 V2.6 ===${NC}"
    echo -e "${GREEN}===================================================================${NC}"
    echo "请选择操作:"
    echo "  1. 首次设置新域名 (申请证书, 配置 DNS/DDNS, Nginx[可选自定义端口])"
    echo "  2. 手动触发一次 DDNS 更新检查 (需要域名已配置)"
    echo "  3. 强制续期证书 (谨慎使用! 可能受 Let's Encrypt 速率限制)"
    echo "  4. 查看/删除已配置域名信息 (按序号选择删除)"
    echo "  5. 退出脚本"
    read -p "请输入选项 [1-5]: " main_choice

    case $main_choice in
        1) # 首次设置
           get_user_input_initial      # 获取用户输入 (邮箱已固定)
           install_packages            # 安装依赖包 (根据是否选 Nginx 决定)
           create_cf_credentials       # 创建 CF 凭证文件
           detect_public_ip            # 检测公网 IP
           select_record_type          # 选择 DNS 记录类型 (A/AAAA)
           get_zone_id                 # 获取 CF Zone ID
           manage_cloudflare_record "create/update" # 检查/创建/更新 CF DNS 记录
           request_certificate         # 申请 Let's Encrypt 证书
           copy_certificate            # 复制证书到工作目录
           setup_nginx_proxy           # 配置 Nginx (可选, 含端口自定义, 优化协议选择, 修复跳转)
           create_ddns_script          # 创建 DDNS 更新脚本 (如果启用)
           setup_cron_jobs             # 设置 Cron 任务 (证书续期和 DDNS)
           echo -e "\n${GREEN}[✓] 域名 ${DOMAIN} 设置完成！${NC}"
           ;;
        2) # 手动触发 DDNS
           read -p "请输入要手动触发 DDNS 更新的域名: " DOMAIN_FOR_DDNS
           if [[ -z "$DOMAIN_FOR_DDNS" ]]; then echo "${YELLOW}未输入域名。${NC}"; continue; fi
           update_paths_for_domain "$DOMAIN_FOR_DDNS" # 设置相关路径
           if [[ -f "$DDNS_SCRIPT_PATH" ]]; then
               echo "正在执行 DDNS 更新脚本: $DDNS_SCRIPT_PATH ..."
               # 直接执行脚本
               bash "$DDNS_SCRIPT_PATH"
               echo "DDNS 更新检查完成，请查看日志文件获取详细信息: /var/log/cf_ddns_update_${DOMAIN_FOR_DDNS}.log"
           else
               echo -e "${RED}[✗] 未找到域名 ${DOMAIN_FOR_DDNS} 的 DDNS 更新脚本 ($DDNS_SCRIPT_PATH)。请确保该域名已配置并启用了 DDNS。${NC}";
           fi
           ;;
        3) # 强制续期
           read -p "请输入要强制续期的域名: " DOMAIN_FOR_RENEW
           if [[ -z "$DOMAIN_FOR_RENEW" ]]; then echo "${YELLOW}未输入域名。${NC}"; continue; fi
           update_paths_for_domain "$DOMAIN_FOR_RENEW" # 设置相关路径

           echo -e "${YELLOW}警告：强制续期受 Let's Encrypt 的速率限制 (每个注册域名每周最多 5 次)。过度使用可能导致暂时无法申请/续期。${NC}"
           read -p "确认强制续期 ${DOMAIN_FOR_RENEW} 吗? (yes/no) [no]: " confirm_force_renew
           if [[ "$confirm_force_renew" == "yes" ]]; then
               local cf_creds_renew="/root/.cloudflare-${DOMAIN_FOR_RENEW}.ini"
               local deploy_hook_renew="/root/cert-renew-hook-${DOMAIN_FOR_RENEW}.sh"
               local deploy_hook_arg=""

               # 检查 CF 凭证文件是否存在
               if [[ ! -f "$cf_creds_renew" ]]; then
                   echo -e "${RED}[✗] 未找到 Cloudflare 凭证文件 ($cf_creds_renew)。无法续期。${NC}";
               else
                   # 检查部署钩子脚本是否存在，如果存在则添加到命令中
                   if [[ -f "$deploy_hook_renew" ]]; then
                       deploy_hook_arg="--deploy-hook \"$deploy_hook_renew\""
                       echo "将使用部署钩子: $deploy_hook_renew"
                   else
                       echo -e "${YELLOW}[!] 未找到部署钩子脚本 ($deploy_hook_renew)，续期后将不会执行钩子操作 (如复制证书、重载 Nginx)。${NC}";
                   fi

                   echo "正在尝试强制续期 $DOMAIN_FOR_RENEW ..."
                   # 执行强制续期命令
                   certbot certonly \
                       --dns-cloudflare \
                       --dns-cloudflare-credentials "$cf_creds_renew" \
                       --dns-cloudflare-propagation-seconds 60 \
                       -d "$DOMAIN_FOR_RENEW" \
                       --email "$EMAIL" \
                       --force-renewal \
                       --non-interactive \
                       $deploy_hook_arg # 传递钩子参数 (如果存在)

                   if [[ $? -eq 0 ]]; then
                       echo -e "${GREEN}[✓] 强制续期命令执行成功。请检查 certbot 日志确认结果。${NC}"
                       # 如果没有钩子，提示手动操作
                       if [[ -z "$deploy_hook_arg" ]]; then
                            echo -e "${YELLOW}提醒：由于未找到部署钩子，您可能需要手动复制新证书并重载相关服务 (如 Nginx)。${NC}"
                       fi
                   else
                       echo -e "${RED}[✗] 强制续期命令执行失败。请检查 certbot 日志 (/var/log/letsencrypt/letsencrypt.log) 获取详细信息。${NC}"
                   fi
               fi
           else
               echo "操作取消。";
           fi
           ;;
        4) # 查看/删除配置
           install_packages # 确保 jq, openssl 等命令可用
           view_all_configurations_and_manage # 已修改为按序号删除
           ;;
        5) # 退出
           echo "退出脚本。";
           exit 0
           ;;
        *) # 无效选项
           echo -e "${RED}无效选项 '$main_choice'。请输入 1 到 5 之间的数字。${NC}";
           ;;
    esac
    # 在每个操作后暂停，等待用户按 Enter 返回主菜单
    echo -e "\n${BLUE}按 Enter键 返回主菜单...${NC}"; read -r
done

# 脚本正常结束时的退出码
exit 0
