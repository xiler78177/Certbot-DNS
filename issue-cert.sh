#!/bin/bash

CERT_DIR="/root/cert"
NGINX_CONF_DIR="/etc/nginx/conf.d"
CONFIG_FILE="/root/ddns_config.json"

# 显示主菜单
main_menu() {
    while true; do
        clear
        echo "=============================="
        echo "  证书自动化与反代管理脚本"
        echo "=============================="
        echo "1. 申请/续期证书"
        echo "2. 自动添加 DNS 解析 (A/AAAA)"
        echo "3. 启用 DDNS 动态域名解析"
        echo "4. 配置 Nginx 反向代理"
        echo "5. 查看当前配置"
        echo "0. 退出脚本"
        echo "=============================="
        read -p "请输入选项: " choice

        case $choice in
            1) issue_cert_menu ;;
            2) dns_record_menu ;;
            3) setup_ddns_menu ;;
            4) nginx_menu ;;
            5) show_config ;;
            0) exit 0 ;;
            *) echo "无效选项，按任意键返回菜单..." ; read ;;
        esac
    done
}

# 证书申请子菜单
issue_cert_menu() {
    clear
    echo "[申请证书]"
    read -p "请输入要申请的域名: " DOMAIN
    read -p "请输入 Cloudflare API Token: " CF_API_TOKEN

    mkdir -p /root/.cf
    echo "dns_cloudflare_api_token = $CF_API_TOKEN" > /root/.cf/cloudflare.ini
    chmod 600 /root/.cf/cloudflare.ini

    certbot certonly --dns-cloudflare --dns-cloudflare-credentials /root/.cf/cloudflare.ini         --dns-cloudflare-propagation-seconds 30 -d "$DOMAIN"         --email your@mail.com --agree-tos --no-eff-email --non-interactive

    mkdir -p "$CERT_DIR/$DOMAIN"
    cp -L /etc/letsencrypt/live/$DOMAIN/* "$CERT_DIR/$DOMAIN/"

    echo "证书申请完成，已保存到 $CERT_DIR/$DOMAIN"
    echo "配置自动续期任务"
    echo "0 4 * * * root certbot renew --deploy-hook 'cp -L /etc/letsencrypt/live/$DOMAIN/* $CERT_DIR/$DOMAIN/'" > /etc/cron.d/cert_renew
    echo "按任意键返回菜单..." ; read
}

# DNS 自动添加记录
dns_record_menu() {
    clear
    echo "[DNS 添加记录]"
    read -p "请输入域名: " DOMAIN
    read -p "请输入 Cloudflare API Token: " CF_API_TOKEN

    ipv4=$(curl -s4 ifconfig.co)
    ipv6=$(curl -s6 ifconfig.co)
    echo "检测到的 IP:"
    echo "IPv4: ${ipv4:-无}"
    echo "IPv6: ${ipv6:-无}"
    echo "请选择绑定哪一个:"
    echo "1. IPv4"
    echo "2. IPv6"
    echo "0. 返回上一级菜单"
    read -p "选择 (1/2/0): " ip_choice

    if [[ $ip_choice == "1" ]]; then
        ip="$ipv4"
        type="A"
    elif [[ $ip_choice == "2" ]]; then
        ip="$ipv6"
        type="AAAA"
    else
        return
    fi

    zone_id=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=${DOMAIN#*.}"         -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" | jq -r '.result[0].id')
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records"         -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json"         --data "{"type":"$type","name":"$DOMAIN","content":"$ip","ttl":120,"proxied":false}" > /dev/null

    echo "$type 记录添加完成: $DOMAIN -> $ip"
    echo "按任意键返回菜单..." ; read
}

# 配置 DDNS
setup_ddns_menu() {
    clear
    echo "[设置 DDNS]"
    read -p "请输入完整域名: " DOMAIN
    read -p "请输入 Cloudflare API Token: " CF_API_TOKEN
    read -p "请输入检测间隔时间（分钟）: " INTERVAL

    cat > /usr/local/bin/ddns_update.sh <<EOF
#!/bin/bash
IPV4=\$(curl -s4 ifconfig.co)
RECORD_ID=\$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=\${DOMAIN#*.}" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" | jq -r '.result[0].id')
curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/\$RECORD_ID/dns_records" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" --data "{"type":"A","name":"$DOMAIN","content":"\$IPV4","ttl":120,"proxied":false}" > /dev/null
EOF

    chmod +x /usr/local/bin/ddns_update.sh
    echo "*/$INTERVAL * * * * root /usr/local/bin/ddns_update.sh" > /etc/cron.d/ddns_update
    echo "DDNS 配置完成，每 $INTERVAL 分钟自动更新 IP"
    echo "按任意键返回菜单..." ; read
}

# Nginx 配置
nginx_menu() {
    clear
    echo "[反向代理配置]"
    read -p "请输入要反代的域名: " DOMAIN
    read -p "请输入要反代的 IP:PORT（如 192.168.1.100:8000）: " TARGET

    cat > "$NGINX_CONF_DIR/$DOMAIN.conf" <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    location / {
        proxy_pass http://$TARGET;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF

    nginx -t && systemctl reload nginx
    echo "反向代理配置已写入: $NGINX_CONF_DIR/$DOMAIN.conf"
    echo "按任意键返回菜单..." ; read
}

# 查看配置
show_config() {
    clear
    echo "[当前配置信息]"
    echo "- 已申请证书目录:"
    ls "$CERT_DIR" 2>/dev/null || echo "暂无证书"
    echo "- 当前 Nginx 配置:"
    ls "$NGINX_CONF_DIR" 2>/dev/null || echo "暂无反代配置"
    echo "- DDNS 配置:"
    cat /etc/cron.d/ddns_update 2>/dev/null || echo "未配置"
    echo "按任意键返回菜单..." ; read
}

main_menu
