#!/bin/bash

set -e

CONFIG_DIR="/root/cert_toolkit"
mkdir -p "$CONFIG_DIR"

function get_ip_info() {
  IPV4=$(curl -s -4 https://api.ipify.org || echo "无")
  IPV6=$(curl -s -6 https://api6.ipify.org || echo "无")

  echo -e "\n当前主机 IP 信息："
  echo "IPv4: $IPV4"
  echo "IPv6: $IPV6"
}

function select_ip_version() {
  get_ip_info
  echo -e "\n请选择使用的 IP 版本："
  echo "1) IPv4 ($IPV4)"
  echo "2) IPv6 ($IPV6)"
  read -p "请输入选项 [1-2]: " IP_CHOICE
  if [[ "$IP_CHOICE" == "1" ]]; then
    SELECTED_IP=$IPV4
  else
    SELECTED_IP=$IPV6
  fi
}

function apply_cert() {
  read -p "请输入您要申请的域名（如 example.com）: " DOMAIN
  read -p "请输入您的 Cloudflare API Token: " CF_API_TOKEN

  # 设置证书保存路径
  DEFAULT_PATH="/root/cert/${DOMAIN}"
  read -p "请输入证书保存路径（默认: ${DEFAULT_PATH}）: " CUSTOM_PATH
  CERT_PATH=${CUSTOM_PATH:-$DEFAULT_PATH}

  select_ip_version
  CLOUDFLARE_CREDENTIALS="$CONFIG_DIR/.cloudflare-${DOMAIN}.ini"

  echo -e "\n[1] 安装必要组件..."
  apt update -y
  apt install -y certbot python3-certbot-dns-cloudflare curl jq cron nginx

  echo -e "\n[2] 创建 Cloudflare API 凭证配置..."
  echo "dns_cloudflare_api_token = $CF_API_TOKEN" > "$CLOUDFLARE_CREDENTIALS"
  chmod 600 "$CLOUDFLARE_CREDENTIALS"

  echo -e "\n[3] 添加 DNS 记录..."
  CF_API="https://api.cloudflare.com/client/v4"
  ZONE_NAME=$(echo "$DOMAIN" | awk -F. '{print $(NF-1)"."$NF}')
  ZONE_ID=$(curl -s -X GET "$CF_API/zones?name=$ZONE_NAME" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" | jq -r '.result[0].id')
  RECORD_TYPE="A"
  [[ "$SELECTED_IP" == *:* ]] && RECORD_TYPE="AAAA"
  RECORD_ID=$(curl -s -X GET "$CF_API/zones/$ZONE_ID/dns_records?type=$RECORD_TYPE&name=$DOMAIN" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" | jq -r '.result[0].id')

  if [[ "$RECORD_ID" == "null" || -z "$RECORD_ID" ]]; then
    curl -s -X POST "$CF_API/zones/$ZONE_ID/dns_records" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" --data "{"type":"$RECORD_TYPE","name":"$DOMAIN","content":"$SELECTED_IP","ttl":120,"proxied":false}" > /dev/null
    echo "✅ DNS记录创建成功：$DOMAIN -> $SELECTED_IP"
  else
    echo "✅ DNS记录已存在：$DOMAIN"
  fi

  echo -e "\n[4] 申请 SSL 证书..."
  certbot certonly --dns-cloudflare --dns-cloudflare-credentials "$CLOUDFLARE_CREDENTIALS" -d "$DOMAIN" --email your@mail.com --agree-tos --no-eff-email --non-interactive

  echo -e "\n[5] 复制证书文件到 $CERT_PATH..."
  mkdir -p "$CERT_PATH"
  cp "/etc/letsencrypt/live/${DOMAIN}/"*.pem "$CERT_PATH/"

  echo -e "\n[6] 设置自动续期钩子..."
  DEPLOY_HOOK="$CONFIG_DIR/cert-renew-hook-${DOMAIN}.sh"
  echo "#!/bin/bash\ncp /etc/letsencrypt/live/${DOMAIN}/*.pem $CERT_PATH/" > "$DEPLOY_HOOK"
  chmod +x "$DEPLOY_HOOK"

  echo -e "\n[7] 配置自动续期任务..."
  (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --deploy-hook \"$DEPLOY_HOOK\" > /dev/null 2>&1") | crontab -
  echo -e "\n✅ 证书部署完成！"
}

function ddns_daemon_systemd() {
  read -p "请输入域名: " DOMAIN
  read -p "请输入 Cloudflare API Token: " CF_API_TOKEN
  CLOUDFLARE_CREDENTIALS="$CONFIG_DIR/.cloudflare-${DOMAIN}.ini"
  echo "dns_cloudflare_api_token = $CF_API_TOKEN" > "$CLOUDFLARE_CREDENTIALS"

  # 写 DDNS 脚本
  DDNS_SCRIPT="$CONFIG_DIR/ddns-${DOMAIN}.sh"
  cat > "$DDNS_SCRIPT" <<EOF
#!/bin/bash
IP_FILE="/tmp/current_ip.txt"
CF_API="https://api.cloudflare.com/client/v4"
DOMAIN="$DOMAIN"
ZONE_NAME=\$(echo "\$DOMAIN" | awk -F. '{print \$(NF-1)"."\$NF}')
ZONE_ID=\$(curl -s -X GET "\$CF_API/zones?name=\$ZONE_NAME" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" | jq -r '.result[0].id')

while true; do
  NEW_IP=\$(curl -s https://api.ipify.org)
  OLD_IP=\$(cat \$IP_FILE 2>/dev/null)
  if [[ "\$NEW_IP" != "\$OLD_IP" ]]; then
    RECORD_ID=\$(curl -s -X GET "\$CF_API/zones/\$ZONE_ID/dns_records?type=A&name=\$DOMAIN" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" | jq -r '.result[0].id')
    curl -s -X PUT "\$CF_API/zones/\$ZONE_ID/dns_records/\$RECORD_ID" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" --data "{"type":"A","name":"\$DOMAIN","content":"\$NEW_IP","ttl":120,"proxied":false}"
    echo "\$NEW_IP" > \$IP_FILE
    echo "[\$(date)] IP已更新为 \$NEW_IP"
  fi
  sleep 300
done
EOF

  chmod +x "$DDNS_SCRIPT"

  # 写 systemd service 文件
  SERVICE_FILE="/etc/systemd/system/ddns-${DOMAIN}.service"
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=DDNS Update for $DOMAIN
After=network.target

[Service]
ExecStart=$DDNS_SCRIPT
Restart=always

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reexec
  systemctl daemon-reload
  systemctl enable ddns-${DOMAIN}
  systemctl start ddns-${DOMAIN}
  echo -e "\n✅ DDNS 守护进程已启动并注册为 systemd 服务: ddns-${DOMAIN}"
}

function main_menu() {
  while true; do
    echo -e "\n=== Let's Encrypt Toolkit 增强版 v3 ==="
    echo "1) 申请新证书（含 DNS 设置）"
    echo "2) 启用动态 DNS 守护进程（Systemd 模式）"
    echo "3) 查看本机 IP 信息"
    echo "0) 退出"
    read -p "请选择操作: " CHOICE
    case $CHOICE in
      1) apply_cert ;;
      2) ddns_daemon_systemd ;;
      3) get_ip_info ;;
      0) exit 0 ;;
      *) echo "无效选项，请重试。" ;;
    esac
  done
}

main_menu
