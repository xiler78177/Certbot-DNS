#!/bin/bash

echo -e "\n========== Let's Encrypt + Cloudflare DNS 一键证书脚本 ==========\n"

read -rp "请输入您要申请的域名（如：example.com）: " DOMAIN
read -rp "请输入您的 Cloudflare API Token: " CF_API_TOKEN
read -rp "请输入用于接收 Let's Encrypt 通知的邮箱: " EMAIL

CERT_DIR="/root/cert/${DOMAIN}"
CRED_FILE="/root/.secrets/certbot/cloudflare.ini"
HOOK_FILE="/etc/letsencrypt/renewal-hooks/pre/cloudflare-dns.sh"

echo -e "\n[1] 安装依赖..."
apt update &>/dev/null
apt install -y curl socat jq python3-certbot-dns-cloudflare certbot &>/dev/null

echo -e "\n[2] 创建 Cloudflare 凭证文件..."
mkdir -p "$(dirname $CRED_FILE)"
cat > "$CRED_FILE" <<EOF
dns_cloudflare_api_token = $CF_API_TOKEN
EOF
chmod 600 "$CRED_FILE"

echo -e "\n[3] 正在申请证书..."
certbot certonly \
  --non-interactive \
  --agree-tos \
  --email "$EMAIL" \
  --dns-cloudflare \
  --dns-cloudflare-credentials "$CRED_FILE" \
  --dns-cloudflare-propagation-seconds 30 \
  -d "$DOMAIN"

if [[ $? -ne 0 ]]; then
  echo -e "\n❌ 证书申请失败，请检查 Cloudflare Token 和域名设置。"
  exit 1
fi

echo -e "\n[4] 拷贝证书文件到 $CERT_DIR ..."
mkdir -p "$CERT_DIR"
cp -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$CERT_DIR/cert.pem"
cp -f "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$CERT_DIR/key.pem"

echo -e "\n[5] 写入 deploy-hook 自动续期同步脚本..."
cat > /etc/letsencrypt/renewal-hooks/deploy/copy-cert.sh <<EOF
#!/bin/bash
cp -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$CERT_DIR/cert.pem"
cp -f "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$CERT_DIR/key.pem"
EOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/copy-cert.sh

echo -e "\n[6] 写入 pre-hook 保证续期时 API Token 可用..."
mkdir -p "$(dirname "$HOOK_FILE")"
cat > "$HOOK_FILE" <<EOF
#!/bin/bash
echo "dns_cloudflare_api_token = $CF_API_TOKEN" > /tmp/cloudflare.ini
chmod 600 /tmp/cloudflare.ini
EOF
chmod +x "$HOOK_FILE"

echo -e "\n[7] 修改续期配置为临时 API 凭证路径..."
RENEW_CONF="/etc/letsencrypt/renewal/$DOMAIN.conf"
if grep -q "dns_cloudflare_credentials" "$RENEW_CONF"; then
  sed -i "s|dns_cloudflare_credentials = .*|dns_cloudflare_credentials = /tmp/cloudflare.ini|g" "$RENEW_CONF"
fi

echo -e "\n[8] 测试自动续期钩子是否正常运行..."
certbot renew --dry-run

echo -e "\n✅ 所有任务已完成，证书已保存于：$CERT_DIR"
