#!/bin/bash

echo "=== Let's Encrypt 证书申请脚本（基于 Cloudflare DNS 验证）==="

# 获取用户输入
read -p "请输入您要申请的域名: " DOMAIN
read -p "请输入您的 Cloudflare API Token: " CF_API_TOKEN

CERT_DST="/root/cert/$DOMAIN"

echo "[1] 安装必要组件..."
apt update -y && apt install -y curl sudo cron python3-certbot-dns-cloudflare

echo "[2] 创建 API 凭证文件..."
mkdir -p ~/.secrets
CF_INI=~/.secrets/cloudflare.ini
cat > "$CF_INI" <<EOF
dns_cloudflare_api_token = $CF_API_TOKEN
EOF
chmod 600 "$CF_INI"

echo "[3] 申请证书中..."
certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials "$CF_INI" \
  --dns-cloudflare-propagation-seconds 30 \
  -d "$DOMAIN" \
  --non-interactive \
  --agree-tos \
  -m your@mail.com

if [ $? -ne 0 ]; then
  echo "❌ 证书申请失败，请检查 Cloudflare API Token 和域名配置是否正确。"
  exit 1
fi

echo "[4] 复制证书到 $CERT_DST ..."
mkdir -p "$CERT_DST"
cp /etc/letsencrypt/live/$DOMAIN/*.pem "$CERT_DST/"

echo "[5] 写入 deploy-hook 脚本以支持自动续期同步..."
HOOK_SCRIPT="/root/certbot-deploy-hook.sh"
cat > "$HOOK_SCRIPT" <<EOF
#!/bin/bash
CERT_SRC="/etc/letsencrypt/live/$DOMAIN"
CERT_DST="/root/cert/$DOMAIN"

mkdir -p "\$CERT_DST"
cp -f "\$CERT_SRC/privkey.pem" "\$CERT_DST/"
cp -f "\$CERT_SRC/fullchain.pem" "\$CERT_DST/"
cp -f "\$CERT_SRC/cert.pem" "\$CERT_DST/"
cp -f "\$CERT_SRC/chain.pem" "\$CERT_DST/"
EOF

chmod +x "$HOOK_SCRIPT"

echo "[6] 添加定时续期任务（每天凌晨2点）..."
(crontab -l 2>/dev/null; echo "0 2 * * * certbot renew --deploy-hook \"$HOOK_SCRIPT\" >> /var/log/letsencrypt/renew.log 2>&1") | crontab -

echo "✅ 完成！证书文件已复制到: $CERT_DST"
echo "📆 自动续期任务已添加，可通过 crontab -l 查看。"
