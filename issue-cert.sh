#!/bin/bash

# ==== 参数校验 ====
if [[ $# -ne 2 ]]; then
  echo "用法: $0 <你的域名> <Cloudflare API Token>"
  echo "示例: $0 send-5.niub.tk abcdef1234567890"
  exit 1
fi

DOMAIN="$1"
CF_API_TOKEN="$2"

# ==== 开始执行 ====

set -e

echo "[1] 安装 certbot 和 Cloudflare 插件..."
apt update && apt install -y certbot python3-certbot-dns-cloudflare

echo "[2] 创建 API 凭证文件..."
mkdir -p /root/.secrets/certbot
CRED_FILE="/root/.secrets/certbot/cloudflare.ini"
echo "dns_cloudflare_api_token = $CF_API_TOKEN" > "$CRED_FILE"
chmod 600 "$CRED_FILE"

echo "[3] 申请证书中..."
certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials "$CRED_FILE" \
  -d "$DOMAIN" \
  --deploy-hook "mkdir -p /root/cert && cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem /root/cert/fullchain.pem && cp /etc/letsencrypt/live/$DOMAIN/privkey.pem /root/cert/privkey.pem && chmod 600 /root/cert/*.pem"

echo "[4] 写入 deploy-hook 脚本以支持自动续期同步..."
HOOK_FILE="/etc/letsencrypt/renewal-hooks/deploy/copy-cert.sh"
cat > "$HOOK_FILE" <<EOF
#!/bin/bash
CERT_SRC="/etc/letsencrypt/live/$DOMAIN"
CERT_DST="/root/cert"

mkdir -p "\$CERT_DST"
cp "\$CERT_SRC/fullchain.pem" "\$CERT_DST/fullchain.pem"
cp "\$CERT_SRC/privkey.pem" "\$CERT_DST/privkey.pem"
chmod 600 "\$CERT_DST"/*.pem
EOF
chmod +x "$HOOK_FILE"

echo "[5] 测试续期钩子是否正常运行..."
certbot renew --dry-run

echo "✅ 成功：证书已申请，并保存至 /root/cert/ 下。"
