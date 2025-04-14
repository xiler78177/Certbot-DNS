#!/bin/bash

set -e

echo -e "\n=== Let's Encrypt + Cloudflare 一键证书部署脚本 ===\n"

# 1. 读取用户输入
read -p "请输入您要申请的域名（如 example.com）: " DOMAIN
read -p "请输入您的 Cloudflare API Token: " CF_API_TOKEN

CERT_PATH="/root/cert/${DOMAIN}"

echo -e "\n[1] 安装必要组件..."
apt update -y
apt install -y certbot python3-certbot-dns-cloudflare curl jq cron

# 2. 创建 Cloudflare API 配置文件
echo -e "\n[2] 创建 Cloudflare API 凭证配置..."
CLOUDFLARE_CREDENTIALS="/root/.cloudflare-${DOMAIN}.ini"
cat > "$CLOUDFLARE_CREDENTIALS" <<EOF
dns_cloudflare_api_token = $CF_API_TOKEN
EOF
chmod 600 "$CLOUDFLARE_CREDENTIALS"

# 3. 自动添加 A 记录到 Cloudflare
echo -e "\n[3] 检查并自动添加 A 记录..."
CF_API="https://api.cloudflare.com/client/v4"
IP=$(curl -s https://api.ipify.org)

# 获取 zone_id
ZONE_NAME=$(echo "$DOMAIN" | awk -F. '{print $(NF-1)"."$NF}')
ZONE_ID=$(curl -s -X GET "$CF_API/zones?name=$ZONE_NAME" \
     -H "Authorization: Bearer $CF_API_TOKEN" \
     -H "Content-Type: application/json" | jq -r '.result[0].id')

# 检查是否已存在记录
RECORD_ID=$(curl -s -X GET "$CF_API/zones/$ZONE_ID/dns_records?type=A&name=$DOMAIN" \
    -H "Authorization: Bearer $CF_API_TOKEN" \
    -H "Content-Type: application/json" | jq -r '.result[0].id')

if [[ "$RECORD_ID" == "null" || -z "$RECORD_ID" ]]; then
  echo "未找到 A 记录，正在创建..."
  curl -s -X POST "$CF_API/zones/$ZONE_ID/dns_records" \
    -H "Authorization: Bearer $CF_API_TOKEN" \
    -H "Content-Type: application/json" \
    --data "{\"type\":\"A\",\"name\":\"$DOMAIN\",\"content\":\"$IP\",\"ttl\":120,\"proxied\":false}" > /dev/null
  echo "✅ A 记录创建成功：$DOMAIN -> $IP"
else
  echo "✅ 已存在 A 记录：$DOMAIN"
fi

# 4. 申请证书
echo -e "\n[4] 申请 SSL 证书..."
certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials "$CLOUDFLARE_CREDENTIALS" \
  -d "$DOMAIN" --email your@mail.com --agree-tos --no-eff-email --non-interactive

# 5. 同步证书文件
echo -e "\n[5] 复制证书文件到 $CERT_PATH"
mkdir -p "$CERT_PATH"
cp "/etc/letsencrypt/live/${DOMAIN}/"*.pem "$CERT_PATH/"

# 6. 设置自动续期钩子
echo -e "\n[6] 设置自动续期钩子脚本..."
DEPLOY_HOOK="/root/cert-renew-hook-${DOMAIN}.sh"
cat > "$DEPLOY_HOOK" <<EOF
#!/bin/bash
cp /etc/letsencrypt/live/${DOMAIN}/*.pem $CERT_PATH/
EOF
chmod +x "$DEPLOY_HOOK"

# 7. 创建定时任务
echo -e "\n[7] 配置定时任务自动续期..."
(crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --deploy-hook \"$DEPLOY_HOOK\" > /dev/null 2>&1") | crontab -

echo -e "\n✅ 所有操作完成！证书已申请并配置自动续期。\n证书位置: $CERT_PATH"
