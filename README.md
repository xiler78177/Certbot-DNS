apt-get update && apt-get install -y curl && bash <(curl -sSL https://raw.githubusercontent.com/xiler78177/Certbot-DNS/main/issue-cert.sh)
# 服务器初始化与管理脚本
# 功能:
# 1.  **基础工具**: 安装常用软件包。
# 2.  **防火墙 (UFW)**: 安装、启用、管理端口规则 (增/删/查)。
# 3.  **入侵防御 (Fail2ban)**: 安装并配置 SSH 防护、重新配置、查看状态。
# 4.  **SSH 安全**: 更改端口、创建 sudo 用户、禁用 root 登录、配置密钥登录。
# 5.  **Web 服务 (LE + CF + Nginx)**:
#     - 自动申请 Let's Encrypt 证书 (使用 Cloudflare DNS 验证)。
#     - 支持 IPv4 (A) / IPv6 (AAAA) 记录自动检测与添加/更新。
#     - 支持 DDNS (动态域名解析)，自动更新 Cloudflare 记录。
#     - 自动配置 Nginx 反向代理 (支持自定义端口, HTTP/HTTPS 后端)。
#     - 证书自动续期与部署 (通过 Cron)。
#     - 集中查看/删除已配置域名信息。
