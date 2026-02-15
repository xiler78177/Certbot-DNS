#!/bin/sh
# install.sh - 引导脚本，确保 bash/curl 存在后拉取主脚本执行
set -e

REPO_URL="https://raw.githubusercontent.com/xiler78177/Certbot-DNS/main/1.sh"

# 检测并安装 bash
if ! command -v bash >/dev/null 2>&1; then
    echo "[!] 未检测到 bash，正在自动安装..."
    if command -v opkg >/dev/null 2>&1; then
        opkg update >/dev/null 2>&1
        opkg install bash curl ca-bundle || { echo "[✗] 安装失败，请手动: opkg install bash curl ca-bundle"; exit 1; }
    elif command -v apt-get >/dev/null 2>&1; then
        apt-get update && apt-get install -y bash curl
    elif command -v yum >/dev/null 2>&1; then
        yum install -y bash curl
    else
        echo "[✗] 无法自动安装 bash，请手动安装后重试"; exit 1
    fi
fi

# 检测并安装 curl
if ! command -v curl >/dev/null 2>&1; then
    echo "[!] 未检测到 curl，正在安装..."
    if command -v opkg >/dev/null 2>&1; then
        opkg install curl ca-bundle
    elif command -v apt-get >/dev/null 2>&1; then
        apt-get install -y curl
    fi
fi

echo "[✓] 环境就绪，启动主脚本..."
curl -sSL "$REPO_URL" -o /tmp/_main_script.sh
exec bash /tmp/_main_script.sh "$@"
