cat > install_fixed_v258.sh << 'EOF'
#!/bin/bash

# === 配置区域 ===
VERSION="v2.5.8"
MIRROR_URL="https://ghproxy.net/"
INSTALL_PATH="/usr/local/x-ui"
# ===============

echo -e "\033[32m>>> 开始安装 3x-ui 版本: ${VERSION} (集成修复版)\033[0m"

# 1. 环境检测与清理
arch=$(uname -m)
if [[ $arch == "x86_64" ]]; then
    file_arch="amd64"
elif [[ $arch == "aarch64" ]]; then
    file_arch="arm64"
else
    echo -e "\033[31m不支持的架构: $arch\033[0m"
    exit 1
fi

echo "正在停止旧服务..."
systemctl stop x-ui 2>/dev/null

# 2. 下载文件 (使用加速镜像)
cd /root/
FILENAME="x-ui-linux-${file_arch}.tar.gz"
DOWNLOAD_URL="${MIRROR_URL}https://github.com/mhsanaei/3x-ui/releases/download/${VERSION}/${FILENAME}"

echo "正在下载: $DOWNLOAD_URL"
wget --no-check-certificate -O "$FILENAME" "$DOWNLOAD_URL"

if [[ ! -s "$FILENAME" ]]; then
    echo -e "\033[31m下载失败或文件为空，请检查网络。\033[0m"
    rm -f "$FILENAME"
    exit 1
fi

# 3. 解压与安装
echo "正在解压..."
mkdir -p x-ui-temp
tar -zxvf "$FILENAME" -C x-ui-temp/

# 确保目标目录存在
mkdir -p ${INSTALL_PATH}/bin

# 复制文件 (修复路径层级问题)
# v2.5.8 解压后多一层 x-ui 目录，这里做兼容处理
if [ -d "x-ui-temp/x-ui" ]; then
    SOURCE_DIR="x-ui-temp/x-ui"
else
    SOURCE_DIR="x-ui-temp"
fi

echo "正在安装文件..."
yes | cp -rf ${SOURCE_DIR}/x-ui ${INSTALL_PATH}/
yes | cp -rf ${SOURCE_DIR}/bin/xray-linux-${file_arch} ${INSTALL_PATH}/bin/
cp -n ${SOURCE_DIR}/bin/*.dat ${INSTALL_PATH}/bin/ 2>/dev/null

# 赋予权限
chmod +x ${INSTALL_PATH}/x-ui
chmod +x ${INSTALL_PATH}/bin/xray-linux-${file_arch}

# 4. 写入系统服务 (关键修复：添加 WorkingDirectory)
echo "正在配置系统服务..."
cat > /etc/systemd/system/x-ui.service <<SERVICE
[Unit]
Description=x-ui Service
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_PATH}
ExecStart=${INSTALL_PATH}/x-ui
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
SERVICE

# 5. 清理与启动
rm -rf "$FILENAME" x-ui-temp
systemctl daemon-reload
systemctl enable x-ui
systemctl restart x-ui

# 6. 验证状态
sleep 2
is_active=$(systemctl is-active x-ui)
if [[ "$is_active" == "active" ]]; then
    echo -e "\033[32m------------------------------------------------"
    echo -e "✅ 安装并启动成功！当前版本: ${VERSION}"
    echo -e "   状态: 运行中 (Active)"
    echo -e "   请在浏览器访问面板进行后续配置。"
    echo -e "------------------------------------------------\033[0m"
else
    echo -e "\033[31m⚠️ 安装完成但启动失败，请使用 'systemctl status x-ui' 查看日志。\033[0m"
fi
EOF

# 立即执行
chmod +x install_fixed_v258.sh && ./install_fixed_v258.sh
