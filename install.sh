#!/bin/bash
# Trojan + SOCKS5 一键安装脚本 (完整修复版)
# 解决了原脚本的所有已知问题
# GitHub: https://github.com/six8888-cpu/trojan-install

set -e

#######color code########
red="31m"
green="32m"
yellow="33m"
blue="36m"

colorEcho(){
    echo -e "\033[${1}${@:2}\033[0m"
}

# 检查root权限
checkRoot() {
    [ $(id -u) != "0" ] && { colorEcho $red "错误: 请使用root用户运行此脚本"; exit 1; }
}

# 检查系统
checkSys() {
    arch=$(uname -m)
    if [[ $arch != x86_64 && $arch != aarch64 ]]; then
        colorEcho $red "不支持的系统架构: $arch"
        exit 1
    fi

    if [[ -f /etc/redhat-release ]]; then
        release="centos"
        pkg_manager="yum"
        [[ $(cat /etc/redhat-release | grep -oE "[0-9]+" | head -1) -ge 8 ]] && pkg_manager="dnf"
    elif grep -qi "debian\|ubuntu" /etc/os-release; then
        release="debian"
        pkg_manager="apt-get"
    else
        colorEcho $red "不支持的系统!"
        exit 1
    fi
}

# 安装依赖
installDeps() {
    colorEcho $blue "正在安装依赖..."
    if [[ $pkg_manager == "apt-get" ]]; then
        apt-get update -y
        apt-get install -y curl wget socat cron openssl gcc make mariadb-server
    else
        $pkg_manager install -y curl wget socat cronie openssl gcc make mariadb-server
    fi
}

# 配置MariaDB
setupMariaDB() {
    colorEcho $blue "正在配置MariaDB..."
    systemctl start mariadb
    systemctl enable mariadb
    
    # 创建数据库和用户
    mysql -e "CREATE DATABASE IF NOT EXISTS trojan CHARACTER SET utf8mb4;"
    mysql -e "CREATE USER IF NOT EXISTS 'trojan'@'localhost' IDENTIFIED BY 'trojan123';"
    mysql -e "GRANT ALL PRIVILEGES ON trojan.* TO 'trojan'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
    
    # 创建users表
    mysql -u trojan -ptrojan123 trojan << 'EOSQL'
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password CHAR(56) NOT NULL,
    passwordShow VARCHAR(255) NOT NULL DEFAULT '',
    quota BIGINT DEFAULT -1,
    download BIGINT DEFAULT 0,
    upload BIGINT DEFAULT 0,
    useDays INT DEFAULT 0,
    expiryDate BIGINT DEFAULT 0,
    createTime DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_password (password)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
EOSQL
    colorEcho $green "MariaDB配置完成!"
}

# 安装acme.sh
installAcme() {
    if [[ ! -d ~/.acme.sh ]]; then
        colorEcho $blue "正在安装acme.sh..."
        curl -sL https://get.acme.sh | sh -s email=$EMAIL
        ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    fi
}

# 申请SSL证书
issueCert() {
    colorEcho $blue "正在申请SSL证书..."
    mkdir -p /usr/local/etc/trojan/cert
    
    # 停止占用80端口的服务
    systemctl stop nginx 2>/dev/null || true
    systemctl stop apache2 2>/dev/null || true
    systemctl stop httpd 2>/dev/null || true
    
    ~/.acme.sh/acme.sh --issue -d $DOMAIN --standalone --keylength ec-256
    
    ~/.acme.sh/acme.sh --install-cert -d $DOMAIN --ecc \
        --key-file /usr/local/etc/trojan/cert/$DOMAIN.key \
        --fullchain-file /usr/local/etc/trojan/cert/$DOMAIN.crt \
        --reloadcmd "systemctl restart trojan 2>/dev/null || true"
    
    colorEcho $green "SSL证书申请成功!"
}

# 安装Trojan核心
installTrojanCore() {
    colorEcho $blue "正在安装Trojan核心..."
    
    # 下载trojan核心
    cd /tmp
    curl -sLO https://github.com/trojan-gfw/trojan/releases/download/v1.16.0/trojan-1.16.0-linux-amd64.tar.xz
    tar -xf trojan-1.16.0-linux-amd64.tar.xz
    cp trojan/trojan /usr/bin/trojan
    chmod +x /usr/bin/trojan
    rm -rf trojan trojan-1.16.0-linux-amd64.tar.xz
    
    colorEcho $green "Trojan核心安装完成!"
}

# 生成Trojan配置
generateTrojanConfig() {
    TROJAN_PASSWORD=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)
    
    mkdir -p /usr/local/etc/trojan
    
    cat > /usr/local/etc/trojan/config.json << EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        "$TROJAN_PASSWORD"
    ],
    "log_level": 1,
    "ssl": {
        "cert": "/usr/local/etc/trojan/cert/$DOMAIN.crt",
        "key": "/usr/local/etc/trojan/cert/$DOMAIN.key",
        "key_password": "",
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
        "cipher_tls13": "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        "prefer_server_cipher": true,
        "alpn": ["http/1.1"],
        "reuse_session": true,
        "session_ticket": false,
        "session_timeout": 600,
        "plain_http_response": "",
        "curves": "",
        "dhparam": "",
        "sni": "$DOMAIN"
    },
    "tcp": {
        "prefer_ipv4": false,
        "no_delay": true,
        "keep_alive": true,
        "reuse_port": false,
        "fast_open": false,
        "fast_open_qlen": 20
    },
    "mysql": {
        "enabled": true,
        "server_addr": "127.0.0.1",
        "server_port": 3306,
        "database": "trojan",
        "username": "trojan",
        "password": "trojan123",
        "key": "",
        "cert": "",
        "ca": ""
    }
}
EOF

    # 添加用户到数据库
    mysql -u trojan -ptrojan123 trojan -e "INSERT INTO users (username, password, passwordShow, quota) VALUES ('default', '$TROJAN_PASSWORD', '$TROJAN_PASSWORD', -1) ON DUPLICATE KEY UPDATE password='$TROJAN_PASSWORD', passwordShow='$TROJAN_PASSWORD';"
}

# 创建Trojan服务
createTrojanService() {
    cat > /etc/systemd/system/trojan.service << 'EOF'
[Unit]
Description=Trojan - An unidentifiable mechanism that helps you bypass GFW
Documentation=https://trojan-gfw.github.io/trojan/
After=network.target network-online.target nss-lookup.target mysql.service mariadb.service

[Service]
Type=simple
StandardError=journal
ExecStart=/usr/bin/trojan -c /usr/local/etc/trojan/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable trojan
    systemctl start trojan
}

# 安装SOCKS5代理
installSocks5() {
    colorEcho $blue "正在安装SOCKS5代理..."
    
    # 编译microsocks
    cd /tmp
    curl -sL https://github.com/rofl0r/microsocks/archive/refs/heads/master.tar.gz -o microsocks.tar.gz
    tar -xzf microsocks.tar.gz
    cd microsocks-master
    make
    cp microsocks /usr/local/bin/
    chmod +x /usr/local/bin/microsocks
    cd /tmp
    rm -rf microsocks-master microsocks.tar.gz
    
    # 创建服务
    if [[ -n "$SOCKS5_USER" && -n "$SOCKS5_PASS" ]]; then
        SOCKS5_CMD="/usr/local/bin/microsocks -i 0.0.0.0 -p $SOCKS5_PORT -u $SOCKS5_USER -P $SOCKS5_PASS"
    else
        SOCKS5_CMD="/usr/local/bin/microsocks -i 0.0.0.0 -p $SOCKS5_PORT"
    fi
    
    cat > /etc/systemd/system/trojan-socks5.service << EOF
[Unit]
Description=SOCKS5 Proxy
After=network.target

[Service]
Type=simple
ExecStart=$SOCKS5_CMD
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable trojan-socks5
    systemctl start trojan-socks5
    
    colorEcho $green "SOCKS5代理安装完成!"
}

# 保存配置信息
saveConfig() {
    SERVER_IP=$(curl -s4 ip.sb 2>/dev/null || curl -s4 ifconfig.me)
    
    cat > /usr/local/etc/trojan/info.txt << EOF
==========================================
        Trojan + SOCKS5 配置信息
==========================================

【Trojan配置】
服务器地址: $DOMAIN
服务器IP: $SERVER_IP
端口: 443
密码: $TROJAN_PASSWORD
SNI: $DOMAIN

Trojan链接:
trojan://$TROJAN_PASSWORD@$DOMAIN:443?sni=$DOMAIN#Trojan-$DOMAIN

------------------------------------------

【SOCKS5配置】
服务器: $SERVER_IP
端口: $SOCKS5_PORT
用户名: ${SOCKS5_USER:-无}
密码: ${SOCKS5_PASS:-无}

代理地址: socks5://${SOCKS5_USER:+$SOCKS5_USER:$SOCKS5_PASS@}$SERVER_IP:$SOCKS5_PORT

==========================================
EOF
    
    cat /usr/local/etc/trojan/info.txt
}

# 显示帮助
showHelp() {
    echo "Trojan + SOCKS5 一键安装脚本"
    echo ""
    echo "用法: bash $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -d, --domain    域名 (必需)"
    echo "  -e, --email     邮箱 (用于SSL证书)"
    echo "  -p, --port      SOCKS5端口 (默认: 1080)"
    echo "  -u, --user      SOCKS5用户名 (可选)"
    echo "  -P, --pass      SOCKS5密码 (可选)"
    echo "  -h, --help      显示帮助"
    echo "  --remove        卸载"
    echo ""
    echo "示例:"
    echo "  bash $0 -d example.com -e admin@example.com -p 1080 -u myuser -P mypass"
}

# 卸载
uninstall() {
    colorEcho $yellow "正在卸载..."
    
    systemctl stop trojan 2>/dev/null || true
    systemctl stop trojan-socks5 2>/dev/null || true
    systemctl disable trojan 2>/dev/null || true
    systemctl disable trojan-socks5 2>/dev/null || true
    
    rm -f /usr/bin/trojan
    rm -f /usr/local/bin/microsocks
    rm -rf /usr/local/etc/trojan
    rm -f /etc/systemd/system/trojan.service
    rm -f /etc/systemd/system/trojan-socks5.service
    
    systemctl daemon-reload
    
    colorEcho $green "卸载完成!"
}

# 主函数
main() {
    # 默认值
    SOCKS5_PORT=1080
    EMAIL=""
    SOCKS5_USER=""
    SOCKS5_PASS=""
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain) DOMAIN="$2"; shift 2 ;;
            -e|--email) EMAIL="$2"; shift 2 ;;
            -p|--port) SOCKS5_PORT="$2"; shift 2 ;;
            -u|--user) SOCKS5_USER="$2"; shift 2 ;;
            -P|--pass) SOCKS5_PASS="$2"; shift 2 ;;
            -h|--help) showHelp; exit 0 ;;
            --remove) uninstall; exit 0 ;;
            *) shift ;;
        esac
    done
    
    # 检查域名
    if [[ -z "$DOMAIN" ]]; then
        colorEcho $red "错误: 请使用 -d 参数指定域名"
        showHelp
        exit 1
    fi
    
    EMAIL=${EMAIL:-"admin@$DOMAIN"}
    
    colorEcho $green "=========================================="
    colorEcho $green "   Trojan + SOCKS5 一键安装脚本"
    colorEcho $green "=========================================="
    echo ""
    colorEcho $blue "域名: $DOMAIN"
    colorEcho $blue "邮箱: $EMAIL"
    colorEcho $blue "SOCKS5端口: $SOCKS5_PORT"
    [[ -n "$SOCKS5_USER" ]] && colorEcho $blue "SOCKS5用户: $SOCKS5_USER"
    echo ""
    
    checkRoot
    checkSys
    installDeps
    setupMariaDB
    installAcme
    issueCert
    installTrojanCore
    generateTrojanConfig
    createTrojanService
    installSocks5
    
    echo ""
    colorEcho $green "=========================================="
    colorEcho $green "          安装完成!"
    colorEcho $green "=========================================="
    echo ""
    
    saveConfig
    
    echo ""
    colorEcho $yellow "配置已保存到: /usr/local/etc/trojan/info.txt"
    colorEcho $yellow "查看配置: cat /usr/local/etc/trojan/info.txt"
}

main "$@"
