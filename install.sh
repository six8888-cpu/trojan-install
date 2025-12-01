#!/bin/bash
# Author: Jrohy (原作者)
# github: https://github.com/Jrohy/trojan
# 修改: 添加域名配置、SSL证书申请、SOCKS5代理功能

#定义操作变量, 0为否, 1为是
help=0
remove=0
update=0

download_url="https://github.com/Jrohy/trojan/releases/download/"
version_check="https://api.github.com/repos/Jrohy/trojan/releases/latest"
service_url="https://raw.githubusercontent.com/Jrohy/trojan/master/asset/trojan-web.service"

[[ -e /var/lib/trojan-manager ]] && update=1

#Centos 临时取消别名
[[ -f /etc/redhat-release && -z $(echo $SHELL|grep zsh) ]] && unalias -a

[[ -z $(echo $SHELL|grep zsh) ]] && shell_way="bash" || shell_way="zsh"

#######color code########
red="31m"
green="32m"
yellow="33m"
blue="36m"
fuchsia="35m"

colorEcho(){
    color=$1
    echo -e "\033[${color}${@:2}\033[0m"
}

#######get params#########
while [[ $# > 0 ]];do
    key="$1"
    case $key in
        --remove)
        remove=1
        ;;
        -h|--help)
        help=1
        ;;
        *)
        ;;
    esac
    shift
done
#############################

help(){
    echo "bash $0 [-h|--help] [--remove]"
    echo "  -h, --help           Show help"
    echo "      --remove         remove trojan"
    return 0
}

removeTrojan() {
    #移除trojan
    rm -rf /usr/bin/trojan >/dev/null 2>&1
    rm -rf /usr/local/etc/trojan >/dev/null 2>&1
    rm -f /etc/systemd/system/trojan.service >/dev/null 2>&1

    #移除trojan管理程序
    rm -f /usr/local/bin/trojan >/dev/null 2>&1
    rm -rf /var/lib/trojan-manager >/dev/null 2>&1
    rm -f /etc/systemd/system/trojan-web.service >/dev/null 2>&1

    #移除socks5代理
    rm -f /etc/systemd/system/trojan-socks5.service >/dev/null 2>&1
    rm -f /usr/local/bin/microsocks >/dev/null 2>&1
    
    #移除acme.sh
    ~/.acme.sh/acme.sh --uninstall >/dev/null 2>&1
    rm -rf ~/.acme.sh >/dev/null 2>&1
    
    systemctl daemon-reload

    #移除trojan的专用db
    docker rm -f trojan-mysql trojan-mariadb >/dev/null 2>&1
    rm -rf /home/mysql /home/mariadb >/dev/null 2>&1

    #移除环境变量
    sed -i '/trojan/d' ~/.${shell_way}rc
    source ~/.${shell_way}rc

    colorEcho ${green} "uninstall success!"
}

checkSys() {
    #检查是否为Root
    [ $(id -u) != "0" ] && { colorEcho ${red} "Error: You must be root to run this script"; exit 1; }

    arch=$(uname -m 2> /dev/null)
    if [[ $arch != x86_64 && $arch != aarch64 ]];then
        colorEcho $yellow "not support $arch machine"
        exit 1
    fi

    if [[ `command -v apt-get` ]];then
        package_manager='apt-get'
    elif [[ `command -v dnf` ]];then
        package_manager='dnf'
    elif [[ `command -v yum` ]];then
        package_manager='yum'
    else
        colorEcho $red "Not support OS!"
        exit 1
    fi

    # 缺失/usr/local/bin路径时自动添加
    [[ -z `echo $PATH|grep /usr/local/bin` ]] && { echo 'export PATH=$PATH:/usr/local/bin' >> /etc/bashrc; source /etc/bashrc; }
}

#安装依赖
installDependent(){
    colorEcho $blue "正在安装依赖..."
    if [[ ${package_manager} == 'dnf' || ${package_manager} == 'yum' ]];then
        ${package_manager} install socat crontabs bash-completion curl wget openssl -y
    else
        ${package_manager} update
        ${package_manager} install socat cron bash-completion xz-utils curl wget openssl -y
    fi
}

setupCron() {
    if [[ `crontab -l 2>/dev/null|grep acme` ]]; then
        if [[ -z `crontab -l 2>/dev/null|grep trojan-web` || `crontab -l 2>/dev/null|grep trojan-web|grep "&"` ]]; then
            #计算北京时间早上3点时VPS的实际时间
            origin_time_zone=$(date -R|awk '{printf"%d",$6}')
            local_time_zone=${origin_time_zone%00}
            beijing_zone=8
            beijing_update_time=3
            diff_zone=$[$beijing_zone-$local_time_zone]
            local_time=$[$beijing_update_time-$diff_zone]
            if [ $local_time -lt 0 ];then
                local_time=$[24+$local_time]
            elif [ $local_time -ge 24 ];then
                local_time=$[$local_time-24]
            fi
            crontab -l 2>/dev/null|sed '/acme.sh/d' > crontab.txt
            echo "0 ${local_time}"' * * * systemctl stop trojan-web; "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" > /dev/null; systemctl start trojan-web' >> crontab.txt
            crontab crontab.txt
            rm -f crontab.txt
        fi
    fi
}

# ============ 域名和SSL证书功能 ============
DOMAIN=""
EMAIL=""
CERT_PATH="/usr/local/etc/trojan/cert"

# 安装acme.sh
installAcme() {
    if [[ ! -d ~/.acme.sh ]]; then
        colorEcho $blue "正在安装acme.sh..."
        curl https://get.acme.sh | sh -s email=${EMAIL}
        if [[ $? -ne 0 ]]; then
            colorEcho $red "acme.sh安装失败!"
            return 1
        fi
        # 设置默认CA为Let's Encrypt
        ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    fi
    source ~/.bashrc
    return 0
}

# 申请SSL证书
issueCert() {
    colorEcho $blue "正在申请SSL证书..."
    
    # 创建证书目录
    mkdir -p ${CERT_PATH}
    
    # 检查80端口是否被占用
    if netstat -tlnp 2>/dev/null | grep -q ':80 ' || ss -tlnp 2>/dev/null | grep -q ':80 '; then
        colorEcho $yellow "检测到80端口被占用，尝试停止相关服务..."
        systemctl stop nginx 2>/dev/null
        systemctl stop apache2 2>/dev/null
        systemctl stop httpd 2>/dev/null
        sleep 2
    fi
    
    # 使用standalone模式申请证书
    ~/.acme.sh/acme.sh --issue -d ${DOMAIN} --standalone --keylength ec-256
    
    if [[ $? -ne 0 ]]; then
        colorEcho $red "证书申请失败! 请检查:"
        colorEcho $yellow "1. 域名是否正确解析到本服务器IP"
        colorEcho $yellow "2. 80端口是否被占用"
        colorEcho $yellow "3. 防火墙是否开放80端口"
        return 1
    fi
    
    # 安装证书到指定目录
    ~/.acme.sh/acme.sh --install-cert -d ${DOMAIN} --ecc \
        --key-file ${CERT_PATH}/${DOMAIN}.key \
        --fullchain-file ${CERT_PATH}/${DOMAIN}.crt \
        --reloadcmd "systemctl restart trojan 2>/dev/null; systemctl restart trojan-web 2>/dev/null"
    
    if [[ $? -eq 0 ]]; then
        colorEcho $green "SSL证书申请成功!"
        colorEcho $blue "证书路径: ${CERT_PATH}/${DOMAIN}.crt"
        colorEcho $blue "私钥路径: ${CERT_PATH}/${DOMAIN}.key"
        return 0
    else
        colorEcho $red "证书安装失败!"
        return 1
    fi
}

# 配置域名和证书
setupDomainAndCert() {
    echo ""
    colorEcho $blue "=========================================="
    colorEcho $blue "        域名和SSL证书配置"
    colorEcho $blue "=========================================="
    echo ""
    
    # 获取服务器IP
    local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s4 ifconfig.me 2>/dev/null)
    colorEcho $yellow "当前服务器IP: ${server_ip}"
    echo ""
    
    # 输入域名
    while true; do
        read -p "请输入您的域名 (例如: example.com): " DOMAIN
        if [[ -z "$DOMAIN" ]]; then
            colorEcho $red "域名不能为空!"
            continue
        fi
        # 简单验证域名格式
        if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then
            colorEcho $red "域名格式不正确!"
            continue
        fi
        break
    done
    
    # 检查域名解析
    colorEcho $blue "正在检查域名解析..."
    local domain_ip=$(ping -c 1 ${DOMAIN} 2>/dev/null | grep -oP '(\d{1,3}\.){3}\d{1,3}' | head -1)
    if [[ -z "$domain_ip" ]]; then
        # 尝试使用nslookup或dig
        domain_ip=$(nslookup ${DOMAIN} 2>/dev/null | grep -A1 'Name:' | grep 'Address' | awk '{print $2}' | head -1)
    fi
    
    if [[ "$domain_ip" != "$server_ip" ]]; then
        colorEcho $yellow "警告: 域名 ${DOMAIN} 解析到的IP (${domain_ip:-未知}) 与服务器IP (${server_ip}) 不一致!"
        read -p "是否继续? [y/N]: " continue_anyway
        if [[ ! "$continue_anyway" =~ ^[Yy]$ ]]; then
            colorEcho $yellow "请先将域名A记录指向本服务器IP: ${server_ip}"
            return 1
        fi
    else
        colorEcho $green "域名解析正确!"
    fi
    
    # 输入邮箱
    read -p "请输入您的邮箱 (用于SSL证书申请, 可留空): " EMAIL
    EMAIL=${EMAIL:-"admin@${DOMAIN}"}
    
    # 安装acme.sh并申请证书
    installAcme
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    
    issueCert
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    
    # 保存域名配置
    cat > /usr/local/etc/trojan/domain.info << EOF
# Domain Configuration
DOMAIN=${DOMAIN}
EMAIL=${EMAIL}
CERT_PATH=${CERT_PATH}
CERT_FILE=${CERT_PATH}/${DOMAIN}.crt
KEY_FILE=${CERT_PATH}/${DOMAIN}.key
EOF

    colorEcho $green "域名配置已保存到: /usr/local/etc/trojan/domain.info"
    return 0
}

# 生成trojan配置文件
generateTrojanConfig() {
    local trojan_password=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)
    local trojan_port=443
    
    read -p "请输入trojan监听端口 [默认: 443]: " input_port
    trojan_port=${input_port:-443}
    
    mkdir -p /usr/local/etc/trojan
    
    cat > /usr/local/etc/trojan/config.json << EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": ${trojan_port},
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        "${trojan_password}"
    ],
    "log_level": 1,
    "ssl": {
        "cert": "${CERT_PATH}/${DOMAIN}.crt",
        "key": "${CERT_PATH}/${DOMAIN}.key",
        "key_password": "",
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384",
        "cipher_tls13": "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        "prefer_server_cipher": true,
        "alpn": [
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "session_timeout": 600,
        "plain_http_response": "",
        "curves": "",
        "dhparam": "",
        "sni": "${DOMAIN}"
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
        "enabled": false,
        "server_addr": "127.0.0.1",
        "server_port": 3306,
        "database": "trojan",
        "username": "trojan",
        "password": "",
        "key": "",
        "cert": "",
        "ca": ""
    }
}
EOF

    # 保存连接信息
    local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s4 ifconfig.me 2>/dev/null)
    
    cat > /usr/local/etc/trojan/client.info << EOF
# Trojan Client Configuration
# ========================================
# 服务器地址: ${DOMAIN}
# 服务器IP: ${server_ip}
# 端口: ${trojan_port}
# 密码: ${trojan_password}
# SNI: ${DOMAIN}
# ========================================
# Trojan链接:
# trojan://${trojan_password}@${DOMAIN}:${trojan_port}?sni=${DOMAIN}#Trojan-${DOMAIN}
# ========================================
EOF

    echo ""
    colorEcho $green "=========================================="
    colorEcho $green "    Trojan配置完成!"
    colorEcho $green "=========================================="
    echo ""
    colorEcho $blue "服务器地址: ${DOMAIN}"
    colorEcho $blue "端口: ${trojan_port}"
    colorEcho $blue "密码: ${trojan_password}"
    echo ""
    colorEcho $green "Trojan链接:"
    colorEcho $yellow "trojan://${trojan_password}@${DOMAIN}:${trojan_port}?sni=${DOMAIN}#Trojan-${DOMAIN}"
    echo ""
    colorEcho $green "配置信息已保存到: /usr/local/etc/trojan/client.info"
}
# ============ 域名和SSL证书功能结束 ============

# ============ SOCKS5代理功能 ============
SOCKS5_PORT=1080
SOCKS5_USER=""
SOCKS5_PASS=""

setupSocks5() {
    colorEcho $blue "配置SOCKS5代理..."
    
    echo ""
    read -p "请输入SOCKS5监听端口 [默认: 1080]: " input_port
    SOCKS5_PORT=${input_port:-1080}
    
    read -p "请输入SOCKS5用户名 (留空则无认证): " SOCKS5_USER
    if [[ -n "$SOCKS5_USER" ]]; then
        read -p "请输入SOCKS5密码: " SOCKS5_PASS
    fi
    
    installSocks5WithMicrosocks
}

# 使用microsocks实现SOCKS5代理
installSocks5WithMicrosocks() {
    colorEcho $yellow "正在安装microsocks..."
    
    # 下载并编译microsocks
    cd /tmp
    if [[ ! -f /usr/local/bin/microsocks ]]; then
        curl -sL https://github.com/rofl0r/microsocks/archive/refs/heads/master.tar.gz -o microsocks.tar.gz
        if [[ $? -ne 0 ]]; then
            colorEcho $red "下载microsocks失败!"
            return 1
        fi
        tar -xzf microsocks.tar.gz
        cd microsocks-master
        
        # 检查是否有gcc
        if ! command -v gcc &> /dev/null; then
            colorEcho $yellow "正在安装gcc..."
            ${package_manager} install -y gcc make
        fi
        
        make
        if [[ $? -ne 0 ]]; then
            colorEcho $red "编译microsocks失败!"
            return 1
        fi
        cp microsocks /usr/local/bin/
        chmod +x /usr/local/bin/microsocks
        cd /tmp
        rm -rf microsocks-master microsocks.tar.gz
    fi
    
    # 创建systemd服务
    if [[ -n "$SOCKS5_USER" && -n "$SOCKS5_PASS" ]]; then
        SOCKS5_CMD="/usr/local/bin/microsocks -i 0.0.0.0 -p ${SOCKS5_PORT} -u ${SOCKS5_USER} -P ${SOCKS5_PASS}"
    else
        SOCKS5_CMD="/usr/local/bin/microsocks -i 0.0.0.0 -p ${SOCKS5_PORT}"
    fi
    
    cat > /etc/systemd/system/trojan-socks5.service << EOF
[Unit]
Description=Trojan SOCKS5 Proxy
After=network.target

[Service]
Type=simple
ExecStart=${SOCKS5_CMD}
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable trojan-socks5
    systemctl start trojan-socks5
    
    if [[ $? -eq 0 ]]; then
        showSocks5Info
    else
        colorEcho $red "SOCKS5服务启动失败!"
        return 1
    fi
}

showSocks5Info() {
    local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s4 ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
    
    echo ""
    colorEcho $green "=========================================="
    colorEcho $green "    SOCKS5代理配置完成!"
    colorEcho $green "=========================================="
    echo ""
    colorEcho $blue "服务器地址: ${server_ip}"
    colorEcho $blue "端口: ${SOCKS5_PORT}"
    if [[ -n "$SOCKS5_USER" ]]; then
        colorEcho $blue "用户名: ${SOCKS5_USER}"
        colorEcho $blue "密码: ${SOCKS5_PASS}"
    else
        colorEcho $yellow "认证: 无需认证"
    fi
    echo ""
    colorEcho $green "代理地址: socks5://${server_ip}:${SOCKS5_PORT}"
    if [[ -n "$SOCKS5_USER" ]]; then
        colorEcho $green "完整格式: socks5://${SOCKS5_USER}:${SOCKS5_PASS}@${server_ip}:${SOCKS5_PORT}"
    fi
    echo ""
    colorEcho $yellow "测试命令: curl --socks5 ${server_ip}:${SOCKS5_PORT} http://ip.sb"
    echo ""
    
    # 保存配置信息到文件
    mkdir -p /usr/local/etc/trojan
    cat > /usr/local/etc/trojan/socks5.info << EOF
# SOCKS5 Proxy Info
SERVER=${server_ip}
PORT=${SOCKS5_PORT}
USER=${SOCKS5_USER}
PASS=${SOCKS5_PASS}
# 代理地址: socks5://${server_ip}:${SOCKS5_PORT}
EOF
    colorEcho $green "配置信息已保存到: /usr/local/etc/trojan/socks5.info"
}
# ============ SOCKS5功能结束 ============

# ============ 显示所有配置信息 ============
showAllInfo() {
    echo ""
    colorEcho $green "=========================================="
    colorEcho $green "        所有配置信息汇总"
    colorEcho $green "=========================================="
    
    if [[ -f /usr/local/etc/trojan/client.info ]]; then
        echo ""
        colorEcho $blue "=== Trojan配置 ==="
        cat /usr/local/etc/trojan/client.info
    fi
    
    if [[ -f /usr/local/etc/trojan/socks5.info ]]; then
        echo ""
        colorEcho $blue "=== SOCKS5配置 ==="
        cat /usr/local/etc/trojan/socks5.info
    fi
    
    echo ""
    colorEcho $green "=========================================="
}
# ============ 显示配置信息结束 ============

installTrojan(){
    local show_tip=0
    if [[ $update == 1 ]];then
        systemctl stop trojan-web >/dev/null 2>&1
        rm -f /usr/local/bin/trojan
    fi
    lastest_version=$(curl -H 'Cache-Control: no-cache' -s "$version_check" | grep 'tag_name' | cut -d\" -f4)
    echo "正在下载管理程序`colorEcho $blue $lastest_version`版本..."
    [[ $arch == x86_64 ]] && bin="trojan-linux-amd64" || bin="trojan-linux-arm64"
    curl -L "$download_url/$lastest_version/$bin" -o /usr/local/bin/trojan
    chmod +x /usr/local/bin/trojan
    if [[ ! -e /etc/systemd/system/trojan-web.service ]];then
        show_tip=1
        curl -L $service_url -o /etc/systemd/system/trojan-web.service
        systemctl daemon-reload
        systemctl enable trojan-web
    fi
    #命令补全环境变量
    [[ -z $(grep trojan ~/.${shell_way}rc) ]] && echo "source <(trojan completion ${shell_way})" >> ~/.${shell_way}rc
    source ~/.${shell_way}rc
    
    # 创建配置目录
    mkdir -p /usr/local/etc/trojan
    
    if [[ $update == 0 ]];then
        colorEcho $green "安装trojan管理程序成功!\n"
        
        # 询问是否配置域名和SSL证书
        echo ""
        read -p "是否现在配置域名和SSL证书? [Y/n]: " setup_domain
        if [[ ! "$setup_domain" =~ ^[Nn]$ ]]; then
            setupDomainAndCert
            if [[ $? -eq 0 ]]; then
                generateTrojanConfig
            fi
        fi
        
        echo -e "\n运行命令`colorEcho $blue trojan`可进行trojan管理\n"
        /usr/local/bin/trojan
    else
        if [[ -f /usr/local/etc/trojan/config.json ]]; then
            if [[ `cat /usr/local/etc/trojan/config.json|grep -w "\"db\""` ]];then
                sed -i "s/\"db\"/\"database\"/g" /usr/local/etc/trojan/config.json
                systemctl restart trojan
            fi
            /usr/local/bin/trojan upgrade db
            if [[ -z `cat /usr/local/etc/trojan/config.json|grep sni` ]];then
                /usr/local/bin/trojan upgrade config
            fi
        fi
        systemctl restart trojan-web
        colorEcho $green "更新trojan管理程序成功!\n"
    fi
    setupCron
    [[ $show_tip == 1 ]] && echo "浏览器访问'`colorEcho $blue https://域名`'可在线trojan多用户管理"
    
    # 询问是否配置SOCKS5代理
    echo ""
    read -p "是否同时配置SOCKS5代理? [y/N]: " setup_socks5
    if [[ "$setup_socks5" =~ ^[Yy]$ ]]; then
        setupSocks5
    fi
    
    # 显示所有配置信息
    showAllInfo
}

main(){
    [[ ${help} == 1 ]] && help && return
    [[ ${remove} == 1 ]] && removeTrojan && return
    [[ $update == 0 ]] && echo "正在安装trojan管理程序.." || echo "正在更新trojan管理程序.."
    checkSys
    [[ $update == 0 ]] && installDependent
    installTrojan
}

main
