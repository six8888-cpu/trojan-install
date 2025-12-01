# Trojan 一键安装脚本

Trojan多用户管理部署程序，支持域名配置、SSL证书自动申请、SOCKS5代理功能。

## 功能特性

- ✅ 一键安装Trojan管理程序
- ✅ 自动配置域名和DNS检查
- ✅ 自动申请Let's Encrypt SSL证书（使用acme.sh）
- ✅ 证书自动续期
- ✅ 同时生成SOCKS5代理
- ✅ 支持用户名密码认证
- ✅ 自动生成客户端配置信息

## 安装方式

```bash
# 安装/更新
bash <(curl -sL https://raw.githubusercontent.com/six8888-cpu/trojan-install/main/install.sh)

# 卸载
bash <(curl -sL https://raw.githubusercontent.com/six8888-cpu/trojan-install/main/install.sh) --remove
```

## 使用说明

安装过程中会依次询问：
1. 是否配置域名和SSL证书
2. 输入域名（需提前将域名A记录解析到服务器IP）
3. 输入邮箱（用于SSL证书申请）
4. 是否配置SOCKS5代理
5. SOCKS5端口和认证信息

## 配置文件位置

- Trojan客户端信息: `/usr/local/etc/trojan/client.info`
- SOCKS5代理信息: `/usr/local/etc/trojan/socks5.info`
- 域名和证书信息: `/usr/local/etc/trojan/domain.info`
- SSL证书目录: `/usr/local/etc/trojan/cert/`

## 管理命令

安装完成后，运行 `trojan` 命令可进入管理程序。

## 系统要求

- 支持 CentOS 7+、Debian 9+、Ubuntu 16+
- 需要 root 权限
- 需要一个已解析到服务器的域名
- 80端口需要开放（用于证书申请）

## 致谢

基于 [Jrohy/trojan](https://github.com/Jrohy/trojan) 项目修改。

