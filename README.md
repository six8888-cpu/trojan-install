# Trojan + SOCKS5 一键安装脚本 (完整修复版)

解决了原 Jrohy/trojan 脚本的所有已知问题，一键安装 Trojan 代理 + SOCKS5 代理。

## 修复的问题

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| git.io短链接失效 | GitHub停止服务 | 使用完整链接 |
| MySQL连接失败 | 数据库未安装 | 自动安装MariaDB |
| 数据库权限错误 | 用户/密码未配置 | 自动创建并配置 |
| 表不存在 | 未初始化 | 自动创建表结构 |
| trojan核心未安装 | 只装了管理程序 | 自动安装核心 |

## 一键安装

```bash
bash <(curl -sL https://raw.githubusercontent.com/six8888-cpu/trojan-install/main/install.sh) -d 你的域名
```

## 完整参数

```bash
bash <(curl -sL https://raw.githubusercontent.com/six8888-cpu/trojan-install/main/install.sh) \
  -d example.com \
  -e admin@example.com \
  -p 1080 \
  -u socks5用户名 \
  -P socks5密码
```

### 参数说明

| 参数 | 说明 | 必需 | 默认值 |
|------|------|------|--------|
| -d, --domain | 域名 | 是 | - |
| -e, --email | 邮箱(SSL证书) | 否 | admin@域名 |
| -p, --port | SOCKS5端口 | 否 | 1080 |
| -u, --user | SOCKS5用户名 | 否 | 无认证 |
| -P, --pass | SOCKS5密码 | 否 | 无认证 |
| --remove | 卸载 | - | - |

## 卸载

```bash
bash <(curl -sL https://raw.githubusercontent.com/six8888-cpu/trojan-install/main/install.sh) --remove
```

## 安装后

配置信息保存在: `/usr/local/etc/trojan/info.txt`

```bash
cat /usr/local/etc/trojan/info.txt
```

## 系统要求

- CentOS 7+、Debian 9+、Ubuntu 16+
- root权限
- 已解析到服务器的域名
- 80端口开放(证书申请)
- 443端口开放(Trojan)

## 服务管理

```bash
# Trojan
systemctl status trojan
systemctl restart trojan

# SOCKS5
systemctl status trojan-socks5
systemctl restart trojan-socks5

# MariaDB
systemctl status mariadb
```

## 致谢

基于 [Jrohy/trojan](https://github.com/Jrohy/trojan) 项目修改。

