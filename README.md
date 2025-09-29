# SOCKS5 Server Shell

一个功能完整的SOCKS5代理服务器一键安装脚本，支持x86_64和ARM架构设备。

## 🚀 一键安装

### 支持的架构
- ✅ **x86_64/amd64** - 常规云服务器、PC
- ✅ **aarch64/arm64** - 树莓派4、NVIDIA Jetson、ARM服务器  
- ✅ **armv7/armv7l** - 树莓派3、Orange Pi、旧款ARM设备
- ✅ **armv6/armv6l** - 树莓派1、Zero、嵌入式设备

### 快速开始

```bash
# 一键安装 (自动检测架构)
bash -c "$(curl -fsSL https://raw.githubusercontent.com/yoush2021/socks5_server_shell/main/install-socks5.sh)"

# 或使用wget
bash -c "$(wget -qO- https://raw.githubusercontent.com/yoush2021/socks5_server_shell/main/install-socks5.sh)"
```

### 树莓派专用

```bash
# 树莓派一键安装
curl -sSL https://raw.githubusercontent.com/yoush2021/socks5_server_shell/main/install-socks5.sh | bash

# 查看设备架构
uname -m
```

### 设备兼容性

| 设备 | 架构 | 状态 | 备注 |
|------|------|------|------|
| 树莓派 4B | arm64 | ✅ 完全支持 | 推荐64位系统 |
| 树莓派 3B+ | armv7 | ✅ 完全支持 | 性能优秀 |
| 树莓派 2 | armv7 | ✅ 完全支持 | 稳定运行 |
| 树莓派 1/Zero | armv6 | ✅ 支持 | 基础功能 |
| NVIDIA Jetson | arm64 | ✅ 完全支持 | 高性能 |
| Orange Pi | arm64/armv7 | ✅ 完全支持 | 多种型号 |
| AWS Graviton | arm64 | ✅ 完全支持 | 云服务器 |

## ⚙️ 功能特性

- 🔧 **一键安装** - 全自动安装配置
- 🏗️ **多架构支持** - x86_64和ARM全面支持  
- 🔐 **认证安全** - 用户名密码认证
- 🚀 **高性能** - Go语言编译，资源占用低
- 🔄 **自启动** - systemd服务管理
- 📊 **状态监控** - 实时服务状态查看
- 🛡️ **防火墙配置** - 自动配置防火墙规则

## 🎯 使用方法

### 安装选项

```bash
# 交互式安装 (推荐)
./install-socks5.sh install

# 查看服务状态
./install-socks5.sh status

# 重启服务
./install-socks5.sh restart

# 卸载服务
./install-socks5.sh uninstall

# 查看架构信息
./install-socks5.sh arch
```

### 默认配置

- **端口**: 1080
- **用户名**: admin  
- **密码**: admin
- **架构**: 自动检测

## 📁 文件结构

```
/etc/socks5-server/config      # 配置文件
/usr/local/bin/socks5-server   # 二进制文件
/var/log/socks5-server.log     # 日志文件
/etc/systemd/system/socks5-server.service  # 服务文件
```

## 🔧 测试连接

安装完成后，使用以下命令测试：

```bash
curl --socks5 admin:admin123@服务器IP:1080 http://4.ipw.cn
```

## 🐛 问题排查

### 查看服务状态
```bash
systemctl status socks5-server
```

### 查看实时日志
```bash  
journalctl -u socks5-server -f
```

### 检查端口监听
```bash
netstat -tuln | grep 1080
```

## 📄 许可证

MIT License

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！
