# socks5_server_shell
用于debian linux 的socks5的一键部署脚本，自启动，自定义端口用户名密码、基于go运行

## 🚀 一键安装

### 快速开始

```bash
# 一键安装 (交互式配置)
bash -c "$(curl -fsSL https://raw.githubusercontent.com/yoush2021/socks5_server_shell/main/install-socks5.sh)"

# 或使用wget
bash -c "$(wget -qO- https://raw.githubusercontent.com/yoush2021/socks5_server_shell/main/install-socks5.sh)"
```

### 高级用法

```bash
# 下载脚本后安装
wget https://raw.githubusercontent.com/yoush2021/socks5_server_shell/main/install-socks5.sh
chmod +x install-socks5.sh
./install-socks5.sh

# 带参数安装
./install-socks5.sh install    # 安装
./install-socks5.sh status     # 查看状态  
./install-socks5.sh restart    # 重启
./install-socks5.sh uninstall  # 卸载
```

### 功能特性

- ✅ 一键安装部署
- ✅ 自定义端口和认证
- ✅ 系统服务集成
- ✅ 自动防火墙配置
- ✅ 安全卸载

### 默认配置

- 端口: `1080`
- 用户名: `admin`
- 密码: `admin`
