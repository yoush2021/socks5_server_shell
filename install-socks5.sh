#!/bin/bash
# install-socks5.sh - 一键SOCKS5服务器安装脚本

set -e

# 配置信息
REPO_URL="https://github.com/yoush2021/socks5_server_shell"
SCRIPT_URL="https://raw.githubusercontent.com/yoush2021/socks5_server_shell/main"
DEFAULT_PORT=1080
DEFAULT_USER="admin"
DEFAULT_PASS="admin"
INSTALL_DIR="/usr/local/bin"
SERVICE_NAME="socks5-server"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
CONFIG_DIR="/etc/socks5-server"
LOG_FILE="/var/log/socks5-server.log"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_debug() { echo -e "${BLUE}[DEBUG]${NC} $1"; }

# 显示横幅
show_banner() {
    cat << "EOF"
    
  _____  _____  _____ _   _ _______  _____   _____ 
 / ____|/ ____|/ ____| \ | |__   __|/ ____| / ____|
| (___ | |    | |    |  \| |  | |  | (___  | (___  
 \___ \| |    | |    | . ` |  | |   \___ \  \___ \ 
 ____) | |____| |____| |\  |  | |   ____) | ____) |
|_____/ \_____|\_____|_| \_|  |_|  |_____/ |_____/ 
                                                   
            SOCKS5 服务器一键安装脚本
            GitHub: https://github.com/yoush2021/socks5_server_shell
                                                                    
EOF
}

# 检查系统
check_system() {
    if [[ -f /etc/redhat-release ]]; then
        OS="centos"
    elif grep -Eqi "debian" /etc/issue; then
        OS="debian"
    elif grep -Eqi "ubuntu" /etc/issue; then
        OS="ubuntu"
    else
        log_error "不支持的操作系统"
        exit 1
    fi
    log_info "检测到系统: $OS"
}

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "请使用root权限运行此脚本"
        exit 1
    fi
}

# 安装依赖
install_dependencies() {
    log_info "安装系统依赖..."
    
    case $OS in
        "centos")
            yum update -y
            yum install -y wget curl net-tools socat
            ;;
        "debian"|"ubuntu")
            apt-get update
            apt-get install -y wget curl net-tools socat
            ;;
    esac
}

# 交互式配置
get_user_config() {
    echo
    log_info "=== SOCKS5服务器配置 ==="
    
    while true; do
        read -p "请输入端口号 [默认: $DEFAULT_PORT]: " port
        if [[ -z "$port" ]]; then
            SOCKS_PORT=$DEFAULT_PORT
            break
        elif [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1024 ] && [ "$port" -le 65535 ]; then
            SOCKS_PORT=$port
            break
        else
            log_error "端口号必须是1024-65535之间的数字"
        fi
    done
    
    read -p "请输入用户名 [默认: $DEFAULT_USER]: " user
    SOCKS_USER=${user:-$DEFAULT_USER}
    
    while true; do
        read -s -p "请输入密码 [默认: $DEFAULT_PASS]: " pass
        echo
        if [[ -n "$pass" ]]; then
            SOCKS_PASS=$pass
            break
        else
            SOCKS_PASS=$DEFAULT_PASS
            break
        fi
    done
    
    # 显示配置确认
    echo
    log_info "配置确认:"
    echo "═══════════════════════════════════════"
    echo "  端口: $SOCKS_PORT"
    echo "  用户名: $SOCKS_USER" 
    echo "  密码: ***"
    echo "═══════════════════════════════════════"
    echo
    
    read -p "确认开始安装? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "安装取消"
        exit 0
    fi
}

# 创建SOCKS5服务器脚本
create_socks5_script() {
    log_info "创建SOCKS5服务器脚本..."
    
    cat > $INSTALL_DIR/socks5-server << 'EOF'
#!/bin/bash

# SOCKS5服务器实现
CONFIG_FILE="/etc/socks5-server/config"
LOG_FILE="/var/log/socks5-server.log"

# 读取配置
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
else
    echo "配置文件不存在: $CONFIG_FILE" >&2
    exit 1
fi

# 日志函数
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# 启动服务器
start_server() {
    log "启动SOCKS5服务器 - 端口: $PORT, 用户: $USERNAME"
    
    # 使用socat创建简单的SOCKS代理
    # 注意：这是一个简化实现，生产环境建议使用专门的SOCKS5服务器
    while true; do
        log "监听端口: $PORT"
        socat TCP-LISTEN:$PORT,fork,reuseaddr SOCKS4A:localhost:localhost:0,socksport=$PORT 2>> "$LOG_FILE"
        sleep 1
    done
}

# 主函数
case "${1:-start}" in
    start)
        start_server
        ;;
    stop)
        pkill -f "socat TCP-LISTEN:$PORT"
        log "停止SOCKS5服务器"
        ;;
    status)
        if pgrep -f "socat TCP-LISTEN:$PORT" > /dev/null; then
            echo "SOCKS5服务器运行中"
            netstat -tuln | grep ":$PORT " || true
        else
            echo "SOCKS5服务器未运行"
        fi
        ;;
    *)
        echo "用法: $0 {start|stop|status}"
        exit 1
        ;;
esac
EOF

    chmod +x $INSTALL_DIR/socks5-server
    log_info "SOCKS5服务器脚本已安装: $INSTALL_DIR/socks5-server"
}

# 创建配置文件
create_config() {
    log_info "创建配置文件..."
    
    mkdir -p "$CONFIG_DIR"
    
    cat > "$CONFIG_DIR/config" << EOF
# SOCKS5服务器配置
PORT=$SOCKS_PORT
USERNAME=$SOCKS_USER
PASSWORD=$SOCKS_PASS
EOF

    chmod 600 "$CONFIG_DIR/config"
    log_info "配置文件已创建: $CONFIG_DIR/config"
}

# 创建systemd服务
create_systemd_service() {
    log_info "创建systemd服务..."
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=SOCKS5 Proxy Server
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/socks5-server start
ExecReload=/bin/kill -HUP \$MAINPID
ExecStop=$INSTALL_DIR/socks5-server stop
Restart=always
RestartSec=5
User=root
Group=root

# 安全设置
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes

# 日志
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    log_info "Systemd服务已创建: $SERVICE_FILE"
}

# 配置防火墙
configure_firewall() {
    log_info "配置防火墙..."
    
    # 检查UFW
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        ufw allow $SOCKS_PORT/tcp
        log_info "UFW防火墙已放行端口: $SOCKS_PORT"
    fi
    
    # 检查firewalld
    if command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --state >/dev/null 2>&1; then
            firewall-cmd --permanent --add-port=$SOCKS_PORT/tcp
            firewall-cmd --reload
            log_info "Firewalld已放行端口: $SOCKS_PORT"
        fi
    fi
    
    # 检查iptables
    if command -v iptables >/dev/null 2>&1; then
        iptables -I INPUT -p tcp --dport $SOCKS_PORT -j ACCEPT 2>/dev/null && \
        log_info "iptables已放行端口: $SOCKS_PORT" || true
    fi
}

# 启动服务
start_service() {
    log_info "启动SOCKS5服务..."
    
    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    systemctl restart $SERVICE_NAME
    
    # 等待服务启动
    sleep 3
    
    if systemctl is-active --quiet $SERVICE_NAME; then
        log_info "✅ SOCKS5服务器启动成功!"
    else
        log_error "❌ 服务启动失败"
        log_info "查看日志: journalctl -u $SERVICE_NAME -n 20 --no-pager"
        journalctl -u $SERVICE_NAME -n 20 --no-pager
        exit 1
    fi
}

# 验证安装
verify_installation() {
    log_info "验证安装..."
    
    # 检查服务状态
    if systemctl is-active --quiet $SERVICE_NAME; then
        log_info "✅ 服务运行正常"
    else
        log_error "❌ 服务未运行"
        return 1
    fi
    
    # 检查端口监听
    if netstat -tuln | grep -q ":$SOCKS_PORT "; then
        log_info "✅ 端口 $SOCKS_PORT 监听正常"
    else
        log_error "❌ 端口 $SOCKS_PORT 未监听"
        return 1
    fi
    
    # 检查配置文件
    if [[ -f "$CONFIG_DIR/config" ]]; then
        log_info "✅ 配置文件正常"
    else
        log_error "❌ 配置文件缺失"
        return 1
    fi
    
    return 0
}

# 显示安装结果
show_installation_result() {
    #local server_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    local server_ip=$(wget -qO- "http://4.ipw.cn")
    if [[ -z "$server_ip" ]]; then
        server_ip="你的服务器IP"
    fi
    
    echo
    echo "═══════════════════════════════════════════════════════════════"
    log_info "🎉 SOCKS5服务器安装完成!"
    echo "═══════════════════════════════════════════════════════════════"
    echo
    echo "📋 服务器信息:"
    echo "   ▸ 服务器地址: $server_ip"
    echo "   ▸ 端口: $SOCKS_PORT"
    echo "   ▸ 用户名: $SOCKS_USER"
    echo "   ▸ 密码: $SOCKS_PASS"
    echo
    echo "🔧 测试命令:"
    echo "   curl --socks5 $SOCKS_USER:$SOCKS_PASS@$server_ip:$SOCKS_PORT http://4.ipw.cn"
    echo
    echo "⚙️  管理命令:"
    echo "   systemctl status $SERVICE_NAME    # 查看状态"
    echo "   systemctl restart $SERVICE_NAME   # 重启服务" 
    echo "   systemctl stop $SERVICE_NAME      # 停止服务"
    echo "   journalctl -u $SERVICE_NAME -f    # 查看实时日志"
    echo
    echo "📁 文件位置:"
    echo "   ▸ 配置文件: $CONFIG_DIR/config"
    echo "   ▸ 日志文件: $LOG_FILE"
    echo "   ▸ 服务文件: $SERVICE_FILE"
    echo
    echo "💡 提示: 确保防火墙已放行端口 $SOCKS_PORT"
    echo "═══════════════════════════════════════════════════════════════"
}

# 卸载功能
uninstall_server() {
    log_info "开始卸载SOCKS5服务器..."
    
    # 停止服务
    systemctl stop $SERVICE_NAME 2>/dev/null || true
    systemctl disable $SERVICE_NAME 2>/dev/null || true
    
    # 删除文件
    rm -f $SERVICE_FILE
    rm -f $INSTALL_DIR/socks5-server
    rm -rf $CONFIG_DIR
    
    # 重新加载systemd
    systemctl daemon-reload
    
    log_info "✅ SOCKS5服务器已卸载"
}

# 显示状态
show_status() {
    echo
    log_info "=== SOCKS5服务器状态 ==="
    systemctl status $SERVICE_NAME --no-pager
    
    echo
    log_info "=== 端口监听状态 ==="
    netstat -tuln | grep ":$SOCKS_PORT " || echo "端口 $SOCKS_PORT 未监听"
    
    echo
    log_info "=== 最近日志 ==="
    journalctl -u $SERVICE_NAME -n 10 --no-pager
}

# 主安装函数
main_install() {
    show_banner
    check_root
    check_system
    get_user_config
    install_dependencies
    create_socks5_script
    create_config
    create_systemd_service
    configure_firewall
    start_service
    
    if verify_installation; then
        show_installation_result
    else
        log_error "安装验证失败，请检查日志"
        exit 1
    fi
}

# 显示帮助
show_help() {
    cat << EOF
用法: $0 [选项]

选项:
    install     安装SOCKS5服务器 (默认)
    uninstall   卸载SOCKS5服务器  
    status      查看服务状态
    restart     重启服务
    help        显示此帮助信息

示例:
    $0 install      # 交互式安装
    $0 status       # 查看状态
    $0 uninstall    # 卸载

GitHub: $REPO_URL
EOF
}

# 脚本入口
case "${1:-install}" in
    install)
        main_install
        ;;
    uninstall)
        uninstall_server
        ;;
    status)
        show_status
        ;;
    restart)
        systemctl restart $SERVICE_NAME
        show_status
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_error "未知参数: $1"
        show_help
        exit 1
        ;;
esac
