cat > socks5-config.sh << 'EOF'
#!/bin/bash
# socks5-config.sh - SOCKS5服务器配置管理

set -e

SERVICE_FILE="/etc/systemd/system/socks5-server.service"
INSTALL_DIR="/usr/local/bin"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 检查服务状态
check_service() {
    if ! systemctl is-active socks5-server >/dev/null 2>&1; then
        log_error "SOCKS5服务器未运行，请先安装"
        exit 1
    fi
}

# 更新节点版配置
update_node_config() {
    check_service
    
    echo "=== 更新节点版配置 ==="
    
    read -p "新监听端口 [当前: 1080]: " new_port
    NEW_PORT=${new_port:-1080}
    
    read -p "新用户名 [当前: admin]: " new_user
    NEW_USER=${new_user:-admin}
    
    read -s -p "新密码 [当前: admin]: " new_pass
    echo
    NEW_PASS=${new_pass:-admin}
    
    # 停止服务
    systemctl stop socks5-server
    
    # 更新服务配置
    cat > $SERVICE_FILE << EOF
[Unit]
Description=SOCKS5 Node Server
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/socks5-node -port $NEW_PORT -user "$NEW_USER" -pass "$NEW_PASS" -verbose=true
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl start socks5-server
    
    log_info "✅ 节点版配置更新完成"
    log_info "新配置: 端口 $NEW_PORT, 用户 $NEW_USER, 密码 $NEW_PASS"
}

# 更新转发版配置  
update_forward_config() {
    check_service
    
    echo "=== 更新转发版配置 ==="
    
    read -p "VPS1新端口 [当前: 1080]: " new_entry_port
    NEW_ENTRY_PORT=${new_entry_port:-1080}
    
    read -p "VPS1新用户名 [当前: admin]: " new_entry_user
    NEW_ENTRY_USER=${new_entry_user:-admin}
    
    read -s -p "VPS1新密码 [当前: admin]: " new_entry_pass
    echo
    NEW_ENTRY_PASS=${new_entry_pass:-admin}
    
    echo "=== VPS2配置更新 ==="
    read -p "VPS2 IP地址 [当前: 需要查看当前配置]: " new_exit_ip
    read -p "VPS2端口 [当前: 需要查看当前配置]: " new_exit_port
    read -p "VPS2用户名 [当前: 需要查看当前配置]: " new_exit_user
    read -s -p "VPS2密码 [当前: 需要查看当前配置]: " new_exit_pass
    echo
    
    # 停止服务
    systemctl stop socks5-server
    
    # 更新服务配置
    cat > $SERVICE_FILE << EOF
[Unit]
Description=SOCKS5 Forward Server
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/socks5-forward -entry-port $NEW_ENTRY_PORT -entry-user "$NEW_ENTRY_USER" -entry-pass "$NEW_ENTRY_PASS" -exit-ip "$new_exit_ip" -exit-port $new_exit_port -exit-user "$new_exit_user" -exit-pass "$new_exit_pass" -verbose=true
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl start socks5-server
    
    log_info "✅ 转发版配置更新完成"
    log_info "VPS1: 端口 $NEW_ENTRY_PORT, 用户 $NEW_ENTRY_USER"
    log_info "VPS2: $new_exit_ip:$new_exit_port, 用户 $new_exit_user"
}

# 显示当前配置
show_config() {
    if [ -f "$SERVICE_FILE" ]; then
        echo "=== 当前服务配置 ==="
        grep "ExecStart" "$SERVICE_FILE" | head -1
    else
        log_error "服务配置文件不存在"
    fi
}

# 显示菜单
show_menu() {
    echo
    echo "=== SOCKS5配置管理 ==="
    echo "1. 更新节点版配置"
    echo "2. 更新转发版配置"
    echo "3. 查看当前配置"
    echo "4. 返回主菜单"
    echo
    read -p "请选择操作 [1-4]: " choice
    
    case $choice in
        1) update_node_config ;;
        2) update_forward_config ;;
        3) show_config ;;
        4) exit 0 ;;
        *) echo "无效选择" ;;
    esac
}

# 主函数
main() {
    case "${1:-menu}" in
        "node")
            update_node_config
            ;;
        "forward")
            update_forward_config
            ;;
        "show")
            show_config
            ;;
        "menu")
            show_menu
            ;;
        *)
            echo "用法: $0 {node|forward|show|menu}"
            echo "  node    - 更新节点版配置"
            echo "  forward - 更新转发版配置"
            echo "  show    - 显示当前配置"
            echo "  menu    - 显示菜单 (默认)"
            ;;
    esac
}

main "$@"
EOF

chmod +x socks5-config.sh
