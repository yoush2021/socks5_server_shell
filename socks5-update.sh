#!/bin/bash

# socks5用户配置更新脚本
# 用于更新节点版和转发版的用户信息，包括转发版的出口代理配置

CONFIG_DIR="/etc/socks5"
NODE_CONFIG="$CONFIG_DIR/node.conf"
FORWARD_CONFIG="$CONFIG_DIR/forward.conf"
FORWARD_PROXY_CONFIG="$CONFIG_DIR/forward_proxy.conf"
BACKUP_DIR="/etc/socks5/backups"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
}

# 检查配置文件是否存在
check_configs() {
    if [[ ! -f "$NODE_CONFIG" && ! -f "$FORWARD_CONFIG" && ! -f "$FORWARD_PROXY_CONFIG" ]]; then
        log_error "未找到任何配置文件"
        log_error "请确保以下至少一个配置文件存在："
        log_error "  - 节点版: $NODE_CONFIG"
        log_error "  - 转发版用户: $FORWARD_CONFIG"
        log_error "  - 转发版出口代理: $FORWARD_PROXY_CONFIG"
        exit 1
    fi
}

# 创建备份
create_backup() {
    mkdir -p "$BACKUP_DIR"
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    
    if [[ -f "$NODE_CONFIG" ]]; then
        cp "$NODE_CONFIG" "$BACKUP_DIR/node.conf.$timestamp"
    fi
    
    if [[ -f "$FORWARD_CONFIG" ]]; then
        cp "$FORWARD_CONFIG" "$BACKUP_DIR/forward.conf.$timestamp"
    fi
    
    if [[ -f "$FORWARD_PROXY_CONFIG" ]]; then
        cp "$FORWARD_PROXY_CONFIG" "$BACKUP_DIR/forward_proxy.conf.$timestamp"
    fi
    
    log_info "配置文件已备份到 $BACKUP_DIR"
}

# 显示当前配置
show_configs() {
    echo -e "\n${BLUE}=== 当前配置信息 ===${NC}"
    
    # 节点版用户
    if [[ -f "$NODE_CONFIG" ]]; then
        echo -e "\n${YELLOW}📡 节点版用户 ($NODE_CONFIG):${NC}"
        if grep -q "=" "$NODE_CONFIG" 2>/dev/null; then
            echo "用户名 | 密码 | 端口"
            echo "-------------------"
            grep -v "^#" "$NODE_CONFIG" | grep "=" | while IFS='=' read -r user pass_port; do
                local pass=$(echo "$pass_port" | cut -d':' -f1)
                local port=$(echo "$pass_port" | cut -d':' -f2)
                printf "%-10s | %-10s | %-5s\n" "$user" "$pass" "$port"
            done
        else
            echo "    无用户配置"
        fi
    fi
    
    # 转发版用户
    if [[ -f "$FORWARD_CONFIG" ]]; then
        echo -e "\n${YELLOW}🔀 转发版用户 ($FORWARD_CONFIG):${NC}"
        if grep -q ":" "$FORWARD_CONFIG" 2>/dev/null; then
            echo "用户名 | 密码 | 端口"
            echo "-------------------"
            grep -v "^#" "$FORWARD_CONFIG" | grep ":" | while IFS=':' read -r user pass port; do
                printf "%-10s | %-10s | %-5s\n" "$user" "$pass" "$port"
            done
        else
            echo "    无用户配置"
        fi
    fi
    
    # 转发版出口代理配置
    if [[ -f "$FORWARD_PROXY_CONFIG" ]]; then
        echo -e "\n${YELLOW}🌐 转发版出口代理配置 ($FORWARD_PROXY_CONFIG):${NC}"
        if grep -q ":" "$FORWARD_PROXY_CONFIG" 2>/dev/null; then
            echo "出口代理地址 | 端口 | 用户名 | 密码"
            echo "-----------------------------------"
            grep -v "^#" "$FORWARD_PROXY_CONFIG" | grep ":" | while IFS=':' read -r ip port user pass; do
                printf "%-15s | %-5s | %-10s | %-10s\n" "$ip" "$port" "$user" "$pass"
            done
        else
            echo "    无出口代理配置"
        fi
    fi
    echo ""
}

# 添加节点版用户
add_node_user() {
    echo -e "\n${BLUE}=== 添加节点版用户 ===${NC}"
    
    read -p "请输入用户名: " username
    if [[ -z "$username" ]]; then
        log_error "用户名不能为空"
        return 1
    fi
    
    read -s -p "请输入密码: " password
    echo
    if [[ -z "$password" ]]; then
        log_error "密码不能为空"
        return 1
    fi
    
    read -p "请输入端口 (默认1080): " port
    port=${port:-1080}
    
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 || "$port" -gt 65535 ]]; then
        log_error "端口号必须是1-65535之间的数字"
        return 1
    fi
    
    # 检查用户是否已存在
    if grep -q "^$username=" "$NODE_CONFIG" 2>/dev/null; then
        log_warn "用户 $username 已存在，将更新密码和端口"
        sed -i "/^$username=/d" "$NODE_CONFIG"
    fi
    
    echo "$username=$password:$port" >> "$NODE_CONFIG"
    log_info "✅ 节点版用户 $username 添加成功 (端口: $port)"
}

# 添加转发版用户
add_forward_user() {
    echo -e "\n${BLUE}=== 添加转发版用户 ===${NC}"
    
    read -p "请输入用户名: " username
    if [[ -z "$username" ]]; then
        log_error "用户名不能为空"
        return 1
    fi
    
    read -s -p "请输入密码: " password
    echo
    if [[ -z "$password" ]]; then
        log_error "密码不能为空"
        return 1
    fi
    
    read -p "请输入端口 (默认1080): " port
    port=${port:-1080}
    
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 || "$port" -gt 65535 ]]; then
        log_error "端口号必须是1-65535之间的数字"
        return 1
    fi
    
    # 检查用户是否已存在
    if grep -q "^$username:" "$FORWARD_CONFIG" 2>/dev/null; then
        log_warn "用户 $username 已存在，将更新密码和端口"
        sed -i "/^$username:/d" "$FORWARD_CONFIG"
    fi
    
    echo "$username:$password:$port" >> "$FORWARD_CONFIG"
    log_info "✅ 转发版用户 $username 添加成功 (端口: $port)"
}

# 配置转发版出口代理
configure_forward_proxy() {
    echo -e "\n${BLUE}=== 配置转发版出口代理 ===${NC}"
    
    echo "请选择操作："
    echo "1. 添加出口代理"
    echo "2. 修改出口代理"
    echo "3. 删除出口代理"
    echo "4. 查看当前配置"
    read -p "请选择 [1-4]: " action
    
    case $action in
        1)
            add_forward_proxy
            ;;
        2)
            modify_forward_proxy
            ;;
        3)
            delete_forward_proxy
            ;;
        4)
            show_forward_proxy
            ;;
        *)
            log_error "无效选择"
            return 1
            ;;
    esac
}

# 添加转发版出口代理
add_forward_proxy() {
    echo -e "\n${PURPLE}>>> 添加出口代理${NC}"
    
    read -p "请输入出口代理IP地址: " proxy_ip
    if [[ -z "$proxy_ip" ]]; then
        log_error "IP地址不能为空"
        return 1
    fi
    
    # 验证IP地址格式
    if ! [[ "$proxy_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_error "IP地址格式不正确"
        return 1
    fi
    
    read -p "请输入出口代理端口: " proxy_port
    if ! [[ "$proxy_port" =~ ^[0-9]+$ ]] || [[ "$proxy_port" -lt 1 || "$proxy_port" -gt 65535 ]]; then
        log_error "端口号必须是1-65535之间的数字"
        return 1
    fi
    
    read -p "请输入出口代理用户名 (如无需认证请留空): " proxy_user
    if [[ -n "$proxy_user" ]]; then
        read -s -p "请输入出口代理密码: " proxy_pass
        echo
    else
        proxy_pass=""
    fi
    
    # 清空现有配置（我们只支持一个出口代理）
    > "$FORWARD_PROXY_CONFIG"
    
    if [[ -n "$proxy_user" ]]; then
        echo "$proxy_ip:$proxy_port:$proxy_user:$proxy_pass" >> "$FORWARD_PROXY_CONFIG"
        log_info "✅ 出口代理配置成功 (需要认证)"
        log_info "   IP: $proxy_ip, 端口: $proxy_port, 用户: $proxy_user"
    else
        echo "$proxy_ip:$proxy_port" >> "$FORWARD_PROXY_CONFIG"
        log_info "✅ 出口代理配置成功 (无需认证)"
        log_info "   IP: $proxy_ip, 端口: $proxy_port"
    fi
}

# 修改转发版出口代理
modify_forward_proxy() {
    echo -e "\n${PURPLE}>>> 修改出口代理${NC}"
    
    if [[ ! -f "$FORWARD_PROXY_CONFIG" ]] || ! grep -q ":" "$FORWARD_PROXY_CONFIG" 2>/dev/null; then
        log_error "当前没有配置出口代理"
        return 1
    fi
    
    local current_config=$(grep -v "^#" "$FORWARD_PROXY_CONFIG" | head -1)
    local current_ip=$(echo "$current_config" | cut -d':' -f1)
    local current_port=$(echo "$current_config" | cut -d':' -f2)
    local current_user=$(echo "$current_config" | cut -d':' -f3)
    local current_pass=$(echo "$current_config" | cut -d':' -f4)
    
    echo "当前配置:"
    if [[ -n "$current_user" ]]; then
        echo "  IP: $current_ip, 端口: $current_port, 用户: $current_user"
    else
        echo "  IP: $current_ip, 端口: $current_port (无需认证)"
    fi
    
    read -p "请输入新的出口代理IP地址 (留空保持不变: $current_ip): " new_ip
    new_ip=${new_ip:-$current_ip}
    
    read -p "请输入新的出口代理端口 (留空保持不变: $current_port): " new_port
    new_port=${new_port:-$current_port}
    
    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [[ "$new_port" -lt 1 || "$new_port" -gt 65535 ]]; then
        log_error "端口号必须是1-65535之间的数字"
        return 1
    fi
    
    read -p "请输入新的出口代理用户名 (留空表示无需认证): " new_user
    
    if [[ -n "$new_user" ]]; then
        read -s -p "请输入新的出口代理密码: " new_pass
        echo
    else
        new_pass=""
    fi
    
    # 更新配置
    > "$FORWARD_PROXY_CONFIG"
    
    if [[ -n "$new_user" ]]; then
        echo "$new_ip:$new_port:$new_user:$new_pass" >> "$FORWARD_PROXY_CONFIG"
        log_info "✅ 出口代理修改成功 (需要认证)"
        log_info "   IP: $new_ip, 端口: $new_port, 用户: $new_user"
    else
        echo "$new_ip:$new_port" >> "$FORWARD_PROXY_CONFIG"
        log_info "✅ 出口代理修改成功 (无需认证)"
        log_info "   IP: $new_ip, 端口: $new_port"
    fi
}

# 删除转发版出口代理
delete_forward_proxy() {
    echo -e "\n${PURPLE}>>> 删除出口代理${NC}"
    
    if [[ ! -f "$FORWARD_PROXY_CONFIG" ]] || ! grep -q ":" "$FORWARD_PROXY_CONFIG" 2>/dev/null; then
        log_error "当前没有配置出口代理"
        return 1
    fi
    
    > "$FORWARD_PROXY_CONFIG"
    log_info "✅ 出口代理配置已删除"
}

# 显示转发版出口代理
show_forward_proxy() {
    echo -e "\n${PURPLE}>>> 当前出口代理配置${NC}"
    
    if [[ ! -f "$FORWARD_PROXY_CONFIG" ]] || ! grep -q ":" "$FORWARD_PROXY_CONFIG" 2>/dev/null; then
        echo "暂无出口代理配置"
    else
        local config=$(grep -v "^#" "$FORWARD_PROXY_CONFIG" | head -1)
        local ip=$(echo "$config" | cut -d':' -f1)
        local port=$(echo "$config" | cut -d':' -f2)
        local user=$(echo "$config" | cut -d':' -f3)
        local pass=$(echo "$config" | cut -d':' -f4)
        
        echo "出口代理服务器: $ip:$port"
        if [[ -n "$user" ]]; then
            echo "认证用户: $user"
            echo "认证密码: ******"
        else
            echo "认证: 无需认证"
        fi
    fi
}

# 删除用户
delete_user() {
    local config_type=$1
    
    echo -e "\n${BLUE}=== 删除用户 ===${NC}"
    
    read -p "请输入要删除的用户名: " username
    if [[ -z "$username" ]]; then
        log_error "用户名不能为空"
        return 1
    fi
    
    case $config_type in
        "node")
            if grep -q "^$username=" "$NODE_CONFIG" 2>/dev/null; then
                sed -i "/^$username=/d" "$NODE_CONFIG"
                log_info "✅ 节点版用户 $username 删除成功"
            else
                log_warn "节点版中未找到用户 $username"
            fi
            ;;
        "forward")
            if grep -q "^$username:" "$FORWARD_CONFIG" 2>/dev/null; then
                sed -i "/^$username:/d" "$FORWARD_CONFIG"
                log_info "✅ 转发版用户 $username 删除成功"
            else
                log_warn "转发版中未找到用户 $username"
            fi
            ;;
        "both")
            local found=0
            if grep -q "^$username=" "$NODE_CONFIG" 2>/dev/null; then
                sed -i "/^$username=/d" "$NODE_CONFIG"
                log_info "✅ 节点版用户 $username 删除成功"
                found=1
            fi
            
            if grep -q "^$username:" "$FORWARD_CONFIG" 2>/dev/null; then
                sed -i "/^$username:/d" "$FORWARD_CONFIG"
                log_info "✅ 转发版用户 $username 删除成功"
                found=1
            fi
            
            if [[ $found -eq 0 ]]; then
                log_warn "未找到用户 $username"
            fi
            ;;
    esac
}

# 修改用户信息
modify_user() {
    local config_type=$1
    
    echo -e "\n${BLUE}=== 修改用户信息 ===${NC}"
    
    read -p "请输入要修改的用户名: " username
    if [[ -z "$username" ]]; then
        log_error "用户名不能为空"
        return 1
    fi
    
    case $config_type in
        "node")
            if ! grep -q "^$username=" "$NODE_CONFIG" 2>/dev/null; then
                log_error "节点版中未找到用户 $username"
                return 1
            fi
            
            local current_info=$(grep "^$username=" "$NODE_CONFIG")
            local current_pass=$(echo "$current_info" | cut -d'=' -f2 | cut -d':' -f1)
            local current_port=$(echo "$current_info" | cut -d':' -f2)
            
            read -p "请输入新密码 (留空保持不变): " new_password
            read -p "请输入新端口 (留空保持不变): " new_port
            
            new_password=${new_password:-$current_pass}
            new_port=${new_port:-$current_port}
            
            if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [[ "$new_port" -lt 1 || "$new_port" -gt 65535 ]]; then
                log_error "端口号必须是1-65535之间的数字"
                return 1
            fi
            
            sed -i "s/^$username=.*/$username=$new_password:$new_port/" "$NODE_CONFIG"
            log_info "✅ 节点版用户 $username 修改成功"
            ;;
        "forward")
            if ! grep -q "^$username:" "$FORWARD_CONFIG" 2>/dev/null; then
                log_error "转发版中未找到用户 $username"
                return 1
            fi
            
            local current_info=$(grep "^$username:" "$FORWARD_CONFIG")
            local current_pass=$(echo "$current_info" | cut -d':' -f2)
            local current_port=$(echo "$current_info" | cut -d':' -f3)
            
            read -p "请输入新密码 (留空保持不变): " new_password
            read -p "请输入新端口 (留空保持不变): " new_port
            
            new_password=${new_password:-$current_pass}
            new_port=${new_port:-$current_port}
            
            if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [[ "$new_port" -lt 1 || "$new_port" -gt 65535 ]]; then
                log_error "端口号必须是1-65535之间的数字"
                return 1
            fi
            
            sed -i "s/^$username:.*/$username:$new_password:$new_port/" "$FORWARD_CONFIG"
            log_info "✅ 转发版用户 $username 修改成功"
            ;;
    esac
}

# 重启服务
restart_services() {
    echo -e "\n${BLUE}=== 重启服务 ===${NC}"
    
    # 重启节点版服务
    if systemctl is-active --quiet socks5-node; then
        log_info "重启节点版服务..."
        systemctl restart socks5-node
        sleep 2
        if systemctl is-active --quiet socks5-node; then
            log_info "✅ 节点版服务重启成功"
        else
            log_error "❌ 节点版服务重启失败"
        fi
    fi
    
    # 重启转发版服务
    if systemctl is-active --quiet socks5-forward; then
        log_info "重启转发版服务..."
        systemctl restart socks5-forward
        sleep 2
        if systemctl is-active --quiet socks5-forward; then
            log_info "✅ 转发版服务重启成功"
        else
            log_error "❌ 转发版服务重启失败"
        fi
    fi
    
    log_info "服务重启完成"
}

# 主菜单
main_menu() {
    while true; do
        echo -e "\n${BLUE}=== SOCKS5 用户配置管理 ===${NC}"
        echo "1. 📊 显示当前配置"
        echo "2. 📡 管理节点版用户"
        echo "3. 🔀 管理转发版用户"
        echo "4. 🌐 管理转发版出口代理"
        echo "5. ⚡ 重启服务"
        echo "6. 🚪 退出"
        echo ""
        read -p "请选择操作 [1-6]: " choice
        
        case $choice in
            1)
                show_configs
                ;;
            2)
                node_menu
                ;;
            3)
                forward_menu
                ;;
            4)
                configure_forward_proxy
                ;;
            5)
                restart_services
                ;;
            6)
                log_info "再见!"
                exit 0
                ;;
            *)
                log_error "无效选择，请重新输入"
                ;;
        esac
    done
}

# 节点版菜单
node_menu() {
    while true; do
        echo -e "\n${YELLOW}=== 节点版用户管理 ===${NC}"
        echo "1. ➕ 添加用户"
        echo "2. ❌ 删除用户"
        echo "3. ✏️  修改用户"
        echo "4. 📋 显示用户"
        echo "5. 🔙 返回主菜单"
        echo ""
        read -p "请选择操作 [1-5]: " choice
        
        case $choice in
            1)
                add_node_user
                ;;
            2)
                delete_user "node"
                ;;
            3)
                modify_user "node"
                ;;
            4)
                show_configs
                ;;
            5)
                break
                ;;
            *)
                log_error "无效选择，请重新输入"
                ;;
        esac
    done
}

# 转发版菜单
forward_menu() {
    while true; do
        echo -e "\n${YELLOW}=== 转发版用户管理 ===${NC}"
        echo "1. ➕ 添加用户"
        echo "2. ❌ 删除用户"
        echo "3. ✏️  修改用户"
        echo "4. 📋 显示用户"
        echo "5. 🔙 返回主菜单"
        echo ""
        read -p "请选择操作 [1-5]: " choice
        
        case $choice in
            1)
                add_forward_user
                ;;
            2)
                delete_user "forward"
                ;;
            3)
                modify_user "forward"
                ;;
            4)
                show_configs
                ;;
            5)
                break
                ;;
            *)
                log_error "无效选择，请重新输入"
                ;;
        esac
    done
}

# 初始化检查
init_check() {
    if [[ $EUID -ne 0 ]]; then
        log_error "请使用 root 权限运行此脚本"
        exit 1
    fi
    
    check_configs
    create_backup
}

# 脚本入口
main() {
    echo -e "${GREEN}SOCKS5 用户配置管理脚本${NC}"
    echo "作者: yoush2021"
    echo "GitHub: https://github.com/yoush2021/socks5_server_shell"
    echo ""
    
    init_check
    main_menu
}

# 运行主函数
main "$@"
