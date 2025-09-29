#!/bin/bash
# install-socks5-fixed.sh

set -e

# 配置
DEFAULT_PORT=1080
DEFAULT_USER="admin"
DEFAULT_PASS="admin"
INSTALL_DIR="/usr/local/bin"
SERVICE_FILE="/etc/systemd/system/socks5-server.service"
CONFIG_DIR="/etc/socks5-server"
CONFIG_FILE="$CONFIG_DIR/config"
GO_CACHE_DIR="/tmp/golang"
GO_VERSION="1.21.0"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 检查架构
get_architecture() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l) echo "armv6l" ;;
        *) echo "unknown" ;;
    esac
}

# 下载文件，支持多个镜像和超时重试
download_file() {
    local url=$1
    local output=$2
    local timeout=${3:-30}
    
    if command -v wget >/dev/null 2>&1; then
        wget --timeout=$timeout --tries=3 -O "$output" "$url" && return 0
    elif command -v curl >/dev/null 2>&1; then
        curl --connect-timeout $timeout --retry 3 -L -o "$output" "$url" && return 0
    fi
    return 1
}

# 下载Go安装包
download_go_package() {
    local arch=$1
    local filename="go${GO_VERSION}.linux-${arch}.tar.gz"
    local cache_file="${GO_CACHE_DIR}/${filename}"
    
    # 创建缓存目录
    mkdir -p "$GO_CACHE_DIR"
    
    # 检查缓存
    if [ -f "$cache_file" ]; then
        log_info "使用缓存的Go安装包: $cache_file"
        cp "$cache_file" "/tmp/$filename"
        return 0
    fi
    
    # 定义多个镜像源
    local mirrors=(
        "https://golang.org/dl/${filename}"
        "https://dl.google.com/go/${filename}"
        "https://mirrors.aliyun.com/golang/${filename}"
        "https://mirrors.ustc.edu.cn/golang/${filename}"
        "https://mirrors.tuna.tsinghua.edu.cn/golang/${filename}"
    )
    
    log_info "下载Go ${GO_VERSION} (${arch})..."
    
    for mirror in "${mirrors[@]}"; do
        log_info "尝试从: $mirror"
        if download_file "$mirror" "/tmp/$filename" 30; then
            log_info "下载成功"
            # 缓存文件
            cp "/tmp/$filename" "$cache_file"
            return 0
        else
            log_warn "下载失败，尝试下一个镜像"
        fi
    done
    
    log_error "所有镜像下载失败"
    return 1
}

# 安装Go环境
install_go() {
    local arch=$1
    
    if command -v go >/dev/null 2>&1; then
        log_info "Go已安装: $(go version)"
        return 0
    fi
    
    # 下载Go安装包
    if ! download_go_package "$arch"; then
        log_error "Go安装包下载失败"
        return 1
    fi
    
    local filename="go${GO_VERSION}.linux-${arch}.tar.gz"
    
    # 安装Go
    log_info "安装Go到 /usr/local"
    tar -C /usr/local -xzf "/tmp/$filename"
    rm -f "/tmp/$filename"
    
    # 设置环境变量
    if ! grep -q "/usr/local/go/bin" /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi
    if ! grep -q "/root/go/bin" /etc/profile; then
        echo 'export PATH=$PATH:/root/go/bin' >> /etc/profile
    fi
    
    # 立即生效
    export PATH=$PATH:/usr/local/go/bin
    
    # 验证安装
    if command -v go >/dev/null 2>&1; then
        log_info "Go安装成功: $(go version)"
        return 0
    else
        log_error "Go安装失败"
        return 1
    fi
}

# 编译SOCKS5服务器
compile_socks5_server() {
    local arch=$1
    
    log_info "编译SOCKS5服务器 (${arch})..."
    
    # 创建Go模块
    mkdir -p /tmp/socks5-build
    cd /tmp/socks5-build
    
    cat > go.mod << 'EOF'
module socks5-server

go 1.21
EOF

    # SOCKS5服务器源码
    cat > main.go << 'EOF'
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

var (
	port     = flag.Int("port", 1080, "SOCKS5 server port")
	username = flag.String("user", "admin", "Username for authentication")
	password = flag.String("pass", "admin", "Password for authentication")
	verbose  = flag.Bool("verbose", true, "Enable verbose logging")
)

const (
	socksVersion5 = 0x05

	authNone         = 0x00
	authPassword     = 0x02
	authNotSupported = 0xFF

	cmdConnect = 0x01
	cmdBind    = 0x02
	cmdUDP     = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	success         = 0x00
	generalFailure  = 0x01
	notAllowed      = 0x02
	networkUnreach  = 0x03
	hostUnreach     = 0x04
	connRefused     = 0x05
	ttlExpired      = 0x06
	cmdNotSupported = 0x07
	addrNotSupported = 0x08
)

type Config struct {
	Port     int
	Username string
	Password string
	Verbose  bool
}

type Server struct {
	config *Config
}

func NewServer(config *Config) *Server {
	return &Server{config: config}
}

func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.config.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %v", s.config.Port, err)
	}
	defer listener.Close()

	if s.config.Verbose {
		log.Printf("SOCKS5 server started on port %d", s.config.Port)
		if s.config.Username != "" {
			log.Printf("Authentication enabled - Username: %s", s.config.Username)
		} else {
			log.Printf("No authentication required")
		}
	}

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down server...")
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}

	return nil
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	if s.config.Verbose {
		log.Printf("New connection from %s", clientAddr)
	}

	// Authentication negotiation
	if err := s.authenticate(conn); err != nil {
		if s.config.Verbose {
			log.Printf("Authentication failed for %s: %v", clientAddr, err)
		}
		return
	}

	// Handle SOCKS5 request
	if err := s.handleRequest(conn); err != nil {
		if s.config.Verbose {
			log.Printf("Request handling failed for %s: %v", clientAddr, err)
		}
	}
}

func (s *Server) authenticate(conn net.Conn) error {
	buf := make([]byte, 256)

	// Read client authentication methods
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}

	if n < 2 || buf[0] != socksVersion5 {
		return errors.New("invalid SOCKS version")
	}

	nmethods := int(buf[1])
	if n != 2+nmethods {
		return errors.New("invalid authentication methods length")
	}

	// Check if client supports our authentication method
	supported := false
	for i := 0; i < nmethods; i++ {
		if buf[2+i] == authPassword && s.config.Username != "" {
			supported = true
			break
		} else if buf[2+i] == authNone && s.config.Username == "" {
			supported = true
			break
		}
	}

	// Send selected authentication method
	var method byte
	if s.config.Username != "" && supported {
		method = authPassword
	} else if s.config.Username == "" && supported {
		method = authNone
	} else {
		method = authNotSupported
	}

	_, err = conn.Write([]byte{socksVersion5, method})
	if err != nil {
		return err
	}

	if method == authNotSupported {
		return errors.New("no acceptable authentication methods")
	}

	// Handle username/password authentication
	if method == authPassword {
		if err := s.handlePasswordAuth(conn); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) handlePasswordAuth(conn net.Conn) error {
	buf := make([]byte, 256)

	// Read authentication version and username length
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}

	if n < 2 || buf[0] != 0x01 {
		return errors.New("invalid password authentication version")
	}

	ulen := int(buf[1])
	if n < 2+ulen+1 {
		return errors.New("invalid password authentication data")
	}

	// Read password length
	plen := int(buf[2+ulen])
	if n != 2+ulen+1+plen {
		return errors.New("invalid password authentication data length")
	}

	// Extract username and password
	user := string(buf[2 : 2+ulen])
	pass := string(buf[3+ulen : 3+ulen+plen])

	// Verify credentials
	if user != s.config.Username || pass != s.config.Password {
		conn.Write([]byte{0x01, 0x01}) // Authentication failed
		return errors.New("invalid credentials")
	}

	// Authentication successful
	_, err = conn.Write([]byte{0x01, 0x00})
	return err
}

func (s *Server) handleRequest(conn net.Conn) error {
	buf := make([]byte, 256)

	// Read SOCKS5 request
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}

	if n < 4 || buf[0] != socksVersion5 {
		return errors.New("invalid SOCKS request")
	}

	cmd := buf[1]
	atyp := buf[3]

	var host string
	var port uint16

	// Parse address based on address type
	switch atyp {
	case atypIPv4:
		if n < 10 {
			return errors.New("invalid IPv4 address length")
		}
		host = net.IPv4(buf[4], buf[5], buf[6], buf[7]).String()
		port = binary.BigEndian.Uint16(buf[8:10])
	case atypDomain:
		domainLen := int(buf[4])
		if n < 7+domainLen {
			return errors.New("invalid domain length")
		}
		host = string(buf[5 : 5+domainLen])
		port = binary.BigEndian.Uint16(buf[5+domainLen : 7+domainLen])
	default:
		s.sendReply(conn, addrNotSupported, nil)
		return errors.New("address type not supported")
	}

	// Handle command
	switch cmd {
	case cmdConnect:
		return s.handleConnect(conn, host, port)
	default:
		s.sendReply(conn, cmdNotSupported, nil)
		return fmt.Errorf("command not supported: %d", cmd)
	}
}

func (s *Server) handleConnect(conn net.Conn, host string, port uint16) error {
	targetAddr := fmt.Sprintf("%s:%d", host, port)
	
	if s.config.Verbose {
		log.Printf("Connecting to %s", targetAddr)
	}

	// Connect to target
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		var replyCode byte
		switch {
		case strings.Contains(err.Error(), "refused"):
			replyCode = connRefused
		case strings.Contains(err.Error(), "network is unreachable"):
			replyCode = networkUnreach
		case strings.Contains(err.Error(), "no such host"):
			replyCode = hostUnreach
		default:
			replyCode = generalFailure
		}
		s.sendReply(conn, replyCode, nil)
		return fmt.Errorf("failed to connect to target: %v", err)
	}
	defer target.Close()

	// Get local address for reply
	localAddr := target.LocalAddr().(*net.TCPAddr)

	// Send success reply
	if err := s.sendReply(conn, success, localAddr); err != nil {
		return err
	}

	// Start bidirectional data transfer
	done := make(chan error, 2)

	go func() {
		_, err := io.Copy(target, conn)
		done <- err
	}()

	go func() {
		_, err := io.Copy(conn, target)
		done <- err
	}()

	// Wait for one side to close
	err = <-done
	if s.config.Verbose {
		log.Printf("Connection to %s closed: %v", targetAddr, err)
	}

	return nil
}

func (s *Server) sendReply(conn net.Conn, replyCode byte, addr *net.TCPAddr) error {
	var reply []byte

	if addr != nil {
		reply = make([]byte, 10)
		reply[0] = socksVersion5
		reply[1] = replyCode
		reply[2] = 0x00 // RSV
		reply[3] = atypIPv4
		copy(reply[4:8], addr.IP.To4())
		binary.BigEndian.PutUint16(reply[8:10], uint16(addr.Port))
	} else {
		reply = []byte{
			socksVersion5,
			replyCode,
			0x00, // RSV
			atypIPv4,
			0x00, 0x00, 0x00, 0x00, // IP
			0x00, 0x00, // Port
		}
	}

	_, err := conn.Write(reply)
	return err
}

func main() {
	flag.Parse()

	config := &Config{
		Port:     *port,
		Username: *username,
		Password: *password,
		Verbose:  *verbose,
	}

	server := NewServer(config)
	
	if err := server.Start(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
EOF

    # 编译
    if go build -o "$INSTALL_DIR/socks5-server" main.go; then
        # 确保二进制文件有执行权限
        chmod 755 "$INSTALL_DIR/socks5-server"
        # 验证文件权限
        if [ -x "$INSTALL_DIR/socks5-server" ]; then
            log_info "SOCKS5服务器编译成功，权限正常"
        else
            log_error "二进制文件没有执行权限，手动设置..."
            chmod +x "$INSTALL_DIR/socks5-server"
        fi
        cd /
        rm -rf /tmp/socks5-build
        return 0
    else
        log_error "编译失败"
        return 1
    fi
}

# 下载预编译二进制文件
download_binary() {
    local arch=$1
    
    # 由于预编译版本可能不存在，这里我们直接返回失败，强制编译
    log_warn "预编译版本暂不可用，将使用编译安装"
    return 1
}

# 安装SOCKS5服务器
install_socks5_server() {
    local arch=$1
    
    # 首先尝试下载预编译版本
    if download_binary "$arch"; then
        return 0
    fi
    
    # 预编译版本失败，安装Go并编译
    log_info "开始编译安装SOCKS5服务器..."
    
    if ! install_go "$arch"; then
        log_error "Go环境安装失败"
        return 1
    fi
    
    if ! compile_socks5_server "$arch"; then
        log_error "SOCKS5服务器编译失败"
        return 1
    fi
    
    return 0
}

# 获取用户配置
get_user_config() {
    echo "=== SOCKS5服务器配置 ==="
    
    read -p "请输入端口号 [默认: $DEFAULT_PORT]: " port
    SOCKS_PORT=${port:-$DEFAULT_PORT}
    
    read -p "请输入用户名 [默认: $DEFAULT_USER]: " user
    SOCKS_USER=${user:-$DEFAULT_USER}
    
    read -s -p "请输入密码 [默认: $DEFAULT_PASS]: " pass
    echo
    SOCKS_PASS=${pass:-$DEFAULT_PASS}
    
    echo
    echo "配置确认:"
    echo "端口: $SOCKS_PORT"
    echo "用户名: $SOCKS_USER"
    echo "密码: ***"
    echo
    
    read -p "确认配置? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "安装取消"
        exit 0
    fi
}

# 创建配置文件
create_config() {
    log_info "创建配置文件..."
    
    mkdir -p "$CONFIG_DIR"
    
    cat > "$CONFIG_FILE" << EOF
# SOCKS5服务器配置
PORT=$SOCKS_PORT
USERNAME=$SOCKS_USER
PASSWORD=$SOCKS_PASS
EOF

    chmod 600 "$CONFIG_FILE"
    log_info "配置文件已创建: $CONFIG_FILE"
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
ExecStart=$INSTALL_DIR/socks5-server -port $SOCKS_PORT -user "$SOCKS_USER" -pass "$SOCKS_PASS" -verbose=true
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
User=root
Group=root

# 安全设置
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF
}

# 配置防火墙
configure_firewall() {
    log_info "配置防火墙..."
    
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        ufw allow $SOCKS_PORT/tcp
        log_info "UFW已允许端口 $SOCKS_PORT"
    fi
    
    if command -v iptables >/dev/null 2>&1; then
        iptables -I INPUT -p tcp --dport $SOCKS_PORT -j ACCEPT 2>/dev/null || true
        log_info "iptables已允许端口 $SOCKS_PORT"
    fi
}

# 启动服务
start_service() {
    log_info "启动SOCKS5服务..."
    
    # 停止旧服务
    systemctl stop socks5-server 2>/dev/null || true
    
    # 重新加载systemd
    systemctl daemon-reload
    systemctl enable socks5-server
    
    # 验证二进制文件
    if [ ! -x "$INSTALL_DIR/socks5-server" ]; then
        log_error "SOCKS5服务器二进制文件不存在或没有执行权限"
        log_info "尝试修复权限..."
        chmod +x "$INSTALL_DIR/socks5-server" 2>/dev/null || true
    fi
    
    # 测试运行
    log_info "测试SOCKS5服务器..."
    if timeout 2 "$INSTALL_DIR/socks5-server" -version 2>/dev/null; then
        log_info "SOCKS5服务器测试通过"
    else
        log_warn "SOCKS5服务器测试失败，但继续启动服务"
    fi
    
    systemctl start socks5-server
    
    sleep 3
    
    if systemctl is-active --quiet socks5-server; then
        log_info "SOCKS5服务器启动成功!"
        
        # 验证端口监听
        if netstat -tuln | grep -q ":$SOCKS_PORT "; then
            log_info "端口 $SOCKS_PORT 正在监听"
        else
            log_warn "端口 $SOCKS_PORT 未监听，服务可能有问题"
        fi
    else
        log_error "启动失败，查看日志: journalctl -u socks5-server -n 20"
        journalctl -u socks5-server -n 20 --no-pager
        exit 1
    fi
}

# 显示状态
show_status() {
    echo
    echo "=== SOCKS5服务器状态 ==="
    systemctl status socks5-server --no-pager
    
    echo
    echo "=== 端口监听状态 ==="
    netstat -tuln | grep ":$SOCKS_PORT " || echo "端口 $SOCKS_PORT 未监听"
    
    echo
    echo "=== 最近日志 ==="
    journalctl -u socks5-server -n 10 --no-pager
}

# 显示使用信息
show_usage_info() {
    #local server_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "SERVER_IP")
    local server_ip=$(wget -qO- "http://4.ipw.cn")
    echo
    echo "=== SOCKS5服务器安装完成 ==="
    echo "服务器地址: $server_ip"
    echo "端口: $SOCKS_PORT"
    echo "用户名: $SOCKS_USER"
    echo "密码: ***"
    echo
    echo "测试命令:"
    echo "curl --socks5 $SOCKS_USER:$SOCKS_PASS@$server_ip:$SOCKS_PORT http://4.ipw.cn"
    echo
    echo "管理命令:"
    echo "systemctl status socks5-server  # 查看状态"
    echo "systemctl restart socks5-server # 重启服务"
    echo "systemctl stop socks5-server    # 停止服务"
    echo "journalctl -u socks5-server -f  # 查看实时日志"
    echo
    echo "配置文件: $CONFIG_FILE"
    echo "二进制文件: $INSTALL_DIR/socks5-server"
}

# 安装依赖
install_dependencies() {
    log_info "安装系统依赖..."
    apt-get update
    apt-get install -y wget curl net-tools
}

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "请使用root权限运行此脚本"
        exit 1
    fi
}

# 修复现有安装
fix_existing_installation() {
    log_info "检测到现有安装，尝试修复..."
    
    # 停止服务
    systemctl stop socks5-server 2>/dev/null || true
    
    # 检查二进制文件
    if [ -f "$INSTALL_DIR/socks5-server" ]; then
        log_info "修复二进制文件权限..."
        chmod 755 "$INSTALL_DIR/socks5-server"
        
        # 验证权限
        if [ -x "$INSTALL_DIR/socks5-server" ]; then
            log_info "二进制文件权限修复成功"
        else
            log_error "二进制文件权限修复失败"
            return 1
        fi
    else
        log_error "二进制文件不存在: $INSTALL_DIR/socks5-server"
        return 1
    fi
    
    # 重新启动服务
    systemctl daemon-reload
    systemctl start socks5-server
    
    sleep 2
    
    if systemctl is-active --quiet socks5-server; then
        log_info "修复成功，服务已启动"
        return 0
    else
        log_error "修复失败"
        return 1
    fi
}

# 主安装函数
main_install() {
    log_info "开始安装SOCKS5服务器..."
    
    check_root
    
    # 检查是否已安装
    if systemctl list-unit-files | grep -q socks5-server; then
        log_warn "检测到已安装的SOCKS5服务器"
        read -p "是否重新安装? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "开始重新安装..."
        else
            read -p "是否尝试修复现有安装? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                if fix_existing_installation; then
                    show_status
                    exit 0
                else
                    log_error "修复失败，请重新安装"
                    exit 1
                fi
            else
                exit 0
            fi
        fi
    fi
    
    install_dependencies
    
    # 获取系统架构
    local arch=$(get_architecture)
    if [ "$arch" = "unknown" ]; then
        log_error "不支持的系统架构: $(uname -m)"
        exit 1
    fi
    
    log_info "检测到系统架构: $arch"
    
    get_user_config
    
    # 安装SOCKS5服务器
    if ! install_socks5_server "$arch"; then
        log_error "SOCKS5服务器安装失败"
        exit 1
    fi
    
    create_config
    create_systemd_service
    configure_firewall
    start_service
    show_usage_info
}

# 卸载函数
uninstall() {
    log_info "开始卸载SOCKS5服务器..."
    
    systemctl stop socks5-server 2>/dev/null || true
    systemctl disable socks5-server 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    rm -rf "$CONFIG_DIR"
    rm -f "$INSTALL_DIR/socks5-server"
    systemctl daemon-reload
    
    log_info "SOCKS5服务器已卸载"
}

# 显示菜单
show_menu() {
    echo "=== SOCKS5服务器管理 ==="
    echo "1. 安装SOCKS5服务器"
    echo "2. 卸载SOCKS5服务器"
    echo "3. 查看服务状态"
    echo "4. 重启服务"
    echo "5. 修复安装"
    echo "6. 清理缓存"
    echo "7. 退出"
    echo
    read -p "请选择操作 [1-7]: " choice
    
    case $choice in
        1) main_install ;;
        2) uninstall ;;
        3) show_status ;;
        4) systemctl restart socks5-server && show_status ;;
        5) fix_existing_installation && show_status ;;
        6) rm -rf "$GO_CACHE_DIR" && log_info "缓存已清理" ;;
        7) exit 0 ;;
        *) echo "无效选择" ;;
    esac
}

# 脚本入口
if [[ $# -eq 0 ]]; then
    show_menu
else
    case $1 in
        install) main_install ;;
        uninstall) uninstall ;;
        status) show_status ;;
        restart) systemctl restart socks5-server ;;
        fix) fix_existing_installation ;;
        clean) rm -rf "$GO_CACHE_DIR" && log_info "缓存已清理" ;;
        *) 
            echo "用法: $0 {install|uninstall|status|restart|fix|clean}"
            echo "不带参数运行显示菜单"
            exit 1
            ;;
    esac
fi
