#!/bin/bash
# install-socks5.sh - 支持ARM架构的SOCKS5服务器一键安装脚本

set -e

# 配置信息
REPO_URL="https://github.com/yoush2021/socks5_server_shell"
DEFAULT_PORT=1080
DEFAULT_USER="admin"
DEFAULT_PASS="admin"
INSTALL_DIR="/usr/local/bin"
SERVICE_NAME="socks5-server"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
CONFIG_DIR="/etc/socks5-server"
LOG_FILE="/var/log/socks5-server.log"
ARCH=""
PLATFORM=""

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 显示横幅
show_banner() {
    cat << "EOF"
    
  ____   ___   ____ _  ______ ____            ____  _          _ _ 
 / ___| / _ \ / ___| |/ / ___| ___|          / ___|| |__   ___| | |
 \___ \| | | | |   | ' /\___ \___ \   _____  \___ \| '_ \ / _ \ | |
  ___) | |_| | |___| . \ ___) |__) | |_____|  ___) | | | |  __/ | |
 |____/ \___/ \____|_|\_\____/____/          |____/|_| |_|\___|_|_|
                                                                   
                                                   
            SOCKS5 服务器一键安装脚本
       支持 x86_64, ARM64, ARMv7 架构
            GitHub: https://github.com/yoush2021/socks5_server_shell
                                                                    
EOF
}

# 检测系统架构
detect_architecture() {
    local arch
    arch=$(uname -m)
    
    case "$arch" in
        x86_64|amd64)
            ARCH="amd64"
            PLATFORM="linux-amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            PLATFORM="linux-arm64"
            ;;
        armv7l|armv7)
            ARCH="armv7"
            PLATFORM="linux-armv7"
            ;;
        armv6l|armv6)
            ARCH="armv6"
            PLATFORM="linux-armv6"
            ;;
        *)
            log_error "不支持的架构: $arch"
            log_info "支持的架构: x86_64, arm64, armv7, armv6"
            exit 1
            ;;
    esac
    
    log_info "检测到系统架构: $arch -> $ARCH"
}

# 检测操作系统
detect_os() {
    if [[ -f /etc/redhat-release ]]; then
        OS="centos"
    elif grep -Eqi "debian" /etc/issue || grep -Eqi "debian" /etc/os-release; then
        OS="debian"
    elif grep -Eqi "ubuntu" /etc/issue || grep -Eqi "ubuntu" /etc/os-release; then
        OS="ubuntu"
    elif grep -Eqi "raspbian" /etc/issue || grep -Eqi "raspbian" /etc/os-release; then
        OS="raspbian"
    else
        OS="unknown"
        log_warn "未知操作系统，尝试继续安装..."
    fi
    
    log_info "检测到操作系统: $OS"
}

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "请使用root权限运行此脚本"
        exit 1
    fi
}

# 安装系统依赖
install_dependencies() {
    log_info "安装系统依赖..."
    
    case $OS in
        "centos"|"rhel"|"fedora")
            yum update -y
            yum install -y wget curl net-tools
            ;;
        "debian"|"ubuntu"|"raspbian")
            apt-get update
            apt-get install -y wget curl net-tools
            ;;
        *)
            log_warn "未知操作系统，尝试安装基本依赖..."
            if command -v apt-get >/dev/null; then
                apt-get update && apt-get install -y wget curl net-tools
            elif command -v yum >/dev/null; then
                yum update -y && yum install -y wget curl net-tools
            else
                log_error "无法安装依赖，请手动安装: wget curl net-tools"
                exit 1
            fi
            ;;
    esac
    
    log_info "系统依赖安装完成"
}

# 为ARM设备安装Go
install_go_for_arm() {
    local go_version="1.21.0"
    local go_tarball="go${go_version}.${PLATFORM}.tar.gz"
    
    log_info "为设备安装Go ${go_version}..."
    
    # 尝试多个镜像源
    local mirrors=(
        "https://golang.org/dl/${go_tarball}"
        "https://dl.google.com/go/${go_tarball}"
        "https://mirrors.aliyun.com/golang/${go_tarball}"
        "https://mirrors.ustc.edu.cn/golang/${go_tarball}"
    )
    
    local download_success=0
    for mirror in "${mirrors[@]}"; do
        log_info "尝试从: $(basename $mirror)"
        if wget --timeout=30 -O "/tmp/${go_tarball}" "$mirror"; then
            download_success=1
            break
        fi
    done
    
    if [[ $download_success -eq 0 ]]; then
        log_error "Go安装包下载失败"
        return 1
    fi
    
    # 安装Go
    tar -C /usr/local -xzf "/tmp/${go_tarball}"
    rm -f "/tmp/${go_tarball}"
    
    # 设置环境变量
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    echo 'export PATH=$PATH:/root/go/bin' >> /etc/profile
    
    # 验证安装
    if command -v go >/dev/null 2>&1; then
        log_info "✅ Go安装成功: $(go version)"
        return 0
    else
        log_error "❌ Go安装失败"
        return 1
    fi
}

# 创建完整的SOCKS5服务器Go代码
create_socks5_go_code() {
    local build_dir=$1
    
    cat > "${build_dir}/main.go" << 'EOF'
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

	success              = 0x00
	generalFailure       = 0x01
	connectionNotAllowed = 0x02
	networkUnreachable   = 0x03
	hostUnreachable      = 0x04
	connectionRefused    = 0x05
	ttlExpired           = 0x06
	commandNotSupported  = 0x07
	addressTypeNotSupported = 0x08
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
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-sigCh
		log.Println("Shutting down SOCKS5 server...")
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			if s.config.Verbose {
				log.Printf("Failed to accept connection: %v", err)
			}
			continue
		}

		go s.handleConnection(conn)
	}

	log.Println("SOCKS5 server stopped")
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
		s.sendReply(conn, addressTypeNotSupported, nil)
		return errors.New("address type not supported")
	}

	// Handle command
	switch cmd {
	case cmdConnect:
		return s.handleConnect(conn, host, port)
	default:
		s.sendReply(conn, commandNotSupported, nil)
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
			replyCode = connectionRefused
		case strings.Contains(err.Error(), "network is unreachable"):
			replyCode = networkUnreachable
		case strings.Contains(err.Error(), "no such host"):
			replyCode = hostUnreachable
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
		log.Printf("Connection to %s closed", targetAddr)
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
}

# 编译SOCKS5服务器
compile_socks5_server() {
    log_info "编译SOCKS5服务器 (架构: $ARCH)..."
    
    # 检查是否已安装Go
    if ! command -v go >/dev/null 2>&1; then
        log_info "安装Go语言环境..."
        if ! install_go_for_arm; then
            log_error "Go安装失败"
            return 1
        fi
    fi
    
    # 创建临时构建目录
    local build_dir="/tmp/socks5-build-$$"
    mkdir -p "$build_dir"
    cd "$build_dir"
    
    # 创建Go模块文件
    cat > go.mod << 'EOF'
module socks5-server

go 1.21
EOF

    # 创建完整的SOCKS5服务器源码
    create_socks5_go_code "$build_dir"
    
    # 设置Go环境变量（针对架构优化）
    export GOOS=linux
    case "$ARCH" in
        "arm64") export GOARCH=arm64 ;;
        "armv7") export GOARCH=arm GOARM=7 ;;
        "armv6") export GOARCH=arm GOARM=6 ;;
        *) export GOARCH=amd64 ;;
    esac
    
    # 编译优化参数
    export CGO_ENABLED=0
    export GOPROXY="https://goproxy.cn,direct"
    
    log_info "编译参数: GOOS=$GOOS, GOARCH=$GOARCH"
    
    # 编译
    log_info "开始编译SOCKS5服务器..."
    if go build -ldflags="-s -w" -o "$INSTALL_DIR/socks5-server" main.go; then
        chmod 755 "$INSTALL_DIR/socks5-server"
        log_info "✅ SOCKS5服务器编译成功"
        
        # 简单验证二进制文件
        if [ -x "$INSTALL_DIR/socks5-server" ]; then
            log_info "✅ 二进制文件验证通过"
        fi
    else
        log_error "❌ 编译失败"
        # 清理临时文件
        cd /
        rm -rf "$build_dir"
        return 1
    fi
    
    # 清理临时文件
    cd /
    rm -rf "$build_dir"
    return 0
}

# 交互式配置
get_user_config() {
    echo
    log_info "=== SOCKS5服务器配置 ==="
    log_info "检测到设备: $ARCH 架构"
    
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
    echo "  架构: $ARCH"
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

# 创建配置文件
create_config() {
    log_info "创建配置文件..."
    
    mkdir -p "$CONFIG_DIR"
    
    cat > "$CONFIG_DIR/config" << EOF
# SOCKS5服务器配置
# 架构: $ARCH
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
Description=SOCKS5 Proxy Server ($ARCH)
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

    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    log_info "Systemd服务已创建: $SERVICE_FILE"
}

# 配置防火墙
configure_firewall() {
    log_info "配置防火墙..."
    
    # 检查UFW (Ubuntu/Debian)
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        ufw allow $SOCKS_PORT/tcp
        log_info "UFW防火墙已放行端口: $SOCKS_PORT"
    fi
    
    # 检查firewalld (CentOS/RHEL)
    if command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --state >/dev/null 2>&1; then
            firewall-cmd --permanent --add-port=$SOCKS_PORT/tcp
            firewall-cmd --reload
            log_info "Firewalld已放行端口: $SOCKS_PORT"
        fi
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
    if netstat -tuln 2>/dev/null | grep -q ":$SOCKS_PORT "; then
        log_info "✅ 端口 $SOCKS_PORT 监听正常"
    elif ss -tuln 2>/dev/null | grep -q ":$SOCKS_PORT "; then
        log_info "✅ 端口 $SOCKS_PORT 监听正常"
    else
        log_error "❌ 端口 $SOCKS_PORT 未监听"
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
    log_info "📱 设备架构: $ARCH"
    echo "═══════════════════════════════════════════════════════════════"
    echo
    echo "📋 服务器信息:"
    echo "   ▸ 服务器地址: $server_ip"
    echo "   ▸ 端口: $SOCKS_PORT"
    echo "   ▸ 用户名: $SOCKS_USER"
    echo "   ▸ 密码: $SOCKS_PASS"
    echo "   ▸ 设备架构: $ARCH"
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
    echo "   ▸ 日志文件: /var/log/socks5-server.log"
    echo "   ▸ 服务文件: $SERVICE_FILE"
    echo "   ▸ 二进制文件: $INSTALL_DIR/socks5-server"
    echo
    echo "💡 提示: 确保防火墙已放行端口 $SOCKS_PORT"
    echo "═══════════════════════════════════════════════════════════════"
}

# 主安装函数
main_install() {
    show_banner
    check_root
    detect_architecture
    detect_os
    get_user_config
    install_dependencies
    
    log_info "开始编译SOCKS5服务器..."
    if compile_socks5_server; then
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
    else
        log_error "SOCKS5服务器编译失败"
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
    arch        显示系统架构
    help        显示此帮助信息

示例:
    $0 install      # 交互式安装
    $0 status       # 查看状态
    $0 arch         # 显示架构信息

支持的架构: x86_64, arm64, armv7, armv6

GitHub: $REPO_URL
EOF
}

# 显示架构信息
show_arch_info() {
    detect_architecture
    detect_os
    echo
    log_info "系统信息:"
    echo "  ▸ 架构: $(uname -m) -> $ARCH"
    echo "  ▸ 操作系统: $OS"
    echo "  ▸ 内核: $(uname -r)"
    echo
    log_info "此设备完全支持SOCKS5服务器安装"
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
    if command -v netstat >/dev/null; then
        netstat -tuln | grep ":$SOCKS_PORT " || echo "端口 $SOCKS_PORT 未监听"
    elif command -v ss >/dev/null; then
        ss -tuln | grep ":$SOCKS_PORT " || echo "端口 $SOCKS_PORT 未监听"
    fi
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
    arch|architecture)
        show_arch_info
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
