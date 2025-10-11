#!/bin/bash
# install-socks5.sh - SOCKS5服务器一键安装管理脚本

set -e

# 默认配置
DEFAULT_PORT=1080
DEFAULT_USER="admin"
DEFAULT_PASS="admin"
INSTALL_DIR="/usr/local/bin"
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

# 显示横幅
show_banner() {
    cat << "EOF"
    
  ____             _        ____  _   _ _____    ____  _          _ _ 
 / ___|  ___   ___| | _____| ___|| \ | |  ___|  / ___|| |__   ___| | |
 \___ \ / _ \ / __| |/ / __|___ \|  \| | |_ ____\___ \| '_ \ / _ \ | |
  ___) | (_) | (__|   <\__ \___) | |\  |  _|_____|__) | | | |  __/ | |
 |____/ \___/ \___|_|\_\___/____/|_| \_|_|      |____/|_| |_|\___|_|_|
                                                                      
                                                   
            SOCKS5 服务器一键管理脚本
           GitHub: yoush2021/socks5_server_shell
                                                                    
EOF
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
    
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        apt-get install -y wget curl net-tools
    elif command -v yum >/dev/null 2>&1; then
        yum update -y
        yum install -y wget curl net-tools
    else
        log_error "不支持的包管理器"
        exit 1
    fi
}

# 安装Go环境
install_go() {
    if command -v go >/dev/null 2>&1; then
        log_info "Go已安装: $(go version)"
        return 0
    fi
    
    log_info "安装Go语言环境..."
    
    local arch=$(uname -m)
    case "$arch" in
        x86_64) local go_tarball="go1.21.0.linux-amd64.tar.gz" ;;
        aarch64) local go_tarball="go1.21.0.linux-arm64.tar.gz" ;;
        armv7l) local go_tarball="go1.21.0.linux-armv6l.tar.gz" ;;
        *) log_error "不支持的架构: $arch"; return 1 ;;
    esac
    
    if wget -O /tmp/go.tar.gz "https://golang.org/dl/$go_tarball"; then
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm -f /tmp/go.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
        log_info "✅ Go安装成功"
        return 0
    else
        log_error "❌ Go安装失败"
        return 1
    fi
}

# 编译节点版SOCKS5服务器
compile_node_server() {
    log_info "编译节点版SOCKS5服务器..."
    
    local build_dir="/tmp/socks5-node-$$"
    mkdir -p "$build_dir"
    cd "$build_dir"
    
    cat > go.mod << 'EOF'
module socks5-node

go 1.21
EOF

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
	authNone      = 0x00
	authPassword  = 0x02
	cmdConnect    = 0x01
	atypIPv4      = 0x01
	atypDomain    = 0x03
)

type Server struct {
	config *Config
}

type Config struct {
	Port     int
	Username string
	Password string
	Verbose  bool
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
		log.Printf("SOCKS5节点服务器启动在端口 %d", s.config.Port)
		if s.config.Username != "" {
			log.Printf("认证用户: %s", s.config.Username)
		} else {
			log.Printf("无认证模式")
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("关闭SOCKS5服务器...")
		listener.Close()
		os.Exit(0)
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			if s.config.Verbose {
				log.Printf("接受连接错误: %v", err)
			}
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
		log.Printf("新连接来自: %s", clientAddr)
	}

	if err := s.authenticate(conn); err != nil {
		if s.config.Verbose {
			log.Printf("认证失败 %s: %v", clientAddr, err)
		}
		return
	}

	if err := s.handleRequest(conn); err != nil {
		if s.config.Verbose {
			log.Printf("请求处理失败 %s: %v", clientAddr, err)
		}
	} else {
		if s.config.Verbose {
			log.Printf("连接完成: %s", clientAddr)
		}
	}
}

func (s *Server) authenticate(conn net.Conn) error {
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != socksVersion5 {
		return errors.New("invalid SOCKS version")
	}

	if s.config.Username == "" {
		_, err = conn.Write([]byte{socksVersion5, authNone})
	} else {
		_, err = conn.Write([]byte{socksVersion5, authPassword})
	}
	if err != nil {
		return err
	}

	if s.config.Username != "" {
		n, err = conn.Read(buf)
		if err != nil || n < 3 || buf[0] != 0x01 {
			return errors.New("invalid auth data")
		}

		ulen := int(buf[1])
		if n < 2+ulen+1 {
			return errors.New("invalid username length")
		}

		plen := int(buf[2+ulen])
		if n != 2+ulen+1+plen {
			return errors.New("invalid password length")
		}

		user := string(buf[2 : 2+ulen])
		pass := string(buf[3+ulen : 3+ulen+plen])

		if user != s.config.Username || pass != s.config.Password {
			conn.Write([]byte{0x01, 0x01})
			return errors.New("authentication failed")
		}
		conn.Write([]byte{0x01, 0x00})
	}
	return nil
}

func (s *Server) handleRequest(conn net.Conn) error {
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 4 || buf[0] != socksVersion5 {
		return errors.New("invalid SOCKS request")
	}

	cmd := buf[1]
	atyp := buf[3]

	if cmd != 0x01 {
		s.sendReply(conn, 0x07, nil)
		return errors.New("command not supported")
	}

	var host string
	var port uint16

	switch atyp {
	case 0x01:
		if n < 10 {
			return errors.New("invalid IPv4 address")
		}
		host = net.IPv4(buf[4], buf[5], buf[6], buf[7]).String()
		port = binary.BigEndian.Uint16(buf[8:10])
	case 0x03:
		domainLen := int(buf[4])
		if n < 7+domainLen {
			return errors.New("invalid domain length")
		}
		host = string(buf[5 : 5+domainLen])
		port = binary.BigEndian.Uint16(buf[5+domainLen : 7+domainLen])
	default:
		s.sendReply(conn, 0x08, nil)
		return errors.New("address type not supported")
	}

	targetAddr := fmt.Sprintf("%s:%d", host, port)
	if s.config.Verbose {
		log.Printf("连接目标: %s", targetAddr)
	}

	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		s.sendReply(conn, 0x01, nil)
		return fmt.Errorf("connect to target failed: %v", err)
	}
	defer target.Close()

	localAddr := target.LocalAddr().(*net.TCPAddr)
	if err := s.sendReply(conn, 0x00, localAddr); err != nil {
		return err
	}

	done := make(chan error, 2)
	go func() {
		_, err := io.Copy(target, conn)
		done <- err
	}()
	go func() {
		_, err := io.Copy(conn, target)
		done <- err
	}()

	err = <-done
	return err
}

func (s *Server) sendReply(conn net.Conn, replyCode byte, addr *net.TCPAddr) error {
	reply := []byte{
		socksVersion5,
		replyCode,
		0x00,
		atypIPv4,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}

	if addr != nil {
		copy(reply[4:8], addr.IP.To4())
		binary.BigEndian.PutUint16(reply[8:10], uint16(addr.Port))
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

    export GO111MODULE=on
    if go build -ldflags="-s -w" -o "$INSTALL_DIR/socks5-node" main.go; then
        chmod +x "$INSTALL_DIR/socks5-node"
        log_info "✅ 节点版SOCKS5服务器编译成功"
    else
        log_error "❌ 节点版编译失败"
        return 1
    fi

    cd /
    rm -rf "$build_dir"
    return 0
}

# 编译转发版SOCKS5服务器
compile_forward_server() {
    log_info "编译转发版SOCKS5服务器..."
    
    local build_dir="/tmp/socks5-forward-$$"
    mkdir -p "$build_dir"
    cd "$build_dir"
    
    cat > go.mod << 'EOF'
module socks5-forward

go 1.21
EOF

    cat > main.go << 'EOF'
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	entryPort  = flag.Int("entry-port", 1080, "VPS1监听端口")
	entryUser  = flag.String("entry-user", "admin", "VPS1用户名")
	entryPass  = flag.String("entry-pass", "admin", "VPS1密码")
	exitIP     = flag.String("exit-ip", "", "VPS2 IP地址")
	exitPort   = flag.Int("exit-port", 1080, "VPS2端口")
	exitUser   = flag.String("exit-user", "", "VPS2用户名")
	exitPass   = flag.String("exit-pass", "", "VPS2密码")
	verbose    = flag.Bool("verbose", true, "详细日志")
)

const (
	socksVersion5 = 0x05
	authNone      = 0x00
	authPassword  = 0x02
	cmdConnect    = 0x01
	atypIPv4      = 0x01
	atypDomain    = 0x03
)

func main() {
	flag.Parse()
	
	if *exitIP == "" {
		log.Fatal("必须指定VPS2 IP地址")
	}

	log.Printf("🚀 SOCKS5转发服务器启动")
	log.Printf("📍 VPS1: 0.0.0.0:%d", *entryPort)
	log.Printf("🎯 VPS2: %s:%d", *exitIP, *exitPort)

	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", *entryPort))
	if err != nil {
		log.Fatal("监听失败:", err)
	}
	defer listener.Close()

	log.Printf("✅ 端口 %d 监听成功", *entryPort)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("关闭服务器...")
		listener.Close()
		os.Exit(0)
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if *verbose {
				log.Printf("接受连接错误: %v", err)
			}
			continue
		}
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr().String()
	
	if *verbose {
		log.Printf("📥 新连接: %s", clientAddr)
	}

	if err := handleSocks5Handshake(conn); err != nil {
		if *verbose {
			log.Printf("❌ VPS1握手失败 %s: %v", clientAddr, err)
		}
		return
	}

	if err := handleSocks5Request(conn, clientAddr); err != nil {
		if *verbose {
			log.Printf("❌ 请求失败 %s: %v", clientAddr, err)
		}
	} else {
		if *verbose {
			log.Printf("✅ 连接完成: %s", clientAddr)
		}
	}
}

func handleSocks5Handshake(conn net.Conn) error {
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != socksVersion5 {
		return fmt.Errorf("无效SOCKS版本")
	}

	if *entryUser == "admin" && *entryPass == "admin" {
		_, err = conn.Write([]byte{socksVersion5, authNone})
	} else {
		_, err = conn.Write([]byte{socksVersion5, authPassword})
	}
	if err != nil {
		return err
	}

	if *entryUser != "admin" || *entryPass != "admin" {
		n, err = conn.Read(buf)
		if err != nil || n < 3 || buf[0] != 0x01 {
			return fmt.Errorf("无效认证数据")
		}

		ulen := int(buf[1])
		if n < 2+ulen+1 {
			return fmt.Errorf("无效用户长度")
		}

		plen := int(buf[2+ulen])
		if n != 2+ulen+1+plen {
			return fmt.Errorf("无效密码长度")
		}

		user := string(buf[2 : 2+ulen])
		pass := string(buf[3+ulen : 3+ulen+plen])

		if user != *entryUser || pass != *entryPass {
			conn.Write([]byte{0x01, 0x01})
			return fmt.Errorf("认证失败")
		}
		conn.Write([]byte{0x01, 0x00})
	}
	return nil
}

func handleSocks5Request(conn net.Conn, clientAddr string) error {
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 4 || buf[0] != socksVersion5 {
		return fmt.Errorf("无效SOCKS请求")
	}

	cmd := buf[1]
	atyp := buf[3]

	if cmd != cmdConnect {
		sendReply(conn, 0x07, nil)
		return fmt.Errorf("不支持的命令: %d", cmd)
	}

	var host string
	var port uint16

	switch atyp {
	case atypIPv4:
		if n < 10 {
			return fmt.Errorf("无效IPv4地址")
		}
		host = net.IPv4(buf[4], buf[5], buf[6], buf[7]).String()
		port = binary.BigEndian.Uint16(buf[8:10])
	case atypDomain:
		domainLen := int(buf[4])
		if n < 7+domainLen {
			return fmt.Errorf("无效域名长度")
		}
		host = string(buf[5 : 5+domainLen])
		port = binary.BigEndian.Uint16(buf[5+domainLen : 7+domainLen])
	default:
		sendReply(conn, 0x08, nil)
		return fmt.Errorf("不支持的地址类型: %d", atyp)
	}

	target := fmt.Sprintf("%s:%d", host, port)
	log.Printf("🔗 转发目标: %s <- %s", target, clientAddr)

	exitConn, err := connectToVPS2Fixed(target)
	if err != nil {
		sendReply(conn, 0x01, nil)
		return fmt.Errorf("VPS2连接失败: %v", err)
	}
	defer exitConn.Close()

	localAddr := exitConn.LocalAddr().(*net.TCPAddr)
	sendReply(conn, 0x00, localAddr)

	done := make(chan error, 2)
	go func() {
		_, err := io.Copy(exitConn, conn)
		done <- err
	}()
	go func() {
		_, err := io.Copy(conn, exitConn)
		done <- err
	}()
	
	err = <-done
	return err
}

func connectToVPS2Fixed(target string) (net.Conn, error) {
	exitServer := fmt.Sprintf("%s:%d", *exitIP, *exitPort)
	conn, err := net.DialTimeout("tcp", exitServer, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("连接VPS2失败: %v", err)
	}

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	authMethods := []byte{socksVersion5, 1, authNone}
	if *exitUser != "" {
		authMethods = []byte{socksVersion5, 1, authPassword}
	}

	if _, err := conn.Write(authMethods); err != nil {
		conn.Close()
		return nil, fmt.Errorf("发送认证方法失败: %v", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("读取认证响应失败: %v", err)
	}

	if resp[0] != socksVersion5 {
		conn.Close()
		return nil, fmt.Errorf("无效的SOCKS版本响应: %d", resp[0])
	}

	if *exitUser != "" && resp[1] == authPassword {
		authReq := make([]byte, 0, 3+len(*exitUser)+len(*exitPass))
		authReq = append(authReq, 0x01)
		authReq = append(authReq, byte(len(*exitUser)))
		authReq = append(authReq, []byte(*exitUser)...)
		authReq = append(authReq, byte(len(*exitPass)))
		authReq = append(authReq, []byte(*exitPass)...)

		if _, err := conn.Write(authReq); err != nil {
			conn.Close()
			return nil, fmt.Errorf("发送认证数据失败: %v", err)
		}

		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			conn.Close()
			return nil, fmt.Errorf("读取认证响应失败: %v", err)
		}

		if authResp[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("VPS2认证失败，状态码: %d", authResp[1])
		}
	} else if *exitUser != "" && resp[1] != authPassword {
		conn.Close()
		return nil, fmt.Errorf("VPS2不支持密码认证，支持的方法: %d", resp[1])
	}

	targetHost, targetPort, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("解析目标地址失败: %v", err)
	}

	connectReq := make([]byte, 0, 256)
	connectReq = append(connectReq, socksVersion5, cmdConnect, 0x00)

	if ip := net.ParseIP(targetHost); ip != nil && ip.To4() != nil {
		connectReq = append(connectReq, atypIPv4)
		connectReq = append(connectReq, ip.To4()...)
	} else {
		connectReq = append(connectReq, atypDomain)
		connectReq = append(connectReq, byte(len(targetHost)))
		connectReq = append(connectReq, []byte(targetHost)...)
	}

	portNum := 0
	fmt.Sscanf(targetPort, "%d", &portNum)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(portNum))
	connectReq = append(connectReq, portBytes...)

	if _, err := conn.Write(connectReq); err != nil {
		conn.Close()
		return nil, fmt.Errorf("发送CONNECT请求失败: %v", err)
	}

	connectResp := make([]byte, 256)
	n, err := io.ReadAtLeast(conn, connectResp, 10)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("读取CONNECT响应失败: %v", err)
	}

	if n < 4 || connectResp[0] != socksVersion5 || connectResp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("VPS2连接失败，响应码: %d", connectResp[1])
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

func sendReply(conn net.Conn, replyCode byte, addr *net.TCPAddr) error {
	reply := []byte{
		socksVersion5,
		replyCode,
		0x00,
		atypIPv4,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}

	if addr != nil {
		copy(reply[4:8], addr.IP.To4())
		binary.BigEndian.PutUint16(reply[8:10], uint16(addr.Port))
	}

	_, err := conn.Write(reply)
	return err
}
EOF

    export GO111MODULE=on
    if go build -ldflags="-s -w" -o "$INSTALL_DIR/socks5-forward" main.go; then
        chmod +x "$INSTALL_DIR/socks5-forward"
        log_info "✅ 转发版SOCKS5服务器编译成功"
    else
        log_error "❌ 转发版编译失败"
        return 1
    fi

    cd /
    rm -rf "$build_dir"
    return 0
}

# 安装节点版
install_node_version() {
    log_info "=== 安装节点版SOCKS5服务器 ==="
    
    read -p "监听端口 [默认: $DEFAULT_PORT]: " port
    PORT=${port:-$DEFAULT_PORT}
    
    read -p "认证用户名 [默认: $DEFAULT_USER]: " user
    USERNAME=${user:-$DEFAULT_USER}
    
    read -s -p "认证密码 [默认: $DEFAULT_PASS]: " pass
    echo
    PASSWORD=${pass:-$DEFAULT_PASS}
    
    install_dependencies
    install_go
    compile_node_server
    
    # 创建服务
    cat > /etc/systemd/system/socks5-server.service << EOF
[Unit]
Description=SOCKS5 Node Server
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/socks5-node -port $PORT -user "$USERNAME" -pass "$PASSWORD" -verbose=true
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable socks5-server
    systemctl start socks5-server
    
    log_info "✅ 节点版SOCKS5服务器安装完成"
    log_info "端口: $PORT, 用户: $USERNAME, 密码: $PASSWORD"
}

# 安装转发版
install_forward_version() {
    log_info "=== 安装转发版SOCKS5服务器 ==="
    
    read -p "VPS1监听端口 [默认: $DEFAULT_PORT]: " entry_port
    ENTRY_PORT=${entry_port:-$DEFAULT_PORT}
    
    read -p "VPS1认证用户名 [默认: $DEFAULT_USER]: " entry_user
    ENTRY_USER=${entry_user:-$DEFAULT_USER}
    
    read -s -p "VPS1认证密码 [默认: $DEFAULT_PASS]: " entry_pass
    echo
    ENTRY_PASS=${entry_pass:-$DEFAULT_PASS}
    
    echo "=== VPS2配置 ==="
    read -p "VPS2 IP地址: " EXIT_IP
    read -p "VPS2 SOCKS5端口: " EXIT_PORT
    read -p "VPS2 SOCKS5用户名: " EXIT_USER
    read -s -p "VPS2 SOCKS5密码: " EXIT_PASS
    echo
    
    install_dependencies
    install_go
    compile_forward_server
    
    # 创建服务
    cat > /etc/systemd/system/socks5-server.service << EOF
[Unit]
Description=SOCKS5 Forward Server
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/socks5-forward -entry-port $ENTRY_PORT -entry-user "$ENTRY_USER" -entry-pass "$ENTRY_PASS" -exit-ip "$EXIT_IP" -exit-port $EXIT_PORT -exit-user "$EXIT_USER" -exit-pass "$EXIT_PASS" -verbose=true
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable socks5-server
    systemctl start socks5-server
    
    log_info "✅ 转发版SOCKS5服务器安装完成"
    log_info "VPS1: 0.0.0.0:$ENTRY_PORT ($ENTRY_USER/$ENTRY_PASS)"
    log_info "VPS2: $EXIT_IP:$EXIT_PORT ($EXIT_USER/***)"
}

# 卸载功能
uninstall_server() {
    log_info "开始卸载SOCKS5服务器..."
    
    systemctl stop socks5-server 2>/dev/null || true
    systemctl disable socks5-server 2>/dev/null || true
    rm -f /etc/systemd/system/socks5-server.service
    rm -f $INSTALL_DIR/socks5-node
    rm -f $INSTALL_DIR/socks5-forward
    systemctl daemon-reload
    
    log_info "✅ SOCKS5服务器已卸载"
}

# 显示状态
show_status() {
    if systemctl is-active socks5-server 2>/dev/null; then
        log_info "=== SOCKS5服务器状态 ==="
        systemctl status socks5-server --no-pager
    else
        log_info "SOCKS5服务器未运行"
    fi
}

# 显示菜单
show_menu() {
    echo
    echo "=== SOCKS5服务器管理 ==="
    echo "1. 安装节点版 (独立SOCKS5服务器)"
    echo "2. 安装转发版 (VPS1 → VPS2代理链)" 
    echo "3. 查看服务状态"
    echo "4. 重启服务"
    echo "5. 卸载服务器"
    echo "6. 配置管理"
    echo "7. 退出"
    echo
    read -p "请选择操作 [1-7]: " choice
    
    case $choice in
        1) install_node_version ;;
        2) install_forward_version ;;
        3) show_status ;;
        4) systemctl restart socks5-server && show_status ;;
        5) uninstall_server ;;
        6) ./socks5-config.sh ;;
        7) exit 0 ;;
        *) echo "无效选择" ;;
    esac
}

# 主函数
main() {
    check_root
    show_banner
    
    case "${1:-menu}" in
        "node")
            install_node_version
            ;;
        "forward")
            install_forward_version
            ;;
        "status")
            show_status
            ;;
        "restart")
            systemctl restart socks5-server
            show_status
            ;;
        "uninstall")
            uninstall_server
            ;;
        "menu")
            show_menu
            ;;
        *)
            echo "用法: $0 {node|forward|status|restart|uninstall|menu}"
            echo "  node     - 安装节点版"
            echo "  forward  - 安装转发版"
            echo "  status   - 查看状态"
            echo "  restart  - 重启服务"
            echo "  uninstall- 卸载"
            echo "  menu     - 显示菜单 (默认)"
            ;;
    esac
}

main "$@"
