#!/bin/bash
# install-socks5-forwarder.sh - SOCKS5代理转发服务器

set -e

# 默认配置
DEFAULT_ENTRY_PORT=1080
DEFAULT_ENTRY_USER="admin"
DEFAULT_ENTRY_PASS="admin"
INSTALL_DIR="/usr/local/bin"
SERVICE_NAME="socks5-forwarder"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
CONFIG_DIR="/etc/socks5-forwarder"
LOG_FILE="/var/log/socks5-forwarder.log"

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
    
  ____             _        ____         __                                  _ 
 / ___|  ___   ___| | _____| ___|       / _| ___  _ ____      ____ _ _ __ __| |
 \___ \ / _ \ / __| |/ / __|___ \ _____| |_ / _ \| '__\ \ /\ / / _` | '__/ _` |
  ___) | (_) | (__|   <\__ \___) |_____|  _| (_) | |   \ V  V / (_| | | | (_| |
 |____/ \___/ \___|_|\_\___/____/      |_|  \___/|_|    \_/\_/ \__,_|_|  \__,_|
                                                                               
                                                   
            SOCKS5 代理转发服务器
            VPS1 → VPS2 代理链
                                                                    
EOF
}

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "请使用root权限运行此脚本"
        exit 1
    fi
}

# 获取VPS2代理信息
get_vps2_info() {
    echo
    log_info "=== 配置VPS2 SOCKS5代理信息 ==="
    
    while true; do
        read -p "VPS2服务器IP地址: " VPS2_IP
        if [[ -n "$VPS2_IP" ]]; then
            break
        else
            log_error "IP地址不能为空"
        fi
    done
    
    read -p "VPS2 SOCKS5端口 [默认: 1080]: " vps2_port
    VPS2_PORT=${vps2_port:-1080}
    
    read -p "VPS2 SOCKS5用户名 [如果无认证请直接回车]: " VPS2_USER
    
    if [[ -n "$VPS2_USER" ]]; then
        read -s -p "VPS2 SOCKS5密码: " VPS2_PASS
        echo
    else
        VPS2_USER=""
        VPS2_PASS=""
    fi
    
    # 测试VPS2连接
    log_info "测试VPS2 SOCKS5连接..."
    if command -v curl >/dev/null 2>&1; then
        if [[ -n "$VPS2_USER" ]]; then
            if timeout 10 curl --socks5 "$VPS2_USER:$VPS2_PASS@$VPS2_IP:$VPS2_PORT" --max-time 5 http://4.ipw.cn >/dev/null 2>&1; then
                log_info "✅ VPS2 SOCKS5连接测试成功"
            else
                log_warn "⚠️  VPS2 SOCKS5连接测试失败，但继续安装"
            fi
        else
            if timeout 10 curl --socks5 "$VPS2_IP:$VPS2_PORT" --max-time 5 http://4.ipw.cn >/dev/null 2>&1; then
                log_info "✅ VPS2 SOCKS5连接测试成功"
            else
                log_warn "⚠️  VPS2 SOCKS5连接测试失败，但继续安装"
            fi
        fi
    else
        log_warn "无法测试连接，请确保VPS2 SOCKS5服务正常运行"
    fi
}

# 获取VPS1配置
get_vps1_config() {
    echo
    log_info "=== 配置VPS1入口代理 ==="
    
    while true; do
        read -p "VPS1监听端口 [默认: $DEFAULT_ENTRY_PORT]: " entry_port
        if [[ -z "$entry_port" ]]; then
            ENTRY_PORT=$DEFAULT_ENTRY_PORT
            break
        elif [[ "$entry_port" =~ ^[0-9]+$ ]] && [ "$entry_port" -ge 1024 ] && [ "$entry_port" -le 65535 ]; then
            ENTRY_PORT=$entry_port
            break
        else
            log_error "端口号必须是1024-65535之间的数字"
        fi
    done
    
    read -p "VPS1认证用户名 [默认: $DEFAULT_ENTRY_USER]: " entry_user
    ENTRY_USER=${entry_user:-$DEFAULT_ENTRY_USER}
    
    read -s -p "VPS1认证密码 [默认: $DEFAULT_ENTRY_PASS]: " entry_pass
    echo
    ENTRY_PASS=${entry_pass:-$DEFAULT_ENTRY_PASS}
    
    # 显示配置摘要
    echo
    log_info "配置摘要:"
    echo "═══════════════════════════════════════"
    echo "  VPS1 (入口): 0.0.0.0:$ENTRY_PORT"
    echo "  认证: $ENTRY_USER / ***"
    echo "  VPS2 (出口): $VPS2_IP:$VPS2_PORT"
    if [[ -n "$VPS2_USER" ]]; then
        echo "  认证: $VPS2_USER / ***"
    else
        echo "  认证: 无"
    fi
    echo "═══════════════════════════════════════"
    echo
    
    read -p "确认配置并开始安装? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "安装取消"
        exit 0
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
    
    # 下载Go
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

# 编译SOCKS5转发服务器
compile_forwarder() {
    log_info "编译SOCKS5代理转发服务器..."
    
    # 创建临时构建目录
    local build_dir="/tmp/socks5-forwarder-$$"
    mkdir -p "$build_dir"
    cd "$build_dir"
    
    # 创建Go模块
    cat > go.mod << 'EOF'
module socks5-forwarder

go 1.21
EOF

    # 创建SOCKS5转发服务器代码
    cat > main.go << EOF
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
	"time"
)

// 配置参数
var (
	entryPort    = flag.Int("entry-port", 1080, "VPS1监听端口")
	entryUser    = flag.String("entry-user", "admin", "VPS1认证用户名")
	entryPass    = flag.String("entry-pass", "admin", "VPS1认证密码")
	exitServer   = flag.String("exit-server", "", "VPS2服务器地址 (IP:端口)")
	exitUser     = flag.String("exit-user", "", "VPS2认证用户名")
	exitPass     = flag.String("exit-pass", "", "VPS2认证密码")
	verbose      = flag.Bool("verbose", true, "详细日志")
)

const (
	socksVersion5 = 0x05
	authNone      = 0x00
	authPassword  = 0x02
	cmdConnect    = 0x01
	atypIPv4      = 0x01
	atypDomain    = 0x03
)

type Forwarder struct {
	exitServer string
	exitUser   string
	exitPass   string
	verbose    bool
}

func NewForwarder(exitServer, exitUser, exitPass string, verbose bool) *Forwarder {
	return &Forwarder{
		exitServer: exitServer,
		exitUser:   exitUser,
		exitPass:   exitPass,
		verbose:    verbose,
	}
}

func (f *Forwarder) StartEntryServer(port int, username, password string) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("监听端口失败: %v", err)
	}
	defer listener.Close()

	if f.verbose {
		log.Printf("🚀 SOCKS5代理转发服务器启动")
		log.Printf("📍 入口: 0.0.0.0:%d (用户: %s)", port, username)
		log.Printf("🎯 出口: %s", f.exitServer)
		if f.exitUser != "" {
			log.Printf("🔑 VPS2认证: %s", f.exitUser)
		}
	}

	// 信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("正在关闭服务器...")
		listener.Close()
		os.Exit(0)
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if f.verbose {
				log.Printf("接受连接错误: %v", err)
			}
			continue
		}

		go f.handleEntryConnection(conn, username, password)
	}
}

func (f *Forwarder) handleEntryConnection(conn net.Conn, username, password string) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr().String()

	if f.verbose {
		log.Printf("📥 新连接来自: %s", clientAddr)
	}

	// VPS1端SOCKS5认证
	if err := f.authenticate(conn, username, password); err != nil {
		if f.verbose {
			log.Printf("❌ VPS1认证失败 %s: %v", clientAddr, err)
		}
		return
	}

	// 处理SOCKS5请求
	if err := f.handleRequest(conn, clientAddr); err != nil {
		if f.verbose {
			log.Printf("❌ 请求处理失败 %s: %v", clientAddr, err)
		}
	} else {
		if f.verbose {
			log.Printf("✅ 连接完成: %s", clientAddr)
		}
	}
}

func (f *Forwarder) authenticate(conn net.Conn, username, password string) error {
	buf := make([]byte, 256)

	// 读取认证方法
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != socksVersion5 {
		return errors.New("无效的SOCKS版本")
	}

	// 发送无需认证
	if username == "" {
		_, err = conn.Write([]byte{socksVersion5, authNone})
		return err
	}

	// 发送用户名密码认证
	_, err = conn.Write([]byte{socksVersion5, authPassword})
	if err != nil {
		return err
	}

	// 读取认证数据
	n, err = conn.Read(buf)
	if err != nil || n < 3 || buf[0] != 0x01 {
		return errors.New("无效的认证数据")
	}

	// 验证用户名密码
	ulen := int(buf[1])
	if n < 2+ulen+1 {
		return errors.New("无效的认证长度")
	}

	plen := int(buf[2+ulen])
	if n != 2+ulen+1+plen {
		return errors.New("无效的密码长度")
	}

	user := string(buf[2 : 2+ulen])
	pass := string(buf[3+ulen : 3+ulen+plen])

	if user != username || pass != password {
		conn.Write([]byte{0x01, 0x01})
		return errors.New("认证失败")
	}

	// 认证成功
	_, err = conn.Write([]byte{0x01, 0x00})
	return err
}

func (f *Forwarder) handleRequest(conn net.Conn, clientAddr string) error {
	buf := make([]byte, 256)

	// 读取SOCKS5请求
	n, err := conn.Read(buf)
	if err != nil || n < 4 || buf[0] != socksVersion5 {
		return errors.New("无效的SOCKS请求")
	}

	cmd := buf[1]
	atyp := buf[3]

	// 只支持CONNECT命令
	if cmd != cmdConnect {
		f.sendReply(conn, 0x07, nil) // Command not supported
		return errors.New("不支持的命令")
	}

	// 解析目标地址
	var host string
	var port uint16

	switch atyp {
	case atypIPv4:
		if n < 10 {
			return errors.New("无效的IPv4地址")
		}
		host = net.IPv4(buf[4], buf[5], buf[6], buf[7]).String()
		port = binary.BigEndian.Uint16(buf[8:10])
	case atypDomain:
		domainLen := int(buf[4])
		if n < 7+domainLen {
			return errors.New("无效的域名长度")
		}
		host = string(buf[5 : 5+domainLen])
		port = binary.BigEndian.Uint16(buf[5+domainLen : 7+domainLen])
	default:
		f.sendReply(conn, 0x08, nil) // Address type not supported
		return errors.New("不支持的地址类型")
	}

	targetAddr := fmt.Sprintf("%s:%d", host, port)

	if f.verbose {
		log.Printf("🔗 连接目标: %s (来自: %s)", targetAddr, clientAddr)
	}

	// 连接到VPS2 SOCKS5代理
	exitConn, err := f.connectToExitServer(targetAddr)
	if err != nil {
		f.sendReply(conn, 0x01, nil) // General failure
		return fmt.Errorf("连接到VPS2失败: %v", err)
	}
	defer exitConn.Close()

	// 发送成功响应
	f.sendReply(conn, 0x00, exitConn.LocalAddr().(*net.TCPAddr))

	// 开始双向数据转发
	return f.forwardData(conn, exitConn, clientAddr, targetAddr)
}

func (f *Forwarder) connectToExitServer(targetAddr string) (net.Conn, error) {
	// 连接到VPS2 SOCKS5代理
	conn, err := net.DialTimeout("tcp", f.exitServer, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// VPS2 SOCKS5认证协商
	authMethods := []byte{socksVersion5, 1, authNone}
	if f.exitUser != "" {
		authMethods = []byte{socksVersion5, 1, authPassword}
	}

	if _, err := conn.Write(authMethods); err != nil {
		conn.Close()
		return nil, err
	}

	// 读取认证方法响应
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil || resp[0] != socksVersion5 {
		conn.Close()
		return nil, errors.New("VPS2认证协商失败")
	}

	// 用户名密码认证
	if f.exitUser != "" && resp[1] == authPassword {
		authReq := make([]byte, 3+len(f.exitUser)+len(f.exitPass))
		authReq[0] = 0x01
		authReq[1] = byte(len(f.exitUser))
		copy(authReq[2:], f.exitUser)
		authReq[2+len(f.exitUser)] = byte(len(f.exitPass))
		copy(authReq[3+len(f.exitUser):], f.exitPass)

		if _, err := conn.Write(authReq); err != nil {
			conn.Close()
			return nil, err
		}

		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil || authResp[1] != 0x00 {
			conn.Close()
			return nil, errors.New("VPS2认证失败")
		}
	}

	// 发送CONNECT请求到VPS2
	connectReq := make([]byte, 10)
	connectReq[0] = socksVersion5
	connectReq[1] = cmdConnect
	connectReq[2] = 0x00
	connectReq[3] = atypIPv4
	// 目标地址会在VPS2端解析，这里发送空地址
	if _, err := conn.Write(connectReq); err != nil {
		conn.Close()
		return nil, err
	}

	// 读取VPS2响应
	connectResp := make([]byte, 10)
	if _, err := io.ReadFull(conn, connectResp); err != nil || connectResp[1] != 0x00 {
		conn.Close()
		return nil, errors.New("VPS2连接失败")
	}

	return conn, nil
}

func (f *Forwarder) forwardData(clientConn, exitConn net.Conn, clientAddr, targetAddr string) error {
	done := make(chan error, 2)

	// 客户端 → VPS2
	go func() {
		_, err := io.Copy(exitConn, clientConn)
		done <- err
	}()

	// VPS2 → 客户端
	go func() {
		_, err := io.Copy(clientConn, exitConn)
		done <- err
	}()

	// 等待任一方向完成
	err := <-done
	if f.verbose {
		if err != nil {
			log.Printf("🔌 连接关闭 %s → %s: %v", clientAddr, targetAddr, err)
		} else {
			log.Printf("🔌 连接正常关闭 %s → %s", clientAddr, targetAddr)
		}
	}

	return err
}

func (f *Forwarder) sendReply(conn net.Conn, replyCode byte, addr *net.TCPAddr) error {
	var reply []byte

	if addr != nil {
		reply = make([]byte, 10)
		reply[0] = socksVersion5
		reply[1] = replyCode
		reply[2] = 0x00
		reply[3] = atypIPv4
		copy(reply[4:8], addr.IP.To4())
		binary.BigEndian.PutUint16(reply[8:10], uint16(addr.Port))
	} else {
		reply = []byte{
			socksVersion5,
			replyCode,
			0x00,
			atypIPv4,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00,
		}
	}

	_, err := conn.Write(reply)
	return err
}

func main() {
	flag.Parse()

	if *exitServer == "" {
		log.Fatal("必须指定VPS2服务器地址")
	}

	forwarder := NewForwarder(*exitServer, *exitUser, *exitPass, *verbose)
	
	if err := forwarder.StartEntryServer(*entryPort, *entryUser, *entryPass); err != nil {
		log.Fatalf("服务器启动失败: %v", err)
	}
}
EOF

    # 编译
    export GO111MODULE=on
    if go build -ldflags="-s -w" -o "$INSTALL_DIR/socks5-forwarder" main.go; then
        chmod +x "$INSTALL_DIR/socks5-forwarder"
        log_info "✅ SOCKS5转发服务器编译成功"
    else
        log_error "❌ 编译失败"
        cd /
        rm -rf "$build_dir"
        return 1
    fi

    cd /
    rm -rf "$build_dir"
    return 0
}

# 创建配置文件
create_config() {
    log_info "创建配置文件..."
    
    mkdir -p "$CONFIG_DIR"
    
    cat > "$CONFIG_DIR/forwarder.conf" << EOF
# SOCKS5代理转发配置
# 生成时间: $(date)

# VPS1入口配置
ENTRY_PORT=$ENTRY_PORT
ENTRY_USER=$ENTRY_USER
ENTRY_PASS=$ENTRY_PASS

# VPS2出口配置  
VPS2_IP=$VPS2_IP
VPS2_PORT=$VPS2_PORT
VPS2_USER=$VPS2_USER
VPS2_PASS=$VPS2_PASS
EOF

    chmod 600 "$CONFIG_DIR/forwarder.conf"
    log_info "配置文件已创建: $CONFIG_DIR/forwarder.conf"
}

# 创建systemd服务
create_systemd_service() {
    log_info "创建systemd服务..."
    
    # 构建启动命令
    local start_cmd="$INSTALL_DIR/socks5-forwarder -entry-port $ENTRY_PORT -entry-user \"$ENTRY_USER\" -entry-pass \"$ENTRY_PASS\" -exit-server \"$VPS2_IP:$VPS2_PORT\""
    
    if [[ -n "$VPS2_USER" ]]; then
        start_cmd="$start_cmd -exit-user \"$VPS2_USER\" -exit-pass \"$VPS2_PASS\""
    fi
    
    start_cmd="$start_cmd -verbose=true"
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=SOCKS5 Proxy Forwarder (VPS1 -> VPS2)
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=$start_cmd
Restart=always
RestartSec=5
User=root
Group=root

# 日志配置
StandardOutput=journal
StandardError=journal

# 安全设置
NoNewPrivileges=yes
PrivateTmp=yes

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
    
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        ufw allow $ENTRY_PORT/tcp
        log_info "✅ UFW已放行端口: $ENTRY_PORT"
    fi
    
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=$ENTRY_PORT/tcp
        firewall-cmd --reload
        log_info "✅ Firewalld已放行端口: $ENTRY_PORT"
    fi
    
    # 通用iptables规则
    if command -v iptables >/dev/null 2>&1; then
        iptables -I INPUT -p tcp --dport $ENTRY_PORT -j ACCEPT 2>/dev/null && \
        log_info "✅ iptables已放行端口: $ENTRY_PORT" || true
    fi
}

# 启动服务
start_service() {
    log_info "启动SOCKS5转发服务..."
    
    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    systemctl restart $SERVICE_NAME
    
    sleep 3
    
    if systemctl is-active --quiet $SERVICE_NAME; then
        log_info "✅ SOCKS5转发服务器启动成功!"
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
    if netstat -tuln 2>/dev/null | grep -q ":$ENTRY_PORT "; then
        log_info "✅ 端口 $ENTRY_PORT 监听正常"
    elif ss -tuln 2>/dev/null | grep -q ":$ENTRY_PORT "; then
        log_info "✅ 端口 $ENTRY_PORT 监听正常"
    else
        log_error "❌ 端口 $ENTRY_PORT 未监听"
        return 1
    fi
    
    return 0
}

# 显示安装结果
show_installation_result() {
    local vps1_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [[ -z "$vps1_ip" ]]; then
        vps1_ip="你的VPS1_IP"
    fi
    
    echo
    echo "═══════════════════════════════════════════════════════════════"
    log_info "🎉 SOCKS5代理转发服务器安装完成!"
    echo "═══════════════════════════════════════════════════════════════"
    echo
    echo "📱 客户端配置:"
    echo "   ▸ 服务器: $vps1_ip"
    echo "   ▸ 端口: $ENTRY_PORT"
    echo "   ▸ 协议: SOCKS5"
    echo "   ▸ 用户名: $ENTRY_USER"
    echo "   ▸ 密码: $ENTRY_PASS"
    echo
    echo "🔗 转发路径:"
    echo "   ▸ 客户端 → VPS1:$ENTRY_PORT → VPS2:$VPS2_PORT → 目标网站"
    echo
    echo "🔧 测试命令:"
    if [[ -n "$ENTRY_USER" ]]; then
        echo "   curl --socks5 $ENTRY_USER:$ENTRY_PASS@$vps1_ip:$ENTRY_PORT http://4.ipw.cn"
    else
        echo "   curl --socks5 $vps1_ip:$ENTRY_PORT http://4.ipw.cn"
    fi
    echo
    echo "⚙️  管理命令:"
    echo "   systemctl status $SERVICE_NAME    # 查看状态"
    echo "   systemctl restart $SERVICE_NAME   # 重启服务"
    echo "   journalctl -u $SERVICE_NAME -f    # 查看实时日志"
    echo
    echo "💡 提示:"
    echo "   ▸ 所有流量将通过 VPS2 ($VPS2_IP) 出口"
    echo "   ▸ 确保VPS2的SOCKS5服务正常运行"
    echo "═══════════════════════════════════════════════════════════════"
}

# 主安装函数
main_install() {
    show_banner
    check_root
    get_vps2_info
    get_vps1_config
    install_dependencies
    install_go
    compile_forwarder
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
    install     安装SOCKS5代理转发服务器 (默认)
    uninstall   卸载
    status      查看服务状态
    restart     重启服务
    help        显示帮助

示例:
    $0 install      # 交互式安装
    $0 status       # 查看状态

功能:
    📍 在VPS1部署SOCKS5代理转发
    🔗 将流量转发到VPS2现有SOCKS5代理
    🔐 支持双重认证
    📊 完整日志记录
EOF
}

# 卸载功能
uninstall_server() {
    log_info "开始卸载SOCKS5转发服务器..."
    
    systemctl stop $SERVICE_NAME 2>/dev/null || true
    systemctl disable $SERVICE_NAME 2>/dev/null || true
    rm -f $SERVICE_FILE
    rm -f $INSTALL_DIR/socks5-forwarder
    rm -rf $CONFIG_DIR
    systemctl daemon-reload
    
    log_info "✅ SOCKS5转发服务器已卸载"
}

# 显示状态
show_status() {
    echo
    log_info "=== SOCKS5转发服务器状态 ==="
    systemctl status $SERVICE_NAME --no-pager
    
    echo
    log_info "=== 端口监听状态 ==="
    if command -v netstat >/dev/null; then
        netstat -tuln | grep ":$ENTRY_PORT " || echo "端口 $ENTRY_PORT 未监听"
    elif command -v ss >/dev/null; then
        ss -tuln | grep ":$ENTRY_PORT " || echo "端口 $ENTRY_PORT 未监听"
    fi
    
    echo
    log_info "=== 最近日志 ==="
    journalctl -u $SERVICE_NAME -n 10 --no-pager
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
