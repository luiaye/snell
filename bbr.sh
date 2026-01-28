#!/bin/bash
# =========================================
# 作者: luiaye
# 日期: 2026年11月
# 描述: 这个脚本用于配置bbr
# =========================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

# 检查是否以 root 权限运行
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}请以 root 权限运行此脚本。${RESET}"
    exit 1
fi

# 配置系统参数和启用 BBR
configure_system_and_bbr() {
    echo -e "${YELLOW}配置系统参数和BBR...${RESET}"
    
    cat > /etc/sysctl.conf << EOF
# =================================================================
# Linux Kernel Performance Optimization (By Gemini)
# 目标环境: 2-4GB RAM / 1Gbps Bandwidth / KVM or Physical
# =================================================================

# --- 1. BBR 拥塞控制 (核心) ---
# 必须先设置队列算法为 fq，再开启 bbr
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# --- 2. 内存缓冲区优化 (针对 4GB 内存定制) ---
# 接收/发送窗口的最大大小 (字节)
# 16MB 足够跑满 1Gbps 带宽 (125MB/s) 下的 130ms 延迟
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216

# UDP 缓冲区默认值 (兼顾 QUIC/HTTP3/WireGuard)
net.core.rmem_default = 262144
net.core.wmem_default = 262144

# TCP 接收窗口 [最小] [默认] [最大]
# 默认值 256KB 保证一般连接够用，最大值 16MB 允许大流量突发
net.ipv4.tcp_rmem = 4096 262144 16777216
# TCP 发送窗口 [最小] [默认] [最大]
net.ipv4.tcp_wmem = 4096 65536 16777216

# TCP 全局内存压力阈值 (单位: 4KB页)
# 针对 4GB 内存计算: 192MB / 256MB / 384MB
# 当 TCP 占用超过 384MB 内存时，内核开始丢包保护系统
net.ipv4.tcp_mem = 49152 65536 98304

# --- 3. 连接队列与高并发优化 ---
# 网卡设备积压队列 (防止网卡收包过快导致丢包)
net.core.netdev_max_backlog = 30000
# 系统最大连接监听队列 (对应 Nginx/Web 服务)
net.core.somaxconn = 4096
# 半连接队列长度 (防御轻微 SYN Flood)
net.ipv4.tcp_max_syn_backlog = 8192
# 开启 SYN Cookies (防御 SYN Flood 必须开启)
net.ipv4.tcp_syncookies = 1

# --- 4. 协议栈行为调优 ---
# 开启 TCP Fast Open (减少握手延迟，值为3代表客户端和服务端都开启)
net.ipv4.tcp_fastopen = 3
# 禁止空闲后慢启动 (关键！保持空闲连接的传输速度)
net.ipv4.tcp_slow_start_after_idle = 0
# 减少缓冲区膨胀 (降低延迟)
net.ipv4.tcp_notsent_lowat = 16384
# 孤儿连接重试次数 (快速回收资源)
net.ipv4.tcp_orphan_retries = 2
# 开启 MTU 探测 (解决部分网络环境下的包丢弃问题)
net.ipv4.tcp_mtu_probing = 1
# 允许复用 TIME_WAIT 状态的 socket (仅对出站连接有效)
net.ipv4.tcp_tw_reuse = 1

# --- 5. 连接保活与超时 (防止僵尸连接) ---
# TCP Keepalive 心跳时间 (默认2小时 -> 改为10分钟)
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
# 加快 FIN_WAIT2 状态回收 (30秒)
net.ipv4.tcp_fin_timeout = 30

# --- 6. 端口与路由设置 ---
# 扩大本地端口范围 (防止作为代理客户端时端口耗尽)
net.ipv4.ip_local_port_range = 10000 65000
# 开启 IP 转发 (VPN/Docker/路由中转 必须开启)
net.ipv4.ip_forward = 1

# --- 7. 安全性加固 ---
# 忽略恶意的 ICMP 错误消息
net.ipv4.icmp_ignore_bogus_error_responses = 1
# 禁用 ICMP 重定向 (防止路由劫持)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOF

    sysctl -p

    if lsmod | grep -q tcp_bbr && sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        echo -e "${GREEN}BBR 和系统参数已成功配置。${RESET}"
    else
        echo -e "${YELLOW}BBR 或系统参数配置可能需要重启系统才能生效。${RESET}"
    fi
}

# 启用标准BBR
enable_bbr() {
    echo -e "${YELLOW}正在启用标准BBR...${RESET}"
    
    # 检查是否已启用
    if lsmod | grep -q "^tcp_bbr" && sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        echo -e "${GREEN}BBR 已经启用。${RESET}"
        return 0
    fi
    
    configure_system_and_bbr
}

# 安装 XanMod BBR v3
install_xanmod_bbr() {
    echo -e "${YELLOW}准备安装 XanMod 内核...${RESET}"
    
    # 检查架构
    if [ "$(uname -m)" != "x86_64" ]; then
        echo -e "${RED}错误: 仅支持x86_64架构${RESET}"
        return 1
    fi
    
    # 检查系统
    if ! grep -Eqi "debian|ubuntu" /etc/os-release; then
        echo -e "${RED}错误: 仅支持Debian/Ubuntu系统${RESET}"
        return 1
    fi
    
    # 注册PGP密钥
    wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
    
    # 添加存储库
    echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list
    
    # 更新包列表
    apt update -y
    
    # 尝试安装最新版本
    echo -e "${YELLOW}尝试安装最新版本内核...${RESET}"
    if apt install -y linux-xanmod-x64v4; then
        echo -e "${GREEN}成功安装最新版本内核${RESET}"
    else
        echo -e "${YELLOW}最新版本安装失败，尝试安装较低版本...${RESET}"
        if apt install -y linux-xanmod-x64v2; then
            echo -e "${GREEN}成功安装兼容版本内核${RESET}"
        else
            echo -e "${RED}内核安装失败${RESET}"
            return 1
        fi
    fi
    
    configure_system_and_bbr
    
    echo -e "${GREEN}XanMod内核安装完成，请重启系统以使用新内核${RESET}"
    read -p "是否现在重启系统？[y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        reboot
    fi
}

# 手动编译安装BBR v3
install_bbr3_manual() {
    echo -e "${YELLOW}准备手动编译安装BBR v3...${RESET}"
    
    # 安装编译依赖
    apt update
    apt install -y build-essential git
    
    # 克隆源码
    git clone -b v3 https://github.com/google/bbr.git
    cd bbr
    
    # 编译安装
    make
    make install
    
    configure_system_and_bbr
    
    echo -e "${GREEN}BBR v3 编译安装完成${RESET}"
    read -p "是否现在重启系统？[y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        reboot
    fi
}

# 主菜单
main_menu() {
    while true; do
        echo -e "\n${CYAN}BBR 管理菜单${RESET}"
        echo -e "${YELLOW}1. 启用标准 BBR${RESET}"
        echo -e "${YELLOW}2. 安装 BBR v3 (XanMod版本)${RESET}"
        echo -e "${YELLOW}3. 安装 BBR v3 (手动编译)${RESET}"
        echo -e "${YELLOW}4. 返回上级菜单${RESET}"
        echo -e "${YELLOW}5. 退出脚本${RESET}"
        read -p "请选择操作 [1-5]: " choice

        case "$choice" in
            1)
                enable_bbr
                ;;
            2)
                install_xanmod_bbr
                ;;
            3)
                install_bbr3_manual
                ;;
            4)
                return 0
                ;;
            5)
                exit 0
                ;;
            *)
                echo -e "${RED}无效的选择${RESET}"
                ;;
        esac
    done
}

# 运行主菜单
main_menu
