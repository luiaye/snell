#!/usr/bin/env bash
set -euo pipefail

# Snell 多用户完整管理脚本
# 功能：安装/更新 snell-server、主用户初始化、子用户多开、查看配置、删除用户、重启、卸载

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

INSTALL_DIR="/usr/local/bin"
SNELL_BIN="${INSTALL_DIR}/snell-server"
SNELL_DIR="/etc/snell"
USERS_DIR="${SNELL_DIR}/users"
MAIN_CONF="${USERS_DIR}/snell-main.conf"
MAIN_SERVICE="/etc/systemd/system/snell.service"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo -e "${RED}请用 root 运行：sudo bash $0${RESET}"
    exit 1
  fi
}

wait_apt_lock() {
  while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
    echo -e "${YELLOW}等待 apt 锁释放...${RESET}"
    sleep 1
  done
}

ensure_packages() {
  if command -v apt >/dev/null 2>&1; then
    wait_apt_lock
    apt update -y
    apt install -y curl wget unzip ca-certificates iproute2
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl wget unzip ca-certificates iproute
  else
    echo -e "${RED}不支持的包管理器，请手动安装 curl/wget/unzip${RESET}"
    exit 1
  fi
}

arch_tag() {
  case "$(uname -m)" in
    x86_64|amd64) echo "linux-amd64" ;;
    i386|i686) echo "linux-i386" ;;
    aarch64|arm64) echo "linux-aarch64" ;;
    armv7l|armv7) echo "linux-armv7l" ;;
    *) echo "" ;;
  esac
}

latest_version_v5() {
  local html="" v=""

  # 站点偶发 404，静默降级到备选来源，避免误报噪音
  html="$(curl -fsSL https://manual.nssurge.com/others/snell.html 2>/dev/null || true)"
  if [[ -z "$html" ]]; then
    html="$(curl -fsSL https://kb.nssurge.com/surge-knowledge-base/zh/release-notes/snell 2>/dev/null || true)"
  fi

  if [[ -n "$html" ]]; then
    # 优先 beta，再正式
    v="$(echo "$html" | grep -oP 'snell-server-v\K5\.[0-9]+\.[0-9]+b[0-9]+' | head -n1 || true)"
    [[ -z "$v" ]] && v="$(echo "$html" | grep -oP 'snell-server-v\K5\.[0-9]+\.[0-9]+' | head -n1 || true)"
  fi

  [[ -z "$v" ]] && v="5.0.0"
  echo "v${v}"
}

install_or_update_binary() {
  ensure_packages
  local ver arch url tmp
  ver="$(latest_version_v5)"
  arch="$(arch_tag)"
  if [[ -z "$arch" ]]; then
    echo -e "${RED}不支持当前架构：$(uname -m)${RESET}"
    return 1
  fi

  url="https://dl.nssurge.com/snell/snell-server-${ver}-${arch}.zip"
  tmp="/tmp/snell-server.zip"

  echo -e "${CYAN}下载：${url}${RESET}"
  if ! wget -qO "$tmp" "$url"; then
    echo -e "${RED}下载失败：${url}${RESET}"
    rm -f "$tmp"
    return 1
  fi

  if ! unzip -o "$tmp" -d "$INSTALL_DIR" >/dev/null; then
    echo -e "${RED}解压失败，下载包可能无效。${RESET}"
    rm -f "$tmp"
    return 1
  fi

  chmod +x "$SNELL_BIN"
  rm -f "$tmp"

  mkdir -p "$USERS_DIR"
  echo -e "${GREEN}snell-server 安装/更新完成：$($SNELL_BIN --v 2>/dev/null || echo unknown)${RESET}"
  return 0
}

install_and_init_main() {
  if ! install_or_update_binary; then
    return 1
  fi

  if [[ -f "$MAIN_CONF" ]]; then
    read -rp "检测到主用户已存在，是否重新初始化主用户？[y/N]: " yn
    if [[ "$yn" =~ ^[Yy]$ ]]; then
      init_main_user || true
    else
      echo -e "${YELLOW}保留现有主用户配置。${RESET}"
    fi
  else
    init_main_user || true
  fi

  return 0
}

get_system_dns() {
  local d
  d="$(grep -E '^nameserver' /etc/resolv.conf | awk '{print $2}' | paste -sd, -)"
  [[ -z "$d" ]] && d="1.1.1.1,8.8.8.8"
  echo "$d"
}

gen_psk() {
  local p=""

  if command -v openssl >/dev/null 2>&1; then
    p="$(openssl rand -base64 24 2>/dev/null | tr -dc 'A-Za-z0-9' | cut -c1-20 || true)"
  fi

  if [[ ${#p} -lt 20 ]]; then
    set +o pipefail
    p="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)"
    set -o pipefail
  fi

  echo "$p"
}

port_in_use() {
  local p="$1"
  ss -lnt | awk '{print $4}' | grep -qE "[:.]${p}$"
}

open_port() {
  local p="$1"
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "${p}/tcp" >/dev/null 2>&1 || true
  fi
  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p tcp --dport "$p" -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT -p tcp --dport "$p" -j ACCEPT
  fi
}

make_service() {
  local name="$1" conf="$2" svc="$3"
  cat > "$svc" <<EOF
[Unit]
Description=Snell Proxy Service (${name})
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
LimitNOFILE=32768
ExecStart=${SNELL_BIN} -c ${conf}
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
EOF
}

create_conf() {
  local conf="$1" port="$2" psk="$3" dns="$4"
  cat > "$conf" <<EOF
[snell-server]
listen = ::0:${port}
psk = ${psk}
ipv6 = true
dns = ${dns}
EOF
}

get_main_port() {
  [[ -f "$MAIN_CONF" ]] || return 0
  grep -E '^listen' "$MAIN_CONF" | sed -n 's/.*::0:\([0-9]*\)/\1/p'
}

init_main_user() {
  [[ -x "$SNELL_BIN" ]] || { echo -e "${RED}请先安装 snell-server（二进制）${RESET}"; return; }

  local port psk dns
  read -rp "主用户端口 (1-65535): " port
  if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
    echo -e "${RED}端口非法${RESET}"; return
  fi

  if port_in_use "$port"; then
    echo -e "${RED}端口已被占用${RESET}"; return
  fi

  read -rp "主用户 PSK（留空自动生成）: " psk
  [[ -z "$psk" ]] && psk="$(gen_psk)"
  read -rp "DNS（留空用系统DNS）: " dns
  [[ -z "$dns" ]] && dns="$(get_system_dns)"

  mkdir -p "$USERS_DIR"
  create_conf "$MAIN_CONF" "$port" "$psk" "$dns"
  make_service "main" "$MAIN_CONF" "$MAIN_SERVICE"

  systemctl daemon-reload
  systemctl enable --now snell
  open_port "$port"

  echo -e "${GREEN}主用户创建成功${RESET}"
  echo -e "端口: ${YELLOW}${port}${RESET}"
  echo -e "PSK : ${YELLOW}${psk}${RESET}"
}

add_user() {
  [[ -f "$MAIN_CONF" ]] || { echo -e "${RED}请先初始化主用户${RESET}"; return; }

  local port psk dns conf svc main_port
  main_port="$(get_main_port || true)"

  read -rp "新增用户端口: " port
  if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
    echo -e "${RED}端口非法${RESET}"; return
  fi
  if [[ "$port" == "$main_port" ]]; then
    echo -e "${RED}不能和主端口重复${RESET}"; return
  fi
  if port_in_use "$port"; then
    echo -e "${RED}端口已占用${RESET}"; return
  fi

  conf="${USERS_DIR}/snell-${port}.conf"
  svc="/etc/systemd/system/snell-${port}.service"
  if [[ -f "$conf" ]]; then
    echo -e "${RED}该用户已存在${RESET}"; return
  fi

  read -rp "PSK（留空自动生成）: " psk
  [[ -z "$psk" ]] && psk="$(gen_psk)"

  dns="$(grep -E '^dns' "$MAIN_CONF" | awk -F'=' '{print $2}' | tr -d ' ' || true)"
  [[ -z "$dns" ]] && dns="$(get_system_dns)"

  create_conf "$conf" "$port" "$psk" "$dns"
  make_service "user-${port}" "$conf" "$svc"

  systemctl daemon-reload
  systemctl enable --now "snell-${port}"
  open_port "$port"

  echo -e "${GREEN}用户创建成功${RESET}"
  echo -e "端口: ${YELLOW}${port}${RESET}"
  echo -e "PSK : ${YELLOW}${psk}${RESET}"
}

del_user() {
  local port conf svc

  echo -e "${CYAN}=== 可删除的 Snell 子用户列表（Surge 格式）===${RESET}"
  local found=0 ip
  ip="$(public_ip)"
  [[ -z "$ip" ]] && echo -e "${YELLOW}无法获取公网 IP，将仅显示端口/PSK。${RESET}"

  for c in "${USERS_DIR}"/snell-*.conf; do
    [[ -f "$c" ]] || continue
    [[ "$c" == *"snell-main.conf" ]] && continue
    found=1
    local p psk st
    p="$(grep -E '^listen' "$c" | sed -n 's/.*::0:\([0-9]*\)/\1/p')"
    psk="$(grep -E '^psk' "$c" | awk -F'=' '{print $2}' | tr -d ' ')"
    st="$(systemctl is-active "snell-${p}" 2>/dev/null || true)"

    if [[ -n "$ip" ]]; then
      echo "U${p} = snell, $(surge_host "$ip"), ${p}, psk = ${psk}, version = 5, reuse = true, tfo = true    # 状态:${st}"
    else
      echo "U${p} -> 端口:${p}, psk:${psk}, 状态:${st}"
    fi
  done

  if [[ $found -eq 0 ]]; then
    echo -e "${YELLOW}当前没有可删除的子用户。${RESET}"
    return 0
  fi

  read -rp "要删除的用户端口: " port
  conf="${USERS_DIR}/snell-${port}.conf"
  svc="/etc/systemd/system/snell-${port}.service"

  if [[ ! -f "$conf" && ! -f "$svc" ]]; then
    echo -e "${RED}用户不存在${RESET}"
    return 1
  fi

  systemctl disable --now "snell-${port}" >/dev/null 2>&1 || true
  rm -f "$conf" "$svc"
  systemctl daemon-reload
  echo -e "${GREEN}已删除端口 ${port}${RESET}"
}

detect_snell_major() {
  if [[ ! -x "$SNELL_BIN" ]]; then echo "4"; return; fi
  local v
  v="$($SNELL_BIN --v 2>/dev/null || true)"
  echo "$v" | grep -q 'v5' && echo "5" || echo "4"
}

public_ip4() {
  curl -fsS4 https://api.ipify.org 2>/dev/null || true
}

public_ip6() {
  local ip6=""
  if ip -6 addr show scope global 2>/dev/null | grep -q 'inet6'; then
    ip6="$(curl -fsS6 https://api64.ipify.org 2>/dev/null || true)"
  fi
  echo "$ip6"
}

public_ip() {
  local ip6 ip4
  ip6="$(public_ip6)"
  [[ -n "$ip6" ]] && { echo "$ip6"; return 0; }
  ip4="$(public_ip4)"
  echo "$ip4"
}

surge_host() {
  local ip="$1"
  if [[ "$ip" == *:* ]]; then
    echo "[$ip]"
  else
    echo "$ip"
  fi
}

list_users() {
  echo -e "${CYAN}=== 用户列表 ===${RESET}"
  if [[ -f "$MAIN_CONF" ]]; then
    local p psk st
    p="$(grep -E '^listen' "$MAIN_CONF" | sed -n 's/.*::0:\([0-9]*\)/\1/p')"
    psk="$(grep -E '^psk' "$MAIN_CONF" | awk -F'=' '{print $2}' | tr -d ' ')"
    st="$(systemctl is-active snell 2>/dev/null || true)"
    echo -e "[MAIN] 端口:${p} PSK:${psk} 状态:${st}"
  else
    echo "主用户：未初始化"
  fi

  local found=0
  for conf in "${USERS_DIR}"/snell-*.conf; do
    [[ -f "$conf" ]] || continue
    [[ "$conf" == *"snell-main.conf" ]] && continue
    found=1
    local p psk st
    p="$(grep -E '^listen' "$conf" | sed -n 's/.*::0:\([0-9]*\)/\1/p')"
    psk="$(grep -E '^psk' "$conf" | awk -F'=' '{print $2}' | tr -d ' ')"
    st="$(systemctl is-active "snell-${p}" 2>/dev/null || true)"
    echo "[USER] 端口:${p} PSK:${psk} 状态:${st}"
  done

  if [[ $found -eq 0 ]]; then
    echo "无子用户"
  fi

  return 0
}

show_surge_lines() {
  local ip4 ip6 host4 host6
  ip4="$(public_ip4)"
  ip6="$(public_ip6)"
  host4="$(surge_host "$ip4")"
  host6="$(surge_host "$ip6")"

  if [[ -z "$ip4" && -z "$ip6" ]]; then
    echo -e "${YELLOW}无法获取公网 IP，先显示端口/PSK：${RESET}"
  fi

  list_users
  echo
  echo -e "${CYAN}=== Surge 示例行（Snell v5）===${RESET}"

  if [[ -f "$MAIN_CONF" ]]; then
    local p psk
    p="$(grep -E '^listen' "$MAIN_CONF" | sed -n 's/.*::0:\([0-9]*\)/\1/p')"
    psk="$(grep -E '^psk' "$MAIN_CONF" | awk -F'=' '{print $2}' | tr -d ' ')"
    [[ -n "$ip4" ]] && echo "MAIN4 = snell, ${host4}, ${p}, psk = ${psk}, version = 5, reuse = true, tfo = true"
    [[ -n "$ip6" ]] && echo "MAIN6 = snell, ${host6}, ${p}, psk = ${psk}, version = 5, reuse = true, tfo = true"
  fi

  for conf in "${USERS_DIR}"/snell-*.conf; do
    [[ -f "$conf" ]] || continue
    [[ "$conf" == *"snell-main.conf" ]] && continue
    local p psk
    p="$(grep -E '^listen' "$conf" | sed -n 's/.*::0:\([0-9]*\)/\1/p')"
    psk="$(grep -E '^psk' "$conf" | awk -F'=' '{print $2}' | tr -d ' ')"
    [[ -n "$ip4" ]] && echo "U${p}4 = snell, ${host4}, ${p}, psk = ${psk}, version = 5, reuse = true, tfo = true"
    [[ -n "$ip6" ]] && echo "U${p}6 = snell, ${host6}, ${p}, psk = ${psk}, version = 5, reuse = true, tfo = true"
  done

  echo
  echo -e "${CYAN}=== ShadowTLS 组合（若已配置）===${RESET}"
  show_shadowtls_lines
}

show_shadowtls_lines() {
  local ip4 ip6 host4 host6
  ip4="$(public_ip4)"
  ip6="$(public_ip6)"
  host4="$(surge_host "$ip4")"
  host6="$(surge_host "$ip6")"

  local found=0
  for svc in /etc/systemd/system/shadowtls-snell-*.service; do
    [[ -f "$svc" ]] || continue
    found=1

    local exec_line stls_port stls_pwd stls_sni snell_port psk
    exec_line="$(grep '^ExecStart=' "$svc" || true)"
    stls_port="$(echo "$exec_line" | grep -oP '(?<=--listen ::0:)\d+' || true)"
    stls_pwd="$(echo "$exec_line" | grep -oP '(?<=--password )[^ ]+' || true)"
    stls_sni="$(echo "$exec_line" | grep -oP '(?<=--tls )[^ ]+' || true)"
    snell_port="$(echo "$exec_line" | grep -oP '(?<=--server 127.0.0.1:)\d+' || true)"

    if [[ -z "$snell_port" ]]; then
      continue
    fi

    if [[ "$snell_port" == "$(get_main_port || true)" ]]; then
      psk="$(grep -E '^psk' "$MAIN_CONF" | awk -F'=' '{print $2}' | tr -d ' ' || true)"
    else
      psk="$(grep -E '^psk' "${USERS_DIR}/snell-${snell_port}.conf" 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' || true)"
    fi

    echo "ShadowTLS 端口:${stls_port} -> Snell端口:${snell_port} | SNI:${stls_sni}"
    [[ -n "$ip4" && -n "$psk" ]] && echo "S${snell_port}4 = snell, ${host4}, ${stls_port}, psk = ${psk}, version = 5, reuse = true, tfo = true, shadow-tls-password = ${stls_pwd}, shadow-tls-sni = ${stls_sni}, shadow-tls-version = 3"
    [[ -n "$ip6" && -n "$psk" ]] && echo "S${snell_port}6 = snell, ${host6}, ${stls_port}, psk = ${psk}, version = 5, reuse = true, tfo = true, shadow-tls-password = ${stls_pwd}, shadow-tls-sni = ${stls_sni}, shadow-tls-version = 3"
  done

  if [[ $found -eq 0 ]]; then
    echo "未检测到 ShadowTLS 服务（shadowtls-snell-*.service）"
  fi

  return 0
}

SHADOWTLS_BIN="/usr/local/bin/shadow-tls"

install_shadowtls_binary() {
  local arch pattern api url
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) pattern='x86_64-unknown-linux-musl$' ;;
    aarch64|arm64) pattern='aarch64-unknown-linux-musl$' ;;
    armv7l|armv7) pattern='armv7-unknown-linux-musleabihf$' ;;
    i386|i686) pattern='i686-unknown-linux-musl$' ;;
    *)
      echo -e "${RED}不支持的架构: ${arch}${RESET}"
      return 1
      ;;
  esac

  api="https://api.github.com/repos/ihciah/shadow-tls/releases/latest"
  url="$(curl -fsSL "$api" | grep 'browser_download_url' | cut -d '"' -f 4 | grep -E "$pattern" | head -n1 || true)"

  if [[ -z "$url" ]]; then
    echo -e "${RED}未找到匹配架构的 ShadowTLS 下载链接${RESET}"
    return 1
  fi

  echo -e "${CYAN}下载 ShadowTLS: ${url}${RESET}"
  curl -fL "$url" -o "$SHADOWTLS_BIN"
  chmod +x "$SHADOWTLS_BIN"

  if "$SHADOWTLS_BIN" --help >/dev/null 2>&1; then
    echo -e "${GREEN}ShadowTLS 安装/更新完成: ${SHADOWTLS_BIN}${RESET}"
  else
    echo -e "${YELLOW}ShadowTLS 已下载，但 --help 返回异常，请手动检查${RESET}"
  fi
}

gen_shadowtls_password() {
  local p=""

  if command -v openssl >/dev/null 2>&1; then
    p="$(openssl rand -base64 24 2>/dev/null | tr -dc 'A-Za-z0-9' | cut -c1-20 || true)"
  fi

  if [[ ${#p} -lt 20 ]]; then
    set +o pipefail
    p="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)"
    set -o pipefail
  fi

  echo "$p"
}

list_shadowtls() {
  local found=0 ip4 ip6 host4 host6
  ip4="$(public_ip4)"
  ip6="$(public_ip6)"
  host4="$(surge_host "$ip4")"
  host6="$(surge_host "$ip6")"

  echo -e "${CYAN}=== ShadowTLS 列表（Surge 格式）===${RESET}"
  [[ -z "$ip4" && -z "$ip6" ]] && echo -e "${YELLOW}无法获取公网 IP，将仅显示本地参数。${RESET}"

  for svc in /etc/systemd/system/shadowtls-snell-*.service; do
    [[ -f "$svc" ]] || continue
    found=1

    local exec_line stls_port stls_pwd stls_sni snell_port state psk tag
    exec_line="$(grep '^ExecStart=' "$svc" || true)"
    stls_port="$(echo "$exec_line" | grep -oP '(?<=--listen ::0:)\d+' || true)"
    stls_pwd="$(echo "$exec_line" | grep -oP '(?<=--password )[^ ]+' || true)"
    stls_sni="$(echo "$exec_line" | grep -oP '(?<=--tls )[^ ]+' || true)"
    snell_port="$(echo "$exec_line" | grep -oP '(?<=--server 127.0.0.1:)\d+' || true)"
    state="$(systemctl is-active "$(basename "$svc" .service)" 2>/dev/null || true)"

    if [[ -z "$snell_port" || -z "$stls_port" ]]; then
      continue
    fi

    if [[ "$snell_port" == "$(get_main_port || true)" ]]; then
      psk="$(grep -E '^psk' "$MAIN_CONF" 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' || true)"
      tag="MAIN-STLS"
    else
      psk="$(grep -E '^psk' "${USERS_DIR}/snell-${snell_port}.conf" 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' || true)"
      tag="U${snell_port}-STLS"
    fi

    if [[ -n "$psk" && ( -n "$ip4" || -n "$ip6" ) ]]; then
      [[ -n "$ip4" ]] && echo "${tag}4 = snell, ${host4}, ${stls_port}, psk = ${psk}, version = 5, reuse = true, tfo = true, shadow-tls-password = ${stls_pwd}, shadow-tls-sni = ${stls_sni}, shadow-tls-version = 3"
      [[ -n "$ip6" ]] && echo "${tag}6 = snell, ${host6}, ${stls_port}, psk = ${psk}, version = 5, reuse = true, tfo = true, shadow-tls-password = ${stls_pwd}, shadow-tls-sni = ${stls_sni}, shadow-tls-version = 3"
    else
      echo "${tag} (state=${state}) -> snell_port=${snell_port}, stls_port=${stls_port}, psk=${psk}, stls_password=${stls_pwd}, stls_sni=${stls_sni}"
    fi
  done

  if [[ $found -eq 0 ]]; then
    echo "未检测到 ShadowTLS 服务"
  fi

  return 0
}

add_shadowtls_binding() {
  if [[ ! -x "$SHADOWTLS_BIN" ]]; then
    echo -e "${YELLOW}未检测到 ShadowTLS 二进制，先自动安装/更新...${RESET}"
    install_shadowtls_binary || return 1
  fi

  echo -e "${CYAN}=== 可绑定的 Snell 列表（已绑定的不显示）===${RESET}"
  local mport mstate found
  found=0

  # 收集已绑定 ShadowTLS 的 snell 端口
  local bound_ports=" "
  for s in /etc/systemd/system/shadowtls-snell-*.service; do
    [[ -f "$s" ]] || continue
    local bp
    bp="$(basename "$s" .service | sed -n 's/^shadowtls-snell-\([0-9]\+\)$/\1/p')"
    [[ -n "$bp" ]] && bound_ports+="${bp} "
  done

  mport="$(get_main_port || true)"
  if [[ -n "$mport" && -f "$MAIN_CONF" ]]; then
    if [[ "$bound_ports" != *" ${mport} "* ]]; then
      mstate="$(systemctl is-active snell 2>/dev/null || true)"
      echo "[MAIN] 端口:${mport} | 状态:${mstate}"
      found=1
    fi
  fi

  for c in "${USERS_DIR}"/snell-*.conf; do
    [[ -f "$c" ]] || continue
    [[ "$c" == *"snell-main.conf" ]] && continue
    local p st
    p="$(grep -E '^listen' "$c" | sed -n 's/.*::0:\([0-9]*\)/\1/p')"
    [[ "$bound_ports" == *" ${p} "* ]] && continue
    st="$(systemctl is-active "snell-${p}" 2>/dev/null || true)"
    echo "[USER] 端口:${p} | 状态:${st}"
    found=1
  done

  if [[ $found -eq 0 ]]; then
    echo -e "${YELLOW}没有可绑定的 Snell（可能都已绑定 ShadowTLS）。${RESET}"
    return 1
  fi

  local snell_port stls_port stls_pwd stls_sni svc
  read -rp "绑定哪个 Snell 端口: " snell_port

  if [[ ! -f "${USERS_DIR}/snell-${snell_port}.conf" && "$snell_port" != "$(get_main_port || true)" ]]; then
    echo -e "${RED}未找到对应 Snell 端口配置${RESET}"
    return 1
  fi

  if [[ "$bound_ports" == *" ${snell_port} "* ]]; then
    echo -e "${RED}该 Snell 端口已绑定 ShadowTLS，请先删除旧绑定再创建。${RESET}"
    return 1
  fi

  read -rp "ShadowTLS 监听端口: " stls_port
  if ! [[ "$stls_port" =~ ^[0-9]+$ ]] || (( stls_port < 1 || stls_port > 65535 )); then
    echo -e "${RED}端口非法${RESET}"
    return 1
  fi
  if port_in_use "$stls_port"; then
    echo -e "${RED}端口已占用${RESET}"
    return 1
  fi

  read -rp "ShadowTLS 密码（留空自动生成）: " stls_pwd
  [[ -z "$stls_pwd" ]] && stls_pwd="$(gen_shadowtls_password)"
  read -rp "ShadowTLS SNI（默认 www.apple.com）: " stls_sni
  [[ -z "$stls_sni" ]] && stls_sni="www.apple.com"

  svc="/etc/systemd/system/shadowtls-snell-${snell_port}.service"
  cat > "$svc" <<EOF
[Unit]
Description=ShadowTLS for Snell ${snell_port}
After=network.target

[Service]
Type=simple
ExecStart=${SHADOWTLS_BIN} --v3 server --listen ::0:${stls_port} --server 127.0.0.1:${snell_port} --tls ${stls_sni} --password ${stls_pwd}
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "shadowtls-snell-${snell_port}"
  open_port "$stls_port"

  echo -e "${GREEN}ShadowTLS 创建成功${RESET}"
  echo "Snell端口: ${snell_port}"
  echo "ShadowTLS端口: ${stls_port}"
  echo "密码: ${stls_pwd}"
  echo "SNI: ${stls_sni}"
}

install_or_update_shadowtls() {
  local has_bind=0 choice
  for s in /etc/systemd/system/shadowtls-snell-*.service; do
    [[ -f "$s" ]] || continue
    has_bind=1
    break
  done

  if [[ $has_bind -eq 0 ]]; then
    echo -e "${CYAN}首次使用：先安装/更新 ShadowTLS，再添加绑定。${RESET}"
    install_shadowtls_binary || return 1
    add_shadowtls_binding || return 1
    return 0
  fi

  echo -e "${YELLOW}检测到已有 ShadowTLS 绑定。${RESET}"
  echo "1) 仅更新 ShadowTLS 二进制"
  echo "0) 返回菜单"
  read -rp "请选择 [0-1]: " choice
  case "$choice" in
    1) install_shadowtls_binary || return 1 ;;
    0) return 0 ;;
    *) echo -e "${RED}无效选项${RESET}"; return 1 ;;
  esac

  return 0
}

del_shadowtls() {
  local snell_port svc

  echo -e "${CYAN}=== 可删除的 ShadowTLS 列表 ===${RESET}"
  local found=0
  for s in /etc/systemd/system/shadowtls-snell-*.service; do
    [[ -f "$s" ]] || continue
    found=1
    local exec_line stls_port stls_sni p st
    p="$(basename "$s" .service | sed -n 's/^shadowtls-snell-\([0-9]\+\)$/\1/p')"
    exec_line="$(grep '^ExecStart=' "$s" || true)"
    stls_port="$(echo "$exec_line" | grep -oP '(?<=--listen ::0:)\d+' || true)"
    stls_sni="$(echo "$exec_line" | grep -oP '(?<=--tls )[^ ]+' || true)"
    st="$(systemctl is-active "shadowtls-snell-${p}" 2>/dev/null || true)"
    echo "- Snell端口: ${p} | ShadowTLS端口: ${stls_port} | SNI: ${stls_sni} | 状态: ${st}"
  done

  if [[ $found -eq 0 ]]; then
    echo -e "${YELLOW}当前没有可删除的 ShadowTLS。${RESET}"
    return 0
  fi

  read -rp "删除哪个 Snell 端口对应的 ShadowTLS: " snell_port
  svc="/etc/systemd/system/shadowtls-snell-${snell_port}.service"
  if [[ ! -f "$svc" ]]; then
    echo -e "${RED}服务不存在${RESET}"
    return 1
  fi
  systemctl disable --now "shadowtls-snell-${snell_port}" >/dev/null 2>&1 || true
  rm -f "$svc"
  systemctl daemon-reload
  echo -e "${GREEN}已删除 ShadowTLS: snell-${snell_port}${RESET}"
}

shadowtls_menu() {
  while true; do
    clear
    echo -e "${CYAN}========== ShadowTLS 管理 ==========${RESET}"
    echo "1) 安装/更新 ShadowTLS"
    echo "2) 添加 ShadowTLS"
    echo "3) 删除 ShadowTLS"
    echo "4) 查看 ShadowTLS"
    echo "0) 返回"
    read -rp "请选择 [0-4]: " sopt
    case "$sopt" in
      1) install_or_update_shadowtls || true ;;
      2) add_shadowtls_binding || true ;;
      3) del_shadowtls || true ;;
      4) list_shadowtls || true ;;
      0) break ;;
      *) echo -e "${RED}无效选项${RESET}" ;;
    esac
    echo
    read -rp "按回车继续..." _
  done
}

restart_all() {
  systemctl restart snell >/dev/null 2>&1 || true
  for conf in "${USERS_DIR}"/snell-*.conf; do
    [[ -f "$conf" ]] || continue
    [[ "$conf" == *"snell-main.conf" ]] && continue
    local p
    p="$(grep -E '^listen' "$conf" | sed -n 's/.*::0:\([0-9]*\)/\1/p')"
    systemctl restart "snell-${p}" >/dev/null 2>&1 || true
  done
  echo -e "${GREEN}全部 Snell 服务已重启${RESET}"
}

uninstall_all() {
  read -rp "确认卸载 Snell + ShadowTLS 全部组件？[y/N]: " yn
  [[ "$yn" =~ ^[Yy]$ ]] || { echo "已取消"; return; }

  # 停止并清理 Snell
  systemctl disable --now snell >/dev/null 2>&1 || true
  rm -f "$MAIN_SERVICE"

  for svc in /etc/systemd/system/snell-*.service; do
    [[ -f "$svc" ]] || continue
    local name
    name="$(basename "$svc" .service)"
    systemctl disable --now "$name" >/dev/null 2>&1 || true
    rm -f "$svc"
  done

  # 停止并清理 ShadowTLS
  for svc in /etc/systemd/system/shadowtls-snell-*.service; do
    [[ -f "$svc" ]] || continue
    local name
    name="$(basename "$svc" .service)"
    systemctl disable --now "$name" >/dev/null 2>&1 || true
    rm -f "$svc"
  done

  rm -rf "$SNELL_DIR"
  rm -f "$SNELL_BIN" "$SHADOWTLS_BIN"
  systemctl daemon-reload
  echo -e "${GREEN}卸载完成（Snell + ShadowTLS）${RESET}"
}

menu() {
  clear
  echo -e "${CYAN}========================================${RESET}"
  echo -e "${CYAN}   Snell v5 + ShadowTLS 综合管理脚本${RESET}"
  echo -e "${CYAN}========================================${RESET}"
  echo "1) 安装/更新"
  echo "2) 新增子用户"
  echo "3) 删除子用户"
  echo "4) 输出 Surge 配置"
  echo "5) 重启全部 Snell 服务"
  echo "6) ShadowTLS 管理"
  echo -e "${RED}7) 卸载全部（Snell + ShadowTLS）${RESET}"
  echo "0) 退出"
}

main() {
  require_root
  mkdir -p "$USERS_DIR"

  while true; do
    menu
    read -rp "请选择 [0-7]: " opt
    case "${opt}" in
      1) install_and_init_main || true ;;
      2) add_user || true ;;
      3) del_user || true ;;
      4) show_surge_lines || true ;;
      5) restart_all || true ;;
      6) shadowtls_menu || true ;;
      7) uninstall_all || true ;;
      0) exit 0 ;;
      *) echo -e "${RED}无效选项${RESET}" ;;
    esac
    echo
    read -rp "按回车继续..." _
  done
}

main "$@"
