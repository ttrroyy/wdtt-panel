#!/usr/bin/env bash
# WDTT Panel: select protocols; panel and subscriptions share one loopback-only port.
set -euo pipefail
umask 077
[[ $(id -u) == 0 ]] || { echo 'Запустите установщик от root.' >&2; exit 1; }
. /etc/os-release
case "$ID:$VERSION_ID" in debian:12|debian:13|ubuntu:22.04|ubuntu:24.04|ubuntu:26.04) ;; *) echo 'Поддерживаются Debian 12/13 и Ubuntu 22.04/24.04/26.04 LTS.' >&2; exit 1;; esac
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd)
if [[ "${1:-}" == uninstall && -f /usr/local/lib/wdtt/uninstall.py ]]; then
    exec python3 /usr/local/lib/wdtt/uninstall.py
fi
if [[ ! -f "$SOURCE_DIR/scripts/protocols.py" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq git ca-certificates
    SOURCE_DIR=$(mktemp -d /opt/wdtt-panel-install.XXXXXX)
    git clone --depth 1 https://github.com/ttrroyy/wdtt-panel.git "$SOURCE_DIR"
    exec bash "$SOURCE_DIR/install.sh" "$@"
fi

[[ "${1:-}" != install ]] || shift
if [[ "${1:-}" == uninstall ]]; then
    exec python3 "$SOURCE_DIR/scripts/uninstall.py"
fi
INSTALL_ROLE=${1:-combined}
case "$INSTALL_ROLE" in panel|node|combined) ;; *) echo 'Использование: install.sh [panel|node|combined|uninstall]' >&2; exit 1;; esac
[[ $# -le 1 ]] || exit 1
if [[ "$INSTALL_ROLE" == panel ]]; then export WDTT_PROTOCOLS=''; fi
if ! command -v python3 >/dev/null || ! command -v curl >/dev/null; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 curl ca-certificates
fi
python3 "$SOURCE_DIR/scripts/local-install.py" choose
python3 "$SOURCE_DIR/scripts/frontend.py" choose
python3 "$SOURCE_DIR/scripts/preflight.py" "$INSTALL_ROLE"
mapfile -t SELECTED < <(python3 -c 'import json; print("\n".join(json.load(open("/etc/wdtt/install-selection.json"))["protocols"]))')
export WDTT_PUBLIC_IP=${WDTT_PUBLIC_IP:-$(curl -4fsS --max-time 15 https://api.ipify.org)}
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl git python3 openssl openssh-client sshpass iproute2 iptables nftables wireguard-tools unzip build-essential cmake pkg-config libssl-dev
case $(uname -m) in x86_64) GO_ARCH=amd64; XRAY_ARCH=64;; aarch64) GO_ARCH=arm64; XRAY_ARCH=arm64-v8a;; *) echo 'Неподдерживаемая архитектура'; exit 1;; esac
WDTT_GO_DIR=/usr/local/go
if [[ ! -x "$WDTT_GO_DIR/bin/go" ]] || [[ $("$WDTT_GO_DIR/bin/go" version) != *go1.26.10* ]]; then
    WDTT_GO_DIR=/usr/local/lib/wdtt/toolchains/go
fi
if [[ ! -x "$WDTT_GO_DIR/bin/go" ]] || [[ $("$WDTT_GO_DIR/bin/go" version) != *go1.26.10* ]]; then
    GO_ARCHIVE=$(mktemp /tmp/wdtt-go.XXXXXX.tar.gz)
    curl -fsSL "https://go.dev/dl/go1.26.10.linux-${GO_ARCH}.tar.gz" -o "$GO_ARCHIVE"
    GO_CHECKSUM=$(curl -fsSL "https://go.dev/dl/go1.26.10.linux-${GO_ARCH}.tar.gz.sha256")
    printf '%s  %s\n' "$GO_CHECKSUM" "$GO_ARCHIVE" | sha256sum -c -
    install -d /usr/local/lib/wdtt/toolchains
    tar -xzf "$GO_ARCHIVE" -C /usr/local/lib/wdtt/toolchains
    rm -f -- "$GO_ARCHIVE"
fi
export PATH="$WDTT_GO_DIR/bin:/root/.cargo/bin:$PATH"
export GOPATH=${GOPATH:-/root/go} GOCACHE=${GOCACHE:-/root/.cache/go-build}
export CARGO_HOME=${CARGO_HOME:-/root/.cargo} RUSTUP_HOME=${RUSTUP_HOME:-/root/.rustup}
if [[ "$INSTALL_ROLE" != panel ]]; then
if [[ ! -x /root/.cargo/bin/rustup ]]; then
    curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.97.1
fi
/root/.cargo/bin/rustup toolchain install 1.97.1 --profile minimal
fi
install -d -m 700 /etc/wdtt /etc/wdtt/protocols
install -d /usr/local/lib/wdtt /usr/local/lib/wdtt/protocols
printf '%s\n' "$INSTALL_ROLE" >/etc/wdtt/role
if [[ "$INSTALL_ROLE" != panel ]]; then
for protocol in qwdtt wdtt-plus csqtt-2.1.9 csqtt-2.5.0 freeturn csqtt-2.5.3-community dnstt vaydns slipstream masterdns cottendns soar openflux; do
    case "$protocol" in
        wdtt) ;;
        qwdtt|wdtt-plus|csqtt-2.1.9|csqtt-2.5.0|csqtt-2.5.3-community|freeturn) python3 "$SOURCE_DIR/scripts/build-protocols.py" "$protocol";;
        *) python3 "$SOURCE_DIR/scripts/build-edges.py" "$protocol";;
    esac
done
fi
TEMP_BINARY=$(mktemp /tmp/wdtt-app.XXXXXX)
(cd "$SOURCE_DIR"; CGO_ENABLED=0 go build -trimpath -o "$TEMP_BINARY" ./cmd/wdtt)
install -m 755 "$TEMP_BINARY" /usr/local/bin/wdtt-app.new
mv /usr/local/bin/wdtt-app.new /usr/local/bin/wdtt-app
(cd "$SOURCE_DIR"; CGO_ENABLED=0 go build -trimpath -o "$TEMP_BINARY" ./cmd/wdtt-dns)
install -m 755 "$TEMP_BINARY" /usr/local/bin/wdtt-dns.new
mv /usr/local/bin/wdtt-dns.new /usr/local/bin/wdtt-dns
rm -f -- "$TEMP_BINARY"
install -m 755 "$SOURCE_DIR/scripts/protocols.py" "$SOURCE_DIR/scripts/edge_protocols.py" "$SOURCE_DIR/scripts/fleet.py" "$SOURCE_DIR/scripts/frontend.py" "$SOURCE_DIR/scripts/preflight.py" /usr/local/lib/wdtt/
tar --exclude=.git --exclude=.task --exclude=graphify-out --exclude=__pycache__ -czf /usr/local/lib/wdtt/node-source.tar.gz -C "$SOURCE_DIR" .
install -m 755 "$SOURCE_DIR/scripts/wdtt-mtu-rules.sh" /usr/local/bin/wdtt-mtu-rules.sh
if [[ ! -x /usr/local/wdtt-xray/bin/xray-linux-amd64 ]]; then
    XRAY_TEMP=$(mktemp -d /tmp/wdtt-xray.XXXXXX)
    curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/v26.6.1/Xray-linux-${XRAY_ARCH}.zip" -o "$XRAY_TEMP/xray.zip"
    unzip -q "$XRAY_TEMP/xray.zip" -d "$XRAY_TEMP/files"
    install -d /usr/local/wdtt-xray/bin
    install -m 755 "$XRAY_TEMP/files/xray" /usr/local/wdtt-xray/bin/xray-linux-amd64
    for file in geoip.dat geosite.dat; do [[ ! -f "$XRAY_TEMP/files/$file" ]] || install -m 644 "$XRAY_TEMP/files/$file" /usr/local/wdtt-xray/bin/; done
fi
python3 "$SOURCE_DIR/scripts/local-install.py" migrate
systemctl stop wdtt wdtt-protocol-watch wdtt-fleet 2>/dev/null || true
SAVED_PORT=$(python3 -c 'import sqlite3,pathlib; p=pathlib.Path("/etc/wdtt/panel.db"); print(sqlite3.connect(p).execute("SELECT port FROM panel_config WHERE id=1").fetchone()[0] if p.exists() else 2860)')
export WDTT_BACKEND_PORT=$(python3 "$SOURCE_DIR/scripts/local-install.py" port "$SAVED_PORT")
export WDTT_PUBLIC_URL="http://127.0.0.1:$WDTT_BACKEND_PORT"
export WDTT_INITIAL_INBOUNDS=$(printf '%s\n' "${SELECTED[@]}" | python3 -c 'import sys; names=[n.strip() for n in sys.stdin]; print(",".join(n for n in names if n in ["wdtt","qwdtt","wdtt-plus","csqtt-2.1.9","csqtt-2.5.0","freeturn","csqtt-2.5.3-community"]))')
export WDTT_INITIAL_PASSWORD=''
if [[ ! -f /etc/wdtt/panel.db ]]; then
    WDTT_INITIAL_PASSWORD=$(openssl rand -hex 16)
    printf 'admin\n%s\n' "$WDTT_INITIAL_PASSWORD" >/etc/wdtt/install-credentials
fi
/usr/local/bin/wdtt-app -init-panel
unset WDTT_INITIAL_PASSWORD
python3 - <<'PYCONFIG'
import json,os,sqlite3
from pathlib import Path
with sqlite3.connect('/etc/wdtt/panel.db') as db:
    db.execute("UPDATE wdtt_inbound SET server_host=CASE WHEN server_host='' THEN ? ELSE server_host END",(os.environ['WDTT_PUBLIC_IP'],))
p=Path('/etc/wdtt-xray/config.json');p.parent.mkdir(exist_ok=True)
if not p.exists():p.write_text(json.dumps({'log':{'loglevel':'warning'},'inbounds':[],'outbounds':[{'tag':'direct','protocol':'freedom','settings':{}},{'tag':'blocked','protocol':'blackhole','settings':{}}],'routing':{'rules':[]}}))
p=Path('/etc/wdtt/dns-router.json')
if not p.exists():p.write_text('{"zones":[],"routes":[]}')
PYCONFIG
cat >/etc/systemd/system/wdtt.service <<'UNIT'
[Unit]
Description=WDTT Panel and VPN
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/wdtt-app -config-dir /etc/wdtt
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
case "$INSTALL_ROLE" in
    panel) sed -i 's|wdtt-app -config-dir|wdtt-app -panel-only -config-dir|' /etc/systemd/system/wdtt.service;;
    node) sed -i 's|wdtt-app -config-dir|wdtt-app -node-only -config-dir|' /etc/systemd/system/wdtt.service;;
esac
cat >/etc/systemd/system/wdtt-protocol@.service <<'UNIT'
[Unit]
Description=WDTT Panel protocol %i
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/bin/python3 /usr/local/lib/wdtt/protocols.py run %i
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
KillMode=mixed
LimitNOFILE=1048576
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/systemd/system/wdtt-protocol-watch.service <<'UNIT'
[Unit]
Description=WDTT Panel protocol routing and limits
After=wdtt.service wdtt-xray.service
[Service]
ExecStart=/usr/bin/python3 /usr/local/lib/wdtt/protocols.py watch
Restart=on-failure
RestartSec=3
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/systemd/system/wdtt-xray.service <<'UNIT'
[Unit]
Description=WDTT Panel Xray routing
After=network-online.target
[Service]
ExecStart=/usr/local/wdtt-xray/bin/xray-linux-amd64 run -c /etc/wdtt-xray/config.json
Environment=XRAY_LOCATION_ASSET=/usr/local/wdtt-xray/bin
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/systemd/system/wdtt-edge@.service <<'UNIT'
[Unit]
Description=WDTT Panel original tunnel for %i
After=network-online.target wdtt-xray.service
Wants=network-online.target
[Service]
User=root
ExecStart=/usr/bin/python3 /usr/local/lib/wdtt/protocols.py edge-run %i
Restart=on-failure
RestartSec=3
TimeoutStopSec=10
KillMode=control-group
LimitNOFILE=65536
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/systemd/system/wdtt-dns.service <<'UNIT'
[Unit]
Description=WDTT authoritative DNS tunnel dispatcher
After=network-online.target
[Service]
ExecStart=/usr/local/bin/wdtt-dns -config /etc/wdtt/dns-router.json
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
[Install]
WantedBy=multi-user.target
UNIT
printf 'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.rp_filter=0\n' >/etc/sysctl.d/90-wdtt-panel.conf
sysctl -p /etc/sysctl.d/90-wdtt-panel.conf
systemctl daemon-reload
python3 "$SOURCE_DIR/scripts/local-install.py" configure
if [[ "$INSTALL_ROLE" == panel ]]; then
    systemctl disable --now wdtt-xray wdtt-protocol-watch wdtt-dns 2>/dev/null || true
    systemctl enable --now wdtt
    systemctl restart wdtt
else
    systemctl enable --now wdtt wdtt-xray wdtt-protocol-watch
    systemctl restart wdtt wdtt-xray wdtt-protocol-watch
fi
for protocol in "${SELECTED[@]}"; do
    case "$protocol" in wdtt|dnstt|vaydns|slipstream|masterdns|cottendns|soar|openflux) continue;; esac
    if systemctl is-enabled --quiet "wdtt-protocol@$protocol"; then systemctl restart "wdtt-protocol@$protocol"; fi
done
if python3 -c 'import json,sys; s=json.load(open("/etc/wdtt/install-selection.json")); sys.exit(not bool(s["dns_zone"]))'; then
    systemctl enable --now wdtt-dns
    systemctl restart wdtt-dns
fi
printf '{"op":"seed-default"}\n' | python3 /usr/local/lib/wdtt/protocols.py
install -m 755 "$SOURCE_DIR/scripts/uninstall.py" /usr/local/lib/wdtt/uninstall.py
printf '#!/bin/sh\nexec python3 /usr/local/lib/wdtt/uninstall.py "$@"\n' >/usr/local/bin/wdtt-panel-uninstall
chmod 755 /usr/local/bin/wdtt-panel-uninstall
printf '#!/bin/sh\nexec /usr/local/bin/wdtt-app -create-node-key "$@"\n' >/usr/local/bin/wdtt-node-key
chmod 755 /usr/local/bin/wdtt-node-key
install -m 755 "$SOURCE_DIR/scripts/panel-firewall.py" /usr/local/lib/wdtt/panel-firewall.py
cat >/etc/systemd/system/wdtt-panel-firewall.service <<'UNIT'
[Unit]
Description=WDTT Panel protocol firewall
After=network-online.target ufw.service nftables.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/lib/wdtt/panel-firewall.py
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now wdtt-panel-firewall
systemctl restart wdtt-panel-firewall
cat >/etc/systemd/system/wdtt-fleet.service <<'UNIT'
[Unit]
Description=WDTT managed nodes and users
After=wdtt.service network-online.target
[Service]
ExecStart=/usr/bin/python3 /usr/local/lib/wdtt/fleet.py watch
Restart=on-failure
RestartSec=3
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
if [[ "$INSTALL_ROLE" == node ]]; then
    systemctl disable --now wdtt-fleet 2>/dev/null || true
else
    systemctl enable --now wdtt-fleet
    systemctl restart wdtt-fleet
fi
python3 /usr/local/lib/wdtt/frontend.py configure
python3 /usr/local/lib/wdtt/frontend.py info
echo 'Полное удаление: wdtt-panel-uninstall'
