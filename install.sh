#!/usr/bin/env bash
# WDTT Panel: all six VPN servers, with only TLS and external-port choices.
set -euo pipefail
umask 077
[[ $(id -u) == 0 ]] || { echo 'Запустите установщик от root.' >&2; exit 1; }
. /etc/os-release
case "$ID" in debian|ubuntu) ;; *) echo 'Поддерживаются Debian и Ubuntu.' >&2; exit 1;; esac
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ ! -f "$SOURCE_DIR/scripts/protocols.py" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq git ca-certificates
    SOURCE_DIR=$(mktemp -d /opt/wdtt-panel-install.XXXXXX)
    git clone --depth 1 https://github.com/ttrroyy/wdtt-panel.git "$SOURCE_DIR"
    exec bash "$SOURCE_DIR/install.sh"
fi

prompt() { read -r -p "$1" "$2" </dev/tty; }
MODE=${WDTT_TLS_MODE:-}
if [[ -z "$MODE" ]]; then
    printf '\nДоступ к панели:\n1) HTTP\n2) HTTPS с самоподписанным сертификатом на IP\n3) Домен с существующим сертификатом\n4) Домен с выпуском сертификата Certbot\n'
    prompt 'Вариант [2]: ' choice
    case "${choice:-2}" in 1) MODE=http;; 2) MODE=selfsigned;; 3) MODE=existing;; 4) MODE=certbot;; *) echo 'Неизвестный вариант'; exit 1;; esac
fi
case "$MODE" in http|selfsigned|existing|certbot) ;; *) echo 'Неверный режим TLS'; exit 1;; esac
PUBLIC_IP=${WDTT_PUBLIC_IP:-$(curl -4fsS --max-time 15 https://api.ipify.org)}
PANEL_HOST=${WDTT_PANEL_HOST:-$PUBLIC_IP}
CERT=${WDTT_CERT_FILE:-}; KEY=${WDTT_KEY_FILE:-}
if [[ "$MODE" == existing || "$MODE" == certbot ]]; then
    [[ -n "${WDTT_PANEL_HOST:-}" ]] || prompt 'Домен панели: ' PANEL_HOST
    if [[ "$MODE" == existing ]]; then
        CERT=${CERT:-/etc/letsencrypt/live/$PANEL_HOST/fullchain.pem}
        KEY=${KEY:-/etc/letsencrypt/live/$PANEL_HOST/privkey.pem}
        [[ -f "$CERT" ]] || prompt 'Путь к сертификату: ' CERT
        [[ -f "$KEY" ]] || prompt 'Путь к закрытому ключу: ' KEY
    fi
fi
EXTERNAL_PORT=${WDTT_EXTERNAL_PORT:-}
if [[ -z "$EXTERNAL_PORT" ]]; then
    printf '\nВнешний порт:\n1) Оставить 443 (по умолчанию)\n2) Выбрать свой\n'
    prompt 'Вариант [1]: ' choice
    case "${choice:-1}" in 1) EXTERNAL_PORT=443;; 2) prompt 'Внешний порт: ' EXTERNAL_PORT;; *) echo 'Неизвестный вариант'; exit 1;; esac
fi
[[ "$EXTERNAL_PORT" =~ ^[0-9]+$ && "$EXTERNAL_PORT" -ge 1 && "$EXTERNAL_PORT" -le 65535 ]] || { echo 'Некорректный порт'; exit 1; }
while ! python3 "$SOURCE_DIR/scripts/configure-nginx.py" --check --host "$PANEL_HOST" --mode "$MODE" --port "$EXTERNAL_PORT"; do
    [[ -z "${WDTT_EXTERNAL_PORT:-}" ]] || exit 1
    prompt 'Выберите другой внешний порт: ' EXTERNAL_PORT
done

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl git python3 openssl iproute2 iptables nftables wireguard-tools nginx certbot unzip build-essential pkg-config libssl-dev
case $(uname -m) in x86_64) GO_ARCH=amd64; XRAY_ARCH=64;; aarch64) GO_ARCH=arm64; XRAY_ARCH=arm64-v8a;; *) echo 'Неподдерживаемая архитектура'; exit 1;; esac
if [[ ! -x /usr/local/go/bin/go ]] || [[ $(/usr/local/go/bin/go version) != *go1.26.10* ]]; then
    GO_ARCHIVE=$(mktemp /tmp/wdtt-go.XXXXXX.tar.gz)
    curl -fsSL "https://go.dev/dl/go1.26.10.linux-${GO_ARCH}.tar.gz" -o "$GO_ARCHIVE"
    GO_CHECKSUM=$(curl -fsSL "https://go.dev/dl/go1.26.10.linux-${GO_ARCH}.tar.gz.sha256")
    printf '%s  %s\n' "$GO_CHECKSUM" "$GO_ARCHIVE" | sha256sum -c -
    tar -xzf "$GO_ARCHIVE" -C /usr/local
    rm -f -- "$GO_ARCHIVE"
fi
export PATH="/usr/local/go/bin:/root/.cargo/bin:$PATH"
if ! command -v cargo >/dev/null; then
    curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.97.1
fi
install -d -m 700 /etc/wdtt /etc/wdtt/protocols
install -d /usr/local/lib/wdtt /usr/local/lib/wdtt/protocols
install -m 755 "$SOURCE_DIR/scripts/protocols.py" /usr/local/lib/wdtt/protocols.py
install -m 755 "$SOURCE_DIR/scripts/wdtt-mtu-rules.sh" /usr/local/bin/wdtt-mtu-rules.sh
python3 "$SOURCE_DIR/scripts/build-protocols.py"
TEMP_BINARY=$(mktemp /tmp/wdtt-app.XXXXXX)
(cd "$SOURCE_DIR"; CGO_ENABLED=0 go build -trimpath -o "$TEMP_BINARY" ./cmd/wdtt)
install -m 755 "$TEMP_BINARY" /usr/local/bin/wdtt-app.new
mv /usr/local/bin/wdtt-app.new /usr/local/bin/wdtt-app
rm -f -- "$TEMP_BINARY"

if [[ ! -x /usr/local/wdtt-xray/bin/xray-linux-amd64 ]]; then
    XRAY_TEMP=$(mktemp -d /tmp/wdtt-xray.XXXXXX)
    curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/v26.6.1/Xray-linux-${XRAY_ARCH}.zip" -o "$XRAY_TEMP/xray.zip"
    unzip -q "$XRAY_TEMP/xray.zip" -d "$XRAY_TEMP/files"
    install -d /usr/local/wdtt-xray/bin
    install -m 755 "$XRAY_TEMP/files/xray" /usr/local/wdtt-xray/bin/xray-linux-amd64
    for file in geoip.dat geosite.dat; do [[ ! -f "$XRAY_TEMP/files/$file" ]] || install -m 644 "$XRAY_TEMP/files/$file" /usr/local/wdtt-xray/bin/; done
fi
export WDTT_BACKEND_PORT=${WDTT_BACKEND_PORT:-$(python3 -c 'import runpy,sys; m=runpy.run_path(sys.argv[1]); print(m["free_port"](2860))' "$SOURCE_DIR/scripts/configure-nginx.py")}
export WDTT_SUB_PORT=${WDTT_SUB_PORT:-$(python3 -c 'import runpy,sys; m=runpy.run_path(sys.argv[1]); print(m["free_port"](2096))' "$SOURCE_DIR/scripts/configure-nginx.py")}
SCHEME=https; [[ "$MODE" != http ]] || SCHEME=http
export WDTT_PUBLIC_URL="$SCHEME://$PANEL_HOST:$EXTERNAL_PORT"
export WDTT_INITIAL_PASSWORD=''
if [[ ! -f /etc/wdtt/panel.db ]]; then
    WDTT_INITIAL_PASSWORD=$(openssl rand -hex 16)
    printf 'admin\n%s\n' "$WDTT_INITIAL_PASSWORD" > /etc/wdtt/install-credentials
fi
touch /etc/wdtt/nginx-managed
printf '%s\n' "$SCHEME" > /etc/wdtt/public-scheme
systemctl stop wdtt 2>/dev/null || true
/usr/local/bin/wdtt-app -init-panel
unset WDTT_INITIAL_PASSWORD
export PANEL_HOST PUBLIC_IP WDTT_SUB_PORT WDTT_BACKEND_PORT
python3 - "$SOURCE_DIR" <<'PY'
import os,runpy,sqlite3,json,sys
from pathlib import Path
with sqlite3.connect('/etc/wdtt/panel.db') as db:
    db.execute('UPDATE panel_config SET web_listen=?,sub_listen=?',('127.0.0.1','127.0.0.1'))
    db.execute('UPDATE wdtt_inbound SET server_host=?,max_users=65023',(os.environ['PUBLIC_IP'],))
cfg=Path('/etc/wdtt-xray/config.json'); cfg.parent.mkdir(exist_ok=True)
if not cfg.exists():
    cfg.write_text(json.dumps({'log':{'loglevel':'warning'},'inbounds':[], 'outbounds':[{'tag':'direct','protocol':'freedom','settings':{}},{'tag':'blocked','protocol':'blackhole','settings':{}}],'routing':{'rules':[]}}))
runtime=runpy.run_path(str(Path(sys.argv[1])/'scripts/protocols.py'))
with runtime['locked']():
    state=runtime['state'](); state['profiles'].setdefault('wdtt',True); runtime['save'](state)
PY
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
printf 'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.rp_filter=0\n' >/etc/sysctl.d/90-wdtt-panel.conf
sysctl -p /etc/sysctl.d/90-wdtt-panel.conf
systemctl daemon-reload
systemctl enable --now nginx wdtt wdtt-xray
systemctl restart wdtt wdtt-xray
for protocol in qwdtt wdtt-plus csqtt-2.1.9 csqtt-2.5.0 freeturn; do
    if python3 -c 'import json,sys; s=json.load(open("/etc/wdtt/protocols/state.json")); sys.exit(0 if s["profiles"].get(sys.argv[1]) else 1)' "$protocol"; then
        systemctl restart "wdtt-protocol@$protocol"
        continue
    fi
    printf '{"op":"create","protocol":"%s","host":"%s"}\n' "$protocol" "$PUBLIC_IP" | python3 /usr/local/lib/wdtt/protocols.py || {
        printf '{"op":"list"}\n' | python3 /usr/local/lib/wdtt/protocols.py
        exit 1
    }
done
systemctl enable --now wdtt-protocol-watch
systemctl restart wdtt-protocol-watch
seeded=0
for attempt in $(seq 1 20); do
    if printf '{"op":"seed-default"}\n' | python3 /usr/local/lib/wdtt/protocols.py; then seeded=1; break; fi
    sleep 1
done
[[ "$seeded" == 1 ]] || { echo 'Не удалось создать общую подписку; проверьте журналы серверов.' >&2; exit 1; }

if [[ "$MODE" == selfsigned ]]; then
    CERT=/etc/wdtt/panel-cert.pem; KEY=/etc/wdtt/panel-key.pem
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=$PUBLIC_IP" -addext "subjectAltName=IP:$PUBLIC_IP" -keyout "$KEY" -out "$CERT"
elif [[ "$MODE" == certbot ]]; then
    CERT=/etc/letsencrypt/live/$PANEL_HOST/fullchain.pem; KEY=/etc/letsencrypt/live/$PANEL_HOST/privkey.pem
    if [[ ! -f "$CERT" ]]; then
        mkdir -p /var/lib/wdtt-acme
        printf 'server { listen 80; server_name %s; location /.well-known/acme-challenge/ { root /var/lib/wdtt-acme; } }\n' "$PANEL_HOST" > /etc/nginx/conf.d/wdtt-panel-acme.conf
        nginx -t
        systemctl reload nginx
        certbot certonly --non-interactive --agree-tos --register-unsafely-without-email --webroot -w /var/lib/wdtt-acme -d "$PANEL_HOST"
    fi
    install -d /etc/letsencrypt/renewal-hooks/deploy
    printf '#!/bin/sh\nnginx -t && systemctl reload nginx\n' >/etc/letsencrypt/renewal-hooks/deploy/wdtt-panel
    chmod 755 /etc/letsencrypt/renewal-hooks/deploy/wdtt-panel
    systemctl enable --now certbot.timer
fi
python3 "$SOURCE_DIR/scripts/configure-nginx.py" --host "$PANEL_HOST" --port "$EXTERNAL_PORT" --backend "$WDTT_BACKEND_PORT" --subport "$WDTT_SUB_PORT" --mode "$MODE" --cert "$CERT" --key "$KEY"
iptables -w -C INPUT -p tcp --dport "$EXTERNAL_PORT" -m comment --comment WDTT_PANEL -j ACCEPT 2>/dev/null || iptables -w -I INPUT -p tcp --dport "$EXTERNAL_PORT" -m comment --comment WDTT_PANEL -j ACCEPT
cat >/usr/local/lib/wdtt/panel-firewall.sh <<FIREWALL
#!/bin/sh
iptables -w -C INPUT -p tcp --dport $EXTERNAL_PORT -m comment --comment WDTT_PANEL -j ACCEPT 2>/dev/null || iptables -w -I INPUT -p tcp --dport $EXTERNAL_PORT -m comment --comment WDTT_PANEL -j ACCEPT
FIREWALL
chmod 755 /usr/local/lib/wdtt/panel-firewall.sh
cat >/etc/systemd/system/wdtt-panel-firewall.service <<'UNIT'
[Unit]
Description=WDTT Panel external port
After=network-online.target ufw.service nftables.service
Before=nginx.service
[Service]
Type=oneshot
ExecStart=/usr/local/lib/wdtt/panel-firewall.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now wdtt-panel-firewall
for port in 56000 56001 56003; do
    iptables -w -C INPUT -p udp --dport "$port" -m comment --comment WDTT_PANEL -j ACCEPT 2>/dev/null || iptables -w -I INPUT -p udp --dport "$port" -m comment --comment WDTT_PANEL -j ACCEPT
done
echo 'Установка завершена. Логин и пароль: /etc/wdtt/install-credentials (доступ только root).'
echo "Панель: $WDTT_PUBLIC_URL/wdtt/"
if [[ -f /etc/wdtt/protocols/default-subscription-id ]]; then
    echo "Общая подписка: $WDTT_PUBLIC_URL/wdtt/sub/$(cat /etc/wdtt/protocols/default-subscription-id)"
fi
