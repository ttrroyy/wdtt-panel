# WDTT Panel

Панель для VPN, DNS-туннелей и удалённых нод. Общие пользователи, подписки, маршрутизация Xray. Интерфейс в стиле 3x-ui, темы OLED и светлая.

## Установка

Debian / Ubuntu, amd64 / arm64, root.

```bash
# Панель + нода
bash <(curl -fsSL https://raw.githubusercontent.com/ttrroyy/wdtt-panel/main/install.sh) combined

# Только панель
bash <(curl -fsSL https://raw.githubusercontent.com/ttrroyy/wdtt-panel/main/install.sh) panel

# Только нода
bash <(curl -fsSL https://raw.githubusercontent.com/ttrroyy/wdtt-panel/main/install.sh) node
```

Установщик проверит совместимость и предложит выбрать инбаунды и доступ:

- **Nginx / Caddy:** домен, панель и подписки на 443, сертификат и продление через Certbot.
- **Локально:** без домена, доступ через SSH, ручное копирование конфигов.

Адрес печатается после установки. Пути панели и подписок случайные, по 17-24 латинских буквы и цифры. Данные входа: `/etc/wdtt/install-credentials`.

Повторная установка сохраняет пользователей, инбаунды, ключи и сертификаты. На нодах все ядра устанавливаются сразу; новые инбаунды добавляются из панели.

## Протоколы

- WDTT, qWDTT, WDTT Plus, CSQTT 2.1.9, CSQTT 2.5.0, CSQTT 2.5.3 (community), FreeTurn.
- DNSTT, VayDNS, Slipstream, MasterDNS / StormDNS, CottenDNS, Soar.
- OpenFlux Direct.

VPN-протоколы создаются по одному экземпляру на VPS. DNS и OpenFlux поддерживают несколько инбаундов. Подсети изолированы; CSQTT 2.5.3 использует оригинальный пул `/24`.

Для DNS-туннелей нужны записи: `A ns.example.org → IP VPS`, `NS t.example.org → ns.example.org`, без CDN. Зона: `t.example.org`. Порты TCP/UDP 53 должны быть свободны. Для Slipstream длина зоны не больше 18 символов, для Soar 26.

## Управление

**Пользователи:** одна подписка на выбранные инбаунды. Главный ADMIN создаётся автоматически. Квота и срок `0` означают безлимит.

**Ноды:** установка по SSH или подключение готовой ноды по SSH/API-ключу. Ключ на ноде: `wdtt-node-key`. Вторая веб-панель не устанавливается.

**Маршрутизация:** правила Xray по инбаунду или общему пользователю. IP клиентов вручную указывать не нужно.

## Удаление

Полное удаление установки на текущем VPS:

```bash
wdtt-panel-uninstall
```

## API и лицензии

[Документация API](docs/API.md) · [Версии VPN-ядер](scripts/protocol-sources.json) · [Версии DNS/OpenFlux](scripts/edge-sources.json)

Панель: [GPL-3.0](LICENSE). У сторонних ядер собственные лицензии. CSQTT community распространяется по PolyForm Noncommercial.
