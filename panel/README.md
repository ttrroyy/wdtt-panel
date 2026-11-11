# wdtt-panel

Веб-панель управления WDTT VPN + Xray. Интерфейс в стиле [3x-ui](https://github.com/MHSanaei/3x-ui).

## Возможности

- **Дашборд** — CPU/RAM, статус WDTT/Xray, онлайн
- **Подключения** — inbound (порты, DNS, лимит пользователей); применение без остановки панели (hot-reload / in-process restart)
- **Пользователи** — пароли, лимит устройств, трафик, ссылки `wdtt://`
- **Настройки Xray** — routing, outbounds, балансеры
- **Настройки панели** — порт, SSL, учётная запись

Протокол VPN основан на [proxy-turn-vk-android](https://github.com/amurcanov/proxy-turn-vk-android) — см. [CREDITS.md](../CREDITS.md).

## API

REST API для автоматизации: **[docs/API.md](../docs/API.md)**

## Установка

Актуальные команды, шесть протоколов, сертификаты, переустановка и удаление описаны в **[основном README](../README.md)**. Панель доступна через **Nginx на 443**, внутренний backend слушает `127.0.0.1`. Пароль первой установки — `/etc/wdtt/install-credentials`.

Все пользователи, их подписки и привязки инбаундов редактируются в разделе **Пользователи**. Основная подписка принадлежит ADMIN и не удаляется.

## Сборка

```bash
# из корня репозитория (рекомендуется)
./build.sh amd64 unified          # → wdtt-linux-amd64 → /usr/local/bin/wdtt-app

# legacy — отдельные бинарники
./build.sh amd64 panel            # → wdtt-panel-linux-amd64
```

Требуется Go 1.21+. UI встроен через `go:embed`.

## Конфигурация

Primary — `/etc/wdtt/panel.db` (SQLite). При обновлении JSON-файлы из `/etc/wdtt/` импортируются в БД и удаляются.

| Файл | Назначение |
|------|------------|
| `/etc/wdtt/panel.db` | Панель, users, inbound, xray meta/config |
| `/etc/wdtt-xray/config.json` | Конфиг Xray на диске (процесс xray; панель синхронизирует из БД) |

## Зависимости

- `wdtt.service` — unified `wdtt-app` (панель `:2860` + VPN; ExecStart только `-config-dir`)
- `wdtt-xray.service` — опционально, маршрутизация
