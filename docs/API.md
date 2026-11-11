# WDTT Panel API

Базовый URL панели: `https://<домен или IP>/wdtt/` — через Nginx, внешний порт по умолчанию **443**. При выборе другого порта он указывается в URL. Backend панели (`127.0.0.1:2860` по умолчанию) не доступен снаружи.

Все эндпоинты ниже — относительно базового URL панели. Режим HTTP также поддерживается, если выбран при установке.

## Аутентификация

1. **Логин:** `POST /login`  
   Тело (form или JSON, как в UI): `username`, `password`  
   При успехе устанавливается cookie `wdtt-panel`.

2. **Дальнейшие запросы:** cookie `wdtt-panel` обязателен (сессия).

3. **Изменяющие запросы:** передавайте `X-CSRF-Token` из cookie `wdtt-csrf` (либо из meta-тега страницы панели). Для GET токен не требуется.

4. **Выход:** `POST /logout/`

Пример с curl (после логина cookie в файле):

```bash
umask 077
BASE="https://panel.example.com/wdtt"
read -rs -p "Пароль панели: " PANEL_PASSWORD; echo
curl -c /tmp/wdtt.cookie -X POST "$BASE/login" \
  --data-urlencode "username=admin" --data-urlencode "password=$PANEL_PASSWORD"
unset PANEL_PASSWORD
CSRF=$(awk '$6 == "wdtt-csrf" { print $7 }' /tmp/wdtt.cookie)
curl -b /tmp/wdtt.cookie "$BASE/panel/api/status"
```

## Формат ответов

Успех:

```json
{ "success": true, "obj": { ... } }
```

Ошибка:

```json
{ "success": false, "msg": "описание ошибки" }
```

---

## Статус и мониторинг

### `GET /panel/api/status`

Сводка: сервисы, IP, статистика WDTT.

**Ответ `obj`:**

| Поле | Тип | Описание |
|------|-----|----------|
| `wdtt_active` | bool | `wdtt.service` запущен |
| `xray_active` | bool | `wdtt-xray.service` запущен |
| `wdtt_iface` | string | Адрес `wdtt0` |
| `server_ip` | string | Публичный IP |
| `main_password` | string | Главный пароль VPN |
| `users_count` | int | Число пользователей в БД |
| `stats` | object | `server.log` — онлайн, трафик, uptime |

---

## Протоколы VPS

### `GET /panel/api/protocols`

Каталог шести типов, включая удалённые инбаунды. Авторизация — cookie панели.

| ID протокола | Основной порт | Подсеть |
|--------------|---------------|---------|
| `wdtt` | 56000 | `10.66.0.0/16`; RAW `10.70.0.0/16` |
| `qwdtt` | 56100 | `10.67.0.0/16`; RAW `10.73.0.0/16` |
| `wdtt-plus` | 56200 | `10.68.0.0/16` |
| `csqtt-2.1.9` | 56300 | `10.69.0.0/16` |
| `csqtt-2.5.0` | 56400 | `10.71.0.0/16` |
| `freeturn` | 56500 | `10.72.0.0/16` |

**Ответ `obj`:** массив объектов.

| Поле | Тип | Описание |
|------|-----|----------|
| `id`, `name`, `display_id` | string, string, int | Тип, название и ID строки |
| `tag` | string | Управляемый вход Xray, например `vpn-qwdtt` |
| `present` | bool | Экземпляр создан; второй такой тип создать нельзя |
| `enabled` | bool | Инбаунд включён в настройках |
| `active` | bool | Служба работает; для WDTT служба содержит также саму панель |
| `port`, `ports` | int, int[] | Основной порт и отображаемые порты |
| `subnet`, `subnets` | string, string[] | Основная и дополнительные подсети |
| `protocol_labels` | string[] | Метки транспорта |
| `users`, `traffic_bytes` | int, int | Число пользователей и суммарный трафик из последнего снимка |

### `POST /panel/api/protocols`

JSON + cookie + CSRF. Общий маршрут управления:

```json
{"op":"create","protocol":"csqtt-2.1.9"}
```

| `op` | Действие |
|------|----------|
| `list` | То же, что GET каталога |
| `create` | Создать / восстановить один инбаунд; существующий тип вернёт ошибку |
| `delete` | Удалить инбаунд из таблицы и остановить его; настройки и пользователи остаются |
| `enable` / `disable` | Запустить / остановить без удаления из таблицы |
| `update` | Изменить настройки дополнительного инбаунда |

Для `update` передаются `protocol` и редактируемые параметры из `settings_sections` ответа каталога. Каждый раздел содержит `title` и массив `fields`: `key`, `label`, `type`, `value`, `min`/`max`, `options`, `readonly`, `help`. Поля с `readonly:true` не передаются в запросе и защищены API.

Общие параметры: `remark`, `host`, `dns`, `enabled`, `listen_host`, `port`, `client_port`; для WireGuard — `wg_port`. qWDTT: `direct_enabled`, `direct_port`, `raw_enabled`, `raw_port`. Plus: `max_users`, `max_workers_per_access`, `max_handshakes`, `handshake_rate`, `max_client_mbps`, `wg_backend`. CSQTT: `secure_cookie`, дополнительно `fec` у 2.1.9. FreeTurn: `mtu`, `obf_profile`, `obf_timing_ms`, `debug`.

Неподдерживаемые параметры отклоняются до записи. UDP-порты проверяются на конфликты с другими инбаундами и процессами; firewall и выдаваемые клиентские конфиги следуют настройкам. При ошибке применения восстанавливаются предыдущие настройки. Для WDTT используется `/panel/api/inbound/save`.


Управление пользователями через этот endpoint не поддерживается. Используйте `/panel/api/users`.

## Общая подписка пользователя

Главный пользователь **ADMIN** создаётся с шестью инбаундами. Удаление главного пользователя запрещено. Для любого пользователя список `inbounds` определяет состав подписки; пустой список отключает все протоколы. `sub_id` остаётся стабильным при смене пароля и переустановке.

`GET <sub_url>` возвращает страницу с конфигами при открытии в браузере; `?format=raw` выбирает машинный ответ. Ссылки разделены переводами строк; при включённом `SubEncrypt` весь ответ кодируется в Base64 (по умолчанию включено). Ссылки сохраняют форматы исходных проектов; CSQTT 2.5.0 выдаёт шифрованный URI из своего API, FreeTurn — URI с полем `wg`.

Изменения членства и настроек дополнительных серверов применяет контроллер, обычно в течение нескольких секунд. Удалённые из пользователя инбаунды отзываются; сохранённые пароли используются повторно при добавлении. Удаление пользователя блокирует все его дополнительные протоколы. Существующие пользователи прежней версии сохраняются при миграции.

## Маршрутизация протоколов и пользователей

### `GET /panel/api/protocol-route-options`

Доступные именованные селекторы:

```json
{"success":true,"obj":[
  {"tag":"vpn-qwdtt","label":"qWDTT"},
  {"tag":"vpn-user-<sub_id>","label":"Phone"}
]}
```

ID единого пользователя основан на `sub_id` и сохраняется при смене пароля. Один выбор охватывает все его привязанные инбаунды; адреса новых устройств подставляются автоматически.

Сохранение правил — `POST /panel/xray/update`, **form-поле** `xraySetting` с JSON полной конфигурации. Передавайте cookie и CSRF. Пример фрагмента `routing.rules`:

```json
[
  {"type":"field","inboundTag":["vpn-user-<sub_id>"],"outboundTag":"user-proxy"},
  {"type":"field","inboundTag":["vpn-qwdtt"],"outboundTag":"shared-proxy"}
]
```

Используйте настоящий тег из `protocol-route-options`; outbound должен существовать в конфигурации. В UI это поля **Inbound Tags**, **Пользователь VPN**, **Outbound Tag**. Индивидуальное правило располагается выше общего.

Панель сохраняет логическую таблицу правил в SQLite, а в runtime-конфигурации расширяет общее правило протокола на его пользовательские входы. Пользовательские IPv4-адреса вручную указывать не нужно. Локальные контрольные API закрыты от прозрачного VPN-трафика. Входы `vpn-*` управляются автоматически и не удаляются через API обычных Xray inbound.

---

## Подключения (WDTT Inbound)

### `GET /panel/api/inbound`

Текущие настройки входа + статус.

**Ответ `obj`:** `tag`, `remark`, `listen_host`, `server_host`, `dtls_port`, `wg_port`, `client_port`, `dns`, `max_users`, `service_active`, `iface_up`, `dtls_listening`, `wg_listening`, `active_users`, `online_users`, `xray_active`, …

### `POST /panel/api/inbound/save`

Сохранить inbound и перезапустить WDTT (+ Xray при необходимости).

**Тело:**

```json
{
  "tag": "wdtt-in",
  "remark": "WDTT",
  "listen_host": "0.0.0.0",
  "server_host": "",
  "dtls_port": 56000,
  "wg_port": 56001,
  "client_port": 9000,
  "dns": "1.1.1.1",
  "max_users": 10
}
```

---

## Пользователи VPN

### `GET /panel/api/users`

Каждый пользователь дополнительно содержит:

| Поле | Тип | Описание |
|------|-----|----------|
| `inbounds` | string[] | Выбранные ID из каталога протоколов |
| `connections` | object[] | Конфиги дополнительных инбаундов: `protocol`, `title`, `link`, `wg_config` |
| `route_tag` | string | `vpn-user-<sub_id>`: единый выбор для маршрутизации всех протоколов пользователя |

В `POST /panel/api/users/add` и `/update` передавайте `inbounds`, например `["wdtt","csqtt-2.5.0","freeturn"]`. Если при обновлении поле не передано, состав сохраняется. Пустой массив снимает все привязки. Неподдерживаемые или повторные ID отклоняются до изменения пользователя.

Для изменения основной подписки: `{"old_password":"MAIN_PASSWORD","inbounds":["qwdtt","freeturn"],"main_vk_hash":"HASH"}`. Смена главного пароля выполняется существующим `/panel/api/password/main`. Запрос удаления главного пользователя возвращает ошибку.


Список пользователей + inbound для ссылок.

**Ответ `obj`:**

```json
{
  "main_password": "...",
  "users": [
    {
      "password": "abc123",
      "comment": "Иван",
      "device_ids": ["uuid-1"],
      "devices_bound": 1,
      "max_devices": 3,
      "active": true,
      "online": false,
      "expires": "бессрочно",
      "total_gb": 0,
      "traffic_used_fmt": "1.2 GB",
      "link": "wdtt://..."
    }
  ],
  "inbound": { "dtls_port": 56000, "wg_port": 56001, ... }
}
```

### `POST /panel/api/users/add`

Создать пользователя.

**Тело (все поля опциональны):**

```json
{
  "password": "",
  "comment": "новый",
  "expires_at": 0,
  "total_gb": 0,
  "max_down_mbps": 0,
  "max_up_mbps": 0,
  "max_devices": 1,
  "active": true,
  "count": 1
}
```

- `password` пустой → автогенерация  
- только `count` → массовое создание паролей  

**Ответ:** `{ "password": "..." }` или `{ "passwords": ["...", "..."] }`

### `POST /panel/api/users/update`

**Тело:**

```json
{
  "old_password": "старый",
  "password": "новый",
  "comment": "...",
  "expires_at": 1735689600,
  "total_gb": 50,
  "max_devices": 3,
  "device_ids": ["uuid-1"],
  "active": true,
  "max_down_mbps": 10,
  "max_up_mbps": 5
}
```

Удаление устройства из списка `device_ids` отвязывает его при сохранении.

### `POST /panel/api/users/reset-traffic`

```json
{ "password": "userpass" }
```

### `POST /panel/api/users/delete`

```json
{ "password": "userpass" }
```

### `POST /panel/api/password/main`

Сменить главный пароль VPN.

```json
{ "password": "newMainPass" }
```

---

## Сервисы

### `POST /panel/api/server/restartWdttService`

Перезапуск VPN (unified: in-process restart; legacy: `systemctl restart wdtt`).

```bash
curl -b cookie -X POST "$BASE/panel/api/server/restartWdttService"
```

### `POST /panel/api/server/restartXrayService`

```bash
curl -b cookie -X POST "$BASE/panel/api/server/restartXrayService"
```

Legacy `POST /panel/api/service/{wdtt|xray}/{restart|stop|start}` удалён с v1.4.21.

---

## Xray

| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/panel/api/xray/config` | JSON-конфиг |
| POST | `/panel/xray/update` | Form-поле `xraySetting`: JSON конфигурации; сохранение + restart |
| GET | `/panel/api/xray/versions` | Доступные версии Xray |
| POST | `/panel/api/xray/install/{tag}` | Установить версию |

Совместимые эндпоинты 3x-ui: `/panel/xray/*`, `/panel/setting/*` — см. исходники `panel/xray_handlers.go`.

---

## Ссылки подключения `wdtt://`

Формат (как `vmess://` в 3x-ui):

```
wdtt:// + base64(JSON)
```

JSON:

```json
{
  "v": "1",
  "ps": "WDTT",
  "tag": "wdtt-in",
  "add": "YOUR_SERVER_IP",
  "dtls": 56000,
  "wg": 56001,
  "lp": 9000,
  "id": "password"
}
```

Поле `did` (device id) не обязательно — устройства привязываются автоматически до лимита `max_devices`.

Генерация на сервере: `buildWdttShareLink()` в `panel/wdtt_link.go`.

---

## Файлы конфигурации

Primary — `/etc/wdtt/panel.db` (SQLite). Миграции схемы выполняются автоматически. Legacy JSON исходного WDTT импортируются в БД.

| Файл | Назначение |
|------|------------|
| `/etc/wdtt/panel.db` | Панель, users, inbound, xray meta/config |
| `/etc/wdtt-xray/config.json` | Скомпилированный runtime Xray; логическая конфигурация — в SQLite |
| `/etc/wdtt/protocols/state.json` | Экземпляры, лимиты, связи общей подписки |
| `/etc/wdtt/protocols/<тип>/` | База и ключи соответствующего сервера |
| `/etc/wdtt/protocol-inbounds.json` | Управляемые входы Xray |
| `/etc/wdtt/protocol-subscriptions.json` | Снимок связанных ссылок для выдачи подписок |

---

## Примеры автоматизации

```bash
# Создать пользователя на 30 дней, 50 GB, 2 устройства
curl -b /tmp/wdtt.cookie -H "X-CSRF-Token: $CSRF" -X POST "$BASE/panel/api/users/add" \
  -H "Content-Type: application/json" \
  -d '{
    "comment": "API user",
    "expires_at": '"$(date -d '+30 days' +%s)"',
    "total_gb": 50,
    "max_devices": 2
  }'

# Увеличить лимит активных пользователей и DNS
curl -b /tmp/wdtt.cookie -H "X-CSRF-Token: $CSRF" -X POST "$BASE/panel/api/inbound/save" \
  -H "Content-Type: application/json" \
  -d '{"dns":"1.1.1.1","max_users":20,"dtls_port":56000,"wg_port":56001,"client_port":9000}'
```

---

## Ограничения API

- Нет отдельного API-токена — только сессия панели.
- Unified (`wdtt-app`): изменение inbound/users применяется через hot-reload или in-process restart VPN; панель не останавливается. `wdtt.service` содержит только `-config-dir`.
- Вход имеет ограничение числа неудачных попыток. Для управляющих запросов отдельного общего rate-limit нет. Пароль первой установки генерируется автоматически.
- Backend и подписки слушают localhost; доступ на 443 обслуживает Nginx.
- Внешние квоты и привязка пользователей к маршрутам обновляются контроллером раз в несколько секунд.
- Пользовательская маршрутизация VPN основана на IPv4. Для работы через VK TURN нужен действующий VK hash; он не создаётся без данных VK-аккаунта.
