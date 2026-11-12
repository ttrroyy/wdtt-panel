# API WDTT Panel

`BASE=https://panel.example.org/<путь панели>` без завершающего `/`. В локальном режиме используйте адрес из установщика через SSH-туннель.

## Доступ

API-ключ создаётся во вкладке **API-ключи**. Заголовок: `Authorization: Bearer <ключ>`. Права `read` разрешают чтение, `manage` также изменения.

Альтернатива: `POST /login` с JSON `{"username":"admin","password":"..."}`. Сохраните cookie; для изменений передавайте значение cookie `wdtt-csrf` в заголовке `X-CSRF-Token`.

```bash
curl "$BASE/panel/api/users" -H "Authorization: Bearer $API_KEY"
```

Ответ: `{"success":true,"obj":...}`. Ошибка: `{"success":false,"msg":"..."}`. Проверяйте `success`, а не только HTTP-код.

## Инбаунды

| Метод | Путь | Действие |
|---|---|---|
| GET | `/panel/api/protocols` | Каталог локальной ноды |
| GET | `/panel/api/protocols?node_id=<ID>` | Каталог выбранной ноды |
| GET | `/panel/api/protocols?all=1` | Общий каталог для назначения пользователям |
| POST | `/panel/api/protocols` | Операция над инбаундом |
| GET | `/panel/api/inbound` | Настройки WDTT |
| POST | `/panel/api/inbound/save` | Сохранить WDTT |

К методам управления добавляйте `?node_id=<ID>` для удалённой ноды.

Создание VPN-инбаунда:

```json
{"op":"create","protocol":"csqtt-2.5.3-community"}
```

Создание DNS-инбаунда:

```json
{"op":"create","engine":"dnstt","zone":"t.example.org","ns":"ns.example.org"}
```

Типы VPN: `wdtt`, `qwdtt`, `wdtt-plus`, `csqtt-2.1.9`, `csqtt-2.5.0`, `csqtt-2.5.3-community`, `freeturn`.

Движки: `dnstt`, `vaydns`, `slipstream`, `masterdns`, `cottendns`, `soar`, `openflux`. OpenFlux не требует `zone` и `ns`. Ответ создания содержит `id` экземпляра.

Операции: `create`, `delete`, `enable`, `disable`, `update`. Для существующего инбаунда передавайте `protocol` с его ID. Удаление сохраняет ключи для восстановления.

Настройки берите из `settings_sections` каталога. Передавайте только поля без `readonly:true`. WDTT сохраняется отдельным методом `/inbound/save`. Пример:

```json
{"op":"update","protocol":"wdtt-plus","remark":"VPN","port":56200}
```

## Пользователи

| Метод | Путь | Действие |
|---|---|---|
| GET | `/panel/api/users` | Пользователи, подписки, конфиги, трафик |
| POST | `/panel/api/users/add` | Создать пользователя |
| POST | `/panel/api/users/update` | Изменить пользователя |
| POST | `/panel/api/users/delete` | Удалить; JSON `{"password":"..."}` |
| POST | `/panel/api/users/reset-traffic` | Сбросить трафик; тот же JSON |
| POST | `/panel/api/password/main` | Сменить главный пароль; тот же JSON |

```json
{"comment":"User","inbounds":["wdtt","freeturn"],"expires_at":0,"total_gb":0,"max_devices":2}
```

Пустой `password` при создании генерируется автоматически. `expires_at` задаётся в Unix time; `0` отключает срок. `total_gb:0` отключает квоту. Дополнительные поля: `active`, `vk_hash`, `device_ids`, `max_down_mbps`, `max_up_mbps`.

Для обновления нужен `old_password`. Изменение только состава инбаундов:

```json
{"old_password":"USER_PASSWORD","inbounds":["wdtt","n-0123--qwdtt"]}
```

ID удалённого инбаунда: `<node_id>--<local_id>`. Используйте значения из каталога. Отсутствие `inbounds` сохраняет состав, `[]` снимает все привязки. ADMIN нельзя удалить.

Ответ пользователя содержит `sub_id`, `sub_url`, `inbounds`, `connections`, `route_tag`. В `connections`: `protocol`, `title`, `link`, необязательный `wg_config`.

## Подписки и маршруты

`GET <случайный путь подписок>/<sub_id>` не требует сессии. Ссылка возвращается в `sub_url`; в публичном режиме она использует HTTPS на 443. `?format=raw` выдаёт подписку для клиента, `?html=1` открывает страницу конфигов.

| Метод | Путь | Действие |
|---|---|---|
| GET | `/panel/api/protocol-route-options` | Теги инбаундов и пользователей |
| GET | `/panel/api/xray/config` | Конфигурация Xray |
| POST | `/panel/xray/update` | Сохранить; form-поле `xraySetting` с JSON |

Передавайте теги из `protocol-route-options` в `routing.rules[].inboundTag`. `vpn-user-<sub_id>` выбирает все инбаунды пользователя. Выход задаётся в `outboundTag`. Пользовательское правило размещайте выше общего.

## Ноды

`GET /panel/api/nodes` возвращает список. `POST` принимает:

```json
{"op":"add","name":"Node","address":"203.0.113.2","ssh_port":22,"password":"ROOT_PASSWORD","deploy":true}
```

`deploy:true` устанавливает только ноду. `false` подключает готовую ноду. Пароль SSH не сохраняется.

Подключение по API:

```json
{"op":"add","name":"Node","transport":"api","api_url":"https://node.example.org","api_key":"wdtt_api_...","deploy":false}
```

На ноде нужен HTTPS с действующим сертификатом. Ключ создаётся командой `wdtt-node-key`. Отвязка: `{"op":"delete","node_id":"n-..."}`. Службы отвязанной ноды продолжают работать.

## API-ключи и сервисы

| Метод | Путь | Действие |
|---|---|---|
| GET | `/panel/api/api-keys` | Метаданные ключей |
| POST | `/panel/api/api-keys` | `op:create`, `name`, `scope`, `expires_at` |
| POST | `/panel/api/api-keys` | Отзыв: `op:delete`, `id` |
| GET | `/panel/api/status` | Состояние сервисов |
| GET | `/panel/api/logs` | Журнал |
| POST | `/panel/api/server/restartWdttService` | Перезапустить WDTT |
| POST | `/panel/api/server/restartXrayService` | Перезапустить Xray |

Ключи создаются и отзываются только через сессию панели с CSRF. `secret` возвращается один раз. `expires_at:0` означает бессрочный ключ. Права `node` предназначены для служебного `/rpc` отдельной ноды.
