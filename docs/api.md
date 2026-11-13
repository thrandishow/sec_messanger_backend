# API v2

Адрес: `https://<LAN-IP>:8443`. JSON в UTF-8, cookie с `credentials: 'include'`.
Изменяющие запросы требуют точный Origin из `ALLOWED_ORIGINS`. Ответы не кешируются.
В Compose IP клиента берётся только от одного доверенного Nginx, который
перезаписывает X-Forwarded-For. API не принимает публичные IP.

## HTTP

| Метод | Путь | Тело / результат |
| --- | --- | --- |
| GET | `/health/live` | `{status:"ok"}` |
| GET | `/health/ready` | `{status:"ok",irc:true}` либо HTTP 503 |
| GET | `/api/config` | protocolVersion=2, registration=admin, history=true, fileMaxBytes=10485760, messageMaxBytes=350, endToEndEncryption=false |
| POST | `/api/auth/register` | Всегда 403 REGISTRATION_CLOSED |
| POST | `/api/auth/login` | `{nickname,password}` → `{user,expiresAt}` + cookie |
| GET | `/api/auth/me` | `{user,expiresAt}` |
| POST | `/api/auth/logout` | 204; отзыв текущей сессии |
| GET | `/api/chat/status` | `{connected:boolean}` |
| GET | `/api/directory` | `{channels:[{channel,name}],users:[{nickname}],conversations:[nickname]}`; доступные чаты и активные аккаунты |
| GET | `/api/history?target=…&before=…` | `{messages,nextBefore}`; target URL-encoded, before необязательный ID, до 50 сообщений в порядке возрастания ID |
| GET | `/api/resources` | `{files:[{id,name,size,created_at}]}` |
| POST | `/api/files?scope=chat&target=…&name=…` | Бинарное тело application/octet-stream, до 10 МиБ → 201 `{file:{id,name,size}}` |
| POST | `/api/files?scope=resource&name=…` | Публикация ресурса модератором/администратором; тот же бинарный формат |
| GET | `/api/files/:id` | Скачивание с авторизацией и проверкой доступа; application/octet-stream, Content-Disposition: attachment |
| POST | `/api/resources/:id/delete` | Модератор/администратор, 204 |
| GET | `/api/admin/users` | Администратор: `{users,departments}` |
| POST | `/api/admin/users` | `{nickname,password,role,department}` → 201 `{user}`; department — канал отдела или null |
| POST | `/api/admin/users/:id` | `{role,department,active,password?}` → `{user}`; сессии пользователя отзываются |
| POST | `/api/admin/departments` | `{channel:"#finance",name:"Финансы"}` → 201; системные каналы зарезервированы |
| GET | `/api/admin/audit?before=…` | `{entries,nextBefore}`; до 100 событий в порядке убывания ID |

`user`: `{id,nickname,role,department,active}`. Роли: `admin`, `moderator`, `member`.
`active` в ответе — 0/1; в запросе изменения — boolean. `expiresAt` и `created_at` —
Unix milliseconds. Сессия действует 24 часа по умолчанию, максимум пять сессий
на аккаунт. Пароль: 12–128 символов; ник: 3–24 латинских символа, цифры, `_`, первая буква.

Для вложения сначала загрузите файл с `scope=chat` и target, затем передайте его ID
в WS-команде. Прикрепить можно только свой ещё не использованный файл к указанному
при загрузке диалогу. Неприкреплённый файл скачивает только загрузивший пользователь;
после прикрепления — участники диалога. Для отдела право проверяется по текущему
членству; администратор видит историю отделов, но не чужие личные диалоги.

Аудит содержит `{id,time,actor,nickname,action,subject,ip}`. `time` — ISO UTC,
subject — ID объекта или JSON с изменениями аккаунта без пароля. Журнал доступен
только администратору. Первое назначение администратора — локальный CLI,
см. [эксплуатацию](organization.md).

## WebSocket

`wss://<LAN-IP>:8443/ws`. Cookie и Origin проверяются до upgrade. Один аккаунт —
одно соединение; второй получает HTTP 409. Дождитесь `ready`, затем отправляйте
текстовые JSON-кадры:

```json
{"type":"join","channel":"#general"}
{"type":"names","channel":"#general"}
{"type":"message","target":"#general","text":"Привет!"}
{"type":"message","target":"bob","text":"Документ","attachmentId":"550e8400-e29b-41d4-a716-446655440000"}
{"type":"part","channel":"#general"}
{"type":"ping"}
```

Доступны #general, #announcements и зарегистрированные отделы из directory.
Произвольные каналы создавать через join нельзя. Обычный сотрудник читает
#announcements, но писать может только модератор или администратор.
Проверки ролей выполняются на сервере для каждой команды, а не только в UI.
IRC-префикс оператора (`@`) не является ролью приложения.

Текст: до 350 байт UTF-8, одна строка без управляющих символов. Вложения передаются
через HTTP; текст и метаданные сообщения — через WS. Для отправки в канал нужно
вступить в него; личный адресат должен быть активным аккаунтом онлайн.

События: ready, join, part, quit, names, topic, message, pong, error. Пример сохранённого
сообщения с файлом:

```json
{"type":"message","id":42,"from":"alice","target":"bob","text":"Документ","time":"2026-11-13T12:00:00.000Z","attachment":{"id":"550e8400-e29b-41d4-a716-446655440000","name":"График.pdf","size":1024}}
```

API сохраняет сообщение один раз по IRC-эху отправителя. Всем получателям отдаётся
одинаковый ID, используемый и в истории. До получения эха отправка не подтверждена;
подтверждения прочтения нет. После reconnect повторите join и загрузите history,
объединяя события по ID. Один отправитель может ждать подтверждения одного сообщения.

## Ошибки и лимиты

Ошибки HTTP: `{error:"CODE"}`; WS: `{type:"error",code:"CODE",message:"…"}`.

| HTTP | Коды / смысл |
| --- | --- |
| 400 | INVALID_INPUT / INVALID_REQUEST |
| 401 | UNAUTHORIZED / INVALID_CREDENTIALS |
| 403 | FORBIDDEN, REGISTRATION_CLOSED, ORIGIN_DENIED, LAN_ONLY |
| 404 | NOT_FOUND, в том числе при недоступном чужом файле |
| 409 | NICKNAME_TAKEN, ALREADY_EXISTS, ALREADY_CONNECTED, LAST_ADMIN |
| 413 | Превышен размер тела |
| 429 | Лимит запросов; учитывать Retry-After |
| 500 | INTERNAL_ERROR без текста исключения/секретов |
| 507 | STORAGE_FULL — квота файлов исчерпана |

Дополнительные WS-коды: NOT_READY, NOT_JOINED, INVALID_JSON, INVALID_COMMAND,
MESSAGE_PENDING, MESSAGE_TIMEOUT, STORAGE_ERROR, FORBIDDEN, IRC_401 (адресат офлайн)
и прочие IRC_<число>, IRC_UNAVAILABLE/DISCONNECTED/TIMEOUT.

JSON HTTP — 4096 байт; upload — 10 МиБ; общая квота содержимого файлов — 1 ГиБ.
HTTP — 120 запросов в минуту на IP, вход и загрузка файлов — по 10 на маршрут/IP.
WS — 4096 байт на кадр, 5 команд/с, всплеск до 20; ping каждые 30 секунд.
Переполнение очереди, истечение сессии, выход или административное изменение
аккаунта закрывают WSS; перепроверьте `/api/auth/me`. Лимит каналов InspIRCd — 20
на соединение. UI восстанавливает первые 20 доступных чатов; для остальных
сначала покиньте один из подключённых.
