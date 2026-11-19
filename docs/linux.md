# Запуск в Linux через systemd

Приложение запускается от обычной учётной записи. Nginx отдаёт собранный Next.js
и проксирует HTTPS и WebSocket на Rust API. Для клиентов адрес такой же, как в Compose.
В этом режиме у приложения свои сертификаты и своя PostgreSQL. Если переходите
с работающей установки Compose, сначала прочитайте раздел о переносе ниже.

## Зависимости

Нужен Linux с пользовательским systemd и обычная локальная или SSH-сессия.
Для Debian/Ubuntu установите серверные программы и инструменты сборки:

```bash
sudo apt update
sudo apt install nginx postgresql postgresql-client libpq-dev libssl-dev build-essential pkg-config openssl curl iproute2 util-linux
```

Для сборки также нужны **Node.js 24.x с npm** и **Rust 1.91.1 или новее с Cargo**.
Проверьте версии под той учётной записью, которая будет запускать приложение.
[Node.js 24 для Linux](https://nodejs.org/en/download) · [Установка Rust](https://rustup.rs/).

```bash
node --version
npm --version
rustc --version
cargo --version
pg_config --version
systemctl --user status
```

Скрипт находит серверные бинарники PostgreSQL через `pg_config --bindir`.
При нескольких версиях задайте, например, `export PG_BINDIR=/usr/lib/postgresql/17/bin`.
При переносе из Compose с PostgreSQL 17 используйте PostgreSQL 17 на принимающем сервере. Пакет Ubuntu 24.04 по умолчанию
содержит PostgreSQL 16. [Пакеты PostgreSQL для Ubuntu](https://www.postgresql.org/download/linux/ubuntu/).

Для первого запуска или пересборки нужен доступ к реестрам npm и Cargo либо заполненные кеши.

## Первый запуск

Положите `project_back` и `project_front` рядом. Узнайте адрес интерфейса
командой `ip -br -4 addr`. Используйте частный IPv4, доступный клиентам в LAN.
На сервере из `project_back` выполните **без sudo**:

```bash
./start-linux.sh 192.168.1.10
./start-linux.sh admin
```

Первая команда собирает Rust и Next.js, создаёт сертификаты и запускает службы.
Вторая создаёт первого администратора с ником `admin` и запрашивает пароль без эха.
Для другого ника используйте `./start-linux.sh admin alice`.
Скрипт выводит адрес интерфейса. Установите на клиентские устройства публичный
`~/.local/share/shifr-svyaz/runtime/tls/ca.crt` и откройте
`https://192.168.1.10:8443`. [Установка CA на устройства](certificates-sre.md).

| Служба systemd | Где принимает соединения |
| --- | --- |
| `shifr-web.service` | LAN-IP сервера, TCP 8443, HTTPS/WSS |
| `shifr-api.service` | 127.0.0.1:9443, HTTPS |
| `shifr-broker.service` | 127.0.0.1:7000, TCP |
| `shifr-postgres.service` | Unix-сокет в `$XDG_RUNTIME_DIR/shifr-postgres`, TCP выключен |

Закрепите LAN-IP за сервером и разрешите TCP 8443 из своей подсети в firewall.
API подключается к БД как роль `shifr`. PostgreSQL сверяет владельца соединения
через peer-аутентификацию. Доступ к сокету и каталогу установки имеет системная
учётная запись, запустившая установщик.

## Управление

```bash
./start-linux.sh                          # запуск с проверкой HTTPS, без пересборки
systemctl --user stop shifr.target         # остановить приложение и его PostgreSQL
systemctl --user restart shifr.target      # перезапустить все четыре службы
systemctl --user status 'shifr-*.service'
journalctl --user -u shifr-api -u shifr-web -n 80
./start-linux.sh --build                   # обновить после изменения исходников
```

Установщик включает `shifr.target` для пользовательской сессии. Чтобы сервер
поднимался после перезагрузки до входа пользователя и продолжал работу после выхода,
один раз выполните `sudo loginctl enable-linger "$(id -un)"`.
Для проверки с сервера подставьте его IP:

```bash
curl --cacert ~/.local/share/shifr-svyaz/runtime/tls/ca.crt https://192.168.1.10:8443/health/ready
```

Ожидается HTTP 200 с `"status":"ok"` и `"broker":true`. При конфликте портов
проверьте `ss -lntp` и журналы служб. Повторный запуск использует прежние ключи и базу.

## Данные и переход с Compose

Каталог установки — `~/.local/share/shifr-svyaz/`. В нём находятся `pgdata/`,
`.env`, `runtime/` и текущая сборка. Том Docker и системный кластер PostgreSQL
используют отдельные каталоги. Снимайте согласованную копию работающей нативной БД так:

```bash
umask 077
~/.local/share/shifr-svyaz/pg-bin/pg_dump -h "$XDG_RUNTIME_DIR/shifr-postgres" -U shifr -d shifr -Fc > shifr-native.dump
```

Отдельно сохраните `.env` и `runtime/` в защищённом хранилище. Для переноса с Compose:

1. В старой установке остановите запись командой `docker compose stop web api`. Снимите дамп командой `docker compose exec -T postgres pg_dump -U shifr -d shifr -Fc > shifr-compose.dump` после `umask 077`.
2. Чтобы клиенты продолжили доверять прежнему CA при том же LAN-IP, **до первого нативного запуска** создайте `~/.local/share/shifr-svyaz` с правами 700 и скопируйте в него прежние `.env` и `runtime/` с закрытыми правами. У аккаунта установки должен быть доступ к этим файлам. Установщик использует сохранённый IP. Порт 8443 должен быть свободен.
3. Запустите `./start-linux.sh <LAN-IP>`. До открытия сервиса пользователям остановите `web` и `api` и восстановите снимок в **новой нативной установке с пустой историей**. Команда ниже заменяет созданную при первом старте схему.

```bash
systemctl --user stop shifr-web shifr-api
~/.local/share/shifr-svyaz/pg-bin/pg_restore -h "$XDG_RUNTIME_DIR/shifr-postgres" -U shifr -d shifr \
  --clean --if-exists --no-owner --no-acl --single-transaction --exit-on-error < shifr-compose.dump
./start-linux.sh
```

Проверьте вход со старым паролем, историю чата и скачивание вложения.
Храните исходный дамп и том Compose до завершения проверки.
