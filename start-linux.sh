#!/usr/bin/env bash
# Native Linux installation. All files and services belong to the invoking user.
set -euo pipefail
umask 077
fail() { printf '%s\n' "$*" >&2; exit 1; }

[[ $(uname -s) == Linux && $EUID != 0 ]] || fail 'Запускайте от обычного пользователя Linux, без sudo.'
project=$(cd -- "$(dirname -- "$0")" && pwd)
front="$project/../project_front"
state="$HOME/.local/share/shifr-svyaz"
units="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
socket="${XDG_RUNTIME_DIR:?Войдите в обычную сессию Linux с systemd --user.}/shifr-postgres"
systemctl --user show-environment >/dev/null || fail 'Недоступен systemd --user. Откройте обычную SSH- или локальную сессию.'

if [[ ${1:-} == admin ]]; then
  [[ $# -le 2 && -x "$state/current/shifr-api" ]] || fail 'Сначала установите сервисы. Команда: ./start-linux.sh admin [ник]'
  read -rsp 'Пароль первого администратора (12–128 символов): ' password
  printf '\n' >&2
  printf '%s\n' "$password" | env -u LEGACY_SQLITE_PATH DATABASE_URL="host=$socket user=shifr dbname=shifr" "$state/current/shifr-api" admin --nickname "${2:-admin}"
  exit
fi

rebuild=false
if [[ ${1:-} == --build ]]; then rebuild=true; shift; fi
[[ $# -le 1 ]] || fail 'Использование: ./start-linux.sh [--build] [LAN-IP]'
ip_arg=${1:-}
mkdir -p -- "$state"
cd -- "$state"
exec 9>.install.lock
flock -n 9 || fail 'Установка уже выполняется.'

if [[ -f .env ]]; then
  ip=$(awk -F= '$1 == "LAN_IP" { print $2; exit }' .env)
  [[ -n "$ip" && (-z "$ip_arg" || "$ip_arg" == "$ip") ]] || fail 'LAN-IP отличается от сохранённого. Выполните ./change-ip.py --native <новый-IP>.'
else
  ip=$ip_arg
  [[ -n "$ip" ]] || fail 'Первый запуск: ./start-linux.sh <LAN-IP>'
fi
ip -o -4 addr show | awk '{split($4,a,"/"); print a[1]}' | grep -Fx "$ip" >/dev/null || fail "Адрес $ip не назначен сетевому интерфейсу сервера."

wait_web() {
  for ((attempt=0; attempt<90; attempt++)); do
    if curl -fs --noproxy '*' --max-time 3 --cacert runtime/tls/ca.crt "https://$ip:8443/health/ready" >/dev/null &&
       curl -fs --noproxy '*' --max-time 3 --cacert runtime/tls/ca.crt "https://$ip:8443/" >/dev/null &&
       systemctl --user is-active --quiet shifr-web.service; then
      printf 'Шифр-связь готова: https://%s:8443\nСертификат для устройств: %s/runtime/tls/ca.crt\n' "$ip" "$state"
      return
    fi
    sleep 1
  done
  fail 'Сервисы не готовы. Проверьте journalctl --user -u "shifr-*" -n 80.'
}

if [[ -f installed && "$rebuild" == false ]]; then
  systemctl --user start shifr.target
  wait_web
  exit
fi

for cmd in node npm cargo openssl curl; do
  command -v "$cmd" >/dev/null || fail "Нужна команда $cmd. См. docs/linux.md."
done
[[ $(node -p 'process.versions.node.split(".")[0]') == 24 ]] || fail 'Для сборки нужен Node.js 24.'
[[ -f "$front/package-lock.json" ]] || fail 'Положите project_front рядом с project_back.'
pg_bin=${PG_BINDIR:-$(pg_config --bindir)} || fail 'Укажите PG_BINDIR или установите pg_config.'
for cmd in initdb postgres psql pg_isready createdb; do
  [[ -x "$pg_bin/$cmd" ]] || fail "Не найден $pg_bin/$cmd. Укажите PG_BINDIR с серверными программами PostgreSQL."
done
nginx_bin=$(command -v nginx || true)
nginx_bin=${nginx_bin:-/usr/sbin/nginx}
[[ -x "$nginx_bin" ]] || fail 'Установите nginx.'
[[ -r /etc/nginx/mime.types ]] || fail 'Не найден /etc/nginx/mime.types из пакета nginx.'
if [[ -e pgdata ]]; then
  [[ -s pgdata/PG_VERSION ]] || fail 'Проверьте существующий каталог pgdata: отсутствует PG_VERSION.'
  # Debian appends a package version in parentheses.
  pg_version=$("$pg_bin/postgres" --version | awk '{split($3,v,"."); print v[1]}')
  [[ $(<pgdata/PG_VERSION) == "$pg_version" ]] || fail 'Версия PostgreSQL отличается от PG_VERSION. Укажите прежний PG_BINDIR или перенесите базу через дамп.'
fi

stage=$(mktemp -d "$state/.stage.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
if [[ ! -f .env ]]; then
  [[ ! -e runtime ]] || fail 'Найдена прежняя runtime/ без .env. Восстановите конфигурацию из копии.'
  (cd "$stage" && node "$project/scripts/setup.mjs" --ip "$ip" >/dev/null)
  mv -- "$stage/runtime" .
  mv -- "$stage/.env" .
fi
node "$project/linux/configure.mjs" "$front/nginx.conf"
mkdir -p -- tmp "$units"
"$nginx_bin" -t -p "$state/" -c nginx.candidate.conf -e stderr

# Compile as the unprivileged operator; keep the running binaries until the build succeeds.
CARGO_TARGET_DIR="$project/api/target" cargo build --release --locked --manifest-path "$project/api/Cargo.toml"
CARGO_TARGET_DIR="$project/broker/target" cargo build --release --locked --manifest-path "$project/broker/Cargo.toml"
(cd "$front" && npm ci --include=dev --no-audit --no-fund && NEXT_PUBLIC_API_URL='' NEXT_TELEMETRY_DISABLED=1 npm run build)
[[ -s "$front/out/index.html" ]] || fail 'Сборка Next.js не создала out/index.html.'
mkdir "$stage/release"
cp -r -- "$front/out" "$stage/release/html"
install -m 700 "$project/api/target/release/shifr-api" "$project/broker/target/release/shifr-broker" "$stage/release/"

if [[ ! -e pgdata ]]; then
  "$pg_bin/initdb" -D "$stage/pgdata" -U postgres --encoding=UTF8 --locale=C --auth-local=peer --auth-host=scram-sha-256 >/dev/null
  account=$(id -un)
  # Peer authentication authorizes only the owner of this private Unix socket.
  printf 'local all all peer map=shifr_owner\n' > "$stage/pgdata/pg_hba.conf"
  printf 'shifr_owner "%s" postgres\nshifr_owner "%s" shifr\n' "$account" "$account" > "$stage/pgdata/pg_ident.conf"
  mv -- "$stage/pgdata" pgdata
fi

ln -sfnT -- "$pg_bin" pg-bin
ln -sfnT -- "$nginx_bin" nginx
install -m 644 "$project"/linux/shifr*.service "$project/linux/shifr.target" "$units/"
systemctl --user daemon-reload
systemctl --user start shifr-postgres.service
export PGHOST="$socket" PGPORT=5432 PGUSER=postgres PGDATABASE=postgres
for ((attempt=0; attempt<60; attempt++)); do
  if "$pg_bin/pg_isready" -q; then break; fi
  sleep 1
done
# Recover also if a prior first start stopped between creating the role and database.
"$pg_bin/psql" -X -v ON_ERROR_STOP=1 <<'SQL'
SELECT 'CREATE ROLE shifr LOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='shifr') \gexec
SELECT 'CREATE DATABASE shifr OWNER shifr' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='shifr') \gexec
SQL

release=$(mktemp -d "$state/release.XXXXXXXX")
mv -- "$stage/release/"* "$release/"
previous=$(readlink current || true)
ln -s -- "${release##*/}" "$stage/current"
mv -Tf -- "$stage/current" current
mv -f -- nginx.candidate.conf nginx.conf
systemctl --user enable shifr.target
systemctl --user restart shifr.target
wait_web
touch installed
# Only remove a previous release made by this installer, after the new one passed readiness.
if [[ "$previous" =~ ^release\.[a-zA-Z0-9]{8}$ ]]; then rm -rf -- "$state/$previous"; fi
