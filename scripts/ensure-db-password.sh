#!/bin/sh
# Upgrade a pre-PostgreSQL installation in place. Only append a freshly generated field.
set -eu
[ -f .env ] || { echo 'Сначала настройте проект через ./start.sh <LAN-IP>.' >&2; exit 1; }
if grep -q '^POSTGRES_PASSWORD=.' .env; then exit 0; fi
if grep -q '^POSTGRES_PASSWORD=' .env; then
  echo 'POSTGRES_PASSWORD задан пустым. Укажите пароль в .env.' >&2; exit 1
fi
# Serialize concurrent start.sh processes. Never echo the generated secret.
lock=.env.pg-lock
mkdir "$lock" || { echo 'Другой процесс обновляет .env. Проверьте .env.pg-lock.' >&2; exit 1; }
trap 'rmdir "$lock"' EXIT
if ! grep -q '^POSTGRES_PASSWORD=.' .env; then
  password=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
  [ "${#password}" = 64 ] || exit 1
  printf '\nPOSTGRES_PASSWORD=%s\n' "$password" >> .env
fi
