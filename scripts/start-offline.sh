#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$project_dir"
if [ ! -f .env ]; then
  if [ "$#" -ne 1 ]; then printf '%s\n' 'Первый запуск: bash start.sh <LAN-IP>' >&2; exit 1; fi
  setup_uid=${SUDO_UID:-$(id -u)}
  setup_gid=${SUDO_GID:-$(id -g)}
  if [ "$setup_uid" = 0 ]; then printf '%s\n' 'Запускайте от владельца проекта, при необходимости через sudo.' >&2; exit 1; fi
  sha256sum -c images.tar.sha256
  docker load -i images.tar
  docker image inspect shifr-svyaz-api:0.1.0 shifr-svyaz-web:0.1.0 shifr-svyaz-inspircd:4.12.1 shifr-svyaz-setup:0.1.0 >/dev/null
  docker compose -f compose.setup.yaml run --rm --pull never --user "$setup_uid:$setup_gid" setup --ip "$1"
fi
lan_ip=$(awk -F= '$1 == "LAN_IP" { print $2; exit }' .env)
if [ -z "$lan_ip" ]; then printf '%s\n' 'LAN_IP отсутствует в .env.' >&2; exit 1; fi
if [ "$#" -gt 0 ] && [ "$1" != "$lan_ip" ]; then printf '%s\n' 'Для смены IP перевыпустите сертификат: docs/certificates-sre.md.' >&2; exit 1; fi
docker compose up -d --no-build --pull never --wait --wait-timeout 180
printf 'Шифр-связь: https://%s:8443\n' "$lan_ip"
printf '%s\n' 'Установите runtime/tls/ca.crt на клиентах. Создайте администратора по docs/organization.md.'
