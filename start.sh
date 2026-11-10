#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$project_dir"
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  printf '%s\n' 'Нужен Docker с Compose v2. Установите и запустите Docker Desktop (macOS/Windows) или Docker Engine (Linux).' >&2
  exit 1
fi
if [ ! -f ../project_front/package.json ]; then
  printf '%s\n' 'Папки project_back и project_front должны лежать рядом.' >&2
  exit 1
fi
if [ ! -f .env ]; then
  if [ "$#" -ne 1 ]; then
    printf '%s\n' 'Первый запуск: ./start.sh <LAN-IP>, например ./start.sh 192.168.1.10' >&2
    exit 1
  fi
  docker compose -f compose.setup.yaml build
  docker compose -f compose.setup.yaml run --rm --user "$(id -u):$(id -g)" setup --ip "$1"
fi
lan_ip=$(awk -F= '$1 == "LAN_IP" { print $2; exit }' .env)
if [ -z "$lan_ip" ]; then
  printf '%s\n' 'В .env отсутствует LAN_IP. Настройка не изменена.' >&2
  exit 1
fi
if [ "$#" -gt 0 ] && [ "$1" != "$lan_ip" ]; then
  printf '%s\n' 'Уже настроен другой LAN-IP. Сначала обновите адрес, сертификат и ALLOWED_ORIGINS; существующие данные не перезаписаны.' >&2
  exit 1
fi
docker compose up --build -d --wait --wait-timeout 180
printf '\nШифр-связь готова: https://%s:8443\n' "$lan_ip"
printf '%s\n' 'Установите runtime/tls/ca.crt как доверенный CA на клиентских устройствах.'
