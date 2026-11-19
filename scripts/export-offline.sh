#!/bin/sh
# Build on an online host of the same architecture as the isolated target.
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"
if [ "$#" -ne 1 ]; then
  printf '%s\n' 'Usage: bash scripts/export-offline.sh /absolute/path/to/new-package-directory' >&2
  exit 1
fi
case "$1" in /*) ;; *) printf '%s\n' 'Use an absolute output directory.' >&2; exit 1 ;; esac
sh scripts/ensure-db-password.sh
# mkdir without -p refuses to overwrite a prior package.
mkdir -m 700 "$1"
package_dir=$1
docker compose pull postgres
docker compose build
docker compose -f compose.setup.yaml build
docker save -o "$package_dir/images.tar" postgres:17-bookworm shifr-svyaz-api:0.1.0 shifr-svyaz-web:0.1.0 shifr-svyaz-broker:0.1.0 shifr-svyaz-setup:0.2.0
mkdir "$package_dir/bin"
docker run --rm --pull never --network none --entrypoint /bin/cat shifr-svyaz-setup:0.2.0 /usr/local/bin/shifrctl > "$package_dir/bin/shifrctl-linux"
chmod 755 "$package_dir/bin/shifrctl-linux"
cp compose.yaml compose.setup.yaml shifrctl change-ip.py "$package_dir/"
cp scripts/start-offline.sh "$package_dir/start.sh"
mkdir -p "$package_dir/docs" "$package_dir/docker/postgres" "$package_dir/scripts"
cp docker/postgres/init.sql "$package_dir/docker/postgres/"
cp scripts/ensure-db-password.sh "$package_dir/scripts/"
cp docs/organization.md docs/certificates-sre.md docs/broker.md "$package_dir/docs/"
(
  cd "$package_dir"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum images.tar bin/shifrctl-linux > images.tar.sha256
  else
    shasum -a 256 images.tar bin/shifrctl-linux > images.tar.sha256
  fi
)
if [ "$(id -u)" = 0 ] && [ "${SUDO_UID:-0}" != 0 ]; then
  chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$package_dir"
fi
printf '%s\n' 'Offline package ready. It contains images and instructions, no runtime data, accounts or keys.'
