#!/usr/bin/env python3
"""Change the messenger's LAN address in an existing installation."""
import argparse
from contextlib import contextmanager
import fcntl
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import time

PROJECT = Path(__file__).resolve().parent
TLS = Path("runtime/tls")
CERT = TLS / "server.crt"
CA = TLS / "ca.crt"
PENDING = Path("runtime/ip-change.pending")
PRIVATE = tuple(map(ipaddress.ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))


def private_ip(value):
    try:
        addr = ipaddress.IPv4Address(value)
    except ValueError:
        addr = None
    if not addr or not any(addr in subnet for subnet in PRIVATE):
        raise ValueError("Укажите частный IPv4, например 192.168.1.10.")
    return str(addr)


def check_interface(addr):
    if sys.platform == "darwin":
        output = subprocess.check_output(["ifconfig", "-a"], text=True)
    else:
        output = subprocess.check_output(["ip", "-o", "-4", "addr", "show"], text=True)
    if addr not in re.findall(r"\binet\s+([0-9.]+)", output):
        raise ValueError(f"Адрес {addr} не назначен интерфейсу этого сервера.")


def field(text, name):
    matches = list(re.finditer(rf"^{name}=([^\r\n]*)", text, re.M))
    if len(matches) != 1:
        raise ValueError(f"Ожидалась одна строка {name}= в конфигурации.")
    return matches[0]


def replace_origins(text, old, new):
    match = field(text, "ALLOWED_ORIGINS")
    value = match[1]
    # Setup writes a comma-separated list without quotes. Preserve unrelated origins and ports.
    if any(c in value for c in "\"'#"):
        raise ValueError("ALLOWED_ORIGINS должен содержать список адресов без кавычек и комментариев.")
    value = re.sub(rf"(https?://){re.escape(old)}(?=[:\s,]|$)", lambda m: m[1] + new, value)
    required = f"https://{new}:8443"
    if required not in (entry.strip() for entry in value.split(",")):
        value = value.rstrip() + ("," if value.strip() else "") + required
    return text[:match.start(1)] + value + text[match.end(1):]


def issue_certificate(work, old, new):
    output = subprocess.check_output(
        ["openssl", "x509", "-in", CERT, "-noout", "-ext", "subjectAltName"], text=True)
    names = [f"IP:{new}", "IP:127.0.0.1", "DNS:localhost"]
    for entry in " ".join(output.splitlines()[1:]).split(","):
        entry = entry.strip()
        if entry.startswith("IP Address:"):
            addr = str(ipaddress.ip_address(entry[len("IP Address:"):]))
            if addr != old:
                names.append("IP:" + addr)
        elif re.fullmatch(r"DNS:[A-Za-z0-9_.*-]+", entry):
            names.append(entry)
        else:
            raise ValueError("Нестандартный SAN в сертификате. Нужен ручной перевыпуск.")
    ext = work / "server.ext"
    ext.write_text("subjectAltName=" + ",".join(dict.fromkeys(names)) +
                   "\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                   "extendedKeyUsage=serverAuth\n")
    csr, cert = work / "server.csr", work / "server.crt"
    def openssl(*args):
        subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL)
    openssl("req", "-new", "-key", TLS / "server.key", "-subj", "/CN=Shifr Svyaz Local", "-out", csr)
    openssl("x509", "-req", "-in", csr, "-CA", CA, "-CAkey", "runtime/ca/ca.key",
            "-set_serial", "0x" + secrets.token_hex(16), "-days", "365", "-sha256", "-extfile", ext, "-out", cert)
    for option, name in [("-verify_ip", new), ("-verify_hostname", "localhost")]:
        openssl("verify", "-CAfile", CA, "-purpose", "sslserver", option, name, cert)
    return cert.read_bytes()


def atomic_write(path, contents):
    original = path.stat()
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as tmp:
        temp = Path(tmp.name)
        try:
            tmp.write(contents)
            tmp.flush()
            tmp_stat = os.fstat(tmp.fileno())
            if (tmp_stat.st_uid, tmp_stat.st_gid) != (original.st_uid, original.st_gid):
                os.fchown(tmp.fileno(), original.st_uid, original.st_gid)
            os.fchmod(tmp.fileno(), stat.S_IMODE(original.st_mode))
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)


def service(mode, action):
    if mode == "native":
        if action == "running":
            subprocess.run(["systemctl", "--user", "show-environment"], check=True, stdout=subprocess.DEVNULL)
            return subprocess.run(["systemctl", "--user", "is-active", "--quiet",
                                   "shifr-api.service", "shifr-web.service"]).returncode == 0
        subprocess.run(["systemctl", "--user", "restart", "shifr-api", "shifr-web"], check=True)
    else:
        env = os.environ.copy()
        env.pop("LAN_IP", None)  # Compose must read the current .env for the published port.
        compose = ["docker", "compose"]
        if action == "running":
            return bool(subprocess.check_output(compose + ["ps", "--status", "running", "--services", "api", "web"],
                                                env=env, text=True).strip())
        subprocess.run(compose + ["up", "-d", "--no-deps", "--no-build", "--pull", "never", "--force-recreate",
                                  "--wait", "--wait-timeout", "90", "api", "web"], env=env, check=True)


def wait_ready(addr):
    ctx = ssl.create_default_context(cafile=str(CA))
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        try:
            for path in ("/health/frontend", "/health/ready"):
                conn = http.client.HTTPSConnection(addr, 8443, context=ctx, timeout=2)
                try:
                    conn.request("GET", path)
                    res = conn.getresponse()
                    if res.status != 200 or json.loads(res.read(4096)).get("status") != "ok":
                        raise ValueError("not ready")
                finally:
                    conn.close()
            return
        except (OSError, http.client.HTTPException, ValueError):
            time.sleep(1)
    raise RuntimeError(f"Проверка HTTPS на {addr}:8443 не прошла.")


def restore(files):
    for path in files:
        atomic_write(path, (PENDING / path).read_bytes())


@contextmanager
def installation_lock(mode):
    # Share the native installer's lock. Lock the directory itself for Compose so sudo
    # never leaves a root-owned lock file in the operator's project.
    fd = (os.open(".install.lock", os.O_RDWR | os.O_CREAT, 0o600) if mode == "native"
          else os.open("runtime", os.O_RDONLY))
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Другая операция уже меняет конфигурацию установки.") from None
        yield
    finally:
        os.close(fd)


def change(mode, new):
    with installation_lock(mode):
        files = [Path(".env"), CERT]
        if mode == "native":
            files += [Path("native.env"), Path("nginx.conf")]
        active = service(mode, "running")
        if PENDING.exists():
            # A killed process might have installed only part of the bundle.
            print("Восстанавливаю файлы после прерванной смены IP.", file=sys.stderr)
            restore(files)
            active = active or (PENDING / "was-running").exists()
        env = Path(".env").read_bytes().decode()
        match = field(env, "LAN_IP")
        old = private_ip(match[1])
        if old == new and not PENDING.exists():
            print(f"Адрес уже настроен: https://{new}:8443")
            return

        with tempfile.TemporaryDirectory(dir="runtime") as tmp:
            work = Path(tmp)
            updated = {Path(".env"): replace_origins(env[:match.start(1)] + new + env[match.end(1):], old, new).encode(),
                       CERT: issue_certificate(work, old, new)}
            if mode == "native":
                updated[Path("native.env")] = replace_origins(Path("native.env").read_bytes().decode(), old, new).encode()
                nginx, count = re.subn(rf"(?m)^(\s*listen\s+){re.escape(old)}(:8443\s+ssl;)",
                                       lambda m: m[1] + new + m[2], Path("nginx.conf").read_bytes().decode())
                if count != 1:
                    raise ValueError("Не найдена однозначная привязка старого IP в nginx.conf.")
                updated[Path("nginx.conf")] = nginx.encode()

            if not PENDING.exists():
                backup = work / "backup"
                for path in files:
                    (backup / path).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, backup / path)
                if active:
                    (backup / "was-running").touch()
                backup.rename(PENDING)
            try:
                for path, data in updated.items():
                    atomic_write(path, data)
                if mode == "native":
                    subprocess.run(["./nginx", "-t", "-p", str(Path.cwd()) + "/", "-c", "nginx.conf",
                                    "-e", "stderr"], check=True)
                if active:
                    service(mode, "apply")
                    wait_ready(new)
            except BaseException:
                restore(files)
                print(f"Восстановлена конфигурация для {old}.", file=sys.stderr)
                if active:
                    try:
                        service(mode, "apply")
                    except (OSError, subprocess.CalledProcessError) as err:
                        raise RuntimeError(f"Сервисы на {old} не запустились. Снимок в {PENDING}. "
                                           "Проверьте доступность адреса и повторите смену IP.") from err
                PENDING.rename(work / "restored")
                raise
            PENDING.rename(work / "finished")
        print(f"Новый адрес: https://{new}:8443" if active else
              f"Адрес для следующего запуска: https://{new}:8443")


def main():
    parser = argparse.ArgumentParser(description="Сменить LAN-IP мессенджера и перевыпустить серверный сертификат.")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--native", action="store_true", help="установка systemd текущего пользователя")
    modes.add_argument("--compose", action="store_true", help="установка Docker Compose рядом со скриптом")
    parser.add_argument("ip", metavar="LAN-IP")
    args = parser.parse_args()
    new = private_ip(args.ip)
    native = Path.home() / ".local/share/shifr-svyaz"
    if not args.native and not args.compose:
        if (native / "installed").exists() and (PROJECT / ".env").exists():
            parser.error("Найдены две установки. Укажите --native или --compose.")
        args.native = (native / "installed").exists()
    if args.native and os.geteuid() == 0:
        parser.error("Для --native запустите скрипт от владельца установки без sudo.")
    root = native if args.native else PROJECT
    if not (root / ".env").is_file() or not (root / CA).is_file():
        parser.error(f"Не найдена настроенная установка в {root}.")
    check_interface(new)
    os.chdir(root)
    os.umask(0o077)
    change("native" if args.native else "compose", new)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError, KeyboardInterrupt) as exc:
        sys.exit(f"Смена IP не завершена. {exc}")
