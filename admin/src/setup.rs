use super::{field, lock, pki};
use anyhow::{Context, Result, ensure};
use std::{env, fs, net::Ipv4Addr, path::Path};

pub fn use_operator_identity() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let owner = |name| -> Result<u32> {
        env::var(name).ok().and_then(|v| v.parse().ok()).context(
            "Первую настройку запускайте от обычного владельца проекта (можно через sudo).",
        )
    };
    let uid = owner("SUDO_UID")?;
    let gid = owner("SUDO_GID")?;
    ensure!(uid != 0, "Запустите init от владельца проекта.");
    // Only init drops sudo privileges. A later Compose restart may require sudo.
    ensure!(
        unsafe {
            libc::setgroups(0, std::ptr::null()) == 0
                && libc::setgid(gid) == 0
                && libc::setuid(uid) == 0
        },
        "Не удалось переключиться на владельца проекта."
    );
    Ok(())
}

fn dotenv(ip: Ipv4Addr) -> Result<String> {
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let broker = pki::random_hex(32)?;
    let password = pki::random_hex(32)?;
    Ok(format!("HOST=0.0.0.0
PORT=8443
LAN_IP={ip}
LOCAL_UID={uid}
LOCAL_GID={gid}
ALLOWED_ORIGINS=https://{ip}:3000,https://{ip}:8443,https://localhost:3000,https://127.0.0.1:3000,https://localhost:8443,https://127.0.0.1:8443
PGDATABASE=shifr
PGUSER=shifr
PGHOST=127.0.0.1
PGPORT=5432
POSTGRES_PASSWORD={password}
TLS_CERT_PATH=./runtime/tls/server.crt
TLS_KEY_PATH=./runtime/tls/server.key
BROKER_HOST=127.0.0.1
BROKER_PORT=7000
BROKER_TOKEN={broker}
SESSION_TTL_SECONDS=86400
TRUST_PROXY=0
"))
}

pub fn initialize(ip: Ipv4Addr) -> Result<()> {
    let directory = fs::File::open(".")?;
    lock(&directory)?;
    ensure!(
        fs::symlink_metadata(".env").is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "В каталоге уже есть .env. Используйте set-ip или renew-cert."
    );
    // Publishing runtime first leaves the matching env available after an interrupted init.
    let staged_env = Path::new("runtime/.init.env");
    if staged_env.is_file() {
        ensure!(
            field(&fs::read_to_string(staged_env)?, "LAN_IP")? == ip.to_string(),
            "Прерван предыдущий init. Повторите его с первоначальным IP."
        );
    } else {
        ensure!(
            fs::symlink_metadata("runtime")
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "В каталоге уже есть runtime/. Проверьте существующую конфигурацию."
        );
        let stage = tempfile::tempdir_in(".")?;
        let root = stage.path();
        fs::create_dir_all(root.join("runtime/ca"))?;
        fs::create_dir(root.join("runtime/tls"))?;
        pki::new_authority(root)?;
        fs::write(root.join(pki::CERT), pki::issue(root, root, None, ip)?)?;
        fs::write(root.join(staged_env), dotenv(ip)?)?;
        fs::create_dir_all("data")?;
        fs::rename(root.join("runtime"), "runtime")?;
    }
    fs::rename(staged_env, ".env")?;
    println!(
        "Настройка для https://{ip}:8443 готова. Сертификат для устройств: runtime/tls/ca.crt"
    );
    Ok(())
}
