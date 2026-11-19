use super::{Mode, field, lan_ip, lock, pki, services};
use anyhow::{Context, Result, bail, ensure};
use std::{
    fs,
    io::Write,
    net::Ipv4Addr,
    os::unix::fs::{MetadataExt, fchown},
    path::Path,
};

const PENDING: &str = "runtime/ip-change.pending";

fn replace_field(text: &str, name: &str, value: &str) -> Result<String> {
    let previous = field(text, name)?;
    let prefix = format!("{name}=");
    let mut updated = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        if let Some(rest) = line.strip_prefix(&prefix) {
            updated.push_str(&prefix);
            updated.push_str(value);
            updated.push_str(&rest[previous.len()..]);
        } else {
            updated.push_str(line);
        }
    }
    Ok(updated)
}

fn update_origins(text: &str, old: Ipv4Addr, new: Ipv4Addr) -> Result<String> {
    let value = field(text, "ALLOWED_ORIGINS")?;
    ensure!(
        !value.contains(['\'', '"', '#']),
        "ALLOWED_ORIGINS должен содержать адреса без кавычек и комментариев."
    );
    let old = old.to_string();
    let mut origins: Vec<String> = value
        .split(',')
        .map(|original| {
            let entry = original.trim();
            if let Some(host) = entry
                .strip_prefix("https://")
                .or_else(|| entry.strip_prefix("http://"))
                && let Some(port) = host.strip_prefix(&old)
                && (port.is_empty() || port.starts_with(':'))
            {
                return original.replacen(&old, &new.to_string(), 1);
            }
            original.to_string()
        })
        .collect();
    let required = format!("https://{new}:8443");
    if !origins.iter().any(|s| s.trim() == required) {
        if value.trim().is_empty() {
            origins.clear();
        }
        origins.push(required);
    }
    replace_field(text, "ALLOWED_ORIGINS", &origins.join(","))
}

fn nginx_address(config: &str, old: Ipv4Addr, new: Ipv4Addr) -> Result<String> {
    let address = format!("{old}:8443");
    let mut count = 0;
    let mut updated = String::new();
    for line in config.split_inclusive('\n') {
        let mut words = line.split_ascii_whitespace();
        if words.next() == Some("listen")
            && words.next() == Some(&address)
            && words.next().is_some_and(|s| s.starts_with("ssl;"))
        {
            updated.push_str(&line.replacen(&address, &format!("{new}:8443"), 1));
            count += 1;
        } else {
            updated.push_str(line);
        }
    }
    ensure!(
        count == 1,
        "Не найдена однозначная привязка прежнего IP в nginx.conf."
    );
    Ok(updated)
}

// Preserve owner and permissions even when Compose is managed via sudo.
fn atomic_write(path: &str, bytes: &[u8]) -> Result<()> {
    let path = Path::new(path);
    let original = fs::metadata(path)?;
    let mut tmp = tempfile::NamedTempFile::new_in(path.parent().unwrap_or(Path::new(".")))?;
    tmp.write_all(bytes)?;
    let current = tmp.as_file().metadata()?;
    if (original.uid(), original.gid()) != (current.uid(), current.gid()) {
        fchown(tmp.as_file(), Some(original.uid()), Some(original.gid()))?;
    }
    tmp.as_file().set_permissions(original.permissions())?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)?;
    Ok(())
}

fn snapshot(files: &[&str], active: bool, work: &Path) -> Result<()> {
    let snapshot = work.join("backup");
    for name in files {
        let dest = snapshot.join(name);
        fs::create_dir_all(dest.parent().unwrap())?;
        fs::copy(name, dest)?;
    }
    if active {
        fs::File::create(snapshot.join("was-running"))?;
    }
    fs::rename(snapshot, PENDING)?;
    Ok(())
}

fn restore(files: &[&str]) -> Result<()> {
    for name in files {
        atomic_write(name, &fs::read(Path::new(PENDING).join(name))?)?;
    }
    Ok(())
}

pub fn apply(mode: Mode, requested: Option<Ipv4Addr>) -> Result<()> {
    let guard = match mode {
        Mode::Compose => fs::File::open("runtime"),
        Mode::Native => fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(".install.lock"),
    }
    .context("Не найдена настроенная установка. Проверьте каталог и режим запуска.")?;
    lock(&guard)?;
    // A standalone native init can be maintained before the first systemd deployment.
    let prepared_only = mode == Mode::Native
        && ["installed", "native.env", "nginx.conf"]
            .iter()
            .all(|p| !Path::new(p).exists());
    let native_config = mode == Mode::Native && !prepared_only;
    let files: &[&str] = if native_config {
        &[".env", pki::CERT, "native.env", "nginx.conf"]
    } else {
        &[".env", pki::CERT]
    };
    if let Some(ip) = requested {
        services::check_interface(ip)?;
    }
    let pending = Path::new(PENDING);
    let recovering = pending.is_dir();
    if recovering {
        eprintln!("Восстанавливаю конфигурацию после прерванной операции.");
        restore(files)?;
    }
    let env = fs::read_to_string(".env")?;
    let old = lan_ip(field(&env, "LAN_IP")?)?;
    let new = requested.unwrap_or(old);
    if requested == Some(old) && !recovering {
        println!("Адрес уже настроен: https://{old}:8443");
        return Ok(());
    }
    let active = (!prepared_only && mode.running()?) || pending.join("was-running").is_file();
    let work = tempfile::tempdir_in("runtime")?;
    let mut updates = Vec::new();
    if requested != Some(old) {
        updates.push((
            pki::CERT,
            pki::issue(Path::new("."), work.path(), Some(old), new)?,
        ));
    }
    if new != old {
        let env = replace_field(&env, "LAN_IP", &new.to_string())?;
        updates.push((".env", update_origins(&env, old, new)?.into_bytes()));
        if native_config {
            updates.push((
                "native.env",
                update_origins(&fs::read_to_string("native.env")?, old, new)?.into_bytes(),
            ));
            updates.push((
                "nginx.conf",
                nginx_address(&fs::read_to_string("nginx.conf")?, old, new)?.into_bytes(),
            ));
        }
    }
    if !recovering {
        snapshot(files, active, work.path())?;
    }
    let apply_changes = || -> Result<()> {
        for (name, bytes) in updates {
            atomic_write(name, &bytes)?;
        }
        if native_config {
            mode.validate()?;
        }
        if active {
            mode.restart()?;
            services::wait_ready(new)?;
        }
        Ok(())
    };
    if let Err(error) = apply_changes() {
        restore(files).with_context(|| {
            format!("Ошибка применения ({error:#}). Для восстановления сохранён {PENDING}")
        })?;
        if active && let Err(restart) = mode.restart() {
            bail!(
                "Ошибка применения ({error:#}). Файлы восстановлены для {old}, но перезапуск не удался ({restart:#}). Снимок в {PENDING}. Повторите команду."
            );
        }
        fs::rename(pending, work.path().join("restored"))?;
        return Err(error.context(format!("Восстановлена конфигурация для {old}")));
    }
    fs::rename(pending, work.path().join("finished"))?;
    println!("Сертификат для https://{new}:8443 готов.");
    if active {
        println!("HTTPS проверен.");
    } else {
        println!("Изменения вступят в силу при следующем запуске.");
    }
    Ok(())
}
