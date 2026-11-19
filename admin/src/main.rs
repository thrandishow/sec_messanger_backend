mod change;
mod pki;
mod services;
mod setup;

use anyhow::{Context, Result, bail, ensure};
use std::{
    env,
    fs::File,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Command,
};

const HELP: &str = "shifrctl — администрирование Шифр-связи

  shifrctl init LAN-IP       Создать .env, ключи и сертификаты
  shifrctl set-ip LAN-IP     Сменить адрес и применить сертификат
  shifrctl renew-cert        Продлить сертификат на текущем адресе

  --compose     Установка Docker Compose в каталоге проекта
  --native      Установка systemd в ~/.local/share/shifr-svyaz
  --root ПУТЬ   Явно задать каталог установки

При первом init по умолчанию выбирается Compose. Для обслуживания
утилита определяет установку автоматически. Запуск служб — через
./start.sh (Compose) или ./start-linux.sh (systemd).";

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Compose,
    Native,
}

fn lan_ip(s: &str) -> Result<Ipv4Addr> {
    s.parse::<Ipv4Addr>()
        .ok()
        .filter(Ipv4Addr::is_private)
        .context("Нужен частный IPv4, например 192.168.1.10.")
}

// Never echo a service's environment, a private key or the output of secret generation.
fn output(cmd: &mut Command) -> Result<Vec<u8>> {
    let name = cmd.get_program().to_string_lossy().into_owned();
    let out = cmd
        .output()
        .with_context(|| format!("Не удалось запустить {name}"))?;
    ensure!(out.status.success(), "{name} завершился с {}", out.status);
    Ok(out.stdout)
}

fn lock(file: &File) -> Result<()> {
    file.try_lock()
        .context("Не удалось заблокировать установку. Возможно, уже выполняется другая операция.")
}

fn field<'a>(text: &'a str, name: &str) -> Result<&'a str> {
    let mut values = text
        .lines()
        .filter_map(|line| line.strip_prefix(name)?.strip_prefix('='));
    let value = values.next();
    ensure!(
        value.is_some() && values.next().is_none(),
        "Ожидалась одна строка {name}= в конфигурации."
    );
    Ok(value.unwrap())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("shifrctl: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = env::args_os().skip(1);
    let mut mode = None;
    let mut root = None;
    let mut positionals = Vec::new();
    while let Some(arg) = args.next() {
        match arg.to_str().context("Некорректный аргумент")? {
            "-h" | "--help" => {
                println!("{HELP}");
                return Ok(());
            }
            "--root" if root.is_none() => {
                root = Some(PathBuf::from(
                    args.next().context("Укажите каталог после --root")?,
                ))
            }
            "--compose" | "--native" => {
                ensure!(
                    mode.is_none(),
                    "Выберите один режим: --compose или --native."
                );
                mode = Some(if arg == "--native" {
                    Mode::Native
                } else {
                    Mode::Compose
                });
            }
            value => positionals.push(value.to_owned()),
        }
    }
    let words: Vec<_> = positionals.iter().map(String::as_str).collect();
    let (init, ip) = match words.as_slice() {
        ["init" | "--ip", ip] => (true, Some(lan_ip(ip)?)),
        ["set-ip", ip] => (false, Some(lan_ip(ip)?)),
        ["renew-cert"] => (false, None),
        _ => bail!("{HELP}"),
    };
    let native =
        env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share/shifr-svyaz"));
    let compose = root.as_deref().unwrap_or(Path::new("."));
    let mode = match mode {
        Some(mode) => mode,
        None if !init
            && root.is_none()
            && native
                .as_ref()
                .is_some_and(|p| p.join(".env").is_file() || p.join("installed").is_file()) =>
        {
            ensure!(
                !compose.join(".env").is_file(),
                "Найдены две установки. Укажите --native или --compose."
            );
            Mode::Native
        }
        None => Mode::Compose,
    };
    unsafe { libc::umask(0o077) };
    if mode == Mode::Native {
        ensure!(
            unsafe { libc::geteuid() } != 0,
            "Для --native запустите команду от владельца установки без sudo."
        );
    }
    let dir = match (root, mode) {
        (Some(path), _) => path,
        (None, Mode::Native) => native.context("Не задан HOME")?,
        (None, Mode::Compose) => PathBuf::from("."),
    };
    if init {
        setup::use_operator_identity()?;
        if mode == Mode::Native {
            std::fs::create_dir_all(&dir)?;
        }
    }
    env::set_current_dir(&dir).with_context(|| format!("Не удалось открыть {}", dir.display()))?;
    match (init, ip) {
        (true, Some(ip)) => setup::initialize(ip),
        _ => change::apply(mode, ip),
    }
}
