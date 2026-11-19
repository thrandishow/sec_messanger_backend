use super::{Mode, output, pki::CA};
use anyhow::{Context, Result, bail, ensure};
use std::{
    net::Ipv4Addr,
    process::Command,
    thread,
    time::{Duration, Instant},
};

pub fn check_interface(ip: Ipv4Addr) -> Result<()> {
    let result = if cfg!(target_os = "macos") {
        output(Command::new("ifconfig").arg("-a"))?
    } else {
        output(Command::new("ip").args(["-o", "-4", "addr", "show"]))?
    };
    let text = String::from_utf8(result)?;
    let addr = ip.to_string();
    let found = text.lines().any(|line| {
        let mut fields = line.split_whitespace();
        fields.any(|word| word == "inet")
            && fields.next().and_then(|w| w.split('/').next()) == Some(addr.as_str())
    });
    ensure!(found, "Адрес {ip} не назначен интерфейсу сервера.");
    Ok(())
}

fn compose() -> Command {
    let mut c = Command::new("docker");
    c.env_remove("LAN_IP").arg("compose");
    c
}

impl Mode {
    pub fn running(self) -> Result<bool> {
        match self {
            Mode::Compose => Ok(!output(compose().args([
                "ps",
                "--status",
                "running",
                "--services",
                "api",
                "web",
            ]))?
            .iter()
            .all(u8::is_ascii_whitespace)),
            Mode::Native => {
                output(Command::new("systemctl").args(["--user", "show-environment"]))?;
                let s = Command::new("systemctl")
                    .args([
                        "--user",
                        "is-active",
                        "--quiet",
                        "shifr-api.service",
                        "shifr-web.service",
                    ])
                    .status()?;
                match s.code() {
                    Some(0) => Ok(true),
                    Some(3 | 4) => Ok(false),
                    _ => bail!("Не удалось проверить состояние служб systemd ({s})"),
                }
            }
        }
    }

    pub fn validate(self) -> Result<()> {
        if self == Mode::Native {
            let prefix = std::env::current_dir()?.join("");
            output(
                Command::new("./nginx")
                    .args(["-t", "-p"])
                    .arg(prefix)
                    .args(["-c", "nginx.conf", "-e", "stderr"]),
            )
            .context("nginx -t отклонил конфигурацию")?;
        }
        Ok(())
    }

    pub fn restart(self) -> Result<()> {
        match self {
            Mode::Native => output(Command::new("systemctl").args([
                "--user",
                "restart",
                "shifr-api",
                "shifr-web",
            ])),
            Mode::Compose => output(compose().args([
                "up",
                "-d",
                "--no-deps",
                "--no-build",
                "--pull",
                "never",
                "--force-recreate",
                "--wait",
                "--wait-timeout",
                "90",
                "api",
                "web",
            ])),
        }
        .context("Не удалось перезапустить API и web")?;
        Ok(())
    }
}

pub fn wait_ready(ip: Ipv4Addr) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(40);
    let check = |path: &str| -> Result<bool> {
        let response = output(Command::new("curl").args([
            "--disable",
            "--silent",
            "--fail",
            "--noproxy",
            "*",
            "--max-time",
            "2",
            "--max-filesize",
            "4096",
            "--cacert",
            CA,
            "--write-out",
            "\\n%{http_code}",
            &format!("https://{ip}:8443/health/{path}"),
        ]))?;
        let (body, code) = std::str::from_utf8(&response)?
            .rsplit_once('\n')
            .context("Нет HTTP-статуса")?;
        let json: serde_json::Value = serde_json::from_str(body)?;
        Ok(code == "200" && json["status"] == "ok")
    };
    loop {
        if check("frontend").unwrap_or(false) && check("ready").unwrap_or(false) {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "Проверка HTTPS на {ip}:8443 не прошла."
        );
        thread::sleep(Duration::from_secs(1));
    }
}
