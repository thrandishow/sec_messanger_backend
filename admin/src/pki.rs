use super::output;
use anyhow::{Context, Result, bail, ensure};
use std::{
    fs,
    io::Read,
    net::{IpAddr, Ipv4Addr},
    path::Path,
    process::Command,
};

pub const CERT: &str = "runtime/tls/server.crt";
pub const CA: &str = "runtime/tls/ca.crt";
const KEY: &str = "runtime/tls/server.key";

pub fn random_hex(bytes: usize) -> Result<String> {
    let mut buffer = vec![0; bytes];
    fs::File::open("/dev/urandom")?.read_exact(&mut buffer)?;
    Ok(buffer.iter().map(|n| format!("{n:02x}")).collect())
}

pub fn new_authority(root: &Path) -> Result<()> {
    output(Command::new("openssl").current_dir(root).args([
        "req",
        "-x509",
        "-newkey",
        "rsa:3072",
        "-sha256",
        "-days",
        "3650",
        "-noenc",
        "-keyout",
        "runtime/ca/ca.key",
        "-out",
        CA,
        "-subj",
        "/CN=Shifr Svyaz Local CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    ]))
    .context("Не удалось создать CA. Для выпуска нужен OpenSSL 3")?;
    output(Command::new("openssl").current_dir(root).args([
        "genpkey",
        "-algorithm",
        "RSA",
        "-pkeyopt",
        "rsa_keygen_bits:3072",
        "-out",
        KEY,
    ]))
    .context("Не удалось создать ключ сервера")?;
    Ok(())
}

fn names(root: &Path, old: Option<Ipv4Addr>, new: Ipv4Addr) -> Result<Vec<String>> {
    let mut names = vec![
        format!("IP:{new}"),
        "IP:127.0.0.1".into(),
        "DNS:localhost".into(),
    ];
    if let Some(old) = old {
        let ext = output(Command::new("openssl").current_dir(root).args([
            "x509",
            "-in",
            CERT,
            "-noout",
            "-ext",
            "subjectAltName",
        ]))?;
        let ext = std::str::from_utf8(&ext)?;
        let (_, values) = ext
            .trim()
            .split_once('\n')
            .context("В сертификате отсутствует subjectAltName")?;
        for entry in values.trim().split(',').map(str::trim) {
            let name = if let Some(ip) = entry.strip_prefix("IP Address:") {
                let ip: IpAddr = ip.parse()?;
                if ip == IpAddr::V4(old) {
                    continue;
                }
                format!("IP:{ip}")
            } else if let Some(dns) = entry.strip_prefix("DNS:") {
                ensure!(
                    !dns.is_empty()
                        && dns
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-_.*".contains(&b)),
                    "Нестандартный DNS SAN"
                );
                entry.into()
            } else {
                bail!("Нестандартный SAN. Для этого сертификата нужен ручной перевыпуск.");
            };
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    Ok(names)
}

// Return only a verified leaf. The caller publishes it together with the configuration.
pub fn issue(root: &Path, work: &Path, old: Option<Ipv4Addr>, new: Ipv4Addr) -> Result<Vec<u8>> {
    let work = work.canonicalize()?;
    let san = names(root, old, new)?.join(",");
    let ext = work.join("server.ext");
    let csr = work.join("server.csr");
    let crt = work.join("server.crt");
    fs::write(
        &ext,
        format!(
            "subjectAltName={san}\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
        ),
    )?;
    let openssl = || {
        let mut c = Command::new("openssl");
        c.current_dir(root);
        c
    };
    output(
        openssl()
            .args([
                "req",
                "-new",
                "-key",
                KEY,
                "-subj",
                "/CN=Shifr Svyaz Local",
                "-out",
            ])
            .arg(&csr),
    )
    .context("Не удалось прочитать серверный ключ")?;
    output(
        openssl()
            .args(["x509", "-req", "-in"])
            .arg(&csr)
            .args([
                "-CA",
                CA,
                "-CAkey",
                "runtime/ca/ca.key",
                "-set_serial",
                &format!("0x{}", random_hex(16)?),
                "-days",
                "365",
                "-sha256",
                "-extfile",
            ])
            .arg(&ext)
            .arg("-out")
            .arg(&crt),
    )
    .context("Не удалось подписать сертификат. Проверьте сертификат и ключ CA")?;
    for (option, value) in [
        ("-verify_ip", new.to_string()),
        ("-verify_hostname", "localhost".into()),
    ] {
        output(
            openssl()
                .args([
                    "verify",
                    "-CAfile",
                    CA,
                    "-purpose",
                    "sslserver",
                    option,
                    &value,
                ])
                .arg(&crt),
        )
        .context("Новый серверный сертификат не прошёл проверку OpenSSL")?;
    }
    Ok(fs::read(crt)?)
}
