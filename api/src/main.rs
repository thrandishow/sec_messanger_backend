mod auth;
mod db;
mod http;
mod legacy;
mod ws;
use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;
use std::{
    collections::HashMap,
    env,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{Semaphore, watch};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub u16, pub &'static str);
impl Error {
    const INTERNAL: Self = Self(500, "INTERNAL_ERROR");
    const INPUT: Self = Self(400, "INVALID_INPUT");
    const AUTH: Self = Self(401, "UNAUTHORIZED");
    const DENIED: Self = Self(403, "FORBIDDEN");
    const MISSING: Self = Self(404, "NOT_FOUND");
}
impl From<postgres::Error> for Error {
    fn from(_: postgres::Error) -> Self {
        Self::INTERNAL
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (
            StatusCode::from_u16(self.0).unwrap(),
            Json(json!({"error":self.1})),
        )
            .into_response()
    }
}
type Result<T> = std::result::Result<T, Error>;
type App = Arc<Service>;
pub struct Service {
    db: db::Store,
    cfg: Config,
    slots: Arc<Semaphore>,
    active: Mutex<HashMap<String, Connection>>,
    rates: Mutex<Rates>,
}
struct Connection {
    hash: String,
    generation: uuid::Uuid,
    stop: watch::Sender<bool>,
}
struct Rates {
    windows: HashMap<(IpAddr, u8), (Instant, u32)>,
    swept: Instant,
}
struct Config {
    addr: SocketAddr,
    origins: Vec<String>,
    cert: Option<String>,
    key: Option<String>,
    proxy: bool,
    ttl: i64,
    broker: String,
    token: String,
}
fn var(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.into())
}
fn local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_loopback() || v.is_private() || v.is_link_local(),
        IpAddr::V6(v) => v.to_ipv4_mapped().map_or(
            v.is_loopback() || v.is_unique_local() || v.is_unicast_link_local(),
            |v| local(v.into()),
        ),
    }
}
impl Config {
    fn load() -> Result<Self> {
        let ip: IpAddr = var("HOST", "127.0.0.1").parse().map_err(|_| Error::INPUT)?;
        let port = var("PORT", "8443")
            .parse::<u16>()
            .ok()
            .filter(|p| *p > 0)
            .ok_or(Error::INPUT)?;
        let cert = env::var("TLS_CERT_PATH").ok().filter(|s| !s.is_empty());
        let key = env::var("TLS_KEY_PATH").ok().filter(|s| !s.is_empty());
        if (!local(ip) && ip != "0.0.0.0".parse::<IpAddr>().unwrap())
            || cert.is_some() != key.is_some()
            || (!ip.is_loopback() && cert.is_none())
        {
            return Err(Error::INPUT);
        }
        let origins = var("ALLOWED_ORIGINS", "")
            .split(',')
            .map(|s| s.trim().to_owned())
            .collect::<Vec<_>>();
        for o in &origins {
            let uri = o.parse::<Uri>().map_err(|_| Error::INPUT)?;
            let a = uri.authority().ok_or(Error::INPUT)?;
            let host = a.host().trim_matches(['[', ']']);
            let addr = host.parse::<IpAddr>().ok();
            if !matches!(uri.scheme_str(), Some("https" | "http"))
                || (cert.is_some() && uri.scheme_str() != Some("https"))
                || *o != format!("{}://{}", uri.scheme_str().unwrap(), a)
                || a.as_str().contains('@')
                || (host != "localhost"
                    && !addr.is_some_and(|ip| local(ip) && (cert.is_some() || ip.is_loopback())))
            {
                return Err(Error::INPUT);
            }
        }
        let ttl = var("SESSION_TTL_SECONDS", "86400")
            .parse()
            .ok()
            .filter(|n| (60..=604800).contains(n))
            .ok_or(Error::INPUT)?;
        let token = env::var("BROKER_TOKEN")
            .or_else(|_| env::var("IRC_PASSWORD"))
            .map_err(|_| Error::INPUT)?;
        if !shifr_broker::valid_token(&token) {
            return Err(Error::INPUT);
        }
        let broker_port = var("BROKER_PORT", "7000")
            .parse::<u16>()
            .ok()
            .filter(|p| *p > 0)
            .ok_or(Error::INPUT)?;
        let broker_host = var("BROKER_HOST", "127.0.0.1");
        let broker = if broker_host.contains(':') && !broker_host.starts_with('[') {
            format!("[{broker_host}]:{broker_port}")
        } else {
            format!("{broker_host}:{broker_port}")
        };
        let proxy = match var("TRUST_PROXY", "0").as_str() {
            "1" => true,
            "0" => false,
            _ => return Err(Error::INPUT),
        };
        Ok(Self {
            addr: SocketAddr::new(ip, port),
            cert,
            key,
            origins,
            ttl,
            token,
            broker,
            proxy,
        })
    }
}
fn cookie_hash(h: &HeaderMap) -> Result<String> {
    let token = h
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.split(';')
                .find_map(|v| v.trim().strip_prefix("shifr_session="))
        })
        .filter(|s| shifr_broker::valid_token(s))
        .ok_or(Error::AUTH)?;
    Ok(hex::encode(openssl::sha::sha256(token.as_bytes())))
}
fn target(s: &str) -> Result<String> {
    if shifr_broker::valid_room(s) || shifr_broker::valid_nick(&s.to_ascii_lowercase()) {
        Ok(s.to_ascii_lowercase())
    } else {
        Err(Error::INPUT)
    }
}
fn identity(store: &mut impl postgres::GenericClient, hash: &str) -> Result<db::User> {
    db::session(store, hash).map(|s| s.0)
}
#[derive(Clone)]
struct ClientIp(String);
fn limit(app: &Service, ip: IpAddr, path: &str) -> bool {
    let now = Instant::now();
    let mut rates = app.rates.lock().unwrap();
    if rates.swept.elapsed().as_secs() >= 60 {
        rates.windows.retain(|_, (t, _)| t.elapsed().as_secs() < 60);
        rates.swept = now;
    }
    let class = match path {
        "/api/auth/login" => 1,
        "/api/files" => 2,
        _ => 0,
    };
    for (key, max) in [(0, 120), (class, 10)] {
        let (start, n) = rates.windows.entry((ip, key)).or_insert((now, 0));
        if start.elapsed().as_secs() >= 60 {
            *start = now;
            *n = 0
        }
        if *n >= max {
            return false;
        }
        *n += 1;
        if class == 0 {
            break;
        }
    }
    true
}
async fn guard(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut req: Request,
    next: Next,
) -> Response {
    let ip = if app.cfg.proxy && local(peer.ip()) && req.headers().contains_key("x-forwarded-for") {
        req.headers()["x-forwarded-for"]
            .to_str()
            .ok()
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
    } else {
        Some(peer.ip())
    };
    let origin = req.headers().get("origin").cloned();
    let allowed = origin
        .as_ref()
        .is_some_and(|o| app.cfg.origins.iter().any(|s| o.as_bytes() == s.as_bytes()));
    let needs_origin =
        !matches!(*req.method(), Method::GET | Method::HEAD) || req.uri().path() == "/ws";
    let mut response = if !ip.is_some_and(local) {
        Error(403, "LAN_ONLY").into_response()
    } else if (origin.is_some() || needs_origin) && !allowed {
        Error(403, "ORIGIN_DENIED").into_response()
    } else if !limit(&app, ip.unwrap(), req.uri().path()) {
        let mut r = Error(429, "RATE_LIMIT").into_response();
        r.headers_mut()
            .insert("retry-after", HeaderValue::from_static("60"));
        r
    } else if req.method() == Method::OPTIONS {
        StatusCode::NO_CONTENT.into_response()
    } else {
        req.extensions_mut()
            .insert(ClientIp(ip.unwrap().to_string()));
        let r = next.run(req).await;
        if r.status().is_client_error()
            && r.headers()
                .get("content-type")
                .is_none_or(|v| v != "application/json")
        {
            Error(
                if r.status().as_u16() == 422 {
                    400
                } else {
                    r.status().as_u16()
                },
                "INVALID_REQUEST",
            )
            .into_response()
        } else {
            r
        }
    };
    let h = response.headers_mut();
    h.insert("cache-control", HeaderValue::from_static("no-store"));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    if let Some(o) = origin.filter(|_| allowed) {
        h.insert("access-control-allow-origin", o);
        h.insert(
            "access-control-allow-credentials",
            HeaderValue::from_static("true"),
        );
        h.insert(
            "access-control-allow-methods",
            HeaderValue::from_static("GET, POST"),
        );
        h.insert(
            "access-control-allow-headers",
            HeaderValue::from_static("content-type"),
        );
        h.insert("vary", HeaderValue::from_static("Origin"));
    }
    response
}
struct Input<T>(T);
impl<T: serde::de::DeserializeOwned + Send, S: Send + Sync> axum::extract::FromRequest<S>
    for Input<T>
{
    type Rejection = Error;
    async fn from_request(req: Request, state: &S) -> Result<Self> {
        use axum::extract::rejection::JsonRejection;
        let parsed =
            tokio::time::timeout(Duration::from_secs(10), Json::<T>::from_request(req, state))
                .await
                .map_err(|_| Error(408, "INVALID_REQUEST"))?;
        parsed.map(|Json(body)| Self(body)).map_err(|e| match e {
            JsonRejection::JsonDataError(_) => Error::INPUT,
            _ => Error(e.status().as_u16(), "INVALID_REQUEST"),
        })
    }
}
fn routes(app: App) -> Router {
    Router::new()
        .route("/health/live", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/health/ready", get(ws::ready))
        .route("/ws", get(ws::upgrade))
        .route("/api/config", get(|| async { Json(json!({
            "name":"Шифр-связь", "protocolVersion":2, "broker":"shifr-rust", "registration":"admin",
            "messageMaxBytes":350, "history":true, "fileMaxBytes":http::FILE_LIMIT,
            "endToEndEncryption":false
        })) }))
        .route("/api/auth/register", post(|| async { Error(403,"REGISTRATION_CLOSED") }))
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/me", get(auth::me))
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/chat/status", get(auth::status))
        .route("/api/directory", get(http::directory))
        .route("/api/history", get(http::history))
        .route("/api/admin/users", get(http::users).post(auth::create_user))
        .route("/api/admin/users/{id}", post(auth::update_user))
        .route("/api/admin/departments", post(http::department))
        .route("/api/admin/audit", get(http::audit))
        .route("/api/resources", get(http::resources))
        .route("/api/resources/{id}/delete", post(http::delete_resource))
        .route("/api/files/{id}", get(http::download))
        .layer(DefaultBodyLimit::max(4096))
        .route("/api/files", post(http::upload))
        .layer(middleware::from_fn_with_state(app.clone(),guard))
        .with_state(app)
}
fn healthcheck(cfg: &Config) -> Result<()> {
    use openssl::ssl::{SslConnector, SslMethod};
    use std::io::{BufRead, BufReader, Read, Write};
    let addr = SocketAddr::new(
        if cfg.addr.ip().is_unspecified() {
            "127.0.0.1".parse().unwrap()
        } else {
            cfg.addr.ip()
        },
        cfg.addr.port(),
    );
    let failed = Error(503, "UNAVAILABLE");
    let socket =
        std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(1)).map_err(|_| failed)?;
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| failed)?;
    socket
        .set_write_timeout(Some(Duration::from_secs(1)))
        .map_err(|_| failed)?;
    trait Stream: Read + Write {}
    impl<T: Read + Write> Stream for T {}
    let mut stream: Box<dyn Stream> = if let Some(cert) = &cfg.cert {
        let mut builder = SslConnector::builder(SslMethod::tls_client()).map_err(|_| failed)?;
        builder
            .set_ca_file(std::path::Path::new(cert).with_file_name("ca.crt"))
            .map_err(|_| failed)?;
        Box::new(
            builder
                .build()
                .connect("localhost", socket)
                .map_err(|_| failed)?,
        )
    } else {
        Box::new(socket)
    };
    stream
        .write_all(b"GET /health/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .map_err(|_| failed)?;
    let mut status = String::new();
    BufReader::new(stream.take(128))
        .read_line(&mut status)
        .map_err(|_| failed)?;
    if status.starts_with("HTTP/1.1 200 ") {
        Ok(())
    } else {
        Err(failed)
    }
}
#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("shifr-api: {}", err.1);
        std::process::exit(1)
    }
}
async fn run() -> Result<()> {
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
    }

    if env::args().nth(1).as_deref() == Some("migrate") {
        return tokio::task::spawn_blocking(|| {
            db::initialize(&mut db::config()?.connect(postgres::NoTls)?)
        })
        .await
        .map_err(|_| Error::INTERNAL)?;
    }
    if env::args().nth(1).as_deref() == Some("admin") {
        return tokio::task::spawn_blocking(auth::bootstrap)
            .await
            .map_err(|_| Error::INTERNAL)?;
    }
    let cfg = Config::load()?;
    if env::args().nth(1).as_deref() == Some("healthcheck") {
        return healthcheck(&cfg);
    }
    let addr = cfg.addr;
    let tls = match (&cfg.cert, &cfg.key) {
        (Some(cert), Some(key)) => Some(
            axum_server::tls_openssl::OpenSSLConfig::from_pem_file(cert, key)
                .map_err(|_| Error(500, "INVALID_TLS"))?,
        ),
        _ => None,
    };
    let pool = tokio::task::spawn_blocking(db::Store::open)
        .await
        .map_err(|_| Error::INTERNAL)??;
    let app = Arc::new(Service {
        cfg,
        db: pool.clone(),
        slots: Arc::new(Semaphore::new(4)),
        active: Mutex::default(),
        rates: Mutex::new(Rates {
            windows: HashMap::new(),
            swept: Instant::now(),
        }),
    });
    let service = routes(app).into_make_service_with_connect_info::<SocketAddr>();
    let handle = axum_server::Handle::new();
    let shutdown = handle.clone();
    tokio::spawn(async move {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM");
        tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
        shutdown.graceful_shutdown(Some(Duration::from_secs(3)));
    });
    let result = match tls {
        Some(tls) => {
            axum_server::bind_openssl(addr, tls)
                .handle(handle)
                .serve(service)
                .await
        }
        None => axum_server::bind(addr).handle(handle).serve(service).await,
    }
    .map_err(|_| Error(500, "LISTENER_FAILED"));
    tokio::task::spawn_blocking(move || drop(pool))
        .await
        .map_err(|_| Error::INTERNAL)?;
    result
}
