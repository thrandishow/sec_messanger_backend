use std::{env, io, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    time::timeout,
};

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("Broker failed. Check bind address, token and port availability.");
        std::process::exit(1);
    }
}
async fn run() -> io::Result<()> {
    let token = env::var("BROKER_TOKEN")
        .or_else(|_| env::var("IRC_PASSWORD"))
        .map_err(|_| io::ErrorKind::InvalidInput)?;
    if !shifr_broker::valid_token(&token) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let bind: SocketAddr = env::var("BROKER_BIND")
        .unwrap_or_else(|_| "127.0.0.1:7000".into())
        .parse()
        .map_err(|_| io::ErrorKind::InvalidInput)?;
    if env::args().nth(1).as_deref() == Some("healthcheck") {
        let local = SocketAddr::new(
            if bind.is_ipv4() {
                "127.0.0.1".parse().unwrap()
            } else {
                "::1".parse().unwrap()
            },
            bind.port(),
        );
        return timeout(Duration::from_secs(2), async {
            let mut socket = TcpStream::connect(local).await?;
            let request = serde_json::json!({"type":"health","token":token}).to_string() + "\n";
            socket.write_all(request.as_bytes()).await?;
            let mut reader = BufReader::new(socket);
            let line = shifr_broker::read_frame(&mut reader)
                .await?
                .ok_or(io::ErrorKind::UnexpectedEof)?;
            let value: serde_json::Value =
                serde_json::from_slice(&line).map_err(|_| io::ErrorKind::InvalidData)?;
            if value["type"] != "health" || value["version"] != 1 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok(())
        })
        .await?;
    }
    let listener = TcpListener::bind(bind).await?;
    eprintln!(
        "Shifr broker v{} listening on {}",
        env!("CARGO_PKG_VERSION"),
        listener.local_addr()?
    );
    tokio::select! {
        result = shifr_broker::serve(listener, token) => result,
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = terminate() => Ok(()),
    }
}
#[cfg(unix)]
async fn terminate() {
    if let Ok(mut signal) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        signal.recv().await;
    }
}
#[cfg(not(unix))]
async fn terminate() {
    std::future::pending::<()>().await;
}
