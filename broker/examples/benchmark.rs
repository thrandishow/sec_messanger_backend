//! Separate broker process, real loopback TCP, prepare + publish + sender echo.
//! Each group has one publisher and N subscribers; all deliveries are checked.
use serde_json::{Value, json};
use shifr_broker::read_frame;
use std::{
    env, io,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::Barrier,
    time::timeout,
};

struct Broker(Child);
impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Client(BufReader<TcpStream>);
impl Client {
    async fn send(&mut self, value: Value) {
        self.0
            .get_mut()
            .write_all((value.to_string() + "\n").as_bytes())
            .await
            .unwrap();
    }
    async fn event(&mut self, kind: &str) -> Value {
        loop {
            let line = timeout(Duration::from_secs(15), read_frame(&mut self.0))
                .await
                .expect("broker timeout")
                .unwrap()
                .expect("connection closed");
            let event: Value = serde_json::from_slice(&line).unwrap();
            assert_ne!(event["type"], "error", "{event}");
            if event["type"] == kind {
                return event;
            }
        }
    }
    async fn connect(addr: std::net::SocketAddr, nick: &str, room: &str, token: &str) -> Self {
        let stream = TcpStream::connect(addr).await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut c = Self(BufReader::new(stream));
        c.send(json!({"type":"hello","version":1,"nickname":nick,"token":token}))
            .await;
        c.event("ready").await;
        c.send(json!({"type":"join","channel":room})).await;
        c.event("names").await;
        c
    }
}

#[tokio::main(worker_threads = 4)]
async fn main() -> io::Result<()> {
    let args: Vec<_> = env::args().collect();
    let groups: usize = args.get(1).map_or(4, |s| s.parse().expect("groups"));
    let subscribers: usize = args.get(2).map_or(8, |s| s.parse().expect("subscribers"));
    let messages: usize = args.get(3).map_or(5000, |s| s.parse().expect("messages"));
    assert!(
        (1..=32).contains(&groups)
            && (1..=64).contains(&subscribers)
            && (1..=100_000).contains(&messages)
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    drop(listener);
    // Isolated synthetic data only. Never reads the deployment's .env or keys.
    let token = "a".repeat(64);
    let binary = env::var("BROKER_BINARY")
        .expect("Set BROKER_BINARY to the release shifr-broker executable");
    let _broker = Broker(
        Command::new(binary)
            .env("BROKER_BIND", addr.to_string())
            .env("BROKER_TOKEN", &token)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    timeout(Duration::from_secs(10), async {
        loop {
            if TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    let mut clients = Vec::new();
    for group in 0..groups {
        let room = format!("#bench{group}");
        let nick = format!("pub{group}");
        let publisher = Client::connect(addr, &nick, &room, &token).await;
        let mut readers = Vec::new();
        for sub in 0..subscribers {
            readers.push(Client::connect(addr, &format!("sub{group}_{sub}"), &room, &token).await);
        }
        clients.push((publisher, readers, nick, room));
    }
    let barrier = Arc::new(Barrier::new(groups * (subscribers + 1) + 1));
    let epoch = Instant::now();
    let mut tasks = Vec::new();
    for (mut publisher, readers, nick, room) in clients {
        for mut client in readers {
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                let mut latencies = Vec::with_capacity(messages);
                for expected in 1..=messages {
                    let e = client.event("message").await;
                    assert_eq!(e["id"], expected, "lost, duplicated or reordered message");
                    let payload = e["text"].as_str().unwrap();
                    assert_eq!(payload.len(), 128);
                    let sent: u128 = payload[..20].parse().unwrap();
                    latencies.push((epoch.elapsed().as_nanos() - sent) as u64);
                }
                latencies
            }));
        }
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            for id in 1..=messages {
                let sent = epoch.elapsed().as_nanos(); let request = id.to_string();
                publisher.send(json!({"type":"prepare","requestId":request,"target":room})).await;
                assert_eq!(publisher.event("accepted").await["requestId"], request);
                let text = format!("{sent:020}{}", "x".repeat(108));
                publisher.send(json!({"type":"publish","requestId":request,"message":{
                    "id":id,"from":nick,"target":room,"text":text,"time":"2026-11-19T12:00:00.000Z"}})).await;
                assert_eq!(publisher.event("message").await["id"], id);
            }
            Vec::new()
        }));
    }
    let started = Instant::now();
    barrier.wait().await;
    let mut latencies = Vec::new();
    for task in tasks {
        latencies.extend(task.await.unwrap());
    }
    let elapsed = started.elapsed().as_secs_f64();
    latencies.sort_unstable();
    let percentile = |p: usize| latencies[(latencies.len() - 1) * p / 100] as f64 / 1e6;
    println!(
        "{}",
        json!({"groups":groups,"subscribersPerGroup":subscribers,"clients":groups*(subscribers+1),
        "payloadBytes":128,"messages":groups*messages,"verifiedDeliveries":latencies.len(),"seconds":elapsed,
        "messagesPerSecond":(groups*messages) as f64/elapsed,"deliveriesPerSecond":latencies.len() as f64/elapsed,
        "latencyMs":{"p50":percentile(50),"p95":percentile(95),"p99":percentile(99)},
        "includes":"prepare + publish + TCP delivery; excludes SQLite, TLS, API and browser"})
    );
    Ok(())
}
