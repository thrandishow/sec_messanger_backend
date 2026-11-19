use serde_json::{Value, json};
use shifr_broker::{read_frame, serve};
use std::time::Duration;
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::{
        TcpListener, TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    time::timeout,
};

struct Client {
    read: BufReader<OwnedReadHalf>,
    write: OwnedWriteHalf,
}
impl Client {
    async fn connect(addr: std::net::SocketAddr, nick: &str) -> Self {
        let (read, write) = TcpStream::connect(addr).await.unwrap().into_split();
        let mut c = Self {
            read: BufReader::new(read),
            write,
        };
        c.send(json!({"type":"hello","version":1,"token":"a".repeat(64),"nickname":nick}))
            .await;
        c
    }
    async fn send(&mut self, value: Value) {
        self.write
            .write_all((value.to_string() + "\n").as_bytes())
            .await
            .unwrap();
    }
    async fn next(&mut self) -> Value {
        let line = timeout(Duration::from_secs(3), read_frame(&mut self.read))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        serde_json::from_slice(&line).unwrap()
    }
    async fn event(&mut self, kind: &str) -> Value {
        for _ in 0..32 {
            let e = self.next().await;
            if e["type"] == kind {
                return e;
            }
        }
        panic!("event not found");
    }
    async fn join(&mut self, channel: &str) {
        self.send(json!({"type":"join","channel":channel})).await;
        self.event("join").await;
        self.event("names").await;
    }
}
async fn server() -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (addr, tokio::spawn(serve(listener, "a".repeat(64))))
}
fn message(id: u64, target: &str) -> Value {
    json!({"id":id,"from":"alice","target":target,"text":"Привет из Rust","time":"2026-11-19T12:00:00.000Z"})
}

#[tokio::test]
async fn authentication_duplicate_identity_and_real_health() {
    let (addr, task) = server().await;
    let mut alice = Client::connect(addr, "alice").await;
    assert_eq!(alice.next().await["type"], "ready");
    let mut duplicate = Client::connect(addr, "alice").await;
    assert_eq!(duplicate.next().await["code"], "BROKER_DUPLICATE_NICK");
    assert!(
        timeout(Duration::from_secs(2), read_frame(&mut duplicate.read))
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
    let stream = TcpStream::connect(addr).await.unwrap();
    let (read, write) = stream.into_split();
    let mut bad = Client {
        read: BufReader::new(read),
        write,
    };
    bad.send(json!({"type":"hello","version":1,"nickname":"bad","token":"b".repeat(64)}))
        .await;
    assert_eq!(bad.next().await["code"], "BROKER_AUTH_FAILED");
    let stream = TcpStream::connect(addr).await.unwrap();
    let (read, write) = stream.into_split();
    let mut health = Client {
        read: BufReader::new(read),
        write,
    };
    health
        .send(json!({"type":"health","token":"a".repeat(64)}))
        .await;
    let status = health.next().await;
    assert_eq!(status["clients"], 1);
    assert_eq!(status["version"], 1);
    task.abort();
}

#[tokio::test]
async fn prepare_is_not_delivery_commit_fanout_ordering_and_membership() {
    let (addr, task) = server().await;
    let mut a = Client::connect(addr, "alice").await;
    a.event("ready").await;
    let mut b = Client::connect(addr, "bob").await;
    b.event("ready").await;
    a.join("#team").await;
    b.join("#team").await;
    a.event("join").await;
    a.send(json!({"type":"prepare","requestId":"one","target":"#team"}))
        .await;
    assert_eq!(a.next().await["type"], "accepted");
    // A prepare must not disclose/deliver a message before PostgreSQL has committed it.
    assert!(
        timeout(Duration::from_millis(50), read_frame(&mut b.read))
            .await
            .is_err()
    );
    a.send(json!({"type":"publish","requestId":"wrong","message":message(1,"#team")}))
        .await;
    assert_eq!(a.next().await["code"], "BROKER_INVALID_COMMIT");
    a.send(json!({"type":"publish","requestId":"one","message":message(1,"#team")}))
        .await;
    assert_eq!(a.next().await, b.next().await);
    a.send(json!({"type":"publish","requestId":"one","message":message(1,"#team")}))
        .await;
    assert_eq!(a.next().await["code"], "BROKER_INVALID_COMMIT");
    for id in 2..=20 {
        let req = id.to_string();
        a.send(json!({"type":"prepare","requestId":req,"target":"#team"}))
            .await;
        a.event("accepted").await;
        a.send(json!({"type":"publish","requestId":req,"message":message(id,"#team")}))
            .await;
        assert_eq!(a.next().await["id"], id);
        assert_eq!(b.next().await["id"], id);
    }
    b.send(json!({"type":"part","channel":"#team"})).await;
    b.event("part").await;
    a.event("part").await;
    b.send(json!({"type":"prepare","requestId":"forbidden","target":"#team"}))
        .await;
    assert_eq!(b.next().await["code"], "NOT_JOINED");
    b.send(json!({"type":"names","channel":"#team"})).await;
    assert_eq!(b.next().await["code"], "NOT_JOINED");
    a.send(json!({"type":"prepare","requestId":"offline","target":"nobody"}))
        .await;
    assert_eq!(a.next().await["code"], "BROKER_RECIPIENT_OFFLINE");
    a.send(json!({"type":"prepare","requestId":"direct","target":"bob"}))
        .await;
    a.event("accepted").await;
    let mut attachment = message(21, "bob");
    attachment["attachment"] =
        json!({"id":"550e8400-e29b-41d4-a716-446655440000","name":"doc.pdf","size":1024});
    a.send(json!({"type":"publish","requestId":"direct","message":attachment}))
        .await;
    let delivered = b.next().await;
    assert_eq!(delivered["attachment"]["size"], 1024);
    assert_eq!(delivered, a.next().await);
    task.abort();
}

#[tokio::test]
async fn cancellation_disconnect_and_oversized_partial_frame_release_identity() {
    let (addr, task) = server().await;
    let mut a = Client::connect(addr, "alice").await;
    a.event("ready").await;
    let mut b = Client::connect(addr, "bob").await;
    b.event("ready").await;
    a.join("#team").await;
    b.join("#team").await;
    a.event("join").await;
    a.send(json!({"type":"prepare","requestId":"cancelled","target":"#team"}))
        .await;
    a.event("accepted").await;
    a.send(json!({"type":"cancel","requestId":"cancelled"}))
        .await;
    a.send(json!({"type":"prepare","requestId":"new","target":"#team"}))
        .await;
    assert_eq!(a.next().await["type"], "accepted");
    a.write.write_all(&vec![b'x'; 4097]).await.unwrap();
    assert_eq!(b.event("quit").await["nickname"], "alice");
    let mut reconnected = Client::connect(addr, "alice").await;
    assert_eq!(reconnected.next().await["type"], "ready");
    task.abort();
}
