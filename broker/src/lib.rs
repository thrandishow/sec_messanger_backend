//! Authenticated, ephemeral LAN message router. SQLite durability and RBAC belong to the gateway.
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc, oneshot, watch},
    time::timeout,
};

pub const MAX_FRAME: usize = 4096;
pub const MAX_CONNECTIONS: usize = 4096;
pub const MAX_ROOMS: usize = 20;
pub const MAX_MEMBERS: usize = 512;
const QUEUE_MESSAGES: usize = 128;
const QUEUE_BYTES: usize = 256 * 1024;
const HUB_QUEUE: usize = 4096;
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);

type Id = u64;
type Frame = Arc<[u8]>;
fn frame(value: Value) -> Frame {
    let mut bytes = serde_json::to_vec(&value).expect("serializable event");
    bytes.push(b'\n');
    bytes.into()
}
fn error(code: &str) -> Frame {
    frame(json!({"type":"error","code":code,"message":code}))
}
fn request_error(code: &str, request_id: &str) -> Frame {
    frame(json!({"type":"error","code":code,"message":code,"requestId":request_id}))
}
pub fn valid_nick(s: &str) -> bool {
    (3..=24).contains(&s.len())
        && s.as_bytes()[0].is_ascii_lowercase()
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}
pub fn valid_room(s: &str) -> bool {
    (2..=49).contains(&s.len())
        && s.starts_with('#')
        && s.as_bytes()[1].is_ascii_alphanumeric()
        && s[1..]
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-".contains(&c))
}
fn valid_request(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}
pub fn valid_token(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())
}

/// Bounded framing, including an unterminated line. read_line/read_until alone would allocate without a bound.
pub async fn read_frame<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> io::Result<Option<Vec<u8>>> {
    let mut result = Vec::with_capacity(256);
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if result.is_empty() {
                Ok(None)
            } else {
                Err(io::ErrorKind::UnexpectedEof.into())
            };
        }
        let end = available.iter().position(|b| *b == b'\n');
        let count = end.map_or(available.len(), |i| i + 1);
        if result.len() + count > MAX_FRAME {
            return Err(io::ErrorKind::InvalidData.into());
        }
        result.extend_from_slice(&available[..count]);
        reader.consume(count);
        if end.is_some() {
            return Ok(Some(result));
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Hello {
    Hello {
        token: String,
        nickname: String,
        version: u8,
    },
    Health {
        token: String,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Attachment {
    id: String,
    name: String,
    size: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Message {
    id: u64,
    from: String,
    target: String,
    text: String,
    time: String,
    attachment: Option<Attachment>,
}
impl Message {
    fn valid(&self) -> bool {
        self.id > 0
            && self.id <= 9_007_199_254_740_991
            && !self.text.is_empty()
            && self.text.len() <= 350
            && !self.text.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}')
            && !self.time.is_empty()
            && self.time.len() <= 40
            && self.attachment.as_ref().is_none_or(|a| {
                a.id.len() == 36
                    && a.name.chars().count() <= 180
                    && !a.name.is_empty()
                    && !a
                        .name
                        .chars()
                        .any(|c| c.is_control() || c == '/' || c == '\\')
                    && a.size > 0
                    && a.size <= 10 * 1024 * 1024
            })
    }
    fn event(&self) -> Frame {
        let mut value = json!({"type":"message","id":self.id,"from":self.from,"target":self.target,"text":self.text,"time":self.time});
        if let Some(a) = &self.attachment {
            value["attachment"] = json!({"id":a.id,"name":a.name,"size":a.size});
        }
        frame(value)
    }
}
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Join {
        channel: String,
    },
    Part {
        channel: String,
    },
    Names {
        channel: String,
    },
    Ping,
    Prepare {
        #[serde(rename = "requestId")]
        request_id: String,
        target: String,
    },
    Publish {
        #[serde(rename = "requestId")]
        request_id: String,
        message: Message,
    },
    Cancel {
        #[serde(rename = "requestId")]
        request_id: String,
    },
}
#[derive(Clone)]
struct Outbox {
    tx: mpsc::Sender<Frame>,
    bytes: Arc<AtomicUsize>,
    closed: watch::Sender<bool>,
}
impl Outbox {
    fn send(&self, data: Frame) -> bool {
        let n = data.len();
        let reserved = self
            .bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(n).filter(|v| *v <= QUEUE_BYTES)
            });
        if reserved.is_err() {
            let _ = self.closed.send(true);
            return false;
        }
        if self.tx.try_send(data).is_err() {
            self.bytes.fetch_sub(n, Ordering::Relaxed);
            let _ = self.closed.send(true);
            return false;
        }
        true
    }
}
struct Peer {
    nickname: String,
    rooms: HashSet<String>,
    out: Outbox,
    pending: Option<(String, String)>,
    last_id: u64,
}
enum Work {
    Connect {
        id: Id,
        nickname: String,
        out: Outbox,
    },
    Command(Id, Command),
    Disconnect(Id),
    Health(oneshot::Sender<usize>),
}
#[derive(Default)]
struct Hub {
    peers: HashMap<Id, Peer>,
    nicks: HashMap<String, Id>,
    rooms: HashMap<String, HashSet<Id>>,
    failed: HashSet<Id>,
}
impl Hub {
    fn send(&mut self, id: Id, data: Frame) {
        if let Some(peer) = self.peers.get(&id) {
            if !peer.out.send(data) {
                self.failed.insert(id);
            }
        }
    }
    fn broadcast(&mut self, ids: impl IntoIterator<Item = Id>, data: Frame) {
        // Serialize once, share immutable bytes for all recipients. No socket I/O in the hub.
        for id in ids {
            self.send(id, data.clone());
        }
    }
    fn members(&self, room: &str) -> Vec<Id> {
        self.rooms
            .get(room)
            .map_or_else(Vec::new, |ids| ids.iter().copied().collect())
    }
    fn names(&mut self, id: Id, channel: &str) {
        let mut members: Vec<_> = self
            .members(channel)
            .iter()
            .filter_map(|p| self.peers.get(p))
            .map(|p| json!({"nickname":p.nickname,"prefix":""}))
            .collect();
        members.sort_by(|a, b| a["nickname"].as_str().cmp(&b["nickname"].as_str()));
        self.send(
            id,
            frame(json!({"type":"names","channel":channel,"members":members})),
        );
    }
    fn disconnect(&mut self, id: Id) {
        let Some(peer) = self.peers.remove(&id) else {
            return;
        };
        self.nicks.remove(&peer.nickname);
        let _ = peer.out.closed.send(true);
        let mut recipients = HashSet::new();
        for room in &peer.rooms {
            if let Some(members) = self.rooms.get_mut(room) {
                members.remove(&id);
                recipients.extend(members.iter().copied());
                if members.is_empty() {
                    self.rooms.remove(room);
                }
            }
        }
        self.broadcast(
            recipients,
            frame(json!({"type":"quit","nickname":peer.nickname})),
        );
    }
    fn work(&mut self, work: Work) {
        match work {
            Work::Connect { id, nickname, out } => {
                if self.nicks.contains_key(&nickname) {
                    // Drop the outbox after this error: the writer flushes it and closes.
                    out.send(error("BROKER_DUPLICATE_NICK"));
                    return;
                }
                self.nicks.insert(nickname.clone(), id);
                self.peers.insert(
                    id,
                    Peer {
                        nickname: nickname.clone(),
                        rooms: HashSet::new(),
                        out,
                        pending: None,
                        last_id: 0,
                    },
                );
                self.send(id, frame(json!({"type":"ready","nickname":nickname})));
            }
            Work::Disconnect(id) => self.disconnect(id),
            Work::Health(tx) => {
                let _ = tx.send(self.peers.len());
            }
            Work::Command(id, cmd) => {
                if self.peers.contains_key(&id) {
                    self.command(id, cmd);
                }
            }
        }
        // Iterative eviction avoids recursion during a cascade of slow/disconnected subscribers.
        while !self.failed.is_empty() {
            let failed = std::mem::take(&mut self.failed);
            for id in failed {
                self.disconnect(id);
            }
        }
    }
    fn command(&mut self, id: Id, cmd: Command) {
        match cmd {
            Command::Ping => self.send(id, frame(json!({"type":"pong"}))),
            Command::Join { channel } => {
                if !valid_room(&channel) {
                    self.send(id, error("INVALID_COMMAND"));
                    return;
                }
                if self.peers[&id].rooms.contains(&channel) {
                    self.names(id, &channel);
                    return;
                }
                if self.peers[&id].rooms.len() >= MAX_ROOMS {
                    self.send(id, error("BROKER_ROOM_LIMIT"));
                    return;
                }
                if self
                    .rooms
                    .get(&channel)
                    .is_some_and(|r| r.len() >= MAX_MEMBERS)
                {
                    self.send(id, error("BROKER_ROOM_FULL"));
                    return;
                }
                self.peers
                    .get_mut(&id)
                    .unwrap()
                    .rooms
                    .insert(channel.clone());
                self.rooms.entry(channel.clone()).or_default().insert(id);
                self.broadcast(self.members(&channel), frame(json!({"type":"join","nickname":self.peers[&id].nickname,"channel":channel})));
                self.names(id, &channel);
            }
            Command::Part { channel } => {
                if !self.peers[&id].rooms.contains(&channel) {
                    self.send(id, error("NOT_JOINED"));
                    return;
                }
                self.broadcast(self.members(&channel), frame(json!({"type":"part","nickname":self.peers[&id].nickname,"channel":channel})));
                self.peers.get_mut(&id).unwrap().rooms.remove(&channel);
                let members = self.rooms.get_mut(&channel).unwrap();
                members.remove(&id);
                if members.is_empty() {
                    self.rooms.remove(&channel);
                }
            }
            Command::Names { channel } => {
                if !self.peers[&id].rooms.contains(&channel) {
                    self.send(id, error("NOT_JOINED"));
                } else {
                    self.names(id, &channel);
                }
            }
            Command::Prepare { request_id, target } => {
                if !valid_request(&request_id) || !(valid_room(&target) || valid_nick(&target)) {
                    self.send(id, request_error("INVALID_COMMAND", &request_id));
                    return;
                }
                if self.peers[&id].pending.is_some() {
                    self.send(id, request_error("MESSAGE_PENDING", &request_id));
                    return;
                }
                if target.starts_with('#') {
                    if !self.peers[&id].rooms.contains(&target) {
                        self.send(id, request_error("NOT_JOINED", &request_id));
                        return;
                    }
                } else if !self.nicks.contains_key(&target) {
                    self.send(id, request_error("BROKER_RECIPIENT_OFFLINE", &request_id));
                    return;
                }
                self.peers.get_mut(&id).unwrap().pending =
                    Some((request_id.clone(), target.clone()));
                self.send(
                    id,
                    frame(json!({"type":"accepted","requestId":request_id,"target":target})),
                );
            }
            Command::Cancel { request_id } => {
                let peer = self.peers.get_mut(&id).unwrap();
                if peer.pending.as_ref().is_some_and(|p| p.0 == request_id) {
                    peer.pending = None;
                }
            }
            Command::Publish {
                request_id,
                message,
            } => {
                let peer = self.peers.get_mut(&id).unwrap();
                if peer.pending.as_ref() != Some(&(request_id.clone(), message.target.clone()))
                    || message.from != peer.nickname
                    || !message.valid()
                    || message.id <= peer.last_id
                {
                    self.send(id, request_error("BROKER_INVALID_COMMIT", &request_id));
                    return;
                }
                peer.pending = None;
                if message.target.starts_with('#') && !peer.rooms.contains(&message.target) {
                    self.send(id, request_error("NOT_JOINED", &request_id));
                    return;
                }
                peer.last_id = message.id;
                let mut recipients = if message.target.starts_with('#') {
                    self.members(&message.target)
                } else {
                    self.nicks
                        .get(&message.target)
                        .copied()
                        .filter(|p| *p != id)
                        .into_iter()
                        .collect()
                };
                if !recipients.contains(&id) {
                    recipients.push(id);
                }
                self.broadcast(recipients, message.event());
            }
        }
    }
}

async fn connection(
    stream: TcpStream,
    id: Id,
    token: Arc<String>,
    hub: mpsc::Sender<Work>,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::with_capacity(8192, read);
    let first = timeout(Duration::from_secs(5), read_frame(&mut read))
        .await??
        .ok_or(io::ErrorKind::UnexpectedEof)?;
    let hello: Hello = serde_json::from_slice(&first).map_err(|_| io::ErrorKind::InvalidData)?;
    let supplied = match &hello {
        Hello::Hello { token, .. } | Hello::Health { token } => token,
    };
    if supplied.len() != 64 || !bool::from(supplied.as_bytes().ct_eq(token.as_bytes())) {
        timeout(WRITE_TIMEOUT, write.write_all(&error("BROKER_AUTH_FAILED"))).await??;
        return Ok(());
    }
    let nickname = match hello {
        Hello::Health { .. } => {
            let (tx, rx) = oneshot::channel();
            hub.send(Work::Health(tx))
                .await
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            let clients = timeout(Duration::from_secs(2), rx)
                .await?
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            timeout(
                WRITE_TIMEOUT,
                write.write_all(&frame(
                    json!({"type":"health","version":1,"clients":clients}),
                )),
            )
            .await??;
            return Ok(());
        }
        Hello::Hello {
            nickname, version, ..
        } => {
            if version != 1 || !valid_nick(&nickname) {
                timeout(WRITE_TIMEOUT, write.write_all(&error("BROKER_PROTOCOL"))).await??;
                return Ok(());
            }
            nickname
        }
    };
    let (tx, mut rx) = mpsc::channel::<Frame>(QUEUE_MESSAGES);
    let bytes = Arc::new(AtomicUsize::new(0));
    let (closed, mut closed_rx) = watch::channel(false);
    hub.send(Work::Connect {
        id,
        nickname,
        out: Outbox {
            tx,
            bytes: bytes.clone(),
            closed,
        },
    })
    .await
    .map_err(|_| io::ErrorKind::BrokenPipe)?;
    let reading = async {
        loop {
            let Some(line) = timeout(IDLE_TIMEOUT, read_frame(&mut read)).await?? else {
                return Ok::<_, io::Error>(());
            };
            let command =
                serde_json::from_slice::<Command>(&line).map_err(|_| io::ErrorKind::InvalidData)?;
            hub.send(Work::Command(id, command))
                .await
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
        }
    };
    let writing = async {
        while let Some(data) = rx.recv().await {
            timeout(WRITE_TIMEOUT, write.write_all(&data)).await??;
            bytes.fetch_sub(data.len(), Ordering::Relaxed);
        }
        Ok::<_, io::Error>(())
    };
    tokio::select! {
        _ = reading => {},
        _ = writing => {},
        _ = async { if closed_rx.changed().await.is_ok() { /* eviction */ } else { std::future::pending::<()>().await; } } => {},
    }
    hub.send(Work::Disconnect(id))
        .await
        .map_err(|_| io::ErrorKind::BrokenPipe)?;
    Ok(())
}

pub async fn serve(listener: TcpListener, token: String) -> io::Result<()> {
    if !valid_token(&token) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let token = Arc::new(token);
    let (tx, mut rx) = mpsc::channel(HUB_QUEUE);
    let hub_task = tokio::spawn(async move {
        let mut hub = Hub::default();
        while let Some(work) = rx.recv().await {
            hub.work(work);
        }
    });
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut next_id = 0u64;
    loop {
        let (stream, _) = listener.accept().await?;
        if hub_task.is_finished() {
            return Err(io::Error::other("router task stopped"));
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        next_id = next_id.checked_add(1).ok_or(io::ErrorKind::Other)?;
        let hub = tx.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let _permit = permit;
            // Never log frames, tokens or message content.
            let _ = connection(stream, next_id, token, hub).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn fragmented_frames_and_unterminated_overflow() {
        let mut r = BufReader::with_capacity(2, &b"{\"a\":1}\n{}\n"[..]);
        assert_eq!(read_frame(&mut r).await.unwrap().unwrap(), b"{\"a\":1}\n");
        assert_eq!(read_frame(&mut r).await.unwrap().unwrap(), b"{}\n");
        assert!(read_frame(&mut r).await.unwrap().is_none());
        let huge = vec![b'x'; MAX_FRAME + 1];
        assert!(
            read_frame(&mut BufReader::new(huge.as_slice()))
                .await
                .is_err()
        );
    }
    #[test]
    fn slow_subscriber_is_evicted_without_blocking_healthy_peer() {
        let mut hub = Hub::default();
        let mut readers = Vec::new();
        for (id, nick) in [(1, "alice"), (2, "bob")] {
            let (tx, rx) = mpsc::channel(if id == 1 { 1 } else { 128 });
            let (closed, _) = watch::channel(false);
            hub.work(Work::Connect {
                id,
                nickname: nick.into(),
                out: Outbox {
                    tx,
                    bytes: Arc::new(AtomicUsize::new(0)),
                    closed,
                },
            });
            readers.push(rx);
        }
        hub.work(Work::Command(1, Command::Ping)); // alice's ready occupies the only slot
        assert!(!hub.peers.contains_key(&1));
        hub.work(Work::Command(2, Command::Ping));
        assert!(hub.peers.contains_key(&2));
        assert_eq!(readers[1].len(), 2);
    }
    #[test]
    fn queue_byte_limit_and_input_validation() {
        let (tx, _rx) = mpsc::channel(128);
        let (closed, _watch) = watch::channel(false);
        let out = Outbox {
            tx,
            bytes: Arc::new(AtomicUsize::new(0)),
            closed,
        };
        assert!(!out.send(vec![0; QUEUE_BYTES + 1].into()));
        assert!(valid_nick("alice_12"));
        assert!(!valid_nick("Alice"));
        assert!(!valid_room("#room\n"));
        assert!(valid_room("#room-1"));
    }
}
