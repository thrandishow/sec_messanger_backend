use crate::{db, *};
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;
use tokio::{
    net::TcpStream,
    time::{Instant as Clock, timeout},
};
use tokio_util::codec::{Framed, LinesCodec};

type Broker = Framed<TcpStream, LinesCodec>;
const LOST: Error = Error(503, "BROKER_DISCONNECTED");
async fn connect(cfg: &Config) -> Result<Broker> {
    let stream = TcpStream::connect(&cfg.broker)
        .await
        .map_err(|_| Error(503, "BROKER_UNAVAILABLE"))?;
    stream.set_nodelay(true).map_err(|_| LOST)?;
    // A names event may contain all 512 room members.
    Ok(Framed::new(
        stream,
        LinesCodec::new_with_max_length(64 * 1024),
    ))
}
async fn write(b: &mut Broker, v: Value) -> Result<()> {
    let s = v.to_string();
    if s.len() + 1 > shifr_broker::MAX_FRAME {
        return Err(Error(500, "BROKER_PROTOCOL"));
    }
    timeout(Duration::from_secs(5), b.send(s))
        .await
        .map_err(|_| LOST)?
        .map_err(|_| LOST)
}
async fn read(b: &mut Broker) -> Result<Value> {
    let line = b.next().await.ok_or(LOST)?.map_err(|_| LOST)?;
    serde_json::from_str(&line).map_err(|_| Error(500, "BROKER_PROTOCOL"))
}
pub async fn ready(State(app): State<App>) -> Response {
    let probe = async {
        let mut b = connect(&app.cfg).await?;
        write(&mut b, json!({"type":"health","token":app.cfg.token})).await?;
        let r = read(&mut b).await?;
        Ok::<_, Error>(r["type"] == "health" && r["version"] == 1)
    };
    let broker_ok = matches!(
        timeout(Duration::from_millis(1500), probe).await,
        Ok(Ok(true))
    );
    let db_ok = matches!(
        timeout(
            Duration::from_secs(1),
            app.db.run(|db| Ok(db.simple_query("SELECT 1").is_ok()))
        )
        .await,
        Ok(Ok(true))
    );
    let ok = broker_ok && db_ok;
    (
        if ok {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(json!({"status":if ok{"ok"}else{"unavailable"},"broker":broker_ok})),
    )
        .into_response()
}
struct Registration {
    app: App,
    id: String,
    generation: uuid::Uuid,
}
impl Drop for Registration {
    fn drop(&mut self) {
        let mut map = self.app.active.lock().unwrap();
        if map
            .get(&self.id)
            .is_some_and(|c| c.generation == self.generation)
        {
            map.remove(&self.id);
        }
    }
}
pub async fn upgrade(
    State(app): State<App>,
    h: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response> {
    let hash = cookie_hash(&h)?;
    let check = hash.clone();
    let (user, expiry) = app.db.run(move |db| db::session(db, &check)).await?;
    let (stop, mut cancel) = watch::channel(false);
    let id = user.id.clone();
    let generation = uuid::Uuid::new_v4();
    {
        let mut map = app.active.lock().unwrap();
        if map.contains_key(&id) {
            return Err(Error(409, "ALREADY_CONNECTED"));
        }
        map.insert(
            id.clone(),
            Connection {
                generation,
                hash: hash.clone(),
                stop,
            },
        );
    }
    let registration = Registration {
        app: app.clone(),
        id,
        generation,
    };
    Ok(ws.max_frame_size(4096).max_message_size(4096).write_buffer_size(0).max_write_buffer_size(65536)
        .on_upgrade(move|mut socket|async move{
            let _registration=registration;
            let err=tokio::select!{_=cancel.changed()=>None,_=tokio::time::sleep(Duration::from_millis((expiry-db::now()).max(0) as u64))=>None,r=chat(&app,&hash,&user.nickname,&mut socket)=>r.err()};
            if let Some(e)=err{let _=send_error(&mut socket,e.1).await;}
            let code=match err{Some(Error(429,_))=>1008,Some(Error(400,_))=>1003,Some(_)=>1011,None=>1000};
            let _=timeout(Duration::from_millis(250),socket.send(Message::Close(Some(CloseFrame{code,reason:"".into()})))).await;
        }))
}
async fn send(ws: &mut WebSocket, m: Message) -> Result<()> {
    timeout(Duration::from_secs(5), ws.send(m))
        .await
        .map_err(|_| LOST)?
        .map_err(|_| LOST)
}
async fn event(ws: &mut WebSocket, v: &Value) -> Result<()> {
    send(ws, Message::Text(v.to_string().into())).await
}
async fn send_error(ws: &mut WebSocket, code: &str) -> Result<()> {
    event(ws, &json!({"type":"error","code":code,"message":code})).await
}
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum Command {
    Ping {},
    Join {
        channel: String,
    },
    Part {
        channel: String,
    },
    Names {
        channel: String,
    },
    Message {
        target: String,
        text: String,
        #[serde(rename = "attachmentId")]
        attachment: Option<String>,
    },
}
struct Pending {
    id: String,
    target: String,
    text: String,
    file: Option<String>,
    saved: Option<i64>,
    deadline: Clock,
}
struct Chat<'a> {
    app: &'a Service,
    hash: &'a str,
    nick: &'a str,
    rooms: HashSet<String>,
    pending: Option<Pending>,
}
impl Chat<'_> {
    async fn command(&mut self, b: &mut Broker, ws: &mut WebSocket, s: &str) -> Result<()> {
        let Ok(value) = serde_json::from_str::<Value>(s) else {
            return send_error(ws, "INVALID_JSON").await;
        };
        let Ok(cmd) = serde_json::from_value::<Command>(value) else {
            return send_error(ws, "INVALID_COMMAND").await;
        };
        let hash = self.hash.to_owned();
        if !matches!(cmd, Command::Ping {}) && self.pending.is_some() {
            return send_error(ws, "MESSAGE_PENDING").await;
        }
        match cmd {
            Command::Ping {} => {
                self.app.db.run(move |db| identity(db, &hash)).await?;
                write(b, json!({"type":"ping"})).await
            }
            Command::Message {
                target: t,
                text,
                attachment,
            } => {
                let Ok(t) = target(&t) else {
                    return send_error(ws, "INVALID_COMMAND").await;
                };
                if text.is_empty()
                    || text.len() > 350
                    || text.bytes().any(|b| b < 32 || b == 127)
                    || attachment
                        .as_ref()
                        .is_some_and(|s| uuid::Uuid::parse_str(s).is_err())
                {
                    return send_error(ws, "INVALID_COMMAND").await;
                }
                let dest = t.clone();
                let file = attachment.clone();
                let allowed = self
                    .app
                    .db
                    .run(move |db| {
                        let u = identity(db, &hash)?;
                        Ok(db::can_write(db, &u, &dest)?
                            && match file {
                                Some(f) => db::attachment_allowed(db, &u, &dest, &f)?,
                                None => true,
                            })
                    })
                    .await?;
                if !allowed {
                    return send_error(ws, "FORBIDDEN").await;
                }
                if t.starts_with('#') && !self.rooms.contains(&t) {
                    return send_error(ws, "NOT_JOINED").await;
                }
                let id = uuid::Uuid::new_v4().to_string();
                write(b, json!({"type":"prepare","requestId":id,"target":t})).await?;
                self.pending = Some(Pending {
                    id,
                    target: t,
                    text,
                    file: attachment,
                    saved: None,
                    deadline: Clock::now() + Duration::from_secs(10),
                });
                Ok(())
            }
            room_cmd => {
                let (kind, room) = match room_cmd {
                    Command::Join { channel } => ("join", channel),
                    Command::Part { channel } => ("part", channel),
                    Command::Names { channel } => ("names", channel),
                    _ => unreachable!(),
                };
                if !shifr_broker::valid_room(&room) {
                    return send_error(ws, "INVALID_COMMAND").await;
                }
                let dest = room.clone();
                let allowed = self
                    .app
                    .db
                    .run(move |db| {
                        let user = identity(db, &hash)?;
                        db::can_read(db, &user, &dest)
                    })
                    .await?;
                if !allowed {
                    return send_error(ws, "FORBIDDEN").await;
                }
                write(b, json!({"type":kind,"channel":room})).await
            }
        }
    }
    async fn incoming(&mut self, b: &mut Broker, ws: &mut WebSocket, mut v: Value) -> Result<()> {
        let kind = v["type"].as_str().ok_or(LOST)?;
        match kind {
            "accepted" => {
                let Some(p) = self.pending.as_mut().filter(|p| {
                    v["requestId"] == p.id && v["target"] == p.target && p.saved.is_none()
                }) else {
                    return Err(LOST);
                };
                let hash = self.hash.to_owned();
                let t = p.target.clone();
                let text = p.text.clone();
                let file = p.file.clone();
                match self
                    .app
                    .db
                    .run(move |db| db::save_message(db, &hash, &t, &text, file.as_deref()))
                    .await
                {
                    Ok(msg) => {
                        p.saved = msg["id"].as_i64();
                        write(b, json!({"type":"publish","requestId":p.id,"message":msg})).await
                    }
                    Err(e) => {
                        write(b, json!({"type":"cancel","requestId":p.id})).await?;
                        self.pending = None;
                        send_error(
                            ws,
                            if e == Error::INTERNAL {
                                "STORAGE_ERROR"
                            } else {
                                e.1
                            },
                        )
                        .await
                    }
                }
            }
            "message" => {
                let t = v["target"].as_str().ok_or(LOST)?;
                let sender = v["from"].as_str().ok_or(LOST)?;
                if t.starts_with('#') && !self.rooms.contains(t)
                    || !t.starts_with('#') && sender != self.nick && t != self.nick
                {
                    return Ok(());
                }
                let dest = if !t.starts_with('#') && sender != self.nick {
                    sender
                } else {
                    t
                }
                .to_owned();
                let hash = self.hash.to_owned();
                if !self
                    .app
                    .db
                    .run(move |db| {
                        let user = identity(db, &hash)?;
                        db::can_read(db, &user, &dest)
                    })
                    .await?
                {
                    return Ok(());
                }
                if sender == self.nick
                    && self
                        .pending
                        .as_ref()
                        .is_some_and(|p| p.saved.is_some() && p.saved == v["id"].as_i64())
                {
                    self.pending = None
                }
                event(ws, &v).await
            }
            "error" => {
                if self
                    .pending
                    .as_ref()
                    .is_some_and(|p| v["requestId"] == p.id)
                {
                    let p = self.pending.take().unwrap();
                    write(b, json!({"type":"cancel","requestId":p.id})).await?;
                }
                v.as_object_mut().unwrap().remove("requestId");
                event(ws, &v).await
            }
            "join" | "part" => {
                if v["nickname"] == self.nick {
                    let room = v["channel"].as_str().ok_or(LOST)?;
                    if kind == "join" {
                        self.rooms.insert(room.into());
                    } else {
                        self.rooms.remove(room);
                    }
                }
                event(ws, &v).await
            }
            "names" | "quit" | "pong" => event(ws, &v).await,
            _ => Err(LOST),
        }
    }
}
async fn chat(app: &Service, hash: &str, nick: &str, ws: &mut WebSocket) -> Result<()> {
    let handshake = async {
        let mut b = connect(&app.cfg).await?;
        write(
            &mut b,
            json!({"type":"hello","version":1,"nickname":nick,"token":app.cfg.token}),
        )
        .await?;
        let first = read(&mut b).await?;
        if first["type"] != "ready" || first["nickname"] != nick {
            return Err(Error(
                503,
                match first["code"].as_str() {
                    Some("BROKER_DUPLICATE_NICK") => "BROKER_DUPLICATE_NICK",
                    Some("BROKER_AUTH_FAILED") => "BROKER_AUTH_FAILED",
                    _ => "BROKER_PROTOCOL",
                },
            ));
        }
        Ok((b, first))
    };
    let (mut b, first) = timeout(Duration::from_secs(5), handshake)
        .await
        .map_err(|_| Error(503, "BROKER_TIMEOUT"))??;
    let check = hash.to_owned();
    app.db.run(move |db| identity(db, &check)).await?;
    event(ws, &first).await?;
    let mut chat = Chat {
        app,
        hash,
        nick,
        rooms: HashSet::new(),
        pending: None,
    };
    let interval = Duration::from_secs(25);
    let mut tick = tokio::time::interval_at(Clock::now() + interval, interval);
    let mut alive = true;
    let mut last_broker = Clock::now();
    let mut credits = 20.0_f64;
    let mut previous = Clock::now();
    loop {
        let deadline = chat.pending.as_ref().map(|p| p.deadline);
        tokio::select! {
            _ = async {
                match deadline {
                    Some(t) => tokio::time::sleep_until(t).await,
                    None => std::future::pending().await,
                }
            } => return Err(Error(503, "MESSAGE_TIMEOUT")),
            _ = tick.tick() => {
                if !alive || last_broker.elapsed() > Duration::from_secs(60) {
                    return Err(Error(503, "BROKER_TIMEOUT"));
                }
                alive = false;
                let check = hash.to_owned();
                app.db.run(move |db| identity(db, &check)).await?;
                send(ws, Message::Ping(Default::default())).await?;
                write(&mut b, json!({"type":"ping"})).await?;
            }
            incoming = read(&mut b) => {
                let message = incoming?;
                last_broker = Clock::now();
                chat.incoming(&mut b, ws, message).await?;
            }
            incoming = ws.recv() => match incoming {
                Some(Ok(Message::Text(text))) => {
                    let now = Clock::now();
                    credits = (credits + 5.0 * (now - previous).as_secs_f64()).min(20.0);
                    previous = now;
                    if credits < 1.0 { return Err(Error(429, "RATE_LIMIT")); }
                    credits -= 1.0;
                    chat.command(&mut b, ws, &text).await?;
                }
                Some(Ok(Message::Pong(_))) => alive = true,
                Some(Ok(Message::Ping(_))) => {},
                Some(Ok(Message::Binary(_))) => return Err(Error(400, "INVALID_COMMAND")),
                _ => return Ok(()),
            }
        }
    }
}
