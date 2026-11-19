use crate::{auth, db, *};
use axum::{
    Extension,
    body::Bytes,
    extract::{Path, Query},
};

use serde::Deserialize;
use serde_json::Value;
type Output = Result<Json<Value>>;
pub const FILE_LIMIT: usize = 10 * 1024 * 1024;
const USERS: &str = "SELECT id,nickname,role,department,active FROM users ORDER BY nickname";
const DEPARTMENTS: &str = "SELECT channel,name FROM departments ORDER BY name";
#[derive(Deserialize)]
pub struct Page {
    before: Option<i64>,
}
#[derive(Deserialize)]
pub struct History {
    target: String,
    before: Option<i64>,
}
fn cursor(v: Option<i64>) -> Result<i64> {
    const MAX: i64 = 9007199254740991;
    v.or(Some(MAX))
        .filter(|n| (1..=MAX).contains(n))
        .ok_or(Error::INPUT)
}
pub async fn directory(State(app): State<App>, h: HeaderMap) -> Output {
    let hash = cookie_hash(&h)?;
    app.db.run(move|db|{let u=identity(db,&hash)?;
        let mut channels=vec![json!({"channel":"#general","name":"Общий чат"}),json!({"channel":"#announcements","name":"Объявления"})];
        channels.extend(db::rows(db,"SELECT channel,name FROM departments WHERE $1='admin' OR channel=$2 ORDER BY name",db::params![u.role,u.department])?);
        let users=db::rows(db,"SELECT nickname FROM users WHERE active=1 ORDER BY nickname", &[])?;
        let result=db.query("SELECT DISTINCT nickname FROM messages m JOIN users u ON u.id=CASE WHEN m.sender=$1
             THEN m.recipient ELSE m.sender END WHERE m.recipient IS NOT NULL AND (m.sender=$1 OR
             m.recipient=$1) LIMIT 200",&[&u.id])?;
        let conversations:Vec<String>=result.iter().map(|r|r.get(0)).collect();
        Ok(Json(json!({ "channels":channels,"users":users,"conversations":conversations})))
    }).await
}
pub async fn history(State(app): State<App>, h: HeaderMap, Query(q): Query<History>) -> Output {
    let hash = cookie_hash(&h)?;
    let t = target(&q.target)?;
    let n = cursor(q.before)?;
    app.db
        .run(move |db| {
            let u = identity(db, &hash)?;
            let messages = db::history(db, &u, &t, n)?;
            let next = (messages.len() == 50).then(|| messages[0]["id"].clone());
            Ok(Json(json!({"messages":messages,"nextBefore":next})))
        })
        .await
}
pub async fn users(State(app): State<App>, h: HeaderMap) -> Output {
    let hash = cookie_hash(&h)?;
    app.db
        .run(move |db| {
            auth::admin(db, &hash)?;
            Ok(Json(
                json!({"users":db::rows(db,USERS, &[])?,"departments":db::rows(db,DEPARTMENTS, &[])?}),
            ))
        })
        .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Department {
    channel: String,
    name: String,
}
pub async fn department(
    State(app): State<App>,
    Extension(ip): Extension<ClientIp>,
    h: HeaderMap,
    Input(b): Input<Department>,
) -> Result<(StatusCode, Json<Value>)> {
    let hash = cookie_hash(&h)?;
    app.db
        .run(move |db| {
            let mut tx = db.transaction()?;
            let u = auth::admin(&mut tx, &hash)?;
            let name = b.name.trim();
            if !shifr_broker::valid_room(&b.channel)
                || matches!(b.channel.as_str(), "#general" | "#announcements")
                || !(1..=80).contains(&name.encode_utf16().count())
            {
                return Err(Error::INPUT);
            }
            if tx.execute(
                "INSERT INTO departments(channel,name) VALUES($1,$2) ON CONFLICT DO NOTHING",
                db::params![b.channel, name],
            )? == 0
            {
                return Err(Error(409, "ALREADY_EXISTS"));
            }
            db::audit(&mut tx, Some(&u.id), "department.create", &b.channel, &ip.0)?;
            tx.commit()?;
            Ok((
                StatusCode::CREATED,
                Json(json!({"channel":b.channel,"name":name})),
            ))
        })
        .await
}
pub async fn audit(State(app): State<App>, h: HeaderMap, Query(q): Query<Page>) -> Output {
    let hash = cookie_hash(&h)?;
    let n = cursor(q.before)?;
    app.db
        .run(move |db| {
            auth::admin(db, &hash)?;
            let entries = db::rows(
                db,
                "SELECT a.*,u.nickname FROM audit a LEFT JOIN users u ON u.id=a.actor WHERE a.id<$1
             ORDER BY a.id DESC LIMIT 100",
                &[&n],
            )?;
            let next = (entries.len() == 100).then(|| entries[99]["id"].clone());
            Ok(Json(json!({"entries":entries,"nextBefore":next})))
        })
        .await
}
pub async fn resources(State(app): State<App>, h: HeaderMap) -> Output {
    let hash = cookie_hash(&h)?;
    app.db.run(move|db|{identity(db,&hash)?;
        Ok(Json(json!({"files":db::rows(db,"SELECT id,name,size,created_at FROM files WHERE scope='resource' ORDER BY created_at
             DESC", &[])?}))) }).await
}
pub async fn delete_resource(
    State(app): State<App>,
    Extension(ip): Extension<ClientIp>,
    Path(id): Path<String>,
    h: HeaderMap,
) -> Result<StatusCode> {
    let hash = cookie_hash(&h)?;
    app.db
        .run(move |db| {
            let mut tx = db.transaction()?;
            let u = identity(&mut tx, &hash)?;
            if u.role == "member" {
                return Err(Error::DENIED);
            }
            if tx.execute("DELETE FROM files WHERE id=$1 AND scope='resource'", &[&id])? == 0 {
                return Err(Error::MISSING);
            }
            db::audit(&mut tx, Some(&u.id), "resource.delete", &id, &ip.0)?;
            tx.commit()?;
            Ok(StatusCode::NO_CONTENT)
        })
        .await
}
#[derive(Deserialize)]
pub struct Upload {
    scope: String,
    name: String,
    target: Option<String>,
}
pub async fn upload(
    State(app): State<App>,
    Extension(ip): Extension<ClientIp>,
    Query(q): Query<Upload>,
    req: Request,
) -> Result<(StatusCode, Json<Value>)> {
    let hash = cookie_hash(req.headers())?;
    let check = hash.clone();
    app.db.run(move |db| identity(db, &check)).await?;
    if req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(';').next())
        != Some("application/octet-stream")
        || !(1..=180).contains(&q.name.encode_utf16().count())
        || q.name
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\'))
    {
        return Err(Error::INPUT);
    }
    let dest = q
        .target
        .as_deref()
        .map(target)
        .transpose()?
        .unwrap_or_default();
    let bytes = tokio::time::timeout(
        Duration::from_secs(10),
        axum::body::to_bytes(req.into_body(), FILE_LIMIT),
    )
    .await
    .map_err(|_| Error(408, "INVALID_REQUEST"))?
    .map_err(|_| Error(413, "INVALID_REQUEST"))?;
    if bytes.is_empty() {
        return Err(Error::INPUT);
    }
    app.db
        .run(move |db| {
            let mut tx = db.transaction()?;
            let u = identity(&mut tx, &hash)?;
            tx.batch_execute("LOCK TABLE files IN SHARE ROW EXCLUSIVE MODE")?;
            match q.scope.as_str() {
                "resource" if u.role != "member" => {}
                "chat" if db::can_write(&mut tx, &u, &dest)? => {}
                "resource" | "chat" => return Err(Error::DENIED),
                _ => return Err(Error::INPUT),
            }
            tx.execute(
                "DELETE FROM files WHERE scope='chat' AND created_at<$1 AND NOT EXISTS(SELECT 1 FROM
             messages WHERE file_id=files.id)",
                db::params![db::now() - 86400000],
            )?;
            let size: i64 = tx
                .query_one("SELECT coalesce(sum(size),0)::bigint FROM files", &[])?
                .get(0);
            if size + bytes.len() as i64 > 1024 * 1024 * 1024 {
                return Err(Error(507, "STORAGE_FULL"));
            }
            let id = uuid::Uuid::new_v4().to_string();
            tx.execute(
                "INSERT INTO files(id,owner,scope,target,name,size,content,created_at)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
                db::params![
                    id,
                    u.id,
                    q.scope,
                    dest,
                    q.name,
                    bytes.len() as i64,
                    bytes.as_ref(),
                    db::now()
                ],
            )?;
            db::audit(&mut tx, Some(&u.id), "file.upload", &id, &ip.0)?;
            tx.commit()?;
            Ok((
                StatusCode::CREATED,
                Json(json!({"file":{"id":id,"name":q.name,"size":bytes.len()}})),
            ))
        })
        .await
}
pub async fn download(
    State(app): State<App>,
    Extension(ip): Extension<ClientIp>,
    Path(id): Path<String>,
    h: HeaderMap,
) -> Result<Response> {
    let hash = cookie_hash(&h)?;
    let (name, content) = app
        .db
        .run(move |db| {
            let mut tx = db.transaction()?;
            let user = identity(&mut tx, &hash)?;
            let row=tx.query_opt("SELECT f.name,f.scope,f.owner,f.target,m.sender,m.recipient FROM files f LEFT JOIN messages m ON m.file_id=f.id WHERE f.id=$1 FOR SHARE OF f", &[&id])?.ok_or(Error::MISSING)?;
            let (name,scope,owner,target,sender,recipient):(String,String,String,String,Option<String>,Option<String>)=(row.get(0),row.get(1),row.get(2),row.get(3),row.get(4),row.get(5));
            let allowed = scope == "resource"
                || match (sender, recipient) {
                    (Some(from), Some(to)) => from == user.id || to == user.id,
                    (Some(_), None) => db::can_read(&mut tx, &user, &target)?,
                    _ => owner == user.id && db::can_read(&mut tx, &user, &target)?,
                };
            if !allowed {
                return Err(Error::MISSING);
            }
            let content:Vec<u8>=tx.query_one("SELECT content FROM files WHERE id=$1",&[&id])?.get(0);
            db::audit(&mut tx, Some(&user.id), "file.download", &id, &ip.0)?;
            tx.commit()?;
            Ok((name, content))
        })
        .await?;
    let disposition = format!(
        "attachment; filename=\"document\"; filename*=UTF-8''{}",
        percent_encoding::utf8_percent_encode(&name, percent_encoding::NON_ALPHANUMERIC)
    );
    Ok((
        [
            ("content-type", "application/octet-stream"),
            ("content-disposition", &disposition),
            ("content-security-policy", "sandbox; default-src 'none'"),
        ],
        Bytes::from(content),
    )
        .into_response())
}
