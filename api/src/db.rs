use crate::{Error, Result};
use postgres::{Client, GenericClient, NoTls, types::ToSql};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

use r2d2_postgres::PostgresConnectionManager;
use std::{env, time::Duration};
use uuid::Uuid;

macro_rules! params {
    ($($v:expr),* $(,)?) => { &[$(&$v as &(dyn postgres::types::ToSql + Sync)),*] };
}
pub(crate) use params;
pub fn config() -> Result<postgres::Config> {
    if let Ok(url) = env::var("DATABASE_URL") {
        return url.parse().map_err(|_| Error(500, "INVALID_DATABASE_URL"));
    }
    let mut config = postgres::Config::new();
    config
        .host(&crate::var("PGHOST", "127.0.0.1"))
        .port(
            crate::var("PGPORT", "5432")
                .parse()
                .map_err(|_| Error::INPUT)?,
        )
        .user(&crate::var("PGUSER", "shifr"))
        .dbname(&crate::var("PGDATABASE", "shifr"))
        .password(
            env::var("PGPASSWORD")
                .or_else(|_| env::var("POSTGRES_PASSWORD"))
                .map_err(|_| Error(500, "MISSING_DB_PASSWORD"))?,
        );
    Ok(config)
}
pub fn initialize(db: &mut Client) -> Result<()> {
    let mut tx = db.transaction()?;
    tx.batch_execute("SELECT pg_advisory_xact_lock(1936214374,1)")?;
    tx.batch_execute(include_str!("schema.sql"))?;
    crate::legacy::import(&mut tx)?;
    tx.commit()?;
    Ok(())
}
#[derive(Clone)]
pub struct Store(r2d2::Pool<PostgresConnectionManager<NoTls>>);
impl Store {
    pub fn open() -> Result<Self> {
        let mut cfg = config()?;
        cfg.connect_timeout(Duration::from_secs(5));
        let pool = r2d2::Pool::builder()
            .max_size(8)
            .min_idle(Some(1))
            .connection_timeout(Duration::from_secs(8))
            .build(PostgresConnectionManager::new(cfg, NoTls))
            .map_err(|_| Error(503, "DATABASE_UNAVAILABLE"))?;
        let mut db = pool.get().map_err(|_| Error(503, "DATABASE_UNAVAILABLE"))?;
        initialize(&mut db)?;
        Ok(Self(pool))
    }
    pub async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Client) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let pool = self.0.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(|_| Error(503, "DATABASE_UNAVAILABLE"))?;
            f(&mut conn)
        })
        .await
        .map_err(|_| Error::INTERNAL)?
    }
}
pub fn exists(
    db: &mut impl GenericClient,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
) -> Result<bool> {
    Ok(!db.query(sql, params)?.is_empty())
}
pub fn rows(
    db: &mut impl GenericClient,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
) -> Result<Vec<Value>> {
    let sql = format!("SELECT row_to_json(record) FROM ({sql}) AS record");
    Ok(db
        .query(&sql, params)?
        .into_iter()
        .map(|r| r.get(0))
        .collect())
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub nickname: String,
    pub role: String,
    pub department: Option<String>,
    pub active: i32,
}
fn user_row(r: &postgres::Row) -> User {
    User {
        id: r.get(0),
        nickname: r.get(1),
        role: r.get(2),
        department: r.get(3),
        active: r.get(4),
    }
}
pub fn by_id(db: &mut impl GenericClient, id: &str) -> Result<User> {
    Ok(user_row(
        &db.query_opt(
            "SELECT id,nickname,role,department,active FROM users WHERE id=$1",
            &[&id],
        )?
        .ok_or(Error::MISSING)?,
    ))
}
pub fn session(db: &mut impl GenericClient, hash: &str) -> Result<(User, i64)> {
    let r=db.query_opt("SELECT u.id,nickname,role,department,active,expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE token_hash=$1 AND active=1 AND expires_at>$2",params![hash,now()])?.ok_or(Error::AUTH)?;
    Ok((user_row(&r), r.get(5)))
}
pub fn auth_admin(user: &User) -> Result<()> {
    if user.role == "admin" {
        Ok(())
    } else {
        Err(Error::DENIED)
    }
}
pub fn can_read(db: &mut impl postgres::GenericClient, u: &User, t: &str) -> Result<bool> {
    if t == "#general" || t == "#announcements" {
        return Ok(true);
    }
    if t.starts_with('#') {
        return Ok((u.role == "admin" || u.department.as_deref() == Some(t))
            && exists(db, "SELECT 1 FROM departments WHERE channel=$1", &[&t])?);
    }
    exists(
        db,
        "SELECT 1 FROM users WHERE nickname=$1 AND id<>$2",
        params![t, u.id],
    )
}
pub fn can_write(db: &mut impl postgres::GenericClient, u: &User, t: &str) -> Result<bool> {
    Ok(can_read(db, u, t)?
        && (t != "#announcements" || u.role != "member")
        && (t.starts_with('#')
            || exists(
                db,
                "SELECT 1 FROM users WHERE nickname=$1 AND active=1",
                &[&t],
            )?))
}
pub fn attachment_allowed(
    db: &mut impl postgres::GenericClient,
    u: &User,
    t: &str,
    id: &str,
) -> Result<bool> {
    exists(
        db,
        "SELECT 1 FROM files f WHERE id=$1 AND owner=$2 AND scope='chat' AND target=$3 AND NOT
             EXISTS(SELECT 1 FROM messages WHERE file_id=f.id)",
        params![id, u.id, t],
    )
}
pub fn audit(
    db: &mut impl postgres::GenericClient,
    actor: Option<&str>,
    action: &str,
    subject: &str,
    ip: &str,
) -> Result<()> {
    db.execute(
        "INSERT INTO audit(time,actor,action,subject,ip)
             VALUES(to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'),$1,$2,$3,$4)",
        params![actor, action, subject, ip],
    )?;
    Ok(())
}
pub fn random_hex<const N: usize>() -> Result<String> {
    let mut data = [0; N];
    openssl::rand::rand_bytes(&mut data).map_err(|_| Error::INTERNAL)?;
    Ok(hex::encode(data))
}
pub fn hash_password(password: &str, salt: &str) -> Result<String> {
    let mut key = [0u8; 64];
    openssl::pkcs5::scrypt(
        password.as_bytes(),
        salt.as_bytes(),
        32768,
        8,
        1,
        64 * 1024 * 1024,
        &mut key,
    )
    .map_err(|_| Error::INTERNAL)?;
    Ok(hex::encode(key))
}
pub fn valid_password(s: &str) -> bool {
    (12..=128).contains(&s.encode_utf16().count())
}
pub fn register(
    db: &mut impl postgres::GenericClient,
    nick: &str,
    salt: &str,
    key: &str,
    role: &str,
    dept: Option<&str>,
) -> Result<User> {
    let id = Uuid::new_v4().to_string();
    if db.execute(
        "INSERT INTO users(id,nickname,salt,password_hash,created_at,role,department) VALUES
             ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(nickname) DO NOTHING",
        params![id, nick.to_ascii_lowercase(), salt, key, now(), role, dept],
    )? == 0
    {
        return Err(Error(409, "NICKNAME_TAKEN"));
    }
    by_id(db, &id)
}
pub fn save_message(
    db: &mut postgres::Client,
    hash: &str,
    target: &str,
    text: &str,
    file: Option<&str>,
) -> Result<Value> {
    let mut tx = db.transaction()?;
    let (user, _) = session(&mut tx, hash)?;
    if !can_write(&mut tx, &user, target)? {
        return Err(Error::DENIED);
    }
    if let Some(id) = file
        && !attachment_allowed(&mut tx, &user, target, id)?
    {
        return Err(Error::DENIED);
    }
    let row = tx.query_one(
        "INSERT INTO messages(sender,recipient,target,text,time,file_id) VALUES($1,(SELECT id
             FROM users WHERE nickname=$2),$3,$4,to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'),$5) RETURNING
             id,time",
        params![user.id, target, target, text, file],
    )?;
    let (id, time): (i64, String) = (row.get(0), row.get(1));
    let mut saved = json!({"id":id,"time":time,"from":user.nickname,"target":target,"text":text});
    if let Some(f) = file {
        saved["attachment"] = rows(&mut tx, "SELECT id,name,size FROM files WHERE id=$1", &[&f])?
            .pop()
            .ok_or(Error::MISSING)?
    }
    tx.commit()?;
    Ok(saved)
}
pub fn history(
    db: &mut impl postgres::GenericClient,
    user: &User,
    target: &str,
    before: i64,
) -> Result<Vec<Value>> {
    if !can_read(db, user, target)? {
        return Err(Error::DENIED);
    }
    let filter = if target.starts_with('#') {
        "m.target=$1 AND m.recipient IS NULL AND $3::text IS NOT NULL"
    } else {
        "((m.sender=$3 AND m.recipient=(SELECT id FROM users WHERE nickname=$1)) OR (m.recipient=$3 AND m.sender=(SELECT id FROM users WHERE nickname=$1)))"
    };
    let sql = format!(
        "SELECT m.id,u.nickname AS \"from\",m.target,m.text,m.time,f.id AS file_id,f.name AS
             file_name,f.size AS file_size FROM messages m JOIN users u ON u.id=m.sender LEFT JOIN
             files f ON f.id=m.file_id WHERE m.id<$2 AND {filter} ORDER BY m.id DESC LIMIT 50"
    );
    let mut result = rows(db, &sql, params![target, before, user.id])?;
    for item in &mut result {
        let obj = item.as_object_mut().unwrap();
        let id = obj.remove("file_id");
        let name = obj.remove("file_name");
        let size = obj.remove("file_size");
        if id.as_ref().is_some_and(Value::is_string) {
            obj.insert(
                "attachment".into(),
                json!({"id":id,"name":name,"size":size}),
            );
        }
    }
    result.reverse();
    Ok(result)
}
