use crate::{
    db::{self, User},
    *,
};
use axum::{Extension, extract::Path};

use serde::Deserialize;
use serde_json::Value;
use std::io::Read;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Login {
    nickname: String,
    password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    nickname: String,
    password: String,
    role: String,
    #[serde(deserialize_with = "Deserialize::deserialize")]
    department: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Update {
    role: String,
    #[serde(deserialize_with = "Deserialize::deserialize")]
    department: Option<String>,
    active: bool,
    password: Option<String>,
}
fn valid_user(n: &str, p: &str) -> Result<()> {
    if shifr_broker::valid_nick(&n.to_ascii_lowercase()) && db::valid_password(p) {
        Ok(())
    } else {
        Err(Error::INPUT)
    }
}
fn validate_role(db: &mut impl postgres::GenericClient, r: &str, d: Option<&str>) -> Result<()> {
    if !matches!(r, "admin" | "moderator" | "member") {
        return Err(Error::INPUT);
    }
    if let Some(d) = d
        && !db::exists(db, "SELECT 1 FROM departments WHERE channel=$1", &[&d])?
    {
        return Err(Error::INPUT);
    }
    Ok(())
}
async fn derive(app: &Service, p: String, salt: String) -> Result<String> {
    let permit = app
        .slots
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| Error::INTERNAL)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        db::hash_password(&p, &salt)
    })
    .await
    .map_err(|_| Error::INTERNAL)?
}
fn cookie(app: &Service, token: &str, age: i64) -> HeaderValue {
    format!(
        "shifr_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={age}{}",
        if app.cfg.cert.is_some() {
            "; Secure"
        } else {
            ""
        }
    )
    .parse()
    .unwrap()
}
pub async fn login(
    State(app): State<App>,
    Extension(ip): Extension<ClientIp>,
    Input(body): Input<Login>,
) -> Result<Response> {
    valid_user(&body.nickname, &body.password)?;
    let nick = body.nickname.to_ascii_lowercase();
    let query = nick.clone();
    let salt = app
        .db
        .run(move |db| {
            Ok(db
                .query_opt("SELECT salt FROM users WHERE nickname=$1", &[&query])?
                .map(|r| r.get::<_, String>(0))
                .unwrap_or_else(|| "0".repeat(32)))
        })
        .await?;
    let key = derive(&app, body.password, salt.clone()).await?;
    let ttl = app.cfg.ttl;
    let (user, expires, token) = app
        .db
        .run(move |db| {
            let mut tx = db.transaction()?;
            let account = tx
                .query_opt(
                    "SELECT id,password_hash FROM users WHERE active=1 AND nickname=$1 AND salt=$2 FOR UPDATE",
                    db::params![nick, salt], )?.map(|r|(r.get::<_,String>(0),r.get::<_,String>(1)));
            let id = match account {
                Some((id, expected))
                    if key.len() == expected.len()
                        && openssl::memcmp::eq(key.as_bytes(), expected.as_bytes()) =>
                {
                    id
                }
                _ => {
                    db::audit(&mut tx, None, "auth.login_failed", &nick, &ip.0)?;
                    tx.commit()?;
                    return Err(Error(401, "INVALID_CREDENTIALS"));
                }
            };
            let user = db::by_id(&mut tx, &id)?;
            let expires = db::now() + ttl * 1000;
            let token = db::random_hex::<32>()?;
            tx.execute("DELETE FROM sessions WHERE expires_at<=$1", db::params![db::now()])?;
            tx.execute(
                "DELETE FROM sessions WHERE token_hash IN (SELECT token_hash FROM sessions WHERE
             user_id=$1 ORDER BY expires_at DESC,token_hash OFFSET 4)", &[&id],
            )?;
            tx.execute(
                "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,$3)",
                db::params![
                    hex::encode(openssl::sha::sha256(token.as_bytes())),
                    id,
                    expires
                ],
            )?;
            db::audit(&mut tx, Some(&id), "auth.login", &id, &ip.0)?;
            tx.commit()?;
            Ok((user, expires, token))
        })
        .await?;
    let mut response = Json(json!({"user":user,"expiresAt":expires})).into_response();
    response
        .headers_mut()
        .insert("set-cookie", cookie(&app, &token, ttl));
    Ok(response)
}
pub async fn me(State(app): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    let hash = cookie_hash(&h)?;
    let (u, e) = app.db.run(move |db| db::session(db, &hash)).await?;
    Ok(Json(json!({"user":u,"expiresAt":e})))
}
pub async fn status(State(app): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    let hash = cookie_hash(&h)?;
    let u = app.db.run(move |db| identity(db, &hash)).await?;
    Ok(Json(
        json!({"connected":app.active.lock().unwrap().contains_key(&u.id)}),
    ))
}
pub async fn logout(
    State(app): State<App>,
    Extension(ip): Extension<ClientIp>,
    h: HeaderMap,
) -> Result<Response> {
    if let Ok(hash) = cookie_hash(&h) {
        let query = hash.clone();
        let id = app
            .db
            .run(move |db| {
                let mut tx = db.transaction()?;
                let user = match db::session(&mut tx, &query) {
                    Ok((u, _)) => Some(u),
                    Err(Error::AUTH) => None,
                    Err(e) => return Err(e),
                };
                tx.execute("DELETE FROM sessions WHERE token_hash=$1", &[&query])?;
                if let Some(u) = &user {
                    db::audit(&mut tx, Some(&u.id), "auth.logout", &u.id, &ip.0)?;
                }
                tx.commit()?;
                Ok(user.map(|u| u.id))
            })
            .await?;
        if let Some(id) = id
            && let Some(c) = app.active.lock().unwrap().get(&id)
            && c.hash == hash
        {
            c.stop.send_replace(true);
        }
    }
    let mut res = StatusCode::NO_CONTENT.into_response();
    res.headers_mut().insert("set-cookie", cookie(&app, "", 0));
    Ok(res)
}
pub fn admin(db: &mut impl postgres::GenericClient, hash: &str) -> Result<User> {
    let u = identity(db, hash)?;
    db::auth_admin(&u)?;
    Ok(u)
}
async fn precheck_admin(app: &Service, h: &HeaderMap) -> Result<String> {
    let hash = cookie_hash(h)?;
    let check = hash.clone();
    app.db.run(move |db| admin(db, &check)).await?;
    Ok(hash)
}
pub async fn create_user(
    State(app): State<App>,
    Extension(ip): Extension<ClientIp>,
    h: HeaderMap,
    Input(body): Input<Account>,
) -> Result<(StatusCode, Json<Value>)> {
    let hash = precheck_admin(&app, &h).await?;
    valid_user(&body.nickname, &body.password)?;
    let salt = db::random_hex::<16>()?;
    let key = derive(&app, body.password, salt.clone()).await?;
    let user = app
        .db
        .run(move |db| {
            let mut tx = db.transaction()?;
            let actor = admin(&mut tx, &hash)?;
            validate_role(&mut tx, &body.role, body.department.as_deref())?;
            let user = db::register(
                &mut tx,
                &body.nickname,
                &salt,
                &key,
                &body.role,
                body.department.as_deref(),
            )?;
            db::audit(&mut tx, Some(&actor.id), "user.create", &user.id, &ip.0)?;
            tx.commit()?;
            Ok(user)
        })
        .await?;
    Ok((StatusCode::CREATED, Json(json!({"user":user}))))
}
pub async fn update_user(
    State(app): State<App>,
    Extension(ip): Extension<ClientIp>,
    Path(id): Path<String>,
    h: HeaderMap,
    Input(body): Input<Update>,
) -> Result<Json<Value>> {
    let hash = precheck_admin(&app, &h).await?;
    let password = if let Some(p) = body.password {
        if !db::valid_password(&p) {
            return Err(Error::INPUT);
        }
        let salt = db::random_hex::<16>()?;
        let key = derive(&app, p, salt.clone()).await?;
        Some((salt, key))
    } else {
        None
    };
    let user=app.db.run(move|db|{let mut tx=db.transaction()?;
        tx.batch_execute("LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE")?;
        let actor=admin(&mut tx,&hash)?;validate_role(&mut tx,&body.role,body.department.as_deref())?;
        let prev=db::by_id(&mut tx,&id)?;
        let removing_admin = prev.role == "admin" && prev.active != 0 && (!body.active || body.role != "admin");
        let other_admin = "SELECT 1 FROM users WHERE role='admin' AND active=1 AND id<>$1";
        if removing_admin && !db::exists(&mut tx, other_admin, &[&id])? {
            return Err(Error(409, "LAST_ADMIN"));
        }
        tx.execute("UPDATE users SET role=$1,department=$2,active=$3 WHERE id=$4",db::params![body.role,body.department,i32::from(body.active),id])?;
        if let Some((salt,key))=&password{tx.execute("UPDATE users SET salt=$1,password_hash=$2 WHERE id=$3",db::params![salt,key,id])?;}
        tx.execute("DELETE FROM sessions WHERE user_id=$1", &[&id])?;
        let user=db::by_id(&mut tx,&id)?;
        let fields=|u:&User|json!({"role":u.role,"department":u.department,"active":u.active!=0});
        db::audit(&mut tx,Some(&actor.id),"user.update",&json!({"id":id,"before":fields(&prev),"after":fields(&user),"passwordReset":password.is_some()}).to_string(),&ip.0)?;
        tx.commit()?;
        Ok(user)
    }).await?;
    if let Some(c) = app.active.lock().unwrap().get(&user.id) {
        c.stop.send_replace(true);
    }
    Ok(Json(json!({"user":user})))
}
pub fn bootstrap() -> Result<()> {
    let args: Vec<String> = env::args().skip(2).collect();
    let [mode, nickname] = args.as_slice() else {
        return Err(Error::INPUT);
    };
    if !shifr_broker::valid_nick(&nickname.to_ascii_lowercase()) {
        return Err(Error::INPUT);
    }
    let credentials = match mode.as_str() {
        "--promote" => None,
        "--nickname" => {
            let mut p = String::new();
            std::io::stdin()
                .take(1025)
                .read_to_string(&mut p)
                .map_err(|_| Error::INPUT)?;
            let p = p.strip_suffix('\n').unwrap_or(&p);
            let p = p.strip_suffix('\r').unwrap_or(p);
            if !db::valid_password(p) {
                return Err(Error::INPUT);
            }
            let salt = db::random_hex::<16>()?;
            let key = db::hash_password(p, &salt)?;
            Some((salt, key))
        }
        _ => return Err(Error::INPUT),
    };
    let mut db = db::config()?.connect(postgres::NoTls)?;
    db::initialize(&mut db)?;
    let mut tx = db.transaction()?;
    tx.batch_execute("LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE")?;
    if db::exists(
        &mut tx,
        "SELECT 1 FROM users WHERE role='admin' AND active=1",
        &[],
    )? {
        return Err(Error(409, "ADMIN_ALREADY_EXISTS"));
    }
    let id = if let Some((salt, key)) = credentials {
        db::register(&mut tx, nickname, &salt, &key, "admin", None)?.id
    } else {
        let id: String = tx
            .query_opt(
                "UPDATE users SET role='admin',active=1 WHERE nickname=lower($1) RETURNING id",
                &[nickname],
            )?
            .map(|r| r.get(0))
            .ok_or(Error::MISSING)?;
        tx.execute("DELETE FROM sessions WHERE user_id=$1", &[&id])?;
        id
    };
    db::audit(&mut tx, Some(&id), "admin.bootstrap", &id, "local-console")?;
    tx.commit()?;
    println!("Administrator configured.");
    Ok(())
}
