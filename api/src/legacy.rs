//! One-time, read-only SQLite snapshot import. Normal API operations use PostgreSQL.
use crate::{Error, Result};
use postgres::{
    Transaction,
    types::{ToSql, Type},
};
use rusqlite::{Connection, OpenFlags, types::ValueRef};
use std::{env, path::Path};

impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Error(500, "INVALID_LEGACY_DATABASE")
    }
}
const TABLES: &[(&str, &str)] = &[
    (
        "users",
        "id,nickname,salt,password_hash,created_at,role,department,active",
    ),
    ("departments", "channel,name"),
    ("sessions", "token_hash,user_id,expires_at"),
    (
        "files",
        "id,owner,scope,target,name,size,content,created_at",
    ),
    ("messages", "id,sender,recipient,target,text,time,file_id"),
    ("audit", "id,time,actor,action,subject,ip"),
];
fn has_table(src: &Connection, name: &str) -> Result<bool> {
    Ok(src
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?")?
        .exists([name])?)
}
fn copy(src: &Connection, tx: &mut Transaction<'_>, name: &str, columns: &str) -> Result<()> {
    if !has_table(src, name)? {
        return if matches!(name, "users" | "sessions") {
            Err(Error(500, "INVALID_LEGACY_DATABASE"))
        } else {
            Ok(())
        };
    }
    let mut expressions = vec![];
    for col in columns.split(',') {
        let expr = if name == "users" {
            match col {
                "nickname" => "lower(nickname)",
                "role" | "department" | "active"
                    if !src
                        .prepare("SELECT 1 FROM pragma_table_info('users') WHERE name=?")?
                        .exists([col])? =>
                {
                    match col {
                        "role" => "'member'",
                        "active" => "1",
                        _ => "NULL",
                    }
                }
                _ => col,
            }
        } else {
            col
        };
        expressions.push(expr);
    }
    let bind = (1..=expressions.len())
        .map(|n| format!("${n}"))
        .collect::<Vec<_>>()
        .join(",");
    let insert = tx.prepare(&format!("INSERT INTO {name} ({columns}) VALUES ({bind})"))?;
    let mut select = src.prepare(&format!("SELECT {} FROM {name}", expressions.join(",")))?;
    let mut rows = select.query([])?;
    while let Some(row) = rows.next()? {
        let mut values: Vec<Box<dyn ToSql + Sync>> = Vec::with_capacity(expressions.len());
        for (i, ty) in insert.params().iter().enumerate() {
            let value: Box<dyn ToSql + Sync> = match (row.get_ref(i)?, ty) {
                (ValueRef::Integer(n), &Type::INT4) => {
                    Box::new(i32::try_from(n).map_err(|_| Error::INPUT)?)
                }
                (ValueRef::Integer(n), &Type::INT8) => Box::new(n),
                (ValueRef::Blob(b), &Type::BYTEA) => Box::new(b),
                (ValueRef::Text(_), &Type::TEXT) => Box::new(row.get::<_, String>(i)?),
                (ValueRef::Null, &Type::TEXT) => Box::new(None::<String>),
                _ => return Err(Error(500, "INVALID_LEGACY_VALUE")),
            };
            values.push(value)
        }
        let refs = values.iter().map(Box::as_ref).collect::<Vec<_>>();
        tx.execute(&insert, &refs)?;
    }
    Ok(())
}
pub fn import(tx: &mut Transaction<'_>) -> Result<()> {
    let Ok(path) = env::var("LEGACY_SQLITE_PATH") else {
        return Ok(());
    };
    if tx
        .query_opt(
            "SELECT 1 FROM storage_migrations WHERE name='sqlite-v1'",
            &[],
        )?
        .is_some()
    {
        return Ok(());
    }
    if path.is_empty()
        || !Path::new(&path)
            .try_exists()
            .map_err(|_| Error(500, "LEGACY_DATABASE_UNREADABLE"))?
    {
        return Ok(());
    }
    // Never merge two independent installations. Readers see all rows or none.
    for (table, _) in TABLES {
        if !tx
            .query(&format!("SELECT 1 FROM {table} LIMIT 1"), &[])?
            .is_empty()
        {
            return Err(Error(409, "MIGRATION_TARGET_NOT_EMPTY"));
        }
    }
    // SQLite may try to create -shm even for a checkpointed WAL-mode database.
    // A stopped legacy API and absent journals make its main file a complete snapshot.
    let has_journal = ["-wal", "-journal"]
        .iter()
        .try_fold(false, |found, suffix| {
            Path::new(&format!("{path}{suffix}"))
                .try_exists()
                .map(|present| found || present)
        })
        .map_err(|_| Error(500, "LEGACY_DATABASE_UNREADABLE"))?;
    let mut file = if has_journal {
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?
    } else {
        let absolute =
            std::fs::canonicalize(&path).map_err(|_| Error(500, "LEGACY_DATABASE_UNREADABLE"))?;
        let absolute = absolute.to_str().ok_or(Error::INPUT)?;
        let uri_path = absolute
            .split('/')
            .map(|part| {
                percent_encoding::utf8_percent_encode(part, percent_encoding::NON_ALPHANUMERIC)
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join("/");
        Connection::open_with_flags(
            format!("file:{uri_path}?immutable=1"),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )?
    };
    let snapshot = file.transaction()?;
    for &(table, cols) in TABLES {
        copy(&snapshot, tx, table, cols)?;
    }
    for table in ["messages", "audit"] {
        let max: i64 = tx
            .query_one(&format!("SELECT coalesce(max(id),0) FROM {table}"), &[])?
            .get(0);
        let last = if has_table(&snapshot, "sqlite_sequence")? {
            snapshot.query_row(
                "SELECT coalesce(max(seq),0) FROM sqlite_sequence WHERE name=?",
                [table],
                |r| r.get::<_, i64>(0),
            )?
        } else {
            0
        };
        let next = max.max(last).checked_add(1).ok_or(Error::INPUT)?;
        tx.batch_execute(&format!(
            "ALTER TABLE {table} ALTER COLUMN id RESTART WITH {next}"
        ))?;
    }
    tx.execute(
        "INSERT INTO storage_migrations(name) VALUES ('sqlite-v1')",
        &[],
    )?;
    Ok(())
}
