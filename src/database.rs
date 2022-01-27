use crate::key_manager::AuthKey;
use crate::{InfoHash, AUTH_KEY_LENGTH};
use log::debug;
use r2d2::Pool;
use r2d2_sqlite::rusqlite::NO_PARAMS;
use r2d2_sqlite::{rusqlite, SqliteConnectionManager};
use std::convert::TryInto;
use std::str::FromStr;

pub struct SqliteDatabase {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteDatabase {
    pub fn new(db_path: &str) -> Result<SqliteDatabase, rusqlite::Error> {
        let sqlite_connection_manager = SqliteConnectionManager::file(db_path);
        let sqlite_pool = r2d2::Pool::new(sqlite_connection_manager)
            .expect("Failed to create r2d2 SQLite connection pool.");
        SqliteDatabase::create_database_tables(&sqlite_pool)?;

        Ok(SqliteDatabase { pool: sqlite_pool })
    }

    pub fn create_database_tables(
        pool: &Pool<SqliteConnectionManager>,
    ) -> Result<usize, rusqlite::Error> {
        let create_whitelist_table = "
        CREATE TABLE IF NOT EXISTS whitelist (
            id integer PRIMARY KEY AUTOINCREMENT,
            info_hash VARCHAR(20) NOT NULL UNIQUE
        );";

        let create_keys_table = format!(
            "
        CREATE TABLE IF NOT EXISTS keys (
            id integer PRIMARY KEY AUTOINCREMENT,
            key VARCHAR({}) NOT NULL UNIQUE,
            valid_until INT(10) NOT NULL
         );",
            AUTH_KEY_LENGTH
        );

        let conn = pool.get().unwrap();
        conn.execute(create_whitelist_table, NO_PARAMS)
            .and_then(|updated| {
                conn.execute(&create_keys_table, NO_PARAMS)
                    .map(|updated2| updated + updated2)
            })
            .map_err(trace_debug)
    }

    pub async fn get_info_hash_from_whitelist(
        &self,
        info_hash: &str,
    ) -> Result<InfoHash, rusqlite::Error> {
        let conn = self.pool.get().unwrap();
        let mut stmt = conn.prepare("SELECT info_hash FROM whitelist WHERE info_hash = ?")?;
        let mut rows = stmt.query(&[info_hash])?;

        if let Some(row) = rows.next()? {
            let info_hash: String = row.get(0).unwrap();

            // should never be able to fail
            Ok(InfoHash::from_str(&info_hash).unwrap())
        } else {
            Err(rusqlite::Error::QueryReturnedNoRows)
        }
    }

    pub async fn add_info_hash_to_whitelist(
        &self,
        info_hash: InfoHash,
    ) -> Result<usize, rusqlite::Error> {
        let conn = self.pool.get().unwrap();
        conn.execute(
            "INSERT INTO whitelist (info_hash) VALUES (?)",
            &[info_hash.to_string()],
        )
        .map_err(trace_debug)
        .and_then(validate_updated)
    }

    pub async fn remove_info_hash_from_whitelist(
        &self,
        info_hash: InfoHash,
    ) -> Result<usize, rusqlite::Error> {
        let conn = self.pool.get().unwrap();
        conn.execute(
            "DELETE FROM whitelist WHERE info_hash = ?",
            &[info_hash.to_string()],
        )
        .map_err(trace_debug)
        .and_then(validate_updated)
    }

    pub async fn get_key_from_keys(&self, key: &str) -> Result<AuthKey, rusqlite::Error> {
        let conn = self.pool.get().unwrap();
        let mut stmt = conn.prepare("SELECT key, valid_until FROM keys WHERE key = ?")?;
        let mut rows = stmt.query(&[key.to_string()])?;

        if let Some(row) = rows.next()? {
            let key: String = row.get(0).unwrap();
            let valid_until_i64: i64 = row.get(1).unwrap();

            Ok(AuthKey {
                key,
                valid_until: Some(valid_until_i64.try_into().unwrap()),
            })
        } else {
            Err(rusqlite::Error::QueryReturnedNoRows)
        }
    }

    pub async fn add_key_to_keys(&self, auth_key: &AuthKey) -> Result<usize, rusqlite::Error> {
        let conn = self.pool.get().unwrap();

        conn.execute(
            "INSERT INTO keys (key, valid_until) VALUES (?1, ?2)",
            &[
                auth_key.key.to_string(),
                auth_key.valid_until.unwrap().to_string(),
            ],
        )
        .map_err(trace_debug)
        .and_then(validate_updated)
    }

    pub async fn remove_key_from_keys(&self, key: String) -> Result<usize, rusqlite::Error> {
        let conn = self.pool.get().unwrap();
        conn.execute("DELETE FROM keys WHERE key = ?", &[key])
            .map_err(trace_debug)
            .and_then(validate_updated)
    }
}

fn trace_debug<T: std::fmt::Debug>(value: T) -> T {
    debug!("{:?}", value);
    value
}

fn validate_updated(updated: usize) -> Result<usize, rusqlite::Error> {
    if updated > 0 {
        Ok(updated)
    } else {
        Err(rusqlite::Error::ExecuteReturnedResults)
    }
}
