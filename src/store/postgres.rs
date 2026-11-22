//! PostgreSQL 存储实现（feature `postgres` 启用时编译）。
//!
//! 与 SQLite 的差异（对齐 Go `pkg/database/postgres.go`）：
//! - 主键用 `SERIAL`（`rowid SERIAL`）
//! - 连接池参数：max 10 / min 2 / acquire 5min / idle 1min

#![cfg(feature = "postgres")]

use std::{str::FromStr, time::Duration};

use sqlx::{
    Row,
    postgres::{PgConnectOptions, PgPool, PgPoolOptions},
};
use uuid::Uuid;

use crate::models::{AcmeTxt, AcmeTxtPost, CidrSlice, new_acme_txt, sanitize_string};
use crate::store::{AccountRow, DB_VERSION, Store, StoreError, with_read_timeout, with_timeout};

pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    /// 连接池参数对齐 Go 版：MaxOpenConns 10 / MaxIdleConns 2 / ConnMaxLifetime 5min / ConnMaxIdleTime 1min。
    pub async fn new(connection: &str) -> Result<Self, StoreError> {
        let opts =
            PgConnectOptions::from_str(connection).map_err(|e| StoreError::Db(e.to_string()))?;
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .min_connections(2)
            .acquire_timeout(Duration::from_secs(5 * 60))
            .idle_timeout(Duration::from_secs(60))
            .max_lifetime(Duration::from_secs(5 * 60))
            .connect_with(opts)
            .await
            .map_err(|e| StoreError::Db(e.to_string()))?;
        let store = Self { pool };
        store.init_schema().await?;
        Ok(store)
    }

    async fn init_schema(&self) -> Result<(), StoreError> {
        sqlx::query("CREATE TABLE IF NOT EXISTS acmedns (Name TEXT, Value TEXT)")
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS records (
                Username TEXT UNIQUE NOT NULL PRIMARY KEY,
                Password TEXT UNIQUE NOT NULL,
                Subdomain TEXT UNIQUE NOT NULL,
                AllowFrom TEXT
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS txt (
                rowid SERIAL PRIMARY KEY,
                Subdomain TEXT NOT NULL,
                Value TEXT NOT NULL DEFAULT '',
                LastUpdate INTEGER
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_txt_subdomain ON txt (Subdomain)")
            .execute(&self.pool)
            .await
            .map_err(db_err)?;

        // db_version 初始化
        let row = sqlx::query("SELECT Value FROM acmedns WHERE Name='db_version'")
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        if row.is_none() {
            sqlx::query("INSERT INTO acmedns (Name, Value) VALUES ('db_version', $1)")
                .bind(DB_VERSION.to_string())
                .execute(&self.pool)
                .await
                .map_err(db_err)?;
        }
        Ok(())
    }
}

fn db_err(e: sqlx::Error) -> StoreError {
    StoreError::Db(e.to_string())
}

#[async_trait::async_trait]
impl Store for PostgresStore {
    async fn register(&self, allow_from: CidrSlice) -> Result<(AcmeTxt, String), StoreError> {
        self.register_with_subdomain(allow_from, None).await
    }

    /// 带可选自定义子域的注册（管理端使用）。
    async fn register_with_subdomain(
        &self,
        allow_from: CidrSlice,
        subdomain: Option<&str>,
    ) -> Result<(AcmeTxt, String), StoreError> {
        let requested = subdomain.map(sanitize_string);
        with_timeout(async move {
            let (mut account, plain) = new_acme_txt();
            account.allow_from = CidrSlice(allow_from.valid_entries());
            if let Some(s) = requested {
                if s.is_empty() {
                    return Err(StoreError::Db("invalid subdomain".into()));
                }
                let exists: Option<String> =
                    sqlx::query("SELECT Subdomain FROM records WHERE Subdomain = $1 LIMIT 1")
                        .bind(&s)
                        .fetch_optional(&self.pool)
                        .await
                        .map_err(db_err)?
                        .and_then(|r| r.try_get::<String, _>(0).ok());
                if exists.is_some() {
                    return Err(StoreError::SubdomainExists(s));
                }
                account.subdomain = s;
            }
            let hash = bcrypt::hash(&plain, 10).map_err(|e| StoreError::Db(e.to_string()))?;
            let allow_json = CidrSlice(allow_from.valid_entries()).to_json();
            let mut tx = self.pool.begin().await.map_err(db_err)?;
            sqlx::query("INSERT INTO records (Username, Password, Subdomain, AllowFrom) VALUES ($1,$2,$3,$4)")
                .bind(account.username.to_string())
                .bind(&hash)
                .bind(&account.subdomain)
                .bind(&allow_json)
                .execute(&mut *tx).await.map_err(db_err)?;
            for _ in 0..2 {
                sqlx::query("INSERT INTO txt (Subdomain, LastUpdate) VALUES ($1, 0)")
                    .bind(&account.subdomain)
                    .execute(&mut *tx).await.map_err(db_err)?;
            }
            tx.commit().await.map_err(db_err)?;
            Ok((account, plain))
        }).await
    }

    async fn get_by_username(&self, username: Uuid) -> Result<AcmeTxt, StoreError> {
        with_timeout(async move {
            let row = sqlx::query("SELECT Username, Password, Subdomain, AllowFrom FROM records WHERE Username=$1 LIMIT 1")
                .bind(username.to_string())
                .fetch_optional(&self.pool).await.map_err(db_err)?
                .ok_or_else(|| StoreError::UserNotFound(username.to_string()))?;
            let uname: String = row.try_get(0).map_err(db_err)?;
            let hash: String = row.try_get(1).map_err(db_err)?;
            let subdomain: String = row.try_get(2).map_err(db_err)?;
            let allow: String = row.try_get(3).map_err(db_err).unwrap_or_else(|_| "[]".into());
            Ok(AcmeTxt {
                username: Uuid::parse_str(&uname).map_err(|e| StoreError::Db(e.to_string()))?,
                password_hash: hash,
                subdomain,
                allow_from: CidrSlice::from_json(&allow),
            })
        }).await
    }

    async fn get_txt_for_domain(&self, subdomain: &str) -> Result<Vec<String>, StoreError> {
        let domain = sanitize_string(subdomain);
        with_read_timeout(async move {
            let rows = sqlx::query("SELECT Value FROM txt WHERE Subdomain=$1 LIMIT 2")
                .bind(&domain)
                .fetch_all(&self.pool)
                .await
                .map_err(db_err)?;
            Ok(rows
                .into_iter()
                .filter_map(|r| r.try_get::<String, _>(0).ok())
                .collect())
        })
        .await
    }

    async fn update(&self, post: &AcmeTxtPost) -> Result<(), StoreError> {
        let subdomain = post.subdomain.clone();
        let value = post.value.clone();
        with_timeout(async move {
            let now = chrono::Utc::now().timestamp();
            sqlx::query(
                "UPDATE txt SET Value=$1, LastUpdate=$2 WHERE rowid = (
                    SELECT rowid FROM txt WHERE Subdomain=$3 ORDER BY LastUpdate LIMIT 1
                )",
            )
            .bind(&value)
            .bind(now)
            .bind(&subdomain)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
            Ok(())
        })
        .await
    }

    async fn close(&self) {
        self.pool.close().await;
    }
}

impl PostgresStore {
    async fn account_row(&self, username: Uuid) -> Result<AccountRow, StoreError> {
        let row = sqlx::query(
            "SELECT Username, Subdomain, AllowFrom FROM records WHERE Username = $1 LIMIT 1",
        )
        .bind(username.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?
        .ok_or_else(|| StoreError::UserNotFound(username.to_string()))?;
        let uname: String = row.try_get(0).map_err(db_err)?;
        let subdomain: String = row.try_get(1).map_err(db_err)?;
        let allow: String = row
            .try_get(2)
            .map_err(db_err)
            .unwrap_or_else(|_| "[]".into());
        let txt = self.get_txt_for_domain(&subdomain).await?;
        let (last_update, created_at) = sqlx::query_as::<_, (Option<i64>, Option<i64>)>(
            "SELECT MAX(CASE WHEN Value != '' THEN LastUpdate END), MIN(LastUpdate) FROM txt WHERE Subdomain = $1",
        )
        .bind(&subdomain)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(AccountRow {
            username: Uuid::parse_str(&uname).map_err(|e| StoreError::Db(e.to_string()))?,
            subdomain,
            allow_from: CidrSlice::from_json(&allow),
            txt,
            last_update,
            created_at,
        })
    }

    async fn list_accounts(&self) -> Result<Vec<AccountRow>, StoreError> {
        with_timeout(async {
            let rows: Vec<String> = sqlx::query("SELECT Username FROM records ORDER BY rowid")
                .fetch_all(&self.pool)
                .await
                .map_err(db_err)?
                .into_iter()
                .filter_map(|r| r.try_get::<String, _>(0).ok())
                .collect();
            let mut out = Vec::with_capacity(rows.len());
            for u in rows {
                let uuid = Uuid::parse_str(&u).map_err(|e| StoreError::Db(e.to_string()))?;
                out.push(self.account_row(uuid).await?);
            }
            Ok(out)
        })
        .await
    }

    async fn get_by_subdomain(&self, subdomain: &str) -> Result<AccountRow, StoreError> {
        let sub = sanitize_string(subdomain);
        with_timeout(async move {
            let uname: Option<String> =
                sqlx::query("SELECT Username FROM records WHERE Subdomain = $1 LIMIT 1")
                    .bind(&sub)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(db_err)?
                    .and_then(|r| r.try_get::<String, _>(0).ok());
            match uname {
                Some(u) => {
                    let uuid = Uuid::parse_str(&u).map_err(|e| StoreError::Db(e.to_string()))?;
                    self.account_row(uuid).await
                }
                None => Err(StoreError::SubdomainNotFound(sub)),
            }
        })
        .await
    }

    async fn delete_account(&self, username: Uuid) -> Result<(), StoreError> {
        with_timeout(async move {
            let mut tx = self.pool.begin().await.map_err(db_err)?;
            let subdomain: Option<String> =
                sqlx::query("SELECT Subdomain FROM records WHERE Username = $1")
                    .bind(username.to_string())
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(db_err)?
                    .and_then(|r| r.try_get::<String, _>(0).ok());
            match subdomain {
                Some(sub) => {
                    sqlx::query("DELETE FROM txt WHERE Subdomain = $1")
                        .bind(&sub)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                    sqlx::query("DELETE FROM records WHERE Username = $1")
                        .bind(username.to_string())
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                    tx.commit().await.map_err(db_err)
                }
                None => Err(StoreError::UserNotFound(username.to_string())),
            }
        })
        .await
    }

    async fn update_allow_from(
        &self,
        username: Uuid,
        allow_from: CidrSlice,
    ) -> Result<(), StoreError> {
        let json = CidrSlice(allow_from.valid_entries()).to_json();
        with_timeout(async move {
            let res = sqlx::query("UPDATE records SET AllowFrom = $1 WHERE Username = $2")
                .bind(&json)
                .bind(username.to_string())
                .execute(&self.pool)
                .await
                .map_err(db_err)?;
            if res.rows_affected() == 0 {
                return Err(StoreError::UserNotFound(username.to_string()));
            }
            Ok(())
        })
        .await
    }

    async fn reset_password(&self, username: Uuid) -> Result<String, StoreError> {
        with_timeout(async move {
            let new_password = crate::models::generate_password(40);
            let hash =
                bcrypt::hash(&new_password, 10).map_err(|e| StoreError::Db(e.to_string()))?;
            let res = sqlx::query("UPDATE records SET Password = $1 WHERE Username = $2")
                .bind(&hash)
                .bind(username.to_string())
                .execute(&self.pool)
                .await
                .map_err(db_err)?;
            if res.rows_affected() == 0 {
                return Err(StoreError::UserNotFound(username.to_string()));
            }
            Ok(new_password)
        })
        .await
    }

    async fn set_txt(&self, subdomain: &str, v1: &str, v2: &str) -> Result<(), StoreError> {
        let sub = sanitize_string(subdomain);
        with_timeout(async move {
            let now = chrono::Utc::now().timestamp();
            let mut tx = self.pool.begin().await.map_err(db_err)?;
            let rows: Vec<i32> =
                sqlx::query("SELECT rowid FROM txt WHERE Subdomain = $1 ORDER BY LastUpdate")
                    .bind(&sub)
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(db_err)?
                    .into_iter()
                    .filter_map(|r| r.try_get::<i32, _>(0).ok())
                    .collect();
            if rows.is_empty() {
                return Err(StoreError::SubdomainNotFound(sub));
            }
            for (i, rowid) in rows.iter().enumerate() {
                let val = match i {
                    0 => v1,
                    1 => v2,
                    _ => "",
                };
                sqlx::query("UPDATE txt SET Value = $1, LastUpdate = $2 WHERE rowid = $3")
                    .bind(val)
                    .bind(now + i as i64)
                    .bind(rowid)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
            }
            tx.commit().await.map_err(db_err)
        })
        .await
    }
}
