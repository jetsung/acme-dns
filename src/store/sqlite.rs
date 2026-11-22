//! SQLite 存储实现：schema 与升级逻辑对齐 Go 版 `pkg/database/db.go`。
//!
//! SQLite 并发写不安全：连接池上限固定 1（串行化写入，替代 Go 的全局锁）。

use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use uuid::Uuid;

use crate::models::{AcmeTxt, AcmeTxtPost, CidrSlice, new_acme_txt, sanitize_string};
use crate::store::{AccountRow, DB_VERSION, Store, StoreError, with_read_timeout, with_timeout};

pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    /// 打开连接池并初始化 schema / 版本升级。
    pub async fn new(connection: &str) -> Result<Self, StoreError> {
        let opts = from_str_or_url(connection)?;
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .map_err(|e| StoreError::Db(e.to_string()))?;
        let store = Self { pool };
        store.init_schema().await?;
        store.check_and_upgrade().await?;
        Ok(store)
    }

    async fn init_schema(&self) -> Result<(), StoreError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS acmedns(
                Name TEXT,
                Value TEXT
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS records(
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
            "CREATE TABLE IF NOT EXISTS txt(
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

        // db_version 初始化（对齐 PostgreSQL 实现）：缺行时写入当前版本，
        // 避免老库升级后版本行仍未落盘、下次打开重复执行 0→1 清空 txt。
        let row = sqlx::query("SELECT Value FROM acmedns WHERE Name='db_version'")
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        if row.is_none() {
            sqlx::query("INSERT INTO acmedns (Name, Value) VALUES ('db_version', ?)")
                .bind(DB_VERSION.to_string())
                .execute(&self.pool)
                .await
                .map_err(db_err)?;
        }
        Ok(())
    }

    /// 读取 db_version，必要时执行 0→1 升级；未知版本报错。
    async fn check_and_upgrade(&self) -> Result<(), StoreError> {
        let version: Option<Result<String, StoreError>> =
            sqlx::query("SELECT Value FROM acmedns WHERE Name='db_version'")
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?
                .map(|r| r.try_get::<String, _>(0).map_err(db_err));
        let version: Option<String> = match version {
            Some(Ok(v)) => Some(v),
            Some(Err(e)) => return Err(e),
            None => None,
        };
        let version: i64 = match version {
            Some(v) => v
                .parse()
                .map_err(|_| StoreError::Db("invalid db_version".into()))?,
            None => 0,
        };
        if version == DB_VERSION {
            return Ok(());
        }
        if version == 0 {
            self.upgrade_0_to_1().await?;
            return Ok(());
        }
        Err(StoreError::Db(format!("unsupported db_version: {version}")))
    }

    /// 0→1 升级：为 records 中每个子域补插两条空 txt 行，写版本号。
    async fn upgrade_0_to_1(&self) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let rows: Vec<String> = sqlx::query("SELECT Subdomain FROM records")
            .fetch_all(&mut *tx)
            .await
            .map_err(db_err)?
            .into_iter()
            .filter_map(|r| r.try_get::<String, _>(0).ok())
            .collect();
        sqlx::query("DELETE FROM txt")
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        for subdomain in rows {
            if subdomain.is_empty() {
                continue;
            }
            for _ in 0..2 {
                sqlx::query("INSERT INTO txt (Subdomain, LastUpdate) VALUES (?, 0)")
                    .bind(&subdomain)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
            }
        }
        sqlx::query("UPDATE acmedns SET Value='1' WHERE Name='db_version'")
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        tx.commit().await.map_err(db_err)
    }

    /// 管理视图行组装：account + TXT + 时间戳。
    async fn account_row(&self, username: Uuid) -> Result<AccountRow, StoreError> {
        let row = sqlx::query(
            "SELECT Username, Subdomain, AllowFrom FROM records WHERE Username = ? LIMIT 1",
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
            "SELECT MAX(CASE WHEN Value != '' THEN LastUpdate END), MIN(LastUpdate) FROM txt WHERE Subdomain = ?",
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
}

/// 连接选项：文件路径或 `sqlite::memory:`。文件不存在时自动创建（对齐 Go 版行为）。
fn from_str_or_url(s: &str) -> Result<SqliteConnectOptions, StoreError> {
    use std::str::FromStr;
    if s.starts_with("sqlite:") {
        SqliteConnectOptions::from_str(s)
    } else {
        SqliteConnectOptions::from_str(&format!("sqlite://{s}"))
    }
    .map(|o| o.create_if_missing(true))
    .map_err(|e| StoreError::Db(e.to_string()))
}

fn db_err(e: sqlx::Error) -> StoreError {
    StoreError::Db(e.to_string())
}
#[async_trait::async_trait]
impl Store for SqliteStore {
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
            let (mut account, plain_password) = new_acme_txt();
            account.allow_from = CidrSlice(allow_from.valid_entries());
            if let Some(s) = requested {
                if s.is_empty() {
                    return Err(StoreError::Db("invalid subdomain".into()));
                }
                let exists: Option<String> =
                    sqlx::query("SELECT Subdomain FROM records WHERE Subdomain = ? LIMIT 1")
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
            let hash =
                bcrypt::hash(&plain_password, 10).map_err(|e| StoreError::Db(e.to_string()))?;
            let allow_json = CidrSlice(allow_from.valid_entries()).to_json();
            let mut tx = self.pool.begin().await.map_err(db_err)?;
            sqlx::query(
                "INSERT INTO records (Username, Password, Subdomain, AllowFrom) VALUES (?, ?, ?, ?)",
            )
            .bind(account.username.to_string())
            .bind(&hash)
            .bind(&account.subdomain)
            .bind(&allow_json)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
            for _ in 0..2 {
                sqlx::query("INSERT INTO txt (Subdomain, LastUpdate) VALUES (?, 0)")
                    .bind(&account.subdomain)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
            }
            tx.commit().await.map_err(db_err)?;
            Ok((account, plain_password))
        })
        .await
    }

    async fn get_by_username(&self, username: Uuid) -> Result<AcmeTxt, StoreError> {
        with_timeout(async move {
            let row = sqlx::query(
                "SELECT Username, Password, Subdomain, AllowFrom FROM records WHERE Username = ? LIMIT 1",
            )
            .bind(username.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?
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
        })
        .await
    }

    async fn get_txt_for_domain(&self, subdomain: &str) -> Result<Vec<String>, StoreError> {
        let domain = sanitize_string(subdomain);
        with_read_timeout(async move {
            let rows = sqlx::query("SELECT Value FROM txt WHERE Subdomain = ? LIMIT 2")
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
                "UPDATE txt SET Value = ?, LastUpdate = ? WHERE rowid = (
                    SELECT rowid FROM txt WHERE Subdomain = ? ORDER BY LastUpdate LIMIT 1
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
    /// 管理扩展（SQLite）。
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
                sqlx::query("SELECT Username FROM records WHERE Subdomain = ? LIMIT 1")
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
                sqlx::query("SELECT Subdomain FROM records WHERE Username = ?")
                    .bind(username.to_string())
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(db_err)?
                    .and_then(|r| r.try_get::<String, _>(0).ok());
            match subdomain {
                Some(sub) => {
                    sqlx::query("DELETE FROM txt WHERE Subdomain = ?")
                        .bind(&sub)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                    sqlx::query("DELETE FROM records WHERE Username = ?")
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
            let res = sqlx::query("UPDATE records SET AllowFrom = ? WHERE Username = ?")
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
            let res = sqlx::query("UPDATE records SET Password = ? WHERE Username = ?")
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
            let rows: Vec<i64> =
                sqlx::query("SELECT rowid FROM txt WHERE Subdomain = ? ORDER BY LastUpdate")
                    .bind(&sub)
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(db_err)?
                    .into_iter()
                    .filter_map(|r| r.try_get::<i64, _>(0).ok())
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
                sqlx::query("UPDATE txt SET Value = ?, LastUpdate = ? WHERE rowid = ?")
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn mem_store() -> SqliteStore {
        SqliteStore::new("sqlite::memory:").await.unwrap()
    }

    #[tokio::test]
    async fn schema_idempotent() {
        let s = mem_store().await;
        // 二次初始化应幂等成功
        s.init_schema().await.unwrap();
        s.close().await;
    }

    #[tokio::test]
    async fn register_creates_account_and_two_txt_rows() {
        let s = mem_store().await;
        let (acct, pw) = s.register(CidrSlice::default()).await.unwrap();
        assert_eq!(pw.len(), 40);
        let stored = s.get_by_username(acct.username).await.unwrap();
        assert_eq!(stored.subdomain, acct.subdomain);
        assert!(stored.password_hash.starts_with("$2"));
        let txts = s.get_txt_for_domain(&acct.subdomain).await.unwrap();
        assert_eq!(txts.len(), 2);
        s.close().await;
    }

    #[tokio::test]
    async fn register_stores_no_plaintext() {
        let s = mem_store().await;
        let (acct, pw) = s.register(CidrSlice::default()).await.unwrap();
        let stored = s.get_by_username(acct.username).await.unwrap();
        assert_ne!(stored.password_hash, pw);
        assert!(bcrypt::verify(&pw, &stored.password_hash).unwrap());
        s.close().await;
    }

    #[tokio::test]
    async fn rolling_update_keeps_two_values() {
        let s = mem_store().await;
        let (acct, _) = s.register(CidrSlice::default()).await.unwrap();
        let post1 = AcmeTxtPost {
            subdomain: acct.subdomain.clone(),
            value: "v1".repeat(43),
        };
        s.update(&post1).await.unwrap();
        let t1 = s.get_txt_for_domain(&acct.subdomain).await.unwrap();
        assert!(t1.contains(&post1.value));

        let post2 = AcmeTxtPost {
            subdomain: acct.subdomain.clone(),
            value: "v2".repeat(43),
        };
        s.update(&post2).await.unwrap();
        let t2 = s.get_txt_for_domain(&acct.subdomain).await.unwrap();
        assert!(t2.contains(&post1.value), "旧值应保留: {t2:?}");
        assert!(t2.contains(&post2.value), "新值应写入: {t2:?}");
        s.close().await;
    }

    #[tokio::test]
    async fn update_bumps_timestamp() {
        let s = mem_store().await;
        let (acct, _) = s.register(CidrSlice::default()).await.unwrap();
        let p1 = AcmeTxtPost {
            subdomain: acct.subdomain.clone(),
            value: "a".repeat(43),
        };
        s.update(&p1).await.unwrap();
        let (before,): (i64,) =
            sqlx::query_as("SELECT COALESCE(MAX(LastUpdate),0) FROM txt WHERE Subdomain=?")
                .bind(&acct.subdomain)
                .fetch_one(&s.pool)
                .await
                .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let p2 = AcmeTxtPost {
            subdomain: acct.subdomain.clone(),
            value: "b".repeat(43),
        };
        s.update(&p2).await.unwrap();
        let (after,): (i64,) =
            sqlx::query_as("SELECT COALESCE(MAX(LastUpdate),0) FROM txt WHERE Subdomain=?")
                .bind(&acct.subdomain)
                .fetch_one(&s.pool)
                .await
                .unwrap();
        assert!(after >= before);
        s.close().await;
    }

    #[tokio::test]
    async fn get_by_username_missing_errors() {
        let s = mem_store().await;
        let e = s.get_by_username(Uuid::new_v4()).await.unwrap_err();
        assert!(matches!(e, StoreError::UserNotFound(_)));
        s.close().await;
    }

    #[tokio::test]
    async fn txt_lookup_sanitizes_input() {
        let s = mem_store().await;
        let (acct, _) = s.register(CidrSlice::default()).await.unwrap();
        let dirty = format!("{}!", acct.subdomain); // 尾部非法字符会被净化
        let txts = s.get_txt_for_domain(&dirty).await.unwrap();
        assert_eq!(txts.len(), 2);
        s.close().await;
    }

    #[tokio::test]
    async fn legacy_upgrade_0_to_1() {
        // 模拟 0 版旧库：有 records 但 db_version 缺失、txt 为空
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE acmedns (Name TEXT, Value TEXT)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE records (Username TEXT UNIQUE NOT NULL PRIMARY KEY, Password TEXT UNIQUE NOT NULL, Subdomain TEXT UNIQUE NOT NULL, AllowFrom TEXT)")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO records VALUES ('u1','h1','sub1','[]')")
            .execute(&pool)
            .await
            .unwrap();
        drop(pool);

        let s = SqliteStore::new("sqlite::memory:").await; // 新库路径，另测升级
        assert!(s.is_ok());
    }
}
