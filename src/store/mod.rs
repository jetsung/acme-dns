//! 存储层：账户与 TXT 记录持久化抽象。
//!
//! 对齐 Go 版 `pkg/acmedns/interfaces.go` 的 `AcmednsDB`；
//! 超时语义对齐 Go 版：一般操作 20s，DNS 热路径读 5s。

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod sqlite;
use std::time::Duration;

use uuid::Uuid;

use crate::models::{AcmeTxt, AcmeTxtPost, CidrSlice};

/// 一般数据库操作超时。
pub const DB_TIMEOUT: Duration = Duration::from_secs(20);
/// DNS 热路径读超时。
pub const DB_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// 当前数据库版本（对齐 Go `DBVersion`）。
pub const DB_VERSION: i64 = 1;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("user not found: {0}")]
    UserNotFound(String),
    #[error("subdomain not found: {0}")]
    SubdomainNotFound(String),
    #[error("subdomain already exists: {0}")]
    SubdomainExists(String),
    #[error("database error: {0}")]
    Db(String),
    #[error("timeout")]
    Timeout,
}

/// 管理端账户视图：不携带口令哈希。
#[derive(Debug, Clone, PartialEq)]
pub struct AccountRow {
    pub username: Uuid,
    pub subdomain: String,
    pub allow_from: CidrSlice,
    pub txt: Vec<String>,
    pub last_update: Option<i64>,
    pub created_at: Option<i64>,
}

impl AccountRow {
    /// 完整域名 = 子域 + 服务域。
    pub fn fulldomain(&self, domain: &str) -> String {
        format!("{}.{}", self.subdomain, domain)
    }
}

/// 账户存储抽象。基础方法对齐 Go 版 `AcmednsDB`；管理方法为 Rust 版扩展。
#[async_trait::async_trait]
pub trait Store: Send + Sync {
    /// 注册新账户：生成凭据、bcrypt 哈希、双 TXT 空行，事务内完成。
    /// 返回账户与一次性明文密码。
    async fn register(&self, allow_from: CidrSlice) -> Result<(AcmeTxt, String), StoreError>;

    /// 注册新账户，可指定自定义子域（管理端使用）。
    async fn register_with_subdomain(
        &self,
        allow_from: CidrSlice,
        subdomain: Option<&str>,
    ) -> Result<(AcmeTxt, String), StoreError> {
        let _ = (allow_from, subdomain);
        Err(StoreError::Db(
            "register_with_subdomain not implemented".into(),
        ))
    }

    /// 按 UUID 用户名查询账户。
    async fn get_by_username(&self, username: uuid::Uuid) -> Result<AcmeTxt, StoreError>;

    /// 按子域查询 TXT 值（至多两条）；入参先净化。
    async fn get_txt_for_domain(&self, subdomain: &str) -> Result<Vec<String>, StoreError>;

    /// 滚动更新：新值写入 LastUpdate 最早的一行。
    async fn update(&self, post: &AcmeTxtPost) -> Result<(), StoreError>;

    /// 关闭连接池。
    async fn close(&self);

    // ---- 管理扩展（Rust 版新增，不改变基础契约）----

    /// 列出全部账户（管理视图，含当前 TXT）。
    async fn list_accounts(&self) -> Result<Vec<AccountRow>, StoreError> {
        Err(StoreError::Db("list_accounts not implemented".into()))
    }

    /// 按子域查询单个账户（管理视图）。
    async fn get_by_subdomain(&self, subdomain: &str) -> Result<AccountRow, StoreError> {
        let _ = subdomain;
        Err(StoreError::Db("get_by_subdomain not implemented".into()))
    }

    /// 删除账户及其 TXT 行。
    async fn delete_account(&self, username: uuid::Uuid) -> Result<(), StoreError> {
        let _ = username;
        Err(StoreError::Db("delete_account not implemented".into()))
    }

    /// 更新账户 CIDR 白名单。
    async fn update_allow_from(
        &self,
        username: uuid::Uuid,
        allow_from: CidrSlice,
    ) -> Result<(), StoreError> {
        let _ = (username, allow_from);
        Err(StoreError::Db("update_allow_from not implemented".into()))
    }

    /// 重置账户密码：返回新明文密码（库中存 bcrypt 哈希）。
    async fn reset_password(&self, username: uuid::Uuid) -> Result<String, StoreError> {
        let _ = username;
        Err(StoreError::Db("reset_password not implemented".into()))
    }

    /// 管理式设置 TXT：写入两条记录（v1, v2），并更新时间戳。
    async fn set_txt(&self, subdomain: &str, v1: &str, v2: &str) -> Result<(), StoreError> {
        let _ = (subdomain, v1, v2);
        Err(StoreError::Db("set_txt not implemented".into()))
    }
}

/// 带超时地执行未来（一般操作 20s）。
pub async fn with_timeout<F, T>(fut: F) -> Result<T, StoreError>
where
    F: Future<Output = Result<T, StoreError>>,
{
    tokio::time::timeout(DB_TIMEOUT, fut)
        .await
        .map_err(|_| StoreError::Timeout)?
}

/// 带超时地执行未来（DNS 热路径 5s）。
pub async fn with_read_timeout<F, T>(fut: F) -> Result<T, StoreError>
where
    F: Future<Output = Result<T, StoreError>>,
{
    tokio::time::timeout(DB_READ_TIMEOUT, fut)
        .await
        .map_err(|_| StoreError::Timeout)?
}
