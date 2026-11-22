//! 自身证书 ACME 挑战应答（对齐 Go `pkg/nameserver/validation.go`）。
//!
//! 当 acme-dns 自身证书走 DNS-01 时，LET'S ENCRYPT 查询 `_acme-challenge.<own-domain>`，
//! 此处用 `Arc<RwLock<Option<String>>>` 保存挑战 key，应答 TTL=1 的单条 TXT。

use std::sync::Arc;

use tokio::sync::RwLock;

/// 自身挑战 key 容器。
#[derive(Debug, Clone, Default)]
pub struct OwnAuthKey {
    inner: Arc<RwLock<Option<String>>>,
}

impl OwnAuthKey {
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置挑战 key（Present 阶段）。
    pub async fn set(&self, key: &str) {
        *self.inner.write().await = Some(key.to_string());
    }

    /// 清空挑战 key（CleanUp 阶段）。
    pub async fn clear(&self) {
        *self.inner.write().await = None;
    }

    /// 读取当前挑战 key。
    pub async fn get(&self) -> Option<String> {
        self.inner.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc as StdArc;

    #[tokio::test]
    async fn set_and_get() {
        let k = OwnAuthKey::new();
        assert!(k.get().await.is_none());
        k.set("token123").await;
        assert_eq!(k.get().await.as_deref(), Some("token123"));
        k.clear().await;
        assert!(k.get().await.is_none());
    }

    #[tokio::test]
    async fn concurrent_set_get_thread_safe() {
        let k = StdArc::new(OwnAuthKey::new());
        let w = k.clone();
        let h = tokio::spawn(async move {
            w.set("abc").await;
        });
        h.await.unwrap();
        assert_eq!(k.get().await.as_deref(), Some("abc"));
        let w2 = k.clone();
        let h2 = tokio::spawn(async move {
            w2.clear().await;
        });
        h2.await.unwrap();
        assert!(k.get().await.is_none());
    }
}
