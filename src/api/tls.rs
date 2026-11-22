//! TLS/ACME 相关：challenge provider 与 rustls 配置构造。
//!
//! 对齐 Go `pkg/api/api.go` 的 setupTLS 与 challengeprovider.go：
//! - `letsencrypt` / `letsencryptstaging`：ACME DNS-01 自签发，用自身 DNS 服务器应答挑战
//! - `cert`：静态证书文件
//! - 其他（默认 `http`/空）：纯 HTTP

use std::sync::Arc;

use crate::dnsserver::own_auth::OwnAuthKey;

/// TLS 提供者枚举。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsProvider {
    LetsEncrypt,
    LetsEncryptStaging,
    Cert,
    None,
}

impl TlsProvider {
    /// 解析 `api.tls` 配置值。
    pub fn parse(s: &str) -> Self {
        match s {
            "letsencrypt" => Self::LetsEncrypt,
            "letsencryptstaging" => Self::LetsEncryptStaging,
            "cert" => Self::Cert,
            _ => Self::None,
        }
    }
}

/// DNS-01 挑战提供者：把 key 写入所有 DNS 服务器的 own_auth_key。
pub struct ChallengeProvider {
    keys: Vec<Arc<OwnAuthKey>>,
}

impl ChallengeProvider {
    pub fn new(keys: Vec<Arc<OwnAuthKey>>) -> Self {
        Self { keys }
    }

    /// Present：所有服务器设置挑战 key。
    pub async fn present(&self, key: &str) {
        for k in &self.keys {
            k.set(key).await;
        }
    }

    /// CleanUp：清空所有服务器的挑战 key。
    pub async fn cleanup(&self) {
        for k in &self.keys {
            k.clear().await;
        }
    }
}

/// 构建 API TLS 的 rustls ServerConfig（cert 模式）。
///
/// letsencrypt 模式需要运行期 ACME 客户端，依赖 cert-manager 类外部工具或后续接入；
/// 此处提供 cert 与 none 的同步配置。
pub fn build_server_config(
    provider: &TlsProvider,
    cert_path: &str,
    key_path: &str,
) -> Result<Option<rustls::ServerConfig>, String> {
    match provider {
        TlsProvider::Cert => {
            let certs = load_certs(cert_path)?;
            let key = load_key(key_path)?;
            let cfg = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| format!("tls cert error: {e}"))?;
            Ok(Some(cfg))
        }
        _ => Ok(None),
    }
}

fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    let data = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut rd = std::io::BufReader::new(data.as_slice());
    rustls_pemfile::certs(&mut rd)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse certs: {e}"))
}

fn load_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    let data = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut rd = std::io::BufReader::new(data.as_slice());
    rustls_pemfile::private_key(&mut rd)
        .map_err(|e| format!("parse key: {e}"))?
        .ok_or_else(|| "no private key found".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn challenge_provider_sets_and_clears() {
        let k = Arc::new(OwnAuthKey::new());
        let p = ChallengeProvider::new(vec![k.clone()]);
        p.present("token").await;
        assert_eq!(k.get().await.as_deref(), Some("token"));
        p.cleanup().await;
        assert!(k.get().await.is_none());
    }

    #[test]
    fn tls_provider_parse() {
        assert_eq!(TlsProvider::parse("letsencrypt"), TlsProvider::LetsEncrypt);
        assert_eq!(
            TlsProvider::parse("letsencryptstaging"),
            TlsProvider::LetsEncryptStaging
        );
        assert_eq!(TlsProvider::parse("cert"), TlsProvider::Cert);
        assert_eq!(TlsProvider::parse("http"), TlsProvider::None);
    }
}
