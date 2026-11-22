//! API 共享状态与鉴权中间件（对齐 Go `pkg/api/auth.go`）。

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::Extensions;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::Response;

use crate::dnsserver::own_auth::OwnAuthKey;
use crate::models::{AcmeTxt, AcmeTxtPost, AppConfig};
use crate::store::Store;

use super::util::{dummy_password_check, get_valid_username, valid_key};

/// 请求中传递已鉴权账户与解析出的 POST 数据。
#[derive(Debug, Clone)]
pub struct AuthedUpdate {
    pub user: AcmeTxt,
    pub post: AcmeTxtPost,
}

/// API 共享状态。
#[derive(Clone)]
pub struct ApiState {
    pub db: Arc<dyn Store>,
    pub config: Arc<AppConfig>,
    pub own_auth_key: Arc<OwnAuthKey>,
}

/// 鉴权中间件：校验 `X-Api-User`/`X-Api-Key`、来源 IP 与 subdomain 一致性。
pub async fn auth_middleware(
    State(state): State<ApiState>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let (mut parts, body) = req.into_parts();
    // use_header 模式：把指定头的 IP 列表注入扩展，供 update_allowed_from_ip 使用
    if state.config.api.use_header {
        let ips = parts
            .headers
            .get(state.config.api.header_name.as_str())
            .and_then(|v| v.to_str().ok())
            .map(super::util::ip_list_from_header)
            .unwrap_or_default();
        parts.extensions.insert(ClientIps(ips));
    }
    let authed = match authenticate(&state, &mut parts, body).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    parts.extensions.insert(authed);
    let req = axum::extract::Request::from_parts(parts, Body::empty());
    next.run(req).await
}

/// use_header 模式下从请求头解析出的客户端 IP 列表。
#[derive(Debug, Clone)]
pub struct ClientIps(pub Vec<String>);

/// 完整鉴权流程：成功返回待更新数据，失败返回 401 响应。
#[allow(clippy::result_large_err)]
pub async fn authenticate(
    state: &ApiState,
    parts: &mut Parts,
    body: Body,
) -> Result<AuthedUpdate, Response> {
    let unauthorized =
        || axum::response::IntoResponse::into_response(crate::error::AppError::Forbidden);

    let uname = parts
        .headers
        .get("X-Api-User")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let passwd = parts
        .headers
        .get("X-Api-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let username = match get_valid_username(uname) {
        Some(u) => u,
        None => {
            tracing::error!(username = %uname, "invalid username");
            return Err(unauthorized());
        }
    };
    if !valid_key(passwd) {
        tracing::error!(username = %uname, "invalid key");
        return Err(unauthorized());
    }

    let user = match state.db.get_by_username(username).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "Error while trying to get user");
            // 恒定时间虚拟校验防计时侧信道
            dummy_password_check(passwd);
            return Err(unauthorized());
        }
    };
    if !super::util::correct_password(passwd, &user.password_hash) {
        tracing::error!(username = %uname, "invalid password");
        return Err(unauthorized());
    }

    if !update_allowed_from_ip(state, &parts.extensions, &user) {
        tracing::error!("Update not allowed from IP");
        return Err(unauthorized());
    }

    // 解析 JSON body 并校验 subdomain 匹配
    let body_bytes = match axum::body::to_bytes(body, 1 << 20).await {
        Ok(b) => b,
        Err(_) => return Err(unauthorized()),
    };
    let post: AcmeTxtPost = if body_bytes.is_empty() {
        return Err(unauthorized());
    } else {
        match serde_json::from_slice(&body_bytes) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = %e, "Decoding error");
                return Err(unauthorized());
            }
        }
    };
    if user.subdomain != post.subdomain {
        tracing::error!(
            name = %post.subdomain,
            expected = %user.subdomain,
            "Subdomain mismatch"
        );
        return Err(unauthorized());
    }
    Ok(AuthedUpdate { user, post })
}

/// 来源 IP 判定：use_header 时从 ClientIps 扩展匹配，否则取 RemoteAddr。
fn update_allowed_from_ip(state: &ApiState, ext: &Extensions, user: &AcmeTxt) -> bool {
    if state.config.api.use_header {
        let ips = ext
            .get::<ClientIps>()
            .map(|c| c.0.clone())
            .unwrap_or_default();
        return user.allow_from.allows_any(&ips);
    }
    let remote = ext
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip().to_string())
        .unwrap_or_default();
    user.allow_from.allows(&remote)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AcmeTxtPost, ApiConfig, AppConfig, CidrSlice, DbConfig, GeneralConfig, LogConfig,
    };
    use axum::http::HeaderName;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MemStore(Mutex<HashMap<String, AcmeTxt>>);
    impl MemStore {
        fn new() -> Self {
            Self(Mutex::new(HashMap::new()))
        }
        fn put(&self, u: AcmeTxt) {
            self.0.lock().unwrap().insert(u.username.to_string(), u);
        }
    }
    #[async_trait::async_trait]
    impl Store for MemStore {
        async fn register(
            &self,
            _a: CidrSlice,
        ) -> Result<(AcmeTxt, String), crate::store::StoreError> {
            Err(crate::store::StoreError::Db("x".into()))
        }
        async fn get_by_username(
            &self,
            u: uuid::Uuid,
        ) -> Result<AcmeTxt, crate::store::StoreError> {
            self.0
                .lock()
                .unwrap()
                .get(&u.to_string())
                .cloned()
                .ok_or(crate::store::StoreError::UserNotFound(u.to_string()))
        }
        async fn get_txt_for_domain(
            &self,
            _s: &str,
        ) -> Result<Vec<String>, crate::store::StoreError> {
            Ok(vec![])
        }
        async fn update(&self, _p: &AcmeTxtPost) -> Result<(), crate::store::StoreError> {
            Ok(())
        }
        async fn close(&self) {}
    }

    fn cfg_with_header() -> AppConfig {
        AppConfig {
            general: GeneralConfig {
                listen: "127.0.0.1:0".into(),
                protocol: "udp".into(),
                domain: "auth.example.org".into(),
                nsname: "n".into(),
                nsadmin: "a".into(),
                records: vec![],
                debug: false,
            },
            database: DbConfig {
                engine: "sqlite".into(),
                connection: ":memory:".into(),
            },
            api: ApiConfig {
                ip: "127.0.0.1".into(),
                port: "0".into(),
                tls: String::new(),
                tls_cert_privkey: String::new(),
                tls_cert_fullchain: String::new(),
                acme_cache_dir: "/tmp".into(),
                notification_email: String::new(),
                disable_registration: false,
                cors_origins: vec!["*".into()],
                use_header: true,
                header_name: "X-Forwarded-For".into(),
                hsts_enabled: false,
                hsts_max_age: 0,
                hsts_include_subdomains: false,
                hsts_preload: false,
                admin_token: String::new(),
            },
            log: LogConfig {
                level: "info".into(),
                logtype: "stdout".into(),
                logfile: String::new(),
                format: "text".into(),
            },
        }
    }

    fn user_with(subdomain: &str, cidrs: &[&str]) -> AcmeTxt {
        let (mut u, _) = crate::models::new_acme_txt();
        u.subdomain = subdomain.to_string();
        u.allow_from = CidrSlice(cidrs.iter().map(|s| s.to_string()).collect());
        u
    }

    /// 对齐 Go TestApiManyUpdateWithIpCheckHeaders 的核心判定矩阵。
    #[tokio::test]
    async fn header_ip_check_matrix() {
        let db = Arc::new(MemStore::new());
        let no_cidr = user_with("aaaaaaaa", &[]);
        let cidr4 = user_with("bbbbbbbb", &["192.168.1.2/32", "invalid"]);
        let cidr6 = user_with("cccccccc", &["2002:c0a8::0/32"]);
        db.put(no_cidr.clone());
        db.put(cidr4.clone());
        db.put(cidr6.clone());
        let state = ApiState {
            db,
            config: Arc::new(cfg_with_header()),
            own_auth_key: Arc::new(OwnAuthKey::new()),
        };

        let check = |user: &AcmeTxt, header: &str| {
            let mut parts = axum::http::Request::builder()
                .body(())
                .unwrap()
                .into_parts()
                .0;
            parts.headers.insert(
                HeaderName::from_static("x-forwarded-for"),
                header.parse().unwrap(),
            );
            parts
                .extensions
                .insert(ClientIps(super::super::util::ip_list_from_header(header)));
            update_allowed_from_ip(&state, &parts.extensions, user)
        };

        // 无 CIDR 用户任意 IP 允许
        assert!(check(&no_cidr, "whatever goes"));
        assert!(check(&no_cidr, "10.0.0.1, 1.2.3.4 ,3.4.5.6"));
        // CIDR 限定
        assert!(!check(&cidr4, "127.0.0.1"));
        assert!(!check(&cidr4, "10.0.0.1, 10.0.0.2, 192.168.1.3"));
        assert!(check(&cidr4, "10.1.1.1 ,192.168.1.2, 8.8.8.8"));
        assert!(check(&cidr6, "2002:c0a8:b4dc:0d3::0"));
        assert!(!check(&cidr6, "2002:c0a7:0ff::0"));
        assert!(check(&cidr6, "2002:c0a8:d3ad:b33f:c0ff:33b4:dc0d:3b4d"));
    }
}
