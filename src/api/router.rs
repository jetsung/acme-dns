//! API 路由组装：CORS、HSTS 中间件、路由注册（对齐 Go `Start` 的路由表）。

use std::sync::Arc;

use axum::Router;
use axum::http::{HeaderValue, Method};
use axum::middleware;
use axum::routing::{get, post};
use tower_http::cors::CorsLayer;

use crate::dnsserver::own_auth::OwnAuthKey;
use crate::models::AppConfig;
use crate::store::Store;

use super::auth::{ApiState, auth_middleware};
use super::health::health_check;
use super::register::web_register_post;
use super::update::web_update_post;

/// 构造带中间件的完整 API Router。
pub fn build_router(
    config: Arc<AppConfig>,
    db: Arc<dyn Store>,
    own_auth_key: Arc<OwnAuthKey>,
) -> Router {
    let state = ApiState {
        db,
        config: config.clone(),
        own_auth_key,
    };

    let mut app: axum::Router = Router::new()
        .route("/health", get(health_check))
        .route(
            "/update",
            post(web_update_post).route_layer(middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            )),
        )
        .with_state(state.clone());

    if !config.api.disable_registration {
        app = app.route(
            "/register",
            post(web_register_post).with_state(state.clone()),
        );
    }

    if let Some(admin) = super::admin::maybe_admin_router(&config, state.clone()) {
        app = app.nest("/admin", admin);
    }

    // HSTS 响应头中间件（对齐 Go hstsMiddleware）
    app.layer(cors_layer(&config))
        .layer(middleware::map_response(
            move |mut res: axum::response::Response| {
                if let Some(h) = hsts_header(&config) {
                    res.headers_mut().insert("Strict-Transport-Security", h);
                }
                async move { res }
            },
        ))
}

/// 计算 HSTS 头值；未启用时返回 None。
fn hsts_header(config: &AppConfig) -> Option<HeaderValue> {
    if !config.api.hsts_enabled {
        return None;
    }
    let max_age = if config.api.hsts_max_age <= 0 {
        31_536_000
    } else {
        config.api.hsts_max_age
    };
    let mut header = format!("max-age={max_age}");
    if config.api.hsts_include_subdomains {
        header.push_str("; includeSubDomains");
    }
    if config.api.hsts_preload {
        header.push_str("; preload");
    }
    HeaderValue::from_str(&header).ok()
}

/// CORS 配置（对齐 Go cors.Options：GET/POST、配置的 origins）。
fn cors_layer(config: &AppConfig) -> CorsLayer {
    let methods = [Method::GET, Method::POST];
    if config.api.cors_origins.iter().any(|o| o == "*") {
        return CorsLayer::new()
            .allow_methods(methods)
            .allow_origin(tower_http::cors::Any);
    }
    let list: Vec<HeaderValue> = config
        .api
        .cors_origins
        .iter()
        .filter_map(|o| o.parse::<HeaderValue>().ok())
        .collect();
    CorsLayer::new()
        .allow_methods(methods)
        .allow_origin(tower_http::cors::AllowOrigin::list(list))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ApiConfig, DbConfig, GeneralConfig, LogConfig};

    fn test_config() -> AppConfig {
        AppConfig {
            general: GeneralConfig {
                listen: "127.0.0.1:0".into(),
                protocol: "udp".into(),
                domain: "auth.example.org".into(),
                nsname: "ns1.auth.example.org".into(),
                nsadmin: "admin.example.org".into(),
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
                use_header: false,
                header_name: String::new(),
                hsts_enabled: false,
                hsts_max_age: 0,
                hsts_include_subdomains: false,
                hsts_preload: false,
                admin_token: String::new(),
            },
            log: LogConfig {
                level: "debug".into(),
                logtype: "stdout".into(),
                logfile: String::new(),
                format: "text".into(),
            },
        }
    }

    #[tokio::test]
    async fn health_endpoint_200() {
        let cfg = Arc::new(test_config());
        let db: Arc<dyn Store> = Arc::new(
            crate::store::sqlite::SqliteStore::new(":memory:")
                .await
                .unwrap(),
        );
        let app = build_router(cfg, db, Arc::new(OwnAuthKey::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let h = tokio::spawn(async move { axum::serve(listener, app).await });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let resp = client
            .get(format!("http://{addr}/health"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        h.abort();
    }

    #[tokio::test]
    async fn register_creates_user() {
        let cfg = Arc::new(test_config());
        let db: Arc<dyn Store> = Arc::new(
            crate::store::sqlite::SqliteStore::new(":memory:")
                .await
                .unwrap(),
        );
        let app = build_router(cfg, db, Arc::new(OwnAuthKey::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let h = tokio::spawn(async move { axum::serve(listener, app).await });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let resp = client
            .post(format!("http://{addr}/register"))
            .body("")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(body["username"].as_str().is_some());
        assert_eq!(body["password"].as_str().unwrap().len(), 40);
        assert!(
            body["fulldomain"]
                .as_str()
                .unwrap()
                .ends_with(".auth.example.org")
        );
        h.abort();
    }

    #[tokio::test]
    async fn register_bad_cidr_400() {
        let cfg = Arc::new(test_config());
        let db: Arc<dyn Store> = Arc::new(
            crate::store::sqlite::SqliteStore::new(":memory:")
                .await
                .unwrap(),
        );
        let app = build_router(cfg, db, Arc::new(OwnAuthKey::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let h = tokio::spawn(async move { axum::serve(listener, app).await });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let resp = client
            .post(format!("http://{addr}/register"))
            .header("Content-Type", "application/json")
            .body(r#"{"allowfrom": ["notacidr"]}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["error"], "invalid_allowfrom_cidr");
        h.abort();
    }

    #[tokio::test]
    async fn update_requires_auth() {
        let cfg = Arc::new(test_config());
        let db: Arc<dyn Store> = Arc::new(
            crate::store::sqlite::SqliteStore::new(":memory:")
                .await
                .unwrap(),
        );
        let app = build_router(cfg, db, Arc::new(OwnAuthKey::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let h = tokio::spawn(async move { axum::serve(listener, app).await });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let resp = client
            .post(format!("http://{addr}/update"))
            .header("Content-Type", "application/json")
            .body(r#"{"subdomain": "abc", "txt": "x"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
        assert_eq!(
            resp.json::<serde_json::Value>().await.unwrap()["error"],
            "forbidden"
        );
        h.abort();
    }

    #[tokio::test]
    async fn register_then_update_roundtrip() {
        let cfg = Arc::new(test_config());
        let db: Arc<dyn Store> = Arc::new(
            crate::store::sqlite::SqliteStore::new(":memory:")
                .await
                .unwrap(),
        );
        let app = build_router(cfg, db, Arc::new(OwnAuthKey::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let h = tokio::spawn(async move { axum::serve(listener, app).await });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();

        let resp = client
            .post(format!("http://{addr}/register"))
            .body("")
            .send()
            .await
            .unwrap();
        let reg: serde_json::Value = resp.json().await.unwrap();
        let (user, pass, subdomain) = (
            reg["username"].as_str().unwrap().to_string(),
            reg["password"].as_str().unwrap().to_string(),
            reg["subdomain"].as_str().unwrap().to_string(),
        );

        // 错误 key → 401
        let bad = client
            .post(format!("http://{addr}/update"))
            .header("X-Api-User", &user)
            .header("X-Api-Key", &"x".repeat(40))
            .header("Content-Type", "application/json")
            .body(format!(
                r#"{{"subdomain": "{subdomain}", "txt": "{}"}}"#,
                "t".repeat(43)
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(bad.status(), 401);

        // 正确 key + 43 字符 txt → 200
        let ok = client
            .post(format!("http://{addr}/update"))
            .header("X-Api-User", &user)
            .header("X-Api-Key", &pass)
            .header("Content-Type", "application/json")
            .body(format!(
                r#"{{"subdomain": "{subdomain}", "txt": "{}"}}"#,
                "t".repeat(43)
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(ok.status(), 200);
        let body: serde_json::Value = ok.json().await.unwrap();
        assert_eq!(body["txt"], "t".repeat(43));

        // 错误 subdomain → 401
        let mismatch = client
            .post(format!("http://{addr}/update"))
            .header("X-Api-User", &user)
            .header("X-Api-Key", &pass)
            .header("Content-Type", "application/json")
            .body(format!(
                r#"{{"subdomain": "other", "txt": "{}"}}"#,
                "t".repeat(43)
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(mismatch.status(), 401);

        // 错误 txt 长度 → 400
        let badtxt = client
            .post(format!("http://{addr}/update"))
            .header("X-Api-User", &user)
            .header("X-Api-Key", &pass)
            .header("Content-Type", "application/json")
            .body(format!(r#"{{"subdomain": "{subdomain}", "txt": "short"}}"#))
            .send()
            .await
            .unwrap();
        assert_eq!(badtxt.status(), 400);
        assert_eq!(
            badtxt.json::<serde_json::Value>().await.unwrap()["error"],
            "bad_txt"
        );
        h.abort();
    }

    #[tokio::test]
    async fn hsts_header_on_and_off() {
        let db: Arc<dyn Store> = Arc::new(
            crate::store::sqlite::SqliteStore::new(":memory:")
                .await
                .unwrap(),
        );

        // 关闭：不应出现头
        let mut cfg = test_config();
        cfg.api.hsts_enabled = false;
        let app = build_router(Arc::new(cfg), db.clone(), Arc::new(OwnAuthKey::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let h = tokio::spawn(async move { axum::serve(listener, app).await });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let resp = client
            .get(format!("http://{addr}/health"))
            .send()
            .await
            .unwrap();
        assert!(resp.headers().get("strict-transport-security").is_none());
        h.abort();

        // 开启：应出现默认 max-age
        let mut cfg = test_config();
        cfg.api.hsts_enabled = true;
        cfg.api.hsts_max_age = 0; // 触发默认 31536000
        cfg.api.hsts_include_subdomains = true;
        cfg.api.hsts_preload = true;
        let app = build_router(Arc::new(cfg), db, Arc::new(OwnAuthKey::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let h = tokio::spawn(async move { axum::serve(listener, app).await });
        let resp = client
            .get(format!("http://{addr}/health"))
            .send()
            .await
            .unwrap();
        let v = resp
            .headers()
            .get("strict-transport-security")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(v, "max-age=31536000; includeSubDomains; preload");
        h.abort();
    }
}
