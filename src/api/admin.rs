//! 管理端 REST API（Rust 版扩展，非上游 Go 契约）。
//!
//! 鉴权：`Authorization: Bearer <admin_token>`，token 来自配置
//! `[api] admin_token`；未配置（空）时整组路由不挂载。
//!
//! 路由：
//! - `GET    /admin/accounts`                     列出全部账户
//! - `POST   /admin/accounts`                     注册（可自定义子域）
//! - `GET    /admin/accounts/{username}`          查看账户
//! - `DELETE /admin/accounts/{username}`          删除账户
//! - `PATCH  /admin/accounts/{username}`          更新 allowfrom
//! - `POST   /admin/accounts/{username}/password` 重置密码
//! - `PUT    /admin/accounts/{username}/txt`      覆盖写入 TXT（≤2 条）
//! - `DELETE /admin/accounts/{username}/txt`      清空 TXT

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use uuid::Uuid;

use crate::models::{
    AdminAccountResponse, AdminAllowFromRequest, AdminPasswordResponse, AdminRegisterRequest,
    AdminTxtRequest, AdminTxtResponse, CidrSlice,
};
#[allow(unused_imports)]
use crate::store::{AccountRow, Store, StoreError};

use super::auth::ApiState;
use super::util::json_error;

// Handler 返回的 Response 体较大（axum Body），clippy 的 result_large_err
// 对该模块全部误报；此处显式豁免。
type AdminResult<T> = Result<T, Response>;

fn bad_request(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, json_error(msg)).into_response()
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, json_error("account_not_found")).into_response()
}

fn db_error(e: &StoreError) -> Response {
    tracing::error!(error = %e, "admin store error");
    (StatusCode::INTERNAL_SERVER_ERROR, json_error("db_error")).into_response()
}

fn to_response(row: AccountRow, domain: &str) -> AdminAccountResponse {
    AdminAccountResponse {
        username: row.username.to_string(),
        fulldomain: row.fulldomain(domain),
        subdomain: row.subdomain,
        allowfrom: row.allow_from.valid_entries(),
        txt: row.txt,
        last_update: row.last_update,
        created_at: row.created_at,
    }
}

fn parse_uuid(raw: &str) -> AdminResult<Uuid> {
    Uuid::parse_str(raw).map_err(|_| not_found())
}

/// 将 StoreError 映射为 HTTP 响应。
fn map_err(e: StoreError) -> Response {
    match e {
        StoreError::UserNotFound(_) | StoreError::SubdomainNotFound(_) => not_found(),
        other => db_error(&other),
    }
}

/// `GET /admin/accounts`
pub async fn list_accounts(State(state): State<ApiState>) -> AdminResult<Response> {
    let rows = state.db.list_accounts().await.map_err(map_err)?;
    let domain = state.config.general.domain.clone();
    let accounts: Vec<AdminAccountResponse> =
        rows.into_iter().map(|r| to_response(r, &domain)).collect();
    Ok((StatusCode::OK, Json(accounts)).into_response())
}

/// `POST /admin/accounts`
pub async fn create_account(
    State(state): State<ApiState>,
    body: Json<AdminRegisterRequest>,
) -> AdminResult<Response> {
    let req = body.0;
    if let Err(e) = req.allow_from.validate() {
        tracing::debug!(error = %e, "invalid allowfrom cidr");
        return Err(bad_request("invalid_allowfrom_cidr"));
    }
    if let Some(sub) = req.subdomain.as_deref()
        && !crate::models::valid_subdomain(&crate::models::sanitize_string(sub))
    {
        return Err(bad_request("bad_subdomain"));
    }
    match state
        .db
        .register_with_subdomain(req.allow_from, req.subdomain.as_deref())
        .await
    {
        Ok((user, password)) => {
            tracing::debug!(user = %user.username, "admin created user");
            let resp = crate::models::RegResponse {
                username: user.username.to_string(),
                password,
                fulldomain: format!("{}.{}", user.subdomain, state.config.general.domain),
                subdomain: user.subdomain,
                allowfrom: user.allow_from.valid_entries(),
            };
            Ok((StatusCode::CREATED, Json(resp)).into_response())
        }
        Err(StoreError::SubdomainExists(s)) => Err((
            StatusCode::CONFLICT,
            json_error(&format!("subdomain_already_exists: {s}")),
        )
            .into_response()),
        Err(e) => {
            tracing::error!(error = ?e, "admin create_account store error");
            Err(map_err(e))
        }
    }
}

/// `GET /admin/accounts/{username}`
pub async fn get_account(
    State(state): State<ApiState>,
    Path(username): Path<String>,
) -> AdminResult<Response> {
    let uuid = parse_uuid(&username)?;
    let user = state.db.get_by_username(uuid).await.map_err(map_err)?;
    let row = state
        .db
        .get_by_subdomain(&user.subdomain)
        .await
        .map_err(map_err)?;
    let domain = state.config.general.domain.clone();
    Ok((StatusCode::OK, Json(to_response(row, &domain))).into_response())
}

/// `DELETE /admin/accounts/{username}`
pub async fn delete_account(
    State(state): State<ApiState>,
    Path(username): Path<String>,
) -> AdminResult<Response> {
    let uuid = parse_uuid(&username)?;
    state.db.delete_account(uuid).await.map_err(map_err)?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"deleted": username})),
    )
        .into_response())
}

/// `PATCH /admin/accounts/{username}`：更新 allowfrom。
pub async fn update_account(
    State(state): State<ApiState>,
    Path(username): Path<String>,
    Json(body): Json<AdminAllowFromRequest>,
) -> AdminResult<Response> {
    let uuid = parse_uuid(&username)?;
    if let Err(e) = body.allow_from.validate() {
        tracing::debug!(error = %e, "invalid allowfrom cidr");
        return Err(bad_request("invalid_allowfrom_cidr"));
    }
    state
        .db
        .update_allow_from(uuid, body.allow_from)
        .await
        .map_err(map_err)?;
    let user = state.db.get_by_username(uuid).await.map_err(map_err)?;
    let row = state
        .db
        .get_by_subdomain(&user.subdomain)
        .await
        .map_err(map_err)?;
    let domain = state.config.general.domain.clone();
    Ok((StatusCode::OK, Json(to_response(row, &domain))).into_response())
}

/// `POST /admin/accounts/{username}/password`：重置密码。
pub async fn reset_password(
    State(state): State<ApiState>,
    Path(username): Path<String>,
) -> AdminResult<Response> {
    let uuid = parse_uuid(&username)?;
    let password = state.db.reset_password(uuid).await.map_err(map_err)?;
    Ok((
        StatusCode::OK,
        Json(AdminPasswordResponse { username, password }),
    )
        .into_response())
}

/// `PUT /admin/accounts/{username}/txt`：覆盖写入（≤2 条）。
pub async fn set_txt(
    State(state): State<ApiState>,
    Path(username): Path<String>,
    Json(body): Json<AdminTxtRequest>,
) -> AdminResult<Response> {
    let uuid = parse_uuid(&username)?;
    let user = state.db.get_by_username(uuid).await.map_err(map_err)?;
    let txt2 = body.txt2.unwrap_or_default();
    for v in [&body.txt, &txt2] {
        if !v.is_empty() && !crate::models::valid_txt(v) {
            return Err(bad_request("bad_txt"));
        }
    }
    state
        .db
        .set_txt(&user.subdomain, &body.txt, &txt2)
        .await
        .map_err(map_err)?;
    let txt = state
        .db
        .get_txt_for_domain(&user.subdomain)
        .await
        .map_err(map_err)?;
    Ok((
        StatusCode::OK,
        Json(AdminTxtResponse {
            subdomain: user.subdomain,
            txt,
        }),
    )
        .into_response())
}

/// `DELETE /admin/accounts/{username}/txt`：清空 TXT。
pub async fn clear_txt(
    State(state): State<ApiState>,
    Path(username): Path<String>,
) -> AdminResult<Response> {
    let uuid = parse_uuid(&username)?;
    let user = state.db.get_by_username(uuid).await.map_err(map_err)?;
    state
        .db
        .set_txt(&user.subdomain, "", "")
        .await
        .map_err(map_err)?;
    Ok((
        StatusCode::OK,
        Json(AdminTxtResponse {
            subdomain: user.subdomain,
            txt: vec![],
        }),
    )
        .into_response())
}

/// Admin Bearer Token 中间件。
pub async fn admin_token_middleware(
    State(state): State<ApiState>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let expected = &state.config.api.admin_token;
    let provided = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if expected.is_empty() || provided.is_empty() || !constant_time_eq(provided, expected) {
        return (StatusCode::UNAUTHORIZED, json_error("forbidden")).into_response();
    }
    next.run(req).await
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// 组装 `/admin` 子路由（带 token 中间件）。
pub fn admin_router(state: ApiState) -> axum::Router {
    Router::new()
        .route("/accounts", get(list_accounts).post(create_account))
        .route(
            "/accounts/{username}",
            get(get_account)
                .delete(delete_account)
                .patch(update_account),
        )
        .route("/accounts/{username}/password", post(reset_password))
        .route("/accounts/{username}/txt", put(set_txt).delete(clear_txt))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            admin_token_middleware,
        ))
        .with_state(state)
}

/// 供 router.rs 使用：配置了 admin_token 时返回 Some(router)。
pub fn maybe_admin_router(
    config: &Arc<crate::models::AppConfig>,
    state: ApiState,
) -> Option<axum::Router> {
    if config.api.admin_token.is_empty() {
        None
    } else {
        Some(admin_router(state))
    }
}

/// 管理端 CIDR 白名单入口（供测试复用）。
pub fn validate_allow_from(allow_from: &CidrSlice) -> Result<(), String> {
    allow_from.validate()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnsserver::own_auth::OwnAuthKey;
    use crate::models::{ApiConfig, AppConfig, DbConfig, GeneralConfig, LogConfig};
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_config(admin_token: &str) -> AppConfig {
        AppConfig {
            general: GeneralConfig {
                listen: "127.0.0.1:0".into(),
                protocol: "udp".into(),
                domain: "auth.example.org".into(),
                nsname: "auth.example.org".into(),
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
                tls: "none".into(),
                tls_cert_privkey: String::new(),
                tls_cert_fullchain: String::new(),
                acme_cache_dir: "api-certs".into(),
                notification_email: String::new(),
                disable_registration: false,
                cors_origins: vec!["*".into()],
                use_header: false,
                header_name: "X-Forwarded-For".into(),
                hsts_enabled: false,
                hsts_max_age: 0,
                hsts_include_subdomains: false,
                hsts_preload: false,
                admin_token: admin_token.into(),
            },
            log: LogConfig {
                level: "info".into(),
                logtype: "stdout".into(),
                logfile: String::new(),
                format: "text".into(),
            },
        }
    }

    async fn app_with(token: &str) -> axum::Router {
        let config = Arc::new(test_config(token));
        let db: Arc<dyn Store> = Arc::new(
            crate::store::sqlite::SqliteStore::new(":memory:")
                .await
                .unwrap(),
        );
        let state = ApiState {
            db,
            config: config.clone(),
            own_auth_key: Arc::new(OwnAuthKey::new()),
        };
        admin_router(state)
    }

    #[tokio::test]
    async fn admin_requires_bearer_token() {
        let app = app_with("secret123").await;
        let resp = app
            .clone()
            .oneshot(Request::get("/accounts").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let app = app_with("secret123").await;
        let resp = app
            .clone()
            .oneshot(
                Request::get("/accounts")
                    .header("Authorization", "Bearer wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_list_and_create_and_delete() {
        let app = app_with("secret123").await;
        let resp = app
            .clone()
            .oneshot(
                Request::post("/accounts")
                    .header("Authorization", "Bearer secret123")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"subdomain": "my-sub"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let reg: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let username = reg["username"].as_str().unwrap().to_string();
        assert_eq!(reg["subdomain"], "my-sub");

        let app = app.clone();
        let resp = app
            .clone()
            .oneshot(
                Request::get("/accounts")
                    .header("Authorization", "Bearer secret123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let list: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(list.as_array().unwrap().len(), 1);

        // 重复子域 → 409
        let app = app.clone();
        let resp = app
            .clone()
            .oneshot(
                Request::post("/accounts")
                    .header("Authorization", "Bearer secret123")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"subdomain": "my-sub"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        // 删除
        let app = app.clone();
        let resp = app
            .clone()
            .oneshot(
                Request::delete(format!("/accounts/{username}"))
                    .header("Authorization", "Bearer secret123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // 删除后再查 → 404
        let app = app.clone();
        let resp = app
            .clone()
            .oneshot(
                Request::get(format!("/accounts/{username}"))
                    .header("Authorization", "Bearer secret123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn admin_txt_set_and_clear() {
        let app = app_with("t").await;
        let resp = app
            .clone()
            .oneshot(
                Request::post("/accounts")
                    .header("Authorization", "Bearer t")
                    .header("Content-Type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let reg: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let username = reg["username"].as_str().unwrap().to_string();

        // 非法 txt → 400
        let app = app.clone();
        let resp = app
            .clone()
            .oneshot(
                Request::put(format!("/accounts/{username}/txt"))
                    .header("Authorization", "Bearer t")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"txt": "short"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // 合法写入
        let txt = "a".repeat(43);
        let app = app.clone();
        let resp = app
            .clone()
            .oneshot(
                Request::put(format!("/accounts/{username}/txt"))
                    .header("Authorization", "Bearer t")
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(r#"{{"txt": "{txt}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let out: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = out["txt"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0], txt);

        // 清空
        let app = app.clone();
        let resp = app
            .clone()
            .oneshot(
                Request::delete(format!("/accounts/{username}/txt"))
                    .header("Authorization", "Bearer t")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_password_reset_and_allowfrom_patch() {
        let app = app_with("t").await;
        let resp = app
            .clone()
            .oneshot(
                Request::post("/accounts")
                    .header("Authorization", "Bearer t")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"allowfrom": ["192.168.100.1/24"]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let reg: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let username = reg["username"].as_str().unwrap().to_string();
        assert_eq!(reg["allowfrom"].as_array().unwrap().len(), 1);

        // PATCH allowfrom → 清空
        let app = app.clone();
        let resp = app
            .clone()
            .oneshot(
                Request::patch(format!("/accounts/{username}"))
                    .header("Authorization", "Bearer t")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"allowfrom": []}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let out: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(out["allowfrom"].as_array().unwrap().len(), 0);

        // 重置密码
        let app = app.clone();
        let resp = app
            .clone()
            .oneshot(
                Request::post(format!("/accounts/{username}/password"))
                    .header("Authorization", "Bearer t")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let out: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(out["password"].as_str().unwrap().len(), 40);
    }
}
