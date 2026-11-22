//! `POST /register`：创建账户（对齐 Go `pkg/api/register.go`）。

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::models::RegResponse;

use super::auth::ApiState;

/// 注册处理：空 body 或合法 `{"allowfrom": [...]}`。
#[allow(clippy::result_large_err)]
pub async fn web_register_post(
    State(state): State<ApiState>,
    body: String,
) -> Result<Response, axum::response::Response> {
    // 解析可选 body
    let allow_from = if body.trim().is_empty() {
        Default::default()
    } else {
        match serde_json::from_str::<RegisterPayload>(&body) {
            Ok(p) => p.allow_from,
            Err(_) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    super::util::json_error("malformed_json_payload"),
                )
                    .into_response());
            }
        }
    };

    // 校验 CIDR
    if let Err(e) = allow_from.validate() {
        tracing::debug!(error = %e, "invalid allowfrom cidr");
        return Err((
            StatusCode::BAD_REQUEST,
            super::util::json_error("invalid_allowfrom_cidr"),
        )
            .into_response());
    }

    match state.db.register(allow_from).await {
        Ok((user, password)) => {
            tracing::debug!(user = %user.username, "Created new user");
            let resp = RegResponse {
                username: user.username.to_string(),
                password,
                fulldomain: format!("{}.{}", user.subdomain, state.config.general.domain),
                subdomain: user.subdomain,
                allowfrom: user.allow_from.valid_entries(),
            };
            Ok((StatusCode::CREATED, axum::Json(resp)).into_response())
        }
        Err(e) => {
            tracing::error!(error = %e, "Error in registration");
            let msg = match e {
                crate::store::StoreError::Db(m) => m,
                other => other.to_string(),
            };
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                super::util::json_error(&msg),
            )
                .into_response())
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct RegisterPayload {
    #[serde(default, rename = "allowfrom")]
    allow_from: crate::models::CidrSlice,
}
