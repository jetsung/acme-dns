//! `POST /update`：更新 TXT 记录（对齐 Go `pkg/api/update.go`）。

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use super::auth::{ApiState, AuthedUpdate};
use crate::models::valid_subdomain;
use crate::models::valid_txt;

/// 鉴权后处理更新；body 已由鉴权中间件解码并放入扩展。
pub async fn web_update_post(
    State(_state): State<ApiState>,
    axum::Extension(authed): axum::Extension<AuthedUpdate>,
) -> Response {
    let atxt = authed;
    if !valid_subdomain(&atxt.post.subdomain) {
        tracing::error!(subdomain = %atxt.post.subdomain, txt = %atxt.post.value, "Bad update data: subdomain");
        return (
            StatusCode::BAD_REQUEST,
            super::util::json_error("bad_subdomain"),
        )
            .into_response();
    }
    if !valid_txt(&atxt.post.value) {
        tracing::error!(subdomain = %atxt.post.subdomain, txt = %atxt.post.value, "Bad update data: txt");
        return (StatusCode::BAD_REQUEST, super::util::json_error("bad_txt")).into_response();
    }
    match _state.db.update(&atxt.post).await {
        Ok(()) => {
            tracing::debug!(subdomain = %atxt.post.subdomain, "TXT record updated");
            (
                StatusCode::OK,
                format!("{{\"txt\": \"{}\"}}", atxt.post.value),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Error while trying to update record");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                super::util::json_error("db_error"),
            )
                .into_response()
        }
    }
}
