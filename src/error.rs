//! 统一 API 错误：响应体对齐 Go 版 `{"error": "<message>"}`。

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// 400，`{"error": "..."}`（如 malformed_json_payload / bad_subdomain / bad_txt）。
    #[error("{0}")]
    BadRequest(String),
    /// 401，固定 `{"error": "forbidden"}`。
    #[error("forbidden")]
    Forbidden,
    /// 500，数据库错误，固定 `{"error": "db_error"}`。
    #[error("database error")]
    Db(#[from] sqlx::Error),
    /// 500，`{"error": "<detail>"}`（注册等流程错误）。
    #[error("{0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, json!({"error": msg})),
            AppError::Forbidden => (StatusCode::UNAUTHORIZED, json!({"error": "forbidden"})),
            AppError::Db(e) => {
                tracing::error!(error = %e, "数据库错误");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"error": "db_error"}),
                )
            }
            AppError::Internal(msg) => {
                tracing::error!(%msg, "内部错误");
                (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": msg}))
            }
        };
        (status, Json(body)).into_response()
    }
}

pub type ApiResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::StatusCode;

    async fn resp(err: AppError) -> (StatusCode, String) {
        let r = err.into_response();
        let status = r.status();
        let bytes = to_bytes(r.into_body(), 1024).await.unwrap();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    #[tokio::test]
    async fn bad_request_maps_to_400() {
        let (s, b) = resp(AppError::BadRequest("bad_txt".into())).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(b, r#"{"error":"bad_txt"}"#);
    }

    #[tokio::test]
    async fn forbidden_maps_to_401() {
        let (s, b) = resp(AppError::Forbidden).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert_eq!(b, r#"{"error":"forbidden"}"#);
    }

    #[tokio::test]
    async fn db_error_maps_to_500_db_error() {
        let e = sqlx::Error::RowNotFound;
        let (s, b) = resp(AppError::Db(e)).await;
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(b, r#"{"error":"db_error"}"#);
    }

    #[tokio::test]
    async fn internal_maps_to_500_with_detail() {
        let (s, b) = resp(AppError::Internal("boom".into())).await;
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(b, r#"{"error":"boom"}"#);
    }
}
