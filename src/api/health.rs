//! `GET /health` 健康检查（对齐 Go `pkg/api/healthcheck.go`）。

use axum::http::StatusCode;

pub async fn health_check() -> StatusCode {
    StatusCode::OK
}
