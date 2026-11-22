//! REST API 模块：鉴权、注册、更新、健康检查与 TLS/ACME。

// admin 模块的 Handler 返回 Result<_, Response>，Response 体较大触发
// clippy::result_large_err 误报，模块级豁免。
#[allow(clippy::result_large_err)]
pub mod admin;
pub mod auth;
pub mod health;
pub mod register;
pub mod router;
pub mod tls;
pub mod update;
pub mod util;
