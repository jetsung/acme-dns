//! 日志初始化：对齐 Go 版 `pkg/acmedns/logging.go`。
//!
//! - `loglevel`: error/warning/info/debug（非法值报错）
//! - `logtype`: stdout / file（file 写入 `logfile`）
//! - `logformat`: json / text
//! - 时间戳 ISO8601

use tracing_subscriber::{EnvFilter, filter::LevelFilter, fmt::time::ChronoLocal, prelude::*};

/// 将配置中的 loglevel 映射为 EnvFilter；非法值返回错误。
pub fn build_filter(level: &str) -> Result<EnvFilter, String> {
    let lf = match level.to_ascii_lowercase().as_str() {
        "error" => LevelFilter::ERROR,
        "warning" | "warn" => LevelFilter::WARN,
        "info" => LevelFilter::INFO,
        "debug" => LevelFilter::DEBUG,
        "trace" => LevelFilter::TRACE,
        other => return Err(format!("invalid loglevel: {other}")),
    };
    Ok(EnvFilter::builder()
        .with_default_directive(lf.into())
        .from_env_lossy())
}

/// 依据配置初始化全局 tracing 订阅。日志文件模式下返回 guard 以保持文件句柄。
pub fn init(
    level: &str,
    logtype: &str,
    logfile: &str,
    format: &str,
) -> Result<Option<tracing_appender::non_blocking::WorkerGuard>, String> {
    let filter = build_filter(level)?;

    let timer = ChronoLocal::rfc_3339();
    match logtype {
        "file" => {
            let appender = tracing_appender::rolling::never(".", logfile);
            let (writer, guard) = tracing_appender::non_blocking(appender);
            let layer = tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .with_timer(timer)
                .with_ansi(false);
            let layer = if format == "json" {
                layer.json().flatten_event(true).boxed()
            } else {
                layer.boxed()
            };
            tracing_subscriber::registry()
                .with(filter)
                .with(layer)
                .init();
            Ok(Some(guard))
        }
        _ => {
            let layer = tracing_subscriber::fmt::layer()
                .with_writer(std::io::stdout)
                .with_timer(timer)
                .with_ansi(false);
            let layer = if format == "json" {
                layer.json().flatten_event(true).boxed()
            } else {
                layer.boxed()
            };
            tracing_subscriber::registry()
                .with(filter)
                .with(layer)
                .init();
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_levels_parse() {
        assert!(build_filter("error").is_ok());
        assert!(build_filter("warning").is_ok());
        assert!(build_filter("info").is_ok());
        assert!(build_filter("debug").is_ok());
    }

    #[test]
    fn invalid_level_errors() {
        let e = build_filter("verbose").unwrap_err();
        assert!(e.contains("invalid loglevel"), "e={e}");
    }

    #[test]
    fn level_case_insensitive() {
        assert!(build_filter("DEBUG").is_ok());
    }
}
