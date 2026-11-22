//! 配置解析与校验：四段 TOML 结构（`[general]` / `[database]` / `[api]` / `[log]`，
//! 文件名用 `config.toml`）。
//!
//! 发现顺序：`-c` 指定路径 → `/etc/acme-dns/config.toml` → `./config.toml`。
//! 所有配置项均可用环境变量覆盖，命名 `ACME_DNS_<段>_<字段>`（大写下划线），
//! 优先级：环境变量 > 配置文件 > 代码默认值。

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::models::AppConfig;

pub const ETC_CONFIG: &str = "/etc/acme-dns/config.toml";
pub const LOCAL_CONFIG: &str = "config.toml";

/// `api.tls` 合法取值。
pub const TLS_VALUES: [&str; 4] = ["none", "letsencrypt", "letsencryptstaging", "cert"];

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawConfig {
    general: RawGeneral,
    database: RawDatabase,
    api: RawApi,
    /// 日志段 `[log]`（字段无前缀）。
    #[serde(default, deserialize_with = "deserialize_log_section")]
    log: RawLogConfig,
}

/// 日志段反序列化：字段名 level/type/file/format。
fn deserialize_log_section<'de, D>(deserializer: D) -> Result<RawLogConfig, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct RawLog {
        level: Option<String>,
        #[serde(rename = "type")]
        r#type: Option<String>,
        file: Option<String>,
        format: Option<String>,
    }
    let m = RawLog::deserialize(deserializer)?;
    Ok(RawLogConfig {
        level: m.level,
        logtype: m.r#type,
        logfile: m.file,
        logformat: m.format,
    })
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawGeneral {
    listen: Option<String>,
    protocol: Option<String>,
    domain: Option<String>,
    nsname: Option<String>,
    nsadmin: Option<String>,
    records: Option<Vec<String>>,
    debug: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawDatabase {
    /// 完整连接串；scheme 决定 engine（sqlite: / postgres:）。
    /// env 对应 `ACME_DNS_DATABASE_URL` / `DATABASE_URL`。
    url: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawApi {
    /// 监听地址 `host:port`（如 `0.0.0.0:80`、`[::]:443`）。
    host: Option<String>,
    tls: Option<String>,
    tls_cert_privkey: Option<String>,
    tls_cert_fullchain: Option<String>,
    acme_cache_dir: Option<String>,
    notification_email: Option<String>,
    disable_registration: Option<bool>,
    corsorigins: Option<Vec<String>>,
    use_header: Option<bool>,
    header_name: Option<String>,
    hsts_enabled: Option<bool>,
    hsts_max_age: Option<i64>,
    hsts_include_subdomains: Option<bool>,
    hsts_preload: Option<bool>,
    admin_token: Option<String>,
}

#[derive(Debug, Default)]
struct RawLogConfig {
    level: Option<String>,
    logtype: Option<String>,
    logfile: Option<String>,
    logformat: Option<String>,
}

fn file_accessible(p: &Path) -> bool {
    p.is_file()
}

fn read_toml(path: &Path) -> Result<RawConfig, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("读取配置文件 {} 失败: {e}", path.display()))?;
    toml::from_str(&raw).map_err(|e| format!("解析配置文件 {} 失败: {e}", path.display()))
}

/// 环境变量前缀。
pub const ENV_PREFIX: &str = "ACME_DNS_";

fn env_val(section: &str, key: &str) -> Option<String> {
    let name = format!("{ENV_PREFIX}{}_{}", section.to_uppercase(), key).to_uppercase();
    std::env::var(&name).ok()
}

fn env_bool(section: &str, key: &str) -> Option<bool> {
    env_val(section, key).map(|v| match v.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" | "" => false,
        other => panic!(
            "invalid boolean for {ENV_PREFIX}{}_{}: {other}",
            section.to_uppercase(),
            key.to_uppercase()
        ),
    })
}

fn env_i64(section: &str, key: &str) -> Option<i64> {
    env_val(section, key).map(|v| {
        v.parse::<i64>().unwrap_or_else(|e| {
            panic!(
                "invalid integer for {ENV_PREFIX}{}_{}: {v} ({e})",
                section.to_uppercase(),
                key.to_uppercase()
            )
        })
    })
}

fn env_list(section: &str, key: &str) -> Option<Vec<String>> {
    env_val(section, key).map(|v| {
        v.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    })
}

/// 依据 `-c` 参数（可选）与回退路径发现并解析配置。
/// 返回配置与实际使用的文件路径。
pub fn read_config(cli_path: Option<&str>) -> Result<(AppConfig, PathBuf), String> {
    let candidates: Vec<PathBuf> = match cli_path {
        Some(p) => vec![PathBuf::from(p)],
        None => vec![PathBuf::from(ETC_CONFIG), PathBuf::from(LOCAL_CONFIG)],
    };
    for path in &candidates {
        if file_accessible(path) {
            let mut raw = read_toml(path)?;
            apply_env_overrides(&mut raw);
            let cfg = prepare_config(raw)?;
            return Ok((cfg, path.clone()));
        }
    }
    // 无配置文件时仍允许纯环境变量运行（database url 由 env 提供）。
    let mut raw = RawConfig::default();
    apply_env_overrides(&mut raw);
    if raw.database.url.is_some() {
        let cfg = prepare_config(raw)?;
        return Ok((cfg, PathBuf::from("environment")));
    }
    Err("configuration file not found".to_string())
}

/// 用环境变量覆盖 TOML 解析结果（env 优先）。
///
/// 数据库连接串的优先级：
///   1. `ACME_DNS_DATABASE_URL`（最高）
///   2. `DATABASE_URL`（通用惯例）
///   3. 文件 `[database]` 段的 `url`
///
/// URL 的 scheme 决定 engine（sqlite: / postgres:）。
fn apply_env_overrides(raw: &mut RawConfig) {
    // [database] —— ACME_DNS_DATABASE_URL > DATABASE_URL > 文件 url
    if let Some(url) = std::env::var("ACME_DNS_DATABASE_URL")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .or_else(|| {
            std::env::var("DATABASE_URL")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        })
    {
        raw.database.url = Some(url);
    }
    // [general]
    if let Some(v) = env_val("general", "listen") {
        raw.general.listen = Some(v);
    }
    if let Some(v) = env_val("general", "protocol") {
        raw.general.protocol = Some(v);
    }
    if let Some(v) = env_val("general", "domain") {
        raw.general.domain = Some(v);
    }
    if let Some(v) = env_val("general", "nsname") {
        raw.general.nsname = Some(v);
    }
    if let Some(v) = env_val("general", "nsadmin") {
        raw.general.nsadmin = Some(v);
    }
    if let Some(v) = env_list("general", "records") {
        raw.general.records = Some(v);
    }
    if let Some(v) = env_bool("general", "debug") {
        raw.general.debug = Some(v);
    }
    // [api]：host（host:port）为唯一监听写法；env ACME_DNS_API_HOST 最高优先。
    if let Some(v) = std::env::var("ACME_DNS_API_HOST")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    {
        raw.api.host = Some(v);
    }
    if let Some(v) = env_val("api", "tls") {
        raw.api.tls = Some(v);
    }
    if let Some(v) = env_val("api", "tls_cert_privkey") {
        raw.api.tls_cert_privkey = Some(v);
    }
    if let Some(v) = env_val("api", "tls_cert_fullchain") {
        raw.api.tls_cert_fullchain = Some(v);
    }
    if let Some(v) = env_val("api", "acme_cache_dir") {
        raw.api.acme_cache_dir = Some(v);
    }
    if let Some(v) = env_val("api", "notification_email") {
        raw.api.notification_email = Some(v);
    }
    if let Some(v) = env_bool("api", "disable_registration") {
        raw.api.disable_registration = Some(v);
    }
    if let Some(v) = env_list("api", "corsorigins") {
        raw.api.corsorigins = Some(v);
    }
    if let Some(v) = env_bool("api", "use_header") {
        raw.api.use_header = Some(v);
    }
    if let Some(v) = env_val("api", "header_name") {
        raw.api.header_name = Some(v);
    }
    if let Some(v) = env_bool("api", "hsts_enabled") {
        raw.api.hsts_enabled = Some(v);
    }
    if let Some(v) = env_i64("api", "hsts_max_age") {
        raw.api.hsts_max_age = Some(v);
    }
    if let Some(v) = env_bool("api", "hsts_include_subdomains") {
        raw.api.hsts_include_subdomains = Some(v);
    }
    if let Some(v) = env_bool("api", "hsts_preload") {
        raw.api.hsts_preload = Some(v);
    }
    if let Some(v) = env_val("api", "admin_token") {
        raw.api.admin_token = Some(v);
    }
    // [log]：env ACME_DNS_LOG_<字段> > 文件值。
    if let Some(v) = std::env::var("ACME_DNS_LOG_LEVEL")
        .ok()
        .filter(|v| !v.trim().is_empty())
    {
        raw.log.level = Some(v);
    }
    if let Some(v) = std::env::var("ACME_DNS_LOG_TYPE")
        .ok()
        .filter(|v| !v.trim().is_empty())
    {
        raw.log.logtype = Some(v);
    }
    if let Some(v) = std::env::var("ACME_DNS_LOG_FILE")
        .ok()
        .filter(|v| !v.trim().is_empty())
    {
        raw.log.logfile = Some(v);
    }
    if let Some(v) = std::env::var("ACME_DNS_LOG_FORMAT")
        .ok()
        .filter(|v| !v.trim().is_empty())
    {
        raw.log.logformat = Some(v);
    }
}

/// 从数据库连接串推断 engine：`sqlite:`/`sqlite3:` → sqlite，
/// `postgres:`/`postgresql:` → postgres；其余报错。
fn engine_from_url(url: &str) -> Result<String, String> {
    let scheme = url.split("://").next().unwrap_or("").to_ascii_lowercase();
    match scheme.as_str() {
        "sqlite" | "sqlite3" => Ok("sqlite".to_string()),
        "postgres" | "postgresql" => Ok("postgres".to_string()),
        other => Err(format!(
            "unsupported database URL scheme: {other} (expected sqlite:// or postgres://)"
        )),
    }
}

fn prepare_config(raw: RawConfig) -> Result<AppConfig, String> {
    // 连接串唯一来源：ACME_DNS_DATABASE_URL > DATABASE_URL > 文件 [database] url；
    // URL 的 scheme 决定 engine（sqlite: / postgres:）。
    let url = raw
        .database
        .url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(r#"missing database configuration option "url""#)?;
    let engine = engine_from_url(url)?;
    let connection = url.to_string();

    let tls = raw.api.tls.unwrap_or_else(|| "none".to_string());
    if !TLS_VALUES.contains(&tls.as_str()) {
        return Err(format!(
            "invalid value for api.tls, expected one of [{}]",
            TLS_VALUES.join(", ")
        ));
    }

    let acme_cache_dir = raw
        .api
        .acme_cache_dir
        .unwrap_or_else(|| "api-certs".to_string());

    // host（host:port）按 SocketAddr 校验并拆出 ip/port；非法在启动时报错。
    let host = raw
        .api
        .host
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(r#"missing api configuration option "host""#)?;
    let addr: std::net::SocketAddr = host.parse().map_err(|_| {
        format!("invalid api.host \"{host}\" (expected ip:port, e.g. 0.0.0.0:80 or [::]:443)")
    })?;
    let api_ip = match addr {
        std::net::SocketAddr::V4(a) => a.ip().to_string(),
        std::net::SocketAddr::V6(a) => format!("[{}]", a.ip()),
    };
    let api_port = addr.port().to_string();

    Ok(AppConfig {
        general: crate::models::GeneralConfig {
            listen: raw.general.listen.unwrap_or_else(|| "0.0.0.0:53".into()),
            protocol: raw.general.protocol.unwrap_or_else(|| "both".into()),
            domain: raw.general.domain.unwrap_or_default(),
            nsname: raw.general.nsname.unwrap_or_default(),
            nsadmin: raw.general.nsadmin.unwrap_or_default(),
            records: raw.general.records.unwrap_or_default(),
            debug: raw.general.debug.unwrap_or(false),
        },
        database: crate::models::DbConfig { engine, connection },
        api: crate::models::ApiConfig {
            ip: api_ip,
            port: api_port,
            tls,
            tls_cert_privkey: raw.api.tls_cert_privkey.unwrap_or_default(),
            tls_cert_fullchain: raw.api.tls_cert_fullchain.unwrap_or_default(),
            acme_cache_dir,
            notification_email: raw.api.notification_email.unwrap_or_default(),
            disable_registration: raw.api.disable_registration.unwrap_or(false),
            cors_origins: raw.api.corsorigins.unwrap_or_else(|| vec!["*".into()]),
            use_header: raw.api.use_header.unwrap_or(false),
            header_name: raw
                .api
                .header_name
                .unwrap_or_else(|| "X-Forwarded-For".into()),
            hsts_enabled: raw.api.hsts_enabled.unwrap_or(false),
            hsts_max_age: raw.api.hsts_max_age.unwrap_or(31_536_000),
            hsts_include_subdomains: raw.api.hsts_include_subdomains.unwrap_or(false),
            hsts_preload: raw.api.hsts_preload.unwrap_or(false),
            admin_token: raw.api.admin_token.unwrap_or_default(),
        },
        log: crate::models::LogConfig {
            level: raw.log.level.unwrap_or_else(|| "info".into()),
            logtype: raw.log.logtype.unwrap_or_else(|| "stdout".into()),
            logfile: raw.log.logfile.unwrap_or_else(|| "./acme-dns.log".into()),
            format: raw.log.logformat.unwrap_or_else(|| "text".into()),
        },
    })
}

/// `init` 子命令生成的示例配置（TOML，与文档配置参考一致）。
pub const EXAMPLE_CONFIG: &str = r#"# acme-dns 配置文件（TOML）

[general]
# DNS 监听地址。注意 systemd-resolved 可能占用 127.0.0.53:53
listen = "0.0.0.0:53"
# 监听协议："both", "both4", "both6", "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6"
protocol = "both"
# 服务的域名
domain = "auth.example.org"
# SOA 的 zone name server
nsname = "auth.example.org"
# SOA 管理员邮箱，@ 替换为 .
nsadmin = "admin.example.org"
# 静态预置记录（除 TXT 外）
records = [
    "auth.example.org. A 198.51.100.1",
    "auth.example.org. NS auth.example.org.",
]
# CORS 等调试日志
debug = false

[database]
# 数据库连接串：scheme 决定 engine（sqlite: / postgres:）。
# 也可用环境变量 ACME_DNS_DATABASE_URL 或 DATABASE_URL（优先级更高）。
url = "sqlite://acme-dns.db"

[api]
# API 监听地址 host:port；也可用 env ACME_DNS_API_HOST（优先级最高）。
host = "0.0.0.0:80"
# 关闭 /register 端点
disable_registration = false
# 可选值："cert", "none"（letsencrypt 系列保留兼容，当前未内置 ACME 客户端）
tls = "none"
# tls = "cert" 时使用
#tls_cert_privkey = "/etc/tls/example.org/privkey.pem"
#tls_cert_fullchain = "/etc/tls/example.org/fullchain.pem"
# letsencrypt 模式的缓存目录（保留字段）
#acme_cache_dir = "api-certs"
# Let's Encrypt 到期通知邮箱（保留字段）
#notification_email = ""
# CORS AllowOrigins，可用通配符
corsorigins = ["*"]
# 用 HTTP 头解析客户端 IP（反代场景）
use_header = false
# 从哪个头取 IP 列表
header_name = "X-Forwarded-For"
# 是否发送 HSTS 头
hsts_enabled = false
hsts_max_age = 31536000
hsts_include_subdomains = false
hsts_preload = false
# 管理端 /admin/* Bearer token；为空时管理 API 不挂载。
# 生成方式：acme-dns keygen（默认 48 字符，可选长度 8-256）。
admin_token = ""

# 日志段 [log]（字段无前缀）。
[log]
# "error", "warning", "info" or "debug"
level = "info"
# 输出目标（当前支持 stdout）
type = "stdout"
# "json" or "text"
format = "text"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    /// 全局测试互斥锁：env 是进程级全局，所有触碰 env 的测试必须串行。
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 清空全部 ACME_DNS_* 与 DATABASE_URL 变量并持有锁直到返回的 guard 被 drop。
    /// 调用方必须绑定 guard：`let _g = clean_env();`，
    /// 保证"清理→读取"全程与 with_env 测试互斥。
    fn clean_env() -> std::sync::MutexGuard<'static, ()> {
        let g = env_lock();
        for (k, _) in std::env::vars() {
            if k.starts_with("ACME_DNS_") || k == "DATABASE_URL" {
                unsafe { std::env::remove_var(&k) };
            }
        }
        g
    }

    const SAMPLE: &str = r#"
[general]
listen = "127.0.0.1:5353"
protocol = "both"
domain = "auth.example.org"
nsname = "auth.example.org"
nsadmin = "admin.example.org"
records = [
    "auth.example.org. A 198.51.100.1",
    "auth.example.org. NS auth.example.org.",
]
debug = false

[database]
url = "sqlite://acme-dns.db"

[api]
host = "127.0.0.1:8080"
tls = "none"
corsorigins = ["*"]

[log]
level = "info"
type = "stdout"
format = "json"
"#;

    fn write_tmp(content: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn parses_full_sample() {
        let _env = clean_env();
        let f = write_tmp(SAMPLE);
        let (cfg, used) = read_config(f.path().to_str()).unwrap();
        assert_eq!(used, f.path());
        assert_eq!(cfg.general.listen, "127.0.0.1:5353");
        assert_eq!(cfg.general.protocol, "both");
        assert_eq!(cfg.general.domain, "auth.example.org");
        assert_eq!(cfg.general.records.len(), 2);
        assert_eq!(cfg.database.engine, "sqlite");
        assert_eq!(cfg.database.connection, "sqlite://acme-dns.db");
        assert_eq!(cfg.api.ip, "127.0.0.1");
        assert_eq!(cfg.api.port, "8080");
        assert_eq!(cfg.api.tls, "none");
        assert_eq!(cfg.log.level, "info");
        assert_eq!(cfg.log.format, "json");
    }

    #[test]
    fn missing_url_fails() {
        let _env = clean_env();
        let f = write_tmp("[general]\n[database]\n[api]\nhost = \"127.0.0.1:8080\"\n");
        let err = read_config(f.path().to_str()).unwrap_err();
        assert!(err.contains("\"url\""), "err={err}");
    }

    #[test]
    fn missing_api_host_fails() {
        let _env = clean_env();
        let f = write_tmp("[general]\n[database]\nurl = \"sqlite://x.db\"\n[api]\n");
        let err = read_config(f.path().to_str()).unwrap_err();
        assert!(err.contains("\"host\""), "err={err}");
    }

    #[test]
    fn invalid_tls_value_fails() {
        let _env = clean_env();
        let f = write_tmp(
            "[database]\nurl = \"sqlite://x.db\"\n[api]\nhost = \"127.0.0.1:80\"\ntls = \"auto\"\n",
        );
        let err = read_config(f.path().to_str()).unwrap_err();
        assert!(err.contains("api.tls"), "err={err}");
        assert!(err.contains("none"), "err={err}");
    }

    #[test]
    fn acme_cache_dir_defaults() {
        let _env = clean_env();
        let f = write_tmp(
            "[database]\nurl = \"sqlite://x.db\"\n[api]\nhost = \"127.0.0.1:80\"\ntls = \"letsencryptstaging\"\n",
        );
        let (cfg, _) = read_config(f.path().to_str()).unwrap();
        assert_eq!(cfg.api.acme_cache_dir, "api-certs");
    }

    #[test]
    fn missing_file_reports_not_found() {
        let _env = clean_env();
        let err = read_config(Some("/nonexistent/nope.cfg")).unwrap_err();
        assert_eq!(err, "configuration file not found");
    }

    #[test]
    fn protocol_key_maps() {
        let _env = clean_env();
        let f = write_tmp(
            "[general]\nprotocol = \"both4\"\n[database]\nurl = \"sqlite://x.db\"\n[api]\nhost = \"127.0.0.1:80\"\n",
        );
        let (cfg, _) = read_config(f.path().to_str()).unwrap();
        assert_eq!(cfg.general.protocol, "both4");
    }

    #[test]
    fn log_short_fields_in_log_section() {
        let _env = clean_env();
        let f = write_tmp(
            "[database]\nurl = \"sqlite://x.db\"\n[api]\nhost = \"127.0.0.1:80\"\n[log]\nlevel = \"debug\"\nformat = \"json\"\n",
        );
        let (cfg, _) = read_config(f.path().to_str()).unwrap();
        assert_eq!(cfg.log.level, "debug");
        assert_eq!(cfg.log.format, "json");
    }

    #[test]
    fn database_url_env_top_priority() {
        let _env = clean_env();
        let f = write_tmp(
            "[database]\nurl = \"postgres://file@db/x\"\n[api]\nhost = \"127.0.0.1:80\"\n",
        );
        unsafe { std::env::set_var("ACME_DNS_DATABASE_URL", "sqlite:///tmp/from-url.db") };
        let (cfg, _) = read_config(f.path().to_str()).unwrap();
        unsafe { std::env::remove_var("ACME_DNS_DATABASE_URL") };
        assert_eq!(cfg.database.engine, "sqlite");
        assert_eq!(cfg.database.connection, "sqlite:///tmp/from-url.db");
    }

    #[test]
    fn generic_database_url_fallback() {
        let _env = clean_env();
        unsafe { std::env::set_var("DATABASE_URL", "sqlite:///tmp/generic.db") };
        unsafe { std::env::set_var("ACME_DNS_API_HOST", "127.0.0.1:80") };
        let (cfg, used) = read_config(Some("/nonexistent/nope.cfg")).unwrap();
        unsafe { std::env::remove_var("DATABASE_URL") };
        unsafe { std::env::remove_var("ACME_DNS_API_HOST") };
        assert_eq!(used, PathBuf::from("environment"));
        assert_eq!(cfg.database.engine, "sqlite");
        assert_eq!(cfg.database.connection, "sqlite:///tmp/generic.db");
    }

    #[test]
    fn acme_dns_database_url_beats_generic() {
        let _env = clean_env();
        unsafe { std::env::set_var("ACME_DNS_DATABASE_URL", "sqlite:///tmp/first.db") };
        unsafe { std::env::set_var("DATABASE_URL", "postgres://ignored/x") };
        unsafe { std::env::set_var("ACME_DNS_API_HOST", "127.0.0.1:80") };
        let (cfg, _) = read_config(Some("/nonexistent/nope.cfg")).unwrap();
        unsafe { std::env::remove_var("ACME_DNS_DATABASE_URL") };
        unsafe { std::env::remove_var("DATABASE_URL") };
        unsafe { std::env::remove_var("ACME_DNS_API_HOST") };
        assert_eq!(cfg.database.connection, "sqlite:///tmp/first.db");
    }

    #[test]
    fn file_database_url_works() {
        let _env = clean_env();
        let f = write_tmp(
            "[database]\nurl = \"sqlite:///tmp/file-url.db\"\n[api]\nhost = \"127.0.0.1:80\"\n",
        );
        let (cfg, _) = read_config(f.path().to_str()).unwrap();
        assert_eq!(cfg.database.engine, "sqlite");
        assert_eq!(cfg.database.connection, "sqlite:///tmp/file-url.db");
    }

    #[test]
    fn bad_url_scheme_fails() {
        let _env = clean_env();
        unsafe { std::env::set_var("DATABASE_URL", "mysql://x/y") };
        let err = read_config(Some("/nonexistent/nope.cfg")).unwrap_err();
        unsafe { std::env::remove_var("DATABASE_URL") };
        assert!(err.contains("unsupported database URL scheme"), "err={err}");
    }

    #[test]
    fn parses_example_config() {
        let _env = clean_env();
        let f = write_tmp(EXAMPLE_CONFIG);
        let (cfg, _) = read_config(f.path().to_str()).unwrap();
        assert_eq!(cfg.general.listen, "0.0.0.0:53");
        assert_eq!(cfg.database.engine, "sqlite");
        // [api] host = "0.0.0.0:80" 拆出的 ip/port
        assert_eq!(cfg.api.ip, "0.0.0.0");
        assert_eq!(cfg.api.port, "80");
        assert_eq!(cfg.log.format, "text");
    }

    #[test]
    fn api_host_parses_ip_port() {
        let _env = clean_env();
        let f =
            write_tmp("[database]\nurl = \"sqlite://x.db\"\n[api]\nhost = \"127.0.0.1:9000\"\n");
        let (cfg, _) = read_config(f.path().to_str()).unwrap();
        assert_eq!(cfg.api.ip, "127.0.0.1");
        assert_eq!(cfg.api.port, "9000");
    }

    #[test]
    fn api_host_env_top_priority() {
        let _env = clean_env();
        unsafe {
            std::env::set_var("ACME_DNS_API_HOST", "127.0.0.2:9443");
        }
        let f = write_tmp("[database]\nurl = \"sqlite://x.db\"\n[api]\nhost = \"10.0.0.1:8000\"\n");
        let (cfg, _) = read_config(f.path().to_str()).unwrap();
        assert_eq!(cfg.api.ip, "127.0.0.2");
        assert_eq!(cfg.api.port, "9443");
        unsafe {
            std::env::remove_var("ACME_DNS_API_HOST");
        }
    }

    #[test]
    fn api_host_ipv6_form() {
        let _env = clean_env();
        let f = write_tmp("[database]\nurl = \"sqlite://x.db\"\n[api]\nhost = \"[::1]:8443\"\n");
        let (cfg, _) = read_config(f.path().to_str()).unwrap();
        assert_eq!(cfg.api.ip, "[::1]");
        assert_eq!(cfg.api.port, "8443");
    }

    fn with_env<F: FnOnce() -> R + std::panic::UnwindSafe, R>(vars: &[(&str, &str)], f: F) -> R {
        let guard = env_lock();
        let saved: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(k, _)| {
                let v = std::env::var(k).ok();
                unsafe { std::env::remove_var(k) };
                (k.to_string(), v)
            })
            .collect();
        for (k, v) in vars {
            unsafe { std::env::set_var(k, v) };
        }
        // f 若 panic，先恢复环境再继续传播，保证后续测试不受污染。
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        // 结束时统一清理全部 ACME_DNS_*/DATABASE_URL 变量，防止泄漏到其它测试。
        for (k, _) in std::env::vars() {
            if k.starts_with("ACME_DNS_") || k == "DATABASE_URL" {
                unsafe { std::env::remove_var(&k) };
            }
        }
        for (k, saved_v) in &saved {
            match saved_v {
                Some(v) => unsafe { std::env::set_var(k, v) },
                None => unsafe { std::env::remove_var(k) },
            }
        }
        drop(guard);
        match result {
            Ok(v) => v,
            Err(e) => std::panic::resume_unwind(e),
        }
    }

    #[test]
    fn env_overrides_file() {
        with_env(
            &[
                ("ACME_DNS_API_HOST", "127.0.0.1:8443"),
                ("ACME_DNS_DATABASE_URL", "sqlite:///tmp/env-test.db"),
                ("ACME_DNS_API_HSTS_ENABLED", "true"),
                ("ACME_DNS_API_HSTS_MAX_AGE", "86400"),
                (
                    "ACME_DNS_API_CORSORIGINS",
                    "https://a.example, https://b.example",
                ),
                ("ACME_DNS_LOG_LEVEL", "debug"),
            ],
            || {
                let f = write_tmp(SAMPLE);
                let (cfg, _) = read_config(f.path().to_str()).unwrap();
                assert_eq!(cfg.api.ip, "127.0.0.1");
                assert_eq!(cfg.api.port, "8443");
                assert_eq!(cfg.database.connection, "sqlite:///tmp/env-test.db");
                assert!(cfg.api.hsts_enabled);
                assert_eq!(cfg.api.hsts_max_age, 86400);
                assert_eq!(cfg.api.cors_origins.len(), 2);
                assert_eq!(cfg.log.level, "debug");
                // 未被 env 覆盖的字段仍来自文件
                assert_eq!(cfg.general.listen, "127.0.0.1:5353");
            },
        );
    }

    #[test]
    fn env_only_without_file() {
        with_env(
            &[
                ("ACME_DNS_DATABASE_URL", "sqlite://:memory:"),
                ("ACME_DNS_API_HOST", "127.0.0.1:9000"),
            ],
            || {
                let (cfg, used) = read_config(Some("/nonexistent/nope.cfg")).unwrap();
                assert_eq!(used, PathBuf::from("environment"));
                assert_eq!(cfg.database.engine, "sqlite");
                assert_eq!(cfg.database.connection, "sqlite://:memory:");
                assert_eq!(cfg.api.ip, "127.0.0.1");
                assert_eq!(cfg.api.port, "9000");
            },
        );
    }

    #[test]
    #[should_panic(expected = "invalid boolean")]
    fn env_invalid_bool_panics() {
        with_env(
            &[
                ("ACME_DNS_DATABASE_URL", "sqlite://x.db"),
                ("ACME_DNS_API_DISABLE_REGISTRATION", "maybe"),
            ],
            || {
                let _ = read_config(Some("/nonexistent/nope.cfg"));
            },
        );
    }

    #[test]
    #[should_panic(expected = "invalid integer")]
    fn env_invalid_int_panics() {
        with_env(
            &[
                ("ACME_DNS_DATABASE_URL", "sqlite://x.db"),
                ("ACME_DNS_API_HSTS_MAX_AGE", "abc"),
            ],
            || {
                let _ = read_config(Some("/nonexistent/nope.cfg"));
            },
        );
    }
}
