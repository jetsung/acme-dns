//! 核心领域模型：账户记录、CIDR 白名单、TXT 更新载荷。
//!
//! 对齐 Go 版 `pkg/acmedns/types.go` / `cidrslice.go` / `acmetxt.go` 的行为。

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// 账户完整记录（存储侧，含 bcrypt 口令哈希）。
#[derive(Debug, Clone)]
pub struct AcmeTxt {
    pub username: Uuid,
    /// bcrypt 哈希（`$2a$…`），绝非明文。
    pub password_hash: String,
    pub subdomain: String,
    pub allow_from: CidrSlice,
}

/// API 更新载荷（`POST /update` 的 JSON body）。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AcmeTxtPost {
    pub subdomain: String,
    #[serde(rename = "txt")]
    pub value: String,
}

/// 注册响应（`POST /register` 的 JSON）。
#[derive(Debug, Serialize)]
pub struct RegResponse {
    pub username: String,
    pub password: String,
    pub fulldomain: String,
    pub subdomain: String,
    pub allowfrom: Vec<String>,
}

/// 管理端账户 JSON（`GET /admin/accounts`、`GET /admin/accounts/{username}`）。
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminAccountResponse {
    pub username: String,
    pub fulldomain: String,
    pub subdomain: String,
    pub allowfrom: Vec<String>,
    pub txt: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_update: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
}

/// 管理端注册请求（`POST /admin/accounts`）。
#[derive(Debug, Deserialize, Default)]
pub struct AdminRegisterRequest {
    #[serde(default, rename = "allowfrom")]
    pub allow_from: CidrSlice,
    /// 可选自定义子域；缺省自动生成 UUID。
    #[serde(default)]
    pub subdomain: Option<String>,
}

/// 管理端密码重置响应。
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminPasswordResponse {
    pub username: String,
    pub password: String,
}

/// 管理端 TXT 设置请求（`PUT /admin/accounts/{username}/txt`）。
#[derive(Debug, Deserialize)]
pub struct AdminTxtRequest {
    pub txt: String,
    /// 第二条 TXT；缺省写空串（保留滚动位）。
    #[serde(default)]
    pub txt2: Option<String>,
}

/// 管理端 TXT 设置响应。
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminTxtResponse {
    pub subdomain: String,
    pub txt: Vec<String>,
}

/// 管理端 CIDR 更新请求（`PATCH /admin/accounts/{username}`）。
#[derive(Debug, Deserialize, Default)]
pub struct AdminAllowFromRequest {
    #[serde(default, rename = "allowfrom")]
    pub allow_from: CidrSlice,
}

/// `[general]` 段。
#[derive(Debug, Clone)]
pub struct GeneralConfig {
    pub listen: String,
    pub protocol: String,
    pub domain: String,
    pub nsname: String,
    pub nsadmin: String,
    pub records: Vec<String>,
    pub debug: bool,
}

/// `[database]` 段。
#[derive(Debug, Clone)]
pub struct DbConfig {
    pub engine: String,
    pub connection: String,
}

/// `[api]` 段。
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// 监听 IP；来自 `[api]` host 的 host 部分（优先）或兼容字段 `ip`。
    pub ip: String,
    /// 监听端口；来自 `[api]` host 的 port 部分（优先）或兼容字段 `port`。
    pub port: String,
    pub tls: String,
    pub tls_cert_privkey: String,
    pub tls_cert_fullchain: String,
    pub acme_cache_dir: String,
    pub notification_email: String,
    pub disable_registration: bool,
    pub cors_origins: Vec<String>,
    pub use_header: bool,
    pub header_name: String,
    pub hsts_enabled: bool,
    pub hsts_max_age: i64,
    pub hsts_include_subdomains: bool,
    pub hsts_preload: bool,
    /// 管理端 Bearer Token；为空表示不挂载 /admin 路由。
    pub admin_token: String,
}

/// 日志配置段：`[logconfig]` 为 Go 版原生段名；`[log]` 为 Rust 版提供的简写段名，两者等价。
#[derive(Debug, Clone)]
pub struct LogConfig {
    pub level: String,
    pub logtype: String,
    pub logfile: String,
    pub format: String,
}

/// 完整运行配置。
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub general: GeneralConfig,
    pub database: DbConfig,
    pub api: ApiConfig,
    pub log: LogConfig,
}
/// CIDR 白名单：字符串形式的 CIDR 列表。
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct CidrSlice(pub Vec<String>);

impl CidrSlice {
    /// 去除 IPv6 方括号后逐项校验 CIDR 合法性；任一项非法即报错。
    pub fn validate(&self) -> Result<(), String> {
        for v in &self.0 {
            let s = sanitize_ipv6_addr(v);
            parse_cidr(&s)?;
        }
        Ok(())
    }

    /// 仅保留合法 CIDR 项（去除方括号），用于入库与回显。
    pub fn valid_entries(&self) -> Vec<String> {
        self.0
            .iter()
            .map(|v| sanitize_ipv6_addr(v))
            .filter(|s| parse_cidr(s).is_ok())
            .collect()
    }

    /// 是否允许来自 `ip` 的请求；白名单为空时放行所有来源。
    pub fn allows(&self, ip: &str) -> bool {
        let entries = self.valid_entries();
        if entries.is_empty() {
            return true;
        }
        let Ok(remote) = ip.parse::<std::net::IpAddr>() else {
            return false;
        };
        entries.iter().any(|e| {
            parse_cidr(e)
                .map(|(_, net)| net.contains(&remote))
                .unwrap_or(false)
        })
    }

    /// 逐个 IP 匹配（用于反代头解析出的多 IP 场景）。
    pub fn allows_any(&self, ips: &[String]) -> bool {
        if ips.is_empty() {
            return self.allows("");
        }
        ips.iter().any(|ip| self.allows(ip))
    }

    /// 以 JSON 数组形式序列化合法项（入库 `AllowFrom` 字段）。
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.valid_entries()).unwrap_or_else(|_| "[]".to_string())
    }

    /// 从 JSON 数组字符串解析。
    pub fn from_json(s: &str) -> Self {
        let list: Vec<String> = serde_json::from_str(s).unwrap_or_default();
        CidrSlice(list)
    }
}

/// 解析 CIDR 字符串为 (网络地址, 网段)。
fn parse_cidr(s: &str) -> Result<(std::net::IpAddr, ipnet::IpNet), String> {
    s.parse::<ipnet::IpNet>()
        .map(|net| (net.network(), net))
        .map_err(|e| format!("invalid CIDR: {e}"))
}

/// 去除 IPv6 地址中的方括号（对齐 Go `sanitizeIPv6addr`）。
pub fn sanitize_ipv6_addr(s: &str) -> String {
    s.replace(['[', ']'], "")
}

/// URL-safe base64 字母表净化（对齐 Go `SanitizeString`）。
pub fn sanitize_string(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

/// 生成 `length` 长度的随机密码：ACME URL-safe base64 字母表，加密安全随机源。
pub fn generate_password(length: usize) -> String {
    use rand::RngExt;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890-_";
    let mut rng = rand::rng();
    (0..length)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
        .collect()
}

/// 校验 API key：40 字符且净化后仍为 40 字符。
pub fn valid_key(k: &str) -> bool {
    k.chars().count() == 40 && sanitize_string(k).chars().count() == 40
}

/// 校验 TXT 值：净化后恰为 43 字符（当前 LE 授权 key 尺寸）。
pub fn valid_txt(s: &str) -> bool {
    s.chars().count() == 43 && sanitize_string(s).chars().count() == 43
}

/// 校验子域：`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`。
pub fn valid_subdomain(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 63 {
        return false;
    }
    let ok_char = |c: u8| c.is_ascii_alphanumeric() || c == b'-';
    if !b[0].is_ascii_alphanumeric() || !b[b.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    b.iter().all(|&c| ok_char(c))
}

/// 生成新账户：UUIDv4 用户名、40 字符密码、UUID 子域。
pub fn new_acme_txt() -> (AcmeTxt, String) {
    let password = generate_password(40);
    let account = AcmeTxt {
        username: Uuid::new_v4(),
        password_hash: String::new(),
        subdomain: Uuid::new_v4().to_string(),
        allow_from: CidrSlice::default(),
    };
    (account, password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_string_strips_non_url_safe() {
        assert_eq!(sanitize_string("aB3-_x"), "aB3-_x");
        assert_eq!(sanitize_string("a b+c/d"), "abcd");
        assert_eq!(sanitize_string("héllo"), "hllo");
    }

    #[test]
    fn generate_password_length_and_alphabet() {
        let pw = generate_password(40);
        assert_eq!(pw.len(), 40);
        assert_eq!(sanitize_string(&pw), pw);
    }

    #[test]
    fn valid_key_length_and_charset() {
        assert!(valid_key(&generate_password(40)));
        assert!(!valid_key(&generate_password(39)));
        assert!(!valid_key(&"+".repeat(40))); // 含 URL-safe 字母表外字符
        assert!(!valid_key(&" ".repeat(40)));
    }

    #[test]
    fn valid_txt_43_chars() {
        let t = generate_password(43);
        assert!(valid_txt(&t));
        assert!(!valid_txt(&generate_password(42)));
        assert!(!valid_txt(&format!("{t} ")));
    }

    #[test]
    fn valid_subdomain_rules() {
        assert!(valid_subdomain("d420c923-bbd7-4056-ab64-c3ca54c9b3cf"));
        assert!(valid_subdomain("a"));
        assert!(!valid_subdomain("-abc"));
        assert!(!valid_subdomain("abc-"));
        assert!(!valid_subdomain("a_b"));
        assert!(!valid_subdomain(&"a".repeat(64)));
        assert!(!valid_subdomain(""));
    }

    #[test]
    fn cidr_slice_validate() {
        let c = CidrSlice(vec![
            "192.168.100.1/24".into(),
            "2002:c0a8:2a00::0/40".into(),
        ]);
        assert!(c.validate().is_ok());
        let bad = CidrSlice(vec!["192.168.0.0/99".into()]);
        assert!(bad.validate().is_err());
    }

    #[test]
    fn cidr_slice_valid_entries_strips_brackets() {
        let c = CidrSlice(vec![
            "[2001:db8::/32]".into(),
            "10.0.0.0/8".into(),
            "bad".into(),
        ]);
        assert_eq!(c.valid_entries(), vec!["2001:db8::/32", "10.0.0.0/8"]);
    }

    #[test]
    fn cidr_slice_allows() {
        let c = CidrSlice(vec!["192.168.100.0/24".into()]);
        assert!(c.allows("192.168.100.55"));
        assert!(!c.allows("203.0.113.7"));
        // 空白名单放行所有
        assert!(CidrSlice::default().allows("1.2.3.4"));
    }

    #[test]
    fn cidr_slice_allows_any_empty_list_falls_back() {
        let c = CidrSlice(vec!["10.0.0.0/8".into()]);
        assert!(!c.allows_any(&[])); // 空列表回退到 allows("")，白名单非空时拒绝
        assert!(c.allows_any(&["10.1.2.3".to_string()]));
        assert!(!c.allows_any(&["11.0.0.1".to_string()]));
    }

    #[test]
    fn cidr_json_roundtrip() {
        let c = CidrSlice(vec!["10.0.0.0/8".into()]);
        let j = c.to_json();
        assert_eq!(j, r#"["10.0.0.0/8"]"#);
        assert_eq!(CidrSlice::from_json(&j), c);
    }

    #[test]
    fn cidr_slice_is_valid_go_cases() {
        // 对齐 Go cidrslice_test.go: IsValid
        assert!(
            CidrSlice(vec!["192.168.100.1/24".into()])
                .validate()
                .is_ok()
        );
        assert!(
            CidrSlice(vec!["2002:c0a8:2a00::0/40".into()])
                .validate()
                .is_ok()
        );
        assert!(CidrSlice(vec!["bad input".into()]).validate().is_err());
        assert!(
            CidrSlice(vec!["10.0.0.0/8".into(), "bad".into()])
                .validate()
                .is_err()
        );
    }

    #[test]
    fn cidr_slice_valid_entries_go_cases() {
        // 对齐 Go cidrslice_test.go: ValidEntries 过滤非法项并去括号
        let c = CidrSlice(vec![
            "192.168.100.1/24".into(),
            "2002:c0a8:2a00::0/40".into(),
            "bad input".into(),
        ]);
        assert_eq!(
            c.valid_entries(),
            vec!["192.168.100.1/24", "2002:c0a8:2a00::0/40"]
        );
        let v6 = CidrSlice(vec!["[2002:c0a8:2a00::0/40]".into()]);
        assert_eq!(v6.valid_entries(), vec!["2002:c0a8:2a00::0/40"]);
    }

    #[test]
    fn sanitize_ipv6_strips_brackets() {
        assert_eq!(sanitize_ipv6_addr("[::1]"), "::1");
        assert_eq!(sanitize_ipv6_addr("192.168.0.1"), "192.168.0.1");
    }

    #[test]
    fn generate_password_charset_matches_acme() {
        // ACME URL-safe base64 字母表
        let alphabet: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890-_";
        for _ in 0..10 {
            let pw = generate_password(40);
            assert_eq!(pw.len(), 40);
            assert!(pw.chars().all(|c| alphabet.contains(c)), "pw={pw}");
        }
    }

    #[test]
    fn new_acme_txt_shape() {
        let (a, pw) = new_acme_txt();
        assert_eq!(pw.len(), 40);
        assert_eq!(a.subdomain.len(), 36); // UUID
        assert!(uuid::Uuid::parse_str(&a.username.to_string()).is_ok());
    }
}
