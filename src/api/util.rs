//! API 公共工具：jsonError、请求校验、恒定时间口令比对、IP 头解析。
//!
//! 对齐 Go `pkg/api/util.go` 与 `pkg/acmedns/util.go`。

use uuid::Uuid;

use crate::models::sanitize_string;

/// 构造 `{"error": "<msg>"}` JSON 字符串。
pub fn json_error(message: &str) -> String {
    format!("{{\"error\": \"{message}\"}}")
}

/// 解析用户名 UUID；非法返回 None。
pub fn get_valid_username(u: &str) -> Option<Uuid> {
    Uuid::parse_str(u).ok()
}

/// 恒定时间 bcrypt 比对；任何错误一律 false。
pub fn correct_password(pw: &str, hash: &str) -> bool {
    bcrypt::verify(pw, hash).unwrap_or(false)
}

/// 用户不存在时的虚拟哈希校验，防止计时侧信道（对齐 Go 硬编码哈希）。
pub fn dummy_password_check(pw: &str) {
    const DUMMY_HASH: &str = "$2a$10$8JEFVNYYhLoBysjAxe2yBuXrkDojBQBkVpXEQgyQyjn43SvJ4vL36";
    let _ = correct_password(pw, DUMMY_HASH);
}

/// 从 `X-Forwarded-For` 类头解析 IP 列表（逗号分隔、去空白、去空项）。
pub fn ip_list_from_header(header: &str) -> Vec<String> {
    header
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .collect()
}

/// API key 校验：40 字符且净化后仍 40 字符。
pub fn valid_key(k: &str) -> bool {
    k.chars().count() == 40 && sanitize_string(k).chars().count() == 40
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_error_format() {
        assert_eq!(json_error("forbidden"), "{\"error\": \"forbidden\"}");
    }

    #[test]
    fn username_uuid_parsing() {
        assert!(get_valid_username("d420c923-bbd7-4056-ab64-c3ca54c9b3cf").is_some());
        assert!(get_valid_username("not-a-uuid").is_none());
    }

    #[test]
    fn password_verify_and_dummy() {
        let hash = bcrypt::hash("secret", 10).unwrap();
        assert!(correct_password("secret", &hash));
        assert!(!correct_password("wrong", &hash));
        // 虚拟哈希可正常参与比对不 panic
        dummy_password_check("anything");
    }

    #[test]
    fn header_ip_list() {
        assert_eq!(
            ip_list_from_header("1.2.3.4, 5.6.7.8 ,,9.9.9.9"),
            vec!["1.2.3.4", "5.6.7.8", "9.9.9.9"]
        );
        assert!(ip_list_from_header("").is_empty());
    }
}
