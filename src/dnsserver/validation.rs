//! DNS 请求校验：权威判定、自身挑战识别、域名净化。
//!
//! 对齐 Go 版 `pkg/nameserver/handler.go` 与 `util.go`。

use std::collections::HashMap;

use crate::dnsserver::records::Records;

/// `_acme-challenge.` 前缀长度。
const ACME_CHALLENGE_PREFIX: &str = "_acme-challenge.";

/// 域名净化：取小写并截掉第一个 `.` 之后的部分（对齐 Go `sanitizeDomainQuestion`）。
pub fn sanitize_domain_question(d: &str) -> String {
    let lower = d.to_lowercase();
    match lower.find('.') {
        Some(0) | None => lower,
        Some(i) => lower[..i].to_string(),
    }
}

/// 权威与路由判定上下文。
pub struct Validator<'a> {
    pub own_domain: &'a str,
    pub domains: &'a HashMap<String, Records>,
}

impl<'a> Validator<'a> {
    /// 是否有该域名的记录（OwnDomain 或静态记录表）。
    pub fn answering_for_domain(&self, name: &str) -> bool {
        if self.own_domain == name {
            return true;
        }
        self.domains.contains_key(name)
    }

    /// 权威判定：自身命中，或逐级父域命中（对齐 Go `isAuthoritative`）。
    pub fn is_authoritative(&self, name: &str) -> bool {
        if self.answering_for_domain(name) {
            return true;
        }
        let mut off = 0usize;
        let bytes = name.as_bytes();
        loop {
            match bytes[off..].iter().position(|&b| b == b'.') {
                Some(i) => {
                    off += i + 1;
                    if off >= bytes.len() {
                        return false;
                    }
                    if self.answering_for_domain(&name[off..]) {
                        return true;
                    }
                }
                None => return false,
            }
        }
    }

    /// 是否为 acme-dns 自身证书的 ACME 挑战查询。
    pub fn is_own_challenge(&self, name: &str) -> bool {
        if let Some(domain) = name.strip_prefix(ACME_CHALLENGE_PREFIX) {
            return domain == self.own_domain;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnsserver::records::parse_records;

    fn setup() -> (String, HashMap<String, Records>) {
        let records = vec![
            "auth.example.org. A 192.168.1.100".to_string(),
            "ns1.auth.example.org. A 192.168.1.101".to_string(),
        ];
        let (own, domains, _soa) = parse_records(
            &records,
            "auth.example.org",
            "ns1.auth.example.org",
            "admin.example.org",
        );
        (own, domains)
    }

    #[test]
    fn sanitize_takes_first_label() {
        assert_eq!(
            sanitize_domain_question("d420c923-bbd7-4056-ab64-c3ca54c9b3cf.auth.example.org."),
            "d420c923-bbd7-4056-ab64-c3ca54c9b3cf"
        );
        assert_eq!(sanitize_domain_question("EXAMPLE.ORG."), "example");
    }

    #[test]
    fn answering_for_domain() {
        let (own, domains) = setup();
        let v = Validator {
            own_domain: &own,
            domains: &domains,
        };
        assert!(v.answering_for_domain("auth.example.org."));
        assert!(v.answering_for_domain("ns1.auth.example.org."));
        assert!(!v.answering_for_domain("whatever.tld."));
    }

    #[test]
    fn is_authoritative_subdomain_walk() {
        let (own, domains) = setup();
        let v = Validator {
            own_domain: &own,
            domains: &domains,
        };
        assert!(v.is_authoritative("auth.example.org."));
        assert!(v.is_authoritative("nonexistent.auth.example.org.")); // 父域命中即权威
        assert!(!v.is_authoritative("nonexistent.domain.tld."));
    }

    #[test]
    fn is_own_challenge_matches_prefix_and_domain() {
        let (own, domains) = setup();
        let v = Validator {
            own_domain: &own,
            domains: &domains,
        };
        assert!(v.is_own_challenge("_acme-challenge.auth.example.org."));
        assert!(!v.is_own_challenge("_acme-challenge.other.example.org."));
        assert!(!v.is_own_challenge("auth.example.org."));
    }
}
