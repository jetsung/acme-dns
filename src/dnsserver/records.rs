//! 静态记录解析与 SOA 生成（对齐 Go `pkg/nameserver/parseconfig.go`）。

use std::collections::HashMap;

use hickory_proto::rr::{Name, RData, Record, RecordType};
use tracing::error;

/// 单个域名的记录集。
#[derive(Debug, Clone, Default)]
pub struct Records {
    pub records: Vec<Record>,
}

/// 解析结果：OwnDomain（小写带尾点）、域名映射、SOA 记录。
pub type ParsedRecords = (String, HashMap<String, Records>, Option<Record>);

/// 解析静态记录字符串并生成 SOA；解析失败的行跳过并记日志。
pub fn parse_records(
    static_records: &[String],
    domain: &str,
    nsname: &str,
    nsadmin: &str,
) -> ParsedRecords {
    let mut domains: HashMap<String, Records> = HashMap::new();
    let mut soa: Option<Record> = None;

    for v in static_records {
        let lower = v.to_lowercase();
        match parse_rr(&lower) {
            Ok(rr) => append_rr(&mut domains, rr),
            Err(e) => {
                error!(error = %e, rr = %v, "Could not parse RR from config");
            }
        }
    }

    // SOA：serial 取 yyyyMMddHH（本地时间，对齐 Go time.Now().Format("2006010215")）
    let serial = chrono::Local::now().format("%Y%m%d%H").to_string();
    let soa_str = format!(
        "{}. SOA {}. {}. {} 28800 7200 604800 86400",
        domain.to_lowercase(),
        nsname.to_lowercase(),
        nsadmin.to_lowercase(),
        serial
    );
    match parse_rr(&soa_str) {
        Ok(rr) => {
            append_rr(&mut domains, rr.clone());
            soa = Some(rr);
        }
        Err(e) => {
            error!(error = %e, soa = %soa_str, "Error while adding SOA record");
        }
    }

    let mut own = domain.to_lowercase();
    if !own.ends_with('.') {
        own.push('.');
    }
    (own, domains, soa)
}

/// 解析单条资源记录字符串（hickory-proto）。
pub fn parse_rr(s: &str) -> Result<Record, String> {
    let lower = s.trim().to_lowercase();
    parse_rr_inner(&lower)
}

fn parse_rr_inner(s: &str) -> Result<Record, String> {
    // 简单分词：name ttl class type rdata / 或 name type rdata
    let toks: Vec<&str> = s.split_whitespace().collect();
    if toks.len() < 3 {
        return Err(format!("too few fields: {s}"));
    }
    let name = {
        let n = toks[0];
        let n = if n.ends_with('.') {
            n.to_string()
        } else {
            format!("{n}.")
        };
        Name::from_ascii(&n).map_err(|e| e.to_string())?
    };
    // 支持省略 TTL/class 的两种形态：name type rdata | name ttl class type rdata
    let (rtype_tok, rdata_toks) = if toks.len() >= 4 && toks[1].parse::<u32>().is_ok() {
        (toks[3].to_uppercase(), &toks[4..])
    } else {
        (toks[1].to_uppercase(), &toks[2..])
    };
    let rtype = std::str::FromStr::from_str(&rtype_tok)
        .map_err(|e| format!("unknown type {rtype_tok}: {e}"))?;
    let rdata = parse_rdata(rtype, rdata_toks)?;
    Ok(Record::from_rdata(name, 3600, rdata))
}

fn parse_rdata(rtype: RecordType, toks: &[&str]) -> Result<RData, String> {
    if toks.is_empty() {
        return Err("missing rdata".into());
    }
    match rtype {
        RecordType::A => {
            let ip: std::net::Ipv4Addr = toks[0].parse().map_err(|e| format!("{e}"))?;
            Ok(RData::A(ip.into()))
        }
        RecordType::AAAA => {
            let ip: std::net::Ipv6Addr = toks[0].parse().map_err(|e| format!("{e}"))?;
            Ok(RData::AAAA(ip.into()))
        }
        RecordType::NS | RecordType::CNAME | RecordType::PTR => {
            let n = Name::from_ascii(toks[0]).map_err(|e| e.to_string())?;
            match rtype {
                RecordType::NS => Ok(RData::NS(hickory_proto::rr::rdata::NS(n))),
                RecordType::CNAME => Ok(RData::CNAME(hickory_proto::rr::rdata::CNAME(n))),
                _ => Ok(RData::PTR(hickory_proto::rr::rdata::PTR(n))),
            }
        }
        RecordType::TXT => {
            let text = toks.join(" ");
            let trimmed = text.trim_matches('"');
            Ok(RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![
                trimmed.to_string(),
            ])))
        }
        RecordType::SOA => {
            if toks.len() < 7 {
                return Err("SOA needs 7 fields".into());
            }
            let mname = Name::from_ascii(toks[0]).map_err(|e| e.to_string())?;
            let rname = Name::from_ascii(toks[1]).map_err(|e| e.to_string())?;
            let serial: u32 = toks[2].parse().map_err(|e| format!("{e}"))?;
            let refresh: i32 = toks[3].parse().map_err(|e| format!("{e}"))?;
            let retry: i32 = toks[4].parse().map_err(|e| format!("{e}"))?;
            let expire: i32 = toks[5].parse().map_err(|e| format!("{e}"))?;
            let minimum: u32 = toks[6].parse().map_err(|e| format!("{e}"))?;
            Ok(RData::SOA(hickory_proto::rr::rdata::SOA::new(
                mname, rname, serial, refresh, retry, expire, minimum,
            )))
        }
        other => Err(format!("unsupported record type {other}")),
    }
}

/// 将记录按 owner name 归档（对齐 Go `appendRR`）。
pub fn append_rr(domains: &mut HashMap<String, Records>, rr: Record) {
    let key = rr.name.clone().to_lowercase().to_utf8();
    domains.entry(key).or_default().records.push(rr);
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORDS: &[&str] = &[
        "auth.example.org. A 192.168.1.100",
        "ns1.auth.example.org. A 192.168.1.101",
        "cn.example.org CNAME something.example.org.",
        "!''b', unparseable ",
        "ns2.auth.example.org. A 192.168.1.102",
    ];

    fn as_strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_valid_and_skips_unparseable() {
        let (own, domains, soa) = parse_records(
            &as_strs(RECORDS),
            "auth.example.org",
            "ns1.auth.example.org",
            "admin.example.org",
        );
        assert_eq!(own, "auth.example.org.");
        assert!(domains.contains_key("auth.example.org."));
        assert!(domains.contains_key("ns1.auth.example.org."));
        assert!(domains.contains_key("ns2.auth.example.org."));
        assert!(domains.contains_key("cn.example.org."));
        assert!(soa.is_some());
    }

    #[test]
    fn soa_fields() {
        let (_, _, soa) = parse_records(
            &as_strs(RECORDS),
            "auth.example.org",
            "ns1.auth.example.org",
            "admin.example.org",
        );
        let soa = soa.unwrap();
        let soa_rd = match &soa.data {
            RData::SOA(s) => s,
            other => panic!("not soa: {other:?}"),
        };
        assert!(soa_rd.serial >= 2_026_010_100); // yyyyMMddHH 形态
        assert_eq!(soa_rd.refresh, 28800);
        assert_eq!(soa_rd.retry, 7200);
        assert_eq!(soa_rd.expire, 604800);
        assert_eq!(soa_rd.minimum, 86400);
        assert_eq!(soa.name.clone().to_utf8(), "auth.example.org.");
    }

    #[test]
    fn invalid_soa_domain_logs_and_continues() {
        // 对齐 Go TestParse：domain=')' 时 SOA 解析失败但不 panic
        let (own, domains, soa) =
            parse_records(&[], ")", "ns1.auth.example.org", "admin.example.org");
        assert_eq!(own, ")."); // 仍会补尾点
        assert!(domains.is_empty());
        assert!(soa.is_none());
    }
}
