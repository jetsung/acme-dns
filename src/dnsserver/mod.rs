//! DNS 服务器主体：UDP/TCP 监听、查询分发与应答构造。
//!
//! 对齐 Go `pkg/nameserver/handler.go` / `initialize.go`：
//! - protocol: both / both4 / both6 / udp / udp4 / udp6 / tcp / tcp4 / tcp6
//! - EDNS0：版本非 0 回 BADVERS；版本 0 回显 OPT 并处理查询
//! - TXT 动态应答 TTL=1、最多两条；静态记录类型匹配，无匹配回退 CNAME
//! - 权威应答：NXDOMAIN 时附 SOA 到 Authority

use std::collections::HashMap;
use std::sync::Arc;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, error, info};

use crate::dnsserver::own_auth::OwnAuthKey;
use crate::dnsserver::records::{Records, parse_records};
use crate::dnsserver::validation::{Validator, sanitize_domain_question};
use crate::store::Store;

pub mod own_auth;
pub mod records;
pub mod validation;

/// 动态 TXT TTL 固定 1（对齐 Go）。
const TXT_TTL: u32 = 1;

/// 单个 DNS 监听器（一种协议）。
pub struct DnsServer {
    listen: String,
    proto: String,
    own_domain: String,
    domains: Arc<HashMap<String, Records>>,
    soa: Option<Record>,
    db: Arc<dyn Store>,
    own_auth_key: Arc<OwnAuthKey>,
}

impl DnsServer {
    /// 从配置构造（含静态记录解析与 SOA 生成）。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        listen: &str,
        proto: &str,
        domain: &str,
        nsname: &str,
        nsadmin: &str,
        static_records: &[String],
        db: Arc<dyn Store>,
        own_auth_key: Arc<OwnAuthKey>,
    ) -> Self {
        let (own_domain, domains, soa) = parse_records(static_records, domain, nsname, nsadmin);
        Self {
            listen: listen.to_string(),
            proto: proto.to_string(),
            own_domain,
            domains: Arc::new(domains),
            soa,
            db,
            own_auth_key,
        }
    }

    /// 启动监听；返回前确保套接字已绑定（对齐 NotifyStartedFunc 语义）。
    /// 成功时返回实际绑定的本地地址（端口为 0 时由内核分配）。
    pub async fn start(self: Arc<Self>) -> Result<std::net::SocketAddr, String> {
        match self.proto.as_str() {
            "udp" | "udp4" | "udp6" => self.run_udp().await,
            "tcp" | "tcp4" | "tcp6" => self.run_tcp().await,
            other => Err(format!("unsupported dns protocol: {other}")),
        }
    }

    async fn run_udp(self: Arc<Self>) -> Result<std::net::SocketAddr, String> {
        let socket = UdpSocket::bind(&self.listen)
            .await
            .map_err(|e| format!("DNS server {} failed: {e}", self.proto))?;
        let local = socket
            .local_addr()
            .map_err(|e| format!("udp local_addr: {e}"))?;
        info!(addr = %local, proto = %self.proto, "Starting DNS listener");
        let mut buf = vec![0u8; 4096];
        loop {
            let (len, peer) = socket
                .recv_from(&mut buf)
                .await
                .map_err(|e| format!("udp recv: {e}"))?;
            let msg = match Message::from_vec(&buf[..len]) {
                Ok(m) => m,
                Err(e) => {
                    debug!(error = %e, "malformed dns message");
                    continue;
                }
            };
            let reply = self.handle(&msg).await;
            if let Ok(bytes) = reply.to_vec() {
                let _ = socket.send_to(&bytes, &peer).await;
            }
        }
    }

    async fn run_tcp(self: Arc<Self>) -> Result<std::net::SocketAddr, String> {
        let listener = TcpListener::bind(&self.listen)
            .await
            .map_err(|e| format!("DNS server {} failed: {e}", self.proto))?;
        let local = listener
            .local_addr()
            .map_err(|e| format!("tcp local_addr: {e}"))?;
        info!(addr = %local, proto = %self.proto, "Starting DNS listener");
        loop {
            let (stream, _peer) = listener
                .accept()
                .await
                .map_err(|e| format!("tcp accept: {e}"))?;
            let this = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = handle_tcp(this, stream).await {
                    debug!(error = %e, "tcp dns session error");
                }
            });
        }
    }

    /// 处理一条 DNS 请求（对齐 Go handleRequest）。
    pub async fn handle(&self, request: &Message) -> Message {
        let mut reply = Message::response(request.metadata.id, request.metadata.op_code);
        // EDNS0 处理
        match request.edns.as_ref() {
            Some(edns) if edns.version() != 0 => {
                // 仅 EDNS0 标准化
                reply.metadata.response_code = ResponseCode::BADVERS;
                let mut opt = Edns::new();
                opt.set_max_payload(512);
                reply.set_edns(opt);
                return reply;
            }
            Some(_) => {
                let mut opt = Edns::new();
                opt.set_max_payload(512);
                reply.set_edns(opt);
            }
            None => {}
        }
        if request.metadata.op_code == OpCode::Query {
            self.read_query(request, &mut reply).await;
        }
        reply
    }

    /// 逐问题应答（对齐 Go readQuery）。
    async fn read_query(&self, request: &Message, reply: &mut Message) {
        // 回显问题段（Go dns.Msg.SetReply 语义）
        reply.metadata.op_code = request.metadata.op_code;
        reply.metadata.recursion_desired = request.metadata.recursion_desired;
        for q in &request.queries {
            reply.add_query(q.clone());
        }
        let mut authoritative = false;
        for q in &request.queries {
            let (records, rcode, auth) = self.answer(q).await;
            if auth {
                authoritative = true;
            }
            reply.metadata.response_code = rcode;
            reply.add_answers(records);
        }
        reply.metadata.authoritative = authoritative;
        if authoritative
            && reply.metadata.response_code == ResponseCode::NXDomain
            && let Some(soa) = &self.soa
        {
            reply.add_authorities([soa.clone()]);
        }
    }

    /// 单问题应答（对齐 Go answer）。
    async fn answer(&self, q: &Query) -> (Vec<Record>, ResponseCode, bool) {
        let lowered = q.name().to_lowercase().to_utf8();
        let validator = Validator {
            own_domain: &self.own_domain,
            domains: &self.domains,
        };
        let authoritative = validator.is_authoritative(&lowered);
        let mut rcode =
            if !validator.is_own_challenge(&lowered) && !validator.answering_for_domain(&lowered) {
                ResponseCode::NXDomain
            } else {
                ResponseCode::NoError
            };

        let mut records = self.get_record(&lowered, q.query_type());
        if q.query_type() == RecordType::TXT {
            let txt_rrs = if validator.is_own_challenge(&lowered) {
                self.answer_own_challenge(q).await
            } else {
                self.answer_txt(q).await
            };
            records.extend(txt_rrs);
        }
        if !records.is_empty() {
            rcode = ResponseCode::NoError;
        }
        (records, rcode, authoritative)
    }

    /// 静态记录类型匹配；无匹配回退 CNAME（对齐 Go getRecord）。
    fn get_record(&self, name: &str, qtype: RecordType) -> Vec<Record> {
        let Some(domain) = self.domains.get(name) else {
            return vec![];
        };
        let mut matched = vec![];
        let mut cnames = vec![];
        for rr in &domain.records {
            if rr.record_type() == qtype {
                matched.push(rr.clone());
            }
            if rr.record_type() == RecordType::CNAME {
                cnames.push(rr.clone());
            }
        }
        if matched.is_empty() {
            return cnames;
        }
        matched
    }

    /// 动态 TXT：净化子域，查库取至多两条非空值，TTL=1。
    async fn answer_txt(&self, q: &Query) -> Vec<Record> {
        let subdomain = sanitize_domain_question(&q.name().to_utf8());
        match self.db.get_txt_for_domain(&subdomain).await {
            Ok(values) => values
                .into_iter()
                .filter(|v| !v.is_empty())
                .take(2)
                .map(|v| {
                    Record::from_rdata(q.name().clone(), TXT_TTL, RData::TXT(TXT::new(vec![v])))
                })
                .collect(),
            Err(e) => {
                error!(error = %e, "Error while trying to get record");
                vec![]
            }
        }
    }

    /// 自身证书挑战 TXT：TTL=1、单条。
    async fn answer_own_challenge(&self, q: &Query) -> Vec<Record> {
        let key = self.own_auth_key.get().await.unwrap_or_default();
        let r = Record::from_rdata(q.name().clone(), TXT_TTL, RData::TXT(TXT::new(vec![key])));
        vec![r]
    }
}

/// TCP 长度前缀帧：2 字节大端长度 + 消息。
async fn handle_tcp(server: Arc<DnsServer>, mut stream: TcpStream) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let mut len_buf = [0u8; 2];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| format!("tcp read len: {e}"))?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| format!("tcp read body: {e}"))?;
        let request = Message::from_vec(&buf).map_err(|e| format!("tcp decode: {e}"))?;
        let reply = server.handle(&request).await;
        let bytes = reply.to_vec().map_err(|e| format!("tcp encode: {e}"))?;
        let out_len = (bytes.len() as u16).to_be_bytes();
        stream
            .write_all(&out_len)
            .await
            .map_err(|e| format!("tcp write len: {e}"))?;
        stream
            .write_all(&bytes)
            .await
            .map_err(|e| format!("tcp write body: {e}"))?;
    }
}

/// 依据 protocol 配置生成监听器组合（对齐 Go InitAndStart）。
pub fn protocols_for(protocol: &str) -> Vec<String> {
    if let Some(suffix) = protocol.strip_prefix("both") {
        // suffix: "" | "4" | "6"
        vec![format!("udp{suffix}"), format!("tcp{suffix}")]
    } else {
        vec![protocol.to_string()]
    }
}

/// 构造 DNS 查询（测试与 e2e 复用）。
pub fn build_query(name: &str, qtype: RecordType) -> Message {
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    let mut q = Query::new();
    q.set_name(hickory_proto::rr::Name::from_ascii(format!("{name}.")).unwrap());
    q.set_query_type(qtype);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AcmeTxt, AcmeTxtPost, CidrSlice};
    use crate::store::StoreError;
    use std::sync::Mutex;

    /// 内存假存储（对齐 Go testdb 的最小 mock）。
    struct FakeStore {
        txt: Mutex<HashMap<String, Vec<String>>>,
    }

    impl FakeStore {
        fn new() -> Self {
            let mut txt = HashMap::new();
            txt.insert(
                "d420c923-bbd7-4056-ab64-c3ca54c9b3cf".to_string(),
                vec!["tok1".to_string(), "tok2".to_string()],
            );
            Self {
                txt: Mutex::new(txt),
            }
        }
    }

    #[async_trait::async_trait]
    impl Store for FakeStore {
        async fn register(&self, _allow_from: CidrSlice) -> Result<(AcmeTxt, String), StoreError> {
            Err(StoreError::Db("not implemented".into()))
        }
        async fn get_by_username(&self, _u: uuid::Uuid) -> Result<AcmeTxt, StoreError> {
            Err(StoreError::Db("not implemented".into()))
        }
        async fn get_txt_for_domain(&self, subdomain: &str) -> Result<Vec<String>, StoreError> {
            let d = sanitize_domain_question(subdomain);
            Ok(self
                .txt
                .lock()
                .unwrap()
                .get(&d)
                .cloned()
                .unwrap_or_default())
        }
        async fn update(&self, _p: &AcmeTxtPost) -> Result<(), StoreError> {
            Err(StoreError::Db("not implemented".into()))
        }
        async fn close(&self) {}
    }

    fn server() -> Arc<DnsServer> {
        let records = vec![
            "auth.example.org. A 192.168.1.100".to_string(),
            "ns1.auth.example.org. A 192.168.1.101".to_string(),
            "cn.example.org. CNAME something.example.org.".to_string(),
            "ns2.auth.example.org. A 192.168.1.102".to_string(),
        ];
        Arc::new(DnsServer::new(
            "127.0.0.1:0",
            "udp",
            "auth.example.org",
            "ns1.auth.example.org",
            "admin.example.org",
            &records,
            Arc::new(FakeStore::new()),
            Arc::new(OwnAuthKey::new()),
        ))
    }

    #[tokio::test]
    async fn resolves_a_record() {
        let s = server();
        let req = build_query("auth.example.org", RecordType::A);
        let resp = s.handle(&req).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(resp.metadata.authoritative);
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].record_type(), RecordType::A);
    }

    #[tokio::test]
    async fn nxdomain_for_unknown() {
        let s = server();
        let req = build_query("nonexistent.domain.tld", RecordType::A);
        let resp = s.handle(&req).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
        // 非权威：Go isAuthoritative 对无关联域返回 false
        assert!(!resp.metadata.authoritative);
        assert!(resp.authorities.is_empty());
    }

    #[tokio::test]
    async fn nxdomain_subdomain_authoritative_with_soa() {
        let s = server();
        let req = build_query("nonexistent.auth.example.org", RecordType::A);
        let resp = s.handle(&req).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
        assert!(resp.metadata.authoritative);
        assert_eq!(resp.authorities.len(), 1);
        assert_eq!(resp.authorities[0].record_type(), RecordType::SOA);
    }

    #[tokio::test]
    async fn cname_fallback() {
        let s = server();
        let req = build_query("cn.example.org", RecordType::A);
        let resp = s.handle(&req).await;
        // 无 A 记录 → 回退 CNAME
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].record_type(), RecordType::CNAME);
    }

    #[tokio::test]
    async fn txt_dynamic_two_values_ttl1() {
        let s = server();
        let req = build_query(
            "d420c923-bbd7-4056-ab64-c3ca54c9b3cf.auth.example.org",
            RecordType::TXT,
        );
        let resp = s.handle(&req).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 2);
        for a in resp.answers {
            assert_eq!(a.record_type(), RecordType::TXT);
            assert_eq!(a.ttl, 1);
        }
    }

    #[tokio::test]
    async fn own_challenge_txt() {
        let records = vec![];
        let key = Arc::new(OwnAuthKey::new());
        key.set("challenge-token").await;
        let s = Arc::new(DnsServer::new(
            "127.0.0.1:0",
            "udp",
            "auth.example.org",
            "ns1.auth.example.org",
            "admin.example.org",
            &records,
            Arc::new(FakeStore::new()),
            key,
        ));
        let req = build_query("_acme-challenge.auth.example.org", RecordType::TXT);
        let resp = s.handle(&req).await;
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].ttl, 1);
    }

    #[tokio::test]
    async fn edns0_echo_and_badvers() {
        let s = server();
        let mut req = build_query("auth.example.org", RecordType::A);
        let mut opt = Edns::new();
        opt.set_max_payload(512);
        req.set_edns(opt);
        let resp = s.handle(&req).await;
        assert!(resp.edns.is_some());

        // 版本非 0 → BADVERS
        let mut req2 = build_query("auth.example.org", RecordType::A);
        let mut opt2 = Edns::new();
        opt2.set_version(1);
        req2.set_edns(opt2);
        let resp2 = s.handle(&req2).await;
        assert_eq!(resp2.metadata.response_code, ResponseCode::BADVERS);
    }

    #[test]
    fn protocols_for_variants() {
        assert_eq!(protocols_for("both"), vec!["udp", "tcp"]);
        assert_eq!(protocols_for("both4"), vec!["udp4", "tcp4"]);
        assert_eq!(protocols_for("both6"), vec!["udp6", "tcp6"]);
        assert_eq!(protocols_for("udp"), vec!["udp"]);
        assert_eq!(protocols_for("tcp6"), vec!["tcp6"]);
    }

    #[tokio::test]
    async fn udp_roundtrip() {
        // 先探测绑定地址
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let s2 = Arc::new(DnsServer::new(
            &addr.to_string(),
            "udp",
            "auth.example.org",
            "ns1.auth.example.org",
            "admin.example.org",
            &["auth.example.org. A 192.168.1.100".to_string()],
            Arc::new(FakeStore::new()),
            Arc::new(OwnAuthKey::new()),
        ));
        let h = tokio::spawn(async move { s2.start().await });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let req = build_query("auth.example.org", RecordType::A);
        sock.send_to(&req.to_vec().unwrap(), addr).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, _) = sock.recv_from(&mut buf).await.unwrap();
        let resp = Message::from_vec(&buf[..n]).unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);
        drop(sock);
        h.abort();
    }
}
