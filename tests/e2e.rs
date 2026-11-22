//! 端到端集成测试：临时 SQLite + 随机高端口启动完整服务栈。
//!
//! 覆盖：register → update → DNS TXT 查询返回新值；二次 update 滚动两条；
//! 未注册子域 NXDOMAIN + SOA；鉴权失败 401；acme.sh 兼容调用形态。

use std::sync::Arc;

use acme_dns::api::router::build_router;
use acme_dns::config::read_config;
use acme_dns::dnsserver::DnsServer;
use acme_dns::dnsserver::own_auth::OwnAuthKey;
use acme_dns::store::Store;

use hickory_proto::op::{MessageType, OpCode, Query};
use hickory_proto::rr::RecordType;
use hickory_proto::serialize::binary::BinDecodable;

struct Stack {
    _dir: std::path::PathBuf,
    api_addr: String,
    dns_addr: std::net::SocketAddr,
    db: Arc<dyn Store>,
}
fn test_config() -> (std::path::PathBuf, acme_dns::models::AppConfig) {
    // 目录名加入调用计数：两个 e2e 测试在同一进程内并行跑（cargo harness），
    // 同名目录会共用一个 config.toml，并发 fs::write 截断会导致偶发解析失败。
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "acme_dns_e2e_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("config.toml");
    std::fs::write(
        &cfg_path,
        r#"
[general]
listen = "127.0.0.1:0"
protocol = "udp"
domain = "auth.example.org"
nsname = "auth.example.org"
nsadmin = "admin.example.org"
records = ["auth.example.org. A 198.51.100.1", "auth.example.org. NS auth.example.org."]
debug = false

[database]
url = "sqlite://:memory:"

[api]
host = "127.0.0.1:0"
tls = "none"
admin_token = "e2e-admin-token"
disable_registration = false
corsorigins = ["*"]
use_header = false
header_name = "X-Forwarded-For"

[log]
level = "info"
type = "stdout"
format = "text"
"#,
    )
    .unwrap();
    let cfg = read_config(Some(cfg_path.to_str().unwrap())).unwrap().0;
    (dir, cfg)
}
async fn start_stack() -> Stack {
    start_stack_with_token("e2e-admin-token").await
}

async fn start_stack_with_token(token: &str) -> Stack {
    let (dir, mut cfg) = test_config();
    cfg.api.admin_token = token.to_string();
    let db: Arc<dyn Store> = Arc::new(
        acme_dns::store::sqlite::SqliteStore::new(":memory:")
            .await
            .unwrap(),
    );
    let key = Arc::new(OwnAuthKey::new());

    // 先占一个随机 UDP 端口再 drop，避免 start() 内部无限循环阻塞取址
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dns_listen = probe.local_addr().unwrap();
    drop(probe);
    let server = Arc::new(DnsServer::new(
        &dns_listen.to_string(),
        "udp",
        &cfg.general.domain,
        &cfg.general.nsname,
        &cfg.general.nsadmin,
        &cfg.general.records,
        db.clone(),
        key.clone(),
    ));
    let dns_addr = dns_listen;
    tokio::spawn(async move { server.start().await });

    // API（随机端口）
    let router = build_router(Arc::new(cfg.clone()), db.clone(), key.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    Stack {
        _dir: dir,
        api_addr: format!("http://{api_addr}"),
        dns_addr,
        db,
    }
}

fn build_query(name: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = hickory_proto::op::Message::new(0xABCD, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let mut q = Query::new();
    q.set_name(hickory_proto::rr::Name::from_utf8(name).unwrap());
    q.set_query_type(qtype);
    msg.add_query(q);
    encode_msg(&msg)
}

fn encode_msg(msg: &hickory_proto::op::Message) -> Vec<u8> {
    msg.to_vec().unwrap()
}

fn parse_response(bytes: &[u8]) -> hickory_proto::op::Message {
    let mut d = hickory_proto::serialize::binary::BinDecoder::new(bytes);
    hickory_proto::op::Message::read(&mut d).unwrap()
}

#[tokio::test]
async fn e2e_register_update_dns() {
    let stack = start_stack().await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();

    // 1. register
    let resp = client
        .post(format!("{}/register", stack.api_addr))
        .body("")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "register should 201");
    let reg: serde_json::Value = resp.json().await.unwrap();
    let user = reg["username"].as_str().unwrap();
    let pass = reg["password"].as_str().unwrap();
    let subdomain = reg["subdomain"].as_str().unwrap();
    let fulldomain = reg["fulldomain"].as_str().unwrap();
    assert_eq!(fulldomain, format!("{subdomain}.auth.example.org"));
    assert_eq!(pass.len(), 40);

    // 2. update（43 字符 txt）
    let txt1 = "a".repeat(43);
    let resp = client
        .post(format!("{}/update", stack.api_addr))
        .header("X-Api-User", user)
        .header("X-Api-Key", pass)
        .header("Content-Type", "application/json")
        .body(format!(
            r#"{{"subdomain": "{subdomain}", "txt": "{txt1}"}}"#
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "update should 200");
    assert_eq!(resp.json::<serde_json::Value>().await.unwrap()["txt"], txt1);

    // 3. update 后 store 落库断言（两条空 TXT，其一为新值）
    let rows = stack.db.get_txt_for_domain(subdomain).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().any(|r| r == &txt1));

    // 4. 再次 update → 滚动为两条不同记录
    let txt2 = "b".repeat(43);
    let resp = client
        .post(format!("{}/update", stack.api_addr))
        .header("X-Api-User", user)
        .header("X-Api-Key", pass)
        .header("Content-Type", "application/json")
        .body(format!(
            r#"{{"subdomain": "{subdomain}", "txt": "{txt2}"}}"#
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let rows = stack.db.get_txt_for_domain(subdomain).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().any(|r| r == &txt1));
    assert!(rows.iter().any(|r| r == &txt2));

    // 5. 鉴权失败 401
    let resp = client
        .post(format!("{}/update", stack.api_addr))
        .header("X-Api-User", user)
        .header("X-Api-Key", &"x".repeat(40))
        .header("Content-Type", "application/json")
        .body(format!(
            r#"{{"subdomain": "{subdomain}", "txt": "{txt1}"}}"#
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert_eq!(
        resp.json::<serde_json::Value>().await.unwrap()["error"],
        "forbidden"
    );

    // 6. acme.sh 兼容形态：JSON + 两个头（同上已覆盖）；这里再验证 health
    let resp = client
        .get(format!("{}/health", stack.api_addr))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 7. DNS 线上应答：向已启动的 UDP server 查询 TXT
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(stack.dns_addr).await.unwrap();
    let q = build_query(fulldomain, RecordType::TXT);
    socket.send(&q).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let len = tokio::time::timeout(std::time::Duration::from_secs(3), socket.recv(&mut buf))
        .await
        .expect("dns reply timeout")
        .unwrap();
    let reply = parse_response(&buf[..len]);
    assert_eq!(
        reply.metadata.response_code,
        hickory_proto::op::ResponseCode::NoError
    );
    let answers: Vec<String> = reply
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            hickory_proto::rr::RData::TXT(txt) => Some(txt.to_string()),
            _ => None,
        })
        .collect();
    assert!(
        answers.iter().any(|a| a.contains(&txt1)),
        "TXT answer should contain new value: {answers:?}"
    );

    // 8. 未注册子域 → NXDOMAIN + Authority SOA
    let q = build_query("noexist12345.auth.example.org", RecordType::TXT);
    socket.send(&q).await.unwrap();
    let len = tokio::time::timeout(std::time::Duration::from_secs(3), socket.recv(&mut buf))
        .await
        .expect("dns reply timeout")
        .unwrap();
    let reply = parse_response(&buf[..len]);
    assert_eq!(
        reply.metadata.response_code,
        hickory_proto::op::ResponseCode::NXDomain
    );
    assert!(
        reply
            .authorities
            .iter()
            .any(|r| matches!(&r.data, hickory_proto::rr::RData::SOA(_))),
        "NXDOMAIN should carry SOA in authority"
    );

    // 9. EDNS0 版本 1 → BADVERS
    let mut msg = hickory_proto::op::Message::new(0xBEEF, MessageType::Query, OpCode::Query);
    let mut q = Query::new();
    q.set_name(hickory_proto::rr::Name::from_utf8(fulldomain).unwrap());
    q.set_query_type(RecordType::TXT);
    msg.add_query(q);
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_version(1);
    msg.set_edns(edns);
    let bytes = encode_msg(&msg);
    socket.send(&bytes).await.unwrap();
    let len = tokio::time::timeout(std::time::Duration::from_secs(3), socket.recv(&mut buf))
        .await
        .expect("dns reply timeout")
        .unwrap();
    let reply = parse_response(&buf[..len]);
    // 对齐 Go 线上行为：低 4 位为 0，完整 RCODE 16 由 EDNS OPT 的扩展 rcode 表达
    let edns = reply.edns.as_ref().expect("BADVERS reply should carry OPT");
    assert_eq!(
        edns.rcode_high(),
        1,
        "extended rcode high nibble should be 1 (RCODE 16 = BADVERS)"
    );
    assert_eq!(reply.metadata.response_code.low(), 0);
}

#[tokio::test]
async fn e2e_admin_accounts_flow() {
    let stack = start_stack().await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let base = format!("{}/admin/accounts", stack.api_addr);
    let auth = ("Authorization", "Bearer e2e-admin-token");

    // 未带 token → 401
    let resp = client.get(&base).send().await.unwrap();
    assert_eq!(resp.status(), 401, "missing token should 401");

    // 错误 token → 401
    let resp = client
        .get(&base)
        .header("Authorization", "Bearer wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "wrong token should 401");

    // 注册（自定义子域 + allowfrom）
    let resp = client
        .post(&base)
        .header(auth.0, auth.1)
        .json(&serde_json::json!({
            "subdomain": "e2e-sub",
            "allowfrom": ["192.168.100.1/24"]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "admin create should 201");
    let reg: serde_json::Value = resp.json().await.unwrap();
    let username = reg["username"].as_str().unwrap().to_string();
    assert_eq!(reg["subdomain"], "e2e-sub");
    assert_eq!(
        reg["allowfrom"].as_array().unwrap(),
        &serde_json::json!(["192.168.100.1/24"])
            .as_array()
            .unwrap()
            .clone()
    );

    // 重复子域 → 409
    let resp = client
        .post(&base)
        .header(auth.0, auth.1)
        .json(&serde_json::json!({ "subdomain": "e2e-sub" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "duplicate subdomain should 409");

    // 列表包含新账户
    let resp = client
        .get(&base)
        .header(auth.0, auth.1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let list: serde_json::Value = resp.json().await.unwrap();
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .any(|a| a["subdomain"] == "e2e-sub"),
        "list should contain created account"
    );

    // 单账户查询
    let resp = client
        .get(format!("{base}/{username}"))
        .header(auth.0, auth.1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let one: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(one["username"], username.as_str());

    // PATCH allowfrom → 清空
    let resp = client
        .patch(format!("{base}/{username}"))
        .header(auth.0, auth.1)
        .json(&serde_json::json!({ "allowfrom": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let patched: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(patched["allowfrom"].as_array().unwrap().len(), 0);

    // 重置密码
    let resp = client
        .post(format!("{base}/{username}/password"))
        .header(auth.0, auth.1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let pw: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(pw["password"].as_str().unwrap().len(), 40);

    // 写入 TXT（合法 43 字符）
    let txt = "b".repeat(43);
    let resp = client
        .put(format!("{base}/{username}/txt"))
        .header(auth.0, auth.1)
        .json(&serde_json::json!({ "txt": txt }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let txt_out: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(txt_out["txt"].as_array().unwrap()[0], txt.as_str());

    // 清空 TXT
    let resp = client
        .delete(format!("{base}/{username}/txt"))
        .header(auth.0, auth.1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 删除账户
    let resp = client
        .delete(format!("{base}/{username}"))
        .header(auth.0, auth.1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "delete should 200");

    // 删除后再查 → 404
    let resp = client
        .get(format!("{base}/{username}"))
        .header(auth.0, auth.1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "deleted account should 404");
}
