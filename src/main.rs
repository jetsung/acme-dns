//! acme-dns —— acme-dns 的 Rust 实现。
//!
//! 二进制入口：加载配置 → 初始化日志 → 打开存储 → 启动 DNS 与 API →
//! 汇聚致命错误并管理进程退出（对齐 Go `main.go` 的编排）。

use acme_dns::{api, config, dnsserver, logger, models, store};

use std::sync::Arc;

use crate::dnsserver::DnsServer;
use crate::dnsserver::own_auth::OwnAuthKey;
use crate::models::AppConfig;
use crate::store::Store;

const HELP_TEXT: &str = r#"acme-dns — acme-dns 的 Rust 重写版

用法: acme-dns [--local | --remote [--url <base>] [--token <token>]] [子命令] [-c <配置文件>]

不带子命令时默认启动 DNS + API 服务。

子命令:
  init            生成示例配置文件 config.toml（已存在时不覆盖；-c 可指定路径）
  keygen [长度]   生成随机密钥/令牌（默认 48 字符，URL-safe base64 字母表，加密安全随机源；
                  可选长度 8-256，可用于 [api] admin_token 等场景）
  version         输出版本号
  help            打印本帮助信息

账户管理（同一组命令，按目标分流；不限 -c/remote 前缀顺序）:
  accounts list                          列出全部账户
  accounts show <subdomain>              按子域查看账户
  accounts delete <username>             删除账户（UUID）
  accounts password <username>           重置账户密码（输出新明文密码）
  txt get <subdomain>                    查询账户当前 TXT
  txt set <subdomain> <txt> [txt2]       覆盖写入 TXT（≤2 条）
  txt clear <subdomain>                  清空 TXT

目标选择（决定上面命令走本地库还是远端 API）:
  --local                                强制走本地数据库（默认；读 -c 配置）
  --remote [--url <base>] [--token <t>]  走目标实例 /admin HTTP API，不读 -c；
                                         --url/--token 可省略，回退环境变量
                                         ACME_DNS_URL / ACME_DNS_TOKEN
示例:
  acme-dns --remote accounts list
  acme-dns accounts list --remote --url https://acme.example.org --token <t>
  acme-dns txt set <subdomain> <txt> --remote
"#;

/// `version` 子命令：输出单行版本号。
fn run_version() -> i32 {
    println!("{}", env!("CARGO_PKG_VERSION"));
    0
}

/// `keygen` 子命令：生成随机密钥/令牌（URL-safe base64 字母表，加密安全随机源）。
fn run_keygen(rest: &[String]) -> i32 {
    const DEFAULT_LEN: usize = 48;
    const MAX_LEN: usize = 256;
    let len = match rest.first() {
        None => DEFAULT_LEN,
        Some(s) => match s.parse::<usize>() {
            Ok(n) if (8..=MAX_LEN).contains(&n) => n,
            Ok(n) => {
                eprintln!("Error: keygen 长度需在 8-{MAX_LEN} 之间，得到 {n}");
                return 2;
            }
            Err(_) => {
                eprintln!("Error: keygen 长度需为整数，得到 {s:?}");
                return 2;
            }
        },
    };
    println!("{}", crate::models::generate_password(len));
    0
}

/// `help` / `-h` / `--help`：打印帮助。
fn print_help(to_stderr: bool) {
    if to_stderr {
        eprint!("{HELP_TEXT}");
    } else {
        print!("{HELP_TEXT}");
    }
}

/// `init` 子命令：生成示例配置文件，已存在时不覆盖。
fn run_init(config_path: Option<&str>) -> i32 {
    let path = std::path::PathBuf::from(config_path.unwrap_or(config::LOCAL_CONFIG));
    if path.exists() {
        eprintln!("配置文件 {} 已存在，不覆盖。", path.display());
        return 2;
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        eprintln!("创建目录 {} 失败: {e}", parent.display());
        return 2;
    }
    match std::fs::write(&path, config::EXAMPLE_CONFIG) {
        Ok(()) => {
            println!("已生成示例配置文件: {}", path.display());
            0
        }
        Err(e) => {
            eprintln!("写入配置文件 {} 失败: {e}", path.display());
            2
        }
    }
}

/// 管理子命令入口：解析参数、加载配置、打开存储并执行。
fn run_admin_command(
    group: &str,
    sub: Option<&str>,
    rest: &[String],
    config_path: Option<&str>,
    target: Target,
    remote_opts: &RemoteOpts,
) -> i32 {
    let sub = match sub {
        Some(s) => s,
        None => {
            eprintln!("Error: missing subcommand for {group}");
            print_help(true);
            return 1;
        }
    };
    // 目标解析：显式 --remote 走远端；Auto 时给了 url/token（参数或环境变量）即走远端
    let remote = match target {
        Target::Local => None,
        Target::Remote => match remote_opts.clone().resolve() {
            Some((base, token)) => Some((base, token)),
            None => {
                eprintln!(
                    "Error: --remote 需要 --url <base> 与 --token <token>（或环境变量 ACME_DNS_URL / ACME_DNS_TOKEN）"
                );
                return 2;
            }
        },
        Target::Auto => remote_opts.clone().resolve(),
    };
    if let Some((base, token)) = remote {
        return run_remote_target(&base, &token, group, sub, rest);
    }
    // 本地路径：单独的 runtime，管理命令是短任务，直接跑完退出
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async move {
        let (config, _) = match config::read_config(config_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error: {e}");
                return 2;
            }
        };
        let db: Arc<dyn Store> = match make_store(&config).await {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error: {e}");
                return 2;
            }
        };
        match (group, sub) {
            ("accounts", "list") => admin_accounts_list(&config, db.as_ref()).await,
            ("accounts", "show") => match rest.first() {
                Some(subdomain) => admin_accounts_show(&config, db.as_ref(), subdomain).await,
                None => missing_arg("accounts show <subdomain>"),
            },
            ("accounts", "delete") => match rest.first() {
                Some(username) => admin_accounts_delete(db.as_ref(), username).await,
                None => missing_arg("accounts delete <username>"),
            },
            ("accounts", "password") => match rest.first() {
                Some(username) => admin_accounts_password(db.as_ref(), username).await,
                None => missing_arg("accounts password <username>"),
            },
            ("txt", "get") => match rest.first() {
                Some(subdomain) => admin_txt_get(db.as_ref(), subdomain).await,
                None => missing_arg("txt get <subdomain>"),
            },
            ("txt", "set") => match (rest.first(), rest.get(1)) {
                (Some(subdomain), Some(txt)) => {
                    admin_txt_set(db.as_ref(), subdomain, txt, rest.get(2).map(String::as_str))
                        .await
                }
                _ => missing_arg("txt set <subdomain> <txt> [txt2]"),
            },
            ("txt", "clear") => match rest.first() {
                Some(subdomain) => admin_txt_clear(db.as_ref(), subdomain).await,
                None => missing_arg("txt clear <subdomain>"),
            },
            _ => {
                eprintln!("Error: unknown {group} subcommand: {sub}");
                print_help(true);
                1
            }
        }
    })
}

/// 远端目标执行：base/token 已解析完成，直接驱动 remote_exec。
fn run_remote_target(base: &str, token: &str, group: &str, sub: &str, rest: &[String]) -> i32 {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(remote_exec(base, token, group, sub, rest))
}

/// 去掉 base URL 尾部斜杠，并拼出 /admin 前缀。
fn admin_base(base: &str) -> String {
    format!("{}/admin", base.trim_end_matches('/'))
}

/// 远程执行具体管理操作（HTTP + JSON）。
async fn remote_exec(base: &str, token: &str, group: &str, sub: &str, pos: &[String]) -> i32 {
    use acme_dns::models::{AdminAccountResponse, AdminPasswordResponse, AdminTxtResponse};
    let client = match reqwest::Client::builder().build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: http client: {e}");
            return 2;
        }
    };
    let admin = admin_base(base);

    // 便捷请求封装：附加鉴权头，非 2xx 时提取错误信息并返回码
    async fn send(
        client: &reqwest::Client,
        method: reqwest::Method,
        url: &str,
        token: &str,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, i32> {
        let mut req = client
            .request(method, url)
            .header("Authorization", format!("Bearer {token}"));
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.map_err(|e| {
            eprintln!("Error: request failed: {e}");
            2
        })?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            // 尽量透出服务端 json_error 的 message 字段
            let msg = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.get("error").and_then(|e| e.as_str().map(String::from)))
                .unwrap_or_else(|| format!("HTTP {status}"));
            eprintln!("Error: {msg}");
            return Err(if status.as_u16() == 404 { 2 } else { 1 });
        }
        if text.is_empty() {
            Ok(serde_json::Value::Null)
        } else {
            serde_json::from_str(&text).map_err(|e| {
                eprintln!("Error: decode response: {e}");
                2
            })
        }
    }

    // txt 子命令需先按子域找到 username（API 以 UUID 为路径参数）
    async fn username_of(
        client: &reqwest::Client,
        admin: &str,
        token: &str,
        subdomain: &str,
    ) -> Result<String, i32> {
        let resp = match send(
            client,
            reqwest::Method::GET,
            &format!("{admin}/accounts"),
            token,
            None,
        )
        .await
        {
            Ok(v) => v,
            Err(code) => return Err(code),
        };
        let accounts: Vec<AdminAccountResponse> = match serde_json::from_value(resp) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Error: decode accounts: {e}");
                return Err(2);
            }
        };
        accounts
            .into_iter()
            .find(|a| a.subdomain == subdomain)
            .map(|a| a.username)
            .ok_or_else(|| {
                eprintln!("Error: subdomain not found: {subdomain}");
                2
            })
    }

    #[allow(clippy::useless_asref)] // 本工具链 str::as_str 尚未稳定，借 as_ref 取 &str
    let (group_s, sub_s) = (group.as_ref(), sub.as_ref());
    match (group_s, sub_s) {
        ("accounts", "list") => {
            let v = match send(
                &client,
                reqwest::Method::GET,
                &format!("{admin}/accounts"),
                token,
                None,
            )
            .await
            {
                Ok(v) => v,
                Err(code) => return code,
            };
            let accounts = match serde_json::from_value::<Vec<AdminAccountResponse>>(v) {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("Error: decode accounts: {e}");
                    return 2;
                }
            };
            if accounts.is_empty() {
                println!("(no accounts)");
                return 0;
            }
            for a in &accounts {
                print_remote_account(a);
                println!("---");
            }
            0
        }
        ("accounts", "show") => match pos.first() {
            Some(subdomain) => {
                let username = match username_of(&client, &admin, token, subdomain).await {
                    Ok(u) => u,
                    Err(code) => return code,
                };
                let v = match send(
                    &client,
                    reqwest::Method::GET,
                    &format!("{admin}/accounts/{username}"),
                    token,
                    None,
                )
                .await
                {
                    Ok(v) => v,
                    Err(code) => return code,
                };
                let a = match serde_json::from_value::<AdminAccountResponse>(v) {
                    Ok(x) => x,
                    Err(e) => {
                        eprintln!("Error: decode account: {e}");
                        return 2;
                    }
                };
                print_remote_account(&a);
                0
            }
            None => missing_arg("remote ... accounts show <subdomain>"),
        },
        ("accounts", "delete") => match pos.first() {
            Some(username) => {
                let v = match send(
                    &client,
                    reqwest::Method::DELETE,
                    &format!("{admin}/accounts/{username}"),
                    token,
                    None,
                )
                .await
                {
                    Ok(v) => v,
                    Err(code) => return code,
                };
                println!(
                    "{}",
                    v.get("deleted")
                        .and_then(|d| d.as_str())
                        .unwrap_or(username)
                );
                0
            }
            None => missing_arg("remote ... accounts delete <username>"),
        },
        ("accounts", "password") => match pos.first() {
            Some(username) => {
                let v = match send(
                    &client,
                    reqwest::Method::POST,
                    &format!("{admin}/accounts/{username}/password"),
                    token,
                    None,
                )
                .await
                {
                    Ok(v) => v,
                    Err(code) => return code,
                };
                let pw = match serde_json::from_value::<AdminPasswordResponse>(v) {
                    Ok(x) => x,
                    Err(e) => {
                        eprintln!("Error: decode password: {e}");
                        return 2;
                    }
                };
                println!("username: {}", pw.username);
                println!("password: {}", pw.password);
                0
            }
            None => missing_arg("remote ... accounts password <username>"),
        },
        ("txt", "get") => match pos.first() {
            Some(subdomain) => {
                let username = match username_of(&client, &admin, token, subdomain).await {
                    Ok(u) => u,
                    Err(code) => return code,
                };
                let v = match send(
                    &client,
                    reqwest::Method::GET,
                    &format!("{admin}/accounts/{username}"),
                    token,
                    None,
                )
                .await
                {
                    Ok(v) => v,
                    Err(code) => return code,
                };
                let a = match serde_json::from_value::<AdminAccountResponse>(v) {
                    Ok(x) => x,
                    Err(e) => {
                        eprintln!("Error: decode account: {e}");
                        return 2;
                    }
                };
                println!("{subdomain}: {:?}", a.txt);
                0
            }
            None => missing_arg("remote ... txt get <subdomain>"),
        },
        ("txt", "set") => match (pos.first(), pos.get(1)) {
            (Some(subdomain), Some(txt)) => {
                let username = match username_of(&client, &admin, token, subdomain).await {
                    Ok(u) => u,
                    Err(code) => return code,
                };
                let body = serde_json::json!({"txt": txt, "txt2": pos.get(2)});
                let v = match send(
                    &client,
                    reqwest::Method::PUT,
                    &format!("{admin}/accounts/{username}/txt"),
                    token,
                    Some(body),
                )
                .await
                {
                    Ok(v) => v,
                    Err(code) => return code,
                };
                let r = match serde_json::from_value::<AdminTxtResponse>(v) {
                    Ok(x) => x,
                    Err(e) => {
                        eprintln!("Error: decode txt: {e}");
                        return 2;
                    }
                };
                println!("set {} -> {:?}", r.subdomain, r.txt);
                0
            }
            _ => missing_arg("remote ... txt set <subdomain> <txt> [txt2]"),
        },
        ("txt", "clear") => match pos.first() {
            Some(subdomain) => {
                let username = match username_of(&client, &admin, token, subdomain).await {
                    Ok(u) => u,
                    Err(code) => return code,
                };
                let v = match send(
                    &client,
                    reqwest::Method::DELETE,
                    &format!("{admin}/accounts/{username}/txt"),
                    token,
                    None,
                )
                .await
                {
                    Ok(v) => v,
                    Err(code) => return code,
                };
                let r = match serde_json::from_value::<AdminTxtResponse>(v) {
                    Ok(x) => x,
                    Err(e) => {
                        eprintln!("Error: decode txt: {e}");
                        return 2;
                    }
                };
                println!("cleared {}", r.subdomain);
                0
            }
            None => missing_arg("remote ... txt clear <subdomain>"),
        },
        _ => {
            eprintln!("Error: unknown remote subcommand: {group} {sub}");
            print_help(true);
            1
        }
    }
}

/// 远程账户行输出（与本地 print_account_row 字段对齐）。
fn print_remote_account(a: &acme_dns::models::AdminAccountResponse) {
    println!("username:     {}", a.username);
    println!("fulldomain:   {}", a.fulldomain);
    println!("subdomain:    {}", a.subdomain);
    println!("allowfrom:    {:?}", a.allowfrom);
    println!("txt:          {:?}", a.txt);
    if let Some(ts) = a.last_update {
        println!("last_update:  {ts}");
    }
    if let Some(ts) = a.created_at {
        println!("created_at:   {ts}");
    }
}

fn missing_arg(usage: &str) -> i32 {
    eprintln!("Error: missing argument; usage: {usage}");
    2
}

fn print_account_row(domain: &str, row: &store::AccountRow) {
    println!("username:     {}", row.username);
    println!("fulldomain:   {}", row.fulldomain(domain));
    println!("subdomain:    {}", row.subdomain);
    println!("allowfrom:    {}", row.allow_from.to_json());
    println!("txt:          {:?}", row.txt);
    if let Some(ts) = row.last_update {
        println!("last_update:  {ts}");
    }
    if let Some(ts) = row.created_at {
        println!("created_at:   {ts}");
    }
}

async fn admin_accounts_list(config: &AppConfig, db: &dyn Store) -> i32 {
    match db.list_accounts().await {
        Ok(rows) => {
            if rows.is_empty() {
                println!("(no accounts)");
                return 0;
            }
            for row in &rows {
                print_account_row(&config.general.domain, row);
                println!("---");
            }
            0
        }
        Err(e) => {
            eprintln!("Error: {e}");
            2
        }
    }
}

async fn admin_accounts_show(config: &AppConfig, db: &dyn Store, subdomain: &str) -> i32 {
    match db.get_by_subdomain(subdomain).await {
        Ok(row) => {
            print_account_row(&config.general.domain, &row);
            0
        }
        Err(e) => {
            eprintln!("Error: {e}");
            2
        }
    }
}

async fn admin_accounts_delete(db: &dyn Store, username: &str) -> i32 {
    let uuid = match uuid::Uuid::parse_str(username) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("Error: invalid username (UUID): {e}");
            return 2;
        }
    };
    match db.delete_account(uuid).await {
        Ok(()) => {
            println!("deleted {username}");
            0
        }
        Err(e) => {
            eprintln!("Error: {e}");
            2
        }
    }
}

async fn admin_accounts_password(db: &dyn Store, username: &str) -> i32 {
    let uuid = match uuid::Uuid::parse_str(username) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("Error: invalid username (UUID): {e}");
            return 2;
        }
    };
    match db.reset_password(uuid).await {
        Ok(password) => {
            println!("username: {username}");
            println!("password: {password}");
            0
        }
        Err(e) => {
            eprintln!("Error: {e}");
            2
        }
    }
}

async fn admin_txt_get(db: &dyn Store, subdomain: &str) -> i32 {
    match db.get_txt_for_domain(subdomain).await {
        Ok(txt) => {
            println!("{subdomain}: {txt:?}");
            0
        }
        Err(e) => {
            eprintln!("Error: {e}");
            2
        }
    }
}

async fn admin_txt_set(db: &dyn Store, subdomain: &str, txt: &str, txt2: Option<&str>) -> i32 {
    let txt2 = txt2.unwrap_or("");
    for v in [txt, txt2] {
        if !v.is_empty() && !models::valid_txt(v) {
            eprintln!("Error: invalid txt value (must be 43 url-safe chars): {v}");
            return 2;
        }
    }
    match db.set_txt(subdomain, txt, txt2).await {
        Ok(()) => {
            println!("set {subdomain}");
            0
        }
        Err(e) => {
            eprintln!("Error: {e}");
            2
        }
    }
}

async fn admin_txt_clear(db: &dyn Store, subdomain: &str) -> i32 {
    match db.set_txt(subdomain, "", "").await {
        Ok(()) => {
            println!("cleared {subdomain}");
            0
        }
        Err(e) => {
            eprintln!("Error: {e}");
            2
        }
    }
}

/// 管理命令目标：本地库或远端实例。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    /// 未显式指定：有 --url/--token/env 时走 remote，否则本地。
    Auto,
    /// 强制本地数据库。
    Local,
    /// 强制远端 /admin API。
    Remote,
}

/// remote 目标的连接参数（--url/--token 或环境变量兜底）。
#[derive(Debug, Default, Clone)]
struct RemoteOpts {
    url: Option<String>,
    token: Option<String>,
}

impl RemoteOpts {
    /// 组装出可用的 (base, token)；缺任一则返回 None。
    fn resolve(self) -> Option<(String, String)> {
        let url = self
            .url
            .or_else(|| std::env::var("ACME_DNS_URL").ok())
            .map(|u| u.trim_end_matches('/').to_string());
        let token = self.token.or_else(|| std::env::var("ACME_DNS_TOKEN").ok());
        Some((url?, token?))
    }
}

/// 解析 CLI：返回 (config_path, 是否执行完子命令后直接退出)。
fn parse_cli() -> (Option<String>, Option<i32>) {
    let mut config_path: Option<String> = None;
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // 提取目标选择与 remote 参数（不限位置，--local/--remote/--url/--token 可出现在任意位置）
    let mut target = Target::Auto;
    let mut remote_opts = RemoteOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--local" => {
                target = Target::Local;
                args.remove(i);
            }
            "--remote" => {
                target = Target::Remote;
                args.remove(i);
            }
            "--url" => match args.get(i + 1) {
                Some(v) => {
                    remote_opts.url = Some(v.clone());
                    args.drain(i..=i + 1);
                }
                None => {
                    eprintln!("Error: --url 需要一个值");
                    return (config_path, Some(2));
                }
            },
            "--token" => match args.get(i + 1) {
                Some(v) => {
                    remote_opts.token = Some(v.clone());
                    args.drain(i..=i + 1);
                }
                None => {
                    eprintln!("Error: --token 需要一个值");
                    return (config_path, Some(2));
                }
            },
            _ => i += 1,
        }
    }
    let mut args = args.into_iter();
    let mut exit: Option<i32> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => config_path = args.next(),
            "--help" | "-h" | "help" => {
                print_help(false);
                exit = Some(0);
            }
            "version" | "--version" | "-V" | "-v" => {
                exit = Some(run_version());
            }
            "init" => {
                exit = Some(run_init(config_path.as_deref()));
            }
            "keygen" => {
                let rest: Vec<String> = args.by_ref().collect();
                exit = Some(run_keygen(&rest));
            }
            "accounts" | "txt" => {
                let group = arg.clone();
                let sub = args.next();
                let mut rest: Vec<String> = args.by_ref().collect();
                // 管理子命令支持 -c/--config 前置或后置；后置覆盖前置
                let mut admin_config = config_path.clone();
                let mut i = 0;
                while i < rest.len() {
                    if (rest[i] == "-c" || rest[i] == "--config")
                        && let Some(v) = rest.get(i + 1)
                    {
                        admin_config = Some(v.clone());
                        rest.remove(i);
                        rest.remove(i);
                        continue;
                    }
                    i += 1;
                }
                exit = Some(run_admin_command(
                    &group,
                    sub.as_deref(),
                    &rest,
                    admin_config.as_deref(),
                    target,
                    &remote_opts,
                ));
            }
            other => {
                eprintln!("Error: unknown argument: {other}");
                print_help(true);
                exit = Some(1);
            }
        }
        if exit.is_some() {
            break;
        }
    }
    (config_path, exit)
}

/// 启动编排：配置→日志→存储→DNS→API，返回错误汇聚通道的接收端。
async fn run() -> Result<tokio::sync::mpsc::Receiver<String>, String> {
    // CLI 已在 main 中解析；这里仅取配置路径（管理子命令不会走到这）
    let (config_path, cli_exit) = parse_cli();
    if let Some(code) = cli_exit {
        std::process::exit(code);
    }

    let (config, used_config_file) =
        config::read_config(config_path.as_deref()).map_err(|e| format!("Error: {e}"))?;
    let config = Arc::new(config);

    let _log_guard = logger::init(
        &config.log.level,
        &config.log.logtype,
        &config.log.logfile,
        &config.log.format,
    )
    .map_err(|e| format!("Could not set up logging: {e}"))?;

    tracing::info!(file = %used_config_file.display(), "Using config file");
    tracing::info!("Starting up");

    let db: Arc<dyn Store> = make_store(&config).await?;
    let own_auth_key = Arc::new(OwnAuthKey::new());

    // DNS 服务器（both 展开为 UDP+TCP 两个）；端口被占等错误 → 进程退出
    let (err_tx, err_rx) = tokio::sync::mpsc::channel::<String>(16);
    for proto in dnsserver::protocols_for(&config.general.protocol) {
        let server = Arc::new(DnsServer::new(
            &config.general.listen,
            &proto,
            &config.general.domain,
            &config.general.nsname,
            &config.general.nsadmin,
            &config.general.records,
            db.clone(),
            own_auth_key.clone(),
        ));
        tracing::info!(proto = %proto, listen = %config.general.listen, "DNS listener starting");
        let err_tx_dns = err_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = server.start().await {
                let _ = err_tx_dns.send(e).await;
            }
        });
    }

    // API 服务器
    let router = api::router::build_router(config.clone(), db.clone(), own_auth_key.clone());

    let api_addr = format!("{}:{}", config.api.ip, config.api.port);
    let tls_provider = api::tls::TlsProvider::parse(&config.api.tls);
    tokio::spawn(async move {
        let result = match tls_provider {
            api::tls::TlsProvider::None => serve_http(api_addr, router).await,
            api::tls::TlsProvider::Cert => {
                serve_tls(
                    api_addr,
                    router,
                    &config.api.tls_cert_fullchain,
                    &config.api.tls_cert_privkey,
                )
                .await
            }
            api::tls::TlsProvider::LetsEncrypt | api::tls::TlsProvider::LetsEncryptStaging => {
                // ACME 自动签发暂未内置；按 Go 版流程需要 certmagic/rustls-acme。
                // 这里退化为 HTTPS+静态证书路径，缺失时报告错误退出。
                serve_tls(
                    api_addr,
                    router,
                    &config.api.tls_cert_fullchain,
                    &config.api.tls_cert_privkey,
                )
                .await
            }
        };
        if let Err(e) = result {
            let _ = err_tx.send(e).await;
        }
    });

    Ok(err_rx)
}

/// 打开数据库存储（engine 归一：sqlite3→sqlite）。
async fn make_store(config: &AppConfig) -> Result<Arc<dyn Store>, String> {
    let engine = config.database.engine.to_lowercase();
    let connection = config.database.connection.clone();
    match engine.as_str() {
        "sqlite" | "sqlite3" => {
            let s = store::sqlite::SqliteStore::new(&connection)
                .await
                .map_err(|e| e.to_string())?;
            Ok(Arc::new(s))
        }
        #[cfg(feature = "postgres")]
        "postgres" | "postgresql" => {
            let s = store::postgres::PostgresStore::new(&connection)
                .await
                .map_err(|e| e.to_string())?;
            Ok(Arc::new(s))
        }
        other => Err(format!("Error: unsupported database engine: {other}")),
    }
}

async fn serve_http(addr: String, router: axum::Router) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("API server failed to bind {addr}: {e}"))?;
    tracing::info!(host = %addr, "Listening HTTP");
    axum::serve(listener, router)
        .await
        .map_err(|e| format!("API server error: {e}"))
}

async fn serve_tls(
    addr: String,
    router: axum::Router,
    cert: &str,
    key: &str,
) -> Result<(), String> {
    let tls_cfg = api::tls::build_server_config(&api::tls::TlsProvider::Cert, cert, key)?;
    let tls_cfg = tls_cfg.ok_or_else(|| "TLS enabled but no certificate configured".to_string())?;
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("API server failed to bind {addr}: {e}"))?;
    tracing::info!(host = %addr, "Listening HTTPS");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_cfg));
    loop {
        let (stream, _remote) = listener
            .accept()
            .await
            .map_err(|e| format!("API accept error: {e}"))?;
        let acceptor = acceptor.clone();
        let app = router.clone();
        tokio::spawn(async move {
            if let Ok(tls_stream) = acceptor.accept(stream).await {
                let io = hyper_util::rt::TokioIo::new(tls_stream);
                let svc = hyper_util::service::TowerToHyperService::new(app);
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection_with_upgrades(io, svc)
                .await;
            }
        });
    }
}

fn main() {
    // 先同步解析 CLI：管理子命令在无 runtime 环境直接执行并退出
    if let Some(code) = parse_cli().1 {
        std::process::exit(code);
    }

    // 服务路径：新建 runtime 驱动
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let mut err_rx = match runtime.block_on(run()) {
        Ok(rx) => rx,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    // 错误汇聚 + 信号优雅退出
    runtime.block_on(async move {
        let sig = tokio::signal::ctrl_c();
        tokio::select! {
            Some(err) = err_rx.recv() => {
                tracing::error!(error = %err, "fatal");
                eprintln!("{err}");
                std::process::exit(1);
            }
            _ = sig => {
                tracing::info!("shutting down");
            }
        }
    });
}
