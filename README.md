# acme-dns

一个只服务 ACME DNS 质询（TXT 记录）的简化 DNS 服务器，附带 RESTful HTTP API，以 Rust 实现。

> [!TIP]
> 本项目最初基于 [acme-dns](https://github.com/joohoi/acme-dns)（Go）的对外契约重写，兼容性说明见 [与 Go 版的差异](#与-go-版的差异)。后续将按本项目路线演进，与上游版本的差异可能逐步扩大。

## Why?

多数 DNS 服务器不为 ACME DNS 质询提供自动化 API；提供的又往往权限过大。acme-dns 提供仅限 TXT 记录更新的简单 API，配合 `_acme-challenge` 子域 CNAME 使用——即使 API key 泄露，影响也被限制在单个子域的 TXT 记录上。

核心是**可用性**与**安全性**。更多背景见 EFF 的博客：https://www.eff.org/deeplinks/2018/02/technical-deep-dive-securing-automation-acme-dns-challenge-validation

## Features

- 简化 DNS 服务器，服务 ACME 质询 TXT 记录
- 支持自定义记录（A、AAAA、NS 等静态记录）
- `/update` 端点可按 CIDR 限制来源（注册时声明，或经 `X-Forwarded-For` 等头解析）
- SQLite（默认，兼容 `sqlite3` 别名）与 PostgreSQL 双后端
- 双 TXT 滚动更新：同时应答 `yourdomain.tld` 与 `*.yourdomain.tld` 两条质询
- HSTS 支持、CORS 可配置
- REST API 与 DNS 应答语义和 Go 版逐项对齐（TTL、SOA serial、NXDOMAIN + SOA authority、EDNS BADVERS 等）

## Usage

使用 acme-dns 的前提是：**acme-dns 服务已部署，且主域名侧已把质询子域授权给它**。
假设 acme-dns 服务域名为 `auth.example.org`（对应配置 `[general] domain`），
主机公网 IP 为 `198.51.100.1`，则需先在主域名的 DNS 服务器添加：

```text
auth.example.org.  NS   auth.example.org.        ; 授权该子域
auth.example.org.  A    198.51.100.1             ; IPv6 加 AAAA
```

之后，对每个要签证书的域名执行三步：

1. `POST /register` 获取凭据与唯一子域；
2. 在主域名区域为该域名添加 CNAME：
   `_acme-challenge.domainiwantcertfor.tld. CNAME <subdomain>.auth.example.org`；
3. 用凭据 `POST /update` 写入 CA 下发的质询 token，等 CA 验证即可。

更多细节见 [DNS Records](#dns-records)。

## API

### POST /register

返回新子域与更新凭据。可选 POST JSON 限制 `/update` 来源 CIDR：

```json
{
    "allowfrom": [
        "192.168.100.1/24",
        "1.2.3.4/32",
        "2002:c0a8:2a00::0/40"
    ]
}
```

`Status: 201 Created`：

```json
{
    "allowfrom": [],
    "fulldomain": "8e5700ea-a4bf-41c7-8a77-e990661dcc6a.auth.example.org",
    "password": "htB9mR9DYgcu9bX_afHF62erXaH2TS7bg9KW3F7Z",
    "subdomain": "8e5700ea-a4bf-41c7-8a77-e990661dcc6a",
    "username": "c36f50e8-4632-44f0-83fe-e070fef28a10"
}
```

### POST /update

更新子域 TXT 应答。必需请求头：

| Header name | Description                                | Example                                            |
| ----------- | ------------------------------------------ | -------------------------------------------------- |
| X-Api-User  | UUIDv4 username received from registration | `X-Api-User: c36f50e8-4632-44f0-83fe-e070fef28a10` |
| X-Api-Key   | Password received from registration        | `X-Api-Key: htB9mR9DYgcu9bX_afHF62erXaH2TS7bg9KW3F7Z` |

请求体：

```json
{
    "subdomain": "8e5700ea-a4bf-41c7-8a77-e990661dcc6a",
    "txt": "___validation_token_received_from_the_ca___"
}
```

`Status: 200 OK`：

```json
{
    "txt": "___validation_token_received_from_the_ca___"
}
```

`txt` 必须恰好 43 个字符，否则返回 400。

### GET /health

就绪/存活探测，成功返回 200。

## 账户管理（Rust 版扩展）

配置 `[api] admin_token` 后自动挂载 `/admin/*` REST API（Bearer token 鉴权），
支持列出 / 注册 / 删除账户、更新 allowfrom、重置密码、管理式设置 TXT。
token 用 `acme-dns keygen` 生成（默认 48 字符，可选长度 8-256）。
同时提供本地 CLI 子命令（直连数据库）：

```bash
acme-dns -c config.toml accounts list
acme-dns -c config.toml accounts show my-sub
acme-dns -c config.toml accounts delete <username>
acme-dns -c config.toml accounts password <username>
acme-dns -c config.toml txt set my-sub <txt> [txt2]
acme-dns -c config.toml txt get my-sub
acme-dns -c config.toml txt clear my-sub
```

远程管理（`--remote`/`--url`/`--token` 为全局参数，位置不限；经 /admin
HTTP API 操作远端实例，不读 -c）：

```bash
acme-dns --remote --url http://cloud-host --token <admin_token> accounts list
acme-dns --remote --url http://cloud-host --token <admin_token> txt set my-sub <txt>

# 也可用环境变量省略 --url/--token（命令行参数优先）
export ACME_DNS_URL=http://cloud-host
export ACME_DNS_TOKEN=<admin_token>
acme-dns --remote accounts list
```

接口明细见 [docs/05-api.md](docs/05-api.md)。

## Installation

### 从源码构建

```bash
git clone <this-repo>
cd acme-dns
cargo build --release
# 产物：target/release/acme-dns
```

使用本机 Rust stable 工具链（rustc ≥ 1.85）。PostgreSQL 后端需加特性：`cargo build --release --features postgres`。

1. 把二进制移入 `$PATH`，例如 `sudo cp target/release/acme-dns /usr/local/bin/`。
2. 编辑 `config.toml`（见[配置](#configuration)）。acme-dns 依次读取 `-c` 指定路径、`/etc/acme-dns/config.toml`、`./config.toml`。
3. 可选 systemd 部署：
   1. 配置文件放到 `/etc/acme-dns/config.toml`；
   2. 二进制放到 `/usr/local/bin/acme-dns`；
   3. 创建系统用户：`sudo adduser --system --gecos "acme-dns Service" --disabled-password --group --home /var/lib/acme-dns acme-dns`；
   4. 安装服务单元：`sudo cp acme-dns.service /etc/systemd/system/ && sudo systemctl daemon-reload`；
   5. `sudo systemctl enable --now acme-dns.service`。
4. 不用 systemd 时直接运行 `acme-dns`。注意 53 端口是特权端口，需要相应权限（systemd 单元已带 `CAP_NET_BIND_SERVICE`）。

### Using Docker

```bash
docker build -f docker/Dockerfile -t acme-dns .              # 国际网络环境
docker build -f docker/CN.Dockerfile -t acme-dns .   # 中国网络环境（国内镜像源）
mkdir -p config data
cp config.toml config/config.toml   # 按需修改
docker run --rm --name acmedns    \
  -p 53:53                        \
  -p 53:53/udp                    \
  -p 80:80                        \
  -v $(pwd)/config:/etc/acme-dns:ro \
  -v $(pwd)/data:/var/lib/acme-dns  \
  -d acme-dns
```

镜像运行阶段基于 distroless static（musl 静态链接，非 root），仅含二进制与 CA 根证书。

### Docker Compose

```bash
cd docker
docker compose up -d
```

compose 使用 `docker/config.toml` 作为容器配置（0.0.0.0 监听、SQLite 落盘到挂载卷）。

## DNS Records

文档约定：

- `auth.example.org` 是 acme-dns 服务器主机名，服务 `*.auth.example.org`；
- `198.51.100.1` 是运行 acme-dns 主机的**公网** IP。请按实际环境替换。

需要在主域名 DNS 服务器添加：

- `auth.example.org. NS auth.example.org.`（授权该子域）
- `auth.example.org. A 198.51.100.1`（IPv6 则加 AAAA）
- 每个要签证书的域名加 `_acme-challenge` CNAME 指向注册得到的 fulldomain。

## Testing It Out

```bash
# 1. 确认 DNS 解析
dig auth.example.org

# 2. 注册测试子域
curl -X POST https://auth.example.org/register
# {"username":"eabcdb41-...","password":"pbAXVjlI...","fulldomain":"d420c923-....auth.example.org","subdomain":"d420c923-...","allowfrom":[]}

# 3. 更新 TXT
curl -X POST \
  -H "X-Api-User: eabcdb41-d89f-4580-826f-3e62e9755ef2" \
  -H "X-Api-Key: pbAXVjlIOE01xbut7YnAbkhMQIkcwoHO0ek2j4Q0" \
  -d '{"subdomain": "d420c923-bbd7-4056-ab64-c3ca54c9b3cf", "txt": "___validation_token_received_from_the_ca___"}' \
  https://auth.example.org/update

# 4. 验证 TXT 已生效
dig -t txt @auth.example.org d420c923-bbd7-4056-ab64-c3ca54c9b3cf.auth.example.org
```

## Configuration

```bash
[general]
# DNS 监听地址。注意 systemd-resolved 可能占用 127.0.0.53:53
listen = "0.0.0.0:53"
# protocol, "both", "both4", "both6", "udp", "udp4", "udp6" or "tcp", "tcp4", "tcp6"
protocol = "both"
# 服务的域名
domain = "auth.example.org"
# zone name server
nsname = "auth.example.org"
# admin email address, where @ is substituted with .
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
# 环境变量 ACME_DNS_DATABASE_URL / DATABASE_URL 优先级更高。
url = "sqlite:///var/lib/acme-dns/acme-dns.db"
# postgres 示例：url = "postgres://user:password@localhost/acmedns_db"

[api]
# API 监听地址 host:port（env ACME_DNS_API_HOST 优先级最高）
host = "0.0.0.0:443"
# 关闭 /register 端点
disable_registration = false
# 可选值："cert", "none"
tls = "none"
# tls = "cert" 时使用
tls_cert_privkey = "/etc/tls/example.org/privkey.pem"
tls_cert_fullchain = "/etc/tls/example.org/fullchain.pem"
# letsencrypt 模式的缓存目录（当前 Rust 版未内置 ACME 客户端，见下文差异说明）
acme_cache_dir = "api-certs"
# Let's Encrypt 到期通知邮箱
notification_email = ""
# CORS AllowOrigins，可用通配符
corsorigins = [
    "*"
]
# 用 HTTP 头解析客户端 IP（反代场景）
use_header = false
# 从哪个头取 IP 列表
header_name = "X-Forwarded-For"
# 是否发送 HSTS 头
hsts_enabled = false
hsts_max_age = 31536000
hsts_include_subdomains = false
hsts_preload = false

[log]
# "error", "warning", "info" or "debug"
level = "debug"
# stdout（文件输出规划中）
type = "stdout"
# "json" or "text"
format = "text"
```

> 数据库连接用 `[database]` 段的 `url`（或 env `ACME_DNS_DATABASE_URL` /
> `DATABASE_URL`），scheme 决定 engine。

### 环境变量

所有配置项均可用环境变量覆盖：`ACME_DNS_<段>_<字段>`（全大写），优先级
**环境变量 > 配置文件 > 默认值**。布尔取 `1/true/yes/on`、`0/false/no/off`；
整数按 `i64`；数组用英文逗号分隔；非法值启动即报错。无配置文件时，只需
数据库连接串（`ACME_DNS_DATABASE_URL` 或 `DATABASE_URL`）即可运行：

```bash
ACME_DNS_DATABASE_URL=sqlite:///var/lib/acme-dns/acme-dns.db \
ACME_DNS_API_HOST=0.0.0.0:8080 \
acme-dns
```

日志级别等也可用 env：`ACME_DNS_LOG_LEVEL` / `ACME_DNS_LOG_TYPE` /
`ACME_DNS_LOG_FILE` / `ACME_DNS_LOG_FORMAT`。

完整说明见[配置参考](docs/03-configuration.md#环境变量)。

## 与 Go 版的差异

- API 路径、请求/响应 JSON、鉴权头、DNS 应答语义、配置文件字段均与 Go 版保持一致；数据库 schema 兼容（可直接复用现有 `acme-dns.db`）。
- `tls = "letsencrypt"` / `"letsencryptstaging"` 模式**暂未内置 ACME 客户端**：Rust 版当前支持 `tls = "cert"`（静态证书）与 `tls = "none"`。需要自动签发 API 证书时，可先用外部工具（如 acme.sh / certbot）签发后走 `tls = "cert"`。
- 其余行为（连接池、超时、恒定时间口令校验、双 TXT 滚动等）与 Go 版对齐。

## HTTPS API

两种方式暴露 HTTPS：

1. `tls = "cert"`：提供自己的证书链与私钥（`tls_cert_fullchain` / `tls_cert_privkey`）。
2. `tls = "letsencrypt"`：Go 版可自动签发；Rust 版暂未内置，见上文差异说明。

**Warning**：使用 `tls = "cert"` 时务必保证证书不过期，否则 ACME 客户端可能因无法连上 API 而陷入无法续期的死锁。

## Development

```bash
cargo test            # 单元 + e2e 测试
cargo clippy --all-targets -- -D warnings
cargo build --release
```

本项目以 Rust 实现，单 crate 结构；架构与模块说明见 [docs/](docs/index.md)，
完整文档含[快速开始](docs/02-getting-started.md)、[配置参考](docs/03-configuration.md)、
[REST API](docs/05-api.md) 等。

## License

本项目及其衍生工作按 [Apache License 2.0](LICENSE) 发布；上游
[acme-dns](https://github.com/joohoi/acme-dns)（Go）采用 MIT 许可证，
其版权与许可声明归原项目所有。
