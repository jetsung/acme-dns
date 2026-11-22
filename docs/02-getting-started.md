# 快速开始

acme-dns 是单二进制 Rust 应用，运行只依赖可执行文件与 SQLite 数据文件
（或 PostgreSQL 连接）。以下按「编译 → 启动 → 验证」三步走通。

## 前置要求

- Rust stable（rustc ≥ 1.85，edition 2024）
- 无外部系统依赖：SQLite 内置于二进制（sqlx），PostgreSQL 后端需另有 PG 实例

## 编译与启动

=== "从源码编译"

    ```bash
    git clone <this-repo>
    cd acme-dns
    cargo build --release
    # 产物：target/release/acme-dns
    ```

    PostgreSQL 后端需加特性：`cargo build --release --features postgres`。

=== "Docker（推荐）"

    ```bash
    docker build -f docker/Dockerfile -t acme-dns .            # 国际网络环境
    docker build -f docker/CN.Dockerfile -t acme-dns . # 中国网络环境（国内镜像源）
    ```

    镜像运行阶段基于 distroless static（musl 静态链接，非 root），
    仅含二进制与 CA 根证书。

=== "官方镜像"

    CI 打 tag 后发布多架构镜像（amd64/arm64）：

    ```bash
    docker pull ghcr.io/jetsung/acme-dns:latest
    ```

## 生成配置并启动

```bash
# 生成示例配置 config.toml（已存在时不覆盖）
acme-dns init

# 按需修改后启动（默认依次尝试 -c 路径 → /etc/acme-dns/config.toml → ./config.toml）
acme-dns -c config.toml
```

最小可用配置（本机调试）：

```toml
[general]
listen = "0.0.0.0:53"
protocol = "both"
domain = "auth.example.org"
nsname = "auth.example.org"
nsadmin = "admin.example.org"
records = []
debug = false

[database]
url = "sqlite://./acme-dns.db"

[api]
host = "0.0.0.0:8080"
tls = "none"

[log]
level = "info"
type = "stdout"
format = "text"
```

> 环境变量 `ACME_DNS_DATABASE_URL` / `DATABASE_URL` 优先于文件中的任何写法。

完整字段见 [配置参考](03-configuration.md)。

## 账户管理

管理操作两条路径：`/admin/*` REST API（配置 `[api] admin_token` 后自动挂载）
与本地 CLI 子命令（直连数据库，无需 API）。token 用 `acme-dns keygen` 生成
（默认 48 字符，可选长度 8-256）。详见 [REST API](05-api.md)。

```bash
# CLI：列出 / 查看账户（-c 指定配置文件）
acme-dns -c config.toml accounts list
acme-dns -c config.toml accounts show my-sub

# 指定子域注册、更新来源白名单、重置密码
acme-dns -c config.toml accounts delete <username>
acme-dns -c config.toml accounts password <username>

# TXT 管理（直连库写入，服务进程共享同一 SQLite/PG 时立即生效）
acme-dns -c config.toml txt set my-sub ___validation_token_received_from_the_ca___
acme-dns -c config.toml txt get my-sub
acme-dns -c config.toml txt clear my-sub
```

!!! warning
    CLI 管理命令直接操作数据库；若服务端缓存了认证数据，密码重置/TXT 变更
    对 DNS 应答立即生效，但对 `/update` 鉴权的生效时机以后端实现为准。

## Docker Compose

```bash
cd docker
docker compose up -d
```

compose 使用 `docker/config.toml` 作为容器配置（0.0.0.0 监听、SQLite 落盘
到命名卷 `acme-dns-data`），映射 `53:53/tcp+udp` 与 `80:80`。宿主机 53/80
被占用时需先释放（如停用 systemd-resolved 的 DNSStubListener），不要改用
非标端口——权威 DNS 必须在 53 端口才能被公网解析到。

## systemd 部署

```bash
sudo cp target/release/acme-dns /usr/local/bin/
sudo mkdir -p /etc/acme-dns && sudo cp config.toml /etc/acme-dns/
sudo adduser --system --gecos "acme-dns Service" --disabled-password \
  --group --home /var/lib/acme-dns acme-dns
sudo cp acme-dns.service /etc/systemd/system/ && sudo systemctl daemon-reload
sudo systemctl enable --now acme-dns.service
```

服务单元已带 `CAP_NET_BIND_SERVICE`（53 特权端口）。不用 systemd 直接运行时
注意端口权限。

## 前置 DNS 授权与验证

服务启动只是第一步；要真正用于 ACME 签发，主域名侧必须先把质询子域授权给
acme-dns（NS/A 记录），再为每个待签域名加 `_acme-challenge` CNAME——见下文
[DNS 记录约定](#dns)。

本机验证：

```bash
# 1. 健康检查
curl http://127.0.0.1:80/health

# 2. 注册测试子域
curl -X POST http://127.0.0.1:80/register
# {"username":"eabcdb41-...","password":"pbAXVjlI...","fulldomain":"d420c923-...auth.example.org",...}

# 3. 更新 TXT
curl -X POST \
  -H "X-Api-User: <username>" -H "X-Api-Key: <password>" \
  -d '{"subdomain": "<subdomain>", "txt": "___validation_token_received_from_the_ca___"}' \
  http://127.0.0.1:80/update

# 4. 验证 TXT 已生效（标准 53 端口，无需 -p）
dig -t txt @127.0.0.1 <subdomain>.auth.example.org
```

## DNS 记录约定

文档约定：

- `auth.example.org` 是 acme-dns 服务器主机名，服务 `*.auth.example.org`；
- `198.51.100.1` 是运行 acme-dns 主机的**公网** IP。请按实际环境替换。

需要在主域名 DNS 服务器添加：

- `auth.example.org. NS auth.example.org.`（授权该子域）
- `auth.example.org. A 198.51.100.1`（IPv6 则加 AAAA）
- 每个要签证书的域名加 `_acme-challenge` CNAME 指向注册得到的 fulldomain
