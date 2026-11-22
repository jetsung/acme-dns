# 配置参考

配置文件为 TOML 格式，`acme-dns` 按以下顺序查找：

1. `-c/--config` 指定路径（优先）；
2. `/etc/acme-dns/config.toml`；
3. `./config.toml`。

`acme-dns init` 可生成带注释的示例配置到 `config.toml`（已存在时不覆盖，
`-c` 可指定目标路径）。数据库连接串优先用 `ACME_DNS_DATABASE_URL` /
`DATABASE_URL`，也可用 `[database]` 段的 `url`；日志段为 `[log]`
（字段无 `log` 前缀）。

## [general]

| 字段 | 默认值 | 环境变量 | 说明 |
|---|---|---|---|
| `listen` | `0.0.0.0:53` | `ACME_DNS_GENERAL_LISTEN` | DNS 监听地址；注意 systemd-resolved 可能占用 `127.0.0.53:53` |
| `protocol` | `both` | `ACME_DNS_GENERAL_PROTOCOL` | 监听协议：`both` / `both4` / `both6` / `udp` / `udp4` / `udp6` / `tcp` / `tcp4` / `tcp6` |
| `domain` | — | `ACME_DNS_GENERAL_DOMAIN` | 服务的域名（如 `auth.example.org`） |
| `nsname` | — | `ACME_DNS_GENERAL_NSNAME` | SOA 的 zone name server |
| `nsadmin` | — | `ACME_DNS_GENERAL_NSADMIN` | SOA 管理员邮箱，`@` 替换为 `.` |
| `records` | `[]` | `ACME_DNS_GENERAL_RECORDS` | 静态预置记录（除 TXT 外），写法见下；环境变量用英文逗号分隔 |
| `debug` | `false` | `ACME_DNS_GENERAL_DEBUG` | CORS 等调试日志 |

`records` 静态预置记录示例（每条格式 `<域名>. <类型> <值>`；TXT 由注册动态生成，不在此配置）：

```toml
[general]
records = [
  "auth.example.org. A 198.51.100.1",
  "auth.example.org. AAAA 2001:db8::1",
  "auth.example.org. NS auth.example.org.",
]
```

等价的环境变量写法（英文逗号分隔，逗号后空格可选，空项自动忽略）：

```bash
export ACME_DNS_GENERAL_RECORDS='auth.example.org. A 198.51.100.1, auth.example.org. AAAA 2001:db8::1, auth.example.org. NS auth.example.org.'
```

## [database]

| 字段 | 默认值 | 环境变量 | 说明 |
|---|---|---|---|
| `url` | — | `ACME_DNS_DATABASE_URL` > `DATABASE_URL` | 完整连接串；scheme 决定 engine（`sqlite://` 或 `postgres://`） |

数据库连接串优先级：`ACME_DNS_DATABASE_URL` > `DATABASE_URL` >
`[database]` 段的 `url`。
URL 示例：`sqlite:///var/lib/acme-dns/acme-dns.db`、
`postgres://user:password@host/acmedns`。

SQLite 单连接串行化（与 Go 版一致），文件不存在时自动创建；
schema 与 Go 版互通，可直接复用现有 `acme-dns.db`。

SQLite 内存模式：连接串为 `sqlite://:memory:`，
数据只存内存、进程退出即丢失、无文件残留。适合测试或临时验证，
生产环境请用文件或 PostgreSQL。

## [api]

| 字段 | 默认值 | 环境变量 | 说明 |
|---|---|---|---|
| `host` | `0.0.0.0:443` | `ACME_DNS_API_HOST` | API 监听地址 `host:port`（如 `0.0.0.0:80`、`[::]:443`） |
| `tls` | `none` | `ACME_DNS_API_TLS` | `cert` / `none`（`letsencrypt` 系列字段保留兼容，当前 Rust 版未内置 ACME 客户端，见[差异说明](07-compat.md)） |
| `disable_registration` | `false` | `ACME_DNS_API_DISABLE_REGISTRATION` | 关闭 `/register` 端点 |
| `tls_cert_privkey` | — | `ACME_DNS_API_TLS_CERT_PRIVKEY` | `tls = "cert"` 时私钥 PEM 路径 |
| `tls_cert_fullchain` | — | `ACME_DNS_API_TLS_CERT_FULLCHAIN` | `tls = "cert"` 时证书全链 PEM 路径 |
| `acme_cache_dir` | `api-certs` | `ACME_DNS_API_ACME_CACHE_DIR` | Let's Encrypt 模式缓存目录（保留字段） |
| `notification_email` | `""` | `ACME_DNS_API_NOTIFICATION_EMAIL` | Let's Encrypt 到期通知邮箱（保留字段） |
| `corsorigins` | `["*"]` | `ACME_DNS_API_CORSORIGINS` | CORS AllowOrigins，可用通配符；环境变量用英文逗号分隔 |
| `use_header` | `false` | `ACME_DNS_API_USE_HEADER` | 用 HTTP 头解析客户端 IP（反代场景） |
| `header_name` | `X-Forwarded-For` | `ACME_DNS_API_HEADER_NAME` | 从哪个头取 IP 列表 |
| `hsts_enabled` | `false` | `ACME_DNS_API_HSTS_ENABLED` | 是否发送 HSTS 头 |
| `hsts_max_age` | `31536000` | `ACME_DNS_API_HSTS_MAX_AGE` | HSTS max-age |
| `hsts_include_subdomains` | `false` | `ACME_DNS_API_HSTS_INCLUDE_SUBDOMAINS` | HSTS includeSubDomains |
| `hsts_preload` | `false` | `ACME_DNS_API_HSTS_PRELOAD` | HSTS preload |
| `admin_token` | `""` | `ACME_DNS_API_ADMIN_TOKEN` | 管理端 `/admin/*` Bearer token；为空时管理 API 不挂载。用 `acme-dns keygen` 生成 |

## [log]

| 字段 | 默认值 | 环境变量 | 说明 |
|---|---|---|---|
| `level` | `info` | `ACME_DNS_LOG_LEVEL` | `error` / `warning` / `info` / `debug` |
| `type` | `stdout` | `ACME_DNS_LOG_TYPE` | 输出目标（当前支持 `stdout`） |
| `file` | `./acme-dns.log` | `ACME_DNS_LOG_FILE` | 日志文件路径（`type` 当前仅支持 `stdout`，字段保留兼容 Go 版） |
| `format` | `text` | `ACME_DNS_LOG_FORMAT` | `text` / `json` |

## 环境变量

所有配置项均可用环境变量覆盖，命名规则：`ACME_DNS_<段>_<字段>`，全大写
（各配置项的完整变量名见上文各表的"环境变量"列）。

优先级：**环境变量 > 配置文件 > 代码默认值**。

类型解析规则：

- 布尔字段接受 `1` / `true` / `yes` / `on` 与 `0` / `false` / `no` / `off`；
- 整数字段按 `i64` 解析（如 `hsts_max_age`）；
- 数组字段（如 `corsorigins`、`records`）用英文逗号分隔；
- 其余字段按字符串原样使用。

非法值（如 `ACME_DNS_API_DISABLE_REGISTRATION=maybe`）会在启动时直接报错退出。

日志字段环境变量：`ACME_DNS_LOG_LEVEL` / `ACME_DNS_LOG_TYPE` /
`ACME_DNS_LOG_FILE` / `ACME_DNS_LOG_FORMAT`。数据库连接串 env 见
`[database]` 段（`ACME_DNS_DATABASE_URL` > `DATABASE_URL`）。

没有配置文件时也可用纯环境变量运行：只要 `ACME_DNS_DATABASE_URL`（或
`DATABASE_URL`）有值，`acme-dns` 即可启动（其余字段用默认值）。

```bash
# 示例：纯环境变量启动（连接串方式，推荐）
ACME_DNS_DATABASE_URL=sqlite:///var/lib/acme-dns/acme-dns.db \
ACME_DNS_API_HOST=0.0.0.0:8080 \
acme-dns
```

## 示例

完整带注释示例见根目录 [`config.toml`](../config.toml)，或运行 `acme-dns init` 生成。
容器专用配置见 [`docker/config.toml`](../docker/config.toml)。
