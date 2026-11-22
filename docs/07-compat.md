# 与 Go 版的差异

本项目最初基于 Go 版 acme-dns 的对外契约重写。当前版本与 Go 版的对应关系
如下；后续随本项目自有功能演进，差异可能逐步扩大，以本文档为准。

## 完全一致

- REST API：`/register`、`/update`、`/health` 的路径、请求/响应结构、
  状态码与错误体。
- DNS 应答语义：TTL、SOA serial、NXDOMAIN + SOA authority、EDNS BADVERS、
  双 TXT 滚动更新。
- 配置文件结构：`[general]` / `[database]` / `[api]` / `[log]` 四段（Rust 版），
  与 Go 版 `config.cfg` 的差异：日志段名为 `[log]`（字段无 `log` 前缀），
  数据库连接串用 `url` 字段（scheme 决定 engine），API 监听用 `host` 合写。
  数据库连接串另支持 `ACME_DNS_DATABASE_URL` / `DATABASE_URL` env。
- 数据库 schema：`records` / `txt` / `acmedns` 表结构兼容，可直接打开
  Go 版创建的 `acme-dns.db`（含 bcrypt 口令哈希，格式跨语言通用）。
- 运维行为：SQLite 单连接串行化、DNS 热路径 5s 读超时 / 一般 20s 超时、
  恒定时间口令校验。

## 行为差异

| 项 | Go 版 | Rust 版 |
|---|---|---|
| `tls = "letsencrypt"` / `"letsencryptstaging"` | certmagic 自动签发与续期 | **暂未内置 ACME 客户端**：配置字段被接受，但启动时报错。需自动签发时用外部工具（acme.sh / certbot）签发后走 `tls = "cert"` |
| API 监听地址 | `[api]` 段 `ip` + `port` 分开写 | `[api]` 段 `host = "0.0.0.0:443"` 合写（env `ACME_DNS_API_HOST` 优先级最高）；不再支持 `ip`/`port` 分写 |
| 日志输出 `logtype = "file"` | 支持写文件 | 当前支持 `stdout`（文件输出规划中） |
| PostgreSQL `rowid` | SQLite/PG 均用 `rowid` | PG 用显式 `SERIAL` 列等价实现，滚动更新选行语义一致 |
| 二进制/进程名 | `acme-dns`（Go） | `acme-dns`（Rust，Cargo 包名 `acme-dns`） |

## 部署差异

- 构建产物为单个 Rust 二进制，无 Go 运行时；静态链接 musl 镜像基于
  distroless static（非 root）。
- `acme-dns.service` 语义与 Go 版一致，`ExecStart` 指向 Rust 二进制。
- `.goreleaser.yml` / `.golangci.yaml` 不再适用；对应能力由
  `.github/workflows/release.yml`（多平台二进制发布）与
  clippy（`-D warnings`）承担。
