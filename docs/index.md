# acme-dns

一个只服务 ACME DNS-01 质询（TXT 记录）的简化权威 DNS 服务器，附带
RESTful HTTP API，以 Rust 实现。

!!! tip "与上游 acme-dns 的关系"

    本项目最初基于 [acme-dns](https://github.com/joohoi/acme-dns)（Go）的
    对外契约重写，兼容性说明见 [与 Go 版的差异](07-compat.md)。
    后续将按本项目路线演进，与上游版本的差异可能逐步扩大。

多数 DNS 服务器不为 ACME DNS 质询提供自动化 API；提供的又往往权限过大。
acme-dns 提供仅限 TXT 记录更新的简单 API，配合 `_acme-challenge` 子域
CNAME 使用——即使 API key 泄露，影响也被限制在单个子域的 TXT 记录上。

## 能力一览

- **ACME 专用 DNS**：服务 `_acme-challenge` TXT 质询；双 TXT 滚动更新，
  同时应答 `yourdomain.tld` 与 `*.yourdomain.tld`。
- **REST API**：`/register` 获取凭据与唯一子域、`/update` 写入质询 token、
  `/health` 探活。
- **来源限制**：注册时可按 CIDR 声明 `/update` 允许来源；反代场景可经
  `X-Forwarded-For` 等头解析真实 IP。
- **双后端**：SQLite（默认，schema 兼容 Go 版，可直接复用现有
  `acme-dns.db`）与 PostgreSQL。
- **自定义记录**：支持 A、AAAA、NS 等静态记录预置。
- **可观测**：tracing 日志，level/type（stdout）/format（json/text）可配；
  CORS、HSTS 可配置。
- **单二进制部署**：Rust stable 编译，提供 Dockerfile / compose /
  systemd 单元；官方镜像 `ghcr.io/jetsung/acme-dns:latest`。

## 快速使用

前提：**acme-dns 服务已部署，且主域名侧已把质询子域授权给它**。假设服务域名为
`auth.example.org`（对应配置 `[general] domain`）、主机公网 IP 为 `198.51.100.1`，
需先在主域名的 DNS 服务器添加：

```text
auth.example.org.  NS   auth.example.org.        ; 授权该子域
auth.example.org.  A    198.51.100.1             ; IPv6 加 AAAA
```

之后，对每个要签证书的域名执行三步：

1. `POST /register` 获取凭据与唯一子域；
2. 在主域名区域为该域名添加 CNAME：
   `_acme-challenge.domainiwantcertfor.tld. CNAME <subdomain>.auth.example.org`；
3. 用凭据 `POST /update` 写入 CA 下发的质询 token，等 CA 验证即可。

部署与记录细节见 [快速开始](02-getting-started.md)。

```bash
# 注册
curl -X POST https://auth.example.org/register
# 更新 TXT
curl -X POST \
  -H "X-Api-User: <username>" -H "X-Api-Key: <password>" \
  -d '{"subdomain": "<subdomain>", "txt": "___validation_token_received_from_the_ca___"}' \
  https://auth.example.org/update
```

## 阅读路径

| 我想…… | 看这里 |
|---|---|
| 尽快跑起来（源码 / Docker / compose / systemd） | [快速开始](02-getting-started.md) |
| 配置 DNS/数据库/API/日志 | [配置参考](03-configuration.md) |
| 对接自动化签发流程 | [REST API](05-api.md) |
| 二次开发、跑测试 | [本地开发](06-development.md) |
| 了解模块划分与技术选型 | [架构设计](01-architecture.md) |
| 看与 Go 版的行为差异 | [与 Go 版的差异](07-compat.md) |
