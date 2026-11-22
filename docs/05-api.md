# REST API

所有接口挂在 API 监听地址下（`[api] ip:port`），路径、请求/响应 JSON、
鉴权头与 Go 版 acme-dns 完全一致。响应错误体统一为：

```json
{"error": "错误描述"}
```

## POST /register

注册新子域，返回更新凭据。可选 POST JSON 限制 `/update` 来源 CIDR：

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

- `username` / `subdomain` 为 UUIDv4；`password` 为 40 字符 URL-safe 随机串。
- `allowfrom` 为空数组表示不限制来源。
- `[api] disable_registration = true` 时该端点返回 403。

## POST /update

更新子域 TXT 应答。必需请求头：

| Header name | Description | Example |
| ----------- | ----------- | ------- |
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

校验规则与错误码：

| 条件 | 响应 |
|---|---|
| 凭据错误 / 子域不匹配 | `401 Unauthorized` |
| 请求体非法、`txt` 非 43 字符 | `400 Bad Request` |
| 来源 IP 不在 `allowfrom` CIDR 内 | `403 Forbidden` |
| 成功 | `200 OK`（写入滚动 TXT 行） |

来源 IP 解析：默认取连接对端地址；`use_header = true` 时按 `header_name`
（默认 `X-Forwarded-For`）取头中 IP 列表（反代场景）。

## GET /health

就绪/存活探测，成功返回 `200 OK`。

## 管理端 `/admin/*`

Rust 版扩展能力，非上游 Go 契约。仅当配置了 `[api] admin_token`
（非空字符串）时挂载；所有请求需携带请求头：

```
Authorization: Bearer <admin_token>
```

token 错误返回 `401 Unauthorized`；账户不存在返回 `404 Not Found`；
请求体非法返回 `400 Bad Request`；子域冲突返回 `409 Conflict`。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/admin/accounts` | 列出全部账户 |
| POST | `/admin/accounts` | 注册账户（可自定义子域） |
| GET | `/admin/accounts/{username}` | 查看账户 |
| DELETE | `/admin/accounts/{username}` | 删除账户 |
| PATCH | `/admin/accounts/{username}` | 更新 `allowfrom` |
| POST | `/admin/accounts/{username}/password` | 重置密码 |
| PUT | `/admin/accounts/{username}/txt` | 覆盖写入 TXT（≤2 条） |
| DELETE | `/admin/accounts/{username}/txt` | 清空 TXT |

CLI 侧提供等价的远程管理入口。`--remote` / `--url` / `--token` 是全局
参数，可放在命令任意位置；走 `/admin` HTTP API，不读本地 `-c` 配置：

```bash
acme-dns --remote --url <api-base> --token <admin_token> accounts list
acme-dns --remote --url <api-base> --token <admin_token> accounts show <subdomain>
acme-dns --remote --url <api-base> --token <admin_token> accounts delete <username>
acme-dns --remote --url <api-base> --token <admin_token> accounts password <username>
acme-dns --remote --url <api-base> --token <admin_token> txt get <subdomain>
acme-dns --remote --url <api-base> --token <admin_token> txt set <subdomain> <txt> [txt2]
acme-dns --remote --url <api-base> --token <admin_token> txt clear <subdomain>
```

`--url` / `--token` 缺省时依次回退环境变量 `ACME_DNS_URL` / `ACME_DNS_TOKEN`；
命令行参数优先于环境变量。目标选择规则：

- 显式 `--remote`：必须能解析出 url+token，否则报错；
- 显式 `--local`：强制走本地数据库；
- 都不指定（默认）：设了 `--url`/`--token`（或环境变量有值）即走远端，
  否则走本地数据库。

### POST /admin/accounts

请求体（均可选；与 `POST /register` 相同的响应结构）：

```json
{
    "subdomain": "my-sub",
    "allowfrom": ["192.168.100.1/24"]
}
```

- `subdomain` 省略时自动生成 UUIDv4；指定时做合法性与查重校验。
- `Status: 201 Created`，响应同 `POST /register`。

### GET /admin/accounts 与 GET /admin/accounts/{username}

`Status: 200 OK`（列表）：

```json
[
    {
        "username": "c36f50e8-4632-44f0-83fe-e070fef28a10",
        "fulldomain": "my-sub.auth.example.org",
        "subdomain": "my-sub",
        "allowfrom": ["192.168.100.1/24"],
        "txt": ["", ""],
        "last_update": 1700000000,
        "created_at": 1700000000
    }
]
```

单个账户返回同一结构（非数组）。

### PATCH /admin/accounts/{username}

请求体：

```json
{
    "allowfrom": ["10.0.0.0/8", "2002:c0a8:2a00::0/40"]
}
```

返回更新后的账户（同上）；`allowfrom` 传空数组即取消来源限制。

### POST /admin/accounts/{username}/password

无请求体。`Status: 200 OK`：

```json
{
    "username": "c36f50e8-4632-44f0-83fe-e070fef28a10",
    "password": "htB9mR9DYgcu9bX_afHF62erXaH2TS7bg9KW3F7Z"
}
```

### PUT /admin/accounts/{username}/txt

请求体（`txt` 必填 43 字符 URL-safe 串；`txt2` 可选，缺省为空）：

```json
{
    "txt": "___validation_token_received_from_the_ca___",
    "txt2": ""
}
```

`Status: 200 OK`：

```json
{
    "txt": ["___validation_token_received_from_the_ca___", ""]
}
```

写入覆盖两条滚动 TXT 行（对齐 `/update` 的滚动语义：最新值在 `txt[0]`）。
`DELETE` 同路径清空两行，返回同结构（两个空串）。

### curl 示例

```bash
AUTH="Authorization: Bearer 你的admin_token"
BASE=https://auth.example.org

# 列出账户
curl -H "$AUTH" $BASE/admin/accounts

# 指定子域注册
curl -X POST -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"subdomain": "my-sub"}' $BASE/admin/accounts

# 更新 allowfrom
curl -X PATCH -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"allowfrom": ["192.168.100.1/24"]}' \
  $BASE/admin/accounts/c36f50e8-4632-44f0-83fe-e070fef28a10

# 重置密码
curl -X POST -H "$AUTH" \
  $BASE/admin/accounts/c36f50e8-4632-44f0-83fe-e070fef28a10/password

# 写入 / 清空 TXT
curl -X PUT -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"txt": "___validation_token_received_from_the_ca___"}' \
  $BASE/admin/accounts/c36f50e8-4632-44f0-83fe-e070fef28a10/txt
curl -X DELETE -H "$AUTH" \
  $BASE/admin/accounts/c36f50e8-4632-44f0-83fe-e070fef28a10/txt

# 删除账户
curl -X DELETE -H "$AUTH" \
  $BASE/admin/accounts/c36f50e8-4632-44f0-83fe-e070fef28a10
```

## 本地客户端用法

`acme-dns` 二进制本身可作为本地客户端：账户管理子命令加 `--remote`
（或 `--url`/`--token`）后经 `/admin/*` HTTP API 操作远端实例，
不需要登录服务器，也不读取本地 `-c` 配置文件。

### 连接参数

| 来源 | 说明 |
|---|---|
| `--remote` | 显式走远端 `/admin` API；此时必须能解析出 url+token |
| `--url <api-base>` | 目标实例 API 地址，如 `https://auth.example.org`（尾随 `/` 自动去除） |
| `--token <admin_token>` | 目标实例的 `[api] admin_token`（Bearer 鉴权） |
| `ACME_DNS_URL` | `--url` 缺省时回退到此环境变量 |
| `ACME_DNS_TOKEN` | `--token` 缺省时回退到此环境变量 |

三个 flag 均为全局参数，可放在命令任意位置；命令行参数优先于环境变量。
不指定 `--remote`/`--local` 时，设了 `--url`/`--token`（或环境变量有值）
即走远端，否则走本地数据库。

### 快速上手

```bash
# 1. 导出目标实例地址与 admin_token（服务端用 acme-dns keygen 生成）
export ACME_DNS_URL=https://auth.example.org
export ACME_DNS_TOKEN=<admin_token>

# 2. 列出全部账户
acme-dns --remote accounts list

# 3. 查看某子域
acme-dns --remote accounts show my-sub

# 4. 写入 / 清空 TXT 质询记录
acme-dns --remote txt set my-sub ___validation_token_received_from_the_ca___
acme-dns --remote txt get my-sub
acme-dns --remote txt clear my-sub

# 5. 重置密码 / 删除账户
acme-dns --remote accounts password my-sub
acme-dns --remote accounts delete <username>
```

也可以不导出环境变量，单次指定：

```bash
acme-dns --remote --url https://auth.example.org --token <admin_token> txt set my-sub <txt>
```

> 建户（注册子域）目前只有 `/register` 端点与 `POST /admin/accounts`，
> CLI 未提供 `accounts register` 子命令；可参考上文 curl 示例调用。

### 与第三方 ACME 客户端对接

`/register` 与 `/update` 的路径、请求/响应 JSON、鉴权头与 Go 版 acme-dns
完全一致，支持 acme-dns 协议的 ACME 客户端与钩子（acme.sh、certbot 配
acme-dns hook、Lego、cert-manager、Traefik 等）可直接对接，无需改动。
