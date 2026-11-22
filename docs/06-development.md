# 本地开发

## 工具链

- Rust stable（rustc ≥ 1.85，edition 2024）；可用 [mise](https://mise.jdx.dev)
  一键安装：`mise use -g rust`
- 无前端、无外部系统依赖；PostgreSQL 后端测试需 PG 实例

## 常用命令

```bash
cargo build --release                 # 发布构建，产物 target/release/acme-dns
cargo test                            # 单元 + e2e 测试（默认 SQLite）
cargo test --features postgres        # PostgreSQL 后端测试（需 PG）
cargo clippy --all-targets -- -D warnings   # 静态检查，拒绝任何警告
cargo fmt --all -- --check            # 格式检查（CI 同参数）
acme-dns init                         # 生成示例配置
acme-dns version                      # 版本号
```

## 代码结构

```
src/
  main.rs        # 入口：CLI 解析、启动编排、错误通道、信号处理
  config.rs      # TOML 配置解析/校验/默认值、示例配置常量
  logger.rs      # tracing-subscriber 初始化
  error.rs       # AppError + IntoResponse
  models.rs      # AcmeTxt / AcmeTxtPost / CidrSlice / 配置结构体
  store/         # Store trait + SQLite / PostgreSQL 实现
  dnsserver/     # 自管 tokio DNS 监听、应答、静态记录、权威判定
  api/           # axum Router：register / update / health + auth + tls
tests/
  e2e.rs         # 端到端集成测试（临时 SQLite + 随机端口全栈）
```

模块职责与 Go 包的对应关系见[架构设计](01-architecture.md)。

## 测试说明

- 单元测试覆盖：CIDR 解析、TXT 长度校验、认证、配置解析、静态记录/SOA、
  权威判定、DNS 应答（A/NS/SOA/TXT/CNAME + EDNS0）。
- `tests/e2e.rs` 启动完整服务栈（临时 SQLite + 随机高端口），覆盖：
  register → update → DNS TXT 查询返回新值；二次 update 滚动两条；
  未注册子域 NXDOMAIN + SOA；鉴权失败 401；acme.sh 兼容调用形态。

## Docker 本地验证

```bash
cd docker
docker compose up --build -d
curl http://127.0.0.1:80/health
docker compose down
```

`docker/CN.Dockerfile` 用于中国网络环境（rustup/crates.io 走国内镜像源），
构建产物与国际版一致。

## CI/CD

`.github/workflows/` 下四条流水线（push 到 GitHub 后生效）：

| 工作流 | 触发 | 作用 |
|---|---|---|
| `ci.yml` | push main/dev*、PR | fmt + clippy + 测试 + release 构建 + Docker 构建检查 |
| `release.yml` | tag vX.Y.Z(-beta/-rc) | Linux 4 目标（x86_64/aarch64 × gnu/musl）编译，发 GitHub Release |
| `docker-release.yml` | tag、手动 | amd64/arm64 镜像推 GHCR，可选同步 Docker Hub / TCR / ACR |
| `docker-dev.yml` | push dev* | 开发镜像 `dev` tag 推 GHCR |

## 与 Go 版的渊源

本项目最初基于 Go 版 acme-dns 的对外契约重写；行为比对见
[与 Go 版的差异](07-compat.md)。
