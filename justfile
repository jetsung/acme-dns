# acme-dns 本地开发任务。
#
# 工具链（rust / just / prek / zensical 等）已通过 mise 全局安装。
# 首次使用：just init 生成示例配置 config.toml（已存在时不覆盖）。

# 默认：列出全部任务
default:
    @just --list

# Debug 构建（开发迭代用，产物 target/debug/acme-dns）
[group('build')]
@build:
    cargo build

# Release 构建（产物 target/release/acme-dns）
[group('build')]
@build-release:
    cargo build --release

# 构建 PostgreSQL 后端（默认 sqlite 已随基础构建编译）
[group('build')]
@build-postgres:
    cargo build --features postgres

# 验证 release 二进制可执行（对齐 CI build job）
[group('build')]
@verify:
    ./target/release/acme-dns version

# 检查代码格式（rustfmt，只读不修改）
[group('check')]
@fmt:
    cargo fmt --all -- --check

# Clippy 静态检查（拒绝任何警告，对齐 CI）
[group('check')]
@clippy:
    cargo clippy --all-targets -- -D warnings

# Clippy 含 PostgreSQL 特性（改 store 层后建议跑一次）
[group('check')]
@clippy-postgres:
    cargo clippy --all-targets --features postgres -- -D warnings

# 编译检查（不生成产物，快速过一遍类型/借用错误）
[group('check')]
@check:
    cargo check

# PostgreSQL 特性编译检查
[group('check')]
@check-postgres:
    cargo check --features postgres

# 全量测试（单元 + 集成 + e2e，对齐 CI test job）
[group('test')]
@test:
    cargo test

# 仅单元测试（lib 内 #[cfg(test)]）
[group('test')]
@test-unit:
    cargo test --lib

# 仅端到端测试（tests/e2e.rs：register → update → DNS TXT 查询）
[group('test')]
@test-e2e:
    cargo test --test e2e

# 启动服务（DNS + API），配置读取顺序：-c 路径 → /etc/acme-dns/config.toml → ./config.toml
# 可附带子命令与参数，例如：just run -c config.toml
[group('run')]
@run *args:
    cargo run -- {{ args }}

# 生成示例配置 config.toml（已存在时不覆盖；-c 可指定路径）
[group('run')]
@init *args:
    cargo run -- init {{ args }}

# 构建文档站点到 site/（产物已 gitignore）
[group('docs')]
@docs-build:
    zensical build --clean

# 本地预览文档（自动打开浏览器）
[group('docs')]
@docs-serve:
    zensical serve

# 构建镜像（对齐 CI docker job：linux/amd64，不推送）
[group('docker')]
@docker-build:
    docker build -f docker/Dockerfile -t acme-dns:local .

# 中国网络环境构建（使用国内镜像源基础镜像）
[group('docker')]
@docker-build-cn:
    docker build -f docker/CN.Dockerfile -t acme-dns:local .

# 启动 compose 栈（映射 53:53/tcp+udp、80:80；配置 docker/config.toml）
[group('docker')]
@docker-up:
    docker compose -f docker/compose.yaml up -d

# 停止并移除 compose 栈
[group('docker')]
@docker-down:
    docker compose -f docker/compose.yaml down

# 全量检查：依次复现 commit 与 push 两道钩子闸门——
# pre-commit 阶段（文件卫生 + cargo fmt）与 pre-push 阶段（clippy + test）
# 提交后、push 前跑一次，避免推送时才发现 pre-push 钩子失败
[group('check')]
@hooks:
    prek run --all-files
    prek run --all-files --stage pre-push

# 复现 CI 全流程：静态检查 → 测试 → release 构建 → 二进制验证
[group('all')]
@ci:
    just fmt
    just clippy
    just test
    just build-release
    just verify
