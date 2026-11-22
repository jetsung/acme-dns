# 中国网络环境专用构建文件：apt 换阿里云镜像，cargo/rustup 走 rsproxy。
# 配置只写入 builder 层，最终运行镜像不含任何镜像源或代理配置。
# 国际/上线构建请用 Dockerfile（官方源），二者除镜像源配置外完全一致：
#
#   docker build -f CN.Dockerfile -t acme-dns:latest .   # 中国网络环境
#   docker build -f Dockerfile    -t acme-dns:latest .   # 国际/上线构建

# ---- Rust builder：musl 静态链接 ----
FROM rust:1-slim AS builder

ARG TARGETPLATFORM

# apt 换阿里云镜像；cargo 走 rsproxy（sparse index），拉依赖不走外网。
RUN sed -i 's|deb.debian.org|mirrors.aliyun.com|g' \
        /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list 2>/dev/null || true \
    && printf '[source.crates-io]\nreplace-with = "rsproxy"\n\n[source.rsproxy]\nregistry = "sparse+https://rsproxy.cn/index/"\n\n[net]\ngit-fetch-with-cli = true\n' \
        > /usr/local/cargo/config.toml

RUN apt-get update \
    && apt-get install -y --no-install-recommends musl-tools pkg-config \
    && rm -rf /var/lib/apt/lists/*

# rustup 下载 musl target 组件走 rsproxy 镜像。
ENV RUSTUP_DIST_SERVER=https://rsproxy.cn \
    RUSTUP_UPDATE_ROOT=https://rsproxy.cn/rustup

RUN case "$TARGETPLATFORM" in \
        linux/amd64) RUST_TARGET=x86_64-unknown-linux-musl ;; \
        linux/arm64) RUST_TARGET=aarch64-unknown-linux-musl ;; \
        *) echo "不支持的构建平台：$TARGETPLATFORM" >&2; exit 1 ;; \
    esac \
    && rustup target add "$RUST_TARGET" \
    && printf '%s\n' "$RUST_TARGET" > /.rust-target \
    && printf 'export CARGO_TARGET_%s_LINKER=musl-gcc\n' \
        "$(printf '%s' "$RUST_TARGET" | tr 'a-z-' 'A-Z_')" > /.rust-env

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests

# 依赖与产物目录挂 cache 卷：源码不变时跨构建复用，改动时只重编译受影响的 crate。
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    . /.rust-env \
    && cargo build --release --target "$(cat /.rust-target)" \
    && cp "target/$(cat /.rust-target)/release/acme-dns" /acme-dns

# ---- 运行阶段：distroless static（非 root） ----
FROM gcr.io/distroless/static-debian13:nonroot

COPY --from=builder /acme-dns /usr/bin/acme-dns
# 53 = DNS TCP/UDP，80 = HTTP API；数据与配置目录挂卷持久化
EXPOSE 53 53/udp 80
WORKDIR /app
VOLUME ["/etc/acme-dns", "/var/lib/acme-dns"]

ENTRYPOINT ["/usr/bin/acme-dns", "-c", "/etc/acme-dns/config.toml"]
