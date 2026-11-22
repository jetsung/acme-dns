# 构建阶段：Rust 编译（bookworm，glibc 2.36，与运行镜像一致）
FROM rust:1-bookworm AS builder

WORKDIR /app
# 先拷贝清单以利用层缓存
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN cargo build --release

# 运行阶段：轻量运行时
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

COPY --from=builder /app/target/release/acme-dns /usr/local/bin/acme-dns

WORKDIR /app
RUN mkdir -p /etc/acme-dns /var/lib/acme-dns

VOLUME ["/etc/acme-dns", "/var/lib/acme-dns"]

# 53 = DNS TCP/UDP，80 = HTTP API
EXPOSE 53 53/udp 80

ENTRYPOINT ["/usr/local/bin/acme-dns", "-c", "/etc/acme-dns/config.toml"]
