# syntax=docker/dockerfile:1
FROM rust:1-slim-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src/ ./src/
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/bifrost-resolver /usr/local/bin/bifrost-resolver
COPY entrypoint.sh /usr/local/bin/bifrost-entrypoint.sh
RUN chmod +x /usr/local/bin/bifrost-entrypoint.sh
# Unprivileged: binds a high port (5454), 53 is remapped externally.
USER 65534:65534
EXPOSE 5454/udp 5454/tcp
ENTRYPOINT ["/usr/local/bin/bifrost-entrypoint.sh"]
