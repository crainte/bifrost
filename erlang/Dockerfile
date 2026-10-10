# syntax=docker/dockerfile:1

# Stage 1: Build Rust binary
FROM rust:1-slim-bookworm AS rust-builder
WORKDIR /app
COPY rust/Cargo.toml rust/Cargo.lock* ./rust/
COPY rust/src/ ./rust/src/
RUN cargo build --release --manifest-path rust/Cargo.toml

# Stage 2: Build Erlang release
FROM erlang:29 AS erlang-builder
WORKDIR /app
COPY erlang/rebar.config erlang/rebar.lock* ./
COPY erlang/apps/ ./apps/
COPY erlang/config/ ./config/
# epgsql 4.8.0 ships the OTP-26 gen_tcp:send fix upstream (PR #304), so the old
# hand-patch of epgsql_sock.erl is gone — we depend on the released driver as-is.
RUN rebar3 get-deps && rebar3 compile && rebar3 release

# Stage 3: Minimal runtime image
FROM erlang:29-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Rust hot-path binary. Cargo package "bifrost-resolver" (rust/Cargo.toml) emits
# target/release/bifrost-resolver; installed as /usr/local/bin/bifrost-resolver
# to match BIFROST_RUST_BIN. Named distinctly from the "bifrost" OTP release that
# supervises it, so both are unambiguous in ps/logs.
COPY --from=rust-builder /app/rust/target/release/bifrost-resolver /usr/local/bin/bifrost-resolver

# Erlang release. relx release name is "bifrost" (erlang/rebar.config), so rebar3
# emits _build/default/rel/bifrost; installed at /opt/bifrost. Owned by the
# runtime user (65534) because the release runner regenerates config under
# releases/<vsn>/ at boot (RELX_REPLACE_OS_VARS writes vm.args.orig / sys.config).
COPY --from=erlang-builder --chown=65534:65534 /app/_build/default/rel/bifrost /opt/bifrost

# Runtime state dirs. Owned by nobody (65534) so the unprivileged runtime user
# can create the IPC socket (/run/bifrost) and write Mnesia disc_copies
# (/var/lib/bifrost/mnesia). In k8s the mnesia PVC is chowned via fsGroup.
RUN mkdir -p /run/bifrost /var/lib/bifrost/mnesia \
    && chown -R 65534:65534 /run/bifrost /var/lib/bifrost

# Node-distribution defaults. RELX_REPLACE_OS_VARS enables ${VAR} substitution
# in vm.args at release start. Dev (docker-compose) uses short names on the
# bridge network; k8s overrides BIFROST_DIST_NAME with a long -name bound to the
# pod FQDN. Override BIFROST_COOKIE via a Secret in production.
ENV RELX_REPLACE_OS_VARS=true \
    BIFROST_DIST_NAME="-sname bifrost" \
    BIFROST_COOKIE=bifrost

# Unprivileged. DNS binds a high port (5454); port 53 is remapped externally by
# the k8s Service (targetPort) or `docker run -p 53:5454`. No CAP_NET_BIND_SERVICE
# and no root required.
USER 65534:65534

EXPOSE 5454/udp 5454/tcp

CMD ["/opt/bifrost/bin/bifrost", "foreground"]
