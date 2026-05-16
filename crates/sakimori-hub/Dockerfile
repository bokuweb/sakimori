# Multi-stage Dockerfile for sakimori-hub on Cloudflare Containers.
#
# Build with the *repository root* as the build context so the
# whole workspace + Cargo.lock are visible:
#
#     docker build -f crates/sakimori-hub/Dockerfile -t sakimori-hub .
#
# The runtime image is debian:bookworm-slim rather than distroless
# because rusqlite (bundled SQLite) links libc and a few libm
# symbols at runtime, and a minimal Debian gets us the system
# resolver + CA bundle for the webhook dispatcher's outbound
# HTTPS without extra wrangling.
#
# Cloudflare Containers expects the entrypoint to:
#   - bind on the port given by $PORT (defaults to 8080 there)
#   - log to stdout/stderr
#   - exit on SIGTERM
# sakimori-hub already does all three. The shell wrapper just
# threads $PORT into --bind.

# -------- builder --------
FROM rust:1.84-slim-bookworm AS builder
WORKDIR /src

# Build deps for rusqlite-bundled (uses cc to compile SQLite) and
# ring/aws-lc-rs (used transitively by the proxy crate; the hub
# build pulls it in via sakimori-core's ureq dep). Keep this list
# minimal — each apt package is a release-process audit item.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        pkg-config build-essential ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Copy the workspace. We intentionally copy everything rather than
# only `crates/sakimori-hub`; cargo can't resolve a workspace
# member without the workspace manifest, and dropping unrelated
# crates would force per-crate Cargo.lock files we don't want.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

RUN cargo build --release -p sakimori-hub --bin sakimori-hub

# -------- runtime --------
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --create-home --uid 10001 sakimori

# Persistent state. On Cloudflare Containers attach a volume here
# (e.g. `volumes: { hub_data: /var/lib/sakimori-hub }` in
# wrangler.toml) so the SQLite file survives restarts. Without a
# volume the inventory resets every cold start.
ENV SAKIMORI_HUB_DB=/var/lib/sakimori-hub/hub.sqlite
RUN install -d -o sakimori -g sakimori /var/lib/sakimori-hub

COPY --from=builder /src/target/release/sakimori-hub /usr/local/bin/sakimori-hub

USER sakimori
EXPOSE 8080

# Cloudflare Containers passes $PORT; default to 8080 locally.
# `--allow-remote` is mandatory because we're binding 0.0.0.0;
# the bearer token (SAKIMORI_HUB_INGEST_TOKEN) is the auth layer
# and `main.rs` will hard-bail at startup if it's missing on a
# non-loopback bind.
ENV PORT=8080 \
    RUST_LOG=info \
    SAKIMORI_HUB_BIND=0.0.0.0:8080
ENTRYPOINT ["/bin/sh", "-c", "exec sakimori-hub \
    --bind 0.0.0.0:${PORT:-8080} \
    --allow-remote --allow-public \
    \"$@\"", "--"]
