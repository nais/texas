FROM --platform=$BUILDPLATFORM rust:1.95.0-trixie AS builder
WORKDIR /build

# zig is not packaged in trixie; install via pip's ziglang wheel.
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3-pip python3-venv && \
    rm -rf /var/lib/apt/lists/* && \
    python3 -m venv /opt/zig && \
    /opt/zig/bin/pip install --no-cache-dir ziglang
ENV PATH="/opt/zig/bin:$PATH"

RUN cargo install --locked cargo-zigbuild cargo-auditable
RUN rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu

ARG TARGETARCH
COPY . .
RUN case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-gnu  ;; \
      arm64) target=aarch64-unknown-linux-gnu ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    cargo auditable zigbuild --locked --release --target "$target" && \
    cp "target/$target/release/texas" /build/texas

FROM cgr.dev/chainguard/glibc-dynamic:latest
WORKDIR /app
COPY --from=builder /build/texas /app/texas
# Cap glibc per-thread arenas to reduce RSS fragmentation under bursty traffic.
ENV MALLOC_ARENA_MAX=2
# Pin the trim threshold to disable glibc's dynamic heap-shrink adjustment.
ENV MALLOC_TRIM_THRESHOLD_=131072
ENTRYPOINT ["/app/texas"]
