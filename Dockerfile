FROM --platform=$BUILDPLATFORM messense/rust-musl-cross:x86_64-musl AS builder-amd64
WORKDIR /build
COPY . .
RUN cargo install cargo-auditable --locked
RUN cargo auditable build --locked --release --target x86_64-unknown-linux-musl

FROM --platform=$BUILDPLATFORM messense/rust-musl-cross:aarch64-musl AS builder-arm64
WORKDIR /build
COPY . .
RUN cargo install cargo-auditable --locked
RUN cargo auditable build --locked --release --target aarch64-unknown-linux-musl

FROM builder-${TARGETARCH} AS builder

FROM cgr.dev/chainguard/static:latest
WORKDIR /app
COPY --from=builder /build/target/*-unknown-linux-musl/release/texas /app/texas
CMD ["/app/texas"]
