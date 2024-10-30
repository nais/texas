FROM rust:alpine AS builder
RUN apk add musl-dev
COPY . /src
WORKDIR /src
RUN cargo build --release

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /src/target/release/texas /app/texas
CMD ["/app/texas"]
