FROM rust AS builder
COPY . /src
WORKDIR /src
RUN cargo build --release

FROM gcr.io/distroless/base-debian12:nonroot
WORKDIR /app
COPY --from=builder /src/target/release/texas /app/texas
CMD ["/app/texas"]
