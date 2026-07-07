FROM rust:1.88-bookworm AS builder

WORKDIR /app
COPY . .
RUN cargo build --workspace --release --locked

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        iproute2 \
        nftables \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/outcalld /usr/local/bin/outcalld
COPY --from=builder /app/target/release/outcall /usr/local/bin/outcall
COPY --from=builder /app/target/release/outcall-agent /usr/local/bin/outcall-agent

ENTRYPOINT ["outcalld"]
