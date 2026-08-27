# syntax=docker/dockerfile:1.7

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        iproute2 \
        nftables \
    && rm -rf /var/lib/apt/lists/*

FROM rust:1.88-bookworm AS builder

ARG TARGETARCH
WORKDIR /app
COPY . .
RUN --mount=type=cache,id=outcall-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=outcall-target-${TARGETARCH},target=/app/target,sharing=locked \
    cargo build --workspace --release --locked \
    && mkdir /out \
    && cp target/release/outcalld target/release/outcall target/release/outcall-agent /out/

FROM runtime

COPY --from=builder /out/outcalld /usr/local/bin/outcalld
COPY --from=builder /out/outcall /usr/local/bin/outcall
COPY --from=builder /out/outcall-agent /usr/local/bin/outcall-agent

ENTRYPOINT ["outcalld"]
