# DEFT Daemon Docker image for k3d testing
FROM rust:1.75-slim-bookworm AS builder

WORKDIR /app
COPY . .

RUN apt-get update && apt-get install -y pkg-config libssl-dev && \
    cargo build --release -p deft-daemon

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/deftd /usr/local/bin/deftd

RUN mkdir -p /etc/deft /var/lib/deft /var/log/deft

EXPOSE 7741 7742

ENTRYPOINT ["deftd"]
CMD ["--config", "/etc/deft/config.toml"]
