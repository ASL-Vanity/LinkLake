FROM rust:1.97-bookworm AS builder
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo +1.91.0 build --release --locked -p linklake-server -p linklake-client && \
    install -D target/release/linklake-server /out/linklake-server && \
    install -D target/release/linklake-client /out/linklake-client

FROM debian:bookworm-slim
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/linklake-server /usr/local/bin/linklake-server
COPY --from=builder /out/linklake-client /usr/local/bin/linklake-client
RUN useradd --system --home /var/lib/linklake --create-home linklake && install -d -o linklake -g linklake /var/log/linklake
USER linklake
ENV LINKLAKE_DATA_DIR=/var/lib/linklake LINKLAKE_LOG_DIR=/var/log/linklake
VOLUME ["/var/lib/linklake", "/var/log/linklake"]
EXPOSE 32100/tcp 32101/tcp 32102/tcp 32103/tcp 32104/udp 32105/tcp
ENTRYPOINT ["/usr/local/bin/linklake-server"]
