# HTTP/2 and gRPC support boundaries

LinkLake HTTP hostname routes accept both HTTP/1.1 and HTTP/2.

## Public ingress

- `LINKLAKE_HTTP_BIND` auto-detects HTTP/1.1 and HTTP/2 prior knowledge.
- `LINKLAKE_HTTPS_BIND` prefers `h2` through TLS ALPN and retains `http/1.1` fallback.
- HTTP/1.1 `Upgrade: h2c` is not implemented. Cleartext HTTP/2 clients must send the connection preface directly.

## Backend protocol

- Regular HTTP/2 requests are translated to HTTP/1.1 backend requests, so existing local websites do not need HTTP/2 support.
- Native gRPC is identified by `Content-Type: application/grpc` or `application/grpc+...` and uses persistent, multiplexed h2c backend connections.
- The local gRPC target must directly support cleartext HTTP/2 prior knowledge. There is currently no local-target TLS, ALPN, or h2c Upgrade setting.
- gRPC-Web is not classified as native gRPC and continues through the regular HTTP path.

## Lifecycle and limits

- An HTTP policy's `max_connections` value is the maximum concurrent stream count for HTTP/2.
- An h2c connection can carry multiple streams for one policy, but connections are never shared across policies, security contexts, or protocols.
- After GOAWAY or a closed sender is observed, the old connection accepts no new streams. It is removed after active streams finish, and a later request establishes a replacement.
- Disabling or deleting a policy, replacing its client registration, or shutting down the server invalidates that policy's backend pool and cancels its active streams.
- Connection establishment, HTTP/2 handshake, and response headers have deadlines. Response bodies have no fixed total-duration limit, allowing long-lived streams.

## gRPC semantics

- Request and response DATA frames stream with backpressure and are not buffered as complete messages.
- `TE: trailers`, response trailers, `grpc-status`, and `grpc-message` are preserved.
- Cancelling a public stream drops the corresponding backend response and releases its stream lease without closing other streams on the shared connection.
- WebSocket/WSS continues to use HTTP/1.1 Upgrade and never enters the gRPC backend pool.

## Observability

`/api/v1/metrics`, the Prometheus endpoint, and each HTTP policy view expose:

- active HTTP/2 streams and request totals;
- active gRPC streams, requests, trailers, failures, and cancellations;
- backend active connections/streams, connections created, reuse, recovery, GOAWAY, failures, and pool-capacity rejections.

The management API's read-only `capabilities` object reports HTTP/1.1, HTTP/2, gRPC, TLS ALPN, h2c prior knowledge, and `grpc_backend_transport = "h2c"`. These fields are not policy switches.
