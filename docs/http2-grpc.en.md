# HTTP/2 and gRPC support boundaries

LinkLake HTTP hostname routes accept HTTP/1.1, HTTP/2 prior knowledge, and a constrained HTTP/1.1 `Upgrade: h2c`. Native gRPC can use either a cleartext h2c target or a verified TLS target that negotiates ALPN `h2`.

## Public ingress

- `LINKLAKE_HTTP_BIND` auto-detects HTTP/1.1 and HTTP/2 prior knowledge.
- `LINKLAKE_HTTPS_BIND` prefers `h2` through TLS ALPN and retains `http/1.1` fallback.
- HTTP/1.1 `Upgrade: h2c` must contain exactly one `Upgrade: h2c`, `Connection: Upgrade, HTTP2-Settings`, and valid base64url `HTTP2-Settings` value. Duplicate settings, malformed values, decoded settings above 1024 bytes, or an upgrade request body are rejected.
- At most 128 h2c upgrades run concurrently across the process. The upgrade handshake has a ten-second deadline and the upgraded byte stream has a two-hour maximum lifetime. Bidirectional transfer starts only after the local target returns a valid `101 Switching Protocols` response.

## Regular HTTP backend

- Regular HTTP/2 requests are translated to HTTP/1.1 backend requests, so existing local websites do not need HTTP/2 support.
- HTTP/1.1 backends use a bounded connection pool. Connections are never shared across policies, targets, or security contexts, and ambiguous hop-by-hop headers, request-smuggling boundaries, and pool exhaustion fail closed.
- WebSocket/WSS uses HTTP/1.1 Upgrade. Neither WebSocket nor h2c Upgrade enters the native gRPC backend pool.

## gRPC backend transport

Native gRPC is identified by `Content-Type: application/grpc` or `application/grpc+...`. Each HTTP route can configure:

```json
{
  "grpc_backend_transport": "tls",
  "grpc_backend_server_name": "grpc.internal.example",
  "grpc_backend_trust_profile": "private_ca"
}
```

- `grpc_backend_transport = "h2c"` is the default. The local target must accept HTTP/2 prior knowledge directly, and the route cannot also carry a TLS server name or trust profile.
- `grpc_backend_transport = "tls"` requires a DNS-form `grpc_backend_server_name`. IP literals, empty labels, and invalid DNS names are rejected. The TLS handshake uses this value for SNI and certificate identity verification and requires ALPN `h2`.
- TLS without `grpc_backend_trust_profile` uses the native trust roots of the LinkLake server host. With a profile, the server loads an independent CA set from `LINKLAKE_GRPC_TRUST_PROFILE_DIR/<profile>.pem`.
- A profile name contains 1–64 ASCII letters, digits, hyphens, or underscores. The directory and file must canonicalize successfully; the file must remain inside that directory, be a regular file, and be at most 1 MiB. At most 64 certificates and 1 MiB of DER are loaded. A missing directory, escaped path, empty file, invalid certificate, or exceeded budget fails closed.
- The TLS handshake has a ten-second deadline. Pools are never shared between h2c and TLS, different server names, system trust and profile trust, or different profiles.
- gRPC-Web is not classified as native gRPC and continues through the regular HTTP path.

## Lifecycle and limits

- An HTTP policy's `max_connections` value is the maximum concurrent stream count for HTTP/2.
- One HTTP/2 backend connection can carry multiple streams only for the same policy and security context.
- After GOAWAY or a closed sender is observed, the old connection accepts no new streams. It is removed after active streams finish, and a later request establishes a replacement.
- Disabling or deleting a policy, replacing its client registration, or shutting down the server invalidates that policy's backend pool and cancels active streams.
- Connection establishment, HTTP/2 handshake, and response headers have deadlines. Response bodies have no fixed total-duration limit, allowing long-lived streams.

## gRPC semantics

- Request and response DATA frames stream with backpressure and are not buffered as complete messages.
- `TE: trailers`, response trailers, `grpc-status`, and `grpc-message` are preserved.
- Cancelling a public stream drops the corresponding backend response and releases its stream lease without closing other streams on the shared connection.
- Automatic retry follows the built-in replay-safety policy; management cannot mark arbitrary non-idempotent requests as replayable.

## Observability and API

`/api/v1/metrics`, the Prometheus endpoint, and each HTTP policy view expose:

- active HTTP/2 streams and request totals;
- active gRPC streams, requests, trailers, failures, and cancellations;
- backend active connections/streams, connections created, reuse, recovery, GOAWAY, failures, and pool-capacity rejections;
- h2c Upgrade attempts, active upgrades, completions, rejections, timeouts, and failures;
- gRPC TLS handshakes, handshake failures, ALPN failures, system-trust connections, and profile-trust connections.

The route's `grpc_backend_transport`, `grpc_backend_server_name`, and `grpc_backend_trust_profile` fields are authoritative per-policy configuration. The aggregate read-only `capabilities.grpc_backend_transport = "h2c"` value is a retained default-transport hint; it does not mean TLS backends are unavailable and does not replace route fields.
