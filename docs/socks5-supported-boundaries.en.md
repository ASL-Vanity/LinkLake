# SOCKS5 supported boundaries

LinkLake formally supports SOCKS5 `CONNECT` and supports `UDP ASSOCIATE` when the server UDP relay is enabled.

`BIND` is intentionally unsupported and deterministically returns reply `0x07` (Command not supported). SOCKS5 application-level UDP fragmentation is also intentionally unsupported, so every datagram with a non-zero `FRAG` field is dropped. LinkLake's internal QUIC datagram fragmentation is a separate transport mechanism and does not implement SOCKS5 FRAG semantics.

`GET /api/v1/socks5-proxies` returns a read-only `capabilities` object for every policy:

```json
{
  "connect": true,
  "udp_associate": true,
  "bind": false,
  "udp_fragmentation": false
}
```

`udp_associate` reflects whether the server UDP relay is available. The aggregate `/api/v1/metrics` response exposes the same contract as `socks5_capabilities`.

Expected BIND and FRAG rejection events keep contributing to the existing compatibility counters and also increment dedicated counters:

- `socks5_bind_rejected_total`
- `socks5_udp_fragmentation_unsupported_total`

Per-policy responses use `bind_rejected_total` and `udp_fragmentation_unsupported_total`. The Web UI and Flutter Manager display these supported boundaries but do not expose switches for unavailable commands.
