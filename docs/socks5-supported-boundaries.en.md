# SOCKS5 supported boundaries

LinkLake formally supports SOCKS5 `CONNECT` and `BIND`. When the server UDP relay is enabled, it also supports `UDP ASSOCIATE` and bounded UDP `FRAG` reassembly.

`GET /api/v1/socks5-proxies` returns read-only `capabilities` for every policy. With the UDP relay enabled:

```json
{
  "connect": true,
  "udp_associate": true,
  "bind": true,
  "udp_fragmentation": true
}
```

Without the UDP relay, `connect` and `bind` remain `true`, while `udp_associate` and `udp_fragmentation` are `false`. The aggregate `/api/v1/metrics` response exposes the same contract as `socks5_capabilities`.

## BIND

- BIND is accepted only after RFC 1929 authentication and creates a temporary TCP listener on the server. It cannot make a remote client execute arbitrary commands or scripts.
- The temporary port is leased only from the allowed, non-reserved TCP ports in `LINKLAKE_TCP_PUBLIC_PORTS` (or the common public-port range) and must pass a real operating-system bind. Existing management, control, HTTP/HTTPS, TLS-SNI, and other listeners are not leased.
- The requested address and port are inbound-peer constraints, not a new forwarding target. An IP must match exactly. A domain is resolved by the server with a five-second timeout and at most 16 retained addresses. A non-zero port must match the incoming connection's source port.
- The server sends the first reply with the temporary listener address. It sends the second success reply and starts bidirectional transfer only after a matching peer arrives. The wait is limited to 120 seconds and tolerates at most 32 mismatched or unauthorized peers.
- The dynamic lease is renewed every 30 seconds and released when the control connection closes, the policy stops, the wait expires, renewal fails, transfer completes, or another error path runs. Transfer still obeys policy traffic control, the global connection budget, bandwidth limits, and the two-hour maximum lifetime.
- The default dynamic-port lease is owned by one server process. This is not a claim that multiple servers share port ownership or that full HA port coordination is complete.

## UDP FRAG

- UDP FRAG is reassembled only inside an authenticated `UDP ASSOCIATE` with a bound source. Fragments must come from the UDP endpoint accepted for that association, and completed target responses still follow the contacted-target allowlist.
- The default follows strict RFC 1928 sequence ordering: a new datagram starts at sequence 1, the low seven bits carry the sequence, and the high bit marks the final fragment. Reordering gaps are not accepted by default.
- A datagram is limited to 64 fragments and `65507` encoded bytes. An incomplete datagram expires after five seconds.
- Each association may reassemble at most eight datagrams concurrently and buffer 128 fragments and 256 KiB. The whole server process is limited to 1024 inflight datagrams, 8192 fragments, and 16 MiB. Reaching any budget drops and counts the input.
- An identical non-final duplicate is counted without reserving budget twice. Conflicting duplicates, a repeated final fragment, conflicting final sequences, fragments after the final sequence, a missing initial fragment, or budget violations discard the affected assembly.
- Data is sent to the target only after SOCKS5-layer reassembly completes. LinkLake's internal QUIC DATAGRAM transport may fragment and reassemble independently, but that is a different protocol layer from SOCKS5 `FRAG`. UDP remains best effort.

## Observability and compatibility fields

Policy views and aggregate metrics expose the following values; aggregate names carry the `socks5_` prefix:

- BIND: `bind_requests_total`, `bind_active_leases`, `bind_first_replies_total`, `bind_second_replies_total`, `bind_accept_timeouts_total`, `bind_peer_rejections_total`, `bind_failures_total`, and `bind_cancellations_total`.
- FRAG: `udp_fragments_from_public_total`, `udp_fragmented_datagrams_completed_total`, `udp_fragment_duplicates_total`, `udp_fragment_rejections_total`, `udp_fragment_budget_rejections_total`, `udp_fragment_timeouts_total`, `udp_fragment_source_rejections_total`, and the current inflight datagram, fragment, and byte gauges.

Legacy `bind_rejected_total` and `udp_fragmentation_unsupported_total` fields remain only for serialization compatibility and must not be used to infer the current capability. The Web UI and Flutter Manager display capabilities and runtime metrics but expose no switch that bypasses these limits.
