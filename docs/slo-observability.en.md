# LinkLake SLO and Alert Observability

The LinkLake server persists protocol request and error counters in a 30-day metrics history. The same SLO result is exposed by `GET /api/v1/slo`, `GET /api/v1/metrics`, and `GET /api/v1/metrics/prometheus`. Management endpoints require a read-scoped or stronger bearer token.

## SLO definition

- The default availability target is `99.9%`. Override it with `LINKLAKE_SLO_AVAILABILITY_TARGET=0.999`; the value must be strictly between `0` and `1`.
- Availability is `1 - errors / requests`. An idle window is treated as 100% available and does not create a burn alert.
- The 30-day error-budget ratio is `1 - target`. The API returns both consumed multiples and a remaining ratio clamped at zero.
- Burn rate is the window error rate divided by the allowed error rate. The fast alert requires both `5m` and `1h` to be at least `14.4x`; the slow alert requires both `6h` and `24h` to be at least `6x`.
- HTTP latency measures admitted requests through receipt of backend response headers. Prometheus exports the standard `linklake_http_request_duration_seconds` histogram and p50/p95/p99 approximations.

## Reliable and secret-safe notifications

Notifications enter a SQLite outbox before delivery. Workers use leases, exponential backoff, a ten-attempt limit, and a dead-letter state. Restarts, expired leases, and stale workers cannot regress a completed state; dead letters can be retried from the API or Manager.

- The database, API, and logs only receive stable codes such as `webhook_http_status_503` and `smtp_status_auth_535`. Webhook query/userinfo, SMTP credentials, and raw SMTP responses are never included.
- Production webhooks require HTTPS and reject URL userinfo. `LINKLAKE_ALERT_ALLOW_LOOPBACK_HTTP=true` only permits `localhost` or loopback IP addresses for explicit tests.
- SMTP host/from/to values reject control characters, command concatenation, and header injection. Subject is folded to one line and capped at 180 characters.
- SMTP requires `implicit` TLS or `starttls` by default. `LINKLAKE_SMTP_ALLOW_INSECURE=true` is only for loopback socket E2E or isolated testing.

## Prometheus, Alertmanager, Grafana, and Kubernetes

Docker Compose loads the recording rules, alert rules, safe-default Alertmanager configuration, and SLO dashboard under `deploy/`. The default Alertmanager receiver sends nothing externally so no destination or credential needs to be committed. Inject production receivers through a secret-management system.

Prometheus Operator users can enable the bundled resources:

```yaml
monitoring:
  serviceMonitor:
    enabled: true
    insecureSkipVerify: false
  prometheusRule:
    enabled: true
```

The `ServiceMonitor` reads its bearer token from the existing authentication Secret at `auth.managementTokenKey`. Use a trusted CA in production; do not make `insecureSkipVerify` the production default.

## Operational checks

1. Confirm that `/api/v1/slo` reports increasing `slo_observed_seconds` and a healthy 30-day archive.
2. Inspect error budget, all four burn rates, HTTP p50/p95/p99, and notification dead letters in Grafana.
3. Exercise notifications only against loopback Webhook/SMTP sockets and confirm that database/API errors do not contain the test marker `supersecret`.
4. Before enabling external delivery, validate safe failure codes and the dead-letter workflow, then inject destinations and credentials from secrets.
