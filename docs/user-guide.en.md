# LinkLake User Guide

[简体中文](user-guide.zh-CN.md)

This guide describes the commands and configuration in LinkLake v1.1. Use the complete package for your platform and verify its version, checksums, and signature. A version in the repository does not by itself mean that a public release has been published. Replace the example paths, domains, ports, and credentials with your own values.

## 1. The three applications

| Application | Where it runs | Purpose |
| --- | --- | --- |
| Server: `linklake-server` | A server or cluster providing the public entry point | Hosts the Web UI, management API, client registration, policies, and forwarding listeners |
| Client: `linklake-client` | A machine that can reach the actual target service | Registers with a Server, maintains a control connection, and forwards traffic to local or network targets |
| LinkLake Manager | An administrator's desktop | Provides a graphical interface for one or more Servers and for local Client configuration, services, and updates |

The Web UI is included with Server. Manager is optional; closing it does not replace stopping a Client that runs as a system service.

There are two separate addresses. The management address, such as `https://management.example.com:32100`, is used by browsers, Manager, and enrollment commands. The control address, such as `tunnel.example.com:32101`, goes in the Client TOML file and is used for persistent forwarding. Do not prefix the control address with `http://` or `https://`.

## 2. Choose a deployment model

| Scenario | Deployment | State to preserve |
| --- | --- | --- |
| One Server exposing internal services | Standalone SQLite | The complete Server data directory, deployment configuration, and external credentials |
| Multiple Server replicas sharing accounts and policies | PostgreSQL HA | Shared PostgreSQL, a separate persistent directory for each replica, a common certificate material key, and ingress configuration |
| One target connected to several independent cloud Servers | Client `[[servers]]` configuration, optionally with Fleet | Each Server's credentials, the stable Client machine identity, and managed configuration for each entry point |

Only one Server process may open a SQLite data directory. Do not mount the same SQLite directory into multiple replicas.

PostgreSQL stores shared administrators and sessions, clients, all eight policy types, Fleet, certificates and ACME accounts, traffic controls and accounting, alerts, audit events, metrics, and update tasks. Each replica still needs its own persistent directory for its instance identity, unacknowledged traffic accounting, and staging state. Separate replicas no longer need external replication of local business SQLite databases. `LINKLAKE_HA_REPLICATED_STATE` and the Helm `replicatedStateAcknowledged` setting remain for compatibility.

Leader takeover does not configure your public ingress. You must provide suitable load balancing or DNS, a stable control address for Clients, and exposure of business ports. Existing TCP sessions can disconnect when a replica fails; Clients and applications must reconnect.

## 3. First connection on Windows

These examples use PowerShell 7 from the extracted Server or Client package root. Prepare a working target service first, for example one listening on `127.0.0.1:8080`.

### 3.1 Start Server

```powershell
$env:LINKLAKE_BIND = '127.0.0.1:32100'
$env:LINKLAKE_CONTROL_BIND = '127.0.0.1:32101'
$env:LINKLAKE_DATA_DIR = 'C:\LinkLake\server-data'
$env:LINKLAKE_ADMIN_USERNAME = 'admin'
$env:LINKLAKE_ADMIN_PASSWORD = Read-Host 'Initial administrator password, at least 12 characters' -MaskInput
$env:LINKLAKE_ENROLLMENT_TOKEN = Read-Host 'Set a separate long random enrollment token' -MaskInput
.\bin\linklake-server.exe
```

Open `http://127.0.0.1:32100`, sign in, and change the initial password when prompted. The administrator environment settings bootstrap a new account; changing them does not reset the password of an existing database account.

This example accepts management and control connections only from the same machine. Policies create business forwarding listeners separately. Create policies only for services you intend to expose.

### 3.2 Enroll Client

Open another PowerShell terminal at the Client package root. Use the same enrollment token you assigned to Server.

```powershell
$enrollmentToken = Read-Host 'Server enrollment token' -MaskInput
.\bin\linklake-client.exe enroll `
  --server http://127.0.0.1:32100 `
  --token $enrollmentToken `
  --name windows-lab `
  --identity-file C:\LinkLake\client\agent-identity.json
```

Save the returned `client_id` and the `client_token` displayed once. Protect `agent-identity.json` and reuse that file when enrolling the same machine with another independent Server. Do not copy another machine's identity file as a substitute for registration.

### 3.3 Configure and run Client

Create `C:\LinkLake\client\client.toml`:

```toml
config_version = 2

[client]
control = "127.0.0.1:32101"
client_id = "replace-with-the-enrolled-client-UUID"
client_token = "replace-with-the-enrolled-client-token"
config_mode = "server_managed"
managed_config_path = 'C:\LinkLake\client\managed.toml'
```

```powershell
.\bin\linklake-client.exe run --config C:\LinkLake\client\client.toml
```

In the Web UI, confirm that `windows-lab` is online on the Clients page. Create a TCP policy with that Client, a name, public port `32080`, and target `127.0.0.1:8080`. Save and enable it. The target address is resolved and reached from the Client machine; here, `127.0.0.1` means the Client itself.

In `server_managed` mode, Client receives and applies policies from management. You do not need to duplicate every TCP or UDP policy in the local file. Connect to Server's port `32080` to reach the target. Before using another machine, configure TLS, listeners, and firewall access as described below.

## 4. Install a persistent deployment

If continuing from the local example, stop the foreground Server and Client before starting the corresponding system services. To retain accounts, clients, and policies, use the original Server data directory or back it up and restore it into the final directory as described in section 10. A new empty data directory does not retain previous registrations.

### 4.1 Domains, TLS, and ports

Remote management and control listeners each require their own certificate and private key configuration. Management TLS, control TLS, and business HTTPS serve separate purposes. Configuring a certificate for management does not issue certificates for business domains.

| Purpose | Setting | Typical port and requirements |
| --- | --- | --- |
| Management UI, API, and enrollment | `LINKLAKE_BIND` | TCP 32100; non-loopback listeners require management TLS |
| Client control connection | `LINKLAKE_CONTROL_BIND` | TCP 32101; non-loopback listeners require control TLS |
| HTTP routing and HTTP-01 challenges | `LINKLAKE_HTTP_BIND` | Example internal TCP 32102; HTTP-01 must be reachable on public port 80 |
| Business TLS terminated by LinkLake | `LINKLAKE_HTTPS_BIND` | Example internal TCP 32103, usually exposed on public port 443 |
| UDP/QUIC relay | `LINKLAKE_UDP_RELAY_BIND` | Example UDP 32104; also requires an advertised endpoint and server name |
| TLS SNI passthrough | `LINKLAKE_TLS_PASSTHROUGH_BIND` | Example TCP 32105; must use a different listener from business HTTPS |
| TCP, UDP, and proxy policy ports | Public port in the policy | Subject to allowed ranges, listener conflicts, host firewall, and cloud security groups |

Example Server environment:

```dotenv
LINKLAKE_BIND=0.0.0.0:32100
LINKLAKE_CONTROL_BIND=0.0.0.0:32101
LINKLAKE_DATA_DIR=/var/lib/linklake
LINKLAKE_LOG_DIR=/var/log/linklake
LINKLAKE_MANAGEMENT_CERT_PATH=/etc/linklake/management-cert.pem
LINKLAKE_MANAGEMENT_KEY_PATH=/etc/linklake/management-key.pem
LINKLAKE_CONTROL_CERT_PATH=/etc/linklake/control-cert.pem
LINKLAKE_CONTROL_KEY_PATH=/etc/linklake/control-key.pem
LINKLAKE_PUBLIC_PORT_RANGES=32000-32999
```

Inject enrollment and initial administrator credentials separately. The service account must be able to read its certificate files. Bare binaries default to loopback management and control addresses; they do not enable HTTP, HTTPS, SNI, or UDP relay automatically. Deployment templates may explicitly enable these listeners.

Example remote Client configuration:

```toml
config_version = 2

[client]
control = "tunnel.example.com:32101"
control_ca_cert = 'C:\LinkLake\client\control-ca.pem'
control_server_name = "tunnel.example.com"
client_id = "replace-with-the-enrolled-client-UUID"
client_token = "replace-with-the-client-token"
config_mode = "server_managed"
managed_config_path = 'C:\LinkLake\client\managed.toml'
```

`control_ca_cert` is the PEM file used to trust the control endpoint's certificate. `control_server_name` must match its certificate name. These settings do not configure trust for the management API. Remote enrollment requires a management HTTPS certificate that the enrollment client can verify. `enroll` currently has no `--ca-cert` option; the option on `check` does not change enrollment trust.

The default public policy port range is `32000-32999`. Set `LINKLAKE_TCP_PUBLIC_PORTS` and `LINKLAKE_UDP_PUBLIC_PORTS` for separate ranges, and `LINKLAKE_RESERVED_TCP_PORTS` and `LINKLAKE_RESERVED_UDP_PORTS` for reserved ports. Disabled policies can still reserve ports; delete the policy or change its port to release the reservation. Open only the ports actually used in your host firewall and cloud security groups.

### 4.2 Linux systemd

From the verified, extracted Linux package root:

```sh
sudo ./systemd/install-linux.sh server
sudoedit /etc/linklake/server.env
sudo systemctl start linklake-server
sudo systemctl status linklake-server
```

The installer creates the service account, directories, and systemd unit and enables startup at boot. It does not supply credentials or start Server automatically. Configure listeners, TLS, the data directory, enrollment token, and initial administrator password in `server.env` before starting it.

On the target machine, install Client:

```sh
sudo ./systemd/install-linux.sh client
sudoedit /etc/linklake/client.toml
sudo systemctl start linklake-client
sudo systemctl status linklake-client
```

Enroll first, then put the returned credentials in the configuration. Use Linux paths such as `/etc/linklake/...` in TOML. Keep the service account, identity file, and state directories stable when moving from an interactive process to a system service.

### 4.3 Windows services

From an elevated PowerShell terminal at the verified Windows package root, install a standalone SQLite Server:

```powershell
$enrollment = Read-Host 'Enrollment token' -AsSecureString
$adminPassword = Read-Host 'Initial administrator password' -AsSecureString
.\windows\install-server.ps1 `
  -EnrollmentToken $enrollment `
  -AdminUsername admin `
  -AdminPassword $adminPassword

.\windows\install-client.ps1 -ConfigPath C:\LinkLake\client\client.toml
Get-Service LinkLakeServer, LinkLakeClient
```

The default Server management and control listeners remain on loopback. For remote access, provide `-Bind`, `-ControlBind`, `-ManagementCertificate`, `-ManagementKey`, `-ControlCertificate`, and `-ControlKey` together as appropriate. Add `-HttpBind`, `-HttpsBind`, and other listeners when needed. Use `-NoStart` to install first and inspect configuration before starting.

The default program directory is `C:\Program Files\LinkLake`. Server data is stored in `C:\ProgramData\LinkLake\data`, and the Client configuration is `C:\ProgramData\LinkLake\client.toml`. Reinstalling Client preserves the existing configuration unless you explicitly pass `-ReplaceConfig`. This Server installer supports standalone SQLite only; use the cluster deployment process for PostgreSQL.

### 4.4 Docker Compose

The [Compose template](../deploy/docker-compose.yml) includes Server and an optional monitoring stack. From the repository root:

```sh
cp deploy/linklake.env.example deploy/linklake.env
# Edit deploy/linklake.env and place management/control certificates in deploy/certs/.
# Set GRAFANA_ADMIN_PASSWORD in this terminal; template expansion requires it.
docker compose -f deploy/docker-compose.yml up -d --build linklake
```

Replace the template's domains, enrollment token, passwords, and UDP relay endpoint. The hostname in `LINKLAKE_HEALTH_URL` must pass validation against the mounted management certificate. Keep only the required listeners and port mappings. Creating a policy inside the container does not change the host's `ports` mappings.

Server data and logs use named volumes; certificates are mounted read-only. Preserve the data volumes when restarting. To enable monitoring, prepare a read-only API token in `deploy/secrets/linklake_metrics_token`, check Prometheus TLS configuration and the Grafana password, and then start the remaining services. See the [deployment guide](deployment.md).

## 5. Manage through the Web UI and Manager

Keep the complete Manager package together when extracting it. On Windows, launch `linklake_manager.exe`; on other desktop platforms, use the corresponding application bundle. Add your own management URL to the Server list, then sign in with your username, password, and TOTP when required. Replace example Server addresses and use the management port.

The Web UI and Manager provide pages for clients, protocol policies, ACME, HA, Fleet, metrics, and alerts. Administrators manage accounts, sessions, and API tokens. Operators manage policies within their permissions; auditors have read-only access. Complete the initial password change, configure TOTP when needed, and review active sessions.

Client configuration has three modes:

| Mode | Daily workflow |
| --- | --- |
| `server_managed` | Edit policies in the Web UI or Manager; Client receives and applies them. Do not edit the generated `managed.toml` manually. |
| `report_only` | Run local TOML configuration and report differences to management, useful during migration. |
| `local` | Run local TOML configuration without accepting management overrides. |

After changes, check Client connectivity, configuration revision, and synchronization results. Saving a policy does not confirm that Client is online or can reach the target. See the [single-entry example](../examples/linklake-client.toml) and [multiple-entry example](../examples/linklake-client-multi-server.toml).

## 6. Choose a forwarding type

Create a policy on the relevant protocol page, select the Client that can reach the target, provide the target and limits, then save and enable it.

| Type | Typical use | Key configuration |
| --- | --- | --- |
| TCP | SSH, RDP, databases, TCP game services | Public port, target `host:port`, maximum connections |
| UDP | UDP games, voice, other UDP applications | Public UDP port, target, session limit, idle timeout; Server must enable UDP relay |
| Port group | Multiple matching ports or ranges | TCP/UDP, equal-length public and target port expressions, target host; pairs follow expansion order, with up to 256 per group |
| HTTP/HTTPS | Websites, WebSocket, HTTP/2, gRPC | Route hostname and target; HTTPS also needs the route's TLS settings |
| TLS SNI | TLS terminated by the internal target | SNI hostname, target, and a separate SNI listener; the target owns its certificate |
| Secret | Private access without a public business port | Target Client, target address, permitted visitor Client, and an access key displayed once |
| SOCKS5 | Outbound access through a Client's network | Public proxy port, username, password displayed once, connection and egress limits |
| HTTP Proxy | HTTP forward proxy and CONNECT | Public proxy port, username, password displayed once, egress restrictions |

SOCKS5 reserves both TCP and UDP ports. Account for both protocols when planning ports. The option to allow private networks controls access to internal egress targets. Enable it only when required, and retain authentication for public proxies. See [SOCKS5 supported boundaries](socks5-supported-boundaries.md).

HTTP/HTTPS domains must resolve to Server. A proxy in front of LinkLake should retain the original Host. The gRPC backend transport defaults to `h2c`; for a TLS backend, configure `grpc_backend_transport="tls"`, a matching `grpc_backend_server_name`, and a `grpc_backend_trust_profile` when needed. See [HTTP/2 and gRPC](http2-grpc.md).

### Secret visitor example

Create the target Secret policy in management and save its `access_key` when displayed. Enroll the visitor Client too. Append the following to the visitor's own TOML; `server_managed` does not distribute visitor entries:

```toml
[[secret_visitors]]
name = "private-service-access"
local_bind = "127.0.0.1:13389"
access_key = "replace-with-the-lls_access-key-displayed-once"
path_policy = "relay_only"
```

Connect to `127.0.0.1:13389` on the visitor machine to reach the target. Applications such as RDP and SSH still enforce their own authentication. `relay_only` always uses the relay. With P2P configured, `prefer_direct` tries a direct path and falls back to relay; `direct_only` fails when a direct path is unavailable. In a multiple-entry configuration, also set `server = "matching-entry-name"` on the visitor.

### Traffic and access limits

Use policy traffic controls to configure quotas, connection rates, source CIDRs, and schedules. Schedules use UTC. Quotas govern subsequent forwarding authorization; they do not promise that every existing long-lived connection will stop at an exact byte boundary.

A PostgreSQL cluster shares controls and usage accounting. Drain Client and Server normally before stopping them. An accounting spool failure can cause new forwarding to be rejected; restore the persistent disk or database connection instead of deleting unacknowledged traffic files. If a host and its unuploaded local data are permanently lost, those accounting records are not guaranteed to survive.

## 7. Business HTTPS and ACME

1. Enable `LINKLAKE_HTTP_BIND` and `LINKLAKE_HTTPS_BIND` and use a persistent data directory.
2. Open ACME settings, start with the staging environment, provide a contact email, accept the terms, and select a challenge type and renewal window.
3. Open the HTTP route's TLS settings, enable ACME, and configure an optional HTTP-to-HTTPS redirect and certificate identifier.
4. Request issuance and inspect the certificate status or failure reason. Once the domain and challenge path work, switch to the intended environment and issue the production certificate.

HTTP-01 requires public port 80 to reach the HTTP listener with the original Host. Business port 443 should forward the TLS connection to LinkLake's HTTPS listener so LinkLake selects the certificate. With SNI passthrough, the target owns the certificate. HTTPS termination and SNI passthrough cannot share the same IP and port.

Use Cloudflare DNS-01 for wildcard certificates or when public port 80 is unavailable. Configure a restricted token through `LINKLAKE_CLOUDFLARE_API_TOKEN_FILE` or `LINKLAKE_CLOUDFLARE_API_TOKEN`, never both. Restrict the file to the service account and scope the token to the necessary Zone read and DNS edit permissions. The ACME page shows whether credentials are ready without accepting or returning the token itself.

`certificate_identifier` can be the route hostname or a wildcard covering one subdomain level, such as `*.example.com`. Wildcards require DNS-01. To change an existing wildcard policy to an exact certificate, explicitly provide the route hostname.

In PostgreSQL mode, all replicas need the same `LINKLAKE_CERTIFICATE_KEY_FILE` to protect certificate private keys and ACME accounts. The file must contain 32 raw bytes, not hexadecimal or base64 text. Use owner-only permissions such as `0600` on Unix. Back up this key separately from the database. Replacing its file or Kubernetes Secret does not re-encrypt existing materials; follow the rotation procedure in section 10.

## 8. PostgreSQL HA and Kubernetes

### 8.1 Prepare the deployment

Prepare a dedicated PostgreSQL database, a trusted TLS connection, protected connection credentials, a separate persistent directory for every replica, and consistent listener, port, and external credential configuration. Database TLS verification is required by default. `LINKLAKE_POSTGRES_ALLOW_INSECURE_LOOPBACK` is for loopback testing, not a production connection policy.

At minimum, each replica needs:

```dotenv
LINKLAKE_STORAGE_BACKEND=postgres
LINKLAKE_POSTGRES_URL=postgresql://linklake:replace-password@postgres.example.com/linklake
LINKLAKE_DATA_DIR=/var/lib/linklake
LINKLAKE_HA_INSTANCE_ID=linklake-a
LINKLAKE_CERTIFICATE_KEY_FILE=/etc/linklake/cluster-certificate.key
```

Use a different `LINKLAKE_HA_INSTANCE_ID` and persistent directory for the next replica, with the same database and certificate material key. Do not clone one data volume into two simultaneously active instance identities. Database connection failure does not cause automatic fallback to local SQLite.

For a new database, run `linklake-server initialize-postgres` in a maintenance process to initialize an empty LinkLake schema without starting Server. For an existing SQLite deployment, use the migration procedure in section 10.

### 8.2 Essential Helm configuration

The Chart does not bundle PostgreSQL or plaintext credentials. Prepare these Secrets in the deployment namespace:

| Example Secret | Required data keys |
| --- | --- |
| `linklake-auth` | `enrollment-token`, `admin-username`, `admin-password`; optionally `management-token` |
| `linklake-management-tls` | Standard TLS Secret: `tls.crt`, `tls.key` |
| `linklake-control-tls` | Standard TLS Secret: `tls.crt`, `tls.key` |
| `linklake-postgres` | `postgres-url` |
| `linklake-certificate-material` | `certificate-key`, decoding to 32 raw bytes |

Save these non-secret settings as `values.local.yaml` and replace the image and external addresses:

```yaml
replicaCount: 3
image:
  repository: replace-with-your-image-repository
  tag: replace-with-a-confirmed-image-tag
auth:
  existingSecret: linklake-auth
tls:
  managementSecret: linklake-management-tls
  controlSecret: linklake-control-tls
storage:
  backend: postgres
  postgres:
    existingSecret: linklake-postgres
ha:
  enabled: true
certificateMaterial:
  existingSecret: linklake-certificate-material
server:
  udpRelay:
    advertisedEndpoint: relay.example.com:32104
    serverName: relay.example.com
services:
  data:
    publicTcpPorts: [32080]
    publicUdpPorts: []
```

```sh
helm upgrade --install linklake deploy/helm/linklake \
  --namespace linklake --create-namespace \
  --values values.local.yaml
```

HA uses a StatefulSet and a separate PVC for each Pod. The default SQLite deployment uses one Deployment replica. Match enabled listeners to certificates, domains, and Service exposure. Disable unused HTTP, HTTPS, SNI, or UDP relay listeners in values. Kubernetes Services do not accept port ranges; list every business port in `publicTcpPorts` or `publicUdpPorts`.

### 8.3 Configure ingress for takeover

`/livez` checks liveness. `/readyz` checks lifecycle readiness. `/leaderz` requires both readiness and leadership. Configure the front load balancer to use `/leaderz` when selecting replicas for control connections and writes. `/readyz` or a generic Service that distributes traffic across all replicas does not ensure routing to Leader.

Read access on a Follower does not imply permission to mutate policies or accept new forwarding control connections. If a request reports that the instance is not Leader, inspect ingress and the HA page before retrying. Shared policies do not configure cloud load balancers or discover and replace control addresses in Client TOML files.

Preserve instance volumes with unacknowledged traffic accounting when scaling down. Drain and confirm the data before applying your retention policy. Retaining PVCs is not an offsite backup. See the [Chart values](../deploy/helm/linklake/values.yaml) and [PostgreSQL upgrades and recovery](postgres-upgrades.md).

## 9. Multiple entry points and Fleet

A multi-entry Client uses several `[[servers]]` sections, each with its own control address, CA, Client ID, and token. Enroll separately with independent Servers while reusing the stable machine identity. This differs from multiple replicas of one PostgreSQL cluster, which share registration data.

Fleet manages independent Servers, health, policy synchronization, and optional DNS failover. The normal workflow is:

1. Enroll Clients on the target Servers and ensure stable identities and public keys match.
2. On each receiving Server, create a suitably scoped API token bound to the originating `source_instance_id`. Add the target node on the source Server's multi-cloud/Fleet page.
3. Preview synchronization. Resolve missing Clients, port conflicts, and credential bindings before applying it.
4. Inspect generation, progress, and conflicts in the Fleet ledger, then check target policies and Client connectivity.

Fleet v2 covers all eight policy types and their traffic controls, tracking ownership by source and resource ID. Secret, SOCKS5, and HTTP Proxy transfer credential references; prepare and bind credentials locally at the destination. Bundles do not include passwords, access keys, Client tokens, or certificate private keys. Interactive login and generic management tokens do not replace the source-bound token required by v2 reconcile.

Ordinary CRUD cannot freely change policies owned by Fleet on the receiving Server. Change and synchronize from the source, or release ownership through the management workflow. Older nodes support a different compatibility scope; inspect the preview and protocol capabilities before applying changes.

Automation can export through `POST /api/v1/fleet/v2/bundle`, preview or apply through `POST /api/v1/fleet/v2/reconcile`, and inspect or manage source state, generations, conflicts, and credential references through `/api/v1/fleet/v2/sources`, `/api/v1/fleet/v2/generations`, `/api/v1/fleet/v2/conflicts`, and `/api/v1/fleet/v2/credentials`. See [Fleet Bundle v2](adr/0003-fleet-bundle-v2.md).

DNS failover requires explicit Cloudflare Zone, record, node, target value, health threshold, and cooldown configuration. DNS TTL, caches, and existing connections affect recovery time. Freeze automatic changes to inspect the plan and events before resuming execution. See [Fleet health and DNS failover](adr/0004-fleet-health-dns-failover.md).

## 10. Backups, migration, key rotation, and upgrades

Maintenance commands do not automatically read a systemd `server.env` file or Kubernetes Secret. Inject the correct deployment environment and credentials into the maintenance process and confirm its data directory and database. Schedule the required service stops in your maintenance window.

### SQLite backup and restore

Use `backup` for the database alone or encrypted `backup-full` to include managed certificates and ACME state:

```sh
linklake-server backup-full \
  --data-dir /var/lib/linklake \
  --output /srv/linklake-backups/linklake-full.llb \
  --password-file /secure/linklake-backup.pass
```

Keep the output and password file outside the data directory. An online backup does not guarantee that SQLite, certificates, and ACME accounts reflect exactly the same point in time. Stop Server first if you require that consistency. Back up environment configuration, external TLS files, material keys, service definitions, DNS, and load balancer configuration separately.

Stop Server before restoring and prepare the target directory with the correct service account ownership and access permissions:

```sh
linklake-server restore-full \
  --data-dir /var/lib/linklake \
  --input /srv/linklake-backups/linklake-full.llb \
  --password-file /secure/linklake-backup.pass
```

Check login, Client reconnection, target services, and certificates before restoring business ingress. See the [deployment guide](deployment.md) for backup scope and permission requirements.

### Migrate SQLite to PostgreSQL

Take a full backup, drain and stop the SQLite Server and all target PostgreSQL replicas, and suspend automatic restart or scaling. Prepare an empty target database and common material key. Preserve original port policy, listeners, and any historical custom ACME account directory configuration.

In a maintenance process configured for the target PostgreSQL environment:

```sh
linklake-server initialize-postgres
linklake-server migrate-sqlite-to-postgres \
  --data-dir /var/lib/linklake \
  --certificate-key-file /secure/cluster-certificate.key \
  --all-instances-stopped --preview
linklake-server migrate-sqlite-to-postgres \
  --data-dir /var/lib/linklake \
  --certificate-key-file /secure/cluster-certificate.key \
  --all-instances-stopped
```

Proceed without `--preview` only after a successful preview. Repeat `--account-directory URL` for custom historical ACME directories. The snapshot limit defaults to 512 MiB and can be changed with `--max-snapshot-mib`. Unknown nonempty tables and unfinished external operations can block migration; resolve them in the original service first.

Retain the source directory after migration. Check accounts, Clients, policies, certificates, and accounting before starting PostgreSQL replicas and switching ingress. Do not operate both deployments as independent writable control planes. If the commit response is lost, keep instances stopped and inspect the migration receipt; do not clear the target database and restart the process blindly.

Rollback eligibility requires the source and target to retain their migration-time state:

```sh
linklake-server verify-sqlite-rollback \
  --data-dir /var/lib/linklake \
  --certificate-key-file /secure/cluster-certificate.key \
  --all-instances-stopped
```

This command does not switch configuration, delete PostgreSQL, or merge new PostgreSQL data back into SQLite. Do not switch to the old snapshot after the target has accepted new data. See [storage migration](storage-migration.md).

### Rotate the PostgreSQL certificate material key

Back up PostgreSQL, the old key, and deployment configuration. Prepare a separate new 32-byte key. Drain and stop all replicas, suspend automatic restart, and let valid leases expire before running:

```sh
linklake-server rotate-certificate-key \
  --previous-key-file /secure/old-key \
  --next-key-file /secure/new-key \
  --all-instances-stopped
```

After confirmed transaction success, configure every replica to use the new key. With Helm, update the controlled Secret and recreate Pods so the material file is copied again. If the response is interrupted, inspect the database key fingerprint read-only before selecting the old or new configuration or retrying. See [certificate key maintenance](certificate-key-maintenance.md).

### Updates and cluster recovery

Inspect installed identities and update candidates:

```sh
linklake-server --version-json
linklake-client --version-json
linklake-client check-update --channel stable
```

A standalone Client installed as a system service supports `update download`, `update apply --yes`, and `update status`. The Web UI and Manager also expose update operations. For a standalone SQLite Server:

```sh
linklake-server update download
linklake-server update apply --yes --data-dir /var/lib/linklake
linklake-server update status
```

These operations require service control permissions and appropriately signed packages. Start Manager self-updates through its interface; a helper coordinates exit and replacement. Keep the complete application package together. See [secure updates](update-security.zh-CN.md) for interruption recovery, rollback, and schema-related data recovery confirmations.

PostgreSQL backup, recovery, and upgrades use PostgreSQL backup/PITR tools and the cluster deployment process. One replica's `linklake.sqlite3` is not a cluster backup; standalone `backup`, `restore`, and the Server updater are not PostgreSQL upgrade tools. Preserve each instance's accounting volume, the common material key, external credentials, and deployment configuration. Retain `postgres-storage.marker`; do not delete it to bypass protection.

A candidate Server may modify the database during startup. Downgrading the image or using `helm rollback` does not undo those changes. Confirm schema compatibility first. When required, stop all writes in a maintenance window and restore matching data, keys, and binaries. See [PostgreSQL cluster upgrades and recovery](postgres-upgrades.md) and [release signing and supply chain](release-supply-chain.zh-CN.md).

## 11. Daily operation and troubleshooting

Start with Client connectivity and synchronization, target reachability, protocol connections and traffic, HA leadership, alerts, and audit events. Prometheus metrics are available at `/api/v1/metrics/prometheus` using a `read`-scope API Bearer token. An enrollment token does not substitute for a management API token.

```sh
linklake-client check --server https://management.example.com:32100
linklake-client diagnose --config /etc/linklake/client.toml
linklake-client logs --lines 100
linklake-client service status
```

For a private management CA, pass `check --ca-cert /path/to/management-ca.pem`. Server logs use `LINKLAKE_LOG_DIR`, or the `logs` subdirectory of the data directory when that setting is absent. With systemd, also inspect `journalctl -u linklake-server` or `journalctl -u linklake-client`.

| Symptom | Check first |
| --- | --- |
| Browser or Manager cannot connect | Management address, DNS, TLS hostname, port mappings, firewall |
| Enrollment is unauthorized | Enrollment token; ensure it was not confused with a Client or management token |
| Client offline or configuration not applied | Persistent Client process, control address, CA/server name, `server_managed` mode |
| Saved policy is unreachable | Target reachability from Client, enabled state, allowed/exposed port, quota, source and schedule rules |
| Port rejected or occupied | Allowed range, reserved or built-in listeners, another enabled or disabled policy, SOCKS5 UDP reservation |
| UDP fails while TCP works | UDP relay enabled, advertised endpoint reachable, server name matching the control certificate, both relay and business UDP ports exposed |
| HTTPS issuance fails | ACME environment, domain, port 80/443 routing, DNS-01 token/propagation, certificate material key |
| HA writes or control connections rejected | Current Leader, `/leaderz` routing, drain state |
| PostgreSQL startup or decryption fails | Backend and URL, database TLS trust, persistent instance directory, matching 32-byte material key on all replicas |
| Fleet ownership or credential conflict | Source-bound token, stable Client identity, destination credential binding, ports and generation; preview again |

Before a planned stop, call `POST /api/v1/lifecycle/drain`, poll `GET /api/v1/lifecycle`, and stop the service after `drained=true`. Allow sufficient shutdown time to persist accounting. After restart, check readiness, leadership, and the actual business ingress. See [SLOs and observability](slo-observability.md).
