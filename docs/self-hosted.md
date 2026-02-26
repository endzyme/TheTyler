# Self-Hosted Deployment

> TODO: step-by-step guide for running the web app behind Caddy with SQLite on a VPS or home server.

## Prerequisites

- A Linux server with a public IP
- A domain name pointing at the server
- Caddy installed (with the `caddy-ratelimit` module)
- nftables on the protected server

## Quick start

_Coming soon._

---

## Sync client setup (protected server)

### 1. Install the binary

```bash
# Build from source (requires Go 1.24+)
go install github.com/endzyme/the-tyler/nftables-sync-client/cmd/nftables-sync-client@latest

# Or copy a pre-built binary to:
cp nftables-sync-client /usr/local/bin/nftables-sync-client
chmod 755 /usr/local/bin/nftables-sync-client
```

### 2. Create a dedicated system user

The sync client does **not** need to run as root. It only needs `CAP_NET_ADMIN`
to manage nftables via netlink.

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin nftables-sync
```

### 3. Configure the environment file

```bash
# /etc/nftables-sync-client.env
GRPC_SERVER=your-web-app.example.com:443
API_KEY=<api-key-from-web-app-admin-panel>

# Optional overrides (defaults shown):
# ENSURE_INTERVAL_SECONDS=300
# NFT_TABLE=inet filter
# NFT_PORTS=8920
```

Ports can be a single port, a comma-separated list, or include ranges:

```bash
# Single port (default)
NFT_PORTS=8920

# Multiple ports
NFT_PORTS=8920,9090

# Ranges and mixed
NFT_PORTS=8092,9080-9081,8922-8925
```

The sync client creates and manages the following nftables objects automatically
using fixed names — you do not need to configure them:

| Object | Name | Description |
|--------|------|-------------|
| set | `the_tyler_allowed_ips` | IPv4 addresses from the web app |
| set | `the_tyler_ports` | TCP ports from `NFT_PORTS` |
| chain | `the_tyler_allowlist` | Accepts @the_tyler_allowed_ips; drops otherwise |
| rule | (in `input`) | `tcp dport @the_tyler_ports jump the_tyler_allowlist` |

```bash
chmod 600 /etc/nftables-sync-client.env
```

### 4. Apply the base nftables configuration

The sync client does **not** create the base table — only its own objects
inside it. Apply the example config first to create the table skeleton:

```bash
cp examples/nftables.conf /etc/nftables.conf
nft -f /etc/nftables.conf
systemctl enable --now nftables
```

### 5. Install and start the systemd service

```bash
cp examples/systemd/nftables-sync-client.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now nftables-sync-client
```

The service runs as the `nftables-sync` user with only `CAP_NET_ADMIN` granted
via systemd's `AmbientCapabilities`. This is narrower than root: the process
can modify network/firewall configuration but has no access to the filesystem,
other processes, or any other privileged operation.

### Running as root (alternative)

If you prefer simplicity, change `User=nftables-sync` to `User=root` and
remove the `AmbientCapabilities` and `CapabilityBoundingSet` lines from the
service file. The binary will work either way.

### File-capability alternative

You can also set the capability directly on the binary and run as any
unprivileged user without touching the service file:

```bash
setcap cap_net_admin+ep /usr/local/bin/nftables-sync-client
```

Note that `setcap` must be re-run every time the binary is replaced.
