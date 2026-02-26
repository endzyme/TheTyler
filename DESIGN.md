# The Tyler — System Design Document

## Overview

This system provides a lightweight, self-hostable IP allowlist manager. It allows trusted users to authorize their IP address via a magic link email flow, and automatically propagates that allowlist to one or more protected servers via a persistent gRPC connection. The protected server uses nftables to enforce the allowlist at the kernel level, making unauthorized ports invisible to port scanners.

The system is intentionally minimal. It is not highly available, not horizontally scalable, and not designed for large teams. It is designed to be easy to run at home or on a cheap VPS with minimal operational overhead.

---

## Architecture

```
User (browser)
    │
    ▼
Web App (auth-e.domainx.com)        ← free/cheap hosted Go service
    │  - Magic link email flow
    │  - IP record storage (SQLite)
    │  - Admin panel
    │  - gRPC server (streams AllowlistSnapshot)
    │
    ▲ outbound gRPC (sync client connects out)
    │
Sync Client (protected server)      ← Go binary, systemd unit
    │  - Receives AllowlistSnapshot
    │  - Reconciles nftables set atomically
    │  - Periodic ensure() for rule integrity
    │
    ▼
nftables (kernel)
    │  - Named set: allowed_ips
    │  - Dedicated chain: allowlist_<port>
    │  - Jump rule in input chain
    │
    ▼
Protected Service (port 8920)
```

---

## Components

### Web App

A Go HTTP server with server-rendered HTML using `html/template` and HTMX for interactivity. Deployed as a single binary.

**Responsibilities:**
- Serve the email submission form
- Send magic link emails
- Serve the magic link confirmation page (shows IP, requires explicit authorization)
- Store authorized email addresses and IP records with timestamps
- Filter IP records older than 90 days from snapshots (TTL enforcement)
- Stream `AllowlistSnapshot` to connected sync clients via gRPC
- Push a fresh snapshot to all connected clients when the allowlist changes
- Serve the admin panel for managing authorized emails and IP records

**Key design decisions:**
- The web app is the single source of truth for the allowlist
- It has no knowledge of ports, services, or what the sync client does with the IP list
- Only one instance should run at a time (see Known Gaps)
- The authorized email list is managed via the admin panel, accessible only to admin emails defined at startup

### Sync Client

A Go binary managed by systemd on the protected server.

**Responsibilities:**
- Connect outbound to the web app gRPC server on startup
- Authenticate with a long random API key sent as gRPC metadata
- Receive `AllowlistSnapshot` streams and atomically update the nftables set
- Run `ensure()` on startup, every 5 minutes, and on gRPC reconnect
- Fail open on disconnect — leave existing rules in place until a fresh snapshot arrives
- Reconnect with exponential backoff on connection loss

**ensure() steps:**
1. Verify the nftables table exists
2. Verify the dedicated chain exists; create if missing
3. Verify the named set exists; create if missing
4. Verify the jump rule exists in the input chain at a valid position; create if missing, warn if position is wrong
5. Reconcile the set contents against the latest snapshot

### nftables Structure

Owned entirely by the sync client. No other process should modify these rules.

```nft
table inet filter {
  set allowed_ips {
    type ipv4_addr
    flags interval
    elements = { }
  }

  chain allowlist_8920 {
    ip saddr @allowed_ips accept
    drop
  }

  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    tcp dport 8920 jump allowlist_8920
    # ... other rules managed outside this system
  }
}
```

Set updates are atomic at the kernel level — there is no window between old and new state. The chain structure never changes after initial setup; only the set contents are updated.

---

## Auth Flows

### User IP Authorization

```
1. User visits auth-e.domainx.com
2. Submits their email address
3. App checks email against authorized email list
4. If authorized: sends magic link email
5. Response is always "check your email" (no enumeration)
6. User clicks link FROM the network they want to authorize
7. Confirmation page shows: "You are about to authorize 203.0.113.47 — Authorize / Cancel"
8. User clicks Authorize
9. IP is stored with authed_at timestamp
10. Fresh AllowlistSnapshot is pushed to all connected sync clients
11. nftables set is atomically updated
12. User sees: "203.0.113.47 has been authorized"
```

If the token is expired or already used, the page shows a clear message with a link back to the email submission form.

### Admin Access

Admin emails are defined at startup via the `ADMIN_EMAILS` environment variable. Admins authenticate via the same magic link flow. If the email that completes the magic link flow is in the admin list, the admin panel is accessible.

### Sync Client Authentication

The sync client authenticates to the web app gRPC server using a long random API key (256-bit, base64 encoded) sent as gRPC metadata on every request:

```
authorization: Bearer <key>
```

Keys are generated in the admin panel ("Add Sync Client"), stored as a bcrypt/argon2 hash server-side, and shown to the admin exactly once. The sync client is configured with the plaintext key via environment variable. Keys can be revoked from the admin panel without affecting other clients.

### Magic Link Token Security

Tokens are short-lived (15 minutes), single-use, and cryptographically signed server-side. The exact signing algorithm is an implementation decision (HMAC-SHA256 is the likely choice). Tokens are invalidated immediately upon use. The email containing the token is intentionally low-information — just a link with no context about what service is being protected, who sent it, or what it grants. All context is presented on the confirmation page after the link is clicked.

---

## Email Design

### Contextual Secrecy

The magic link email is intentionally minimal. It must not contain:
- The name or description of the service being protected
- The domain or port being unlocked
- The user's current IP address
- Any information that would be useful to an interceptor

The email contains only:
- A single magic link URL
- A brief instruction to click from the network they want to authorize
- A link to the auth site to bookmark for future use

All context is deferred to the confirmation page on the web app, which is served over TLS and only meaningful after the token is validated. An intercepted email grants at most the ability to add the interceptor's own IP to the allowlist — a limited blast radius that is mitigated further by short token expiry and single-use enforcement.

### Email Providers

The email sending layer is abstracted behind a driver interface. Configure via `EMAIL_DRIVER` environment variable.

**Recommended providers:**

| Driver | Notes |
|--------|-------|
| `smtp` | Universal fallback. Works with Proton Mail, Gmail app passwords, self-hosted Postfix, etc. |
| `resend` | Best developer experience, generous free tier, minimal setup |
| `ses` | Best for existing AWS users, very low cost, requires sandbox escape approval process |
| `sendgrid` | Solid free tier, slightly more complex setup |
| `postmark` | Strong deliverability, good free tier |

For self-hosters using Proton Mail: use the `smtp` driver with `smtp.protonmail.ch:587`. Note that this is standard SMTP submission — end-to-end encryption to recipients is not available programmatically. The contextual secrecy approach described above makes this a non-issue.

---

## TTL and Record Lifecycle

- IP records include an `authed_at` timestamp set at authorization time
- Records older than 90 days are excluded from `AllowlistSnapshot` responses
- Old records are not automatically deleted from the database (they can be cleaned up later)
- TTL is enforced entirely on the web app side; the sync client has no TTL logic
- When a record ages out, the next snapshot push to sync clients will omit that IP, and the nftables set will be updated atomically to remove it

---

## Configuration

### Web App Environment Variables

```env
# Admin
ADMIN_EMAILS=you@example.com,other@example.com

# Auth
MAGIC_LINK_SECRET=<256-bit random base64>   # Signs magic link tokens
API_KEY_SALT=<random salt>                  # For hashing sync client API keys

# Email
EMAIL_DRIVER=smtp                           # smtp | resend | ses | sendgrid | postmark
SMTP_HOST=smtp.protonmail.ch               # SMTP driver
SMTP_PORT=587
SMTP_USER=you@proton.me
SMTP_PASS=<app password>
SMTP_FROM=you@proton.me
RESEND_API_KEY=re_...                       # Resend driver

# App
BASE_URL=https://auth-e.domainx.com
TOKEN_EXPIRY_MINUTES=15
IP_TTL_DAYS=90

# Database
DATABASE_DRIVER=sqlite                      # sqlite | turso
DATABASE_URL=./data/app.db
TURSO_URL=libsql://...                     # Turso driver
TURSO_TOKEN=...
```

### Sync Client Environment Variables

```env
GRPC_SERVER=auth-e.domainx.com:443
API_KEY=<plaintext key from admin panel>
ENSURE_INTERVAL_SECONDS=300
NFT_TABLE=inet filter
NFT_CHAIN=allowlist_8920
NFT_SET=allowed_ips
NFT_PORT=8920
```

---

## Hosting

### Web App — Managed Hosting (Recommended for most users)

The following providers support Go binaries or Docker containers and handle TLS automatically:

| Provider | Notes |
|----------|-------|
| **Railway** | Recommended. Persistent volumes for SQLite, easy env var management, deploy from GitHub |
| **Render** | Strong alternative to Railway, similar feature set |
| **Fly.io** | More ops overhead but generous free tier and persistent volumes |

All of these terminate TLS at the platform level. The web app listens on plain HTTP internally.

**Important:** Vercel, Netlify, and similar serverless platforms are not suitable. The persistent gRPC server connection is incompatible with the serverless request/response model.

### Web App — Self-Hosted

Run behind Caddy, which handles TLS automatically via Let's Encrypt:

```
auth-e.domainx.com {
    reverse_proxy localhost:8080
}
```

Caddy is the recommended reverse proxy for self-hosted deployments due to its automatic certificate management and minimal configuration. Traefik is also supported for users already running it.

Rate limiting for the email submission endpoint should be handled at the reverse proxy layer:

```
auth-e.domainx.com {
    rate_limit /submit 5r/m
    reverse_proxy localhost:8080
}
```

See the Caddy documentation for the `rate_limit` directive (requires the `caddy-ratelimit` module).

### Sync Client — Installation

The sync client is a single Go binary. Install it as a systemd unit on the protected server:

```bash
# Download or build the binary
cp sync-client /usr/local/bin/sync-client
chmod +x /usr/local/bin/sync-client

# Create environment file
cat > /etc/sync-client.env << EOF
GRPC_SERVER=auth-e.domainx.com:443
API_KEY=<your key>
NFT_PORT=8920
EOF

# Install systemd unit
cp examples/systemd/sync-client.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sync-client
```

Example systemd unit (`examples/systemd/sync-client.service`):

```ini
[Unit]
Description=IP Allowlist Sync Client
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/sync-client.env
ExecStart=/usr/local/bin/sync-client
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

**Deployment assumption:** The sync client is designed to run directly on a VM or bare metal host with access to nftables. Running inside a Docker container requires `--privileged` and host network mode, which is not recommended. See Known Gaps for the Kubernetes adaptation path.

---

## Known Gaps and Constraints

### Single Instance Only

The web app must run as a single instance. Multiple instances would each maintain their own set of connected gRPC sync clients, resulting in inconsistent snapshot delivery — some sync clients would be connected to one instance, others to another, and IP additions on one instance would not be pushed to clients connected to the other.

This is an intentional tradeoff for MVP simplicity. High availability is not a design goal. If the web app goes down, sync clients fail open (existing nftables rules remain in place) until it recovers.

Mitigation: deploy on a platform with automatic restarts (systemd, Railway, Fly.io) to minimize downtime.

### Rate Limiting

The email submission endpoint is a potential spam vector — an attacker could submit arbitrary email addresses and trigger outbound emails. Rate limiting is not implemented in the application layer.

- **Self-hosted:** Handle at the Caddy or Traefik layer (see Hosting section).
- **Managed hosting:** Most managed platforms do not offer per-route rate limiting. Options are to put Cloudflare in front of the web app and use Cloudflare's rate limiting rules, or accept the risk given the low volume and low-value nature of the emails.

### nftables Rule Position

The `ensure()` function can detect if the jump rule is absent and add it, but cannot safely reorder rules it does not own. If another process inserts a broad `drop` rule above the jump rule, traffic to port 8920 will be dropped even for authorized IPs. The sync client will log a warning in this case but will not attempt to reorder rules automatically.

Mitigation: use a dedicated nftables chain for all system-managed rules and avoid broad rules in the input chain above the jump rule.

### IPv6

The current design manages IPv4 addresses only. IPv6 support is a known gap. Users on IPv6-only networks will not be able to authorize their IP.

### Shared / NAT IPs

If a user authorizes their IP from a shared network (corporate, university, CGNAT), all users behind that NAT will gain access. The confirmation page should warn users when their IP appears to be a commonly shared range, though detection is heuristic. This is a fundamental limitation of IP-based allowlisting.

### Kubernetes / Container Environments

The sync client directly manipulates the host's nftables rules, which requires running on a VM or bare metal host with appropriate privileges. It is not designed to run inside a Docker container or Kubernetes pod in its default configuration.

**Adaptation path for Kubernetes:** The gRPC sync architecture is well-suited to adaptation as a Kubernetes controller. Instead of manipulating nftables, a controller could watch the `AllowlistSnapshot` stream and reconcile `NetworkPolicy` resources in the cluster to achieve equivalent access control. This is not implemented in the base release but is a natural extension of the design given the clean separation between the web app (source of truth) and the sync client (enforcement mechanism).

---

## Monorepo Structure

```
/
├── web-app/                  # Go HTTP + gRPC server
├── sync-client/              # Go nftables sync binary
├── proto/                    # Shared protobuf definitions
├── docs/
│   ├── architecture.md
│   ├── self-hosted.md        # Caddy + SQLite setup guide
│   ├── railway.md            # Railway deployment guide
│   └── fly.md                # Fly.io deployment guide
└── examples/
    ├── docker-compose.yml    # Full local stack for development
    ├── nftables.conf         # Example nftables baseline config
    ├── Caddyfile             # Example Caddy config with rate limiting
    └── systemd/
        └── sync-client.service
```

---

## Security Properties

| Property | Mechanism |
|----------|-----------|
| Port invisible to scanners | nftables DROP (not REJECT) for unauthorized IPs — no SYN-ACK sent |
| Magic link confidentiality | Short expiry (15m), single use, low-information email body |
| Sync client authentication | Long random API key, bcrypt-hashed server-side, TLS transport |
| Admin access | Magic link to admin email only; admin emails defined at startup, not in DB |
| Atomic rule updates | nftables named set replace — no window between old and new state |
| Fail open on disconnect | Existing rules preserved if gRPC connection is lost |
| Defense in depth | nftables DROP is primary; proxy-layer allowlist recommended as secondary |
| No inbound attack surface for sync | Sync client connects outbound only; no listening port required on protected server |
