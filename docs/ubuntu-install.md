# Ubuntu Installation Guide

This guide covers self-hosting The Tyler on a single Ubuntu server running both the web app and the nftables sync client.

## Overview

The web app serves the auth flow and gRPC API. The sync client runs on the same host and connects to gRPC over loopback — no external gRPC exposure is needed in this topology. Caddy sits in front of the web app and handles TLS automatically.

## Prerequisites

- Ubuntu 24.04 or later
- A domain name with DNS pointed at the server
- Ports 80 and 443 open in any upstream firewall (required for Caddy ACME challenge and renewal)

---

## 1. Create directories and users

```bash
mkdir -p /opt/thetyler/bin /opt/thetyler/data

# Dedicated unprivileged user for the sync client (needs CAP_NET_ADMIN only)
useradd --system --no-create-home --shell /usr/sbin/nologin thetyler-nftables

chown www-data:www-data /opt/thetyler/data
```

---

## 2. Download and install binaries

Download the latest release archive from GitHub:

```
the-tyler_<version>_linux_amd64.tar.gz
```

The archive contains two binaries: `thetyler` and `nftables-sync-client`. Copy both to `/opt/thetyler/bin/`:

```bash
tar -xzf the-tyler_<version>_linux_amd64.tar.gz
cp thetyler nftables-sync-client /opt/thetyler/bin/
chmod +x /opt/thetyler/bin/thetyler /opt/thetyler/bin/nftables-sync-client
```

---

## 3. Configure the web app

Create `/opt/thetyler/web-app.env`:

```bash
touch /opt/thetyler/thetyler.env
chmod 600 /opt/thetyler/thetyler.env
chown www-data:www-data /opt/thetyler/thetyler.env
```

Edit the file with the following variables:

```ini
# Required
ADMIN_EMAILS=you@example.com
MAGIC_LINK_SECRET=<base64-encoded 32+ bytes — generate: openssl rand -base64 32>
API_KEY_SALT=<random string — generate: openssl rand -base64 16>
BASE_URL=https://your.domain.com
TRUST_PROXY=true

# Email driver: "smtp" or "resend"
EMAIL_DRIVER=smtp

# --- If EMAIL_DRIVER=smtp ---
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@gmail.com
SMTP_PASS=<app password>
SMTP_FROM=you@gmail.com

# --- If EMAIL_DRIVER=resend ---
# RESEND_API_KEY=re_...
# RESEND_FROM=noreply@your.domain.com

# Optional (defaults shown)
# TOKEN_EXPIRY_MINUTES=15
# IP_TTL_DAYS=90
# DATABASE_URL=/opt/thetyler/data/app.db
# HTTP_PORT=8080
# GRPC_PORT=9090
```

`TRUST_PROXY=true` is required when Caddy (or any reverse proxy) sits in front of the app.

---

## 4. Configure the sync client

Create `/opt/thetyler/nftables-sync-client.env`:

```bash
touch /opt/thetyler/nftables-sync-client.env
chmod 600 /opt/thetyler/nftables-sync-client.env
chown thetyler-nftables:thetyler-nftables /opt/thetyler/nftables-sync-client.env
```

Edit the file:

```ini
# Required
GRPC_SERVER=localhost:9090

# Generate an API key from the admin panel after first start, then set it here
API_KEY=<key from admin panel>

# Same-host TLS shortcut — see warning below
DEV_ALLOW_INSECURE_GRPC=true

# Optional (defaults shown)
# ENSURE_INTERVAL_SECONDS=300
# NFT_TABLE=inet filter
# NFT_PORTS=8920
# ALWAYS_ALLOW_IPS=10.0.0.0/8,192.168.0.0/16
```

> **Warning — `DEV_ALLOW_INSECURE_GRPC`**: This skips TLS verification on the gRPC connection. It is acceptable when the sync client and web app are on the same host and gRPC traffic never leaves loopback. Do **not** use this flag if the gRPC port is exposed across a network boundary.

`NFT_PORTS` supports comma-separated ports and ranges (e.g. `8920,9080-9081`). `ALWAYS_ALLOW_IPS` accepts IPs and CIDRs that always bypass the allowlist.

---

## 5. Install and configure nftables

```bash
apt install nftables
systemctl enable nftables
```

> **Warning — read before enabling**: Review `/etc/nftables.conf` carefully before starting the service. A default-drop input policy with a missing SSH rule will lock you out immediately. Make sure you have console or out-of-band access before applying the ruleset.

The following is a generalized example based on a working setup. **YMMV — integrate with your existing rules carefully.**

`/etc/nftables.conf`:

```nft
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Loopback
        iifname "lo" accept

        # Established and related
        ct state established,related accept

        # Invalid
        ct state invalid drop

        # SSH — restricted to RFC-1918 ranges
        ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } tcp dport 22 accept

        # HTTP (required for Caddy ACME renewal)
        tcp dport 80 accept

        # HTTPS
        tcp dport 443 accept
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
```

The sync client creates and manages the `thetyler_allowlist` chain and the associated named set (`allowed_ips`) in the `inet filter` table. Do not define them manually — the sync client will own that state.

---

## 6. Install Caddy

Follow the [Debian/Ubuntu install instructions](https://caddyserver.com/docs/install#debian-ubuntu-raspbian) from the Caddy docs to add the official apt repository and install the package.

---

## 7. Configure Caddy

Edit `/etc/caddy/Caddyfile`:

```caddyfile
your.domain.com {
    reverse_proxy localhost:8080
}
```

Caddy handles TLS certificate issuance and renewal automatically via ACME. No additional configuration is needed.

**Note on gRPC**: proxying gRPC through Caddy on the same 443 port and hostname (using `transport http { versions h2c }`) is theoretically possible but is not a tested pattern with The Tyler. The sync client connects directly to the gRPC port (default 9090), so Caddy does not need to proxy it.

---

## 8. Create systemd service files

The `caddy.service` unit is installed and enabled automatically by the apt package — nothing to do there.

Create `/etc/systemd/system/thetyler.service`:

```ini
[Unit]
Description=thetyler Go App
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/thetyler
EnvironmentFile=/opt/thetyler/thetyler.env
ExecStart=/opt/thetyler/bin/thetyler
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/thetyler-nftables.service`:

```ini
[Unit]
Description=TheTyler NFTables Sync Client
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/opt/thetyler/nftables-sync-client.env
ExecStart=/opt/thetyler/bin/nftables-sync-client
Restart=always
RestartSec=5

# Run as a dedicated unprivileged user. CAP_NET_ADMIN is the only Linux
# capability required to manage nftables via netlink. CapabilityBoundingSet
# prevents the process from ever acquiring any other capability.
User=thetyler-nftables
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

`AmbientCapabilities=CAP_NET_ADMIN` gives the sync client the privilege it needs to modify nftables without running as root. The nftables unit waits for `network-online.target` and `nftables.service` so the ruleset is loaded before the sync client starts.

---

## 9. Enable and start

```bash
systemctl daemon-reload

# Start the web app and Caddy first
systemctl enable --now thetyler caddy
```

Visit `https://your.domain.com` and log in to the admin panel. Generate an API key, then add it to `/opt/thetyler/nftables-sync-client.env`:

```ini
API_KEY=<key from admin panel>
```

Then start the sync client:

```bash
systemctl enable --now thetyler-nftables
```

---

## 10. Verify

```bash
# Check service status
systemctl status thetyler thetyler-nftables caddy

# Confirm the nftables rules after the sync client starts
nft list ruleset

# Confirm the web app is accessible
curl -I https://your.domain.com
```

Visit `https://your.domain.com` in a browser — the auth form should load.

---

## Appendix: Home network / port forwarding setup

If your server is behind a home router using port forwarding, make sure your router preserves the client's original public IP when forwarding traffic — not the router's LAN IP. The Tyler uses the source IP from incoming requests to authorize access, so if every request arrives as `192.168.x.x`, the allowlist won't work correctly.

To verify your router is passing through the real public IP, run a packet capture on your server while hitting your domain from an external network (e.g. a mobile connection with WiFi off):

```bash
tcpdump -i eth0 -n port 80 or port 443
```

You should see the public source IP of the external client in the output. If you only see your router's LAN IP, check your router's port forwarding settings — some routers support a "hairpin NAT" or "DMZ" mode that preserves the original source IP.

---

## Appendix: Running certbot on the same host as Caddy

If you already run certbot on the same host, Caddy and certbot will conflict over port 80 during HTTP-01 challenges. To work around this, add a global block to `/etc/caddy/Caddyfile` that disables automatic HTTP-to-HTTPS redirects, then provide certificate paths manually:

```caddyfile
{
    auto_https disable_redirects
}

your.domain.com {
    tls /path/to/cert.pem /path/to/key.pem
    reverse_proxy localhost:8080
}
```

This is an edge case. Most users should let Caddy manage TLS automatically.
