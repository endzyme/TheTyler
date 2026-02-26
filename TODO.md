# TODO

## IPv6 Support

- The current IP allowlist stores and compares addresses as plain strings. IPv6 addresses have multiple valid textual representations (e.g. `::1` vs `0:0:0:0:0:0:0:1`, compressed vs full). All addresses should be normalised with `net.IP.String()` (or `netip.Addr.String()`) before storage and comparison so that equivalent addresses are treated as equal.
- The nftables sync client writes an nftables set. Confirm the set type supports both `ipv4_addr` and `ipv6_addr` (or use `inet` family with separate sets).
- Review `extractIP()` in `web-app/internal/handler/submit.go` — `net.ParseIP` already handles IPv6 literals, but the `X-Forwarded-For` parsing should be tested against bracketed IPv6 (`[::1]`) and zone-ID formats.
- Test magic-link flows end-to-end from an IPv6-only client.

## Kubernetes NetworkPolicy Sync Client

A client that watches the Tyler gRPC stream and reconciles a Kubernetes `NetworkPolicy` (or `CiliumNetworkPolicy`) so that only allowlisted IPs can reach protected workloads without running nftables on every node.

- Subscribe to `AllowlistService.Subscribe` and receive `AllowlistSnapshot` updates.
- On each snapshot, reconcile a `NetworkPolicy` in a target namespace:
  - Build an `ipBlock` ingress rule from the current IP list.
  - Use `kubectl apply --server-side` (SSA) to avoid last-write-wins conflicts.
- Support `CiliumNetworkPolicy` as an alternative backend for clusters running Cilium.
- Package as a small Go binary with a `Dockerfile` and a Helm chart (or plain Kustomize manifests).
- Config via env vars: `TYLER_GRPC_ADDR`, `TYLER_API_KEY`, `TARGET_NAMESPACE`, `TARGET_POLICY_NAME`, `KUBECONFIG` (optional, falls back to in-cluster config).
- See `nftables-sync-client/` for reference on gRPC subscription and reconnect logic.

## Installation & Operations Examples

### Systemd Units

Currently only `examples/systemd/nftables-sync-client.service` exists. Add:

- `examples/systemd/thetyler.service` — unit for the web-app binary itself, with:
  - `DynamicUser=yes` / `ProtectSystem=strict` / `PrivateTmp=yes` hardening directives
  - `EnvironmentFile=/etc/thetyler/env` for secrets
  - `StateDirectory=thetyler` so the SQLite database lands in `/var/lib/thetyler/`
  - Restart-on-failure policy (`Restart=on-failure`, `RestartSec=5`)
- `examples/systemd/thetyler-caddy.service` (or document using the stock `caddy.service`) — note on ordering with `After=caddy.service` if Caddy provides TLS termination.

### Caddy Reverse Proxy

`examples/Caddyfile` exists but should be expanded / documented:

- Show a complete production example with automatic HTTPS (`tls` directive).
- Document the `trusted_proxies` setting so `X-Forwarded-For` is only accepted from Caddy (`TRUST_PROXY=true` in the web-app env).
- Add a `handle /grpc` block (or a separate site block on port 9090) if gRPC is exposed externally — note that Caddy handles `h2c` natively.
- Add a snippet for rate-limiting at the Caddy layer as a second line of defence.

### Full Self-Hosted Walkthrough

`docs/self-hosted.md` exists but should cover:

1. System user and directory setup (`useradd`, `/etc/thetyler/`, `/var/lib/thetyler/`).
2. Installing the binary from a GitHub release (`curl` + `tar` + `install`).
3. Writing `/etc/thetyler/env` (environment file with correct `chmod 600`).
4. Enabling and starting the systemd units (`systemctl enable --now`).
5. Caddy config and `systemctl reload caddy`.
6. Enabling the nftables sync client unit and verifying the nftables set populates.
7. Log inspection (`journalctl -u thetyler -f`).
8. Upgrade procedure (replace binary, `systemctl restart thetyler`).

### Additional Examples

- `examples/docker-compose.yml` — already present; add a Caddy service to the compose file so a single `docker compose up` gives a fully TLS-terminated stack for local testing.
- `examples/kubernetes/` — basic manifests: `Deployment`, `Service`, `Secret` (for env vars), and a `NetworkPolicy` that the sync client will manage.
