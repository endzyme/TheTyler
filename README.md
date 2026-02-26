<img src="logo.svg" alt="The Tyler" width="120">

# The Tyler

> In Freemasonry, the Tyler (or Tiler) is the outer guard of the lodge — the one who stands at the door and decides who may enter.

The Tyler is a lightweight, self-hostable IP allowlist manager. It lets you share access to a self-hosted service — a media server, photo album, SSH port, self-hosted web app — without requiring users to install a VPN client or giving them access to anything beyond that one port.

Users authorize their IP address via a magic link email flow. That allowlist is automatically propagated to one or more **sync agents** running on your protected servers, which enforce it at the firewall level. Unauthorized IPs never receive a response — the port is invisible to scanners.

## Why Not a VPN?

VPNs (Tailscale, WireGuard, etc.) are great tools, but they require the user to install a client, join your network, and gain access to your entire network topology. Sometimes you just want to say: *"this person can reach port 443 on this one host."*

Maybe you're hosting a self-hosted site for friends and family — a media server, photo album, or home dashboard — and you want them to reach it from a browser or an app on a device that doesn't support a VPN client easily. Maybe they're not technical enough to set up WireGuard but can handle an email and a couple of clicks. The Tyler handles the access grant for you, hands-off: they enter their email, click a link, and they're in. And once their home IP is authorized, every device on their network gets access too — their TV app, their tablet, other phones on the same WiFi — without anyone doing anything extra.

The Tyler is for that use case — lightweight access grants without client software, without enrolling users in your network, and without ongoing key management.

## How It Works

```
User (browser)
    │
    │  1. submits email
    │  2. receives magic link
    │  3. clicks link from the network they want to authorize
    │  4. confirms IP authorization
    ▼
Web App  ─────────────────────────────────────────────────────
    │  · magic link email flow (Gmail SMTP, Resend, or others)
    │  · IP record storage with 90-day TTL (SQLite)
    │  · admin panel for managing emails and IP records
    │  · gRPC server that streams AllowlistSnapshot
    │
    ▲  outbound gRPC  (agents call in from your protected network)
    │
Sync Agent (on your protected server)
    │  · receives AllowlistSnapshot updates
    │  · reconciles firewall rules atomically
    │
    ▼
Firewall / Network Policy
```

The web app can be hosted anywhere with a public URL (Railway, Render, Fly.io, or self-hosted behind Caddy). Agents run on your protected servers and **connect outbound** — no inbound ports need to be opened on the servers you're protecting.

## Sync Agents

The agent interface is intentionally simple: subscribe to a gRPC stream, receive `AllowlistSnapshot` updates, reconcile your enforcement mechanism. The initial agent targets Linux nftables, but the architecture is designed so other agents can be written against the same interface.

| Agent | Status | Enforcement |
|---|---|---|
| `nftables-sync-client` | included | Linux kernel firewall via nftables named sets |
| Kubernetes NetworkPolicy | planned | `NetworkPolicy` / `CiliumNetworkPolicy` reconciliation |
| Other firewalls | community | iptables, pf, Windows Firewall, etc. |

## Distributed Sync Agents

Sync agents do not have to live on the same network as the web app. The web app can run on a cloud provider while agents run on completely separate networks — home labs, office servers, cloud VMs, or any other environment. Each agent connects outbound to the web app's gRPC endpoint, so there is no requirement for the agent and the web app to share a network.

You can run many sync agents, each managed by its own API key. This lets you protect multiple services across different networks from a single web app instance, with independent access control for each agent.

## Email

Authorization is magic link based — no passwords. When a user submits their email, they receive a short-lived, single-use link. Clicking that link from the network they want to authorize confirms the IP.

Supported email providers (configured via `EMAIL_DRIVER` env var):

- `smtp` — works with Gmail app passwords, Proton Mail, or any SMTP server
- `resend` — recommended for simplicity; generous free tier

## Known Gaps

**IPv6** — IP addresses are stored as plain strings without normalization. IPv6 representations are not canonicalized, and the nftables set type is `ipv4_addr` only. Users on IPv6-only networks cannot authorize their IP.

Many IPv6 networks (particularly mobile carriers) use NAT64 or similar translation mechanisms, meaning an IPv6 device accessing your service over IPv4 may present different source IPs depending on which translation pool or tower handles the connection. Allowlisting the IP seen at authorization time provides no reliable protection for subsequent requests from the same device.

**Kubernetes / Container Sync Agent** — A sync agent that reconciles Kubernetes `NetworkPolicy` or `CiliumNetworkPolicy` resources is a natural extension of this design but is not yet implemented. See the nftables sync client for reference on the gRPC subscription and reconnect pattern.

**Single Instance Only** — The web app must run as a single instance. Multiple instances would maintain separate sets of connected agents, leading to inconsistent snapshot delivery. High availability is not a design goal.

**Application-Layer Rate Limiting** — The email submission endpoint does not implement rate limiting in the app layer. Enforce this at your reverse proxy (Caddy, Traefik) or CDN (Cloudflare).

**Shared / NAT IPs** — If a user authorizes from a shared network (corporate, CGNAT, university), all users behind that NAT gain access. This is a fundamental limitation of IP-based allowlisting.

**nftables Rule Position** — The sync agent can detect and recreate a missing jump rule but cannot safely reorder rules it does not own. A broad `drop` rule inserted above the jump rule by another process will block traffic regardless of the allowlist.

## License

MIT — see [LICENSE](LICENSE)
