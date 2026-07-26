package handler

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/netip"
	"strings"
	"time"

	"github.com/endzyme/the-tyler/web-app/internal/token"
)

// maxEmailLen is the maximum length of an email address per RFC 5321.
const maxEmailLen = 254

// ipv6PrefixBits is the prefix length authorized for an IPv6 client. An
// individual /128 address is not stable — privacy extensions (RFC 8981) rotate
// the host bits on both home and mobile networks, and on cellular the whole
// /64 is a single device's allocation. Authorizing the /64 is the stable unit
// that identifies "this LAN" (or "this device's cellular network"), mirroring
// how a single public IPv4 covers an entire NAT'd household.
const ipv6PrefixBits = 64

func (h *Handler) submit(w http.ResponseWriter, r *http.Request) {
	// Always respond the same way to prevent email enumeration and leak rate limit status.
	defer func() {
		h.render(w, r, "home.html", map[string]any{
			"Submitted": true,
		})
	}()

	// Rate limit by IP to prevent email spam abuse.
	ip := extractIP(r, h.cfg.TrustProxy)
	if ip == "" || !h.submitLimiter.allow(ip) {
		return
	}

	emailAddr := strings.TrimSpace(r.FormValue("email"))
	if emailAddr == "" || len(emailAddr) > maxEmailLen {
		return
	}
	if _, err := mail.ParseAddress(emailAddr); err != nil {
		return
	}

	ctx := r.Context()
	authorized, err := h.db.IsEmailAuthorized(ctx, emailAddr)
	if err != nil {
		log.Printf("submit: IsEmailAuthorized: %v", err)
		return
	}
	if !authorized {
		// Silently do nothing — don't reveal whether email is authorized
		return
	}

	expiry := time.Now().Add(h.cfg.TokenExpiry)
	tok, err := token.Generate(h.cfg.MagicLinkSecret, emailAddr, expiry)
	if err != nil {
		log.Printf("submit: generate token: %v", err)
		return
	}

	link := fmt.Sprintf("%s/verify?token=%s", h.cfg.BaseURL, tok)

	// Send asynchronously so the HTTP response timing is the same whether or not
	// the address is authorized — a synchronous send would let an attacker
	// distinguish registered addresses by how long the request takes.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := h.mailer.SendMagicLink(ctx, emailAddr, link); err != nil {
			log.Printf("submit: send email to %q: %v", emailAddr, err)
		}
	}()
}

// extractIP returns the normalized allowlist key for the request's client:
// an IPv4 address is returned canonicalized (e.g. "203.0.113.7"), while an
// IPv6 address is reduced to its /64 prefix in CIDR form (e.g.
// "2001:db8:abcd:1234::/64"). Returns "" if no valid client IP can be found.
func extractIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			// Take the first (client) IP
			parts := strings.SplitN(xff, ",", 2)
			if key := normalizeClientIP(strings.TrimSpace(parts[0])); key != "" {
				return key
			}
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// No port present
		return normalizeClientIP(r.RemoteAddr)
	}
	return normalizeClientIP(host)
}

// normalizeClientIP converts a raw source-IP string into the canonical
// allowlist key. IPv4 addresses are returned as a single host; IPv6 addresses
// are masked to ipv6PrefixBits and returned as a CIDR prefix. Returns "" if raw
// is not a valid IP address.
func normalizeClientIP(raw string) string {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return ""
	}
	// Collapse IPv4-mapped IPv6 (e.g. "::ffff:203.0.113.7") to plain IPv4.
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	// Drop any zone identifier before masking; a public client never carries one.
	prefix, err := addr.WithZone("").Prefix(ipv6PrefixBits)
	if err != nil {
		return ""
	}
	return prefix.String()
}
