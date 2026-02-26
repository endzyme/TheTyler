package handler

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/endzyme/the-tyler/web-app/internal/token"
)

// maxEmailLen is the maximum length of an email address per RFC 5321.
const maxEmailLen = 254

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
	tok, err := token.Generate(h.cfg.MagicLinkSecret, emailAddr, ip, expiry)
	if err != nil {
		log.Printf("submit: generate token: %v", err)
		return
	}

	link := fmt.Sprintf("%s/verify?token=%s", h.cfg.BaseURL, tok)

	if err := h.mailer.SendMagicLink(context.Background(), emailAddr, link); err != nil {
		log.Printf("submit: send email to %q: %v", emailAddr, err)
	}
}

func extractIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			// Take the first (client) IP
			parts := strings.SplitN(xff, ",", 2)
			ip := strings.TrimSpace(parts[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// No port present
		if net.ParseIP(r.RemoteAddr) != nil {
			return r.RemoteAddr
		}
		return ""
	}
	return host
}
