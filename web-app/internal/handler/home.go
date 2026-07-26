package handler

import (
	"log"
	"net/http"

	"github.com/endzyme/the-tyler/web-app/internal/session"
)

func (h *Handler) home(w http.ResponseWriter, r *http.Request) {
	emailAddr, _, err := session.Get(r, h.cfg.MagicLinkSecret)
	if err != nil {
		// Not logged in — just show the email form
		h.render(w, r, "home.html", nil)
		return
	}

	ip := extractIP(r, h.cfg.TrustProxy)
	if ip == "" {
		h.render(w, r, "home.html", nil)
		return
	}

	record, err := h.db.GetIPRecord(r.Context(), emailAddr, ip)
	if err != nil {
		h.renderError(w, r, "Internal error.", 500)
		return
	}

	switch {
	case record == nil:
		// This IP is new for this user — offer a fresh authorization.
		h.render(w, r, "home.html", map[string]any{
			"IP": ip,
		})
	case !record.Expired:
		// Still live — silently refresh the TTL so continued use keeps it alive.
		if err := h.db.UpsertIPRecord(r.Context(), emailAddr, ip); err != nil {
			log.Printf("home: refresh TTL for %s: %v", ip, err)
		}
		h.render(w, r, "home.html", map[string]any{
			"IP":             ip,
			"AlreadyAllowed": true,
		})
	default:
		// Known IP whose authorization has lapsed — offer a re-authorization.
		h.render(w, r, "home.html", map[string]any{
			"IP":     ip,
			"Reauth": true,
		})
	}
}
