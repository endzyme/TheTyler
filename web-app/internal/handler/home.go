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

	active, err := h.db.IsIPActive(r.Context(), ip)
	if err != nil {
		h.renderError(w, r, "Internal error.", 500)
		return
	}

	if active {
		// Silently refresh the TTL so continued use keeps the IP alive
		if err := h.db.RefreshIPRecord(r.Context(), emailAddr, ip); err != nil {
			log.Printf("home: refresh TTL for %s: %v", ip, err)
		}
		h.render(w, r, "home.html", map[string]any{
			"IP":             ip,
			"AlreadyAllowed": true,
		})
		return
	}

	h.render(w, r, "home.html", map[string]any{
		"IP": ip,
	})
}
