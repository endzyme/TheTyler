package handler

import (
	"net/http"

	"github.com/endzyme/the-tyler/web-app/internal/session"
)

func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	emailAddr, _, err := session.Get(r, h.cfg.MagicLinkSecret)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	ip := extractIP(r, h.cfg.TrustProxy)
	if ip == "" {
		h.renderError(w, r, "Could not determine your IP address.", http.StatusBadRequest)
		return
	}

	if err := h.db.AddIPRecord(r.Context(), emailAddr, ip); err != nil {
		h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
		return
	}

	go h.grpcSrv.NotifyAll()

	h.render(w, r, "authorized.html", map[string]any{
		"IP": ip,
	})
}
