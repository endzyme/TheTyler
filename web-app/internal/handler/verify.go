package handler

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/endzyme/the-tyler/web-app/internal/db"
	"github.com/endzyme/the-tyler/web-app/internal/session"
	"github.com/endzyme/the-tyler/web-app/internal/token"
)

func (h *Handler) verify(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("token")
	if raw == "" {
		h.renderError(w, r, "Missing token.", http.StatusBadRequest)
		return
	}

	tok, err := token.Parse(h.cfg.MagicLinkSecret, raw)
	if err != nil {
		if errors.Is(err, token.ErrExpired) {
			h.renderError(w, r, "This link has expired. Please request a new one.", http.StatusGone)
			return
		}
		h.renderError(w, r, "Invalid or tampered link.", http.StatusBadRequest)
		return
	}

	hash := tokenHash(raw)
	used, err := h.db.IsTokenUsed(r.Context(), hash)
	if err != nil {
		h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
		return
	}
	if used {
		// If they already have a valid session (clicked the link twice), just send them home
		if _, _, err := session.Get(r, h.cfg.MagicLinkSecret); err == nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		h.renderError(w, r, "This link has already been used.", http.StatusGone)
		return
	}

	if err := h.db.MarkTokenUsed(r.Context(), hash); err != nil {
		if errors.Is(err, db.ErrTokenAlreadyUsed) {
			if _, _, err := session.Get(r, h.cfg.MagicLinkSecret); err == nil {
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			h.renderError(w, r, "This link has already been used.", http.StatusGone)
			return
		}
		h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
		return
	}

	isAdmin := slices.Contains(h.cfg.AdminEmails, tok.Email)
	session.Set(w, h.cfg.MagicLinkSecret, tok.Email, isAdmin, h.cfg.SecureCookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func tokenHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum)
}
