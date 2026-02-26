package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log"
	"net"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (h *Handler) admin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	emails, err := h.db.ListAuthorizedEmails(ctx)
	if err != nil {
		h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
		return
	}
	ips, err := h.db.ListIPRecords(ctx)
	if err != nil {
		h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
		return
	}
	keys, err := h.db.ListAPIKeys(ctx)
	if err != nil {
		h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
		return
	}
	keyConnections := h.grpcSrv.ConnectedSubscriberCountsByKeyHash()

	h.render(w, r, "admin.html", map[string]any{
		"Emails":         emails,
		"IPs":            ips,
		"Keys":           keys,
		"KeyConnections": keyConnections,
	})
}

func (h *Handler) adminEmails(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, "Bad request.", http.StatusBadRequest)
		return
	}

	action := r.FormValue("action")
	emailAddr := strings.TrimSpace(r.FormValue("email"))

	ctx := r.Context()

	switch action {
	case "add":
		if emailAddr == "" {
			h.renderError(w, r, "Email required.", http.StatusBadRequest)
			return
		}
		if len(emailAddr) > maxEmailLen {
			h.renderError(w, r, "Email address too long.", http.StatusBadRequest)
			return
		}
		if _, err := mail.ParseAddress(emailAddr); err != nil {
			h.renderError(w, r, "Invalid email address.", http.StatusBadRequest)
			return
		}
		if err := h.db.AddAuthorizedEmail(ctx, emailAddr); err != nil {
			log.Printf("admin: add email: %v", err)
			h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
			return
		}
	case "remove":
		if emailAddr == "" {
			h.renderError(w, r, "Email required.", http.StatusBadRequest)
			return
		}
		if err := h.db.RemoveAuthorizedEmail(ctx, emailAddr); err != nil {
			log.Printf("admin: remove email: %v", err)
			h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
			return
		}
	default:
		h.renderError(w, r, "Unknown action.", http.StatusBadRequest)
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		emails, err := h.db.ListAuthorizedEmails(ctx)
		if err != nil {
			h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
			return
		}
		h.renderFragment(w, "admin.html", "emails-partial", map[string]any{
			"Emails":    emails,
			"CSRFToken": h.csrfToken(r),
		})
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (h *Handler) adminIPs(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, "Bad request.", http.StatusBadRequest)
		return
	}

	action := r.FormValue("action")
	ipAddr := strings.TrimSpace(r.FormValue("ip"))
	ctx := r.Context()

	switch action {
	case "remove":
		if ipAddr == "" {
			h.renderError(w, r, "IP required.", http.StatusBadRequest)
			return
		}
		if net.ParseIP(ipAddr) == nil {
			h.renderError(w, r, "Invalid IP address.", http.StatusBadRequest)
			return
		}
		if err := h.db.RemoveIPRecordsByIP(ctx, ipAddr); err != nil {
			log.Printf("admin: remove ip %q: %v", ipAddr, err)
			h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
			return
		}
		go h.grpcSrv.NotifyAll()
	default:
		h.renderError(w, r, "Unknown action.", http.StatusBadRequest)
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		ips, err := h.db.ListIPRecords(ctx)
		if err != nil {
			h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
			return
		}
		h.renderFragment(w, "admin.html", "ips-partial", map[string]any{
			"IPs":       ips,
			"CSRFToken": h.csrfToken(r),
		})
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (h *Handler) adminKeys(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, "Bad request.", http.StatusBadRequest)
		return
	}

	action := r.FormValue("action")
	ctx := r.Context()

	switch action {
	case "create":
		name := strings.TrimSpace(r.FormValue("name"))
		if name == "" {
			h.renderError(w, r, "Key name required.", http.StatusBadRequest)
			return
		}

		rawKey := make([]byte, 32)
		if _, err := rand.Read(rawKey); err != nil {
			log.Printf("admin: generate key bytes: %v", err)
			h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
			return
		}
		key := base64.URLEncoding.EncodeToString(rawKey)

		digest := sha256.Sum256([]byte(h.cfg.APIKeySalt + key))
		hash, err := bcrypt.GenerateFromPassword(digest[:], bcrypt.DefaultCost)
		if err != nil {
			log.Printf("admin: bcrypt key: %v", err)
			h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
			return
		}

		id, err := h.db.CreateAPIKey(ctx, name, string(hash))
		if err != nil {
			log.Printf("admin: create key: %v", err)
			h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
			return
		}

		keys, err := h.db.ListAPIKeys(ctx)
		if err != nil {
			log.Printf("admin: list keys after create: %v", err)
			h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
			return
		}

		data := map[string]any{
			"Keys":           keys,
			"KeyConnections": h.grpcSrv.ConnectedSubscriberCountsByKeyHash(),
			"NewKey":         key,
			"NewKeyID":       id,
			"NewKeyName":     name,
			"CSRFToken":      h.csrfToken(r),
		}

		if r.Header.Get("HX-Request") == "true" {
			h.renderFragment(w, "admin.html", "keys-partial", data)
			return
		}

		emails, _ := h.db.ListAuthorizedEmails(ctx)
		ips, _ := h.db.ListIPRecords(ctx)
		data["Emails"] = emails
		data["IPs"] = ips
		h.render(w, r, "admin.html", data)

	case "disable":
		idStr := r.FormValue("id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			h.renderError(w, r, "Invalid key ID.", http.StatusBadRequest)
			return
		}
		if err := h.db.DisableAPIKey(ctx, id); err != nil {
			log.Printf("admin: disable key %d: %v", id, err)
			h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
			return
		}

		go func() {
			disconnectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			h.grpcSrv.DisconnectRevokedSubscribers(disconnectCtx)
		}()

		if r.Header.Get("HX-Request") == "true" {
			keys, err := h.db.ListAPIKeys(ctx)
			if err != nil {
				h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
				return
			}
			h.renderFragment(w, "admin.html", "keys-partial", map[string]any{
				"Keys":           keys,
				"KeyConnections": h.grpcSrv.ConnectedSubscriberCountsByKeyHash(),
				"CSRFToken":      h.csrfToken(r),
			})
			return
		}

		http.Redirect(w, r, "/admin", http.StatusSeeOther)

	case "enable":
		idStr := r.FormValue("id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			h.renderError(w, r, "Invalid key ID.", http.StatusBadRequest)
			return
		}
		if err := h.db.EnableAPIKey(ctx, id); err != nil {
			log.Printf("admin: enable key %d: %v", id, err)
			h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
			return
		}

		if r.Header.Get("HX-Request") == "true" {
			keys, err := h.db.ListAPIKeys(ctx)
			if err != nil {
				h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
				return
			}
			h.renderFragment(w, "admin.html", "keys-partial", map[string]any{
				"Keys":           keys,
				"KeyConnections": h.grpcSrv.ConnectedSubscriberCountsByKeyHash(),
				"CSRFToken":      h.csrfToken(r),
			})
			return
		}

		http.Redirect(w, r, "/admin", http.StatusSeeOther)

	case "delete":
		idStr := r.FormValue("id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			h.renderError(w, r, "Invalid key ID.", http.StatusBadRequest)
			return
		}
		if err := h.db.DeleteDisabledAPIKey(ctx, id); err != nil {
			log.Printf("admin: delete key %d: %v", id, err)
			h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
			return
		}

		if r.Header.Get("HX-Request") == "true" {
			keys, err := h.db.ListAPIKeys(ctx)
			if err != nil {
				h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
				return
			}
			h.renderFragment(w, "admin.html", "keys-partial", map[string]any{
				"Keys":           keys,
				"KeyConnections": h.grpcSrv.ConnectedSubscriberCountsByKeyHash(),
				"CSRFToken":      h.csrfToken(r),
			})
			return
		}

		http.Redirect(w, r, "/admin", http.StatusSeeOther)

	default:
		h.renderError(w, r, "Unknown action.", http.StatusBadRequest)
	}
}
