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

// isIPOrCIDR reports whether s is a valid bare IP address or CIDR prefix.
// IPv6 allowlist records are stored as /64 prefixes, so the admin remove form
// submits CIDR strings as well as bare IPv4 addresses.
func isIPOrCIDR(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// canonicalizeCIDR validates an operator-assigned network and returns it in
// canonical, host-bits-masked form. A bare address is promoted to a single-host
// prefix (/32 for IPv4, /128 for IPv6). It returns ok=false for anything that is
// neither a valid IP nor a valid CIDR. Storing the canonical form keeps the
// UNIQUE(api_key_id, cidr) constraint meaningful and lets remove match add.
func canonicalizeCIDR(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() != nil {
			s += "/32"
		} else {
			s += "/128"
		}
	}
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return "", false
	}
	// Reject the default route (0.0.0.0/0 or ::/0): assigning it would turn a
	// key's client into allow-all and silently defeat the allowlist for that
	// host. An admin typo should not be able to do that.
	if ones, _ := ipNet.Mask.Size(); ones == 0 {
		return "", false
	}
	return ipNet.String(), true
}

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
	keyCIDRs, err := h.db.ListAPIKeyCIDRsByKeyID(ctx)
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
		"KeyCIDRs":       keyCIDRs,
	})
}

// keysPartialData assembles the data the "keys-partial" template needs: the key
// list, live connection counts, per-key assigned CIDRs, and a CSRF token.
func (h *Handler) keysPartialData(ctx context.Context, r *http.Request) (map[string]any, error) {
	keys, err := h.db.ListAPIKeys(ctx)
	if err != nil {
		return nil, err
	}
	keyCIDRs, err := h.db.ListAPIKeyCIDRsByKeyID(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"Keys":           keys,
		"KeyConnections": h.grpcSrv.ConnectedSubscriberCountsByKeyHash(),
		"KeyCIDRs":       keyCIDRs,
		"CSRFToken":      h.csrfToken(r),
	}, nil
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
		// Removal also deletes the email's IP records, so refresh the allowlist
		// to revoke firewall access immediately instead of at TTL.
		go h.grpcSrv.NotifyAll()
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
	emailAddr := strings.TrimSpace(r.FormValue("email"))
	ctx := r.Context()

	switch action {
	case "remove":
		if ipAddr == "" || emailAddr == "" {
			h.renderError(w, r, "Email and IP required.", http.StatusBadRequest)
			return
		}
		if !isIPOrCIDR(ipAddr) {
			h.renderError(w, r, "Invalid IP address.", http.StatusBadRequest)
			return
		}
		if err := h.db.RemoveIPRecord(ctx, emailAddr, ipAddr); err != nil {
			log.Printf("admin: remove ip %q for %q: %v", ipAddr, emailAddr, err)
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

		data, err := h.keysPartialData(ctx, r)
		if err != nil {
			log.Printf("admin: list keys after create: %v", err)
			h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
			return
		}
		data["NewKey"] = key
		data["NewKeyID"] = id
		data["NewKeyName"] = name

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

		h.renderKeysPartialOrRedirect(w, r, ctx)

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

		h.renderKeysPartialOrRedirect(w, r, ctx)

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

		h.renderKeysPartialOrRedirect(w, r, ctx)

	default:
		h.renderError(w, r, "Unknown action.", http.StatusBadRequest)
	}
}

// renderKeysPartialOrRedirect re-renders the keys-partial fragment for HTMX
// requests, or redirects to /admin for a full page load. Shared by every
// mutating key/CIDR action.
func (h *Handler) renderKeysPartialOrRedirect(w http.ResponseWriter, r *http.Request, ctx context.Context) {
	if r.Header.Get("HX-Request") == "true" {
		data, err := h.keysPartialData(ctx, r)
		if err != nil {
			h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
			return
		}
		h.renderFragment(w, "admin.html", "keys-partial", data)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// adminKeyCIDRs handles assigning and removing operator networks for a single
// API key. On success it pushes a fresh snapshot to that key's connected sync
// clients so the change lands in nftables within seconds.
func (h *Handler) adminKeyCIDRs(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, "Bad request.", http.StatusBadRequest)
		return
	}

	action := r.FormValue("action")
	idStr := r.FormValue("key_id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		h.renderError(w, r, "Invalid key ID.", http.StatusBadRequest)
		return
	}
	cidr, ok := canonicalizeCIDR(r.FormValue("cidr"))
	if !ok {
		h.renderError(w, r, "Invalid IP address or CIDR.", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Resolve the key up front. This both rejects requests for a nonexistent key
	// (avoiding orphaned api_key_cidrs rows) and gives us the hash to target the
	// push at just this key's connected clients.
	hash, err := h.db.GetAPIKeyHash(ctx, id)
	if err != nil {
		log.Printf("admin: lookup key hash %d: %v", id, err)
		h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
		return
	}
	if hash == "" {
		h.renderError(w, r, "Unknown API key.", http.StatusBadRequest)
		return
	}

	switch action {
	case "add":
		if err := h.db.AddAPIKeyCIDR(ctx, id, cidr); err != nil {
			log.Printf("admin: add cidr %q to key %d: %v", cidr, id, err)
			h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
			return
		}
	case "remove":
		if err := h.db.RemoveAPIKeyCIDR(ctx, id, cidr); err != nil {
			log.Printf("admin: remove cidr %q from key %d: %v", cidr, id, err)
			h.renderError(w, r, "Internal error.", http.StatusInternalServerError)
			return
		}
	default:
		h.renderError(w, r, "Unknown action.", http.StatusBadRequest)
		return
	}

	// Push the change to just this key's connected clients.
	go h.grpcSrv.NotifyKeyHash(hash)

	h.renderKeysPartialOrRedirect(w, r, ctx)
}
