package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/endzyme/the-tyler/web-app/internal/config"
	"github.com/endzyme/the-tyler/web-app/internal/db"
	"github.com/endzyme/the-tyler/web-app/internal/email"
	internalgrpc "github.com/endzyme/the-tyler/web-app/internal/grpc"
	"github.com/endzyme/the-tyler/web-app/internal/session"
)

//go:embed templates
var templatesFS embed.FS

//go:embed static/favicon.svg
var faviconSVG []byte

type Handler struct {
	cfg         *config.Config
	db          *db.DB
	mailer      email.Mailer
	grpcSrv     *internalgrpc.Server
	tmplMu      sync.RWMutex
	tmplCache   map[string]*template.Template
	fsys        fs.FS
	submitLimiter *rateLimiter
}

func New(cfg *config.Config, database *db.DB, mailer email.Mailer, grpcSrv *internalgrpc.Server) (*Handler, error) {
	h := &Handler{
		cfg:           cfg,
		db:            database,
		mailer:        mailer,
		grpcSrv:       grpcSrv,
		tmplCache:     make(map[string]*template.Template),
		// Allow 5 /submit requests per IP per 5 minutes.
		submitLimiter: newRateLimiter(5, 5*time.Minute),
	}

	if err := h.initFS(); err != nil {
		return nil, err
	}

	if !cfg.Dev {
		for _, name := range []string{"home.html", "authorized.html", "error.html", "admin.html"} {
			if _, err := h.tmplFor(name); err != nil {
				return nil, err
			}
		}
	}

	return h, nil
}

func (h *Handler) initFS() error {
	if h.cfg.Dev {
		h.fsys = os.DirFS("internal/handler/templates")
	} else {
		sub, err := fs.Sub(templatesFS, "templates")
		if err != nil {
			return err
		}
		h.fsys = sub
	}
	return nil
}

func (h *Handler) tmplFor(page string) (*template.Template, error) {
	if !h.cfg.Dev {
		h.tmplMu.RLock()
		t, ok := h.tmplCache[page]
		h.tmplMu.RUnlock()
		if ok {
			return t, nil
		}
	}

	if h.cfg.Dev {
		if err := h.initFS(); err != nil {
			return nil, err
		}
	}

	t, err := template.ParseFS(h.fsys, "base.html", page)
	if err != nil {
		return nil, err
	}

	if !h.cfg.Dev {
		h.tmplMu.Lock()
		h.tmplCache[page] = t
		h.tmplMu.Unlock()
	}

	return t, nil
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(faviconSVG)
	})
	mux.HandleFunc("GET /", h.home)
	mux.HandleFunc("POST /submit", h.submit)
	mux.HandleFunc("GET /verify", h.verify)
	mux.HandleFunc("POST /authorize", h.requireCSRF(h.authorize))
	mux.HandleFunc("POST /logout", h.logout)
	mux.HandleFunc("GET /admin", h.requireAdmin(h.admin))
	mux.HandleFunc("POST /admin/emails", h.requireAdmin(h.requireCSRF(h.adminEmails)))
	mux.HandleFunc("POST /admin/ips", h.requireAdmin(h.requireCSRF(h.adminIPs)))
	mux.HandleFunc("POST /admin/keys", h.requireAdmin(h.requireCSRF(h.adminKeys)))
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	session.Clear(w, h.cfg.SecureCookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// csrfToken returns a stateless CSRF token derived from the session cookie.
// Returns an empty string when there is no active session.
func (h *Handler) csrfToken(r *http.Request) string {
	c, err := r.Cookie(session.CookieName)
	if err != nil || c.Value == "" {
		return ""
	}
	mac := hmac.New(sha256.New, h.cfg.MagicLinkSecret)
	mac.Write([]byte("csrf:" + c.Value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// requireCSRF is a middleware that validates the csrf_token form field against
// the session-derived CSRF token. It must be called after form parsing.
func (h *Handler) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			h.renderError(w, r, "Bad request.", http.StatusBadRequest)
			return
		}
		submitted := r.FormValue("csrf_token")
		expected := h.csrfToken(r)
		if expected == "" || subtle.ConstantTimeCompare([]byte(submitted), []byte(expected)) != 1 {
			h.renderError(w, r, "Invalid or missing CSRF token.", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// render executes the named page template, automatically injecting session state.
func (h *Handler) render(w http.ResponseWriter, r *http.Request, page string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	if emailAddr, isAdmin, err := session.Get(r, h.cfg.MagicLinkSecret); err == nil {
		data["LoggedIn"] = true
		data["SessionEmail"] = emailAddr
		data["SessionIsAdmin"] = isAdmin
	}
	data["CSRFToken"] = h.csrfToken(r)

	t, err := h.tmplFor(page)
	if err != nil {
		log.Printf("template load %s: %v", page, err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "base", data); err != nil {
		log.Printf("template execute %s: %v", page, err)
	}
}

// renderFragment executes a named partial template (for HTMX responses).
func (h *Handler) renderFragment(w http.ResponseWriter, page, name string, data any) {
	t, err := h.tmplFor(page)
	if err != nil {
		log.Printf("template load %s: %v", page, err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("template fragment %s/%s: %v", page, name, err)
	}
}

func (h *Handler) renderError(w http.ResponseWriter, r *http.Request, msg string, code int) {
	log.Printf("http error: status=%d method=%s path=%q remote=%s msg=%q", code, r.Method, r.URL.Path, r.RemoteAddr, msg)
	w.WriteHeader(code)
	h.render(w, r, "error.html", map[string]any{"Error": msg})
}

func (h *Handler) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		emailAddr, _, err := session.Get(r, h.cfg.MagicLinkSecret)
		if err != nil {
			log.Printf("admin auth: missing/invalid session: method=%s path=%s remote=%s", r.Method, r.URL.Path, r.RemoteAddr)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		if !slices.Contains(h.cfg.AdminEmails, emailAddr) {
			log.Printf("admin auth: forbidden email=%q method=%s path=%s remote=%s", emailAddr, r.Method, r.URL.Path, r.RemoteAddr)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}
