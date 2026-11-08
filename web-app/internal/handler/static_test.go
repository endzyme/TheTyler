package handler

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// TestStaticScriptsServed checks the self-hosted scripts are served with a JS
// content type (required under X-Content-Type-Options: nosniff).
func TestStaticScriptsServed(t *testing.T) {
	mux := http.NewServeMux()
	(&Handler{}).RegisterRoutes(mux)

	for path, want := range map[string][]byte{
		"/static/htmx-2.0.4.min.js": htmxJS,
		"/static/admin.js":          adminJS,
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
			t.Errorf("%s: Content-Type %q", path, ct)
		}
		if rec.Body.String() != string(want) || len(want) == 0 {
			t.Errorf("%s: unexpected body (%d bytes)", path, rec.Body.Len())
		}
	}
}

// TestTemplatesHaveNoInlineScript guards the CSP (script-src 'self'): templates
// must not contain inline <script> bodies, inline event handlers, or
// off-origin script sources.
func TestTemplatesHaveNoInlineScript(t *testing.T) {
	inlineScript := regexp.MustCompile(`<script(?:\s[^>]*)?>\s*[^<\s]`)
	scriptTag := regexp.MustCompile(`<script\b[^>]*>`)
	handlerAttr := regexp.MustCompile(`\son[a-z]+\s*=`)

	err := fs.WalkDir(templatesFS, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := templatesFS.ReadFile(path)
		if err != nil {
			return err
		}
		s := string(b)
		if inlineScript.MatchString(s) {
			t.Errorf("%s: inline <script> body", path)
		}
		for _, tag := range scriptTag.FindAllString(s, -1) {
			if !strings.Contains(tag, `src="/static/`) {
				t.Errorf("%s: script not served from /static/: %s", path, tag)
			}
		}
		if m := handlerAttr.FindString(s); m != "" {
			t.Errorf("%s: inline event handler attribute %q", path, strings.TrimSpace(m))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
