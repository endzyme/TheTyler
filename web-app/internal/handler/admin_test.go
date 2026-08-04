package handler

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
	"time"

	"github.com/endzyme/the-tyler/web-app/internal/db"
)

func TestCanonicalizeCIDR(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"203.0.113.0/24", "203.0.113.0/24", true},
		{"203.0.113.5/24", "203.0.113.0/24", true}, // host bits masked
		{"10.0.0.1", "10.0.0.1/32", true},          // bare IPv4 -> /32
		{"2001:db8::/48", "2001:db8::/48", true},
		{"2001:db8:abcd:1234::1", "2001:db8:abcd:1234::1/128", true}, // bare IPv6 -> /128
		{"  10.0.0.0/8  ", "10.0.0.0/8", true},                       // trimmed
		{"not-an-ip", "", false},
		{"10.0.0.0/33", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := canonicalizeCIDR(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("canonicalizeCIDR(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestKeysPartialRendersCIDRs guards the admin template: the keys-partial must
// list each key's assigned CIDRs and expose add/remove forms.
func TestKeysPartialRendersCIDRs(t *testing.T) {
	tmpl, err := template.ParseFS(templatesFS, "templates/base.html", "templates/admin.html")
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	data := map[string]any{
		"Keys": []db.APIKey{
			{ID: 7, Name: "server-1", KeyHash: "hash7", CreatedAt: time.Now()},
		},
		"KeyConnections": map[string]int{"hash7": 1},
		"KeyCIDRs":       map[int64][]string{7: {"203.0.113.0/24"}},
		"CSRFToken":      "tok",
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "keys-partial", data); err != nil {
		t.Fatalf("execute keys-partial: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"203.0.113.0/24",          // the assigned CIDR is shown
		`name="key_id" value="7"`, // add form carries the key id
		`/admin/keys/cidrs`,       // posts to the new route
		`name="action" value="add"`,
		`name="action" value="remove"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("keys-partial output missing %q\n---\n%s", want, out)
		}
	}
}
