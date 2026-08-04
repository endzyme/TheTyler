package handler

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
	"time"

	"github.com/endzyme/the-tyler/web-app/internal/db"
	internalgrpc "github.com/endzyme/the-tyler/web-app/internal/grpc"
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
		{"0.0.0.0/0", "", false}, // default route rejected (allow-all footgun)
		{"::/0", "", false},      // IPv6 default route rejected
		{"", "", false},

		// IPv4-mapped IPv6 forms. Parsed naively (net.ParseIP + To4() + "/32"),
		// "::ffff:8.8.8.8" would canonicalize to "::/32" — 2^96 addresses for a
		// single-host request — and "::ffff:0:0/96" would render as "0.0.0.0/0",
		// slipping past the default-route guard and making the client allow-all.
		{"::ffff:8.8.8.8", "8.8.8.8/32", true},
		{"::ffff:10.0.0.5", "10.0.0.5/32", true},
		{"::ffff:0:0/96", "", false},

		// A zoned link-local address is not a meaningful operator grant.
		{"fe80::1%eth0", "", false},
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

// TestKeysPartialRendersConnectedClients guards the per-connection version
// display: each live connection for a key must show its source IP, reported
// version, and connect time, and a version that differs from the web app's must
// be flagged as drift.
func TestKeysPartialRendersConnectedClients(t *testing.T) {
	tmpl, err := template.ParseFS(templatesFS, "templates/base.html", "templates/admin.html")
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	connectedAt := time.Date(2026, 8, 4, 9, 30, 0, 0, time.UTC)
	data := map[string]any{
		"Keys": []db.APIKey{
			{ID: 7, Name: "server-1", KeyHash: "hash7", CreatedAt: time.Now()},
		},
		"KeyConnections": map[string]int{"hash7": 2},
		"KeyClients": map[string][]internalgrpc.ClientConn{
			"hash7": {
				{IP: "203.0.113.5", Version: "v1.4.0", ConnectedAt: connectedAt},
				{IP: "198.51.100.9", Version: "v1.3.0", ConnectedAt: connectedAt},
			},
		},
		"KeyCIDRs":   map[int64][]string{},
		"AppVersion": "v1.4.0",
		"CSRFToken":  "tok",
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "keys-partial", data); err != nil {
		t.Fatalf("execute keys-partial: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"Connected clients",     // the collapsible section header
		"203.0.113.5",           // matching-version client's IP
		"198.51.100.9",          // drifted client's IP
		"v1.3.0",                // the drifted version string
		"2026-08-04 09:30 UTC",  // connect time
		"drift",                 // the mismatch marker
	} {
		if !strings.Contains(out, want) {
			t.Errorf("keys-partial output missing %q\n---\n%s", want, out)
		}
	}

	// The client on the same version as the web app must not be flagged as drift.
	// There are two connections and exactly one differs, so "drift" appears once.
	if n := strings.Count(out, "drift"); n != 1 {
		t.Errorf("expected exactly one drift marker, got %d\n---\n%s", n, out)
	}
}

// TestKeysPartialHandlesPreVersionClient locks in backward compatibility: a sync
// client built before version reporting sends no client_version, so the server
// records an empty string. Such a connection must still render (as "unknown")
// and must never be flagged as drift, since we cannot know whether it is current.
func TestKeysPartialHandlesPreVersionClient(t *testing.T) {
	tmpl, err := template.ParseFS(templatesFS, "templates/base.html", "templates/admin.html")
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	data := map[string]any{
		"Keys": []db.APIKey{
			{ID: 7, Name: "server-1", KeyHash: "hash7", CreatedAt: time.Now()},
		},
		"KeyConnections": map[string]int{"hash7": 1},
		"KeyClients": map[string][]internalgrpc.ClientConn{
			"hash7": {
				{IP: "203.0.113.5", Version: "", ConnectedAt: time.Date(2026, 8, 4, 9, 30, 0, 0, time.UTC)},
			},
		},
		"KeyCIDRs":   map[int64][]string{},
		"AppVersion": "v1.4.0",
		"CSRFToken":  "tok",
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "keys-partial", data); err != nil {
		t.Fatalf("execute keys-partial: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "203.0.113.5") {
		t.Errorf("pre-version client connection not rendered\n---\n%s", out)
	}
	if !strings.Contains(out, "unknown") {
		t.Errorf("pre-version client should render as 'unknown'\n---\n%s", out)
	}
	if strings.Contains(out, "drift") {
		t.Errorf("pre-version client (empty version) must not be flagged as drift\n---\n%s", out)
	}
}
