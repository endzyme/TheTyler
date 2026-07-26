package handler

import "testing"

func TestNormalizeClientIP(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ipv4 passthrough", "203.0.113.7", "203.0.113.7"},
		{"ipv6 reduced to /64", "2001:db8:abcd:1234:5678:9abc:def0:1234", "2001:db8:abcd:1234::/64"},
		{"ipv6 already on boundary", "2001:db8:abcd:1234::", "2001:db8:abcd:1234::/64"},
		{"ipv6 compressed forms collapse equally", "2001:0db8:abcd:1234:0000:0000:0000:0001", "2001:db8:abcd:1234::/64"},
		{"ipv4-mapped ipv6 becomes ipv4", "::ffff:203.0.113.7", "203.0.113.7"},
		{"invalid", "not-an-ip", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeClientIP(tc.in); got != tc.want {
				t.Fatalf("normalizeClientIP(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Two distinct /128 addresses inside the same /64 must normalize to the same
// allowlist key, so a client's rotating privacy address stays authorized.
func TestNormalizeClientIPStableAcrossRotation(t *testing.T) {
	a := normalizeClientIP("2001:db8:1:2:aaaa:bbbb:cccc:dddd")
	b := normalizeClientIP("2001:db8:1:2:1111:2222:3333:4444")
	if a != b {
		t.Fatalf("addresses in the same /64 normalized differently: %q vs %q", a, b)
	}
	if a != "2001:db8:1:2::/64" {
		t.Fatalf("got %q, want 2001:db8:1:2::/64", a)
	}
}
