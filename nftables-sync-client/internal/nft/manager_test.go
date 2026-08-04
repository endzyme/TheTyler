package nft

import (
	"bytes"
	"net"
	"testing"
)

func TestParseIPElementsIPv4Single(t *testing.T) {
	v4, v6, skipped := parseIPElements([]string{"203.0.113.7"})
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0", skipped)
	}
	if len(v6) != 0 {
		t.Fatalf("v6 elements = %d, want 0", len(v6))
	}
	if len(v4) != 1 {
		t.Fatalf("v4 elements = %d, want 1", len(v4))
	}
	if want := []byte{203, 0, 113, 7}; !bytes.Equal(v4[0].Key, want) {
		t.Fatalf("v4 key = %v, want %v", v4[0].Key, want)
	}
}

func TestParseIPElementsIPv6Prefix(t *testing.T) {
	v4, v6, skipped := parseIPElements([]string{"2001:db8:abcd:1234::/64"})
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0", skipped)
	}
	if len(v4) != 0 {
		t.Fatalf("v4 elements = %d, want 0", len(v4))
	}
	if len(v6) != 2 {
		t.Fatalf("v6 elements = %d, want 2 (interval start+end)", len(v6))
	}

	wantStart := net.ParseIP("2001:db8:abcd:1234::").To16()
	if !bytes.Equal(v6[0].Key, wantStart) {
		t.Fatalf("interval start = %v, want %v", v6[0].Key, []byte(wantStart))
	}
	// Exclusive upper bound is the next /64: 2001:db8:abcd:1235::.
	wantEnd := net.ParseIP("2001:db8:abcd:1235::").To16()
	if !v6[1].IntervalEnd {
		t.Fatalf("second element is not marked IntervalEnd")
	}
	if !bytes.Equal(v6[1].Key, wantEnd) {
		t.Fatalf("interval end = %v, want %v", v6[1].Key, []byte(wantEnd))
	}
}

func TestParseIPElementsMixedAndInvalid(t *testing.T) {
	v4, v6, skipped := parseIPElements([]string{
		"203.0.113.7",        // v4 host
		"2001:db8::/64",      // v6 prefix
		"not-an-ip",          // invalid
		"10.0.0.0/8",         // v4 CIDR — not allowed in the non-interval v4 set
		"",                   // empty
		"::ffff:203.0.113.9", // v4-mapped v6 → treated as v4 host
	})
	if len(v4) != 2 {
		t.Fatalf("v4 elements = %d, want 2", len(v4))
	}
	if len(v6) != 2 {
		t.Fatalf("v6 elements = %d, want 2", len(v6))
	}
	if skipped != 3 { // invalid, v4 CIDR, empty
		t.Fatalf("skipped = %d, want 3", skipped)
	}
	// The v4-mapped address must be stored as a plain 4-byte IPv4 key.
	if want := []byte{203, 0, 113, 9}; !bytes.Equal(v4[1].Key, want) {
		t.Fatalf("v4-mapped key = %v, want %v", v4[1].Key, want)
	}
}

func TestLastAddrIPv4(t *testing.T) {
	_, n, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	p, ok := ipNetToPrefix(n)
	if !ok {
		t.Fatal("ipNetToPrefix failed")
	}
	last := lastAddr(p)
	if got, want := last.String(), "192.0.2.255"; got != want {
		t.Fatalf("lastAddr = %s, want %s", got, want)
	}
}

func TestNetsToElementsMixedFamilies(t *testing.T) {
	_, n4, _ := net.ParseCIDR("10.0.0.0/24")
	_, n6, _ := net.ParseCIDR("2001:db8::/32")
	elems := netsToElements([]*net.IPNet{n4, n6})
	// Two interval elements per network.
	if len(elems) != 4 {
		t.Fatalf("elements = %d, want 4", len(elems))
	}
	// v4 start is a 4-byte key; v6 start is a 16-byte key.
	if len(elems[0].Key) != 4 {
		t.Fatalf("v4 start key len = %d, want 4", len(elems[0].Key))
	}
	if len(elems[2].Key) != 16 {
		t.Fatalf("v6 start key len = %d, want 16", len(elems[2].Key))
	}
}

func netsToStrings(nets []*net.IPNet) []string {
	out := make([]string, len(nets))
	for i, n := range nets {
		out[i] = n.String()
	}
	return out
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return n
}

func TestConsolidateNetsMergesOverlapsAndDupes(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "exact duplicate collapses",
			in:   []string{"10.0.0.0/24", "10.0.0.0/24"},
			want: []string{"10.0.0.0/24"},
		},
		{
			name: "subnet absorbed by supernet",
			in:   []string{"10.0.0.0/24", "10.0.0.0/16"},
			want: []string{"10.0.0.0/16"},
		},
		{
			name: "adjacent halves coalesce",
			in:   []string{"10.0.0.0/25", "10.0.0.128/25"},
			want: []string{"10.0.0.0/24"},
		},
		{
			name: "disjoint ranges preserved and sorted",
			in:   []string{"192.0.2.0/24", "10.0.0.0/24"},
			want: []string{"10.0.0.0/24", "192.0.2.0/24"},
		},
		{
			name: "ipv6 overlap collapses",
			in:   []string{"2001:db8::/48", "2001:db8::/32"},
			want: []string{"2001:db8::/32"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := make([]*net.IPNet, len(tc.in))
			for i, s := range tc.in {
				in[i] = mustCIDR(t, s)
			}
			got := netsToStrings(consolidateNets(in))
			if len(got) != len(tc.want) {
				t.Fatalf("consolidateNets(%v) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("consolidateNets(%v) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}

func TestParseServerCIDRs(t *testing.T) {
	v4, v6 := parseServerCIDRs([]string{
		"203.0.113.0/24",
		"10.0.0.5",             // bare IPv4 -> /32
		"2001:db8::/48",        // v6 CIDR
		"2001:db8:abcd:1234::", // bare IPv6 -> /128
		"garbage",              // skipped
		"",                     // skipped
	})
	if got := netsToStrings(v4); len(got) != 2 {
		t.Fatalf("v4 = %v, want 2 entries", got)
	}
	if got := netsToStrings(v6); len(got) != 2 {
		t.Fatalf("v6 = %v, want 2 entries", got)
	}
}

// TestSetServerCIDRsConsolidatesWithConfig verifies the whole merge: a locally
// configured static net plus an overlapping server-pushed CIDR collapse into a
// single non-overlapping entry in the effective static set.
func TestSetServerCIDRsConsolidatesWithConfig(t *testing.T) {
	m := &Manager{
		baseNets4: []*net.IPNet{mustCIDR(t, "10.0.0.0/24")},
		baseNets6: []*net.IPNet{mustCIDR(t, "2001:db8:1::/48")},
	}
	// Server pushes a supernet of the config v4 net and a fresh v6 net.
	m.SetServerCIDRs([]string{"10.0.0.0/16", "2001:db8:2::/48"})

	v4, v6 := m.staticNetsSnapshot()
	if got, want := netsToStrings(v4), []string{"10.0.0.0/16"}; !equalStr(got, want) {
		t.Fatalf("v4 = %v, want %v", got, want)
	}
	if got := netsToStrings(v6); len(got) != 2 {
		t.Fatalf("v6 = %v, want 2 disjoint /48s", got)
	}

	// Clearing server CIDRs falls back to config-only.
	m.SetServerCIDRs(nil)
	v4, _ = m.staticNetsSnapshot()
	if got, want := netsToStrings(v4), []string{"10.0.0.0/24"}; !equalStr(got, want) {
		t.Fatalf("after clear v4 = %v, want %v", got, want)
	}
}

func equalStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
