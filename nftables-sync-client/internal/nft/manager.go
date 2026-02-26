// Package nft manages the nftables structure required by the allowlist system.
//
// It uses the github.com/google/nftables library to talk directly to the
// kernel via netlink — no nft(8) CLI dependency. All set updates are batched
// into a single conn.Flush() call, providing kernel-level atomicity.
package nft

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/endzyme/the-tyler/nftables-sync-client/internal/config"
)

// Fixed names for all objects managed by the sync client.
// These are intentionally unusual to avoid collisions with operator-defined
// objects and to make ownership obvious in `nft list ruleset`.
const (
	tylerChainName      = "the_tyler_allowlist"
	tylerIPSetName      = "the_tyler_allowed_ips"
	tylerPortSetName    = "the_tyler_ports"
	tylerStaticSetName  = "the_tyler_always_allowed"
)

// Manager holds the nftables table configuration and provides idempotent
// operations for ensuring the required table structure and atomically
// updating the IP and port sets.
type Manager struct {
	tableName   string
	tableFamily nftables.TableFamily
	ports       []config.PortRange
	staticNets  []*net.IPNet
}

// NewManager constructs a Manager from the supplied configuration.
// The NFTTable field is expected in "family name" form, e.g. "inet filter".
func NewManager(cfg *config.Config) *Manager {
	family, name := parseTableConfig(cfg.NFTTable)
	return &Manager{
		tableName:   name,
		tableFamily: family,
		ports:       cfg.Ports,
		staticNets:  cfg.StaticNets,
	}
}

// parseTableConfig splits "inet filter" into (TableFamilyINet, "filter").
// Defaults to inet if the family string is unrecognised.
func parseTableConfig(tableStr string) (nftables.TableFamily, string) {
	parts := strings.SplitN(tableStr, " ", 2)
	if len(parts) != 2 {
		return nftables.TableFamilyINet, tableStr
	}
	var family nftables.TableFamily
	switch parts[0] {
	case "ip":
		family = nftables.TableFamilyIPv4
	case "ip6":
		family = nftables.TableFamilyIPv6
	case "inet":
		family = nftables.TableFamilyINet
	default:
		log.Printf("[nft] WARNING: unknown table family %q, defaulting to inet", parts[0])
		family = nftables.TableFamilyINet
	}
	return family, parts[1]
}

// ── Public API ────────────────────────────────────────────────────────────────

// Ensure verifies — and where necessary creates — the required nftables
// structure, then applies ips to the IP set. It is safe to call repeatedly.
//
//  1. The base table must exist (operator responsibility; we warn if absent).
//  2. The named IP set (the_tyler_allowed_ips) is created if missing.
//  3. The named port set (the_tyler_ports) is created/updated with the
//     configured port ranges.
//  4. The static set (the_tyler_always_allowed) is synced with ALWAYS_ALLOW_IPS.
//     If ALWAYS_ALLOW_IPS is empty the set is flushed to empty (if it exists).
//  5. The dedicated allowlist chain (the_tyler_allowlist) is created if missing,
//     and its rule set is verified/rebuilt as needed:
//       [ip saddr @the_tyler_always_allowed accept]  (only if static set populated)
//       ip saddr @the_tyler_allowed_ips accept
//       drop
//  6. A single jump rule is added to the "input" chain if missing:
//     tcp dport @the_tyler_ports jump the_tyler_allowlist
//  7. The IP set contents are reconciled against ips.
func (m *Manager) Ensure(ips []string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("open nftables conn: %w", err)
	}

	table, err := m.findTable(conn)
	if err != nil {
		return fmt.Errorf("find table: %w", err)
	}
	if table == nil {
		log.Printf("[nft] WARNING: table %q (family %d) not found; ensure skipped — operator must create it", m.tableName, m.tableFamily)
		return nil
	}

	// Phase 1: ensure IP set exists. Flush immediately so subsequent
	// operations can reference the kernel-assigned set handle.
	ipSet, err := m.findOrCreateSet(conn, table, tylerIPSetName, nftables.TypeIPAddr, false)
	if err != nil {
		return fmt.Errorf("ensure IP set: %w", err)
	}

	// Phase 2: ensure port set exists and is up to date with configured ranges.
	portSet, err := m.findOrCreateSet(conn, table, tylerPortSetName, nftables.TypeInetService, true)
	if err != nil {
		return fmt.Errorf("ensure port set: %w", err)
	}
	if err := m.applyPortSet(conn, portSet); err != nil {
		return fmt.Errorf("apply port set: %w", err)
	}

	// Phase 3: sync static set (the_tyler_always_allowed).
	// Always created with Interval=true to support both /32 hosts and CIDRs.
	var staticSet *nftables.Set
	if len(m.staticNets) > 0 {
		staticSet, err = m.findOrCreateSet(conn, table, tylerStaticSetName, nftables.TypeIPAddr, true)
		if err != nil {
			return fmt.Errorf("ensure static set: %w", err)
		}
		if err := m.applyStaticSet(conn, staticSet); err != nil {
			return fmt.Errorf("apply static set: %w", err)
		}
	} else {
		// ALWAYS_ALLOW_IPS not configured: flush the set if it exists so old
		// entries are not left behind.
		existing, _ := m.findSetByName(conn, table, tylerStaticSetName)
		if existing != nil {
			conn.FlushSet(existing)
			if err := conn.Flush(); err != nil {
				log.Printf("[nft] WARNING: flush stale static set: %v", err)
			}
		}
	}

	// Phase 4: ensure the allowlist chain exists with the correct rule set.
	chain, err := m.findChain(conn, table, tylerChainName)
	if err != nil {
		return fmt.Errorf("find allowlist chain: %w", err)
	}
	if chain == nil {
		log.Printf("[nft] creating allowlist chain %q", tylerChainName)
		chain = conn.AddChain(&nftables.Chain{
			Name:  tylerChainName,
			Table: table,
		})
		if staticSet != nil {
			conn.AddRule(&nftables.Rule{
				Table: table,
				Chain: chain,
				Exprs: allowRuleExprs(staticSet),
			})
		}
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: allowRuleExprs(ipSet),
		})
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}},
		})
		if err := conn.Flush(); err != nil {
			return fmt.Errorf("flush chain creation: %w", err)
		}
	} else {
		// Chain already exists — verify its rules are correct for the current
		// config (e.g. ALWAYS_ALLOW_IPS was added or removed).
		if err := m.ensureChainRules(conn, table, chain, ipSet, staticSet); err != nil {
			return fmt.Errorf("ensure chain rules: %w", err)
		}
	}

	// Phase 5: ensure the jump rule exists in the "input" base chain.
	if err := m.ensureJumpRule(conn, table, portSet); err != nil {
		return fmt.Errorf("ensure jump rule: %w", err)
	}

	// Phase 6: reconcile IP set contents.
	return m.ApplySnapshot(ips)
}

// ApplySnapshot atomically replaces the IP set contents with ips.
// It flushes and re-populates the set in a single netlink transaction.
func (m *Manager) ApplySnapshot(ips []string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("open nftables conn: %w", err)
	}

	table, err := m.findTable(conn)
	if err != nil {
		return fmt.Errorf("find table: %w", err)
	}
	if table == nil {
		log.Printf("[nft] WARNING: table %q not found; snapshot not applied", m.tableName)
		return nil
	}

	ipSet, err := m.findSetByName(conn, table, tylerIPSetName)
	if err != nil {
		return fmt.Errorf("find IP set: %w", err)
	}
	if ipSet == nil {
		log.Printf("[nft] WARNING: IP set %q not found; snapshot not applied (run Ensure first)", tylerIPSetName)
		return nil
	}

	elements, skipped := parseIPElements(ips)
	if skipped > 0 {
		log.Printf("[nft] WARNING: skipped %d non-IPv4 or invalid addresses", skipped)
	}

	// Atomic: flush existing elements then add new ones in one transaction.
	conn.FlushSet(ipSet)
	if len(elements) > 0 {
		if err := conn.SetAddElements(ipSet, elements); err != nil {
			return fmt.Errorf("set add elements: %w", err)
		}
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush snapshot: %w", err)
	}

	log.Printf("[nft] applied snapshot: %d IPs", len(elements))
	return nil
}

// ── Set management ────────────────────────────────────────────────────────────

// findOrCreateSet finds the named set or creates it if absent.
// After creation it re-fetches the set to get the kernel-assigned handle.
func (m *Manager) findOrCreateSet(conn *nftables.Conn, table *nftables.Table, name string, keyType nftables.SetDatatype, interval bool) (*nftables.Set, error) {
	s, err := m.findSetByName(conn, table, name)
	if err != nil {
		return nil, fmt.Errorf("find set %q: %w", name, err)
	}
	if s != nil {
		return s, nil
	}

	log.Printf("[nft] creating set %q", name)
	s = &nftables.Set{
		Table:    table,
		Name:     name,
		KeyType:  keyType,
		Interval: interval,
	}
	if err := conn.AddSet(s, nil); err != nil {
		return nil, fmt.Errorf("add set %q: %w", name, err)
	}
	if err := conn.Flush(); err != nil {
		return nil, fmt.Errorf("flush set %q creation: %w", name, err)
	}
	s, err = m.findSetByName(conn, table, name)
	if err != nil {
		return nil, fmt.Errorf("re-fetch set %q: %w", name, err)
	}
	if s == nil {
		return nil, fmt.Errorf("set %q not found after creation", name)
	}
	return s, nil
}

// applyPortSet atomically replaces the port set contents with the configured
// port ranges. Each range [A, B] is encoded as two interval elements:
//
//	{Key: bigEndian16(A)}                        // interval start (inclusive)
//	{Key: bigEndian16(B+1), IntervalEnd: true}   // interval end (exclusive)
//
// A single port N is encoded as the range [N, N].
func (m *Manager) applyPortSet(conn *nftables.Conn, portSet *nftables.Set) error {
	elements := make([]nftables.SetElement, 0, len(m.ports)*2)
	for _, r := range m.ports {
		start := make([]byte, 2)
		end := make([]byte, 2)
		binary.BigEndian.PutUint16(start, r.Start)
		binary.BigEndian.PutUint16(end, r.End+1) // exclusive upper bound
		elements = append(elements,
			nftables.SetElement{Key: start},
			nftables.SetElement{Key: end, IntervalEnd: true},
		)
	}

	conn.FlushSet(portSet)
	if len(elements) > 0 {
		if err := conn.SetAddElements(portSet, elements); err != nil {
			return fmt.Errorf("set add port elements: %w", err)
		}
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush port set: %w", err)
	}
	return nil
}

// applyStaticSet atomically replaces the static set contents with the
// configured networks. CIDRs are encoded as half-open intervals:
//
//	{Key: networkAddress}                        // start (inclusive)
//	{Key: broadcastAddress+1, IntervalEnd: true} // end (exclusive)
//
// A plain host address (from /32) encodes as a single-address interval.
func (m *Manager) applyStaticSet(conn *nftables.Conn, staticSet *nftables.Set) error {
	elements := cidrToElements(m.staticNets)

	conn.FlushSet(staticSet)
	if len(elements) > 0 {
		if err := conn.SetAddElements(staticSet, elements); err != nil {
			return fmt.Errorf("set add static elements: %w", err)
		}
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush static set: %w", err)
	}
	return nil
}

// cidrToElements converts a slice of IPv4 networks into nftables interval
// SetElements. Each network becomes two elements:
//
//	{Key: network address (4 bytes)}
//	{Key: broadcast+1 (4 bytes), IntervalEnd: true}
func cidrToElements(nets []*net.IPNet) []nftables.SetElement {
	elements := make([]nftables.SetElement, 0, len(nets)*2)
	for _, ipNet := range nets {
		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			continue // skip any non-IPv4 that slipped through
		}
		mask := []byte(ipNet.Mask)
		if len(mask) == 16 {
			mask = mask[12:] // IPv4-in-IPv6 mask representation
		}

		start := make([]byte, 4)
		copy(start, ip4)

		// Compute exclusive upper bound: broadcast + 1.
		end := make([]byte, 4)
		for i := 0; i < 4; i++ {
			end[i] = ip4[i] | ^mask[i]
		}
		for i := 3; i >= 0; i-- {
			end[i]++
			if end[i] != 0 {
				break
			}
		}

		elements = append(elements,
			nftables.SetElement{Key: start},
			nftables.SetElement{Key: end, IntervalEnd: true},
		)
	}
	return elements
}

// ── Chain rule management ─────────────────────────────────────────────────────

// ensureChainRules checks that the allowlist chain contains exactly the rules
// required by the current configuration. If any rule is missing — or if a
// stale static-accept rule remains after ALWAYS_ALLOW_IPS was removed — the
// chain's rules are rebuilt atomically in a single Flush.
//
// Expected rule order (staticSet non-nil only when ALWAYS_ALLOW_IPS is set):
//
//	[ip saddr @the_tyler_always_allowed accept]
//	ip saddr @the_tyler_allowed_ips accept
//	drop
func (m *Manager) ensureChainRules(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain, ipSet, staticSet *nftables.Set) error {
	rules, err := conn.GetRules(table, chain)
	if err != nil {
		return fmt.Errorf("get chain rules: %w", err)
	}

	needsStatic := staticSet != nil
	hasStaticAccept := false
	hasDynamicAccept := false
	hasDrop := false

	for _, rule := range rules {
		switch {
		case ruleLooksUpSet(rule, tylerStaticSetName):
			hasStaticAccept = true
		case ruleLooksUpSet(rule, tylerIPSetName):
			hasDynamicAccept = true
		case ruleIsVerdict(rule, expr.VerdictDrop):
			hasDrop = true
		}
	}

	// Stale static rule: was created when ALWAYS_ALLOW_IPS was set, now it's not.
	staleStaticRule := !needsStatic && hasStaticAccept
	allPresent := hasDynamicAccept && hasDrop && (!needsStatic || hasStaticAccept) && !staleStaticRule

	if allPresent {
		return nil
	}

	log.Printf("[nft] rebuilding rules in chain %q", chain.Name)

	// Delete all existing rules and re-add in correct order, atomically.
	for _, rule := range rules {
		if err := conn.DelRule(rule); err != nil {
			return fmt.Errorf("queue del chain rule: %w", err)
		}
	}
	if needsStatic {
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: allowRuleExprs(staticSet),
		})
	}
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: allowRuleExprs(ipSet),
	})
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}},
	})
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush chain rule rebuild: %w", err)
	}
	return nil
}

// ruleLooksUpSet returns true if the rule contains a Lookup expression that
// references setName.
func ruleLooksUpSet(rule *nftables.Rule, setName string) bool {
	for _, e := range rule.Exprs {
		if l, ok := e.(*expr.Lookup); ok {
			return l.SetName == setName
		}
	}
	return false
}

// ruleIsVerdict returns true if the rule's only verdict matches kind.
func ruleIsVerdict(rule *nftables.Rule, kind expr.VerdictKind) bool {
	for _, e := range rule.Exprs {
		if v, ok := e.(*expr.Verdict); ok {
			return v.Kind == kind
		}
	}
	return false
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// findTable returns the configured table or nil if not found.
func (m *Manager) findTable(conn *nftables.Conn) (*nftables.Table, error) {
	tables, err := conn.ListTablesOfFamily(m.tableFamily)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == m.tableName {
			return t, nil
		}
	}
	return nil, nil
}

// findSetByName returns the named set within table, or nil if not found.
func (m *Manager) findSetByName(conn *nftables.Conn, table *nftables.Table, name string) (*nftables.Set, error) {
	sets, err := conn.GetSets(table)
	if err != nil {
		return nil, fmt.Errorf("get sets: %w", err)
	}
	for _, s := range sets {
		if s.Name == name {
			return s, nil
		}
	}
	return nil, nil
}

// findChain returns the chain with the given name within table, or nil.
func (m *Manager) findChain(conn *nftables.Conn, table *nftables.Table, name string) (*nftables.Chain, error) {
	chains, err := conn.ListChains()
	if err != nil {
		return nil, fmt.Errorf("list chains: %w", err)
	}
	for _, c := range chains {
		if c.Table != nil && c.Table.Name == table.Name && c.Table.Family == table.Family && c.Name == name {
			return c, nil
		}
	}
	return nil, nil
}

// ensureJumpRule ensures a "tcp dport @the_tyler_ports jump the_tyler_allowlist"
// rule exists in the "input" base chain, identified by its jump target.
func (m *Manager) ensureJumpRule(conn *nftables.Conn, table *nftables.Table, portSet *nftables.Set) error {
	inputChain, err := m.findChain(conn, table, "input")
	if err != nil {
		return fmt.Errorf("find input chain: %w", err)
	}
	if inputChain == nil {
		log.Printf("[nft] WARNING: \"input\" chain not found in table %q; jump rule not added", m.tableName)
		return nil
	}

	rules, err := conn.GetRules(table, inputChain)
	if err != nil {
		return fmt.Errorf("get input chain rules: %w", err)
	}

	for i, rule := range rules {
		if ruleJumpsTo(rule, tylerChainName) {
			if i < len(rules)-2 {
				log.Printf("[nft] WARNING: jump rule for %q is at position %d/%d — consider moving it after base accept rules", tylerChainName, i+1, len(rules))
			}
			return nil // already present
		}
	}

	log.Printf("[nft] adding jump rule: tcp dport @%s jump %s", tylerPortSetName, tylerChainName)
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: jumpRuleExprs(portSet),
	})
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush jump rule: %w", err)
	}
	return nil
}

// ruleJumpsTo returns true if the rule's verdict is a jump to chainName.
func ruleJumpsTo(rule *nftables.Rule, chainName string) bool {
	for _, e := range rule.Exprs {
		if v, ok := e.(*expr.Verdict); ok {
			return v.Kind == expr.VerdictJump && v.Chain == chainName
		}
	}
	return false
}

// jumpRuleExprs returns the expressions for
// "tcp dport @the_tyler_ports jump the_tyler_allowlist".
func jumpRuleExprs(portSet *nftables.Set) []expr.Any {
	return []expr.Any{
		// Match TCP only.
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		// Load destination port (transport header, offset 2, 2 bytes).
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
		// Lookup destination port in the named port set.
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        portSet.Name,
			SetID:          portSet.ID,
		},
		// Jump to the allowlist chain on match.
		&expr.Verdict{Kind: expr.VerdictJump, Chain: tylerChainName},
	}
}

// allowRuleExprs returns the expressions for "ip saddr @<set> accept"
// in an inet table. The meta nfproto check restricts matching to IPv4 only.
// Used for both the dynamic IP set and the static always-allowed set.
func allowRuleExprs(set *nftables.Set) []expr.Any {
	return []expr.Any{
		// Restrict to IPv4 traffic (required in inet tables).
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
		// Load IPv4 source address (network header, offset 12, 4 bytes).
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		},
		// Lookup source address in the named set.
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        set.Name,
			SetID:          set.ID,
		},
		// Accept if found.
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// parseIPElements converts a slice of IP strings into nftables SetElements.
// Only IPv4 addresses are accepted; others are counted as skipped.
func parseIPElements(ips []string) ([]nftables.SetElement, int) {
	elements := make([]nftables.SetElement, 0, len(ips))
	skipped := 0
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			skipped++
			continue
		}
		v4 := parsed.To4()
		if v4 == nil {
			skipped++
			continue
		}
		elements = append(elements, nftables.SetElement{Key: []byte(v4)})
	}
	return elements, skipped
}
