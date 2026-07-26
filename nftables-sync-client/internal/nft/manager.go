// Package nft manages the nftables structure required by the allowlist system.
//
// It uses the github.com/google/nftables library to talk directly to the
// kernel via netlink — no nft(8) CLI dependency. All set updates are batched
// into a single conn.Flush() call, providing kernel-level atomicity.
//
// Both IPv4 and IPv6 are supported. IPv4 addresses arrive as single hosts and
// live in a plain (non-interval) set; IPv6 authorizations arrive as /64 CIDR
// prefixes and live in a separate interval set (a /128 key length is
// incompatible with the 4-byte IPv4 set, so the two families cannot share one
// set). Which families are managed depends on the table family: an "inet"
// table carries both, an "ip" table only IPv4, an "ip6" table only IPv6.
package nft

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
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
	tylerChainName       = "the_tyler_allowlist"
	tylerIPSetName       = "the_tyler_allowed_ips"
	tylerIPSetNameV6     = "the_tyler_allowed_ips_v6"
	tylerPortSetName     = "the_tyler_ports"
	tylerStaticSetName   = "the_tyler_always_allowed"
	tylerStaticSetNameV6 = "the_tyler_always_allowed_v6"
)

// Manager holds the nftables table configuration and provides idempotent
// operations for ensuring the required table structure and atomically
// updating the IP and port sets.
type Manager struct {
	tableName   string
	tableFamily nftables.TableFamily
	ports       []config.PortRange
	staticNets4 []*net.IPNet
	staticNets6 []*net.IPNet
}

// NewManager constructs a Manager from the supplied configuration.
// The NFTTable field is expected in "family name" form, e.g. "inet filter".
func NewManager(cfg *config.Config) *Manager {
	family, name := parseTableConfig(cfg.NFTTable)
	v4, v6 := splitNetsByFamily(cfg.StaticNets)
	return &Manager{
		tableName:   name,
		tableFamily: family,
		ports:       cfg.Ports,
		staticNets4: v4,
		staticNets6: v6,
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

// supportsV4 reports whether the configured table family can carry IPv4 rules.
func (m *Manager) supportsV4() bool {
	return m.tableFamily == nftables.TableFamilyINet || m.tableFamily == nftables.TableFamilyIPv4
}

// supportsV6 reports whether the configured table family can carry IPv6 rules.
func (m *Manager) supportsV6() bool {
	return m.tableFamily == nftables.TableFamilyINet || m.tableFamily == nftables.TableFamilyIPv6
}

// acceptRule describes one "<family> saddr @<set> accept" rule the allowlist
// chain should contain, in order.
type acceptRule struct {
	set    *nftables.Set
	family byte // unix.NFPROTO_IPV4 or unix.NFPROTO_IPV6
}

// ── Public API ────────────────────────────────────────────────────────────────

// Ensure verifies — and where necessary creates — the required nftables
// structure, then applies ips to the IP sets. It is safe to call repeatedly.
//
//  1. The base table must exist (operator responsibility; we warn if absent).
//  2. The named IP sets (the_tyler_allowed_ips / _v6) are created if missing,
//     one per address family the table supports.
//  3. The named port set (the_tyler_ports) is created/updated with the
//     configured port ranges.
//  4. The static sets (the_tyler_always_allowed / _v6) are synced with the
//     matching-family entries of ALWAYS_ALLOW_IPS. An empty family flushes its
//     set (if it exists).
//  5. The dedicated allowlist chain (the_tyler_allowlist) is created if missing,
//     and its rule set is verified/rebuilt as needed:
//     [ip  saddr @the_tyler_always_allowed    accept]  (if v4 static set populated)
//     [ip6 saddr @the_tyler_always_allowed_v6 accept]  (if v6 static set populated)
//     [ip  saddr @the_tyler_allowed_ips        accept]  (if table carries v4)
//     [ip6 saddr @the_tyler_allowed_ips_v6     accept]  (if table carries v6)
//     drop
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

	// Phase 1: ensure the dynamic IP sets exist, one per supported family.
	// Flush immediately so subsequent operations can reference the
	// kernel-assigned set handles.
	var ipSet4, ipSet6 *nftables.Set
	if m.supportsV4() {
		ipSet4, err = m.findOrCreateSet(conn, table, tylerIPSetName, nftables.TypeIPAddr, false)
		if err != nil {
			return fmt.Errorf("ensure IPv4 set: %w", err)
		}
	}
	if m.supportsV6() {
		ipSet6, err = m.findOrCreateSet(conn, table, tylerIPSetNameV6, nftables.TypeIP6Addr, true)
		if err != nil {
			return fmt.Errorf("ensure IPv6 set: %w", err)
		}
	}

	// Phase 2: ensure port set exists and is up to date with configured ranges.
	portSet, err := m.findOrCreateSet(conn, table, tylerPortSetName, nftables.TypeInetService, true)
	if err != nil {
		return fmt.Errorf("ensure port set: %w", err)
	}
	if err := m.applyPortSet(conn, portSet); err != nil {
		return fmt.Errorf("apply port set: %w", err)
	}

	// Phase 3: sync static sets (the_tyler_always_allowed / _v6). Always created
	// with Interval=true to support both single hosts and CIDRs.
	staticSet4, err := m.ensureStaticSet(conn, table, tylerStaticSetName, nftables.TypeIPAddr, m.staticNets4, m.supportsV4())
	if err != nil {
		return fmt.Errorf("ensure IPv4 static set: %w", err)
	}
	staticSet6, err := m.ensureStaticSet(conn, table, tylerStaticSetNameV6, nftables.TypeIP6Addr, m.staticNets6, m.supportsV6())
	if err != nil {
		return fmt.Errorf("ensure IPv6 static set: %w", err)
	}

	// Assemble the ordered accept rules the chain should contain: static rules
	// first (most specific operator intent), then the dynamic allowlist rules.
	var accepts []acceptRule
	if staticSet4 != nil {
		accepts = append(accepts, acceptRule{staticSet4, unix.NFPROTO_IPV4})
	}
	if staticSet6 != nil {
		accepts = append(accepts, acceptRule{staticSet6, unix.NFPROTO_IPV6})
	}
	if ipSet4 != nil {
		accepts = append(accepts, acceptRule{ipSet4, unix.NFPROTO_IPV4})
	}
	if ipSet6 != nil {
		accepts = append(accepts, acceptRule{ipSet6, unix.NFPROTO_IPV6})
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
		for _, a := range accepts {
			conn.AddRule(&nftables.Rule{
				Table: table,
				Chain: chain,
				Exprs: allowRuleExprs(a.set, a.family),
			})
		}
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}},
		})
		if err := conn.Flush(); err != nil {
			return fmt.Errorf("flush chain creation: %w", err)
		}
	} else {
		// Chain already exists — verify its rules match the current config
		// (e.g. ALWAYS_ALLOW_IPS changed, or IPv6 support was newly added).
		if err := m.ensureChainRules(conn, table, chain, accepts); err != nil {
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

// ApplySnapshot atomically replaces the IP set contents with ips. Each family's
// set is flushed and re-populated in a single netlink transaction.
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

	ipSet4, err := m.findSetByName(conn, table, tylerIPSetName)
	if err != nil {
		return fmt.Errorf("find IPv4 set: %w", err)
	}
	ipSet6, err := m.findSetByName(conn, table, tylerIPSetNameV6)
	if err != nil {
		return fmt.Errorf("find IPv6 set: %w", err)
	}
	if ipSet4 == nil && ipSet6 == nil {
		log.Printf("[nft] WARNING: IP sets not found; snapshot not applied (run Ensure first)")
		return nil
	}

	v4Elements, v6Elements, skipped := parseIPElements(ips)
	if skipped > 0 {
		log.Printf("[nft] WARNING: skipped %d invalid or unsupported allowlist entries", skipped)
	}
	if len(v4Elements) > 0 && ipSet4 == nil {
		log.Printf("[nft] WARNING: %d IPv4 entries dropped — table family does not carry IPv4", len(v4Elements))
	}
	if len(v6Elements) > 0 && ipSet6 == nil {
		log.Printf("[nft] WARNING: %d IPv6 entries dropped — table family does not carry IPv6", len(v6Elements)/2)
	}

	// Atomic: flush existing elements then add new ones in one transaction.
	if ipSet4 != nil {
		conn.FlushSet(ipSet4)
		if len(v4Elements) > 0 {
			if err := conn.SetAddElements(ipSet4, v4Elements); err != nil {
				return fmt.Errorf("set add IPv4 elements: %w", err)
			}
		}
	}
	if ipSet6 != nil {
		conn.FlushSet(ipSet6)
		if len(v6Elements) > 0 {
			if err := conn.SetAddElements(ipSet6, v6Elements); err != nil {
				return fmt.Errorf("set add IPv6 elements: %w", err)
			}
		}
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush snapshot: %w", err)
	}

	log.Printf("[nft] applied snapshot: %d IPv4, %d IPv6", len(v4Elements), len(v6Elements)/2)
	return nil
}

// ── Set management ────────────────────────────────────────────────────────────

// ensureStaticSet syncs a static (always-allowed) set for one address family.
// When nets is non-empty (and the family is supported) the set is created if
// missing and populated with the configured networks. When nets is empty any
// existing set is flushed so stale entries are not left behind. Returns the set
// when it is populated (so a matching accept rule is installed), or nil.
func (m *Manager) ensureStaticSet(conn *nftables.Conn, table *nftables.Table, name string, keyType nftables.SetDatatype, nets []*net.IPNet, supported bool) (*nftables.Set, error) {
	if len(nets) > 0 && supported {
		set, err := m.findOrCreateSet(conn, table, name, keyType, true)
		if err != nil {
			return nil, fmt.Errorf("ensure static set %q: %w", name, err)
		}
		if err := m.applyStaticSet(conn, set, nets); err != nil {
			return nil, fmt.Errorf("apply static set %q: %w", name, err)
		}
		return set, nil
	}

	// Not configured for this family: flush the set if it exists.
	existing, _ := m.findSetByName(conn, table, name)
	if existing != nil {
		conn.FlushSet(existing)
		if err := conn.Flush(); err != nil {
			log.Printf("[nft] WARNING: flush stale static set %q: %v", name, err)
		}
	}
	return nil, nil
}

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

// applyStaticSet atomically replaces the static set contents with the supplied
// networks, encoded as half-open intervals (see prefixIntervalElements).
func (m *Manager) applyStaticSet(conn *nftables.Conn, staticSet *nftables.Set, nets []*net.IPNet) error {
	elements := netsToElements(nets)

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

// ── Chain rule management ─────────────────────────────────────────────────────

// ensureChainRules checks that the allowlist chain contains exactly the accept
// rules required by the current configuration (one per set in accepts) followed
// by a drop. If any required rule is missing, or a stale accept referencing a
// managed set that is no longer wanted remains (e.g. ALWAYS_ALLOW_IPS was
// removed for a family), the chain's rules are rebuilt atomically.
func (m *Manager) ensureChainRules(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain, accepts []acceptRule) error {
	rules, err := conn.GetRules(table, chain)
	if err != nil {
		return fmt.Errorf("get chain rules: %w", err)
	}

	// Set names an accept rule should exist for.
	expected := make(map[string]bool, len(accepts))
	for _, a := range accepts {
		expected[a.set.Name] = true
	}

	// All set names this manager owns, so we can detect stale accepts.
	managed := map[string]bool{
		tylerIPSetName:       true,
		tylerIPSetNameV6:     true,
		tylerStaticSetName:   true,
		tylerStaticSetNameV6: true,
	}

	present := make(map[string]bool, len(managed))
	hasDrop := false
	for _, rule := range rules {
		for name := range managed {
			if ruleLooksUpSet(rule, name) {
				present[name] = true
			}
		}
		if ruleIsVerdict(rule, expr.VerdictDrop) {
			hasDrop = true
		}
	}

	ok := hasDrop
	for name := range expected {
		if !present[name] {
			ok = false // missing a required accept
		}
	}
	for name := range present {
		if !expected[name] {
			ok = false // stale accept for a managed set we no longer want
		}
	}
	if ok {
		return nil
	}

	log.Printf("[nft] rebuilding rules in chain %q", chain.Name)

	// Delete all existing rules and re-add in correct order, atomically.
	for _, rule := range rules {
		if err := conn.DelRule(rule); err != nil {
			return fmt.Errorf("queue del chain rule: %w", err)
		}
	}
	for _, a := range accepts {
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: allowRuleExprs(a.set, a.family),
		})
	}
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
// rule exists in the "input" base chain, identified by its jump target. The
// match is on destination port only, so it applies to both IPv4 and IPv6.
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

// allowRuleExprs returns the expressions for "<family> saddr @<set> accept" in
// an inet table. The meta nfproto check restricts matching to the given family,
// which is required in inet tables and harmless in single-family tables. Used
// for both the dynamic IP sets and the static always-allowed sets.
func allowRuleExprs(set *nftables.Set, family byte) []expr.Any {
	// IPv6 source address is at network-header offset 8 (16 bytes); IPv4 is at
	// offset 12 (4 bytes).
	var offset, length uint32 = 12, 4
	if family == unix.NFPROTO_IPV6 {
		offset, length = 8, 16
	}
	return []expr.Any{
		// Restrict to the target family (required in inet tables).
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}},
		// Load the source address from the network header.
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offset,
			Len:          length,
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

// ── Element encoding ──────────────────────────────────────────────────────────

// parseIPElements converts a slice of allowlist entries into nftables
// SetElements, split by address family. IPv4 entries are single-host keys for
// the plain IPv4 set; IPv6 entries are /64 (or other) CIDR prefixes encoded as
// half-open intervals (two elements each) for the interval IPv6 set. Invalid or
// unsupported entries are counted as skipped.
func parseIPElements(ips []string) (v4, v6 []nftables.SetElement, skipped int) {
	for _, entry := range ips {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			skipped++
			continue
		}

		if strings.ContainsRune(entry, '/') {
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				skipped++
				continue
			}
			prefix = prefix.Masked()
			if prefix.Addr().Unmap().Is4() {
				// The IPv4 set is non-interval and cannot hold ranges; the web
				// app only ever emits single IPv4 hosts, so a v4 CIDR is
				// unexpected. Skip it rather than silently widen access.
				skipped++
				continue
			}
			elems := prefixIntervalElements(prefix)
			if elems == nil {
				skipped++
				continue
			}
			v6 = append(v6, elems...)
			continue
		}

		addr, err := netip.ParseAddr(entry)
		if err != nil {
			skipped++
			continue
		}
		addr = addr.Unmap()
		if addr.Is4() {
			v4 = append(v4, nftables.SetElement{Key: addr.AsSlice()})
			continue
		}
		// Bare IPv6 host — encode as a single-address /128 interval.
		elems := prefixIntervalElements(netip.PrefixFrom(addr.WithZone(""), 128))
		if elems == nil {
			skipped++
			continue
		}
		v6 = append(v6, elems...)
	}
	return v4, v6, skipped
}

// netsToElements converts a slice of networks into nftables interval
// SetElements (two per network). Entries that cannot be encoded are skipped.
func netsToElements(nets []*net.IPNet) []nftables.SetElement {
	elements := make([]nftables.SetElement, 0, len(nets)*2)
	for _, ipNet := range nets {
		p, ok := ipNetToPrefix(ipNet)
		if !ok {
			continue
		}
		elems := prefixIntervalElements(p)
		if elems == nil {
			continue
		}
		elements = append(elements, elems...)
	}
	return elements
}

// prefixIntervalElements encodes a network prefix as two half-open interval
// elements:
//
//	{Key: network address}                       // start (inclusive)
//	{Key: lastAddress + 1, IntervalEnd: true}    // end   (exclusive)
//
// Returns nil if the prefix spans to the very end of its address space (its
// exclusive upper bound would overflow), which never occurs for the /32–/128
// host and /64 network prefixes this system uses.
func prefixIntervalElements(p netip.Prefix) []nftables.SetElement {
	p = p.Masked()
	start := p.Addr().AsSlice()
	end := lastAddr(p).Next()
	if !end.IsValid() {
		return nil
	}
	return []nftables.SetElement{
		{Key: start},
		{Key: end.AsSlice(), IntervalEnd: true},
	}
}

// lastAddr returns the highest address contained in prefix p (its broadcast
// address for IPv4). p is assumed already masked.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	bits := p.Bits()
	for i := range b {
		lo := i * 8 // index of this byte's first bit
		if bits >= lo+8 {
			continue // byte lies entirely within the network portion
		}
		hostBits := 8
		if bits > lo {
			hostBits = lo + 8 - bits
		}
		b[i] |= byte(0xff >> (8 - hostBits))
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// ipNetToPrefix converts a *net.IPNet into a netip.Prefix.
func ipNetToPrefix(n *net.IPNet) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(addr.Unmap(), ones), true
}

// splitNetsByFamily partitions a slice of networks into IPv4 and IPv6 groups.
func splitNetsByFamily(nets []*net.IPNet) (v4, v6 []*net.IPNet) {
	for _, n := range nets {
		if n.IP.To4() != nil {
			v4 = append(v4, n)
		} else {
			v6 = append(v6, n)
		}
	}
	return v4, v6
}
