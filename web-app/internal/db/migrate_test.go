package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// Deployments auto-update in place, so migrate() runs against databases created
// by older releases rather than a fresh file. This builds a database with the
// pre-release schema — api_keys.revoked_at instead of disabled_at, no
// last_action_at, no ip_records.expiry_notified_at, no unique (email, ip) index,
// and no api_key_cidrs table — seeds it with data that exercises each migration
// step, then opens it with the current code and asserts the upgrade lands
// cleanly and is idempotent.
func TestMigrateOntoOldSchema(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "old.db")
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`
CREATE TABLE IF NOT EXISTS authorized_emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE TABLE IF NOT EXISTS ip_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    ip TEXT NOT NULL,
    authed_at DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    revoked_at DATETIME
);
CREATE TABLE IF NOT EXISTS used_tokens (
    token_hash TEXT PRIMARY KEY,
    used_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
INSERT INTO api_keys (name, key_hash) VALUES ('active','h1');
INSERT INTO api_keys (name, key_hash, revoked_at)
    VALUES ('legacy-revoked','h2','2024-03-01T00:00:00Z');
-- Duplicate (email, ip) rows, legal before the unique index was introduced.
INSERT INTO ip_records (email, ip, authed_at) VALUES ('a@b.c','1.2.3.4','2024-01-01T00:00:00Z');
INSERT INTO ip_records (email, ip, authed_at) VALUES ('a@b.c','1.2.3.4','2024-02-01T00:00:00Z');
`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	d, err := Open(dsn, 90)
	if err != nil {
		t.Fatalf("migrate onto old schema: %v", err)
	}
	defer d.Close()

	ctx := context.Background()

	// Duplicate (email, ip) rows collapse to the most recent authorization so
	// the unique index can be created.
	recs, err := d.ListIPRecords(ctx)
	if err != nil {
		t.Fatalf("list ip records: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected duplicate rows collapsed to 1, got %d", len(recs))
	}

	keys, err := d.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("list keys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys carried over, got %d", len(keys))
	}

	// The legacy revoked_at column is backfilled into disabled_at, so a key
	// revoked under the old schema stays disabled after the upgrade.
	byName := map[string]APIKey{}
	for _, k := range keys {
		byName[k.Name] = k
	}
	if byName["legacy-revoked"].DisabledAt == nil {
		t.Fatal("legacy revoked_at was not backfilled into disabled_at")
	}
	if byName["active"].DisabledAt != nil {
		t.Fatal("active key should not be disabled after migration")
	}

	// The table added by this release exists on the upgraded database and is
	// usable against a key that predates it.
	active := byName["active"]
	if err := d.AddAPIKeyCIDR(ctx, active.ID, "10.0.0.0/8"); err != nil {
		t.Fatalf("add cidr to pre-existing key: %v", err)
	}
	cidrs, err := d.ListCIDRsForKeyHash(ctx, "h1")
	if err != nil {
		t.Fatalf("list cidrs: %v", err)
	}
	if len(cidrs) != 1 || cidrs[0] != "10.0.0.0/8" {
		t.Fatalf("cidrs = %v, want [10.0.0.0/8]", cidrs)
	}
	// A key disabled by the backfill contributes no CIDRs to a snapshot.
	if err := d.AddAPIKeyCIDR(ctx, byName["legacy-revoked"].ID, "192.0.2.0/24"); err != nil {
		t.Fatalf("add cidr to legacy key: %v", err)
	}
	if got, _ := d.ListCIDRsForKeyHash(ctx, "h2"); len(got) != 0 {
		t.Fatalf("disabled key contributed cidrs: %v", got)
	}

	// Re-opening an already-upgraded database must be a no-op, since every
	// start-up runs migrate() again.
	d.Close()
	d2, err := Open(dsn, 90)
	if err != nil {
		t.Fatalf("re-migrate already-upgraded db: %v", err)
	}
	d2.Close()
}
