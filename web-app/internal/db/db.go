package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

var ErrTokenAlreadyUsed = errors.New("token already used")

type DB struct {
	sql       *sql.DB
	ipTTLDays int
}

type AuthorizedEmail struct {
	ID        int64
	Email     string
	CreatedAt time.Time
}

type IPRecord struct {
	ID       int64
	Email    string
	IP       string
	AuthedAt time.Time
}

type APIKey struct {
	ID           int64
	Name         string
	KeyHash      string
	CreatedAt    time.Time
	DisabledAt   *time.Time
	LastActionAt *time.Time
}

func Open(dsn string, ipTTLDays int) (*DB, error) {
	dir := filepath.Dir(dsn)
	// Strip file: prefix and query params for directory creation
	dirPath := dir
	if len(dirPath) > 5 && dirPath[:5] == "file:" {
		dirPath = dirPath[5:]
	}
	if dirPath != "" && dirPath != "." {
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return nil, fmt.Errorf("db: mkdir %s: %w", dirPath, err)
		}
	}

	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}

	// SQLite WAL mode works best with a single writer connection for HTTP handlers
	// and multiple readers for gRPC. Set max open connections sensibly.
	sqlDB.SetMaxOpenConns(1)

	db := &DB{sql: sqlDB, ipTTLDays: ipTTLDays}
	if err := db.migrate(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("db: migrate: %w", err)
	}

	return db, nil
}

func (d *DB) Close() error {
	return d.sql.Close()
}

func (d *DB) migrate() error {
	_, err := d.sql.Exec(`
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
	disabled_at DATETIME,
	last_action_at DATETIME
);

CREATE TABLE IF NOT EXISTS used_tokens (
    token_hash TEXT PRIMARY KEY,
    used_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
`)
	if err != nil {
		return err
	}

	if err := d.ensureAPIKeysColumn("disabled_at", "DATETIME"); err != nil {
		return err
	}

	if err := d.ensureAPIKeysColumn("last_action_at", "DATETIME"); err != nil {
		return err
	}

	hasRevokedAt, err := d.apiKeysHasColumn("revoked_at")
	if err != nil {
		return err
	}
	if hasRevokedAt {
		if _, err := d.sql.Exec(`
UPDATE api_keys
SET disabled_at = revoked_at
WHERE disabled_at IS NULL AND revoked_at IS NOT NULL
`); err != nil {
			return err
		}
	}

	return nil
}

func (d *DB) ensureAPIKeysColumn(name, typ string) error {
	hasColumn, err := d.apiKeysHasColumn(name)
	if err != nil {
		return err
	}
	if hasColumn {
		return nil
	}

	_, err = d.sql.Exec(fmt.Sprintf(`ALTER TABLE api_keys ADD COLUMN %s %s`, name, typ))
	return err
}

func (d *DB) apiKeysHasColumn(name string) (bool, error) {
	rows, err := d.sql.Query(`PRAGMA table_info(api_keys)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var columnName, columnType string
		var notNull int
		var dfltValue any
		var pk int
		if err := rows.Scan(&cid, &columnName, &columnType, &notNull, &dfltValue, &pk); err != nil {
			return false, err
		}
		if columnName == name {
			return true, nil
		}
	}

	if err := rows.Err(); err != nil {
		return false, err
	}

	return false, nil
}

// Emails

func (d *DB) IsEmailAuthorized(ctx context.Context, email string) (bool, error) {
	var count int
	err := d.sql.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM authorized_emails WHERE email = ?`, email,
	).Scan(&count)
	return count > 0, err
}

func (d *DB) AddAuthorizedEmail(ctx context.Context, email string) error {
	_, err := d.sql.ExecContext(ctx,
		`INSERT OR IGNORE INTO authorized_emails (email) VALUES (?)`, email,
	)
	return err
}

func (d *DB) RemoveAuthorizedEmail(ctx context.Context, email string) error {
	_, err := d.sql.ExecContext(ctx,
		`DELETE FROM authorized_emails WHERE email = ?`, email,
	)
	return err
}

func (d *DB) ListAuthorizedEmails(ctx context.Context) ([]AuthorizedEmail, error) {
	rows, err := d.sql.QueryContext(ctx,
		`SELECT id, email, created_at FROM authorized_emails ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuthorizedEmail
	for rows.Next() {
		var e AuthorizedEmail
		var createdStr string
		if err := rows.Scan(&e.ID, &e.Email, &createdStr); err != nil {
			return nil, err
		}
		e.CreatedAt, _ = time.Parse("2006-01-02T15:04:05Z", createdStr)
		out = append(out, e)
	}
	return out, rows.Err()
}

// IPs

func (d *DB) AddIPRecord(ctx context.Context, email, ip string) error {
	_, err := d.sql.ExecContext(ctx,
		`INSERT INTO ip_records (email, ip, authed_at) VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
		email, ip,
	)
	return err
}

func (d *DB) GetActiveIPs(ctx context.Context) ([]string, error) {
	rows, err := d.sql.QueryContext(ctx,
		fmt.Sprintf(`SELECT DISTINCT ip FROM ip_records WHERE authed_at > strftime('%%Y-%%m-%%dT%%H:%%M:%%SZ','now','-%d days')`, d.ipTTLDays),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}

func (d *DB) RefreshIPRecord(ctx context.Context, email, ip string) error {
	_, err := d.sql.ExecContext(ctx, `
UPDATE ip_records SET authed_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
WHERE id = (
    SELECT id FROM ip_records WHERE email = ? AND ip = ? ORDER BY authed_at DESC LIMIT 1
)`, email, ip)
	return err
}

func (d *DB) IsIPActive(ctx context.Context, ip string) (bool, error) {
	var count int
	err := d.sql.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT COUNT(*) FROM ip_records WHERE ip = ? AND authed_at > strftime('%%Y-%%m-%%dT%%H:%%M:%%SZ','now','-%d days')`, d.ipTTLDays),
		ip,
	).Scan(&count)
	return count > 0, err
}

func (d *DB) ListIPRecords(ctx context.Context) ([]IPRecord, error) {
	rows, err := d.sql.QueryContext(ctx,
		`SELECT id, email, ip, authed_at FROM ip_records ORDER BY authed_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []IPRecord
	for rows.Next() {
		var r IPRecord
		var authedStr string
		if err := rows.Scan(&r.ID, &r.Email, &r.IP, &authedStr); err != nil {
			return nil, err
		}
		r.AuthedAt, _ = time.Parse("2006-01-02T15:04:05Z", authedStr)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (d *DB) RemoveIPRecordsByIP(ctx context.Context, ip string) error {
	_, err := d.sql.ExecContext(ctx,
		`DELETE FROM ip_records WHERE ip = ?`, ip,
	)
	return err
}

// Tokens

func (d *DB) MarkTokenUsed(ctx context.Context, tokenHash string) error {
	_, err := d.sql.ExecContext(ctx,
		`INSERT INTO used_tokens (token_hash) VALUES (?)`, tokenHash,
	)
	if err != nil && isUniqueConstraintErr(err) {
		return ErrTokenAlreadyUsed
	}
	return err
}

func (d *DB) IsTokenUsed(ctx context.Context, tokenHash string) (bool, error) {
	var count int
	err := d.sql.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM used_tokens WHERE token_hash = ?`, tokenHash,
	).Scan(&count)
	return count > 0, err
}

func (d *DB) DeleteExpiredTokens(ctx context.Context, olderThan time.Duration) error {
	cutoff := time.Now().Add(-olderThan).UTC().Format("2006-01-02T15:04:05Z")
	_, err := d.sql.ExecContext(ctx,
		`DELETE FROM used_tokens WHERE used_at < ?`, cutoff,
	)
	return err
}

// API Keys

func (d *DB) CreateAPIKey(ctx context.Context, name, keyHash string) (int64, error) {
	res, err := d.sql.ExecContext(ctx,
		`INSERT INTO api_keys (name, key_hash) VALUES (?, ?)`, name, keyHash,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	rows, err := d.sql.QueryContext(ctx,
		`SELECT id, name, key_hash, created_at, disabled_at, last_action_at FROM api_keys ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []APIKey
	for rows.Next() {
		var k APIKey
		var createdStr string
		var disabledStr *string
		var lastActionStr *string
		if err := rows.Scan(&k.ID, &k.Name, &k.KeyHash, &createdStr, &disabledStr, &lastActionStr); err != nil {
			return nil, err
		}
		k.CreatedAt, _ = time.Parse("2006-01-02T15:04:05Z", createdStr)
		if disabledStr != nil {
			t, _ := time.Parse("2006-01-02T15:04:05Z", *disabledStr)
			k.DisabledAt = &t
		}
		if lastActionStr != nil {
			t, _ := time.Parse("2006-01-02T15:04:05Z", *lastActionStr)
			k.LastActionAt = &t
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (d *DB) DisableAPIKey(ctx context.Context, id int64) error {
	_, err := d.sql.ExecContext(ctx,
		`UPDATE api_keys SET disabled_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = ? AND disabled_at IS NULL`,
		id,
	)
	return err
}

func (d *DB) EnableAPIKey(ctx context.Context, id int64) error {
	_, err := d.sql.ExecContext(ctx,
		`UPDATE api_keys SET disabled_at = NULL WHERE id = ? AND disabled_at IS NOT NULL`,
		id,
	)
	return err
}

func (d *DB) DeleteDisabledAPIKey(ctx context.Context, id int64) error {
	_, err := d.sql.ExecContext(ctx,
		`DELETE FROM api_keys WHERE id = ? AND disabled_at IS NOT NULL`,
		id,
	)
	return err
}

func (d *DB) MarkAPIKeyActivityByHash(ctx context.Context, keyHash string) error {
	_, err := d.sql.ExecContext(ctx,
		`UPDATE api_keys SET last_action_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE key_hash = ?`,
		keyHash,
	)
	return err
}

func (d *DB) ListActiveKeyHashes(ctx context.Context) ([]string, error) {
	rows, err := d.sql.QueryContext(ctx,
		`SELECT key_hash FROM api_keys WHERE disabled_at IS NULL`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		hashes = append(hashes, h)
	}
	return hashes, rows.Err()
}

func isUniqueConstraintErr(err error) bool {
	if err == nil {
		return false
	}
	return contains(err.Error(), "UNIQUE constraint failed") ||
		contains(err.Error(), "unique constraint")
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsAt(s, sub))
}

func containsAt(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
