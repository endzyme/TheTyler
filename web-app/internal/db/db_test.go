package db

import (
	"context"
	"path/filepath"
	"testing"
)

func openTest(t *testing.T, ttlDays int) *DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "test.db")
	d, err := Open(dsn, ttlDays)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// Operator CIDRs are scoped per API key, deduped, hidden while the key is
// disabled, and removed when the key is deleted.
func TestAPIKeyCIDRs(t *testing.T) {
	ctx := context.Background()
	d := openTest(t, 90)

	id, err := d.CreateAPIKey(ctx, "server-1", "hash-1")
	if err != nil {
		t.Fatalf("create key: %v", err)
	}

	// Add two CIDRs; re-adding one is a no-op (UNIQUE + INSERT OR IGNORE).
	for _, c := range []string{"203.0.113.0/24", "10.0.0.0/8", "203.0.113.0/24"} {
		if err := d.AddAPIKeyCIDR(ctx, id, c); err != nil {
			t.Fatalf("add cidr %q: %v", c, err)
		}
	}

	byKey, err := d.ListAPIKeyCIDRsByKeyID(ctx)
	if err != nil {
		t.Fatalf("list by key id: %v", err)
	}
	if got := len(byKey[id]); got != 2 {
		t.Fatalf("expected 2 CIDRs for key, got %d (%v)", got, byKey[id])
	}

	hash, err := d.GetAPIKeyHash(ctx, id)
	if err != nil || hash != "hash-1" {
		t.Fatalf("GetAPIKeyHash = (%q, %v), want (hash-1, nil)", hash, err)
	}

	cidrs, err := d.ListCIDRsForKeyHash(ctx, "hash-1")
	if err != nil {
		t.Fatalf("list for hash: %v", err)
	}
	if len(cidrs) != 2 {
		t.Fatalf("expected 2 CIDRs for active key hash, got %d", len(cidrs))
	}

	// A disabled key contributes no CIDRs to a snapshot.
	if err := d.DisableAPIKey(ctx, id); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if cidrs, _ := d.ListCIDRsForKeyHash(ctx, "hash-1"); len(cidrs) != 0 {
		t.Fatalf("disabled key should contribute 0 CIDRs, got %d", len(cidrs))
	}
	if err := d.EnableAPIKey(ctx, id); err != nil {
		t.Fatalf("enable: %v", err)
	}

	// Remove one CIDR.
	if err := d.RemoveAPIKeyCIDR(ctx, id, "10.0.0.0/8"); err != nil {
		t.Fatalf("remove cidr: %v", err)
	}
	if cidrs, _ := d.ListCIDRsForKeyHash(ctx, "hash-1"); len(cidrs) != 1 || cidrs[0] != "203.0.113.0/24" {
		t.Fatalf("after remove got %v, want [203.0.113.0/24]", cidrs)
	}

	// Deleting a disabled key cascades to its CIDRs.
	if err := d.DisableAPIKey(ctx, id); err != nil {
		t.Fatalf("disable before delete: %v", err)
	}
	if err := d.DeleteDisabledAPIKey(ctx, id); err != nil {
		t.Fatalf("delete key: %v", err)
	}
	byKey, err = d.ListAPIKeyCIDRsByKeyID(ctx)
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	if got := len(byKey[id]); got != 0 {
		t.Fatalf("expected CIDRs purged after key delete, got %d", got)
	}
}

// A user authorizing the same IP repeatedly must not accumulate duplicate rows
// (bug: refresh added a new record every time).
func TestUpsertIPRecordDedupes(t *testing.T) {
	ctx := context.Background()
	d := openTest(t, 90)

	for i := 0; i < 3; i++ {
		if err := d.UpsertIPRecord(ctx, "a@example.com", "203.0.113.5"); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
	}

	recs, err := d.ListIPRecords(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record after repeated upserts, got %d", len(recs))
	}
	if recs[0].Expired {
		t.Fatalf("fresh record should be live, got expired")
	}
}

// Removing one user's (email, ip) combination must not delete another user's
// authorization of the same IP (bug: delete removed all rows for the IP).
func TestRemoveIPRecordScopedToCombo(t *testing.T) {
	ctx := context.Background()
	d := openTest(t, 90)

	if err := d.UpsertIPRecord(ctx, "a@example.com", "203.0.113.5"); err != nil {
		t.Fatalf("upsert a: %v", err)
	}
	if err := d.UpsertIPRecord(ctx, "b@example.com", "203.0.113.5"); err != nil {
		t.Fatalf("upsert b: %v", err)
	}

	if err := d.RemoveIPRecord(ctx, "a@example.com", "203.0.113.5"); err != nil {
		t.Fatalf("remove: %v", err)
	}

	recs, err := d.ListIPRecords(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(recs) != 1 || recs[0].Email != "b@example.com" {
		t.Fatalf("expected only b's record to remain, got %+v", recs)
	}

	// The IP is still shared/active via b, so the snapshot must still include it.
	ips, err := d.GetActiveIPs(ctx)
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if len(ips) != 1 || ips[0] != "203.0.113.5" {
		t.Fatalf("expected IP still active via b, got %v", ips)
	}
}

// Expired records must report expired status, drop out of the active snapshot,
// and be surfaced for one-time expiry notification.
func TestExpiryStatusAndNotification(t *testing.T) {
	ctx := context.Background()
	// A zero-day TTL makes any freshly-authorized record already expired
	// (authed_at <= now), which lets us exercise the expiry paths deterministically.
	d := openTest(t, 0)

	if err := d.AddAuthorizedEmail(ctx, "a@example.com"); err != nil {
		t.Fatalf("add email: %v", err)
	}
	if err := d.UpsertIPRecord(ctx, "a@example.com", "203.0.113.5"); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	rec, err := d.GetIPRecord(ctx, "a@example.com", "203.0.113.5")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if rec == nil || !rec.Expired {
		t.Fatalf("expected expired record, got %+v", rec)
	}

	ips, err := d.GetActiveIPs(ctx)
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if len(ips) != 0 {
		t.Fatalf("expected no active IPs, got %v", ips)
	}

	emails, err := d.ListExpiredUnnotifiedEmails(ctx)
	if err != nil {
		t.Fatalf("list expired: %v", err)
	}
	if len(emails) != 1 || emails[0] != "a@example.com" {
		t.Fatalf("expected a@example.com unnotified, got %v", emails)
	}

	if err := d.MarkExpiredNotifiedForEmail(ctx, "a@example.com"); err != nil {
		t.Fatalf("mark notified: %v", err)
	}

	// Once notified it should not be listed again...
	emails, err = d.ListExpiredUnnotifiedEmails(ctx)
	if err != nil {
		t.Fatalf("list expired 2: %v", err)
	}
	if len(emails) != 0 {
		t.Fatalf("expected no unnotified emails after marking, got %v", emails)
	}

	// ...until the user refreshes, which clears the notification flag so a
	// future lapse can notify again.
	if err := d.UpsertIPRecord(ctx, "a@example.com", "203.0.113.5"); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	emails, err = d.ListExpiredUnnotifiedEmails(ctx)
	if err != nil {
		t.Fatalf("list expired 3: %v", err)
	}
	if len(emails) != 1 {
		t.Fatalf("expected refresh to re-arm notification, got %v", emails)
	}
}

// An email removed from the authorized list must not receive an expiry notice,
// even though its expired records still linger in the DB.
func TestExpiryNotificationSkipsUnauthorizedEmail(t *testing.T) {
	ctx := context.Background()
	d := openTest(t, 0) // fresh records are immediately expired

	if err := d.AddAuthorizedEmail(ctx, "a@example.com"); err != nil {
		t.Fatalf("add email: %v", err)
	}
	if err := d.UpsertIPRecord(ctx, "a@example.com", "203.0.113.5"); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	emails, err := d.ListExpiredUnnotifiedEmails(ctx)
	if err != nil {
		t.Fatalf("list expired: %v", err)
	}
	if len(emails) != 1 || emails[0] != "a@example.com" {
		t.Fatalf("expected authorized email to be notifiable, got %v", emails)
	}

	// Admin removes the user; their expired record still exists, but they must
	// no longer be surfaced for notification.
	if err := d.RemoveAuthorizedEmail(ctx, "a@example.com"); err != nil {
		t.Fatalf("remove email: %v", err)
	}
	emails, err = d.ListExpiredUnnotifiedEmails(ctx)
	if err != nil {
		t.Fatalf("list expired 2: %v", err)
	}
	if len(emails) != 0 {
		t.Fatalf("expected removed email to be skipped, got %v", emails)
	}
}

// Removing an authorized email must revoke access immediately by deleting that
// email's IP records, so they drop out of the active snapshot at once — but
// must not disturb another user's records.
func TestRemoveAuthorizedEmailPurgesIPs(t *testing.T) {
	ctx := context.Background()
	d := openTest(t, 90)

	for _, e := range []string{"a@example.com", "b@example.com"} {
		if err := d.AddAuthorizedEmail(ctx, e); err != nil {
			t.Fatalf("add email %s: %v", e, err)
		}
	}
	if err := d.UpsertIPRecord(ctx, "a@example.com", "203.0.113.5"); err != nil {
		t.Fatalf("upsert a: %v", err)
	}
	if err := d.UpsertIPRecord(ctx, "b@example.com", "203.0.113.9"); err != nil {
		t.Fatalf("upsert b: %v", err)
	}

	if err := d.RemoveAuthorizedEmail(ctx, "a@example.com"); err != nil {
		t.Fatalf("remove: %v", err)
	}

	recs, err := d.ListIPRecords(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(recs) != 1 || recs[0].Email != "b@example.com" {
		t.Fatalf("expected only b's record to remain, got %+v", recs)
	}

	ips, err := d.GetActiveIPs(ctx)
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if len(ips) != 1 || ips[0] != "203.0.113.9" {
		t.Fatalf("expected only b's IP active, got %v", ips)
	}
}

func TestGetIPRecordMissing(t *testing.T) {
	ctx := context.Background()
	d := openTest(t, 90)

	rec, err := d.GetIPRecord(ctx, "nobody@example.com", "203.0.113.9")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if rec != nil {
		t.Fatalf("expected nil for unknown combo, got %+v", rec)
	}
}
