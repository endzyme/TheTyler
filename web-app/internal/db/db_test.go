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
