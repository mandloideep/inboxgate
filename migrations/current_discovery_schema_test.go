package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestCurrentDiscoveryMigrationIsAppendOnlyAndProtected(t *testing.T) {
	want := map[string]string{
		"0001_migration_ledger.sql":          "2b70b218b73e9e343e44d068be095ef755a5328e0a315cf42ec3a01704fd2029",
		"0002_accounts_and_sync_cursors.sql": "e416fd942cde37ba7f68ead02e7f78ea1813ff73c49193b564f089f0e3244be3",
		"0003_provider_credentials.sql":      "915f79daa5afb2c280428dd11e6de6a929892a3d3d34bbeda18845ae5f3d90b4",
		"0004_account_lifecycle.sql":         "5502fd21bc363148bce724ef2ea177efc2cb70b1feb0389500cb0bdf21e163d9",
	}
	for name, checksum := range want {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != checksum {
			t.Fatalf("%s checksum = %s, want protected %s", name, got, checksum)
		}
	}
	catalog, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog) != 5 || catalog[4].Name != "0005_current_discovery_atomic_commit.sql" {
		t.Fatalf("catalog = %#v, want append-only migration 0005", catalog)
	}
}

func TestCurrentDiscoveryMigrationPublishesExactAtomicBoundary(t *testing.T) {
	catalog, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog) < 5 {
		t.Fatalf("catalog count = %d, want migration 0005", len(catalog))
	}
	schema := catalog[4].SQL
	for _, required := range []string{
		"CREATE TABLE inboxgate_messages",
		"UNIQUE (account_id, gmail_message_id)",
		"CREATE TABLE inboxgate_current_sync_attempts",
		"UNIQUE (account_id)",
		"state IN ('open', 'sealed')",
		"CREATE TABLE inboxgate_current_sync_staging",
		"manifest_witness TEXT COLLATE BINARY NOT NULL",
		"row_witness TEXT COLLATE BINARY NOT NULL",
		"CREATE TRIGGER inboxgate_current_sync_attempt_insert_open",
		"WHEN NEW.state <> 'open'",
		"CREATE TRIGGER inboxgate_current_sync_attempt_seal",
		"OLD.manifest_witness = NEW.manifest_witness",
		"group_concat(ordered.row_witness, '')",
		"ORDER BY staging.ordinal",
		"CREATE TRIGGER inboxgate_current_sync_staging_immutable",
		"current discovery staging immutable",
		"lower(hex(CAST(staging.metadata_json AS BLOB)))",
		"UNIQUE (account_id, attempt_id, gmail_message_id)",
		"UNIQUE (account_id, attempt_id, record_id)",
		"CREATE VIEW inboxgate_current_sync_finalize",
		"INSTEAD OF INSERT ON inboxgate_current_sync_finalize",
		"INSERT INTO inboxgate_messages",
		"UPDATE inboxgate_synchronization_cursors",
		"DELETE FROM inboxgate_current_sync_staging",
		"DELETE FROM inboxgate_current_sync_attempts",
		"CREATE VIEW inboxgate_current_sync_abort",
		"INSTEAD OF INSERT ON inboxgate_current_sync_abort",
		"lifecycle.state = 'active'",
		"current discovery integrity",
		"CREATE TRIGGER inboxgate_account_lifecycle_current_sync_cleanup",
		"NEW.state = 'revoked'",
		"ON DELETE RESTRICT",
		"STRICT",
	} {
		if !strings.Contains(schema, required) {
			t.Fatalf("migration 0005 does not contain %q", required)
		}
	}
	for _, forbidden := range []string{"json_", "BEGIN TRANSACTION", "COMMIT TRANSACTION", "ON DELETE CASCADE", "committed_record_id", "committed_metadata_hash"} {
		if strings.Contains(schema, forbidden) {
			t.Fatalf("migration 0005 contains forbidden SQL %q", forbidden)
		}
	}
}
