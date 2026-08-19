package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestGateDecisionMigrationIsAppendOnlyOrderedAndGuarded(t *testing.T) {
	protected := map[string]string{
		"0001_migration_ledger.sql":                "2b70b218b73e9e343e44d068be095ef755a5328e0a315cf42ec3a01704fd2029",
		"0002_accounts_and_sync_cursors.sql":       "e416fd942cde37ba7f68ead02e7f78ea1813ff73c49193b564f089f0e3244be3",
		"0003_provider_credentials.sql":            "915f79daa5afb2c280428dd11e6de6a929892a3d3d34bbeda18845ae5f3d90b4",
		"0004_account_lifecycle.sql":               "5502fd21bc363148bce724ef2ea177efc2cb70b1feb0389500cb0bdf21e163d9",
		"0005_current_discovery_atomic_commit.sql": "1a56e9d98eb138e7dce0ba38a04bc7b5056fa068efebed5df59dcd80f7f0d68c",
	}
	for name, want := range protected {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Fatalf("%s checksum = %s, want %s", name, got, want)
		}
	}
	catalog, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog) != 7 || catalog[5].Number != 6 || catalog[5].Name != "0006_gate_decisions.sql" {
		t.Fatalf("catalog count = %d, want retained migration 0006 followed by append-only migration 0007", len(catalog))
	}
	if catalog[5].Checksum != "846a62f6a8533d8a9005e25d5cf2ed5922c3d4ee9d7bfff344bf9e1885d1a48f" {
		t.Fatalf("migration 0006 checksum = %s", catalog[5].Checksum)
	}
	schema := catalog[5].SQL
	for _, required := range []string{
		"CREATE TABLE inboxgate_gate_decisions",
		"record_id TEXT COLLATE BINARY PRIMARY KEY",
		"length(CAST(record_id AS BLOB)) = 64",
		"instr(CAST(record_id AS BLOB), x'00') = 0",
		"gate_version INTEGER NOT NULL",
		"gate_version BETWEEN 1 AND 4294967295",
		"source_metadata_hash TEXT COLLATE BINARY NOT NULL",
		"input_hash TEXT COLLATE BINARY NOT NULL",
		"length(CAST(source_metadata_hash AS BLOB)) = 64",
		"source_metadata_hash NOT GLOB '*[^0-9a-f]*'",
		"length(CAST(input_hash AS BLOB)) = 64",
		"input_hash NOT GLOB '*[^0-9a-f]*'",
		"outcome IN ('ignore', 'metadata_only', 'review_candidate', 'urgent_review_candidate')",
		"reason_codes TEXT COLLATE BINARY NOT NULL",
		"length(CAST(reason_codes AS BLOB)) BETWEEN 2 AND 512",
		"instr(CAST(reason_codes AS BLOB), x'00') = 0",
		"evaluated_at_unix_ms INTEGER NOT NULL",
		"evaluated_at_unix_ms BETWEEN 0 AND 253402300799999",
		"FOREIGN KEY (record_id) REFERENCES inboxgate_messages (record_id) ON DELETE RESTRICT",
		"STRICT, WITHOUT ROWID",
	} {
		if !strings.Contains(schema, required) {
			t.Fatalf("migration 0006 missing %q", required)
		}
	}
	for _, forbidden := range []string{"json_", "ON DELETE CASCADE", "CREATE INDEX", "history", "DROP ", "ALTER "} {
		if strings.Contains(schema, forbidden) {
			t.Fatalf("migration 0006 contains forbidden %q", forbidden)
		}
	}
}
