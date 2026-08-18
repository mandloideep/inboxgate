package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"unicode/utf8"
)

func TestEmbeddedCatalogIsCanonicalAndExactByteChecksummed(t *testing.T) {
	t.Parallel()

	catalog, err := Catalog()
	if err != nil {
		t.Fatalf("Catalog() error = %v", err)
	}
	if len(catalog) != 5 {
		t.Fatalf("Catalog() count = %d, want 5", len(catalog))
	}
	migration := catalog[0]
	if migration.Number != 1 || migration.Name != "0001_migration_ledger.sql" {
		t.Fatalf("Catalog()[0] = %#v, want canonical migration 1", migration)
	}
	raw, err := fs.ReadFile(embedded, migration.Name)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); migration.Checksum != got {
		t.Fatalf("checksum = %q, want exact-byte checksum %q", migration.Checksum, got)
	}
	if migration.SQL != string(raw) {
		t.Fatal("catalog SQL differs from embedded bytes")
	}
	accountSchema := catalog[1]
	if accountSchema.Number != 2 || accountSchema.Name != "0002_accounts_and_sync_cursors.sql" {
		t.Fatalf("Catalog()[1] = %#v, want canonical migration 2", accountSchema)
	}
	raw, err = fs.ReadFile(embedded, accountSchema.Name)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	sum = sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); accountSchema.Checksum != got {
		t.Fatalf("checksum = %q, want exact-byte checksum %q", accountSchema.Checksum, got)
	}
	if accountSchema.SQL != string(raw) {
		t.Fatal("account schema SQL differs from embedded bytes")
	}
	for _, required := range []string{
		"CREATE TABLE inboxgate_accounts",
		"length(CAST(account_id AS BLOB)) = 32",
		"instr(CAST(account_id AS BLOB), x'00') = 0",
		"provider = 'gmail'",
		"provider_subject TEXT COLLATE BINARY",
		"length(CAST(provider_subject AS BLOB)) BETWEEN 1 AND 255",
		"instr(CAST(provider_subject AS BLOB), x'00') = 0",
		"provider_subject NOT GLOB '*[^!-~]*'",
		"UNIQUE (provider, provider_subject)",
		"CREATE TABLE inboxgate_synchronization_cursors",
		"history_id TEXT COLLATE BINARY",
		"length(CAST(history_id AS BLOB)) BETWEEN 1 AND 20",
		"instr(CAST(history_id AS BLOB), x'00') = 0",
		"history_id NOT GLOB '*[^0-9]*'",
		"substr(history_id, 1, 1) BETWEEN '1' AND '9'",
		"history_id <= '18446744073709551615'",
		"FOREIGN KEY (account_id) REFERENCES inboxgate_accounts (account_id) ON DELETE RESTRICT",
	} {
		if !strings.Contains(accountSchema.SQL, required) {
			t.Fatalf("account schema does not contain %q", required)
		}
	}
	credentialSchema := catalog[2]
	if credentialSchema.Number != 3 || credentialSchema.Name != "0003_provider_credentials.sql" {
		t.Fatalf("Catalog()[2] = %#v, want canonical migration 3", credentialSchema)
	}
	raw, err = fs.ReadFile(embedded, credentialSchema.Name)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	sum = sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); credentialSchema.Checksum != got {
		t.Fatalf("credential checksum = %q, want exact-byte checksum %q", credentialSchema.Checksum, got)
	}
	if credentialSchema.SQL != string(raw) {
		t.Fatal("credential schema SQL differs from embedded bytes")
	}
	for _, required := range []string{
		"CREATE TABLE inboxgate_provider_credentials",
		"account_id TEXT PRIMARY KEY",
		"length(CAST(account_id AS BLOB)) = 32",
		"instr(CAST(account_id AS BLOB), x'00') = 0",
		"key_id TEXT COLLATE BINARY NOT NULL",
		"length(CAST(key_id AS BLOB)) BETWEEN 1 AND 32",
		"instr(CAST(key_id AS BLOB), x'00') = 0",
		"envelope TEXT COLLATE BINARY NOT NULL",
		"length(CAST(envelope AS BLOB)) BETWEEN 55 AND 5556",
		"substr(envelope, 1, 5) = 'igc1.'",
		"FOREIGN KEY (account_id) REFERENCES inboxgate_accounts (account_id) ON DELETE RESTRICT",
	} {
		if !strings.Contains(credentialSchema.SQL, required) {
			t.Fatalf("credential schema does not contain %q", required)
		}
	}
	lifecycleSchema := catalog[3]
	if lifecycleSchema.Number != 4 || lifecycleSchema.Name != "0004_account_lifecycle.sql" {
		t.Fatalf("Catalog()[3] = %#v, want canonical migration 4", lifecycleSchema)
	}
	raw, err = fs.ReadFile(embedded, lifecycleSchema.Name)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	sum = sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); lifecycleSchema.Checksum != got {
		t.Fatalf("lifecycle checksum = %q, want exact-byte checksum %q", lifecycleSchema.Checksum, got)
	}
	if lifecycleSchema.SQL != string(raw) {
		t.Fatal("lifecycle schema SQL differs from embedded bytes")
	}
	for _, required := range []string{
		"CREATE TABLE inboxgate_account_lifecycle",
		"state TEXT COLLATE BINARY NOT NULL",
		"state_version INTEGER NOT NULL",
		"state_version BETWEEN 1 AND 9223372036854775807",
		"reauthorization_reason TEXT COLLATE BINARY",
		"revocation_status TEXT COLLATE BINARY NOT NULL",
		"state = 'reauthorization_required'",
		"reason = 'refresh_invalid_grant'",
		"reason = 'refresh_admin_policy_enforced'",
		"reason = 'gmail_unauthorized_after_refresh'",
		"reason = 'gmail_domain_policy'",
		"revocation_status IN ('pending', 'attempting', 'confirmed', 'manual_action_required')",
		"INSERT INTO inboxgate_account_lifecycle",
		"WHEN EXISTS (SELECT 1 FROM inboxgate_synchronization_cursors",
		"AND EXISTS (SELECT 1 FROM inboxgate_provider_credentials",
		"CREATE TRIGGER inboxgate_accounts_lifecycle_after_insert",
		"AFTER INSERT ON inboxgate_accounts",
		"VALUES (NEW.account_id, 'pending', 1, NULL, 'none')",
	} {
		if !strings.Contains(lifecycleSchema.SQL, required) {
			t.Fatalf("lifecycle schema does not contain %q", required)
		}
	}
}

func TestCatalogRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	validLedger := []byte("SELECT 1;\n")
	tests := []struct {
		name   string
		source fs.FS
	}{
		{name: "empty", source: fstest.MapFS{}},
		{name: "wrong first name", source: fstest.MapFS{"0001_other.sql": &fstest.MapFile{Data: validLedger}}},
		{name: "uppercase", source: fstest.MapFS{"0001_Migration_ledger.sql": &fstest.MapFile{Data: validLedger}}},
		{name: "missing number", source: fstest.MapFS{
			"0001_migration_ledger.sql": &fstest.MapFile{Data: validLedger},
			"0003_later.sql":            &fstest.MapFile{Data: validLedger},
		}},
		{name: "empty file", source: fstest.MapFS{"0001_migration_ledger.sql": &fstest.MapFile{}}},
		{name: "non utf8", source: fstest.MapFS{"0001_migration_ledger.sql": &fstest.MapFile{Data: []byte{utf8.RuneSelf, 0xff}}}},
		{name: "nul", source: fstest.MapFS{"0001_migration_ledger.sql": &fstest.MapFile{Data: []byte("SELECT\x00 1")}}},
		{name: "oversized file", source: fstest.MapFS{"0001_migration_ledger.sql": &fstest.MapFile{Data: []byte(strings.Repeat("x", MaximumFileBytes+1))}}},
		{name: "non sql entry", source: fstest.MapFS{"0001_migration_ledger.sql": &fstest.MapFile{Data: validLedger}, "notes.txt": &fstest.MapFile{Data: validLedger}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := loadCatalog(tt.source); !errors.Is(err, ErrInvalidCatalog) {
				t.Fatalf("loadCatalog() error = %v, want ErrInvalidCatalog", err)
			}
		})
	}
}

func TestCatalogRejectsTooManyFiles(t *testing.T) {
	t.Parallel()

	source := make(fstest.MapFS, MaximumCount+1)
	for number := 1; number <= MaximumCount+1; number++ {
		name := fmt.Sprintf("%04d_migration.sql", number)
		source[name] = &fstest.MapFile{Data: []byte("SELECT 1;\n")}
	}
	if _, err := loadCatalog(source); !errors.Is(err, ErrInvalidCatalog) {
		t.Fatalf("loadCatalog() error = %v, want ErrInvalidCatalog", err)
	}
}

func TestCatalogRejectsOversizedTotal(t *testing.T) {
	t.Parallel()

	fileCount := MaximumTotalBytes/MaximumFileBytes + 1
	source := make(fstest.MapFS, fileCount)
	for number := 1; number <= fileCount; number++ {
		name := fmt.Sprintf("%04d_migration.sql", number)
		if number == 1 {
			name = "0001_migration_ledger.sql"
		}
		source[name] = &fstest.MapFile{Data: []byte(strings.Repeat("x", MaximumFileBytes))}
	}
	if _, err := loadCatalog(source); !errors.Is(err, ErrInvalidCatalog) {
		t.Fatalf("loadCatalog() error = %v, want ErrInvalidCatalog", err)
	}
}

func TestCatalogAcceptsExactPublishedBounds(t *testing.T) {
	tests := []struct {
		name      string
		fileCount int
		fileBytes int
		wantTotal int
	}{
		{name: "maximum file count", fileCount: MaximumCount, fileBytes: len("SELECT 1;\n"), wantTotal: MaximumCount * len("SELECT 1;\n")},
		{name: "maximum file bytes", fileCount: 1, fileBytes: MaximumFileBytes, wantTotal: MaximumFileBytes},
		{name: "maximum total bytes", fileCount: MaximumTotalBytes / MaximumFileBytes, fileBytes: MaximumFileBytes, wantTotal: MaximumTotalBytes},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contents := []byte("SELECT 1;\n")
			if tt.fileBytes != len(contents) {
				contents = []byte(strings.Repeat("x", tt.fileBytes-2) + ";\n")
			}
			source := make(fstest.MapFS, tt.fileCount)
			for number := 1; number <= tt.fileCount; number++ {
				name := fmt.Sprintf("%04d_migration.sql", number)
				if number == 1 {
					name = "0001_migration_ledger.sql"
				}
				source[name] = &fstest.MapFile{Data: contents}
			}
			catalog, err := loadCatalog(source)
			if err != nil {
				t.Fatalf("loadCatalog() error = %v", err)
			}
			if len(catalog) != tt.fileCount {
				t.Fatalf("catalog count = %d, want %d", len(catalog), tt.fileCount)
			}
			total := 0
			for _, migration := range catalog {
				total += len(migration.SQL)
			}
			if total != tt.wantTotal {
				t.Fatalf("catalog bytes = %d, want %d", total, tt.wantTotal)
			}
		})
	}
}
