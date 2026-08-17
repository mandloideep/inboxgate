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
	if len(catalog) != 2 {
		t.Fatalf("Catalog() count = %d, want 2", len(catalog))
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
