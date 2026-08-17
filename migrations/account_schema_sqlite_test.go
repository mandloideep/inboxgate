package migrations

import (
	"strings"
	"testing"
)

func TestAccountSchemaPublishesExactNULSafeDurableGuards(t *testing.T) {
	catalog, err := Catalog()
	if err != nil {
		t.Fatalf("Catalog() error = %v", err)
	}
	if len(catalog) < 2 {
		t.Fatalf("Catalog() count = %d, want account schema", len(catalog))
	}
	schema := catalog[1].SQL
	guards := []struct {
		field string
		exact string
	}{
		{
			field: "account_id",
			exact: "account_id TEXT PRIMARY KEY CHECK (length(CAST(account_id AS BLOB)) = 32 AND instr(CAST(account_id AS BLOB), x'00') = 0 AND account_id NOT GLOB '*[^0-9a-f]*')",
		},
		{
			field: "provider_subject",
			exact: "provider_subject TEXT COLLATE BINARY NOT NULL CHECK (length(CAST(provider_subject AS BLOB)) BETWEEN 1 AND 255 AND instr(CAST(provider_subject AS BLOB), x'00') = 0 AND provider_subject NOT GLOB '*[^!-~]*')",
		},
		{
			field: "history_id",
			exact: "history_id TEXT COLLATE BINARY NOT NULL CHECK (\n        length(CAST(history_id AS BLOB)) BETWEEN 1 AND 20\n        AND instr(CAST(history_id AS BLOB), x'00') = 0",
		},
	}
	for _, guard := range guards {
		if count := strings.Count(schema, guard.exact); count != 1 {
			t.Fatalf("%s durable guard count = %d, want exact guard once", guard.field, count)
		}
	}
}

func TestAccountSchemaPublishesExactCanonicalValueBounds(t *testing.T) {
	catalog, err := Catalog()
	if err != nil {
		t.Fatalf("Catalog() error = %v", err)
	}
	if len(catalog) < 2 {
		t.Fatalf("Catalog() count = %d, want account schema", len(catalog))
	}
	schema := catalog[1].SQL
	for _, exact := range []string{
		"length(CAST(account_id AS BLOB)) = 32",
		"length(CAST(provider_subject AS BLOB)) BETWEEN 1 AND 255",
		"length(CAST(history_id AS BLOB)) BETWEEN 1 AND 20",
		"history_id <= '18446744073709551615'",
	} {
		if !strings.Contains(schema, exact) {
			t.Fatalf("account schema does not contain exact canonical bound %q", exact)
		}
	}
}
