package migrations

import "testing"

func TestCandidateContentMigrationExactChecksum(t *testing.T) {
	catalog, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	if catalog[6].Checksum != "b9e8555424c26de167befc7c402c3fc19b5a1d5caddf6e75f6215abf5d339213" {
		t.Fatalf("migration 0007 checksum = %s", catalog[6].Checksum)
	}
}
