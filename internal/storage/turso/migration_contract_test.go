package turso

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/storage"
	"github.com/mandloideep/inboxgate/migrations"
)

const (
	expectedMaximumMigrationCount  = 256
	expectedMigrationSQL           = "CREATE TABLE inboxgate_schema_migrations (\n    number INTEGER PRIMARY KEY CHECK (number BETWEEN 1 AND 256),\n    checksum TEXT NOT NULL CHECK (length(checksum) = 64 AND checksum NOT GLOB '*[^0-9a-f]*')\n) STRICT, WITHOUT ROWID;\n"
	expectedAccountMigrationSQL    = "CREATE TABLE inboxgate_accounts (\n    account_id TEXT PRIMARY KEY CHECK (length(CAST(account_id AS BLOB)) = 32 AND instr(CAST(account_id AS BLOB), x'00') = 0 AND account_id NOT GLOB '*[^0-9a-f]*'),\n    provider TEXT NOT NULL CHECK (provider = 'gmail'),\n    provider_subject TEXT COLLATE BINARY NOT NULL CHECK (length(CAST(provider_subject AS BLOB)) BETWEEN 1 AND 255 AND instr(CAST(provider_subject AS BLOB), x'00') = 0 AND provider_subject NOT GLOB '*[^!-~]*'),\n    UNIQUE (provider, provider_subject)\n) STRICT, WITHOUT ROWID;\n\nCREATE TABLE inboxgate_synchronization_cursors (\n    account_id TEXT PRIMARY KEY,\n    history_id TEXT COLLATE BINARY NOT NULL CHECK (\n        length(CAST(history_id AS BLOB)) BETWEEN 1 AND 20\n        AND instr(CAST(history_id AS BLOB), x'00') = 0\n        AND history_id NOT GLOB '*[^0-9]*'\n        AND substr(history_id, 1, 1) BETWEEN '1' AND '9'\n        AND (length(CAST(history_id AS BLOB)) < 20 OR history_id <= '18446744073709551615')\n    ),\n    FOREIGN KEY (account_id) REFERENCES inboxgate_accounts (account_id) ON DELETE RESTRICT\n) STRICT, WITHOUT ROWID;\n"
	expectedCredentialMigrationSQL = "CREATE TABLE inboxgate_provider_credentials (\n    account_id TEXT PRIMARY KEY CHECK (length(CAST(account_id AS BLOB)) = 32 AND instr(CAST(account_id AS BLOB), x'00') = 0 AND account_id NOT GLOB '*[^0-9a-f]*'),\n    key_id TEXT COLLATE BINARY NOT NULL CHECK (\n        length(CAST(key_id AS BLOB)) BETWEEN 1 AND 32\n        AND instr(CAST(key_id AS BLOB), x'00') = 0\n        AND substr(key_id, 1, 1) GLOB '[a-z]'\n        AND key_id NOT GLOB '*[^a-z0-9_-]*'\n    ),\n    envelope TEXT COLLATE BINARY NOT NULL CHECK (\n        length(CAST(envelope AS BLOB)) BETWEEN 55 AND 5556\n        AND instr(CAST(envelope AS BLOB), x'00') = 0\n        AND substr(envelope, 1, 5) = 'igc1.'\n        AND substr(envelope, 6) NOT GLOB '*[^A-Za-z0-9_-]*'\n    ),\n    FOREIGN KEY (account_id) REFERENCES inboxgate_accounts (account_id) ON DELETE RESTRICT\n) STRICT, WITHOUT ROWID;\n"
	expectedSecondMigrationSQL     = "CREATE TABLE inboxgate_synthetic_second (id INTEGER PRIMARY KEY);\n"
	expectedThirdMigrationSQL      = "CREATE TABLE inboxgate_synthetic_third (id INTEGER PRIMARY KEY);\n"
	ledgerInsertSQL                = "INSERT INTO inboxgate_schema_migrations (number, checksum) VALUES (?, ?)"
	commitAfterDurabilityStage     = "commit-after-durability"
)

var expectedMigrationChecksum = func() string {
	sum := sha256.Sum256([]byte(expectedMigrationSQL))
	return hex.EncodeToString(sum[:])
}()

func TestMain(m *testing.M) {
	code := m.Run()
	closeMigrationProtocolHost()
	os.Exit(code)
}

var expectedAccountMigrationChecksum = func() string {
	sum := sha256.Sum256([]byte(expectedAccountMigrationSQL))
	return hex.EncodeToString(sum[:])
}()

var expectedCredentialMigrationChecksum = func() string {
	sum := sha256.Sum256([]byte(expectedCredentialMigrationSQL))
	return hex.EncodeToString(sum[:])
}()

var expectedLifecycleMigrationSQL = func() string {
	catalog, err := migrations.Catalog()
	if err != nil || len(catalog) < 4 {
		panic("embedded lifecycle migration unavailable")
	}
	return catalog[3].SQL
}()

var expectedLifecycleMigrationChecksum = func() string {
	sum := sha256.Sum256([]byte(expectedLifecycleMigrationSQL))
	return hex.EncodeToString(sum[:])
}()

var expectedCurrentDiscoveryMigrationSQL = func() string {
	catalog, err := migrations.Catalog()
	if err != nil || len(catalog) < 5 {
		panic("embedded current discovery migration unavailable")
	}
	return catalog[4].SQL
}()

var expectedCurrentDiscoveryMigrationChecksum = func() string {
	sum := sha256.Sum256([]byte(expectedCurrentDiscoveryMigrationSQL))
	return hex.EncodeToString(sum[:])
}()

var expectedGateDecisionMigrationSQL = func() string {
	catalog, err := migrations.Catalog()
	if err != nil || len(catalog) < 6 {
		panic("embedded gate decision migration unavailable")
	}
	return catalog[5].SQL
}()

var expectedGateDecisionMigrationChecksum = func() string {
	sum := sha256.Sum256([]byte(expectedGateDecisionMigrationSQL))
	return hex.EncodeToString(sum[:])
}()

var expectedCandidateContentMigrationSQL = func() string {
	catalog, err := migrations.Catalog()
	if err != nil || len(catalog) < 7 {
		panic("embedded candidate content migration unavailable")
	}
	return catalog[6].SQL
}()

var expectedCandidateContentMigrationChecksum = func() string {
	sum := sha256.Sum256([]byte(expectedCandidateContentMigrationSQL))
	return hex.EncodeToString(sum[:])
}()

var expectedMigrationSequence = beginImmediateSQL + ";\n" + expectedMigrationSQL +
	"CREATE TEMP TABLE " + guardTable + " (valid INTEGER NOT NULL CHECK (valid = 1));\n" +
	"INSERT INTO " + guardTable + " (valid) SELECT CASE WHEN (SELECT COUNT(*) FROM " + ledgerTable + ") = 0 THEN 1 ELSE 0 END;\n" +
	"DROP TABLE temp." + guardTable + ";\n" +
	sequenceInsertSQL + "1, '" + expectedMigrationChecksum + "');\n" + commitSQL + ";"

var expectedSecondMigrationChecksum = func() string {
	sum := sha256.Sum256([]byte(expectedSecondMigrationSQL))
	return hex.EncodeToString(sum[:])
}()

var expectedThirdMigrationChecksum = func() string {
	sum := sha256.Sum256([]byte(expectedThirdMigrationSQL))
	return hex.EncodeToString(sum[:])
}()

var expectedSecondMigrationSequence = beginImmediateSQL + ";\n" + expectedSecondMigrationSQL +
	"CREATE TEMP TABLE " + guardTable + " (valid INTEGER NOT NULL CHECK (valid = 1));\n" +
	"INSERT INTO " + guardTable + " (valid) SELECT CASE WHEN (SELECT COUNT(*) FROM " + ledgerTable + ") = 1 AND NOT EXISTS (SELECT 1 FROM " + ledgerTable + " WHERE number IS NULL OR checksum IS NULL) AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 1 AND checksum = '" + expectedMigrationChecksum + "') = 1 THEN 1 ELSE 0 END;\n" +
	"DROP TABLE temp." + guardTable + ";\n" +
	sequenceInsertSQL + "2, '" + expectedSecondMigrationChecksum + "');\n" + commitSQL + ";"

var expectedAccountMigrationSequence = beginImmediateSQL + ";\n" + expectedAccountMigrationSQL +
	"CREATE TEMP TABLE " + guardTable + " (valid INTEGER NOT NULL CHECK (valid = 1));\n" +
	"INSERT INTO " + guardTable + " (valid) SELECT CASE WHEN (SELECT COUNT(*) FROM " + ledgerTable + ") = 1 AND NOT EXISTS (SELECT 1 FROM " + ledgerTable + " WHERE number IS NULL OR checksum IS NULL) AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 1 AND checksum = '" + expectedMigrationChecksum + "') = 1 THEN 1 ELSE 0 END;\n" +
	"DROP TABLE temp." + guardTable + ";\n" +
	sequenceInsertSQL + "2, '" + expectedAccountMigrationChecksum + "');\n" + commitSQL + ";"

var expectedCredentialMigrationSequence = beginImmediateSQL + ";\n" + expectedCredentialMigrationSQL +
	"CREATE TEMP TABLE " + guardTable + " (valid INTEGER NOT NULL CHECK (valid = 1));\n" +
	"INSERT INTO " + guardTable + " (valid) SELECT CASE WHEN (SELECT COUNT(*) FROM " + ledgerTable + ") = 2 AND NOT EXISTS (SELECT 1 FROM " + ledgerTable + " WHERE number IS NULL OR checksum IS NULL) AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 1 AND checksum = '" + expectedMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 2 AND checksum = '" + expectedAccountMigrationChecksum + "') = 1 THEN 1 ELSE 0 END;\n" +
	"DROP TABLE temp." + guardTable + ";\n" +
	sequenceInsertSQL + "3, '" + expectedCredentialMigrationChecksum + "');\n" + commitSQL + ";"

var expectedLifecycleMigrationSequence = beginImmediateSQL + ";\n" + expectedLifecycleMigrationSQL +
	"CREATE TEMP TABLE " + guardTable + " (valid INTEGER NOT NULL CHECK (valid = 1));\n" +
	"INSERT INTO " + guardTable + " (valid) SELECT CASE WHEN (SELECT COUNT(*) FROM " + ledgerTable + ") = 3 AND NOT EXISTS (SELECT 1 FROM " + ledgerTable + " WHERE number IS NULL OR checksum IS NULL) AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 1 AND checksum = '" + expectedMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 2 AND checksum = '" + expectedAccountMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 3 AND checksum = '" + expectedCredentialMigrationChecksum + "') = 1 THEN 1 ELSE 0 END;\n" +
	"DROP TABLE temp." + guardTable + ";\n" +
	sequenceInsertSQL + "4, '" + expectedLifecycleMigrationChecksum + "');\n" + commitSQL + ";"

var expectedCurrentDiscoveryMigrationSequence = beginImmediateSQL + ";\n" + expectedCurrentDiscoveryMigrationSQL +
	"CREATE TEMP TABLE " + guardTable + " (valid INTEGER NOT NULL CHECK (valid = 1));\n" +
	"INSERT INTO " + guardTable + " (valid) SELECT CASE WHEN (SELECT COUNT(*) FROM " + ledgerTable + ") = 4 AND NOT EXISTS (SELECT 1 FROM " + ledgerTable + " WHERE number IS NULL OR checksum IS NULL) AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 1 AND checksum = '" + expectedMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 2 AND checksum = '" + expectedAccountMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 3 AND checksum = '" + expectedCredentialMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 4 AND checksum = '" + expectedLifecycleMigrationChecksum + "') = 1 THEN 1 ELSE 0 END;\n" +
	"DROP TABLE temp." + guardTable + ";\n" +
	sequenceInsertSQL + "5, '" + expectedCurrentDiscoveryMigrationChecksum + "');\n" + commitSQL + ";"

var expectedGateDecisionMigrationSequence = beginImmediateSQL + ";\n" + expectedGateDecisionMigrationSQL +
	"CREATE TEMP TABLE " + guardTable + " (valid INTEGER NOT NULL CHECK (valid = 1));\n" +
	"INSERT INTO " + guardTable + " (valid) SELECT CASE WHEN (SELECT COUNT(*) FROM " + ledgerTable + ") = 5 AND NOT EXISTS (SELECT 1 FROM " + ledgerTable + " WHERE number IS NULL OR checksum IS NULL) AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 1 AND checksum = '" + expectedMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 2 AND checksum = '" + expectedAccountMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 3 AND checksum = '" + expectedCredentialMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 4 AND checksum = '" + expectedLifecycleMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 5 AND checksum = '" + expectedCurrentDiscoveryMigrationChecksum + "') = 1 THEN 1 ELSE 0 END;\n" +
	"DROP TABLE temp." + guardTable + ";\n" +
	sequenceInsertSQL + "6, '" + expectedGateDecisionMigrationChecksum + "');\n" + commitSQL + ";"

var expectedCandidateContentMigrationSequence = beginImmediateSQL + ";\n" + expectedCandidateContentMigrationSQL +
	"CREATE TEMP TABLE " + guardTable + " (valid INTEGER NOT NULL CHECK (valid = 1));\n" +
	"INSERT INTO " + guardTable + " (valid) SELECT CASE WHEN (SELECT COUNT(*) FROM " + ledgerTable + ") = 6 AND NOT EXISTS (SELECT 1 FROM " + ledgerTable + " WHERE number IS NULL OR checksum IS NULL) AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 1 AND checksum = '" + expectedMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 2 AND checksum = '" + expectedAccountMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 3 AND checksum = '" + expectedCredentialMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 4 AND checksum = '" + expectedLifecycleMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 5 AND checksum = '" + expectedCurrentDiscoveryMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 6 AND checksum = '" + expectedGateDecisionMigrationChecksum + "') = 1 THEN 1 ELSE 0 END;\n" +
	"DROP TABLE temp." + guardTable + ";\n" +
	sequenceInsertSQL + "7, '" + expectedCandidateContentMigrationChecksum + "');\n" + commitSQL + ";"

var expectedTerminalSequence = "SAVEPOINT " + terminalSavepoint + ";\n" +
	"UPDATE " + ledgerTable + " SET checksum = checksum WHERE number = 1;\n" +
	"CREATE TEMP TABLE " + terminalGuardTable + " (valid INTEGER NOT NULL CHECK (valid = 1));\n" +
	"INSERT INTO " + terminalGuardTable + " (valid) SELECT CASE WHEN (SELECT COUNT(*) FROM " + ledgerTable + ") = 1 AND NOT EXISTS (SELECT 1 FROM " + ledgerTable + " WHERE number IS NULL OR checksum IS NULL) AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 1 AND checksum = '" + expectedMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM pragma_user_version) = 1 AND (SELECT user_version FROM pragma_user_version) BETWEEN 0 AND 1 THEN 1 ELSE 0 END;\n" +
	"DROP TABLE temp." + terminalGuardTable + ";\n" +
	"PRAGMA user_version = 1;\nRELEASE SAVEPOINT " + terminalSavepoint + ";"

var expectedAccountTerminalSequence = "SAVEPOINT " + terminalSavepoint + ";\n" +
	"UPDATE " + ledgerTable + " SET checksum = checksum WHERE number = 2;\n" +
	"CREATE TEMP TABLE " + terminalGuardTable + " (valid INTEGER NOT NULL CHECK (valid = 1));\n" +
	"INSERT INTO " + terminalGuardTable + " (valid) SELECT CASE WHEN (SELECT COUNT(*) FROM " + ledgerTable + ") = 2 AND NOT EXISTS (SELECT 1 FROM " + ledgerTable + " WHERE number IS NULL OR checksum IS NULL) AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 1 AND checksum = '" + expectedMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 2 AND checksum = '" + expectedAccountMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM pragma_user_version) = 1 AND (SELECT user_version FROM pragma_user_version) BETWEEN 0 AND 2 THEN 1 ELSE 0 END;\n" +
	"DROP TABLE temp." + terminalGuardTable + ";\n" +
	"PRAGMA user_version = 2;\nRELEASE SAVEPOINT " + terminalSavepoint + ";"

var expectedCredentialTerminalSequence = "SAVEPOINT " + terminalSavepoint + ";\n" +
	"UPDATE " + ledgerTable + " SET checksum = checksum WHERE number = 3;\n" +
	"CREATE TEMP TABLE " + terminalGuardTable + " (valid INTEGER NOT NULL CHECK (valid = 1));\n" +
	"INSERT INTO " + terminalGuardTable + " (valid) SELECT CASE WHEN (SELECT COUNT(*) FROM " + ledgerTable + ") = 3 AND NOT EXISTS (SELECT 1 FROM " + ledgerTable + " WHERE number IS NULL OR checksum IS NULL) AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 1 AND checksum = '" + expectedMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 2 AND checksum = '" + expectedAccountMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 3 AND checksum = '" + expectedCredentialMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM pragma_user_version) = 1 AND (SELECT user_version FROM pragma_user_version) BETWEEN 0 AND 3 THEN 1 ELSE 0 END;\n" +
	"DROP TABLE temp." + terminalGuardTable + ";\n" +
	"PRAGMA user_version = 3;\nRELEASE SAVEPOINT " + terminalSavepoint + ";"

var expectedLifecycleTerminalSequence = "SAVEPOINT " + terminalSavepoint + ";\n" +
	"UPDATE " + ledgerTable + " SET checksum = checksum WHERE number = 4;\n" +
	"CREATE TEMP TABLE " + terminalGuardTable + " (valid INTEGER NOT NULL CHECK (valid = 1));\n" +
	"INSERT INTO " + terminalGuardTable + " (valid) SELECT CASE WHEN (SELECT COUNT(*) FROM " + ledgerTable + ") = 4 AND NOT EXISTS (SELECT 1 FROM " + ledgerTable + " WHERE number IS NULL OR checksum IS NULL) AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 1 AND checksum = '" + expectedMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 2 AND checksum = '" + expectedAccountMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 3 AND checksum = '" + expectedCredentialMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 4 AND checksum = '" + expectedLifecycleMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM pragma_user_version) = 1 AND (SELECT user_version FROM pragma_user_version) BETWEEN 0 AND 4 THEN 1 ELSE 0 END;\n" +
	"DROP TABLE temp." + terminalGuardTable + ";\n" +
	"PRAGMA user_version = 4;\nRELEASE SAVEPOINT " + terminalSavepoint + ";"

var expectedCurrentDiscoveryTerminalSequence = "SAVEPOINT " + terminalSavepoint + ";\n" +
	"UPDATE " + ledgerTable + " SET checksum = checksum WHERE number = 5;\n" +
	"CREATE TEMP TABLE " + terminalGuardTable + " (valid INTEGER NOT NULL CHECK (valid = 1));\n" +
	"INSERT INTO " + terminalGuardTable + " (valid) SELECT CASE WHEN (SELECT COUNT(*) FROM " + ledgerTable + ") = 5 AND NOT EXISTS (SELECT 1 FROM " + ledgerTable + " WHERE number IS NULL OR checksum IS NULL) AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 1 AND checksum = '" + expectedMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 2 AND checksum = '" + expectedAccountMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 3 AND checksum = '" + expectedCredentialMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 4 AND checksum = '" + expectedLifecycleMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 5 AND checksum = '" + expectedCurrentDiscoveryMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM pragma_user_version) = 1 AND (SELECT user_version FROM pragma_user_version) BETWEEN 0 AND 5 THEN 1 ELSE 0 END;\n" +
	"DROP TABLE temp." + terminalGuardTable + ";\n" +
	"PRAGMA user_version = 5;\nRELEASE SAVEPOINT " + terminalSavepoint + ";"

var expectedGateDecisionTerminalSequence = "SAVEPOINT " + terminalSavepoint + ";\n" +
	"UPDATE " + ledgerTable + " SET checksum = checksum WHERE number = 6;\n" +
	"CREATE TEMP TABLE " + terminalGuardTable + " (valid INTEGER NOT NULL CHECK (valid = 1));\n" +
	"INSERT INTO " + terminalGuardTable + " (valid) SELECT CASE WHEN (SELECT COUNT(*) FROM " + ledgerTable + ") = 6 AND NOT EXISTS (SELECT 1 FROM " + ledgerTable + " WHERE number IS NULL OR checksum IS NULL) AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 1 AND checksum = '" + expectedMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 2 AND checksum = '" + expectedAccountMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 3 AND checksum = '" + expectedCredentialMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 4 AND checksum = '" + expectedLifecycleMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 5 AND checksum = '" + expectedCurrentDiscoveryMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 6 AND checksum = '" + expectedGateDecisionMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM pragma_user_version) = 1 AND (SELECT user_version FROM pragma_user_version) BETWEEN 0 AND 6 THEN 1 ELSE 0 END;\n" +
	"DROP TABLE temp." + terminalGuardTable + ";\n" +
	"PRAGMA user_version = 6;\nRELEASE SAVEPOINT " + terminalSavepoint + ";"

var expectedCandidateContentTerminalSequence = "SAVEPOINT " + terminalSavepoint + ";\n" +
	"UPDATE " + ledgerTable + " SET checksum = checksum WHERE number = 7;\n" +
	"CREATE TEMP TABLE " + terminalGuardTable + " (valid INTEGER NOT NULL CHECK (valid = 1));\n" +
	"INSERT INTO " + terminalGuardTable + " (valid) SELECT CASE WHEN (SELECT COUNT(*) FROM " + ledgerTable + ") = 7 AND NOT EXISTS (SELECT 1 FROM " + ledgerTable + " WHERE number IS NULL OR checksum IS NULL) AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 1 AND checksum = '" + expectedMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 2 AND checksum = '" + expectedAccountMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 3 AND checksum = '" + expectedCredentialMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 4 AND checksum = '" + expectedLifecycleMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 5 AND checksum = '" + expectedCurrentDiscoveryMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 6 AND checksum = '" + expectedGateDecisionMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM " + ledgerTable + " WHERE number = 7 AND checksum = '" + expectedCandidateContentMigrationChecksum + "') = 1 AND (SELECT COUNT(*) FROM pragma_user_version) = 1 AND (SELECT user_version FROM pragma_user_version) BETWEEN 0 AND 7 THEN 1 ELSE 0 END;\n" +
	"DROP TABLE temp." + terminalGuardTable + ";\n" +
	"PRAGMA user_version = 7;\nRELEASE SAVEPOINT " + terminalSavepoint + ";"

func TestMigrationContractEmptyApplication(t *testing.T) {

	server := newMigrationProtocolServer(t)
	handle := openMigrationContractHandle(t, server.URL)

	result, err := handle.Migrate(context.Background())
	if err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if result != (storage.MigrationResult{Applied: 7, Current: 7}) {
		t.Fatalf("Migrate() result = %#v, want seven applied migrations", result)
	}
	server.assertCommittedCatalog(t)
	server.assertSeparateVerificationStream(t)
	server.assertExactFirstApplicationSequence(t)
	firstMutationCount := server.mutationCount()

	result, err = handle.Migrate(context.Background())
	if err != nil {
		t.Fatalf("second Migrate() error = %v", err)
	}
	if result != (storage.MigrationResult{Applied: 0, Current: 7}) {
		t.Fatalf("second Migrate() result = %#v, want bounded no-op", result)
	}
	if got := server.mutationCount(); got != firstMutationCount {
		t.Fatalf("second Migrate() mutations = %d, want unchanged %d", got, firstMutationCount)
	}
}

func TestMigrationFromAccountSchemaSendsExactCredentialSchemaBytes(t *testing.T) {
	server := newMigrationProtocolServer(t)
	server.seedLedger(1, expectedMigrationChecksum)
	server.seedLedger(2, expectedAccountMigrationChecksum)
	handle := openMigrationContractHandle(t, server.URL)
	result, err := handle.Migrate(context.Background())
	if err != nil || result.Applied != 5 || result.Current != 7 {
		t.Fatalf("Migrate() = (%#v, %v), want one credential migration", result, err)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	for _, record := range server.pipelineRecords {
		for _, request := range record.requests {
			if request.Type == "sequence" && request.SQL == expectedCredentialMigrationSequence && len(request.Args) == 0 && len(request.NamedArgs) == 0 {
				return
			}
		}
	}
	t.Fatal("exact credential migration transaction sequence was not sent")
}

func TestMigrationSequenceUsesOnlyBoundedInternalLiterals(t *testing.T) {

	valid := migrations.Migration{
		Number:   1,
		Checksum: expectedMigrationChecksum,
		SQL:      expectedMigrationSQL,
	}
	sequence, err := migrationSequence([]migrations.Migration{valid}, 0)
	if err != nil {
		t.Fatalf("migrationSequence() error = %v", err)
	}
	if sequence != expectedMigrationSequence {
		t.Fatal("migrationSequence() differs from exact reviewed transaction bytes")
	}

	tests := []struct {
		name      string
		migration migrations.Migration
	}{
		{name: "zero number", migration: migrations.Migration{Checksum: valid.Checksum, SQL: valid.SQL}},
		{name: "over-limit number", migration: migrations.Migration{Number: migrations.MaximumCount + 1, Checksum: valid.Checksum, SQL: valid.SQL}},
		{name: "quoted checksum", migration: migrations.Migration{Number: 1, Checksum: strings.Repeat("a", 63) + "'", SQL: valid.SQL}},
		{name: "uppercase checksum", migration: migrations.Migration{Number: 1, Checksum: strings.Repeat("A", 64), SQL: valid.SQL}},
		{name: "unterminated SQL", migration: migrations.Migration{Number: 1, Checksum: valid.Checksum, SQL: "SELECT 1"}},
		{name: "oversized SQL", migration: migrations.Migration{Number: 1, Checksum: valid.Checksum, SQL: strings.Repeat("x", migrations.MaximumFileBytes) + ";"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := migrationSequence([]migrations.Migration{tt.migration}, 0); !errors.Is(err, ErrMigrationCatalog) {
				t.Fatalf("migrationSequence() error = %v, want ErrMigrationCatalog", err)
			}
		})
	}
}

func TestMigrationLockedSequenceRejectsStaleChecksumPrefix(t *testing.T) {

	server := newMigrationProtocolServer(t)
	server.seedLedger(1, expectedMigrationChecksum)
	stalled, release := server.stallBeforeNextSequence()
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	opened := openMigrationContractHandle(t, server.URL)
	handle := opened.(*handle)
	catalog := []migrations.Migration{
		{Number: 1, Name: "0001_migration_ledger.sql", Checksum: expectedMigrationChecksum, SQL: expectedMigrationSQL},
		{Number: 2, Name: "0002_synthetic_second.sql", Checksum: expectedSecondMigrationChecksum, SQL: expectedSecondMigrationSQL},
	}
	result := make(chan error, 1)
	go func() {
		_, err := handle.migrateCatalog(context.Background(), catalog)
		result <- err
	}()
	select {
	case <-stalled:
	case <-time.After(time.Second):
		t.Fatal("migration did not reach the pre-lock race point")
	}
	server.corruptLedgerChecksum(1, strings.Repeat("0", 64))
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-result:
		if !errors.Is(err, ErrMigrationUnknownOutcome) {
			t.Fatalf("migrateCatalog() error = %v, want ErrMigrationUnknownOutcome", err)
		}
	case <-time.After(time.Second):
		t.Fatal("migration did not return after race release")
	}
	if server.secondSchemaExists() {
		t.Fatal("stale-prefix sequence committed the second schema")
	}
	if checksum, exists := server.ledgerChecksum(2); exists || checksum != "" {
		t.Fatalf("stale-prefix sequence committed ledger row 2 = %q", checksum)
	}
}

func TestMigrationLockedSequenceRejectsDuplicateWithMissingPrefixPair(t *testing.T) {

	server := newMigrationProtocolServer(t)
	server.seedLedger(1, expectedMigrationChecksum)
	server.seedLedger(2, expectedSecondMigrationChecksum)
	stalled, release := server.stallBeforeNextSequence()
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	handle := openMigrationContractHandle(t, server.URL).(*handle)
	catalog := syntheticMigrationCatalog(3)
	result := make(chan error, 1)
	go func() {
		_, err := handle.migrateCatalog(context.Background(), catalog)
		result <- err
	}()
	select {
	case <-stalled:
	case <-time.After(time.Second):
		t.Fatal("migration did not reach the duplicate-prefix race point")
	}
	server.overrideLedgerRows([][]any{
		{integerValue(1), textValue(expectedMigrationChecksum)},
		{integerValue(1), textValue(expectedMigrationChecksum)},
	})
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-result:
		if !errors.Is(err, ErrMigrationUnknownOutcome) {
			t.Fatalf("migrateCatalog() error = %v, want ErrMigrationUnknownOutcome", err)
		}
	case <-time.After(time.Second):
		t.Fatal("migration did not return after duplicate-prefix release")
	}
	if server.thirdSchemaExists() {
		t.Fatal("duplicate-prefix sequence committed the third schema")
	}
}

func TestMigrationLockedSequenceRejectsNullPrefixRow(t *testing.T) {

	server := newMigrationProtocolServer(t)
	server.seedLedger(1, expectedMigrationChecksum)
	stalled, release := server.stallBeforeNextSequence()
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	handle := openMigrationContractHandle(t, server.URL).(*handle)
	catalog := syntheticMigrationCatalog(2)
	result := make(chan error, 1)
	go func() {
		_, err := handle.migrateCatalog(context.Background(), catalog)
		result <- err
	}()
	select {
	case <-stalled:
	case <-time.After(time.Second):
		t.Fatal("migration did not reach the null-prefix race point")
	}
	server.overrideLedgerRows([][]any{{nil, nil}})
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-result:
		if !errors.Is(err, ErrMigrationUnknownOutcome) {
			t.Fatalf("migrateCatalog() error = %v, want ErrMigrationUnknownOutcome", err)
		}
	case <-time.After(time.Second):
		t.Fatal("migration did not return after null-prefix release")
	}
	if server.secondSchemaExists() {
		t.Fatal("null-prefix sequence committed the second schema")
	}
}

func syntheticMigrationCatalog(count int) []migrations.Migration {
	all := []migrations.Migration{
		{Number: 1, Name: "0001_migration_ledger.sql", Checksum: expectedMigrationChecksum, SQL: expectedMigrationSQL},
		{Number: 2, Name: "0002_synthetic_second.sql", Checksum: expectedSecondMigrationChecksum, SQL: expectedSecondMigrationSQL},
		{Number: 3, Name: "0003_synthetic_third.sql", Checksum: expectedThirdMigrationChecksum, SQL: expectedThirdMigrationSQL},
	}
	return slices.Clone(all[:count])
}

func TestMigrationContractRejectsChecksumDrift(t *testing.T) {

	server := newMigrationProtocolServer(t)
	server.seedLedger(1, strings.Repeat("0", 64))
	handle := openMigrationContractHandle(t, server.URL)

	_, err := handle.Migrate(context.Background())
	if !errors.Is(err, ErrMigrationDrift) {
		t.Fatalf("Migrate() error = %v, want ErrMigrationDrift", err)
	}
	if got := server.migrationStatementCount(); got != 0 {
		t.Fatalf("migration statement requests = %d, want 0 after drift", got)
	}
	if got := server.insertCount(); got != 0 {
		t.Fatalf("ledger inserts = %d, want 0 after drift", got)
	}
}

func TestMigrationContractDroppedCommitDoesNotReplayAndFreshRunReconciles(t *testing.T) {

	server := newMigrationProtocolServer(t)
	server.dropNextCommit()
	first := openMigrationContractHandle(t, server.URL)

	_, err := first.Migrate(context.Background())
	if !errors.Is(err, ErrMigrationUnknownOutcome) {
		t.Fatalf("Migrate() error = %v, want ErrMigrationUnknownOutcome", err)
	}
	if got := server.migrationStatementCount(); got != 0 {
		t.Fatalf("same-invocation standalone migration requests = %d, want 0", got)
	}
	if got := server.sequenceCount(); got != 1 {
		t.Fatalf("same-invocation sequence requests = %d, want 1", got)
	}

	second := openMigrationContractHandle(t, server.URL)
	result, err := second.Migrate(context.Background())
	if err != nil {
		t.Fatalf("fresh Migrate() error = %v", err)
	}
	if result != (storage.MigrationResult{Applied: 6, Current: 7}) {
		t.Fatalf("fresh Migrate() result = %#v, want durable reconciliation", result)
	}
	if got := server.sequenceCount(); got != 7 {
		t.Fatalf("sequence requests after reconciliation = %d, want only pending migrations 2 and 3", got)
	}
}

func TestMigrationContractDroppedCommitBeforeDurabilityAppliesOnceOnFreshRun(t *testing.T) {

	server := newMigrationProtocolServer(t)
	server.dropNextCommitBeforeDurability()
	first := openMigrationContractHandle(t, server.URL)
	_, err := first.Migrate(context.Background())
	if !errors.Is(err, ErrMigrationUnknownOutcome) {
		t.Fatalf("Migrate() error = %v, want ErrMigrationUnknownOutcome", err)
	}
	if got := server.sequenceCount(); got != 1 {
		t.Fatalf("same-invocation sequence requests = %d, want 1", got)
	}

	second := openMigrationContractHandle(t, server.URL)
	result, err := second.Migrate(context.Background())
	if err != nil {
		t.Fatalf("fresh Migrate() error = %v", err)
	}
	if result != (storage.MigrationResult{Applied: 7, Current: 7}) {
		t.Fatalf("fresh Migrate() result = %#v, want three newly durable migrations", result)
	}
	if got := server.sequenceCount(); got != 8 {
		t.Fatalf("sequence requests across explicit invocations = %d, want 8", got)
	}
	server.assertCommittedCatalog(t)
}

func TestMigrationHeaderOnlyStandaloneCommitPathIsNotUsed(t *testing.T) {

	server := newMigrationProtocolServer(t)
	server.headerOnlyNextCommitBeforeDurability()
	first := openMigrationContractHandle(t, server.URL)
	result, err := first.Migrate(context.Background())
	if err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if result != (storage.MigrationResult{Applied: 7, Current: 7}) {
		t.Fatalf("Migrate() result = %#v, want six atomic sequences", result)
	}
	if got := server.commitCount(); got != 0 {
		t.Fatalf("standalone commit requests = %d, want 0", got)
	}
	if got := server.sequenceCount(); got != 7 {
		t.Fatalf("sequence requests = %d, want 6", got)
	}
}

func TestMigrationHeaderOnlyBeginCannotMoveWritesToAutocommit(t *testing.T) {

	server := newMigrationProtocolServer(t)
	server.headerOnlyNextBeginWithoutApplying()
	handle := openMigrationContractHandle(t, server.URL)
	result, err := handle.Migrate(context.Background())
	if err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if result != (storage.MigrationResult{Applied: 7, Current: 7}) {
		t.Fatalf("Migrate() result = %#v, want six atomic sequences", result)
	}
	if got := server.countSQL(beginImmediateSQL); got != 0 {
		t.Fatalf("standalone begin requests = %d, want 0", got)
	}
	if got := server.migrationStatementCount(); got != 0 {
		t.Fatalf("standalone migration requests = %d, want 0", got)
	}
	if got := server.sequenceCount(); got != 7 {
		t.Fatalf("sequence requests = %d, want 6", got)
	}
}

func TestMigrationHeaderOnlyPendingStatementCannotCreateFalseLedgerSuccess(t *testing.T) {

	server := newMigrationProtocolServer(t)
	server.headerOnlyNextMigrationWithoutApplying()
	handle := openMigrationContractHandle(t, server.URL)
	result, err := handle.Migrate(context.Background())
	if err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if result != (storage.MigrationResult{Applied: 7, Current: 7}) {
		t.Fatalf("Migrate() result = %#v, want six atomic sequences", result)
	}
	if got := server.migrationStatementCount(); got != 0 {
		t.Fatalf("standalone migration requests = %d, want 0", got)
	}
	if got := server.insertCount(); got != 0 {
		t.Fatalf("standalone ledger inserts = %d, want 0", got)
	}
	if got := server.sequenceCount(); got != 7 {
		t.Fatalf("sequence requests = %d, want 6", got)
	}
}

func TestMigrationDroppedSequenceReturnsUnknownWithoutReplayAndFreshRunReconciles(t *testing.T) {

	server := newMigrationProtocolServer(t)
	server.dropNextCommitBeforeDurability()
	first := openMigrationContractHandle(t, server.URL)
	_, err := first.Migrate(context.Background())
	if !errors.Is(err, ErrMigrationUnknownOutcome) {
		t.Fatalf("Migrate() error = %v, want ErrMigrationUnknownOutcome", err)
	}
	if got := server.sequenceCount(); got != 1 {
		t.Fatalf("same-invocation sequence requests = %d, want 1", got)
	}

	second := openMigrationContractHandle(t, server.URL)
	result, err := second.Migrate(context.Background())
	if err != nil {
		t.Fatalf("fresh Migrate() error = %v", err)
	}
	if result != (storage.MigrationResult{Applied: 7, Current: 7}) {
		t.Fatalf("fresh Migrate() result = %#v, want seven applied migrations", result)
	}
}

func TestMigrationMalformedSequenceResponseIsUnknown(t *testing.T) {

	server := newMigrationProtocolServer(t)
	server.malformedNextSequenceResponse()
	handle := openMigrationContractHandle(t, server.URL)
	_, err := handle.Migrate(context.Background())
	if !errors.Is(err, ErrMigrationUnknownOutcome) {
		t.Fatalf("Migrate() error = %v, want ErrMigrationUnknownOutcome", err)
	}
	if got := server.sequenceCount(); got != 1 {
		t.Fatalf("sequence requests = %d, want one without replay", got)
	}
	if strings.Contains(err.Error(), "malformed synthetic marker") {
		t.Fatalf("Migrate() error %q contains raw marker", err)
	}
}

func TestMigrationRejectsIncompleteSequenceResultsAndReconcilesFresh(t *testing.T) {

	tests := []struct {
		name string
		arm  func(*migrationProtocolServer)
	}{
		{name: "missing result", arm: (*migrationProtocolServer).omitNextSequenceResult},
		{name: "malformed autocommit result", arm: (*migrationProtocolServer).malformNextAutocommitResult},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			tt.arm(server)
			first := openMigrationContractHandle(t, server.URL)
			_, err := first.Migrate(context.Background())
			if !errors.Is(err, ErrMigrationUnknownOutcome) {
				t.Fatalf("Migrate() error = %v, want ErrMigrationUnknownOutcome", err)
			}
			if got := server.sequenceCount(); got != 1 {
				t.Fatalf("same-invocation sequence requests = %d, want 1", got)
			}

			second := openMigrationContractHandle(t, server.URL)
			result, err := second.Migrate(context.Background())
			if err != nil {
				t.Fatalf("fresh Migrate() error = %v", err)
			}
			if result != (storage.MigrationResult{Applied: 7, Current: 7}) {
				t.Fatalf("fresh Migrate() result = %#v, want six atomic migrations", result)
			}
			if got := server.sequenceCount(); got != 8 {
				t.Fatalf("sequence requests across explicit invocations = %d, want 8", got)
			}
		})
	}
}

func TestMigrationSequenceResponseRequiresSemanticTerminalProof(t *testing.T) {

	tests := []struct {
		name string
		arm  func(*migrationProtocolServer)
	}{
		{name: "missing sequence payload", arm: (*migrationProtocolServer).omitNextSequenceResponsePayload},
		{name: "wrong sequence payload", arm: (*migrationProtocolServer).wrongNextSequenceResponsePayload},
		{name: "false autocommit", arm: (*migrationProtocolServer).falseNextSequenceAutocommit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			tt.arm(server)
			handle := openMigrationContractHandle(t, server.URL)
			result, err := handle.Migrate(context.Background())
			if err != nil {
				t.Fatalf("Migrate() error = %v", err)
			}
			if result != (storage.MigrationResult{Applied: 7, Current: 7}) {
				t.Fatalf("Migrate() result = %#v, want six semantically proven migrations", result)
			}
			if got := server.terminalSequenceCount(); got != 7 {
				t.Fatalf("terminal proof sequences = %d, want 6", got)
			}
			if got := server.userVersionValue(); got != 7 {
				t.Fatalf("durable user_version = %d, want 6", got)
			}
		})
	}
}

func TestMigrationUnprovenApplySessionIsDiscardedBeforeFreshReconciliation(t *testing.T) {

	server := newMigrationProtocolServer(t)
	server.holdNextSequenceTransaction()
	handle := openMigrationContractHandle(t, server.URL)
	_, err := handle.Migrate(context.Background())
	if !errors.Is(err, ErrMigrationUnknownOutcome) {
		t.Fatalf("Migrate() error = %v, want ErrMigrationUnknownOutcome", err)
	}
	if server.ledgerExists() {
		t.Fatal("unproven apply transaction became durable")
	}
	if got := server.sequenceCount(); got != 1 {
		t.Fatalf("same-invocation migration sequences = %d, want 1", got)
	}
	if got := server.terminalSequenceCount(); got != 1 {
		t.Fatalf("same-invocation terminal sequences = %d, want 1", got)
	}
	if got := server.closeCount(); got == 0 {
		t.Fatal("unproven apply connection was returned without an exact-driver close request")
	}

	result, err := handle.Migrate(context.Background())
	if err != nil {
		t.Fatalf("fresh explicit Migrate() error = %v", err)
	}
	if result != (storage.MigrationResult{Applied: 7, Current: 7}) {
		t.Fatalf("fresh explicit Migrate() result = %#v, want seven applied migrations", result)
	}
	if got := server.sequenceCount(); got != 8 {
		t.Fatalf("migration sequences across explicit invocations = %d, want 8", got)
	}
}

func TestMigrationRepairsCommittedLedgerWithoutTerminalMarker(t *testing.T) {

	server := newMigrationProtocolServer(t)
	server.seedEmbeddedCatalog()
	server.clearUserVersion()
	handle := openMigrationContractHandle(t, server.URL)
	result, err := handle.Migrate(context.Background())
	if err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if result != (storage.MigrationResult{Current: 7}) {
		t.Fatalf("Migrate() result = %#v, want marker-only reconciliation", result)
	}
	if got := server.sequenceCount(); got != 0 {
		t.Fatalf("migration sequences = %d, want no migration replay", got)
	}
	if got := server.terminalSequenceCount(); got != 1 {
		t.Fatalf("terminal sequences = %d, want one marker repair", got)
	}
	if got := server.userVersionValue(); got != 7 {
		t.Fatalf("durable user_version = %d, want 6", got)
	}
}

func TestMigrationMarkerRepairDoesNotOverwriteConcurrentAdvance(t *testing.T) {

	server := newMigrationProtocolServer(t)
	server.seedEmbeddedCatalog()
	server.clearUserVersion()
	stalled, release := server.stallBeforeNextTerminalSequence()
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	handle := openMigrationContractHandle(t, server.URL)
	result := make(chan error, 1)
	go func() {
		_, err := handle.Migrate(context.Background())
		result <- err
	}()
	select {
	case <-stalled:
	case <-time.After(time.Second):
		t.Fatal("marker repair did not reach the locked race point")
	}
	server.setUserVersion(8)
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-result:
		if !errors.Is(err, ErrMigrationUnknownOutcome) {
			t.Fatalf("Migrate() error = %v, want ErrMigrationUnknownOutcome", err)
		}
	case <-time.After(time.Second):
		t.Fatal("marker repair did not return after race release")
	}
	if got := server.userVersionValue(); got != 8 {
		t.Fatalf("durable user_version = %d, want concurrent value 8 preserved", got)
	}

	fresh := openMigrationContractHandle(t, server.URL)
	_, err := fresh.Migrate(context.Background())
	if !errors.Is(err, ErrMigrationDrift) {
		t.Fatalf("fresh Migrate() error = %v, want ErrMigrationDrift", err)
	}
}

func TestMigrationMarkerRepairRejectsConcurrentLedgerPrefixReplacement(t *testing.T) {

	tests := []struct {
		name   string
		mutate func(*migrationProtocolServer)
	}{
		{name: "missing row", mutate: func(server *migrationProtocolServer) { server.deleteLedgerRow(1) }},
		{name: "mismatched number", mutate: func(server *migrationProtocolServer) {
			server.overrideLedgerRows([][]any{{integerValue(2), textValue(expectedMigrationChecksum)}})
		}},
		{name: "mismatched checksum", mutate: func(server *migrationProtocolServer) {
			server.corruptLedgerChecksum(1, strings.Repeat("0", 64))
		}},
		{name: "duplicate row", mutate: func(server *migrationProtocolServer) {
			server.overrideLedgerRows([][]any{
				{integerValue(1), textValue(expectedMigrationChecksum)},
				{integerValue(1), textValue(expectedMigrationChecksum)},
			})
		}},
		{name: "null row", mutate: func(server *migrationProtocolServer) {
			server.overrideLedgerRows([][]any{{nil, nil}})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			server.seedEmbeddedCatalog()
			server.clearUserVersion()
			stalled, release := server.stallBeforeNextTerminalSequence()
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			handle := openMigrationContractHandle(t, server.URL)
			result := make(chan error, 1)
			go func() {
				_, err := handle.Migrate(context.Background())
				result <- err
			}()
			select {
			case <-stalled:
			case <-time.After(time.Second):
				t.Fatal("marker repair did not reach the prefix race point")
			}
			tt.mutate(server)
			releaseOnce.Do(func() { close(release) })
			select {
			case err := <-result:
				if !errors.Is(err, ErrMigrationUnknownOutcome) {
					t.Fatalf("Migrate() error = %v, want ErrMigrationUnknownOutcome", err)
				}
			case <-time.After(time.Second):
				t.Fatal("marker repair did not return after prefix race release")
			}
			if got := server.userVersionValue(); got != 0 {
				t.Fatalf("durable user_version = %d, want unchanged 0", got)
			}
			if got := server.sequenceCount(); got != 0 {
				t.Fatalf("migration sequences = %d, want no schema replay", got)
			}

			fresh := openMigrationContractHandle(t, server.URL)
			_, err := fresh.Migrate(context.Background())
			if !errors.Is(err, ErrMigrationDrift) && !errors.Is(err, ErrMigrationInspect) {
				t.Fatalf("fresh Migrate() error = %v, want bounded drift or inspection rejection", err)
			}
		})
	}
}

func TestMigrationTerminalSequenceResponsesRequireSeparateMarkerVisibility(t *testing.T) {

	tests := []struct {
		name        string
		arm         func(*migrationProtocolServer)
		wantSuccess bool
	}{
		{name: "malformed json", arm: (*migrationProtocolServer).malformNextTerminalResponse},
		{name: "missing result", arm: (*migrationProtocolServer).omitNextTerminalResult},
		{name: "malformed autocommit", arm: (*migrationProtocolServer).malformNextTerminalAutocommit},
		{name: "false autocommit with visible marker", arm: (*migrationProtocolServer).falseNextTerminalAutocommit, wantSuccess: true},
		{name: "missing sequence payload with visible marker", arm: (*migrationProtocolServer).omitNextTerminalSequencePayload, wantSuccess: true},
		{name: "wrong sequence payload with visible marker", arm: (*migrationProtocolServer).wrongNextTerminalSequencePayload, wantSuccess: true},
		{name: "successful response without marker", arm: (*migrationProtocolServer).skipNextTerminalMarker},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			tt.arm(server)
			handle := openMigrationContractHandle(t, server.URL)
			result, err := handle.Migrate(context.Background())
			if tt.wantSuccess {
				if err != nil {
					t.Fatalf("Migrate() error = %v", err)
				}
				if result != (storage.MigrationResult{Applied: 7, Current: 7}) {
					t.Fatalf("Migrate() result = %#v, want proven migration", result)
				}
				if got := server.userVersionValue(); got != 7 {
					t.Fatalf("durable user_version = %d, want 6", got)
				}
				return
			}
			if !errors.Is(err, ErrMigrationUnknownOutcome) {
				t.Fatalf("Migrate() error = %v, want ErrMigrationUnknownOutcome", err)
			}
			if got := server.closeCount(); got == 0 {
				t.Fatal("unproven terminal session was returned without an exact-driver close request")
			}
			if !server.ledgerExists() {
				t.Fatal("terminal response failure lost the committed ledger")
			}
			if got := server.sequenceCount(); got != 1 {
				t.Fatalf("migration sequences = %d, want one without replay", got)
			}

			freshResult, freshErr := handle.Migrate(context.Background())
			if freshErr != nil {
				t.Fatalf("fresh Migrate() error = %v", freshErr)
			}
			if freshResult != (storage.MigrationResult{Applied: 6, Current: 7}) {
				t.Fatalf("fresh Migrate() result = %#v, want marker repair and migrations 2 through 4", freshResult)
			}
			if got := server.sequenceCount(); got != 7 {
				t.Fatalf("migration sequences after fresh reconciliation = %d, want only migrations 2 through 5 after no schema replay", got)
			}
		})
	}
}

func TestMigrationRejectsTerminalMarkerAheadOfLedger(t *testing.T) {

	server := newMigrationProtocolServer(t)
	server.setUserVersion(1)
	handle := openMigrationContractHandle(t, server.URL)
	_, err := handle.Migrate(context.Background())
	if !errors.Is(err, ErrMigrationDrift) {
		t.Fatalf("Migrate() error = %v, want ErrMigrationDrift", err)
	}
	if got := server.sequenceCount(); got != 0 {
		t.Fatalf("migration sequences = %d, want 0 after marker drift", got)
	}
}

func TestMigrationServerReportedSequenceFailureIsUnknownWithoutReplay(t *testing.T) {

	server := newMigrationProtocolServer(t)
	server.failNextMigration()
	handle := openMigrationContractHandle(t, server.URL)
	_, err := handle.Migrate(context.Background())
	if !errors.Is(err, ErrMigrationUnknownOutcome) {
		t.Fatalf("Migrate() error = %v, want ErrMigrationUnknownOutcome", err)
	}
	for _, raw := range []string{"raw", "synthetic-token", "SELECT", "private marker"} {
		if strings.Contains(err.Error(), raw) {
			t.Fatalf("Migrate() error %q contains fatal remote marker", err)
		}
	}
	if got := server.migrationStatementCount(); got != 0 {
		t.Fatalf("migration requests = %d, want 0", got)
	}
	if got := server.insertCount(); got != 0 {
		t.Fatalf("ledger inserts = %d, want 0", got)
	}
	if got := server.sequenceCount(); got != 1 {
		t.Fatalf("sequence requests = %d, want 1", got)
	}
}

func TestMigrationCurrentSchemaAvoidsAmbiguousFinalCommit(t *testing.T) {

	server := newMigrationProtocolServer(t)
	server.seedEmbeddedCatalog()
	server.headerOnlyNextCommitBeforeDurability()
	handle := openMigrationContractHandle(t, server.URL)
	result, err := handle.Migrate(context.Background())
	if err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if result != (storage.MigrationResult{Current: 7}) {
		t.Fatalf("Migrate() result = %#v, want current migration 3", result)
	}
	if got := server.countSQL(beginImmediateSQL); got != 0 {
		t.Fatalf("begin requests = %d, want 0 for current schema", got)
	}
	if got := server.commitCount(); got != 0 {
		t.Fatalf("commit requests = %d, want 0 for current schema", got)
	}
	if got := server.countSQL(rollbackSQL); got != 0 {
		t.Fatalf("rollback requests = %d, want 0 for current schema", got)
	}
}

func TestMigrationHeaderOnlyRollbackCannotConfirmCleanup(t *testing.T) {

	server := newMigrationProtocolServer(t)
	server.failNextMigration()
	server.headerOnlyNextRollback()
	handle := openMigrationContractHandle(t, server.URL)
	_, err := handle.Migrate(context.Background())
	if !errors.Is(err, ErrMigrationUnknownOutcome) {
		t.Fatalf("Migrate() error = %v, want ErrMigrationUnknownOutcome", err)
	}
	if got := server.sequenceCount(); got != 1 {
		t.Fatalf("sequence requests = %d, want 1", got)
	}
	if got := server.countSQL(rollbackSQL); got != 1 {
		t.Fatalf("rollback requests = %d, want 1", got)
	}
	if got := server.insertCount(); got != 0 {
		t.Fatalf("ledger inserts = %d, want 0", got)
	}
}

func TestMigrationRejectsCredentialedAndNonLoopbackEndpointsBeforeConnection(t *testing.T) {

	tests := []storage.Endpoint{
		{URL: "https://database.example", Token: "synthetic-token"},
		{URL: "https://database.example"},
		{URL: "turso://database.example", Token: "synthetic-token"},
	}
	for _, endpoint := range tests {
		database := &migrationFakeDatabase{}
		adapter, err := newAdapter(Options{}, func(string, string) databaseHandle { return database })
		if err != nil {
			t.Fatalf("newAdapter() error = %v", err)
		}
		handle, err := adapter.Open(context.Background(), endpoint)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		_, err = handle.Migrate(context.Background())
		if !errors.Is(err, ErrMigrationNotAllowed) {
			t.Fatalf("Migrate() error = %v, want ErrMigrationNotAllowed", err)
		}
		if database.connCalls.Load() != 0 {
			t.Fatalf("database connections = %d, want 0", database.connCalls.Load())
		}
	}
}

func TestMigrationStatementFailureAttemptsRollbackAndReturnsUnknown(t *testing.T) {

	server := newMigrationProtocolServer(t)
	server.failNextMigration()
	handle := openMigrationContractHandle(t, server.URL)
	_, err := handle.Migrate(context.Background())
	if !errors.Is(err, ErrMigrationUnknownOutcome) {
		t.Fatalf("Migrate() error = %v, want ErrMigrationUnknownOutcome", err)
	}
	for _, private := range []string{"raw", "synthetic-token", "SELECT", "private marker"} {
		if strings.Contains(err.Error(), private) {
			t.Fatalf("Migrate() error %q contains remote diagnostic", err)
		}
	}
	if got := server.countSQL(rollbackSQL); got != 1 {
		t.Fatalf("rollback requests = %d, want 1", got)
	}
	if server.ledgerExists() {
		t.Fatal("failed migration left ledger table committed")
	}
	if got := server.sequenceCount(); got != 1 {
		t.Fatalf("sequence requests = %d, want 1 without replay", got)
	}
	second := openMigrationContractHandle(t, server.URL)
	result, err := second.Migrate(context.Background())
	if err != nil {
		t.Fatalf("fresh Migrate() error = %v", err)
	}
	if result != (storage.MigrationResult{Applied: 7, Current: 7}) {
		t.Fatalf("fresh Migrate() result = %#v, want atomic reconciliation", result)
	}
	if got := server.sequenceCount(); got != 8 {
		t.Fatalf("sequence requests across explicit invocations = %d, want 8", got)
	}
}

func TestMigrationStageFailuresAreSanitizedAndNeverReplayed(t *testing.T) {

	tests := []struct {
		name         string
		statement    string
		occurrence   int
		seedLedger   bool
		wantCategory error
		wantRollback int
		wantSequence int
		wantTerminal int
	}{
		{name: "server-reported begin failure", statement: beginImmediateSQL, wantCategory: ErrMigrationUnknownOutcome, wantRollback: 1, wantSequence: 1},
		{name: "ledger existence", statement: ledgerExistsSQL, wantCategory: ErrMigrationInspect},
		{name: "terminal marker inspection", statement: userVersionSQL, wantCategory: ErrMigrationInspect},
		{name: "ledger rows", statement: ledgerRowsSQL, seedLedger: true, wantCategory: ErrMigrationInspect},
		{name: "migration statement", statement: "migration", wantCategory: ErrMigrationUnknownOutcome, wantRollback: 1, wantSequence: 1},
		{name: "ledger insertion", statement: ledgerInsertSQL, wantCategory: ErrMigrationUnknownOutcome, wantRollback: 1, wantSequence: 1},
		{name: "server-reported commit failure", statement: commitSQL, wantCategory: ErrMigrationUnknownOutcome, wantRollback: 1, wantSequence: 1},
		{name: "terminal sequence", statement: "terminal", wantCategory: ErrMigrationUnknownOutcome, wantRollback: 1, wantSequence: 1, wantTerminal: 1},
		{name: "post-commit terminal marker inspection", statement: userVersionSQL, occurrence: 2, wantCategory: ErrMigrationUnknownOutcome, wantRollback: 1, wantSequence: 1, wantTerminal: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			if tt.seedLedger {
				server.seedLedger(1, expectedMigrationChecksum)
			}
			if tt.statement != "" {
				if tt.occurrence > 1 {
					server.failNthSQL(tt.statement, tt.occurrence)
				} else {
					server.failNextSQL(tt.statement)
				}
			}
			handle := openMigrationContractHandle(t, server.URL)
			_, err := handle.Migrate(context.Background())
			if !errors.Is(err, tt.wantCategory) {
				t.Fatalf("Migrate() error = %v, want %v", err, tt.wantCategory)
			}
			for _, raw := range []string{"raw", "synthetic-token", "SELECT", "private marker"} {
				if strings.Contains(err.Error(), raw) {
					t.Fatalf("Migrate() error %q contains raw marker", err)
				}
			}
			if got := server.countSQL(rollbackSQL); got != tt.wantRollback {
				t.Fatalf("rollback requests = %d, want %d", got, tt.wantRollback)
			}
			if got := server.sequenceCount(); got != tt.wantSequence {
				t.Fatalf("sequence requests = %d, want %d", got, tt.wantSequence)
			}
			if got := server.terminalSequenceCount(); got != tt.wantTerminal {
				t.Fatalf("terminal sequence requests = %d, want %d", got, tt.wantTerminal)
			}
			if tt.wantSequence == 0 && tt.statement != "" && server.countStageRequests(tt.statement) != 1 {
				t.Fatalf("inspection stage %q was replayed", tt.statement)
			}
		})
	}
}

func TestMigrationConnectionAcquisitionFailuresAreSanitizedAndPreserveDeadline(t *testing.T) {

	raw := "raw synthetic-token https://private.example SELECT secret"
	tests := []struct {
		name         string
		conn         func(context.Context) (*sql.Conn, error)
		ctx          func() (context.Context, context.CancelFunc)
		wantDeadline bool
	}{
		{
			name: "immediate",
			conn: func(context.Context) (*sql.Conn, error) { return nil, errors.New(raw) },
			ctx:  func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
		},
		{
			name: "deadline",
			conn: func(ctx context.Context) (*sql.Conn, error) {
				select {
				case <-ctx.Done():
					return nil, errors.New(raw)
				case <-time.After(time.Second):
					return nil, errors.New("synthetic acquisition test timeout")
				}
			},
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 20*time.Millisecond)
			},
			wantDeadline: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database := &migrationFakeDatabase{conn: tt.conn}
			adapter, err := newAdapter(Options{MigrationTimeout: time.Second}, func(string, string) databaseHandle { return database })
			if err != nil {
				t.Fatalf("newAdapter() error = %v", err)
			}
			handle, err := adapter.Open(context.Background(), storage.Endpoint{URL: "http://127.0.0.1:8080"})
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			ctx, cancel := tt.ctx()
			defer cancel()
			_, err = handle.Migrate(ctx)
			if !errors.Is(err, ErrMigrationAcquire) {
				t.Fatalf("Migrate() error = %v, want ErrMigrationAcquire", err)
			}
			if tt.wantDeadline && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Migrate() error = %v, want context deadline", err)
			}
			if strings.Contains(err.Error(), raw) {
				t.Fatalf("Migrate() error %q contains raw marker", err)
			}
		})
	}
}

func TestMigrationConnectionAcquisitionStagesAreSanitized(t *testing.T) {

	raw := "raw synthetic-token https://private.example SELECT secret"
	tests := []struct {
		name         string
		failAt       int32
		wantCategory error
		wantSequence int
	}{
		{name: "initial inspection", failAt: 1, wantCategory: ErrMigrationAcquire},
		{name: "application", failAt: 2, wantCategory: ErrMigrationAcquire},
		{name: "post-commit verification", failAt: 3, wantCategory: ErrMigrationUnknownOutcome, wantSequence: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			adapter, err := New(Options{MigrationTimeout: 5 * time.Second, CleanupTimeout: 5 * time.Second})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			opened, err := adapter.Open(context.Background(), storage.Endpoint{URL: server.URL})
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			handle := opened.(*handle)
			handle.database = &failNthConnectionDatabase{
				databaseHandle: handle.database,
				failAt:         tt.failAt,
				raw:            raw,
			}
			t.Cleanup(func() { _ = handle.Close() })

			_, err = handle.Migrate(context.Background())
			if !errors.Is(err, tt.wantCategory) {
				t.Fatalf("Migrate() error = %v, want %v", err, tt.wantCategory)
			}
			if strings.Contains(err.Error(), raw) {
				t.Fatalf("Migrate() error %q contains raw marker", err)
			}
			if got := server.sequenceCount(); got != tt.wantSequence {
				t.Fatalf("sequence requests = %d, want %d", got, tt.wantSequence)
			}
		})
	}
}

func TestMigrationPostCommitInspectionFailuresAreUnknownWithoutReplay(t *testing.T) {

	tests := []struct {
		name       string
		statement  string
		occurrence int
	}{
		{name: "ledger existence", statement: ledgerExistsSQL, occurrence: 2},
		{name: "ledger rows", statement: ledgerRowsSQL, occurrence: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			server.failNthSQL(tt.statement, tt.occurrence)
			handle := openMigrationContractHandle(t, server.URL)
			_, err := handle.Migrate(context.Background())
			if !errors.Is(err, ErrMigrationUnknownOutcome) {
				t.Fatalf("Migrate() error = %v, want ErrMigrationUnknownOutcome", err)
			}
			for _, raw := range []string{"raw", "synthetic-token", "SELECT", "private marker"} {
				if strings.Contains(err.Error(), raw) {
					t.Fatalf("Migrate() error %q contains raw marker", err)
				}
			}
			if got := server.sequenceCount(); got != 1 {
				t.Fatalf("sequence requests = %d, want 1 without replay", got)
			}
		})
	}
}

func TestMigrationRejectsMalformedAndOverLimitLedgerRows(t *testing.T) {

	tests := []struct {
		name string
		seed map[int]string
	}{
		{name: "missing first", seed: map[int]string{2: strings.Repeat("0", 64)}},
		{name: "unknown number", seed: map[int]string{1: expectedMigrationChecksum, 2: strings.Repeat("0", 64)}},
		{name: "negative number", seed: map[int]string{-1: strings.Repeat("0", 64)}},
		{name: "uppercase checksum", seed: map[int]string{1: strings.Repeat("A", 64)}},
		{name: "oversized checksum", seed: map[int]string{1: strings.Repeat("a", 65)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			for number, checksum := range tt.seed {
				server.seedLedger(number, checksum)
			}
			handle := openMigrationContractHandle(t, server.URL)
			_, err := handle.Migrate(context.Background())
			if !errors.Is(err, ErrMigrationDrift) {
				t.Fatalf("Migrate() error = %v, want ErrMigrationDrift", err)
			}
			if got := server.insertCount(); got != 0 {
				t.Fatalf("ledger inserts = %d, want 0", got)
			}
		})
	}
}

func TestMigrationStalledBeginAcknowledgementIsUnknownAndSanitized(t *testing.T) {

	server := newMigrationProtocolServer(t)
	started, release, finished := server.stallNext(beginImmediateSQL)
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	adapter, err := New(Options{MigrationTimeout: 5 * time.Second, CleanupTimeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	handle, err := adapter.Open(context.Background(), storage.Endpoint{URL: server.URL})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	result := make(chan error, 1)
	go func() {
		_, migrateErr := handle.Migrate(ctx)
		result <- migrateErr
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("Migrate() did not reach stalled BEGIN acknowledgement")
	}
	canceledAt := time.Now()
	cancel()
	select {
	case err = <-result:
	case <-time.After(time.Second):
		t.Fatal("Migrate() did not return after explicit cancellation")
	}
	if elapsed := time.Since(canceledAt); elapsed >= 500*time.Millisecond {
		t.Fatalf("Migrate() cancellation elapsed = %v, want bounded below server fallback", elapsed)
	}
	if !errors.Is(err, ErrMigrationUnknownOutcome) || !errors.Is(err, context.Canceled) {
		t.Fatalf("Migrate() error = %v, want unknown outcome with cancellation", err)
	}
	if got := server.countSQL(rollbackSQL); got != 1 {
		t.Fatalf("rollback requests = %d, want 1", got)
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("stalled BEGIN handler did not finish after release")
	}
}

func TestMigrationProtocolProvidedBaseURLCanChangeAuthority(t *testing.T) {

	var changedAuthorityRequests atomic.Int32
	changedAuthority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		changedAuthorityRequests.Add(1)
		http.Error(w, "synthetic changed authority", http.StatusBadGateway)
	}))
	t.Cleanup(changedAuthority.Close)

	initial := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		encoder := json.NewEncoder(w)
		_ = encoder.Encode(map[string]any{"baton": "synthetic-baton", "base_url": changedAuthority.URL})
		_ = encoder.Encode(map[string]any{"type": "step_begin", "step": 0, "cols": []any{}})
		_ = encoder.Encode(map[string]any{"type": "step_end", "step": 0})
	}))
	t.Cleanup(initial.Close)

	handle := openMigrationContractHandle(t, initial.URL)
	_, err := handle.Migrate(context.Background())
	if !errors.Is(err, ErrMigrationInspect) {
		t.Fatalf("Migrate() error = %v, want inspection failure after authority change", err)
	}
	if changedAuthorityRequests.Load() == 0 {
		t.Fatal("driver did not follow protocol-provided base_url authority")
	}
}

func TestMigrationDriverFollowsCredentialFreeRedirect(t *testing.T) {

	var redirectedRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectedRequests.Add(1)
		http.Error(w, "synthetic redirect destination", http.StatusBadGateway)
	}))
	t.Cleanup(destination.Close)

	initial := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(initial.Close)

	handle := openMigrationContractHandle(t, initial.URL)
	_, err := handle.Migrate(context.Background())
	if !errors.Is(err, ErrMigrationInspect) {
		t.Fatalf("Migrate() error = %v, want sanitized inspection failure", err)
	}
	if redirectedRequests.Load() != 1 {
		t.Fatalf("redirected requests = %d, want 1", redirectedRequests.Load())
	}
}

func TestMigrationRejectsDriverBufferedOversizedLogicalResult(t *testing.T) {

	server := newMigrationProtocolServer(t)
	server.seedLedger(1, strings.Repeat("a", 1<<20))
	handle := openMigrationContractHandle(t, server.URL)
	_, err := handle.Migrate(context.Background())
	if !errors.Is(err, ErrMigrationDrift) {
		t.Fatalf("Migrate() error = %v, want post-decode drift rejection", err)
	}
}

func TestMigrationRejectsDuplicateAndExcessLogicalRows(t *testing.T) {

	row := []any{integerValue(1), textValue(expectedMigrationChecksum)}
	tests := []struct {
		name string
		rows [][]any
	}{
		{name: "duplicate", rows: [][]any{row, row}},
		{name: "catalog limit plus one", rows: slices.Repeat([][]any{row}, expectedMaximumMigrationCount+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			server.overrideLedgerRows(tt.rows)
			handle := openMigrationContractHandle(t, server.URL)
			_, err := handle.Migrate(context.Background())
			if !errors.Is(err, ErrMigrationDrift) {
				t.Fatalf("Migrate() error = %v, want ErrMigrationDrift", err)
			}
		})
	}
}

func TestMigrationStalledWriteCommitAndCleanupAreNotReplayed(t *testing.T) {

	tests := []struct {
		name        string
		stall       string
		wantDurable bool
	}{
		{name: "migration statement", stall: "migration"},
		{name: "commit before durability", stall: commitSQL},
		{name: "commit after durability", stall: commitAfterDurabilityStage, wantDurable: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			started, release, finished := server.stallNext(tt.stall)
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			handle := openMigrationContractHandleOptions(t, server.URL, Options{
				MigrationTimeout: 5 * time.Second,
				CleanupTimeout:   20 * time.Millisecond,
			})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			t.Cleanup(cancel)
			result := make(chan error, 1)
			go func() {
				_, migrateErr := handle.Migrate(ctx)
				result <- migrateErr
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("Migrate() did not reach the named stalled stage")
			}
			canceledAt := time.Now()
			cancel()
			var err error
			select {
			case err = <-result:
			case <-time.After(time.Second):
				t.Fatal("Migrate() did not return after explicit cancellation")
			}
			if elapsed := time.Since(canceledAt); elapsed >= 500*time.Millisecond {
				t.Fatalf("Migrate() cancellation elapsed = %v, want bounded below server fallback", elapsed)
			}
			if !errors.Is(err, ErrMigrationUnknownOutcome) || !errors.Is(err, context.Canceled) {
				t.Fatalf("Migrate() error = %v, want unknown outcome with cancellation", err)
			}
			if got := server.sequenceCount(); got != 1 {
				t.Fatalf("sequence requests = %d, want 1", got)
			}
			if got := server.countSQL(rollbackSQL); got != 1 {
				t.Fatalf("rollback requests = %d, want 1", got)
			}
			if got := server.ledgerExists(); got != tt.wantDurable {
				t.Fatalf("durable ledger = %t, want %t", got, tt.wantDurable)
			}
			releaseOnce.Do(func() { close(release) })
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("stalled server stage did not finish after release")
			}

			fresh := openMigrationContractHandle(t, server.URL)
			freshResult, freshErr := fresh.Migrate(context.Background())
			if freshErr != nil {
				t.Fatalf("fresh Migrate() error = %v", freshErr)
			}
			wantFresh := storage.MigrationResult{Applied: 7, Current: 7}
			wantSequences := 8
			if tt.wantDurable {
				wantFresh = storage.MigrationResult{Applied: 6, Current: 7}
				wantSequences = 7
			}
			if freshResult != wantFresh {
				t.Fatalf("fresh Migrate() result = %#v, want %#v", freshResult, wantFresh)
			}
			if got := server.sequenceCount(); got != wantSequences {
				t.Fatalf("migration sequences after fresh reconciliation = %d, want %d", got, wantSequences)
			}
		})
	}
}

func TestMigrationRollbackCleanupUsesIndependentContext(t *testing.T) {

	server := newMigrationProtocolServer(t)
	started, release, finished := server.stallNext(rollbackSQL)
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	server.failNextMigration()
	handle := openMigrationContractHandleOptions(t, server.URL, Options{
		MigrationTimeout: 5 * time.Second,
		CleanupTimeout:   time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	result := make(chan error, 1)
	go func() {
		_, migrateErr := handle.Migrate(ctx)
		result <- migrateErr
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("Migrate() did not reach stalled rollback cleanup")
	}
	if got := server.countSQL(rollbackSQL); got != 1 {
		t.Fatalf("rollback requests = %d, want 1", got)
	}
	cancel()
	select {
	case err := <-result:
		t.Fatalf("Migrate() returned while independent cleanup was stalled: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	select {
	case <-finished:
		t.Fatal("rollback cleanup finished from caller cancellation")
	default:
	}
	if server.ledgerExists() {
		t.Fatal("failed migration became durable during rollback cleanup")
	}
	if got := server.sequenceCount(); got != 1 {
		t.Fatalf("migration sequences = %d, want one without replay", got)
	}

	releasedAt := time.Now()
	releaseOnce.Do(func() { close(release) })
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("rollback cleanup did not finish after release")
	}
	var err error
	select {
	case err = <-result:
	case <-time.After(time.Second):
		t.Fatal("Migrate() did not return after rollback cleanup release")
	}
	if elapsed := time.Since(releasedAt); elapsed >= 500*time.Millisecond {
		t.Fatalf("Migrate() cleanup release elapsed = %v, want bounded completion", elapsed)
	}
	if !errors.Is(err, ErrMigrationUnknownOutcome) || !errors.Is(err, context.Canceled) {
		t.Fatalf("Migrate() error = %v, want unknown outcome with caller cancellation", err)
	}

	fresh := openMigrationContractHandle(t, server.URL)
	freshResult, freshErr := fresh.Migrate(context.Background())
	if freshErr != nil {
		t.Fatalf("fresh Migrate() error = %v", freshErr)
	}
	if freshResult != (storage.MigrationResult{Applied: 7, Current: 7}) {
		t.Fatalf("fresh Migrate() result = %#v, want four applied migrations", freshResult)
	}
	if got := server.sequenceCount(); got != 8 {
		t.Fatalf("migration sequences after fresh reconciliation = %d, want 8", got)
	}
}

func TestConcurrentMigrationSequencesConvergeAfterUnknownLockOutcome(t *testing.T) {

	server := newMigrationProtocolServer(t)
	stalled, release, _ := server.stallNext("migration")
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	firstResult := make(chan error, 1)
	first := openMigrationContractHandle(t, server.URL)
	go func() {
		_, err := first.Migrate(context.Background())
		firstResult <- err
	}()
	select {
	case <-stalled:
	case <-time.After(time.Second):
		t.Fatal("first migration did not reach stalled sequence")
	}

	second := openMigrationContractHandle(t, server.URL)
	_, secondErr := second.Migrate(context.Background())
	if !errors.Is(secondErr, ErrMigrationUnknownOutcome) {
		t.Fatalf("concurrent Migrate() error = %v, want ErrMigrationUnknownOutcome", secondErr)
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-firstResult:
		if err != nil {
			t.Fatalf("first Migrate() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first migration did not finish after release")
	}

	third := openMigrationContractHandle(t, server.URL)
	result, err := third.Migrate(context.Background())
	if err != nil {
		t.Fatalf("reconciliation Migrate() error = %v", err)
	}
	if result != (storage.MigrationResult{Current: 7}) {
		t.Fatalf("reconciliation result = %#v, want current migration 3", result)
	}
	if got := server.sequenceCount(); got != 8 {
		t.Fatalf("sequence requests = %d, want seven successful and one rejected sequence", got)
	}
}

func TestDriverStreamCloseHasNoCallerControlledDeadline(t *testing.T) {

	closeStarted := make(chan struct{})
	releaseClose := make(chan struct{})
	var releaseOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/cursor":
			encoder := json.NewEncoder(w)
			_ = encoder.Encode(map[string]any{"baton": "synthetic-baton", "base_url": nil})
			_ = encoder.Encode(map[string]any{"type": "step_begin", "step": 0, "cols": []any{}})
			_ = encoder.Encode(map[string]any{"type": "step_end", "step": 0})
			_ = encoder.Encode(map[string]any{"type": "step_begin", "step": 1, "cols": []any{}})
			_ = encoder.Encode(map[string]any{"type": "step_end", "step": 1})
		case "/v3/pipeline":
			close(closeStarted)
			select {
			case <-releaseClose:
			case <-time.After(time.Second):
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"baton": nil, "base_url": nil,
				"results": []any{map[string]any{"type": "ok", "response": map[string]any{"type": "close"}}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseClose) }) })
	adapter, err := New(Options{PingTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	handle, err := adapter.Open(context.Background(), storage.Endpoint{URL: server.URL})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := handle.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}

	closed := make(chan error, 1)
	go func() { closed <- handle.Close() }()
	select {
	case <-closeStarted:
	case <-time.After(time.Second):
		t.Fatal("Close() did not reach stream close request")
	}
	select {
	case err := <-closed:
		t.Fatalf("Close() returned before server release: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(releaseClose) })
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close() did not finish after server release")
	}
}

func openMigrationContractHandle(t *testing.T, endpoint string) storage.Handle {
	return openMigrationContractHandleOptions(t, endpoint, Options{
		PingTimeout:      5 * time.Second,
		MigrationTimeout: 5 * time.Second,
		CleanupTimeout:   5 * time.Second,
	})
}

func openMigrationContractHandleOptions(t *testing.T, endpoint string, options Options) storage.Handle {
	t.Helper()

	adapter, err := New(options)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	handle, err := adapter.Open(context.Background(), storage.Endpoint{URL: endpoint})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	return handle
}

type migrationFakeDatabase struct {
	conn      func(context.Context) (*sql.Conn, error)
	connCalls atomic.Int32
}

func (d *migrationFakeDatabase) PingContext(context.Context) error { return nil }

func (d *migrationFakeDatabase) Conn(ctx context.Context) (*sql.Conn, error) {
	d.connCalls.Add(1)
	if d.conn != nil {
		return d.conn(ctx)
	}
	return nil, errors.New("synthetic connection unavailable")
}

func (d *migrationFakeDatabase) Close() error { return nil }

type failNthConnectionDatabase struct {
	databaseHandle
	calls  atomic.Int32
	failAt int32
	raw    string
}

func (d *failNthConnectionDatabase) Conn(ctx context.Context) (*sql.Conn, error) {
	if d.calls.Add(1) == d.failAt {
		return nil, errors.New(d.raw)
	}
	return d.databaseHandle.Conn(ctx)
}

type migrationProtocolServer struct {
	*httptest.Server

	testing                       *testing.T
	mu                            sync.Mutex
	ledger                        map[int]string
	pending                       map[int]string
	userVersion                   int
	pendingUserVersion            int
	inTxn                         bool
	exists                        bool
	pendingExists                 bool
	pendingSecondSchema           bool
	pendingThirdSchema            bool
	pendingCredentialSchema       bool
	pendingLifecycleSchema        bool
	pendingCurrentDiscoverySchema bool
	pendingGateDecisionSchema     bool
	pendingCandidateContentSchema bool
	drop                          bool
	dropBeforeCommit              bool
	headerOnlyCommit              bool
	headerOnlyRollback            bool
	headerOnlyBegin               bool
	headerOnlyMigration           bool
	malformedSequence             bool
	omitSequenceResult            bool
	malformedAutocommit           bool
	omitSequencePayload           bool
	wrongSequencePayload          bool
	falseAutocommit               bool
	holdTransaction               bool
	terminalMalformed             bool
	terminalOmitResult            bool
	terminalBadAuto               bool
	terminalFalseAuto             bool
	terminalOmitPayload           bool
	terminalWrongPayload          bool
	terminalSkipMarker            bool
	ignoredRollbacks              int
	ignoredCloses                 int
	failSQL                       string
	failSQLSkip                   int
	ledgerRowsOverride            [][]any
	stallSQL                      string
	stallStarted                  chan struct{}
	stallRelease                  chan struct{}
	stallFinished                 chan struct{}
	beforeSequenceStart           chan struct{}
	beforeSequenceAllow           chan struct{}
	beforeTerminalStart           chan struct{}
	beforeTerminalAllow           chan struct{}
	secondSchema                  bool
	thirdSchema                   bool
	credentialSchema              bool
	lifecycleSchema               bool
	currentDiscoverySchema        bool
	gateDecisionSchema            bool
	candidateContentSchema        bool
	accounts                      map[string]string
	cursors                       map[string]string
	credentials                   map[string]syntheticCredential
	lifecycles                    map[string]syntheticLifecycle
	currentAttempts               map[string]*syntheticCurrentDiscoveryAttempt
	discoveredMessages            map[string]map[string]syntheticDiscoveredMessage
	discoveredRecords             map[string]syntheticDiscoveredMessage
	gateDecisions                 map[string]syntheticGateDecision
	candidateContents             map[string]syntheticCandidateContent
	persistenceMode               string
	persistenceStatement          string
	persistenceStarted            chan struct{}
	persistenceRelease            chan struct{}
	barrierSQL                    string
	barrierTarget                 int
	barrierArrived                int
	barrierStarted                chan struct{}
	barrierRelease                chan struct{}
	persistenceRows               map[string][][]any
	persistenceColumns            map[string][]any
	nextCursorBaseURL             string
	nextCursorBaton               int
	closedCursorAt                map[string]int
	closedCursorCount             map[string]int
	records                       []migrationRequest
	pipelineRecords               []migrationPipelineRequest
}

type migrationProtocolHost struct {
	once   sync.Once
	mu     sync.RWMutex
	server *httptest.Server
	active *migrationProtocolServer
	lease  chan struct{}
}

var sharedMigrationProtocolHost migrationProtocolHost

type migrationRequest struct {
	baton         *string
	sql           string
	args          []protocolValue
	namedArgCount int
	wantRows      bool
	bodyBytes     int
}

type migrationPipelineRequest struct {
	baton    *string
	requests []migrationStreamRequest
}

type syntheticLifecycle struct {
	state      string
	version    int64
	reason     *string
	revocation string
}

type syntheticCurrentDiscoveryAttempt struct {
	attemptID       string
	expected        string
	next            string
	messageCount    int
	encodedBytes    int64
	manifestHash    string
	manifestWitness string
	state           string
	staging         map[int]syntheticDiscoveredMessage
}

type syntheticDiscoveredMessage struct {
	recordID     string
	accountID    string
	messageID    string
	threadID     string
	version      int64
	metadataJSON string
	metadataHash string
	encodedBytes int64
	rowWitness   string
}

type syntheticGateDecision struct {
	version     int64
	sourceHash  string
	inputHash   string
	outcome     string
	reasonJSON  string
	evaluatedAt int64
}

type syntheticCandidateContent struct {
	extractorVersion int64
	sourceHash       string
	gateVersion      int64
	gateInputHash    string
	sourceKind       string
	excerpt          string
	excerptBytes     int64
	excerptLimit     int64
	truncated        int64
	contentHash      string
	fetchedAt        int64
}

func syntheticRowWitness(message syntheticDiscoveredMessage) string {
	return fmt.Sprintf("%08x%s%08x%s%08x%s%08x%08x%s%08x%s",
		len(message.recordID), hex.EncodeToString([]byte(message.recordID)),
		len(message.messageID), hex.EncodeToString([]byte(message.messageID)),
		len(message.threadID), hex.EncodeToString([]byte(message.threadID)),
		message.version, len(message.metadataJSON), hex.EncodeToString([]byte(message.metadataJSON)),
		len(message.metadataHash), hex.EncodeToString([]byte(message.metadataHash)))
}

func syntheticManifestWitness(attempt *syntheticCurrentDiscoveryAttempt) string {
	var witness strings.Builder
	witness.WriteString("696e626f78676174652f63757272656e742d73796e632d6d616e69666573742f763100")
	_, _ = fmt.Fprintf(&witness, "%08x", attempt.messageCount)
	for ordinal := 0; ordinal < attempt.messageCount; ordinal++ {
		witness.WriteString(attempt.staging[ordinal].rowWitness)
	}
	return witness.String()
}

type migrationStreamRequest struct {
	Type      string            `json:"type"`
	SQL       string            `json:"sql"`
	Args      []json.RawMessage `json:"args"`
	NamedArgs []json.RawMessage `json:"named_args"`
}

type protocolValue struct {
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

type protocolCursorRequest struct {
	Baton *string `json:"baton"`
	Batch struct {
		Steps []struct {
			Stmt struct {
				SQL       string            `json:"sql"`
				Args      []protocolValue   `json:"args"`
				NamedArgs []json.RawMessage `json:"named_args"`
				WantRows  bool              `json:"want_rows"`
			} `json:"stmt"`
		} `json:"steps"`
	} `json:"batch"`
}

func newMigrationProtocolServer(t *testing.T) *migrationProtocolServer {
	t.Helper()
	sharedMigrationProtocolHost.once.Do(func() {
		sharedMigrationProtocolHost.lease = make(chan struct{}, 1)
		sharedMigrationProtocolHost.lease <- struct{}{}
		sharedMigrationProtocolHost.server = httptest.NewServer(http.HandlerFunc(sharedMigrationProtocolHost.serveHTTP))
	})
	select {
	case <-sharedMigrationProtocolHost.lease:
	case <-time.After(30 * time.Second):
		t.Fatal("timed out acquiring reusable synthetic protocol server")
	}
	server := &migrationProtocolServer{
		testing:            t,
		ledger:             make(map[int]string),
		accounts:           make(map[string]string),
		cursors:            make(map[string]string),
		credentials:        make(map[string]syntheticCredential),
		lifecycles:         make(map[string]syntheticLifecycle),
		currentAttempts:    make(map[string]*syntheticCurrentDiscoveryAttempt),
		discoveredMessages: make(map[string]map[string]syntheticDiscoveredMessage),
		discoveredRecords:  make(map[string]syntheticDiscoveredMessage),
		gateDecisions:      make(map[string]syntheticGateDecision),
		candidateContents:  make(map[string]syntheticCandidateContent),
		persistenceRows:    make(map[string][][]any),
		persistenceColumns: make(map[string][]any),
		closedCursorAt:     make(map[string]int),
		closedCursorCount:  make(map[string]int),
	}
	server.Server = sharedMigrationProtocolHost.server
	sharedMigrationProtocolHost.mu.Lock()
	sharedMigrationProtocolHost.active = server
	sharedMigrationProtocolHost.mu.Unlock()
	t.Cleanup(func() {
		sharedMigrationProtocolHost.mu.Lock()
		sharedMigrationProtocolHost.active = nil
		sharedMigrationProtocolHost.mu.Unlock()
		sharedMigrationProtocolHost.lease <- struct{}{}
	})
	return server
}

func (h *migrationProtocolHost) serveHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	active := h.active
	h.mu.RUnlock()
	if active == nil {
		http.Error(w, "synthetic protocol server is not leased", http.StatusServiceUnavailable)
		return
	}
	active.serveHTTP(w, r)
}

func closeMigrationProtocolHost() {
	sharedMigrationProtocolHost.mu.Lock()
	server := sharedMigrationProtocolHost.server
	sharedMigrationProtocolHost.server = nil
	sharedMigrationProtocolHost.active = nil
	sharedMigrationProtocolHost.mu.Unlock()
	if server != nil {
		server.Close()
	}
	if transport, ok := http.DefaultTransport.(interface{ CloseIdleConnections() }); ok {
		transport.CloseIdleConnections()
	}
}

func (s *migrationProtocolServer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "" {
		s.testing.Errorf("Authorization header is present in credential-free migration")
	}
	switch r.URL.Path {
	case "/v3/cursor":
		s.serveCursor(w, r)
	case "/v3/pipeline":
		s.servePipeline(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *migrationProtocolServer) serveCursor(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, storage.MaximumCurrentDiscoveryStageWireBytes+1))
	if err != nil {
		s.testing.Errorf("read cursor request: %v", err)
		http.Error(w, "invalid synthetic request", http.StatusBadRequest)
		return
	}
	var request protocolCursorRequest
	if err := json.Unmarshal(body, &request); err != nil || len(request.Batch.Steps) == 0 {
		s.testing.Errorf("decode cursor request: %v", err)
		http.Error(w, "invalid synthetic request", http.StatusBadRequest)
		return
	}
	statement := request.Batch.Steps[0].Stmt

	s.mu.Lock()
	s.records = append(s.records, migrationRequest{
		baton:         request.Baton,
		sql:           statement.SQL,
		args:          statement.Args,
		namedArgCount: len(statement.NamedArgs),
		wantRows:      statement.WantRows,
		bodyBytes:     len(body),
	})
	responseBaton := ""
	if request.Baton == nil {
		s.nextCursorBaton++
		responseBaton = fmt.Sprintf("synthetic-baton-%d", s.nextCursorBaton)
	} else {
		responseBaton = *request.Baton
	}
	responseBaseURL := s.nextCursorBaseURL
	s.nextCursorBaseURL = ""
	if s.headerOnlyBegin && statement.SQL == beginImmediateSQL {
		s.headerOnlyBegin = false
		s.mu.Unlock()
		writeHeaderOnlyCursorResponse(w, responseBaton)
		return
	}
	if s.headerOnlyMigration && strings.HasPrefix(statement.SQL, "CREATE TABLE inboxgate_schema_migrations") {
		s.headerOnlyMigration = false
		s.mu.Unlock()
		writeHeaderOnlyCursorResponse(w, responseBaton)
		return
	}
	if statement.SQL == beginImmediateSQL && s.inTxn {
		s.mu.Unlock()
		s.writeStatementFailure(w, true, responseBaton)
		return
	}
	if s.barrierSQL == statement.SQL && s.barrierArrived < s.barrierTarget {
		s.barrierArrived++
		if s.barrierArrived == s.barrierTarget {
			close(s.barrierStarted)
		}
		release := s.barrierRelease
		s.mu.Unlock()
		select {
		case <-release:
		case <-time.After(time.Second):
		}
		s.mu.Lock()
	}
	if s.persistenceStatement == statement.SQL && s.persistenceStarted != nil && s.persistenceMode != "body-stall" {
		started := s.persistenceStarted
		release := s.persistenceRelease
		s.persistenceStarted = nil
		s.persistenceRelease = nil
		close(started)
		s.mu.Unlock()
		select {
		case <-release:
		case <-time.After(time.Second):
		}
		s.mu.Lock()
	}
	if s.persistenceStatement == statement.SQL && s.persistenceMode == "clean-eof" {
		s.persistenceMode = ""
		s.persistenceStatement = ""
		s.mu.Unlock()
		writeHeaderOnlyCursorResponse(w, responseBaton)
		return
	}
	if s.persistenceStatement == statement.SQL && s.persistenceMode == "drop-before" {
		s.persistenceMode = ""
		s.persistenceStatement = ""
		s.mu.Unlock()
		writeDroppedCursorResponse(w, responseBaton)
		return
	}
	if s.persistenceStatement == statement.SQL && s.persistenceMode == "success-without-apply" {
		s.persistenceMode = ""
		s.persistenceStatement = ""
		s.mu.Unlock()
		writeSuccessfulCursorResponse(w, responseBaton)
		return
	}
	if s.persistenceStatement == statement.SQL && s.persistenceMode == "step-begin-before" {
		s.persistenceMode = ""
		s.persistenceStatement = ""
		s.mu.Unlock()
		writeIncompleteStepResponse(w, responseBaton)
		return
	}
	stall := s.stallSQL == statement.SQL || (s.stallSQL == "migration" && strings.HasPrefix(statement.SQL, "CREATE TABLE inboxgate_schema_migrations"))
	if stall {
		s.stallSQL = ""
		close(s.stallStarted)
		release := s.stallRelease
		finished := s.stallFinished
		s.mu.Unlock()
		select {
		case <-release:
		case <-time.After(time.Second):
		}
		s.mu.Lock()
		close(finished)
		if !s.inTxn || s.pending == nil {
			s.mu.Unlock()
			s.writeSequenceResponse(w, false, true)
			return
		}
	}
	failMatch := s.failSQL == statement.SQL || (s.failSQL == "migration" && strings.HasPrefix(statement.SQL, "CREATE TABLE inboxgate_schema_migrations"))
	if failMatch && s.failSQLSkip > 0 {
		s.failSQLSkip--
		failMatch = false
	}
	if failMatch {
		s.failSQL = ""
		s.failSQLSkip = 0
		inTxn := s.inTxn
		s.mu.Unlock()
		s.writeStatementFailure(w, inTxn, responseBaton)
		return
	}
	if s.headerOnlyCommit && statement.SQL == commitSQL {
		s.headerOnlyCommit = false
		s.pending = nil
		s.pendingExists = false
		s.inTxn = false
		s.mu.Unlock()
		writeHeaderOnlyCursorResponse(w, responseBaton)
		return
	}
	if s.headerOnlyRollback && statement.SQL == rollbackSQL {
		s.headerOnlyRollback = false
		s.mu.Unlock()
		writeHeaderOnlyCursorResponse(w, responseBaton)
		return
	}
	rows, affected, drop := s.execute(statement.SQL, statement.Args)
	overrideColumns := append([]any(nil), s.persistenceColumns[statement.SQL]...)
	persistenceMode := ""
	var bodyStarted, bodyRelease chan struct{}
	if s.persistenceStatement == statement.SQL {
		persistenceMode = s.persistenceMode
		if persistenceMode == "body-stall" {
			bodyStarted = s.persistenceStarted
			bodyRelease = s.persistenceRelease
			s.persistenceStarted = nil
			s.persistenceRelease = nil
		}
		s.persistenceMode = ""
		s.persistenceStatement = ""
	}
	if persistenceMode == "apply-zero-affected" {
		affected = 0
	}
	inTxn := s.inTxn
	s.mu.Unlock()

	if drop {
		writeDroppedCursorResponse(w, responseBaton)
		return
	}
	if persistenceMode == "drop-after" {
		writeDroppedCursorResponse(w, responseBaton)
		return
	}
	if persistenceMode == "malformed-after" {
		_, _ = io.WriteString(w, "{malformed persistence response")
		return
	}
	if persistenceMode == "step-begin-after" {
		writeIncompleteStepResponse(w, responseBaton)
		return
	}

	encoder := json.NewEncoder(w)
	var baseURL any
	if responseBaseURL != "" {
		baseURL = responseBaseURL
	}
	_ = encoder.Encode(map[string]any{"baton": responseBaton, "base_url": baseURL})
	if bodyStarted != nil {
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		close(bodyStarted)
		select {
		case <-bodyRelease:
		case <-r.Context().Done():
			return
		}
	}
	columns := []any{}
	if statement.SQL == ledgerExistsSQL {
		columns = []any{map[string]any{"name": "exists", "decltype": "INTEGER"}}
	} else if statement.SQL == ledgerRowsSQL {
		columns = []any{
			map[string]any{"name": "number", "decltype": "INTEGER"},
			map[string]any{"name": "checksum", "decltype": "TEXT"},
		}
	} else if statement.SQL == userVersionSQL {
		columns = []any{map[string]any{"name": "user_version", "decltype": "INTEGER"}}
	} else if statement.SQL == accountLookupSQL {
		columns = []any{
			map[string]any{"name": "sentinel", "decltype": "INTEGER"},
			map[string]any{"name": "id_count", "decltype": "INTEGER"},
			map[string]any{"name": "id_account_id", "decltype": "TEXT"},
			map[string]any{"name": "id_provider", "decltype": "TEXT"},
			map[string]any{"name": "id_subject", "decltype": "TEXT"},
			map[string]any{"name": "subject_count", "decltype": "INTEGER"},
			map[string]any{"name": "subject_account_id", "decltype": "TEXT"},
			map[string]any{"name": "subject_provider", "decltype": "TEXT"},
			map[string]any{"name": "subject", "decltype": "TEXT"},
		}
	} else if statement.SQL == cursorLookupSQL {
		columns = []any{
			map[string]any{"name": "sentinel", "decltype": "INTEGER"},
			map[string]any{"name": "account_count", "decltype": "INTEGER"},
			map[string]any{"name": "account_id", "decltype": "TEXT"},
			map[string]any{"name": "cursor_count", "decltype": "INTEGER"},
			map[string]any{"name": "cursor_account_id", "decltype": "TEXT"},
			map[string]any{"name": "history_id", "decltype": "TEXT"},
		}
	} else if statement.SQL == credentialLookupSQL {
		columns = []any{
			map[string]any{"name": "sentinel", "decltype": "INTEGER"},
			map[string]any{"name": "account_count", "decltype": "INTEGER"},
			map[string]any{"name": "account_id", "decltype": "TEXT"},
			map[string]any{"name": "credential_count", "decltype": "INTEGER"},
			map[string]any{"name": "credential_account_id", "decltype": "TEXT"},
			map[string]any{"name": "key_id", "decltype": "TEXT"},
			map[string]any{"name": "envelope", "decltype": "TEXT"},
		}
	} else if statement.SQL == lifecycleLookupSQL {
		columns = []any{
			map[string]any{"name": "sentinel", "decltype": "INTEGER"},
			map[string]any{"name": "account_count", "decltype": "INTEGER"},
			map[string]any{"name": "lifecycle_count", "decltype": "INTEGER"},
			map[string]any{"name": "account_id", "decltype": "TEXT"},
			map[string]any{"name": "state", "decltype": "TEXT"},
			map[string]any{"name": "state_version", "decltype": "INTEGER"},
			map[string]any{"name": "reauthorization_reason", "decltype": "TEXT"},
			map[string]any{"name": "revocation_status", "decltype": "TEXT"},
		}
	} else if statement.SQL == accountListSQL {
		columns = []any{
			map[string]any{"name": "account_id", "decltype": "TEXT"},
			map[string]any{"name": "provider", "decltype": "TEXT"},
			map[string]any{"name": "state", "decltype": "TEXT"},
			map[string]any{"name": "state_version", "decltype": "INTEGER"},
			map[string]any{"name": "reauthorization_reason", "decltype": "TEXT"},
			map[string]any{"name": "revocation_status", "decltype": "TEXT"},
			map[string]any{"name": "cursor_present", "decltype": "INTEGER"},
			map[string]any{"name": "credential_present", "decltype": "INTEGER"},
		}
	} else if statement.SQL == currentDiscoveryAttemptLookupSQL {
		columns = []any{
			map[string]any{"name": "sentinel", "decltype": "INTEGER"},
			map[string]any{"name": "account_count", "decltype": "INTEGER"},
			map[string]any{"name": "attempt_count", "decltype": "INTEGER"},
			map[string]any{"name": "account_id", "decltype": "TEXT"},
			map[string]any{"name": "attempt_id", "decltype": "TEXT"},
			map[string]any{"name": "expected_history_id", "decltype": "TEXT"},
			map[string]any{"name": "next_history_id", "decltype": "TEXT"},
			map[string]any{"name": "message_count", "decltype": "INTEGER"},
			map[string]any{"name": "encoded_bytes", "decltype": "INTEGER"},
			map[string]any{"name": "manifest_hash", "decltype": "TEXT"},
			map[string]any{"name": "manifest_witness", "decltype": "TEXT"},
			map[string]any{"name": "state", "decltype": "TEXT"},
		}
	} else if statement.SQL == currentDiscoveryStageLookupSQL {
		columns = []any{
			map[string]any{"name": "sentinel", "decltype": "INTEGER"},
			map[string]any{"name": "attempt_id", "decltype": "TEXT"},
			map[string]any{"name": "ordinal", "decltype": "INTEGER"},
			map[string]any{"name": "record_id", "decltype": "TEXT"},
			map[string]any{"name": "gmail_message_id", "decltype": "TEXT"},
			map[string]any{"name": "gmail_thread_id", "decltype": "TEXT"},
			map[string]any{"name": "metadata_version", "decltype": "INTEGER"},
			map[string]any{"name": "metadata_json", "decltype": "TEXT"},
			map[string]any{"name": "metadata_hash", "decltype": "TEXT"},
			map[string]any{"name": "encoded_bytes", "decltype": "INTEGER"},
			map[string]any{"name": "row_witness", "decltype": "TEXT"},
		}
	} else if statement.SQL == currentDiscoveryNaturalKeyLookupSQL {
		columns = []any{
			map[string]any{"name": "sentinel", "decltype": "INTEGER"},
			map[string]any{"name": "message_count", "decltype": "INTEGER"},
			map[string]any{"name": "record_id", "decltype": "TEXT"},
			map[string]any{"name": "gmail_thread_id", "decltype": "TEXT"},
		}
	} else if statement.SQL == currentDiscoveryMessageLookupSQL {
		columns = []any{
			map[string]any{"name": "sentinel", "decltype": "INTEGER"},
			map[string]any{"name": "account_count", "decltype": "INTEGER"},
			map[string]any{"name": "message_count", "decltype": "INTEGER"},
			map[string]any{"name": "record_id", "decltype": "TEXT"},
			map[string]any{"name": "account_id", "decltype": "TEXT"},
			map[string]any{"name": "gmail_message_id", "decltype": "TEXT"},
			map[string]any{"name": "gmail_thread_id", "decltype": "TEXT"},
			map[string]any{"name": "metadata_version", "decltype": "INTEGER"},
			map[string]any{"name": "metadata_json", "decltype": "TEXT"},
			map[string]any{"name": "metadata_hash", "decltype": "TEXT"},
		}
	} else if statement.SQL == currentDiscoveryRecordLookupSQL {
		columns = []any{
			map[string]any{"name": "sentinel", "decltype": "INTEGER"},
			map[string]any{"name": "message_count", "decltype": "INTEGER"},
			map[string]any{"name": "account_id", "decltype": "TEXT"},
			map[string]any{"name": "gmail_message_id", "decltype": "TEXT"},
		}
	} else if statement.SQL == currentDiscoveryProofSQL || statement.SQL == currentDiscoveryStageProofSQL {
		columns = []any{
			map[string]any{"name": "sentinel", "decltype": "INTEGER"},
			map[string]any{"name": "expected_count", "decltype": "INTEGER"},
			map[string]any{"name": "matched_count", "decltype": "INTEGER"},
		}
	} else if statement.SQL == gateDecisionLookupSQL {
		columns = []any{
			map[string]any{"name": "sentinel", "decltype": "INTEGER"},
			map[string]any{"name": "account_count", "decltype": "INTEGER"},
			map[string]any{"name": "message_count", "decltype": "INTEGER"},
			map[string]any{"name": "record_id", "decltype": "TEXT"},
			map[string]any{"name": "current_metadata_hash", "decltype": "TEXT"},
			map[string]any{"name": "decision_count", "decltype": "INTEGER"},
			map[string]any{"name": "gate_version", "decltype": "INTEGER"},
			map[string]any{"name": "source_metadata_hash", "decltype": "TEXT"},
			map[string]any{"name": "input_hash", "decltype": "TEXT"},
			map[string]any{"name": "outcome", "decltype": "TEXT"},
			map[string]any{"name": "reason_codes", "decltype": "TEXT"},
			map[string]any{"name": "evaluated_at_unix_ms", "decltype": "INTEGER"},
		}
	} else if statement.SQL == candidateContentLookupSQL {
		columns = []any{
			map[string]any{"name": "sentinel", "decltype": "INTEGER"},
			map[string]any{"name": "account_count", "decltype": "INTEGER"},
			map[string]any{"name": "lifecycle_count", "decltype": "INTEGER"},
			map[string]any{"name": "state", "decltype": "TEXT"},
			map[string]any{"name": "state_version", "decltype": "INTEGER"},
			map[string]any{"name": "message_count", "decltype": "INTEGER"},
			map[string]any{"name": "record_id", "decltype": "TEXT"},
			map[string]any{"name": "metadata_hash", "decltype": "TEXT"},
			map[string]any{"name": "decision_count", "decltype": "INTEGER"},
			map[string]any{"name": "gate_version", "decltype": "INTEGER"},
			map[string]any{"name": "gate_source_hash", "decltype": "TEXT"},
			map[string]any{"name": "gate_input_hash", "decltype": "TEXT"},
			map[string]any{"name": "gate_outcome", "decltype": "TEXT"},
			map[string]any{"name": "gate_reasons", "decltype": "TEXT"},
			map[string]any{"name": "gate_evaluated_at", "decltype": "INTEGER"},
			map[string]any{"name": "content_count", "decltype": "INTEGER"},
			map[string]any{"name": "extractor_version", "decltype": "INTEGER"},
			map[string]any{"name": "content_source_hash", "decltype": "TEXT"},
			map[string]any{"name": "content_gate_version", "decltype": "INTEGER"},
			map[string]any{"name": "content_gate_input_hash", "decltype": "TEXT"},
			map[string]any{"name": "source_kind", "decltype": "TEXT"},
			map[string]any{"name": "excerpt", "decltype": "TEXT"},
			map[string]any{"name": "excerpt_bytes", "decltype": "INTEGER"},
			map[string]any{"name": "excerpt_limit", "decltype": "INTEGER"},
			map[string]any{"name": "truncated", "decltype": "INTEGER"},
			map[string]any{"name": "content_hash", "decltype": "TEXT"},
			map[string]any{"name": "fetched_at", "decltype": "INTEGER"},
		}
	}
	if overrideColumns != nil {
		columns = overrideColumns
	}
	_ = encoder.Encode(map[string]any{"type": "step_begin", "step": 0, "cols": columns})
	for _, row := range rows {
		_ = encoder.Encode(map[string]any{"type": "row", "row": row})
	}
	_ = encoder.Encode(map[string]any{"type": "step_end", "step": 0, "affected_row_count": affected})
	if !inTxn {
		_ = encoder.Encode(map[string]any{"type": "step_begin", "step": 1, "cols": []any{}})
		_ = encoder.Encode(map[string]any{"type": "step_end", "step": 1})
	}
}

func writeDroppedCursorResponse(w http.ResponseWriter, baton string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", "256")
	_, _ = io.WriteString(w, "{\"baton\":"+strconv.Quote(baton)+",\"base_url\":null}\n")
}

func writeHeaderOnlyCursorResponse(w http.ResponseWriter, baton string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, "{\"baton\":"+strconv.Quote(baton)+",\"base_url\":null}\n")
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func writeSuccessfulCursorResponse(w http.ResponseWriter, baton string) {
	encoder := json.NewEncoder(w)
	_ = encoder.Encode(map[string]any{"baton": baton, "base_url": nil})
	_ = encoder.Encode(map[string]any{"type": "step_begin", "step": 0, "cols": []any{}})
	_ = encoder.Encode(map[string]any{"type": "step_end", "step": 0, "affected_row_count": 1})
}

func writeIncompleteStepResponse(w http.ResponseWriter, baton string) {
	encoder := json.NewEncoder(w)
	_ = encoder.Encode(map[string]any{"baton": baton, "base_url": nil})
	_ = encoder.Encode(map[string]any{"type": "step_begin", "step": 0, "cols": []any{}})
}

func (s *migrationProtocolServer) writeStatementFailure(w http.ResponseWriter, inTxn bool, baton string) {
	encoder := json.NewEncoder(w)
	_ = encoder.Encode(map[string]any{"baton": baton, "base_url": nil})
	_ = encoder.Encode(map[string]any{
		"type":  "step_error",
		"step":  0,
		"error": map[string]any{"message": "raw synthetic-token SELECT private marker", "code": "SYNTHETIC"},
	})
	if !inTxn {
		_ = encoder.Encode(map[string]any{"type": "step_begin", "step": 1, "cols": []any{}})
		_ = encoder.Encode(map[string]any{"type": "step_end", "step": 1})
	}
}

func (s *migrationProtocolServer) execute(statement string, args []protocolValue) ([][]any, int64, bool) {
	if rows, ok := s.persistenceRows[statement]; ok {
		return rows, 0, false
	}
	switch statement {
	case beginImmediateSQL:
		s.inTxn = true
		s.pending = cloneLedger(s.ledger)
		s.pendingExists = s.exists
		return nil, 0, false
	case ledgerExistsSQL:
		if s.exists {
			return [][]any{{integerValue(1)}}, 0, false
		}
		return nil, 0, false
	case ledgerRowsSQL:
		if s.ledgerRowsOverride != nil {
			return s.ledgerRowsOverride, 0, false
		}
		ledger := s.ledger
		rows := make([][]any, 0, len(ledger))
		numbers := make([]int, 0, len(ledger))
		for number := range ledger {
			numbers = append(numbers, number)
		}
		sort.Ints(numbers)
		for _, number := range numbers {
			rows = append(rows, []any{integerValue(int64(number)), textValue(ledger[number])})
		}
		return rows, 0, false
	case userVersionSQL:
		return [][]any{{integerValue(int64(s.userVersion))}}, 0, false
	case ledgerInsertSQL:
		number, err := strconv.Atoi(parseProtocolValue(args[0]))
		if err != nil {
			s.testing.Errorf("invalid synthetic migration number")
			return nil, 0, false
		}
		if s.inTxn {
			s.pending[number] = parseProtocolValue(args[1])
		} else {
			s.ledger[number] = parseProtocolValue(args[1])
		}
		return nil, 1, false
	case commitSQL:
		if !s.inTxn {
			return nil, 0, false
		}
		if s.dropBeforeCommit {
			s.dropBeforeCommit = false
			s.pending = nil
			s.pendingExists = false
			s.inTxn = false
			return nil, 0, true
		}
		s.ledger = cloneLedger(s.pending)
		s.exists = s.pendingExists
		s.userVersion = s.pendingUserVersion
		s.secondSchema = s.pendingSecondSchema
		s.thirdSchema = s.pendingThirdSchema
		s.credentialSchema = s.pendingCredentialSchema
		s.lifecycleSchema = s.pendingLifecycleSchema
		s.currentDiscoverySchema = s.pendingCurrentDiscoverySchema
		s.gateDecisionSchema = s.pendingGateDecisionSchema
		s.candidateContentSchema = s.pendingCandidateContentSchema
		s.inTxn = false
		if s.drop {
			s.drop = false
			return nil, 0, true
		}
		return nil, 0, false
	case rollbackSQL:
		if s.ignoredRollbacks > 0 {
			s.ignoredRollbacks--
			return nil, 0, false
		}
		s.pending = nil
		s.pendingExists = false
		s.pendingUserVersion = 0
		s.pendingSecondSchema = false
		s.pendingThirdSchema = false
		s.pendingCredentialSchema = false
		s.pendingLifecycleSchema = false
		s.pendingCurrentDiscoverySchema = false
		s.pendingGateDecisionSchema = false
		s.pendingCandidateContentSchema = false
		s.inTxn = false
		return nil, 0, false
	case accountLookupSQL:
		accountID := parseProtocolValue(args[0])
		subject := parseProtocolValue(args[2])
		row := []any{integerValue(1), integerValue(0), nullValue(), nullValue(), nullValue(), integerValue(0), nullValue(), nullValue(), nullValue()}
		if storedSubject, ok := s.accounts[accountID]; ok {
			row[1] = integerValue(1)
			row[2] = textValue(accountID)
			row[3] = textValue(storage.ProviderGmail)
			row[4] = textValue(storedSubject)
		}
		for storedID, storedSubject := range s.accounts {
			if storedSubject == subject {
				row[5] = integerValue(1)
				row[6] = textValue(storedID)
				row[7] = textValue(storage.ProviderGmail)
				row[8] = textValue(storedSubject)
			}
		}
		if s.persistenceMode == "oversized" && s.persistenceStatement == statement {
			rows := make([][]any, migrations.MaximumCount+1)
			for index := range rows {
				rows[index] = row
			}
			return rows, 0, false
		}
		return [][]any{row}, 0, false
	case accountInsertSQL:
		accountID := parseProtocolValue(args[0])
		subject := parseProtocolValue(args[1])
		if _, exists := s.accounts[accountID]; exists {
			return nil, 0, false
		}
		for _, storedSubject := range s.accounts {
			if storedSubject == subject {
				return nil, 0, false
			}
		}
		s.accounts[accountID] = subject
		s.lifecycles[accountID] = syntheticLifecycle{state: "pending", version: 1, revocation: "none"}
		return nil, 1, false
	case cursorLookupSQL:
		accountID := parseProtocolValue(args[0])
		row := []any{integerValue(1), integerValue(0), nullValue(), integerValue(0), nullValue(), nullValue()}
		if _, ok := s.accounts[accountID]; ok {
			row[1] = integerValue(1)
			row[2] = textValue(accountID)
		}
		if historyID, ok := s.cursors[accountID]; ok {
			row[3] = integerValue(1)
			row[4] = textValue(accountID)
			row[5] = textValue(historyID)
		}
		if s.persistenceMode == "oversized" && s.persistenceStatement == statement {
			rows := make([][]any, migrations.MaximumCount+1)
			for index := range rows {
				rows[index] = row
			}
			return rows, 0, false
		}
		return [][]any{row}, 0, false
	case cursorCommitSQL:
		accountID := parseProtocolValue(args[0])
		next := parseProtocolValue(args[1])
		if _, ok := s.accounts[accountID]; !ok || s.currentAttempts[accountID] != nil {
			return nil, 0, false
		}
		if _, exists := s.cursors[accountID]; !exists {
			s.cursors[accountID] = next
			return nil, 1, false
		}
		return nil, 0, false
	case credentialLookupSQL:
		accountID := parseProtocolValue(args[0])
		row := []any{integerValue(1), integerValue(0), nullValue(), integerValue(0), nullValue(), nullValue(), nullValue()}
		if _, ok := s.accounts[accountID]; ok {
			row[1] = integerValue(1)
			row[2] = textValue(accountID)
		}
		if credential, ok := s.credentials[accountID]; ok {
			row[3] = integerValue(1)
			row[4] = textValue(accountID)
			row[5] = textValue(credential.keyID)
			row[6] = textValue(credential.envelope)
		}
		if s.persistenceMode == "oversized" && s.persistenceStatement == statement {
			rows := make([][]any, migrations.MaximumCount+1)
			for index := range rows {
				rows[index] = row
			}
			return rows, 0, false
		}
		return [][]any{row}, 0, false
	case credentialCommitSQL:
		accountID := parseProtocolValue(args[0])
		if _, ok := s.accounts[accountID]; !ok {
			return nil, 0, false
		}
		if lifecycle, ok := s.lifecycles[accountID]; !ok || lifecycle.state == "revoked" {
			return nil, 0, false
		}
		next := syntheticCredential{keyID: parseProtocolValue(args[1]), envelope: parseProtocolValue(args[2])}
		current, exists := s.credentials[accountID]
		expected := parseProtocolValue(args[8])
		if !exists && expected == "" {
			s.credentials[accountID] = next
			return nil, 1, false
		}
		if exists && expected == current.envelope {
			s.credentials[accountID] = next
			return nil, 1, false
		}
		return nil, 0, false
	case lifecycleLookupSQL:
		accountID := parseProtocolValue(args[0])
		accountCount := int64(0)
		if _, ok := s.accounts[accountID]; ok {
			accountCount = 1
		}
		row := []any{integerValue(1), integerValue(accountCount), integerValue(0), nullValue(), nullValue(), nullValue(), nullValue(), nullValue()}
		if lifecycle, ok := s.lifecycles[accountID]; ok {
			row[2] = integerValue(1)
			row[3] = textValue(accountID)
			row[4] = textValue(lifecycle.state)
			row[5] = integerValue(lifecycle.version)
			if lifecycle.reason != nil {
				row[6] = textValue(*lifecycle.reason)
			}
			row[7] = textValue(lifecycle.revocation)
		}
		return [][]any{row}, 0, false
	case accountListSQL:
		ids := make([]string, 0, len(s.lifecycles))
		for accountID := range s.lifecycles {
			ids = append(ids, accountID)
		}
		sort.Strings(ids)
		rows := make([][]any, 0, len(ids))
		for _, accountID := range ids {
			lifecycle := s.lifecycles[accountID]
			row := []any{textValue(accountID), textValue(storage.ProviderGmail), textValue(lifecycle.state), integerValue(lifecycle.version), nullValue(), textValue(lifecycle.revocation), integerValue(0), integerValue(0)}
			if lifecycle.reason != nil {
				row[4] = textValue(*lifecycle.reason)
			}
			if _, ok := s.cursors[accountID]; ok {
				row[6] = integerValue(1)
			}
			if _, ok := s.credentials[accountID]; ok {
				row[7] = integerValue(1)
			}
			rows = append(rows, row)
		}
		return rows, 0, false
	case lifecycleCommitSQL:
		nextState := parseProtocolValue(args[0])
		reasonText := parseProtocolValue(args[1])
		revocation := parseProtocolValue(args[2])
		accountID := parseProtocolValue(args[3])
		expectedState := parseProtocolValue(args[4])
		expectedVersion, _ := strconv.ParseInt(parseProtocolValue(args[5]), 10, 64)
		expectedRevocation := parseProtocolValue(args[6])
		current, ok := s.lifecycles[accountID]
		if !ok || current.state != expectedState || current.version != expectedVersion || current.revocation != expectedRevocation || current.version == math.MaxInt64 {
			return nil, 0, false
		}
		if nextState == "active" {
			if _, ok := s.cursors[accountID]; !ok {
				return nil, 0, false
			}
			if _, ok := s.credentials[accountID]; !ok {
				return nil, 0, false
			}
		}
		current.state = nextState
		current.version++
		current.reason = nil
		if reasonText != "" {
			current.reason = &reasonText
		}
		current.revocation = revocation
		s.lifecycles[accountID] = current
		if nextState == "revoked" {
			delete(s.currentAttempts, accountID)
		}
		return nil, 1, false
	case revokedCredentialDeleteSQL:
		accountID := parseProtocolValue(args[0])
		expected := parseProtocolValue(args[1])
		lifecycle, revoked := s.lifecycles[accountID]
		credential, exists := s.credentials[accountID]
		if !revoked || lifecycle.state != "revoked" || !exists || credential.envelope != expected {
			return nil, 0, false
		}
		delete(s.credentials, accountID)
		return nil, 1, false
	case currentDiscoveryAttemptLookupSQL:
		accountID := parseProtocolValue(args[0])
		accountCount := int64(0)
		if _, ok := s.accounts[accountID]; ok {
			accountCount = 1
		}
		row := []any{integerValue(1), integerValue(accountCount), integerValue(0), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue()}
		if attempt := s.currentAttempts[accountID]; attempt != nil {
			row[2] = integerValue(1)
			row[3] = textValue(accountID)
			row[4] = textValue(attempt.attemptID)
			row[5] = textValue(attempt.expected)
			row[6] = textValue(attempt.next)
			row[7] = integerValue(int64(attempt.messageCount))
			row[8] = integerValue(attempt.encodedBytes)
			row[9] = textValue(attempt.manifestHash)
			row[10] = textValue(attempt.manifestWitness)
			row[11] = textValue(attempt.state)
		}
		return [][]any{row}, 0, false
	case currentDiscoveryStageLookupSQL:
		accountID := parseProtocolValue(args[0])
		attempt := s.currentAttempts[accountID]
		if attempt == nil {
			return [][]any{{integerValue(1), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue()}}, 0, false
		}
		ordinals := make([]int, 0, len(attempt.staging))
		for ordinal := range attempt.staging {
			ordinals = append(ordinals, ordinal)
		}
		sort.Ints(ordinals)
		if len(ordinals) == 0 {
			return [][]any{{integerValue(1), textValue(attempt.attemptID), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue()}}, 0, false
		}
		rows := make([][]any, 0, len(ordinals))
		for _, ordinal := range ordinals {
			message := attempt.staging[ordinal]
			rows = append(rows, []any{integerValue(1), textValue(attempt.attemptID), integerValue(int64(ordinal)), textValue(message.recordID), textValue(message.messageID), textValue(message.threadID), integerValue(message.version), textValue(message.metadataJSON), textValue(message.metadataHash), integerValue(message.encodedBytes), textValue(message.rowWitness)})
		}
		return rows, 0, false
	case currentDiscoveryAttemptCreateSQL:
		accountID := parseProtocolValue(args[0])
		lifecycle := s.lifecycles[accountID]
		if _, ok := s.accounts[accountID]; !ok || s.currentAttempts[accountID] != nil || lifecycle.state != "active" || s.cursors[accountID] != parseProtocolValue(args[2]) {
			return nil, 0, false
		}
		messageCount, countErr := strconv.Atoi(parseProtocolValue(args[4]))
		encodedBytes, bytesErr := strconv.ParseInt(parseProtocolValue(args[5]), 10, 64)
		if countErr != nil || bytesErr != nil {
			return nil, 0, false
		}
		s.currentAttempts[accountID] = &syntheticCurrentDiscoveryAttempt{
			attemptID: parseProtocolValue(args[1]), expected: parseProtocolValue(args[2]), next: parseProtocolValue(args[3]),
			messageCount: messageCount, encodedBytes: encodedBytes, manifestHash: parseProtocolValue(args[6]), manifestWitness: parseProtocolValue(args[7]), state: "open", staging: make(map[int]syntheticDiscoveredMessage),
		}
		return nil, 1, false
	case currentDiscoveryStageSQL:
		accountID := parseProtocolValue(args[0])
		attempt := s.currentAttempts[accountID]
		if attempt == nil || attempt.attemptID != parseProtocolValue(args[1]) || attempt.state != "open" || len(args) != storage.CurrentDiscoveryStageParameters {
			return nil, 0, false
		}
		affected := int64(0)
		for slot := 0; slot < storage.CurrentDiscoveryStageChunkMessages; slot++ {
			base := 2 + slot*8
			present, _ := strconv.ParseInt(parseProtocolValue(args[base]), 10, 64)
			if present == 0 {
				continue
			}
			ordinal, ordinalErr := strconv.Atoi(parseProtocolValue(args[base+1]))
			version, versionErr := strconv.ParseInt(parseProtocolValue(args[base+5]), 10, 64)
			if present != 1 || ordinalErr != nil || versionErr != nil || ordinal < 0 || ordinal >= attempt.messageCount {
				return nil, 0, false
			}
			message := syntheticDiscoveredMessage{
				recordID: parseProtocolValue(args[base+2]), accountID: accountID, messageID: parseProtocolValue(args[base+3]), threadID: parseProtocolValue(args[base+4]),
				version: version, metadataJSON: parseProtocolValue(args[base+6]), metadataHash: parseProtocolValue(args[base+7]),
			}
			message.encodedBytes = int64(4 + len(message.recordID) + 4 + len(message.messageID) + 4 + len(message.threadID) + 4 + 4 + len(message.metadataJSON) + 4 + len(message.metadataHash))
			message.rowWitness = syntheticRowWitness(message)
			if existing, ok := attempt.staging[ordinal]; ok {
				if existing != message {
					return nil, 0, false
				}
			} else {
				attempt.staging[ordinal] = message
			}
			affected++
		}
		return nil, affected, false
	case currentDiscoverySealSQL:
		accountID := parseProtocolValue(args[0])
		attempt := s.currentAttempts[accountID]
		if attempt == nil || attempt.attemptID != parseProtocolValue(args[1]) || attempt.state != "open" || attempt.expected != parseProtocolValue(args[2]) || attempt.next != parseProtocolValue(args[3]) || attempt.manifestHash != parseProtocolValue(args[6]) || attempt.manifestWitness != parseProtocolValue(args[7]) || len(attempt.staging) != attempt.messageCount {
			return nil, 0, false
		}
		var total int64
		for ordinal := 0; ordinal < attempt.messageCount; ordinal++ {
			message, ok := attempt.staging[ordinal]
			if !ok {
				return nil, 0, false
			}
			total += message.encodedBytes
		}
		if total != attempt.encodedBytes || syntheticManifestWitness(attempt) != attempt.manifestWitness {
			return nil, 0, false
		}
		attempt.state = "sealed"
		return nil, 1, false
	case currentDiscoveryFinalizeSQL:
		accountID := parseProtocolValue(args[0])
		attempt := s.currentAttempts[accountID]
		lifecycle := s.lifecycles[accountID]
		if attempt == nil || attempt.attemptID != parseProtocolValue(args[1]) || attempt.manifestHash != parseProtocolValue(args[2]) || attempt.state != "sealed" || lifecycle.state != "active" || s.cursors[accountID] != attempt.expected || len(attempt.staging) != attempt.messageCount || syntheticManifestWitness(attempt) != attempt.manifestWitness {
			return nil, 0, false
		}
		for ordinal := 0; ordinal < attempt.messageCount; ordinal++ {
			message, ok := attempt.staging[ordinal]
			if !ok || message.rowWitness != syntheticRowWitness(message) {
				return nil, 0, false
			}
			if occupied, ok := s.discoveredRecords[message.recordID]; ok && (occupied.accountID != accountID || occupied.messageID != message.messageID) {
				return nil, 0, false
			}
			if existing, ok := s.discoveredMessages[accountID][message.messageID]; ok && (existing.recordID != message.recordID || existing.threadID != message.threadID) {
				return nil, 0, false
			}
		}
		if s.discoveredMessages[accountID] == nil {
			s.discoveredMessages[accountID] = make(map[string]syntheticDiscoveredMessage)
		}
		for ordinal := 0; ordinal < attempt.messageCount; ordinal++ {
			message := attempt.staging[ordinal]
			s.discoveredMessages[accountID][message.messageID] = message
			s.discoveredRecords[message.recordID] = message
		}
		s.cursors[accountID] = attempt.next
		delete(s.currentAttempts, accountID)
		return nil, 1, false
	case currentDiscoveryAbortSQL:
		accountID := parseProtocolValue(args[0])
		attempt := s.currentAttempts[accountID]
		if attempt == nil || attempt.attemptID != parseProtocolValue(args[1]) || attempt.state != "open" || s.cursors[accountID] != attempt.expected || s.lifecycles[accountID].state != "active" {
			return nil, 0, false
		}
		delete(s.currentAttempts, accountID)
		return nil, 1, false
	case currentDiscoveryProofSQL, currentDiscoveryStageProofSQL:
		accountID := parseProtocolValue(args[0])
		attemptID := parseProtocolValue(args[1])
		var expected, matched int64
		for slot := 0; slot < storage.CurrentDiscoveryStageChunkMessages; slot++ {
			base := 2 + slot*8
			present, _ := strconv.ParseInt(parseProtocolValue(args[base]), 10, 64)
			if present != 1 {
				continue
			}
			expected++
			messageID := parseProtocolValue(args[base+3])
			version, _ := strconv.ParseInt(parseProtocolValue(args[base+5]), 10, 64)
			message, ok := s.discoveredMessages[accountID][messageID]
			if statement == currentDiscoveryStageProofSQL {
				attempt := s.currentAttempts[accountID]
				ordinal, _ := strconv.Atoi(parseProtocolValue(args[base+1]))
				if attempt == nil || attempt.attemptID != attemptID || attempt.state != "open" {
					ok = false
				} else {
					message, ok = attempt.staging[ordinal]
				}
			}
			if ok && message.recordID == parseProtocolValue(args[base+2]) && message.threadID == parseProtocolValue(args[base+4]) && message.version == version && message.metadataJSON == parseProtocolValue(args[base+6]) && message.metadataHash == parseProtocolValue(args[base+7]) {
				matched++
			}
		}
		return [][]any{{integerValue(1), integerValue(expected), integerValue(matched)}}, 0, false
	case currentDiscoveryMessageLookupSQL:
		accountID := parseProtocolValue(args[0])
		messageID := parseProtocolValue(args[1])
		accountCount := int64(0)
		if _, ok := s.accounts[accountID]; ok {
			accountCount = 1
		}
		row := []any{integerValue(1), integerValue(accountCount), integerValue(0), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue()}
		if message, ok := s.discoveredMessages[accountID][messageID]; ok {
			row[2] = integerValue(1)
			row[3] = textValue(message.recordID)
			row[4] = textValue(accountID)
			row[5] = textValue(message.messageID)
			row[6] = textValue(message.threadID)
			row[7] = integerValue(message.version)
			row[8] = textValue(message.metadataJSON)
			row[9] = textValue(message.metadataHash)
		}
		return [][]any{row}, 0, false
	case currentDiscoveryRecordLookupSQL:
		recordID := parseProtocolValue(args[0])
		row := []any{integerValue(1), integerValue(0), nullValue(), nullValue()}
		if message, ok := s.discoveredRecords[recordID]; ok {
			row[1] = integerValue(1)
			row[2] = textValue(message.accountID)
			row[3] = textValue(message.messageID)
		}
		return [][]any{row}, 0, false
	case currentDiscoveryNaturalKeyLookupSQL:
		accountID := parseProtocolValue(args[0])
		messageID := parseProtocolValue(args[1])
		row := []any{integerValue(1), integerValue(0), nullValue(), nullValue()}
		if message, ok := s.discoveredMessages[accountID][messageID]; ok {
			row[1] = integerValue(1)
			row[2] = textValue(message.recordID)
			row[3] = textValue(message.threadID)
		}
		return [][]any{row}, 0, false
	case gateDecisionLookupSQL:
		accountID := parseProtocolValue(args[0])
		messageID := parseProtocolValue(args[1])
		accountCount := int64(0)
		if _, ok := s.accounts[accountID]; ok {
			accountCount = 1
		}
		row := []any{integerValue(1), integerValue(accountCount), integerValue(0), nullValue(), nullValue(), integerValue(0), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue()}
		if message, ok := s.discoveredMessages[accountID][messageID]; ok {
			row[2] = integerValue(1)
			row[3] = textValue(message.recordID)
			row[4] = textValue(message.metadataHash)
			if decision, exists := s.gateDecisions[message.recordID]; exists {
				row[5] = integerValue(1)
				row[6] = integerValue(decision.version)
				row[7] = textValue(decision.sourceHash)
				row[8] = textValue(decision.inputHash)
				row[9] = textValue(decision.outcome)
				row[10] = textValue(decision.reasonJSON)
				row[11] = integerValue(decision.evaluatedAt)
			}
		}
		return [][]any{row}, 0, false
	case gateDecisionCommitSQL:
		recordID := parseProtocolValue(args[0])
		accountID := parseProtocolValue(args[1])
		messageID := parseProtocolValue(args[2])
		sourceHash := parseProtocolValue(args[3])
		message, ok := s.discoveredMessages[accountID][messageID]
		if !ok || message.recordID != recordID || message.metadataHash != sourceHash {
			return nil, 0, false
		}
		expectedPresent, _ := strconv.ParseInt(parseProtocolValue(args[4]), 10, 64)
		nextVersion, _ := strconv.ParseInt(parseProtocolValue(args[7]), 10, 64)
		evaluatedAt, _ := strconv.ParseInt(parseProtocolValue(args[11]), 10, 64)
		current, exists := s.gateDecisions[recordID]
		if (!exists && expectedPresent == 0) || (exists && expectedPresent == 1 && current.version == func() int64 { value, _ := strconv.ParseInt(parseProtocolValue(args[5]), 10, 64); return value }() && current.inputHash == parseProtocolValue(args[6])) {
			s.gateDecisions[recordID] = syntheticGateDecision{version: nextVersion, sourceHash: sourceHash, inputHash: parseProtocolValue(args[8]), outcome: parseProtocolValue(args[9]), reasonJSON: parseProtocolValue(args[10]), evaluatedAt: evaluatedAt}
			return nil, 1, false
		}
		return nil, 0, false
	case candidateContentLookupSQL:
		accountID := parseProtocolValue(args[0])
		messageID := parseProtocolValue(args[1])
		accountCount := int64(0)
		if _, ok := s.accounts[accountID]; ok {
			accountCount = 1
		}
		row := []any{integerValue(1), integerValue(accountCount), integerValue(0), nullValue(), nullValue(), integerValue(0), nullValue(), nullValue(), integerValue(0), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), integerValue(0), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue()}
		if lifecycle, ok := s.lifecycles[accountID]; ok {
			row[2] = integerValue(1)
			row[3] = textValue(lifecycle.state)
			row[4] = integerValue(lifecycle.version)
		}
		if message, ok := s.discoveredMessages[accountID][messageID]; ok {
			row[5] = integerValue(1)
			row[6] = textValue(message.recordID)
			row[7] = textValue(message.metadataHash)
			if decision, exists := s.gateDecisions[message.recordID]; exists {
				row[8] = integerValue(1)
				row[9] = integerValue(decision.version)
				row[10] = textValue(decision.sourceHash)
				row[11] = textValue(decision.inputHash)
				row[12] = textValue(decision.outcome)
				row[13] = textValue(decision.reasonJSON)
				row[14] = integerValue(decision.evaluatedAt)
			}
			if content, exists := s.candidateContents[message.recordID]; exists {
				row[15] = integerValue(1)
				row[16] = integerValue(content.extractorVersion)
				row[17] = textValue(content.sourceHash)
				row[18] = integerValue(content.gateVersion)
				row[19] = textValue(content.gateInputHash)
				row[20] = textValue(content.sourceKind)
				row[21] = textValue(content.excerpt)
				row[22] = integerValue(content.excerptBytes)
				row[23] = integerValue(content.excerptLimit)
				row[24] = integerValue(content.truncated)
				row[25] = textValue(content.contentHash)
				row[26] = integerValue(content.fetchedAt)
			}
		}
		return [][]any{row}, 0, false
	case candidateContentCommitSQL:
		recordID := parseProtocolValue(args[0])
		accountID := parseProtocolValue(args[1])
		messageID := parseProtocolValue(args[2])
		lifecycleVersion, _ := strconv.ParseInt(parseProtocolValue(args[3]), 10, 64)
		sourceHash := parseProtocolValue(args[4])
		gateVersion, _ := strconv.ParseInt(parseProtocolValue(args[5]), 10, 64)
		gateInputHash := parseProtocolValue(args[6])
		message, messageOK := s.discoveredMessages[accountID][messageID]
		lifecycle, lifecycleOK := s.lifecycles[accountID]
		decision, decisionOK := s.gateDecisions[recordID]
		if !messageOK || message.recordID != recordID || message.metadataHash != sourceHash || !lifecycleOK || lifecycle.state != "active" || lifecycle.version != lifecycleVersion || !decisionOK || decision.version != gateVersion || decision.sourceHash != sourceHash || decision.inputHash != gateInputHash || decision.outcome != parseProtocolValue(args[7]) || decision.reasonJSON != parseProtocolValue(args[8]) || strconv.FormatInt(decision.evaluatedAt, 10) != parseProtocolValue(args[9]) || decision.outcome != "review_candidate" && decision.outcome != "urgent_review_candidate" {
			return nil, 0, false
		}
		expectedPresent, _ := strconv.ParseInt(parseProtocolValue(args[10]), 10, 64)
		current, exists := s.candidateContents[recordID]
		expectedMatches := exists && expectedPresent == 1 && strconv.FormatInt(current.extractorVersion, 10) == parseProtocolValue(args[11]) && current.sourceHash == parseProtocolValue(args[12]) && current.gateInputHash == parseProtocolValue(args[13]) && strconv.FormatInt(current.excerptLimit, 10) == parseProtocolValue(args[14]) && current.contentHash == parseProtocolValue(args[15])
		if !exists && expectedPresent == 0 || expectedMatches {
			extractor, _ := strconv.ParseInt(parseProtocolValue(args[16]), 10, 64)
			excerptBytes, _ := strconv.ParseInt(parseProtocolValue(args[19]), 10, 64)
			excerptLimit, _ := strconv.ParseInt(parseProtocolValue(args[20]), 10, 64)
			truncated, _ := strconv.ParseInt(parseProtocolValue(args[21]), 10, 64)
			fetchedAt, _ := strconv.ParseInt(parseProtocolValue(args[23]), 10, 64)
			s.candidateContents[recordID] = syntheticCandidateContent{extractorVersion: extractor, sourceHash: sourceHash, gateVersion: gateVersion, gateInputHash: gateInputHash, sourceKind: parseProtocolValue(args[17]), excerpt: parseProtocolValue(args[18]), excerptBytes: excerptBytes, excerptLimit: excerptLimit, truncated: truncated, contentHash: parseProtocolValue(args[22]), fetchedAt: fetchedAt}
			return nil, 1, false
		}
		return nil, 0, false
	default:
		if strings.HasPrefix(statement, "CREATE TABLE inboxgate_schema_migrations") {
			if s.inTxn {
				s.pendingExists = true
			} else {
				s.exists = true
			}
			return nil, 0, false
		}
		s.testing.Errorf("unexpected SQL category")
		return nil, 0, false
	}
}

func (s *migrationProtocolServer) servePipeline(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Baton    *string                  `json:"baton"`
		Requests []migrationStreamRequest `json:"requests"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&request); err != nil {
		s.testing.Errorf("decode pipeline request: %v", err)
		return
	}
	s.mu.Lock()
	s.pipelineRecords = append(s.pipelineRecords, migrationPipelineRequest{baton: request.Baton, requests: request.Requests})
	s.mu.Unlock()
	for _, item := range request.Requests {
		if item.Type == "sequence" {
			if strings.HasPrefix(item.SQL, "SAVEPOINT "+terminalSavepoint+";") {
				s.serveTerminalSequence(w, item.SQL)
			} else {
				s.serveMigrationSequence(w, item.SQL)
			}
			return
		}
	}

	results := make([]any, len(request.Requests))
	s.mu.Lock()
	autocommit := !s.inTxn
	for _, item := range request.Requests {
		if item.Type == "close" {
			if request.Baton != nil {
				s.closedCursorAt[*request.Baton] = len(s.records)
				s.closedCursorCount[*request.Baton]++
			}
			if s.ignoredCloses > 0 {
				s.ignoredCloses--
				continue
			}
			s.inTxn = false
			s.pending = nil
			s.pendingExists = false
			s.pendingUserVersion = 0
			s.pendingSecondSchema = false
			s.pendingThirdSchema = false
			s.pendingCredentialSchema = false
			autocommit = true
		}
	}
	s.mu.Unlock()
	for index, item := range request.Requests {
		response := map[string]any{"type": item.Type}
		if item.Type == "get_autocommit" {
			response["is_autocommit"] = autocommit
		}
		results[index] = map[string]any{"type": "ok", "response": response}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"baton": "synthetic-baton", "base_url": nil, "results": results,
	})
}

func (s *migrationProtocolServer) serveTerminalSequence(w http.ResponseWriter, sequence string) {
	number, ok := parseTerminalSequence(sequence)
	if !ok {
		s.writeSequenceResponse(w, false, true)
		return
	}
	s.mu.Lock()
	if s.beforeTerminalStart != nil {
		started := s.beforeTerminalStart
		release := s.beforeTerminalAllow
		s.beforeTerminalStart = nil
		s.beforeTerminalAllow = nil
		close(started)
		s.mu.Unlock()
		select {
		case <-release:
		case <-time.After(time.Second):
		}
		s.mu.Lock()
	}
	if s.failSQL == "terminal" {
		s.failSQL = ""
		s.failSQLSkip = 0
		s.mu.Unlock()
		s.writeSequenceResponse(w, false, true)
		return
	}
	autocommit := !s.inTxn
	currentMarker := s.userVersion
	if s.inTxn {
		currentMarker = s.pendingUserVersion
	}
	if strings.Contains(sequence, "FROM pragma_user_version") && currentMarker > number {
		s.mu.Unlock()
		s.writeSequenceResponse(w, autocommit, true)
		return
	}
	if strings.Contains(sequence, "number IS NULL OR checksum IS NULL") && !s.lockedPrefixValid(sequence, number) {
		s.mu.Unlock()
		s.writeSequenceResponse(w, autocommit, true)
		return
	}
	if !s.terminalSkipMarker {
		if s.inTxn {
			s.pendingUserVersion = number
		} else {
			s.userVersion = number
		}
	}
	malformed := s.terminalMalformed
	omitResult := s.terminalOmitResult
	badAuto := s.terminalBadAuto
	falseAuto := s.terminalFalseAuto
	omitPayload := s.terminalOmitPayload
	wrongPayload := s.terminalWrongPayload
	s.terminalMalformed = false
	s.terminalOmitResult = false
	s.terminalBadAuto = false
	s.terminalFalseAuto = false
	s.terminalOmitPayload = false
	s.terminalWrongPayload = false
	s.terminalSkipMarker = false
	s.mu.Unlock()
	switch {
	case malformed:
		_, _ = io.WriteString(w, "{malformed terminal marker")
	case omitResult:
		_ = json.NewEncoder(w).Encode(map[string]any{
			"baton": "synthetic-baton", "base_url": nil,
			"results": []any{map[string]any{"type": "ok", "response": map[string]any{"type": "get_autocommit", "is_autocommit": autocommit}}},
		})
	case badAuto:
		_ = json.NewEncoder(w).Encode(map[string]any{
			"baton": "synthetic-baton", "base_url": nil,
			"results": []any{
				map[string]any{"type": "ok", "response": map[string]any{"type": "sequence"}},
				map[string]any{"type": "ok", "response": map[string]any{"type": "get_autocommit"}},
			},
		})
	default:
		s.writeCustomSequenceResponse(w, autocommit && !falseAuto, omitPayload, wrongPayload)
	}
}

func parseTerminalSequence(sequence string) (int, bool) {
	if !strings.HasPrefix(sequence, "SAVEPOINT "+terminalSavepoint+";") ||
		!strings.HasSuffix(sequence, "RELEASE SAVEPOINT "+terminalSavepoint+";") {
		return 0, false
	}
	const assignment = "PRAGMA user_version = "
	start := strings.Index(sequence, assignment)
	if start < 0 {
		return 0, false
	}
	raw := sequence[start+len(assignment):]
	if end := strings.IndexByte(raw, ';'); end >= 0 {
		raw = raw[:end]
	}
	number, err := strconv.Atoi(raw)
	return number, err == nil && number >= 0 && number <= migrations.MaximumCount
}

func (s *migrationProtocolServer) serveMigrationSequence(w http.ResponseWriter, sequence string) {
	s.mu.Lock()
	if s.beforeSequenceStart != nil {
		started := s.beforeSequenceStart
		release := s.beforeSequenceAllow
		s.beforeSequenceStart = nil
		s.beforeSequenceAllow = nil
		close(started)
		s.mu.Unlock()
		select {
		case <-release:
		case <-time.After(time.Second):
		}
		s.mu.Lock()
	}
	if s.malformedSequence {
		s.malformedSequence = false
		s.mu.Unlock()
		_, _ = io.WriteString(w, "{malformed synthetic marker")
		return
	}
	if s.omitSequenceResult {
		s.omitSequenceResult = false
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"baton": "synthetic-baton", "base_url": nil,
			"results": []any{map[string]any{"type": "ok", "response": map[string]any{"type": "get_autocommit", "is_autocommit": true}}},
		})
		return
	}
	if s.malformedAutocommit {
		s.malformedAutocommit = false
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"baton": "synthetic-baton", "base_url": nil,
			"results": []any{
				map[string]any{"type": "ok", "response": map[string]any{"type": "sequence"}},
				map[string]any{"type": "ok", "response": map[string]any{"type": "get_autocommit"}},
			},
		})
		return
	}
	if s.inTxn {
		s.ignoredRollbacks++
		s.ignoredCloses++
		s.mu.Unlock()
		s.writeSequenceResponse(w, false, true)
		return
	}
	s.inTxn = true
	s.pending = cloneLedger(s.ledger)
	s.pendingExists = s.exists
	s.pendingUserVersion = s.userVersion
	s.pendingSecondSchema = s.secondSchema
	s.pendingThirdSchema = s.thirdSchema
	s.pendingCredentialSchema = s.credentialSchema
	s.pendingLifecycleSchema = s.lifecycleSchema
	s.pendingCurrentDiscoverySchema = s.currentDiscoverySchema
	s.pendingGateDecisionSchema = s.gateDecisionSchema
	s.pendingCandidateContentSchema = s.candidateContentSchema
	s.stallSequenceStage("sequence", beginImmediateSQL)
	if s.failSequenceStage(beginImmediateSQL) {
		s.mu.Unlock()
		s.writeSequenceResponse(w, false, true)
		return
	}
	migrationNumber := 0
	credentialMigration := false
	lifecycleMigration := false
	currentDiscoveryMigration := false
	gateDecisionMigration := false
	candidateContentMigration := false
	switch {
	case strings.Contains(sequence, expectedMigrationSQL):
		migrationNumber = 1
	case strings.Contains(sequence, expectedAccountMigrationSQL):
		migrationNumber = 2
	case strings.Contains(sequence, expectedCredentialMigrationSQL):
		migrationNumber = 3
		credentialMigration = true
	case strings.Contains(sequence, expectedLifecycleMigrationSQL):
		migrationNumber = 4
		lifecycleMigration = true
	case strings.Contains(sequence, expectedCurrentDiscoveryMigrationSQL):
		migrationNumber = 5
		currentDiscoveryMigration = true
	case strings.Contains(sequence, expectedGateDecisionMigrationSQL):
		migrationNumber = 6
		gateDecisionMigration = true
	case strings.Contains(sequence, expectedCandidateContentMigrationSQL):
		migrationNumber = 7
		candidateContentMigration = true
	case strings.Contains(sequence, expectedSecondMigrationSQL):
		migrationNumber = 2
	case strings.Contains(sequence, expectedThirdMigrationSQL):
		migrationNumber = 3
	default:
		s.testing.Errorf("sequence SQL differs from exact reviewed transaction")
		s.mu.Unlock()
		s.writeSequenceResponse(w, false, true)
		return
	}
	s.stallSequenceStage("migration")
	if !s.inTxn || s.pending == nil {
		s.mu.Unlock()
		s.writeSequenceResponse(w, true, true)
		return
	}
	if s.failSequenceStage("migration") {
		s.mu.Unlock()
		s.writeSequenceResponse(w, false, true)
		return
	}
	if migrationNumber == 1 {
		s.pendingExists = true
	} else if migrationNumber == 2 {
		s.pendingSecondSchema = true
	} else if credentialMigration {
		s.pendingCredentialSchema = true
	} else if lifecycleMigration {
		s.pendingLifecycleSchema = true
	} else if currentDiscoveryMigration {
		s.pendingCurrentDiscoverySchema = true
	} else if gateDecisionMigration {
		s.pendingGateDecisionSchema = true
	} else if candidateContentMigration {
		s.pendingCandidateContentSchema = true
	} else {
		s.pendingThirdSchema = true
	}
	prefixValid := s.lockedPrefixValid(sequence, migrationNumber-1)
	if !prefixValid {
		s.mu.Unlock()
		s.writeSequenceResponse(w, false, true)
		return
	}
	s.stallSequenceStage(ledgerInsertSQL)
	if !s.inTxn || s.pending == nil {
		s.mu.Unlock()
		s.writeSequenceResponse(w, true, true)
		return
	}
	if s.failSequenceStage(ledgerInsertSQL) {
		s.mu.Unlock()
		s.writeSequenceResponse(w, false, true)
		return
	}
	if s.dropBeforeCommit {
		s.dropBeforeCommit = false
		s.inTxn = false
		s.pending = nil
		s.pendingExists = false
		s.pendingUserVersion = 0
		s.pendingSecondSchema = false
		s.pendingThirdSchema = false
		s.pendingCredentialSchema = false
		s.pendingLifecycleSchema = false
		s.pendingCurrentDiscoverySchema = false
		s.pendingGateDecisionSchema = false
		s.pendingCandidateContentSchema = false
		s.mu.Unlock()
		writeDroppedPipelineResponse(w)
		return
	}
	insertedNumber, insertedChecksum, ok := parseSequenceLedgerInsert(sequence)
	if !ok || insertedNumber != migrationNumber {
		s.testing.Errorf("sequence ledger insertion differs from exact reviewed metadata")
		s.mu.Unlock()
		s.writeSequenceResponse(w, false, true)
		return
	}
	s.pending[insertedNumber] = insertedChecksum
	s.stallSequenceStage(commitSQL)
	if !s.inTxn || s.pending == nil {
		s.mu.Unlock()
		s.writeSequenceResponse(w, true, true)
		return
	}
	if s.failSequenceStage(commitSQL) {
		s.mu.Unlock()
		s.writeSequenceResponse(w, false, true)
		return
	}
	if s.holdTransaction {
		s.holdTransaction = false
		s.mu.Unlock()
		s.writeCustomSequenceResponse(w, false, false, false)
		return
	}
	s.ledger = cloneLedger(s.pending)
	s.exists = s.pendingExists
	s.secondSchema = s.pendingSecondSchema
	s.thirdSchema = s.pendingThirdSchema
	s.credentialSchema = s.pendingCredentialSchema
	s.lifecycleSchema = s.pendingLifecycleSchema
	s.currentDiscoverySchema = s.pendingCurrentDiscoverySchema
	s.gateDecisionSchema = s.pendingGateDecisionSchema
	s.candidateContentSchema = s.pendingCandidateContentSchema
	s.inTxn = false
	s.pending = nil
	s.pendingExists = false
	s.pendingUserVersion = 0
	s.pendingSecondSchema = false
	s.pendingThirdSchema = false
	s.pendingCredentialSchema = false
	s.pendingLifecycleSchema = false
	s.pendingCurrentDiscoverySchema = false
	s.pendingGateDecisionSchema = false
	s.pendingCandidateContentSchema = false
	s.stallSequenceStage(commitAfterDurabilityStage)
	if s.drop {
		s.drop = false
		s.mu.Unlock()
		writeDroppedPipelineResponse(w)
		return
	}
	omitPayload := s.omitSequencePayload
	wrongPayload := s.wrongSequencePayload
	falseAutocommit := s.falseAutocommit
	s.omitSequencePayload = false
	s.wrongSequencePayload = false
	s.falseAutocommit = false
	s.mu.Unlock()
	s.writeCustomSequenceResponse(w, !falseAutocommit, omitPayload, wrongPayload)
}

func (s *migrationProtocolServer) stallSequenceStage(stages ...string) {
	matched := false
	for _, stage := range stages {
		if s.stallSQL == stage {
			matched = true
			break
		}
	}
	if !matched {
		return
	}
	s.stallSQL = ""
	started := s.stallStarted
	release := s.stallRelease
	finished := s.stallFinished
	close(started)
	s.mu.Unlock()
	select {
	case <-release:
	case <-time.After(time.Second):
	}
	s.mu.Lock()
	close(finished)
}

func (s *migrationProtocolServer) failSequenceStage(stage string) bool {
	if s.failSQL != stage {
		return false
	}
	s.failSQL = ""
	s.failSQLSkip = 0
	return true
}

func (s *migrationProtocolServer) lockedPrefixValid(sequence string, prefixLength int) bool {
	rows := s.ledgerRowsOverride
	if rows == nil {
		ledger := s.ledger
		if s.inTxn && s.pending != nil {
			ledger = s.pending
		}
		numbers := make([]int, 0, len(ledger))
		for number := range ledger {
			numbers = append(numbers, number)
		}
		sort.Ints(numbers)
		rows = make([][]any, 0, len(numbers))
		for _, number := range numbers {
			rows = append(rows, []any{integerValue(int64(number)), textValue(ledger[number])})
		}
	}
	if len(rows) != prefixLength {
		return false
	}
	strongGuard := strings.Contains(sequence, "number IS NULL OR checksum IS NULL")
	counts := make([]int, prefixLength)
	for _, row := range rows {
		number, numberOK := syntheticInteger(row, 0)
		checksum, checksumOK := syntheticText(row, 1)
		if !numberOK || !checksumOK {
			if strongGuard {
				return false
			}
			continue
		}
		matched := number >= 1 && number <= prefixLength && strings.Contains(sequence,
			"WHERE number = "+strconv.Itoa(number)+" AND checksum = '"+checksum+"') = 1")
		if matched {
			counts[number-1]++
		}
		if !matched {
			return false
		}
	}
	if !strongGuard {
		return true
	}
	for _, count := range counts {
		if count != 1 {
			return false
		}
	}
	return true
}

func parseSequenceLedgerInsert(sequence string) (int, string, bool) {
	start := strings.Index(sequence, sequenceInsertSQL)
	if start < 0 {
		return 0, "", false
	}
	raw := sequence[start+len(sequenceInsertSQL):]
	end := strings.Index(raw, ");")
	if end < 0 {
		return 0, "", false
	}
	parts := strings.Split(raw[:end], ", '")
	if len(parts) != 2 || !strings.HasSuffix(parts[1], "'") {
		return 0, "", false
	}
	number, err := strconv.Atoi(parts[0])
	checksum := strings.TrimSuffix(parts[1], "'")
	return number, checksum, err == nil && len(checksum) == sha256HexLength && isLowerHex(checksum)
}

func syntheticInteger(row []any, index int) (int, bool) {
	if index >= len(row) || row[index] == nil {
		return 0, false
	}
	value, ok := row[index].(map[string]any)
	if !ok || value["type"] != "integer" {
		return 0, false
	}
	raw, ok := value["value"].(string)
	if !ok {
		return 0, false
	}
	number, err := strconv.Atoi(raw)
	return number, err == nil
}

func syntheticText(row []any, index int) (string, bool) {
	if index >= len(row) || row[index] == nil {
		return "", false
	}
	value, ok := row[index].(map[string]any)
	if !ok || value["type"] != "text" {
		return "", false
	}
	raw, ok := value["value"].(string)
	return raw, ok
}

func (s *migrationProtocolServer) writeSequenceResponse(w http.ResponseWriter, autocommit, failed bool) {
	sequenceResult := map[string]any{"type": "ok", "response": map[string]any{"type": "sequence"}}
	if failed {
		sequenceResult = map[string]any{
			"type":  "error",
			"error": map[string]any{"message": "raw synthetic-token SELECT private marker", "code": "SYNTHETIC"},
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"baton": "synthetic-baton", "base_url": nil,
		"results": []any{
			sequenceResult,
			map[string]any{"type": "ok", "response": map[string]any{"type": "get_autocommit", "is_autocommit": autocommit}},
		},
	})
}

func (s *migrationProtocolServer) writeCustomSequenceResponse(w http.ResponseWriter, autocommit, omitPayload, wrongPayload bool) {
	sequenceResult := map[string]any{"type": "ok", "response": map[string]any{"type": "sequence"}}
	if omitPayload {
		sequenceResult = map[string]any{"type": "ok"}
	}
	if wrongPayload {
		sequenceResult = map[string]any{"type": "ok", "response": map[string]any{"type": "close"}}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"baton": "synthetic-baton", "base_url": nil,
		"results": []any{
			sequenceResult,
			map[string]any{"type": "ok", "response": map[string]any{"type": "get_autocommit", "is_autocommit": autocommit}},
		},
	})
}

func writeDroppedPipelineResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", "256")
	_, _ = io.WriteString(w, "{\"baton\":\"synthetic-baton\",\"base_url\":null,\"results\":[")
}

func (s *migrationProtocolServer) seedLedger(number int, checksum string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exists = true
	s.ledger[number] = checksum
	s.userVersion = number
}

func (s *migrationProtocolServer) seedEmbeddedCatalog() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exists = true
	s.ledger[1] = expectedMigrationChecksum
	s.ledger[2] = expectedAccountMigrationChecksum
	s.ledger[3] = expectedCredentialMigrationChecksum
	s.ledger[4] = expectedLifecycleMigrationChecksum
	s.ledger[5] = expectedCurrentDiscoveryMigrationChecksum
	s.ledger[6] = expectedGateDecisionMigrationChecksum
	s.ledger[7] = expectedCandidateContentMigrationChecksum
	s.secondSchema = true
	s.credentialSchema = true
	s.lifecycleSchema = true
	s.currentDiscoverySchema = true
	s.gateDecisionSchema = true
	s.candidateContentSchema = true
	s.userVersion = 7
}

func (s *migrationProtocolServer) dropNextCommit() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drop = true
}

func (s *migrationProtocolServer) dropNextCommitBeforeDurability() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropBeforeCommit = true
}

func (s *migrationProtocolServer) headerOnlyNextCommitBeforeDurability() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.headerOnlyCommit = true
}

func (s *migrationProtocolServer) headerOnlyNextRollback() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.headerOnlyRollback = true
}

func (s *migrationProtocolServer) headerOnlyNextBeginWithoutApplying() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.headerOnlyBegin = true
}

func (s *migrationProtocolServer) headerOnlyNextMigrationWithoutApplying() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.headerOnlyMigration = true
}

func (s *migrationProtocolServer) malformedNextSequenceResponse() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.malformedSequence = true
}

func (s *migrationProtocolServer) omitNextSequenceResult() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.omitSequenceResult = true
}

func (s *migrationProtocolServer) malformNextAutocommitResult() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.malformedAutocommit = true
}

func (s *migrationProtocolServer) omitNextSequenceResponsePayload() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.omitSequencePayload = true
}

func (s *migrationProtocolServer) wrongNextSequenceResponsePayload() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wrongSequencePayload = true
}

func (s *migrationProtocolServer) falseNextSequenceAutocommit() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.falseAutocommit = true
}

func (s *migrationProtocolServer) holdNextSequenceTransaction() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.holdTransaction = true
}

func (s *migrationProtocolServer) malformNextTerminalResponse() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terminalMalformed = true
}

func (s *migrationProtocolServer) omitNextTerminalResult() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terminalOmitResult = true
}

func (s *migrationProtocolServer) malformNextTerminalAutocommit() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terminalBadAuto = true
}

func (s *migrationProtocolServer) falseNextTerminalAutocommit() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terminalFalseAuto = true
}

func (s *migrationProtocolServer) omitNextTerminalSequencePayload() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terminalOmitPayload = true
}

func (s *migrationProtocolServer) wrongNextTerminalSequencePayload() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terminalWrongPayload = true
}

func (s *migrationProtocolServer) skipNextTerminalMarker() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terminalSkipMarker = true
}

func (s *migrationProtocolServer) clearUserVersion() {
	s.setUserVersion(0)
}

func (s *migrationProtocolServer) setUserVersion(number int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.userVersion = number
}

func (s *migrationProtocolServer) failNextMigration() {
	s.failNextSQL("migration")
}

func (s *migrationProtocolServer) failNextSQL(statement string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failSQL = statement
	s.failSQLSkip = 0
}

func (s *migrationProtocolServer) failNthSQL(statement string, occurrence int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failSQL = statement
	s.failSQLSkip = occurrence - 1
}

func (s *migrationProtocolServer) overrideLedgerRows(rows [][]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exists = true
	s.ledgerRowsOverride = rows
}

func (s *migrationProtocolServer) stallNext(statement string) (chan struct{}, chan struct{}, chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stallSQL = statement
	s.stallStarted = make(chan struct{})
	s.stallRelease = make(chan struct{})
	s.stallFinished = make(chan struct{})
	return s.stallStarted, s.stallRelease, s.stallFinished
}

func (s *migrationProtocolServer) stallBeforeNextSequence() (chan struct{}, chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.beforeSequenceStart = make(chan struct{})
	s.beforeSequenceAllow = make(chan struct{})
	return s.beforeSequenceStart, s.beforeSequenceAllow
}

func (s *migrationProtocolServer) stallBeforeNextTerminalSequence() (chan struct{}, chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.beforeTerminalStart = make(chan struct{})
	s.beforeTerminalAllow = make(chan struct{})
	return s.beforeTerminalStart, s.beforeTerminalAllow
}

func (s *migrationProtocolServer) corruptLedgerChecksum(number int, checksum string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ledger[number] = checksum
}

func (s *migrationProtocolServer) deleteLedgerRow(number int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.ledger, number)
}

func (s *migrationProtocolServer) secondSchemaExists() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.secondSchema
}

func (s *migrationProtocolServer) thirdSchemaExists() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.thirdSchema
}

func (s *migrationProtocolServer) ledgerChecksum(number int) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	checksum, exists := s.ledger[number]
	return checksum, exists
}

func (s *migrationProtocolServer) assertCommittedCatalog(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.exists || s.ledger[1] != expectedMigrationChecksum || s.ledger[2] != expectedAccountMigrationChecksum || s.ledger[3] != expectedCredentialMigrationChecksum || s.ledger[4] != expectedLifecycleMigrationChecksum || s.ledger[5] != expectedCurrentDiscoveryMigrationChecksum || s.ledger[6] != expectedGateDecisionMigrationChecksum || s.ledger[7] != expectedCandidateContentMigrationChecksum {
		t.Fatalf("durable ledger = %#v, want exact embedded catalog", s.ledger)
	}
}

func (s *migrationProtocolServer) assertExactFirstApplicationSequence(t *testing.T) {
	t.Helper()
	expected := []migrationRequest{
		{sql: ledgerExistsSQL, args: []protocolValue{textProtocolValue("table"), textProtocolValue(ledgerTable)}, wantRows: true},
		{sql: userVersionSQL, wantRows: true},
		{sql: ledgerExistsSQL, args: []protocolValue{textProtocolValue("table"), textProtocolValue(ledgerTable)}, wantRows: true},
		{sql: ledgerRowsSQL, args: []protocolValue{integerProtocolValue(expectedMaximumMigrationCount + 1)}, wantRows: true},
		{sql: userVersionSQL, wantRows: true},
		{sql: ledgerExistsSQL, args: []protocolValue{textProtocolValue("table"), textProtocolValue(ledgerTable)}, wantRows: true},
		{sql: ledgerRowsSQL, args: []protocolValue{integerProtocolValue(expectedMaximumMigrationCount + 1)}, wantRows: true},
		{sql: userVersionSQL, wantRows: true},
		{sql: ledgerExistsSQL, args: []protocolValue{textProtocolValue("table"), textProtocolValue(ledgerTable)}, wantRows: true},
		{sql: ledgerRowsSQL, args: []protocolValue{integerProtocolValue(expectedMaximumMigrationCount + 1)}, wantRows: true},
		{sql: userVersionSQL, wantRows: true},
		{sql: ledgerExistsSQL, args: []protocolValue{textProtocolValue("table"), textProtocolValue(ledgerTable)}, wantRows: true},
		{sql: ledgerRowsSQL, args: []protocolValue{integerProtocolValue(expectedMaximumMigrationCount + 1)}, wantRows: true},
		{sql: userVersionSQL, wantRows: true},
		{sql: ledgerExistsSQL, args: []protocolValue{textProtocolValue("table"), textProtocolValue(ledgerTable)}, wantRows: true},
		{sql: ledgerRowsSQL, args: []protocolValue{integerProtocolValue(expectedMaximumMigrationCount + 1)}, wantRows: true},
		{sql: userVersionSQL, wantRows: true},
		{sql: ledgerExistsSQL, args: []protocolValue{textProtocolValue("table"), textProtocolValue(ledgerTable)}, wantRows: true},
		{sql: ledgerRowsSQL, args: []protocolValue{integerProtocolValue(expectedMaximumMigrationCount + 1)}, wantRows: true},
		{sql: userVersionSQL, wantRows: true},
		{sql: ledgerExistsSQL, args: []protocolValue{textProtocolValue("table"), textProtocolValue(ledgerTable)}, wantRows: true},
		{sql: ledgerRowsSQL, args: []protocolValue{integerProtocolValue(expectedMaximumMigrationCount + 1)}, wantRows: true},
		{sql: userVersionSQL, wantRows: true},
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.records) != len(expected) {
		t.Fatalf("migration request count = %d, want %d", len(s.records), len(expected))
	}
	for index, want := range expected {
		got := s.records[index]
		if got.sql != want.sql {
			t.Fatalf("migration request %d SQL differs from exact reviewed bytes", index+1)
		}
		if got.wantRows != want.wantRows || got.namedArgCount != 0 {
			t.Fatalf("migration request %d row or named-argument policy differs", index+1)
		}
		if len(got.args) != len(want.args) {
			t.Fatalf("migration request %d argument count = %d, want %d", index+1, len(got.args), len(want.args))
		}
		for argument := range want.args {
			if got.args[argument].Type != want.args[argument].Type || string(got.args[argument].Value) != string(want.args[argument].Value) {
				t.Fatalf("migration request %d argument %d differs", index+1, argument+1)
			}
		}
	}
	if len(s.pipelineRecords) != 14 {
		t.Fatalf("pipeline request shape = %#v, want seven apply and terminal sequence pairs", s.pipelineRecords)
	}
	for index := range s.pipelineRecords {
		if len(s.pipelineRecords[index].requests) != 2 {
			t.Fatalf("pipeline request %d shape = %#v, want sequence with autocommit observation", index+1, s.pipelineRecords[index])
		}
	}
	sequence := s.pipelineRecords[0].requests[0]
	if sequence.Type != "sequence" || sequence.SQL != expectedMigrationSequence {
		t.Fatal("pipeline sequence differs from exact reviewed transaction bytes")
	}
	if len(sequence.Args) != 0 || len(sequence.NamedArgs) != 0 {
		t.Fatal("pipeline sequence unexpectedly carried arguments")
	}
	autocommit := s.pipelineRecords[0].requests[1]
	if autocommit.Type != "get_autocommit" || autocommit.SQL != "" || len(autocommit.Args) != 0 || len(autocommit.NamedArgs) != 0 {
		t.Fatal("pipeline did not carry one exact get_autocommit validation request")
	}
	terminalRequest := s.pipelineRecords[1].requests[0]
	if terminalRequest.Type != "sequence" || terminalRequest.SQL != expectedTerminalSequence || len(terminalRequest.Args) != 0 || len(terminalRequest.NamedArgs) != 0 {
		t.Fatal("pipeline terminal sequence differs from exact reviewed proof bytes")
	}
	terminalAutocommit := s.pipelineRecords[1].requests[1]
	if terminalAutocommit.Type != "get_autocommit" || terminalAutocommit.SQL != "" || len(terminalAutocommit.Args) != 0 || len(terminalAutocommit.NamedArgs) != 0 {
		t.Fatal("pipeline terminal proof did not carry one exact get_autocommit observation")
	}
	accountSequence := s.pipelineRecords[2].requests[0]
	if accountSequence.Type != "sequence" || accountSequence.SQL != expectedAccountMigrationSequence || len(accountSequence.Args) != 0 || len(accountSequence.NamedArgs) != 0 {
		t.Fatal("account pipeline sequence differs from exact reviewed transaction bytes")
	}
	accountTerminal := s.pipelineRecords[3].requests[0]
	if accountTerminal.Type != "sequence" || accountTerminal.SQL != expectedAccountTerminalSequence || len(accountTerminal.Args) != 0 || len(accountTerminal.NamedArgs) != 0 {
		t.Fatal("account pipeline terminal sequence differs from exact reviewed proof bytes")
	}
	credentialSequence := s.pipelineRecords[4].requests[0]
	if credentialSequence.Type != "sequence" || credentialSequence.SQL != expectedCredentialMigrationSequence || len(credentialSequence.Args) != 0 || len(credentialSequence.NamedArgs) != 0 {
		t.Fatal("credential pipeline sequence differs from exact reviewed transaction bytes")
	}
	credentialTerminal := s.pipelineRecords[5].requests[0]
	if credentialTerminal.Type != "sequence" || credentialTerminal.SQL != expectedCredentialTerminalSequence || len(credentialTerminal.Args) != 0 || len(credentialTerminal.NamedArgs) != 0 {
		t.Fatal("credential pipeline terminal sequence differs from exact reviewed proof bytes")
	}
	lifecycleSequence := s.pipelineRecords[6].requests[0]
	if lifecycleSequence.Type != "sequence" || lifecycleSequence.SQL != expectedLifecycleMigrationSequence || len(lifecycleSequence.Args) != 0 || len(lifecycleSequence.NamedArgs) != 0 {
		t.Fatal("lifecycle pipeline sequence differs from exact reviewed transaction bytes")
	}
	lifecycleTerminal := s.pipelineRecords[7].requests[0]
	if lifecycleTerminal.Type != "sequence" || lifecycleTerminal.SQL != expectedLifecycleTerminalSequence || len(lifecycleTerminal.Args) != 0 || len(lifecycleTerminal.NamedArgs) != 0 {
		t.Fatal("lifecycle pipeline terminal sequence differs from exact reviewed proof bytes")
	}
	currentDiscoverySequence := s.pipelineRecords[8].requests[0]
	if currentDiscoverySequence.Type != "sequence" || currentDiscoverySequence.SQL != expectedCurrentDiscoveryMigrationSequence || len(currentDiscoverySequence.Args) != 0 || len(currentDiscoverySequence.NamedArgs) != 0 {
		t.Fatal("current discovery pipeline sequence differs from exact reviewed transaction bytes")
	}
	currentDiscoveryTerminal := s.pipelineRecords[9].requests[0]
	if currentDiscoveryTerminal.Type != "sequence" || currentDiscoveryTerminal.SQL != expectedCurrentDiscoveryTerminalSequence || len(currentDiscoveryTerminal.Args) != 0 || len(currentDiscoveryTerminal.NamedArgs) != 0 {
		t.Fatal("current discovery pipeline terminal sequence differs from exact reviewed proof bytes")
	}
	gateDecisionSequence := s.pipelineRecords[10].requests[0]
	if gateDecisionSequence.Type != "sequence" || gateDecisionSequence.SQL != expectedGateDecisionMigrationSequence || len(gateDecisionSequence.Args) != 0 || len(gateDecisionSequence.NamedArgs) != 0 {
		t.Fatal("gate decision pipeline sequence differs from exact reviewed transaction bytes")
	}
	gateDecisionTerminal := s.pipelineRecords[11].requests[0]
	if gateDecisionTerminal.Type != "sequence" || gateDecisionTerminal.SQL != expectedGateDecisionTerminalSequence || len(gateDecisionTerminal.Args) != 0 || len(gateDecisionTerminal.NamedArgs) != 0 {
		t.Fatal("gate decision pipeline terminal sequence differs from exact reviewed proof bytes")
	}
	candidateContentSequence := s.pipelineRecords[12].requests[0]
	if candidateContentSequence.Type != "sequence" || candidateContentSequence.SQL != expectedCandidateContentMigrationSequence || len(candidateContentSequence.Args) != 0 || len(candidateContentSequence.NamedArgs) != 0 {
		t.Fatal("candidate content pipeline sequence differs from exact reviewed transaction bytes")
	}
	candidateContentTerminal := s.pipelineRecords[13].requests[0]
	if candidateContentTerminal.Type != "sequence" || candidateContentTerminal.SQL != expectedCandidateContentTerminalSequence || len(candidateContentTerminal.Args) != 0 || len(candidateContentTerminal.NamedArgs) != 0 {
		t.Fatal("candidate content pipeline terminal sequence differs from exact reviewed proof bytes")
	}
}

func textProtocolValue(value string) protocolValue {
	raw, _ := json.Marshal(value)
	return protocolValue{Type: "text", Value: raw}
}

func integerProtocolValue(value int) protocolValue {
	raw, _ := json.Marshal(strconv.Itoa(value))
	return protocolValue{Type: "integer", Value: raw}
}

func (s *migrationProtocolServer) assertSeparateVerificationStream(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.records) != 23 || s.records[0].baton != nil {
		t.Fatal("first migration request did not start a fresh physical stream")
	}
	if s.records[1].baton == nil {
		t.Fatal("initial marker inspection did not continue its physical stream")
	}
	if s.records[2].baton != nil {
		t.Fatal("durability verification did not use a separate physical connection")
	}
	if s.records[3].baton == nil || s.records[4].baton == nil {
		t.Fatal("durability verification did not continue its separate physical stream")
	}
}

func (s *migrationProtocolServer) mutationCount() int {
	return s.sequenceCount() + s.terminalSequenceCount()
}

func (s *migrationProtocolServer) ledgerExists() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exists
}

func (s *migrationProtocolServer) insertCount() int {
	return s.countSQL(ledgerInsertSQL)
}

func (s *migrationProtocolServer) commitCount() int {
	return s.countSQL(commitSQL)
}

func (s *migrationProtocolServer) migrationStatementCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, record := range s.records {
		if strings.HasPrefix(record.sql, "CREATE TABLE inboxgate_schema_migrations") {
			count++
		}
	}
	return count
}

func (s *migrationProtocolServer) countSQL(statement string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, record := range s.records {
		if record.sql == statement {
			count++
		}
	}
	return count
}

func (s *migrationProtocolServer) countStageRequests(statement string) int {
	if statement == "migration" {
		return s.migrationStatementCount()
	}
	return s.countSQL(statement)
}

func (s *migrationProtocolServer) sequenceCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, record := range s.pipelineRecords {
		for _, request := range record.requests {
			if request.Type == "sequence" && !strings.HasPrefix(request.SQL, "SAVEPOINT "+terminalSavepoint+";") {
				count++
			}
		}
	}
	return count
}

func (s *migrationProtocolServer) terminalSequenceCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, record := range s.pipelineRecords {
		for _, request := range record.requests {
			if request.Type == "sequence" && strings.HasPrefix(request.SQL, "SAVEPOINT inboxgate_migration_terminal;") {
				count++
			}
		}
	}
	return count
}

func (s *migrationProtocolServer) closeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, record := range s.pipelineRecords {
		for _, request := range record.requests {
			if request.Type == "close" {
				count++
			}
		}
	}
	return count
}

func (s *migrationProtocolServer) userVersionValue() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.userVersion
}

func cloneLedger(source map[int]string) map[int]string {
	clone := make(map[int]string, len(source))
	for number, checksum := range source {
		clone[number] = checksum
	}
	return clone
}

func integerValue(value int64) map[string]any {
	return map[string]any{"type": "integer", "value": strconv.FormatInt(value, 10)}
}

func textValue(value string) map[string]any {
	return map[string]any{"type": "text", "value": value}
}

func nullValue() map[string]any {
	return map[string]any{"type": "null"}
}

func parseProtocolValue(value protocolValue) string {
	if value.Type == "null" || string(value.Value) == "null" {
		return ""
	}
	var decoded string
	if err := json.Unmarshal(value.Value, &decoded); err != nil {
		return fmt.Sprintf("invalid:%s", value.Value)
	}
	return decoded
}

func historyTextLess(left, right string) bool {
	return len(left) < len(right) || (len(left) == len(right) && left < right)
}

func (s *migrationProtocolServer) seedAccount(accountID, subject string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accounts[accountID] = subject
	s.lifecycles[accountID] = syntheticLifecycle{state: "pending", version: 1, revocation: "none"}
}

func (s *migrationProtocolServer) seedLifecycle(accountID, state string, version int64, reason *string, revocation string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lifecycles[accountID] = syntheticLifecycle{state: state, version: version, reason: reason, revocation: revocation}
}

func (s *migrationProtocolServer) seedCursor(accountID, historyID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cursors[accountID] = historyID
}

func (s *migrationProtocolServer) seedCredential(accountID, keyID, envelope string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentials[accountID] = syntheticCredential{keyID: keyID, envelope: envelope}
}

func (s *migrationProtocolServer) resetCredentialScenario() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accounts = make(map[string]string)
	s.cursors = make(map[string]string)
	s.credentials = make(map[string]syntheticCredential)
	s.lifecycles = make(map[string]syntheticLifecycle)
	s.persistenceMode = ""
	s.persistenceStatement = ""
	s.persistenceStarted = nil
	s.persistenceRelease = nil
	s.persistenceRows = make(map[string][][]any)
	s.persistenceColumns = make(map[string][]any)
	s.nextCursorBaseURL = ""
	s.closedCursorAt = make(map[string]int)
	s.closedCursorCount = make(map[string]int)
	s.records = nil
}

func (s *migrationProtocolServer) armPersistenceResponse(statement, mode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persistenceStatement = statement
	s.persistenceMode = mode
}

func (s *migrationProtocolServer) overridePersistenceRows(statement string, rows [][]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persistenceRows[statement] = rows
}

func (s *migrationProtocolServer) overridePersistenceColumns(statement string, columns []any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persistenceColumns[statement] = append([]any(nil), columns...)
}

func (s *migrationProtocolServer) redirectNextCursorBaseURL(baseURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextCursorBaseURL = baseURL
}

func (s *migrationProtocolServer) stallPersistence(statement string) (chan struct{}, chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	started := make(chan struct{})
	release := make(chan struct{})
	s.persistenceStatement = statement
	s.persistenceStarted = started
	s.persistenceRelease = release
	return started, release
}

func (s *migrationProtocolServer) barrierPersistence(statement string, target int) (chan struct{}, chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	started := make(chan struct{})
	release := make(chan struct{})
	s.barrierSQL = statement
	s.barrierTarget = target
	s.barrierArrived = 0
	s.barrierStarted = started
	s.barrierRelease = release
	return started, release
}

func (s *migrationProtocolServer) stallPersistenceBody(statement string) (chan struct{}, chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	started := make(chan struct{})
	release := make(chan struct{})
	s.persistenceStatement = statement
	s.persistenceMode = "body-stall"
	s.persistenceStarted = started
	s.persistenceRelease = release
	return started, release
}

func (s *migrationProtocolServer) persistenceRecords() []migrationRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := make([]migrationRequest, 0, len(s.records))
	for _, record := range s.records {
		if record.sql == accountLookupSQL || record.sql == accountInsertSQL || record.sql == cursorLookupSQL || record.sql == cursorCommitSQL || record.sql == credentialLookupSQL || record.sql == credentialCommitSQL || record.sql == lifecycleLookupSQL || record.sql == accountListSQL || record.sql == lifecycleCommitSQL || record.sql == revokedCredentialDeleteSQL || record.sql == currentDiscoveryAttemptLookupSQL || record.sql == currentDiscoveryAttemptCreateSQL || record.sql == currentDiscoveryStageLookupSQL || record.sql == currentDiscoveryStageSQL || record.sql == currentDiscoveryStageProofSQL || record.sql == currentDiscoverySealSQL || record.sql == currentDiscoveryFinalizeSQL || record.sql == currentDiscoveryAbortSQL || record.sql == currentDiscoveryMessageLookupSQL || record.sql == currentDiscoveryRecordLookupSQL || record.sql == currentDiscoveryNaturalKeyLookupSQL || record.sql == currentDiscoveryProofSQL || record.sql == gateDecisionLookupSQL || record.sql == gateDecisionCommitSQL || record.sql == candidateContentLookupSQL || record.sql == candidateContentCommitSQL {
			records = append(records, record)
		}
	}
	return records
}

func (s *migrationProtocolServer) rawRecords() []migrationRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]migrationRequest(nil), s.records...)
}

func (s *migrationProtocolServer) cursorSessionWasClosedWithoutReuse(baton string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	closedAt, ok := s.closedCursorAt[baton]
	if !ok {
		return false
	}
	for index := closedAt; index < len(s.records); index++ {
		if s.records[index].baton != nil && *s.records[index].baton == baton {
			return false
		}
	}
	return true
}

func (s *migrationProtocolServer) cursorSessionWasNotReusedAfterMutation(baton, statement string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for _, record := range s.records {
		if !found && record.sql == statement && record.baton != nil && *record.baton == baton {
			found = true
			continue
		}
		if found && record.baton != nil && *record.baton == baton {
			return false
		}
	}
	return found
}

func (s *migrationProtocolServer) cursorSessionCloseCount(baton string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closedCursorCount[baton]
}
