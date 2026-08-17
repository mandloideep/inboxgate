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
	"net/http"
	"net/http/httptest"
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
	expectedMaximumMigrationCount = 256
	expectedMigrationSQL          = "CREATE TABLE inboxgate_schema_migrations (\n    number INTEGER PRIMARY KEY CHECK (number BETWEEN 1 AND 256),\n    checksum TEXT NOT NULL CHECK (length(checksum) = 64 AND checksum NOT GLOB '*[^0-9a-f]*')\n) STRICT, WITHOUT ROWID;\n"
	expectedAccountMigrationSQL   = "CREATE TABLE inboxgate_accounts (\n    account_id TEXT PRIMARY KEY CHECK (length(CAST(account_id AS BLOB)) = 32 AND instr(CAST(account_id AS BLOB), x'00') = 0 AND account_id NOT GLOB '*[^0-9a-f]*'),\n    provider TEXT NOT NULL CHECK (provider = 'gmail'),\n    provider_subject TEXT COLLATE BINARY NOT NULL CHECK (length(CAST(provider_subject AS BLOB)) BETWEEN 1 AND 255 AND instr(CAST(provider_subject AS BLOB), x'00') = 0 AND provider_subject NOT GLOB '*[^!-~]*'),\n    UNIQUE (provider, provider_subject)\n) STRICT, WITHOUT ROWID;\n\nCREATE TABLE inboxgate_synchronization_cursors (\n    account_id TEXT PRIMARY KEY,\n    history_id TEXT COLLATE BINARY NOT NULL CHECK (\n        length(CAST(history_id AS BLOB)) BETWEEN 1 AND 20\n        AND instr(CAST(history_id AS BLOB), x'00') = 0\n        AND history_id NOT GLOB '*[^0-9]*'\n        AND substr(history_id, 1, 1) BETWEEN '1' AND '9'\n        AND (length(CAST(history_id AS BLOB)) < 20 OR history_id <= '18446744073709551615')\n    ),\n    FOREIGN KEY (account_id) REFERENCES inboxgate_accounts (account_id) ON DELETE RESTRICT\n) STRICT, WITHOUT ROWID;\n"
	expectedSecondMigrationSQL    = "CREATE TABLE inboxgate_synthetic_second (id INTEGER PRIMARY KEY);\n"
	expectedThirdMigrationSQL     = "CREATE TABLE inboxgate_synthetic_third (id INTEGER PRIMARY KEY);\n"
	ledgerInsertSQL               = "INSERT INTO inboxgate_schema_migrations (number, checksum) VALUES (?, ?)"
	commitAfterDurabilityStage    = "commit-after-durability"
)

var expectedMigrationChecksum = func() string {
	sum := sha256.Sum256([]byte(expectedMigrationSQL))
	return hex.EncodeToString(sum[:])
}()

var expectedAccountMigrationChecksum = func() string {
	sum := sha256.Sum256([]byte(expectedAccountMigrationSQL))
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

func TestMigrationContractEmptyApplication(t *testing.T) {

	server := newMigrationProtocolServer(t)
	handle := openMigrationContractHandle(t, server.URL)

	result, err := handle.Migrate(context.Background())
	if err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if result != (storage.MigrationResult{Applied: 2, Current: 2}) {
		t.Fatalf("Migrate() result = %#v, want two applied migrations", result)
	}
	server.assertCommittedCatalog(t)
	server.assertSeparateVerificationStream(t)
	server.assertExactFirstApplicationSequence(t)
	firstMutationCount := server.mutationCount()

	result, err = handle.Migrate(context.Background())
	if err != nil {
		t.Fatalf("second Migrate() error = %v", err)
	}
	if result != (storage.MigrationResult{Applied: 0, Current: 2}) {
		t.Fatalf("second Migrate() result = %#v, want bounded no-op", result)
	}
	if got := server.mutationCount(); got != firstMutationCount {
		t.Fatalf("second Migrate() mutations = %d, want unchanged %d", got, firstMutationCount)
	}
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
	if result != (storage.MigrationResult{Applied: 1, Current: 2}) {
		t.Fatalf("fresh Migrate() result = %#v, want durable reconciliation", result)
	}
	if got := server.sequenceCount(); got != 2 {
		t.Fatalf("sequence requests after reconciliation = %d, want only pending migration 2", got)
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
	if result != (storage.MigrationResult{Applied: 2, Current: 2}) {
		t.Fatalf("fresh Migrate() result = %#v, want two newly durable migrations", result)
	}
	if got := server.sequenceCount(); got != 3 {
		t.Fatalf("sequence requests across explicit invocations = %d, want 3", got)
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
	if result != (storage.MigrationResult{Applied: 2, Current: 2}) {
		t.Fatalf("Migrate() result = %#v, want two atomic sequences", result)
	}
	if got := server.commitCount(); got != 0 {
		t.Fatalf("standalone commit requests = %d, want 0", got)
	}
	if got := server.sequenceCount(); got != 2 {
		t.Fatalf("sequence requests = %d, want 2", got)
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
	if result != (storage.MigrationResult{Applied: 2, Current: 2}) {
		t.Fatalf("Migrate() result = %#v, want two atomic sequences", result)
	}
	if got := server.countSQL(beginImmediateSQL); got != 0 {
		t.Fatalf("standalone begin requests = %d, want 0", got)
	}
	if got := server.migrationStatementCount(); got != 0 {
		t.Fatalf("standalone migration requests = %d, want 0", got)
	}
	if got := server.sequenceCount(); got != 2 {
		t.Fatalf("sequence requests = %d, want 2", got)
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
	if result != (storage.MigrationResult{Applied: 2, Current: 2}) {
		t.Fatalf("Migrate() result = %#v, want two atomic sequences", result)
	}
	if got := server.migrationStatementCount(); got != 0 {
		t.Fatalf("standalone migration requests = %d, want 0", got)
	}
	if got := server.insertCount(); got != 0 {
		t.Fatalf("standalone ledger inserts = %d, want 0", got)
	}
	if got := server.sequenceCount(); got != 2 {
		t.Fatalf("sequence requests = %d, want 2", got)
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
	if result != (storage.MigrationResult{Applied: 2, Current: 2}) {
		t.Fatalf("fresh Migrate() result = %#v, want two applied migrations", result)
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
			if result != (storage.MigrationResult{Applied: 2, Current: 2}) {
				t.Fatalf("fresh Migrate() result = %#v, want two atomic migrations", result)
			}
			if got := server.sequenceCount(); got != 3 {
				t.Fatalf("sequence requests across explicit invocations = %d, want 3", got)
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
			if result != (storage.MigrationResult{Applied: 2, Current: 2}) {
				t.Fatalf("Migrate() result = %#v, want two semantically proven migrations", result)
			}
			if got := server.terminalSequenceCount(); got != 2 {
				t.Fatalf("terminal proof sequences = %d, want 2", got)
			}
			if got := server.userVersionValue(); got != 2 {
				t.Fatalf("durable user_version = %d, want 2", got)
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
	if result != (storage.MigrationResult{Applied: 2, Current: 2}) {
		t.Fatalf("fresh explicit Migrate() result = %#v, want two applied migrations", result)
	}
	if got := server.sequenceCount(); got != 3 {
		t.Fatalf("migration sequences across explicit invocations = %d, want 3", got)
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
	if result != (storage.MigrationResult{Current: 2}) {
		t.Fatalf("Migrate() result = %#v, want marker-only reconciliation", result)
	}
	if got := server.sequenceCount(); got != 0 {
		t.Fatalf("migration sequences = %d, want no migration replay", got)
	}
	if got := server.terminalSequenceCount(); got != 1 {
		t.Fatalf("terminal sequences = %d, want one marker repair", got)
	}
	if got := server.userVersionValue(); got != 2 {
		t.Fatalf("durable user_version = %d, want 2", got)
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
	server.setUserVersion(3)
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-result:
		if !errors.Is(err, ErrMigrationUnknownOutcome) {
			t.Fatalf("Migrate() error = %v, want ErrMigrationUnknownOutcome", err)
		}
	case <-time.After(time.Second):
		t.Fatal("marker repair did not return after race release")
	}
	if got := server.userVersionValue(); got != 3 {
		t.Fatalf("durable user_version = %d, want concurrent value 3 preserved", got)
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
				if result != (storage.MigrationResult{Applied: 2, Current: 2}) {
					t.Fatalf("Migrate() result = %#v, want proven migration", result)
				}
				if got := server.userVersionValue(); got != 2 {
					t.Fatalf("durable user_version = %d, want 2", got)
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
			if freshResult != (storage.MigrationResult{Applied: 1, Current: 2}) {
				t.Fatalf("fresh Migrate() result = %#v, want marker repair and migration 2", freshResult)
			}
			if got := server.sequenceCount(); got != 2 {
				t.Fatalf("migration sequences after fresh reconciliation = %d, want only migration 2 after no schema replay", got)
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
	if result != (storage.MigrationResult{Current: 2}) {
		t.Fatalf("Migrate() result = %#v, want current migration 2", result)
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
	if result != (storage.MigrationResult{Applied: 2, Current: 2}) {
		t.Fatalf("fresh Migrate() result = %#v, want atomic reconciliation", result)
	}
	if got := server.sequenceCount(); got != 3 {
		t.Fatalf("sequence requests across explicit invocations = %d, want 3", got)
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
			wantFresh := storage.MigrationResult{Applied: 2, Current: 2}
			wantSequences := 3
			if tt.wantDurable {
				wantFresh = storage.MigrationResult{Applied: 1, Current: 2}
				wantSequences = 2
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
	if freshResult != (storage.MigrationResult{Applied: 2, Current: 2}) {
		t.Fatalf("fresh Migrate() result = %#v, want two applied migrations", freshResult)
	}
	if got := server.sequenceCount(); got != 3 {
		t.Fatalf("migration sequences after fresh reconciliation = %d, want 3", got)
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
	if result != (storage.MigrationResult{Current: 2}) {
		t.Fatalf("reconciliation result = %#v, want current migration 2", result)
	}
	if got := server.sequenceCount(); got != 3 {
		t.Fatalf("sequence requests = %d, want two successful and one rejected sequence", got)
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

	testing              *testing.T
	mu                   sync.Mutex
	ledger               map[int]string
	pending              map[int]string
	userVersion          int
	pendingUserVersion   int
	inTxn                bool
	exists               bool
	pendingExists        bool
	pendingSecondSchema  bool
	pendingThirdSchema   bool
	drop                 bool
	dropBeforeCommit     bool
	headerOnlyCommit     bool
	headerOnlyRollback   bool
	headerOnlyBegin      bool
	headerOnlyMigration  bool
	malformedSequence    bool
	omitSequenceResult   bool
	malformedAutocommit  bool
	omitSequencePayload  bool
	wrongSequencePayload bool
	falseAutocommit      bool
	holdTransaction      bool
	terminalMalformed    bool
	terminalOmitResult   bool
	terminalBadAuto      bool
	terminalFalseAuto    bool
	terminalOmitPayload  bool
	terminalWrongPayload bool
	terminalSkipMarker   bool
	ignoredRollbacks     int
	ignoredCloses        int
	failSQL              string
	failSQLSkip          int
	ledgerRowsOverride   [][]any
	stallSQL             string
	stallStarted         chan struct{}
	stallRelease         chan struct{}
	stallFinished        chan struct{}
	beforeSequenceStart  chan struct{}
	beforeSequenceAllow  chan struct{}
	beforeTerminalStart  chan struct{}
	beforeTerminalAllow  chan struct{}
	secondSchema         bool
	thirdSchema          bool
	accounts             map[string]string
	cursors              map[string]string
	persistenceMode      string
	persistenceStatement string
	persistenceStarted   chan struct{}
	persistenceRelease   chan struct{}
	persistenceRows      map[string][][]any
	persistenceColumns   map[string][]any
	nextCursorBaseURL    string
	nextCursorBaton      int
	closedCursorAt       map[string]int
	closedCursorCount    map[string]int
	records              []migrationRequest
	pipelineRecords      []migrationPipelineRequest
}

type migrationRequest struct {
	baton         *string
	sql           string
	args          []protocolValue
	namedArgCount int
	wantRows      bool
}

type migrationPipelineRequest struct {
	baton    *string
	requests []migrationStreamRequest
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
	server := &migrationProtocolServer{
		testing:            t,
		ledger:             make(map[int]string),
		accounts:           make(map[string]string),
		cursors:            make(map[string]string),
		persistenceRows:    make(map[string][][]any),
		persistenceColumns: make(map[string][]any),
		closedCursorAt:     make(map[string]int),
		closedCursorCount:  make(map[string]int),
	}
	server.Server = httptest.NewServer(http.HandlerFunc(server.serveHTTP))
	t.Cleanup(server.Close)
	return server
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
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
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
	if s.persistenceStatement == statement.SQL && s.persistenceStarted != nil {
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
	if s.persistenceStatement == statement.SQL {
		persistenceMode = s.persistenceMode
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
		if _, ok := s.accounts[accountID]; !ok {
			return nil, 0, false
		}
		current, exists := s.cursors[accountID]
		expected := parseProtocolValue(args[4])
		if !exists && expected == "" {
			s.cursors[accountID] = next
			return nil, 1, false
		}
		if exists && expected == current && historyTextLess(current, next) {
			s.cursors[accountID] = next
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
	s.stallSequenceStage("sequence", beginImmediateSQL)
	if s.failSequenceStage(beginImmediateSQL) {
		s.mu.Unlock()
		s.writeSequenceResponse(w, false, true)
		return
	}
	migrationNumber := 0
	switch {
	case strings.Contains(sequence, expectedMigrationSQL):
		migrationNumber = 1
	case strings.Contains(sequence, expectedAccountMigrationSQL):
		migrationNumber = 2
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
	s.inTxn = false
	s.pending = nil
	s.pendingExists = false
	s.pendingUserVersion = 0
	s.pendingSecondSchema = false
	s.pendingThirdSchema = false
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
	s.secondSchema = true
	s.userVersion = 2
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
	if !s.exists || s.ledger[1] != expectedMigrationChecksum || s.ledger[2] != expectedAccountMigrationChecksum {
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
	if len(s.pipelineRecords) != 4 {
		t.Fatalf("pipeline request shape = %#v, want two apply and terminal sequence pairs", s.pipelineRecords)
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
	if len(s.records) != 8 || s.records[0].baton != nil {
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
}

func (s *migrationProtocolServer) seedCursor(accountID, historyID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cursors[accountID] = historyID
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

func (s *migrationProtocolServer) persistenceRecords() []migrationRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := make([]migrationRequest, 0, len(s.records))
	for _, record := range s.records {
		if record.sql == accountLookupSQL || record.sql == accountInsertSQL || record.sql == cursorLookupSQL || record.sql == cursorCommitSQL {
			records = append(records, record)
		}
	}
	return records
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

func (s *migrationProtocolServer) cursorSessionCloseCount(baton string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closedCursorCount[baton]
}
