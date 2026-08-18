package turso

import (
	"strings"
	"testing"

	"github.com/mandloideep/inboxgate/internal/storage"
)

func TestCurrentDiscoveryStageSQLHasExactFixedParameterizedShape(t *testing.T) {
	if strings.Count(currentDiscoveryStageSQL, "?") != storage.CurrentDiscoveryStageParameters {
		t.Fatalf("stage placeholders = %d, want %d", strings.Count(currentDiscoveryStageSQL, "?"), storage.CurrentDiscoveryStageParameters)
	}
	if strings.Count(currentDiscoveryStageSQL, "(?, ?, ?, ?, ?, ?, ?, ?)") != storage.CurrentDiscoveryStageChunkMessages {
		t.Fatalf("stage slots = %d, want %d", strings.Count(currentDiscoveryStageSQL, "(?, ?, ?, ?, ?, ?, ?, ?)"), storage.CurrentDiscoveryStageChunkMessages)
	}
	for _, required := range []string{
		"WITH input(account_id, attempt_id) AS (VALUES (?, ?))",
		"staged(present, ordinal, record_id, gmail_message_id, gmail_thread_id, metadata_version, metadata_json, metadata_hash)",
		"WHERE staged.present = 1",
		"state = 'open'",
		"ON CONFLICT (account_id, attempt_id, ordinal) DO NOTHING",
	} {
		if !strings.Contains(currentDiscoveryStageSQL, required) {
			t.Fatalf("stage SQL missing %q", required)
		}
	}
	if strings.Contains(currentDiscoveryStageSQL, "DO UPDATE") {
		t.Fatal("stage retry can rewrite immutable durable state")
	}
	if strings.Contains(currentDiscoveryStageSQL, "%!") || !strings.Contains(currentDiscoveryStageSQL, "printf('%08x'") {
		t.Fatal("stage SQL does not use its fixed schema-verifiable witness expression")
	}
}

func TestCurrentDiscoveryUsesOnlyFixedSingleStatementMutations(t *testing.T) {
	statements := []string{currentDiscoveryAttemptCreateSQL, currentDiscoveryStageSQL, currentDiscoverySealSQL, currentDiscoveryFinalizeSQL, currentDiscoveryAbortSQL}
	for _, statement := range statements {
		if statement == "" || strings.Contains(statement, ";") || strings.Contains(statement, "BEGIN") || strings.Contains(statement, "COMMIT") {
			t.Fatalf("unsafe current discovery statement %q", statement)
		}
	}
	if currentDiscoveryFinalizeSQL != "INSERT INTO inboxgate_current_sync_finalize (account_id, attempt_id, manifest_hash) VALUES (?, ?, ?)" {
		t.Fatalf("finalize SQL = %q", currentDiscoveryFinalizeSQL)
	}
	if currentDiscoveryAbortSQL != "INSERT INTO inboxgate_current_sync_abort (account_id, attempt_id) VALUES (?, ?)" {
		t.Fatalf("abort SQL = %q", currentDiscoveryAbortSQL)
	}
}

func TestCurrentDiscoveryAttemptCreationAndAbortCarryDatabaseAuthorityGuards(t *testing.T) {
	for _, required := range []string{
		"INSERT INTO inboxgate_current_sync_attempts",
		"SELECT input.account_id",
		"JOIN inboxgate_account_lifecycle",
		"lifecycle.state = 'active'",
		"JOIN inboxgate_synchronization_cursors",
		"cursors.history_id = input.expected_history_id",
	} {
		if !strings.Contains(currentDiscoveryAttemptCreateSQL, required) {
			t.Fatalf("attempt creation SQL missing %q", required)
		}
	}
}
