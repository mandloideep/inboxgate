package turso

import (
	"strings"
	"testing"
)

func TestGateDecisionSQLIsFixedParameterizedAndNarrow(t *testing.T) {
	if strings.Count(gateDecisionLookupSQL, "?") != 2 || strings.Count(gateDecisionCommitSQL, "?") != 12 {
		t.Fatalf("gate SQL placeholders lookup=%d commit=%d", strings.Count(gateDecisionLookupSQL, "?"), strings.Count(gateDecisionCommitSQL, "?"))
	}
	for _, statement := range []string{gateDecisionLookupSQL, gateDecisionCommitSQL} {
		if statement == "" || strings.Contains(statement, ";") || strings.Contains(statement, "BEGIN") || strings.Contains(statement, "COMMIT") || strings.Contains(statement, "json_") {
			t.Fatalf("gate statement is not one fixed JSON-independent statement: %q", statement)
		}
	}
	for _, required := range []string{
		"INSERT INTO inboxgate_gate_decisions",
		"JOIN inboxgate_messages",
		"messages.metadata_hash = input.source_metadata_hash",
		"input.expected_present = 0",
		"NOT EXISTS",
		"input.expected_present = 1",
		"gate_version = input.expected_version",
		"input_hash = input.expected_input_hash",
		"ON CONFLICT(record_id) DO UPDATE",
		"WHERE input.expected_present = 1",
	} {
		if !strings.Contains(gateDecisionCommitSQL, required) {
			t.Fatalf("gate mutation missing %q", required)
		}
	}
	if strings.Contains(gateDecisionCommitSQL, "DO UPDATE SET record_id") || strings.Contains(gateDecisionCommitSQL, "DELETE") {
		t.Fatal("gate mutation can replace identity or delete state")
	}
}
