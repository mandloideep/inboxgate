package turso

import (
	"strings"
	"testing"
)

func TestReviewInspectionSQLIsFixedParameterizedAndNarrow(t *testing.T) {
	for name, statement := range map[string]string{
		"candidates": reviewCandidateSelectSQL,
		"reason":     currentGateInspectionSelectSQL,
	} {
		if strings.Contains(statement, "%") || strings.Contains(statement, "+") || strings.Contains(statement, "||") {
			t.Errorf("%s SQL permits construction: %q", name, statement)
		}
		for _, forbidden := range []string{"inboxgate_candidate_content", "json_", " OFFSET ", " TEMP ", "INSERT ", "UPDATE ", "DELETE ", "PRAGMA ", ";"} {
			if strings.Contains(strings.ToUpper(statement), strings.ToUpper(forbidden)) {
				t.Errorf("%s SQL contains %q", name, forbidden)
			}
		}
		if !strings.Contains(statement, "inboxgate_accounts") || !strings.Contains(statement, "inboxgate_account_lifecycle") || !strings.Contains(statement, "inboxgate_messages") || !strings.Contains(statement, "inboxgate_gate_decisions") {
			t.Errorf("%s SQL misses an authority or currentness join", name)
		}
	}
	if strings.Count(reviewCandidateSelectSQL, "account_id = ?") != 16 || !strings.Contains(reviewCandidateSelectSQL, "LIMIT ?") || !strings.Contains(reviewCandidateSelectSQL, "COLLATE BINARY") {
		t.Fatalf("candidate SQL lacks fixed 16-slot selector, bound limit, or bytewise ordering: %q", reviewCandidateSelectSQL)
	}
	if strings.Contains(reviewCandidateSelectSQL, "LIMIT 101") {
		t.Fatal("candidate limit must be a fixed parameter value, not rendered SQL")
	}
	if strings.Count(currentGateInspectionSelectSQL, "?") != 2 {
		t.Fatalf("reason SQL parameters = %d, want account and message", strings.Count(currentGateInspectionSelectSQL, "?"))
	}
}

func TestReviewInspectionSourceMethodsRejectRemoteCredentialedAndMalformedRows(t *testing.T) {
	compileReviewInspectionExactDriverContract(t)
}
