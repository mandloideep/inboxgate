package turso

import (
	"strings"
	"testing"
)

const expectedReviewCandidateSelectSQL = "SELECT messages.account_id, messages.gmail_message_id, messages.gmail_thread_id, messages.metadata_version, messages.metadata_json, messages.metadata_hash, decisions.gate_version, decisions.source_metadata_hash, decisions.input_hash, decisions.outcome, decisions.reason_codes, decisions.evaluated_at_unix_ms FROM inboxgate_accounts AS accounts JOIN inboxgate_account_lifecycle AS lifecycle ON lifecycle.account_id = accounts.account_id AND lifecycle.state = 'active' JOIN inboxgate_messages AS messages ON messages.account_id = accounts.account_id JOIN inboxgate_gate_decisions AS decisions ON decisions.record_id = messages.record_id AND decisions.source_metadata_hash = messages.metadata_hash WHERE (? = 0 OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ?) AND decisions.outcome IN ('review_candidate', 'urgent_review_candidate') AND (? = 'all' OR (? = 'standard' AND decisions.outcome = 'review_candidate') OR (? = 'urgent' AND decisions.outcome = 'urgent_review_candidate')) AND (? = 0 OR (messages.account_id COLLATE BINARY, messages.gmail_thread_id COLLATE BINARY, messages.gmail_message_id COLLATE BINARY) > (?, ?, ?)) ORDER BY messages.account_id COLLATE BINARY, messages.gmail_thread_id COLLATE BINARY, messages.gmail_message_id COLLATE BINARY LIMIT ?"

const expectedCurrentGateInspectionSelectSQL = "SELECT messages.account_id, messages.gmail_message_id, messages.gmail_thread_id, messages.metadata_version, messages.metadata_json, messages.metadata_hash, decisions.gate_version, decisions.source_metadata_hash, decisions.input_hash, decisions.outcome, decisions.reason_codes, decisions.evaluated_at_unix_ms FROM inboxgate_accounts AS accounts JOIN inboxgate_account_lifecycle AS lifecycle ON lifecycle.account_id = accounts.account_id AND lifecycle.state = 'active' JOIN inboxgate_messages AS messages ON messages.account_id = accounts.account_id AND messages.gmail_message_id = ? JOIN inboxgate_gate_decisions AS decisions ON decisions.record_id = messages.record_id AND decisions.source_metadata_hash = messages.metadata_hash WHERE accounts.account_id = ? LIMIT 2"

func TestReviewInspectionSQLIsFixedParameterizedAndNarrow(t *testing.T) {
	if reviewCandidateSelectSQL != expectedReviewCandidateSelectSQL {
		t.Fatal("candidate SQL differs from independent fixed literal")
	}
	if currentGateInspectionSelectSQL != expectedCurrentGateInspectionSelectSQL {
		t.Fatal("reason SQL differs from independent fixed literal")
	}
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
