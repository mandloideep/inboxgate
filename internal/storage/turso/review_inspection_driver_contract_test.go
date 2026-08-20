package turso

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/gate"
	"github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
)

func compileReviewInspectionExactDriverContract(t *testing.T) {
	t.Helper()
	accountID, err := storage.ParseAccountID("0000000000000000000000000000000a")
	if err != nil {
		t.Fatal(err)
	}
	query, err := storage.NewReviewCandidateQuery([]storage.AccountID{accountID}, storage.ReviewUrgencyAll, 10, storage.ReviewCursorKey{}, storage.MaximumReviewSourceRows)
	if err != nil {
		t.Fatal(err)
	}
	remote := &handle{migrationAllowed: false}
	if _, err := remote.ListReviewCandidates(context.Background(), query); !errors.Is(err, storage.ErrPersistenceNotAllowed) {
		t.Fatalf("credentialed remote list error = %v", err)
	}
	if _, err := remote.GetCurrentGateInspection(context.Background(), accountID, "message"); !errors.Is(err, storage.ErrPersistenceNotAllowed) {
		t.Fatalf("credentialed remote reason error = %v", err)
	}
	message, err := mail.Normalize(accountID.String(), mail.MessageInput{GmailMessageID: "message", GmailThreadID: "thread", InternalDateMS: 42, SenderAddress: "sender@example.test", To: []string{"owner@example.test"}, Subject: "Subject", Labels: []string{"INBOX"}})
	if err != nil {
		t.Fatal(err)
	}
	reasonPolicy := config.Defaults().Gate
	reasonPolicy.ExcludedLabels = []string{"INBOX"}
	reasonClassification, err := gate.Classify(message, reasonPolicy)
	if err != nil {
		t.Fatal(err)
	}
	reasonDecision, err := storage.NewGateDecision(reasonClassification, 44)
	if err != nil {
		t.Fatal(err)
	}
	classification, err := gate.Classify(message, config.Defaults().Gate)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := storage.NewGateDecision(classification, 43)
	if err != nil {
		t.Fatal(err)
	}
	var cursorCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" {
			t.Error("credential-free review read carried authorization")
		}
		if request.URL.Path == "/v3/pipeline" {
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(map[string]any{"baton": nil, "base_url": nil, "results": []any{map[string]any{"type": "ok", "response": map[string]any{"type": "close"}}}})
			return
		}
		if request.URL.Path != "/v3/cursor" {
			http.NotFound(response, request)
			return
		}
		var input protocolCursorRequest
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil || len(input.Batch.Steps) == 0 {
			t.Errorf("decode review cursor request: %v", err)
			http.Error(response, "invalid", http.StatusBadRequest)
			return
		}
		statement := input.Batch.Steps[0].Stmt
		call := cursorCalls.Add(1)
		if call == 1 && (statement.SQL != reviewCandidateSelectSQL || len(statement.Args) != 25) {
			t.Errorf("candidate statement=%q args=%d", statement.SQL, len(statement.Args))
		}
		if call == 2 && (statement.SQL != currentGateInspectionSelectSQL || len(statement.Args) != 2) {
			t.Errorf("reason statement=%q args=%d", statement.SQL, len(statement.Args))
		}
		response.Header().Set("Content-Type", "application/json")
		encoder := json.NewEncoder(response)
		_ = encoder.Encode(map[string]any{"baton": "review-baton", "base_url": nil})
		columns := []any{
			map[string]any{"name": "account_id", "decltype": "TEXT"}, map[string]any{"name": "gmail_message_id", "decltype": "TEXT"},
			map[string]any{"name": "gmail_thread_id", "decltype": "TEXT"}, map[string]any{"name": "metadata_version", "decltype": "INTEGER"},
			map[string]any{"name": "metadata_json", "decltype": "TEXT"}, map[string]any{"name": "metadata_hash", "decltype": "TEXT"},
			map[string]any{"name": "gate_version", "decltype": "INTEGER"}, map[string]any{"name": "source_metadata_hash", "decltype": "TEXT"},
			map[string]any{"name": "input_hash", "decltype": "TEXT"}, map[string]any{"name": "outcome", "decltype": "TEXT"},
			map[string]any{"name": "reason_codes", "decltype": "TEXT"}, map[string]any{"name": "evaluated_at_unix_ms", "decltype": "INTEGER"},
		}
		_ = encoder.Encode(map[string]any{"type": "step_begin", "step": 0, "cols": columns})
		storedAccount := accountID.String()
		if call == 3 {
			storedAccount = "malformed-account"
		}
		selectedDecision := decision
		if call == 2 {
			selectedDecision = reasonDecision
		}
		row := []any{
			textProtocolValue(storedAccount), textProtocolValue(message.GmailMessageID()), textProtocolValue(message.GmailThreadID()), integerProtocolValue(int(message.MetadataVersion())),
			textProtocolValue(string(message.CanonicalJSON())), textProtocolValue(message.MetadataHash()), integerProtocolValue(int(selectedDecision.Version())), textProtocolValue(selectedDecision.SourceMetadataHash()),
			textProtocolValue(selectedDecision.InputHash()), textProtocolValue(selectedDecision.Outcome().String()), textProtocolValue(selectedDecision.ReasonJSON()), integerProtocolValue(int(selectedDecision.EvaluatedAtUnixMS())),
		}
		_ = encoder.Encode(map[string]any{"type": "row", "row": row})
		_ = encoder.Encode(map[string]any{"type": "step_end", "step": 0, "affected_row_count": 0})
		_ = encoder.Encode(map[string]any{"type": "step_begin", "step": 1, "cols": []any{}})
		_ = encoder.Encode(map[string]any{"type": "step_end", "step": 1})
	}))
	t.Cleanup(server.Close)
	adapter, err := New(Options{PersistenceTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	handle, err := adapter.Open(context.Background(), storage.Endpoint{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	rows, err := handle.ListReviewCandidates(context.Background(), query)
	if err != nil || len(rows) != 1 || !rows[0].Valid() {
		t.Fatalf("exact-driver candidates=%#v error=%v", rows, err)
	}
	inspection, err := handle.GetCurrentGateInspection(context.Background(), accountID, message.GmailMessageID())
	if err != nil || !inspection.Valid() || inspection.Decision.Outcome() != gate.OutcomeIgnore {
		t.Fatalf("exact-driver inspection=%#v error=%v", inspection, err)
	}
	if _, err := handle.ListReviewCandidates(context.Background(), query); !errors.Is(err, storage.ErrPersistenceInspect) {
		t.Fatalf("malformed exact-driver row error = %v", err)
	}
	if cursorCalls.Load() != 3 {
		t.Fatalf("exact-driver cursor calls = %d", cursorCalls.Load())
	}
}
