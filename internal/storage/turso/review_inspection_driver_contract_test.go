package turso

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
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
	secondAccountID, err := storage.ParseAccountID("0000000000000000000000000000000b")
	if err != nil {
		t.Fatal(err)
	}
	outsideAccountID, err := storage.ParseAccountID("0000000000000000000000000000000c")
	if err != nil {
		t.Fatal(err)
	}
	after, err := storage.NewReviewCursorKey(accountID, "before-thread", "before-message")
	if err != nil {
		t.Fatal(err)
	}
	query, err := storage.NewReviewCandidateQuery([]storage.AccountID{accountID, secondAccountID}, storage.ReviewUrgencyUrgent, 10, after, storage.MaximumReviewSourceRows)
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
	outsideMessage, err := mail.Normalize(outsideAccountID.String(), mail.MessageInput{GmailMessageID: "message", GmailThreadID: "thread", InternalDateMS: 42, SenderAddress: "sender@example.test", To: []string{"owner@example.test"}, Subject: "Subject", Labels: []string{"INBOX"}})
	if err != nil {
		t.Fatal(err)
	}
	outsideClassification, err := gate.Classify(outsideMessage, config.Defaults().Gate)
	if err != nil {
		t.Fatal(err)
	}
	outsideDecision, err := storage.NewGateDecision(outsideClassification, 43)
	if err != nil {
		t.Fatal(err)
	}
	cursorMessage, err := mail.Normalize(accountID.String(), mail.MessageInput{GmailMessageID: "before-message", GmailThreadID: "before-thread", InternalDateMS: 42, SenderAddress: "sender@example.test", To: []string{"owner@example.test"}, Subject: "Subject", Labels: []string{"INBOX"}})
	if err != nil {
		t.Fatal(err)
	}
	cursorClassification, err := gate.Classify(cursorMessage, config.Defaults().Gate)
	if err != nil {
		t.Fatal(err)
	}
	cursorDecision, err := storage.NewGateDecision(cursorClassification, 43)
	if err != nil {
		t.Fatal(err)
	}
	differentReasonMessage, err := mail.Normalize(accountID.String(), mail.MessageInput{GmailMessageID: "different-message", GmailThreadID: "thread", InternalDateMS: 42, SenderAddress: "sender@example.test", To: []string{"owner@example.test"}, Subject: "Subject", Labels: []string{"INBOX"}})
	if err != nil {
		t.Fatal(err)
	}
	differentReasonClassification, err := gate.Classify(differentReasonMessage, reasonPolicy)
	if err != nil {
		t.Fatal(err)
	}
	differentReasonDecision, err := storage.NewGateDecision(differentReasonClassification, 44)
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
		if call == 1 {
			wantArgs := []protocolValue{integerProtocolValue(2), textProtocolValue(accountID.String()), textProtocolValue(secondAccountID.String())}
			for len(wantArgs) < 17 {
				wantArgs = append(wantArgs, textProtocolValue(""))
			}
			wantArgs = append(wantArgs,
				textProtocolValue("urgent"), textProtocolValue("urgent"), textProtocolValue("urgent"),
				integerProtocolValue(1), textProtocolValue(accountID.String()), textProtocolValue("before-thread"), textProtocolValue("before-message"),
				integerProtocolValue(101),
			)
			if statement.SQL != expectedReviewCandidateSelectSQL || !reflect.DeepEqual(statement.Args, wantArgs) {
				t.Errorf("candidate statement or typed args differ from independent fixed contract")
			}
		}
		if call == 2 {
			wantArgs := []protocolValue{textProtocolValue("message"), textProtocolValue(accountID.String())}
			if statement.SQL != expectedCurrentGateInspectionSelectSQL || !reflect.DeepEqual(statement.Args, wantArgs) {
				t.Errorf("reason statement or typed args differ from independent fixed contract")
			}
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
		selectedMessage := message
		selectedDecision := decision
		if call == 2 {
			selectedDecision = reasonDecision
		} else if call == 3 {
			selectedMessage = outsideMessage
			selectedDecision = outsideDecision
		} else if call == 4 {
			selectedMessage = cursorMessage
			selectedDecision = cursorDecision
		} else if call == 5 {
			selectedMessage = differentReasonMessage
			selectedDecision = differentReasonDecision
		}
		row := []any{
			textProtocolValue(selectedMessage.AccountID()), textProtocolValue(selectedMessage.GmailMessageID()), textProtocolValue(selectedMessage.GmailThreadID()), integerProtocolValue(int(selectedMessage.MetadataVersion())),
			textProtocolValue(string(selectedMessage.CanonicalJSON())), textProtocolValue(selectedMessage.MetadataHash()), integerProtocolValue(int(selectedDecision.Version())), textProtocolValue(selectedDecision.SourceMetadataHash()),
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
	if rows, err := handle.ListReviewCandidates(context.Background(), query); !errors.Is(err, storage.ErrPersistenceInspect) || rows != nil {
		t.Fatalf("outside-selector exact-driver rows=%#v error=%v", rows, err)
	}
	if rows, err := handle.ListReviewCandidates(context.Background(), query); !errors.Is(err, storage.ErrPersistenceInspect) || rows != nil {
		t.Fatalf("nonexclusive-cursor exact-driver rows=%#v error=%v", rows, err)
	}
	if inspection, err := handle.GetCurrentGateInspection(context.Background(), accountID, message.GmailMessageID()); !errors.Is(err, storage.ErrPersistenceInspect) || !reflect.DeepEqual(inspection, storage.CurrentGateInspection{}) {
		t.Fatalf("mismatched-reason exact-driver inspection=%#v error=%v", inspection, err)
	}
	if cursorCalls.Load() != 5 {
		t.Fatalf("exact-driver cursor calls = %d", cursorCalls.Load())
	}
}

func TestReviewInspectionReadsFailClosedWithoutRetryOnProtocolFailures(t *testing.T) {
	accountID, err := storage.ParseAccountID("0000000000000000000000000000000a")
	if err != nil {
		t.Fatal(err)
	}
	query, err := storage.NewReviewCandidateQuery([]storage.AccountID{accountID}, storage.ReviewUrgencyAll, 10, storage.ReviewCursorKey{}, storage.MaximumReviewSourceRows)
	if err != nil {
		t.Fatal(err)
	}
	for _, read := range []string{"list", "reason"} {
		for _, failure := range []string{"status", "drop", "malformed"} {
			t.Run(read+"/"+failure, func(t *testing.T) {
				var cursorCalls atomic.Int64
				server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
					if request.Header.Get("Authorization") != "" {
						t.Error("credential-free review read carried authorization")
					}
					switch request.URL.Path {
					case "/v3/cursor":
						cursorCalls.Add(1)
						switch failure {
						case "status":
							http.Error(response, "synthetic upstream detail", http.StatusServiceUnavailable)
						case "drop":
							connection, _, hijackErr := response.(http.Hijacker).Hijack()
							if hijackErr != nil {
								t.Errorf("hijack: %v", hijackErr)
								return
							}
							_ = connection.Close()
						case "malformed":
							response.Header().Set("Content-Type", "application/json")
							_, _ = response.Write([]byte("{malformed"))
						}
					case "/v3/pipeline":
						response.Header().Set("Content-Type", "application/json")
						_ = json.NewEncoder(response).Encode(map[string]any{"baton": nil, "base_url": nil, "results": []any{map[string]any{"type": "ok", "response": map[string]any{"type": "close"}}}})
					default:
						http.NotFound(response, request)
					}
				}))
				adapter, adapterErr := New(Options{PersistenceTimeout: time.Second})
				if adapterErr != nil {
					server.Close()
					t.Fatal(adapterErr)
				}
				handle, openErr := adapter.Open(context.Background(), storage.Endpoint{URL: server.URL})
				if openErr != nil {
					server.Close()
					t.Fatal(openErr)
				}
				if read == "list" {
					rows, readErr := handle.ListReviewCandidates(context.Background(), query)
					if !errors.Is(readErr, storage.ErrPersistenceInspect) || rows != nil {
						t.Errorf("ListReviewCandidates() = %#v, %v", rows, readErr)
					}
				} else {
					inspection, readErr := handle.GetCurrentGateInspection(context.Background(), accountID, "message")
					if !errors.Is(readErr, storage.ErrPersistenceInspect) || !reflect.DeepEqual(inspection, storage.CurrentGateInspection{}) {
						t.Errorf("GetCurrentGateInspection() = %#v, %v", inspection, readErr)
					}
				}
				if cursorCalls.Load() != 1 {
					t.Errorf("cursor calls = %d, want one", cursorCalls.Load())
				}
				_ = handle.Close()
				server.Close()
			})
		}
	}
}
