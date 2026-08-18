package fake

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/gate"
	"github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
)

func activeGateStore(t *testing.T) (*Store, storage.AccountID, mail.Message) {
	t.Helper()
	store, discovery := activeDiscoveryStore(t)
	if err := store.CommitCurrentDiscovery(context.Background(), discovery); err != nil {
		t.Fatal(err)
	}
	return store, discovery.AccountID, discovery.Messages[0]
}

func gateDecisionFor(t *testing.T, message mail.Message, policy config.Gate, timestamp int64) storage.GateDecision {
	t.Helper()
	classification, err := gate.Classify(message, policy)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := storage.NewGateDecision(classification, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

func TestGateDecisionMissingInsertIdempotencyAndDefensiveRead(t *testing.T) {
	store, accountID, message := activeGateStore(t)
	if _, err := store.GetGateDecision(context.Background(), accountID, message.GmailMessageID()); !errors.Is(err, storage.ErrGateDecisionNotFound) {
		t.Fatalf("missing error = %v", err)
	}
	decision := gateDecisionFor(t, message, config.Defaults().Gate, 1000)
	commit := storage.GateDecisionCommit{Source: message, Next: decision}
	if err := store.CommitGateDecision(context.Background(), commit); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: message, Next: gateDecisionFor(t, message, config.Defaults().Gate, 2000)}); err != nil {
		t.Fatalf("exact retry error = %v", err)
	}
	state, err := store.GetGateDecision(context.Background(), accountID, message.GmailMessageID())
	if err != nil || !state.Current || state.Decision.EvaluatedAtUnixMS() != 1000 || !state.Decision.Equal(decision) {
		t.Fatalf("state = %#v, %v", state, err)
	}
}

func TestGateDecisionRejectsBlindReplacementAndExpectedRevisionConflict(t *testing.T) {
	store, _, message := activeGateStore(t)
	firstPolicy := config.Defaults().Gate
	first := gateDecisionFor(t, message, firstPolicy, 1000)
	if err := store.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: message, Next: first}); err != nil {
		t.Fatal(err)
	}
	secondPolicy := firstPolicy
	secondPolicy.DirectRecipientIsCandidate = false
	second := gateDecisionFor(t, message, secondPolicy, 2000)
	if err := store.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: message, Next: second}); !errors.Is(err, storage.ErrGateDecisionConflict) {
		t.Fatalf("blind replacement error = %v", err)
	}
	wrong := second.Revision()
	if err := store.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: message, Expected: &wrong, Next: second}); !errors.Is(err, storage.ErrGateDecisionConflict) {
		t.Fatalf("expected revision error = %v", err)
	}
	expected := first.Revision()
	if err := store.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: message, Expected: &expected, Next: second}); err != nil {
		t.Fatalf("compare-and-swap replacement error = %v", err)
	}
}

func TestGateDecisionRejectsSameInputIdentityWithDifferentSemantics(t *testing.T) {
	store, _, message := activeGateStore(t)
	first := gateDecisionFor(t, message, config.Defaults().Gate, 1000)
	if err := store.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: message, Next: first}); err != nil {
		t.Fatal(err)
	}
	conflictingClassification, err := gate.DecodeClassification(first.Version(), first.SourceMetadataHash(), first.InputHash(), gate.OutcomeIgnore, []gate.ReasonCode{gate.ReasonExcludedLabel})
	if err != nil {
		t.Fatal(err)
	}
	conflicting, err := storage.NewGateDecision(conflictingClassification, first.EvaluatedAtUnixMS())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: message, Next: conflicting}); !errors.Is(err, storage.ErrGateDecisionConflict) {
		t.Fatalf("conflicting semantic identity error = %v", err)
	}
}

func TestGateDecisionStaleSourceCanOnlyBeReplacedFromExactExpectedRevision(t *testing.T) {
	store, accountID, message := activeGateStore(t)
	first := gateDecisionFor(t, message, config.Defaults().Gate, 1000)
	if err := store.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: message, Next: first}); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	currentCursor := store.cursors[accountID]
	store.mu.Unlock()
	next, _ := storage.ParseHistoryID("102")
	changed, _ := mail.Normalize(accountID.String(), mail.MessageInput{GmailMessageID: message.GmailMessageID(), GmailThreadID: message.GmailThreadID(), Subject: "changed", To: []string{"owner@example.test"}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{}})
	if err := store.CommitCurrentDiscovery(context.Background(), storage.CurrentDiscoveryCommit{AccountID: accountID, Expected: currentCursor, Next: next, Messages: []mail.Message{changed}}); err != nil {
		t.Fatal(err)
	}
	state, err := store.GetGateDecision(context.Background(), accountID, message.GmailMessageID())
	if err != nil || state.Current {
		t.Fatalf("stale state = %#v, %v", state, err)
	}
	second := gateDecisionFor(t, changed, config.Defaults().Gate, 2000)
	if err := store.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: message, Expected: func() *storage.GateDecisionRevision { value := first.Revision(); return &value }(), Next: second}); !errors.Is(err, storage.ErrGateDecisionStaleSource) {
		t.Fatalf("old source error = %v", err)
	}
	expected := first.Revision()
	if err := store.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: changed, Expected: &expected, Next: second}); err != nil {
		t.Fatalf("stale replacement error = %v", err)
	}
}

func TestGateDecisionConcurrentExactAndDifferentRevisions(t *testing.T) {
	store, _, message := activeGateStore(t)
	exact := gateDecisionFor(t, message, config.Defaults().Gate, 1000)
	var wait sync.WaitGroup
	wait.Add(2)
	results := make(chan error, 2)
	for range 2 {
		go func() {
			defer wait.Done()
			results <- store.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: message, Next: exact})
		}()
	}
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent exact commit error = %v", err)
		}
	}

	store, _, message = activeGateStore(t)
	first := gateDecisionFor(t, message, config.Defaults().Gate, 1000)
	secondPolicy := config.Defaults().Gate
	secondPolicy.DirectRecipientIsCandidate = false
	second := gateDecisionFor(t, message, secondPolicy, 1001)
	wait.Add(2)
	results = make(chan error, 2)
	for _, decision := range []storage.GateDecision{first, second} {
		go func(value storage.GateDecision) {
			defer wait.Done()
			results <- store.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: message, Next: value})
		}(decision)
	}
	wait.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, storage.ErrGateDecisionConflict) {
			conflict++
		} else {
			t.Fatalf("unexpected error = %v", err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("success=%d conflict=%d", success, conflict)
	}
}

func TestGateDecisionMalformedStoredValueRequiresRecovery(t *testing.T) {
	store, accountID, message := activeGateStore(t)
	decision := gateDecisionFor(t, message, config.Defaults().Gate, 1000)
	if err := store.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: message, Next: decision}); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.decisions[message.RecordID()] = storage.GateDecision{}
	store.mu.Unlock()
	if _, err := store.GetGateDecision(context.Background(), accountID, message.GmailMessageID()); !errors.Is(err, storage.ErrGateDecisionRecoveryRequired) {
		t.Fatalf("malformed stored decision error = %v", err)
	}
}
