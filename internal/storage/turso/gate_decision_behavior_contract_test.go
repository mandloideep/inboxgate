package turso

import (
	"context"
	"errors"
	"testing"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/gate"
	"github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
	storagefake "github.com/mandloideep/inboxgate/internal/storage/fake"
)

func TestGateDecisionBehaviorContractAcrossFakeAndExactDriver(t *testing.T) {
	for _, implementation := range []struct {
		name string
		open func(*testing.T) storage.Handle
	}{
		{name: "fake", open: func(*testing.T) storage.Handle { return storagefake.New() }},
		{name: "exact-driver", open: func(t *testing.T) storage.Handle {
			return openPersistenceContractHandle(t, newMigrationProtocolServer(t).URL)
		}},
	} {
		t.Run(implementation.name, func(t *testing.T) {
			handle := implementation.open(t)
			accountID, message := prepareGateDecisionBehaviorFixture(t, handle)
			runGateDecisionBehaviorContract(t, handle, accountID, message)
		})
	}
}

func prepareGateDecisionBehaviorFixture(t *testing.T, handle storage.Handle) (storage.AccountID, mail.Message) {
	t.Helper()
	accountID := persistenceAccountID(t, "1234567890abcdef1234567890abcdef")
	account, err := handle.EnsureAccount(context.Background(), persistenceSeed(t, accountID.String(), "gate-behavior-subject"))
	if err != nil {
		t.Fatal(err)
	}
	history100 := persistenceHistoryID(t, "100")
	if err := handle.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: account.ID, Next: history100}); err != nil {
		t.Fatal(err)
	}
	envelope := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 32, 91))
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: account.ID, Next: envelope}); err != nil {
		t.Fatal(err)
	}
	pending, err := handle.GetAccountLifecycle(context.Background(), account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{
		AccountID: account.ID, ExpectedState: pending.State, ExpectedVersion: pending.Version,
		ExpectedRevocationStatus: pending.RevocationStatus, NextState: storage.AccountStateActive, RevocationStatus: storage.RevocationStatusNone,
	}); err != nil {
		t.Fatal(err)
	}
	message, err := mail.Normalize(account.ID.String(), mail.MessageInput{
		GmailMessageID: "behavior-message", GmailThreadID: "behavior-thread", InternalDateMS: 1234,
		Subject: "synthetic behavior", To: []string{"owner@example.test"}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	history101 := persistenceHistoryID(t, "101")
	if err := handle.CommitCurrentDiscovery(context.Background(), storage.CurrentDiscoveryCommit{AccountID: account.ID, Expected: history100, Next: history101, Messages: []mail.Message{message}}); err != nil {
		t.Fatal(err)
	}
	return account.ID, message
}

func runGateDecisionBehaviorContract(t *testing.T, handle storage.Handle, accountID storage.AccountID, message mail.Message) {
	t.Helper()
	ctx := context.Background()
	if _, err := handle.GetGateDecision(ctx, accountID, message.GmailMessageID()); !errors.Is(err, storage.ErrGateDecisionNotFound) {
		t.Fatalf("missing decision error = %v", err)
	}
	first := behaviorGateDecision(t, message, config.Defaults().Gate, 1000)
	if err := handle.CommitGateDecision(ctx, storage.GateDecisionCommit{Source: message, Next: first}); err != nil {
		t.Fatalf("insert error = %v", err)
	}
	exactRetry := behaviorGateDecision(t, message, config.Defaults().Gate, 2000)
	if err := handle.CommitGateDecision(ctx, storage.GateDecisionCommit{Source: message, Next: exactRetry}); err != nil {
		t.Fatalf("exact idempotency error = %v", err)
	}
	state, err := handle.GetGateDecision(ctx, accountID, message.GmailMessageID())
	if err != nil || !state.Current || !state.Decision.Equal(first) {
		t.Fatalf("durable exact decision = (%#v, %v)", state, err)
	}

	changedPolicy := config.Defaults().Gate
	changedPolicy.DirectRecipientIsCandidate = false
	second := behaviorGateDecision(t, message, changedPolicy, 2000)
	if err := handle.CommitGateDecision(ctx, storage.GateDecisionCommit{Source: message, Next: second}); !errors.Is(err, storage.ErrGateDecisionConflict) {
		t.Fatalf("blind replacement error = %v", err)
	}
	expected := first.Revision()
	if err := handle.CommitGateDecision(ctx, storage.GateDecisionCommit{Source: message, Expected: &expected, Next: second}); err != nil {
		t.Fatalf("exact expected replacement error = %v", err)
	}
	conflictingClassification, err := gate.DecodeClassification(second.Version(), second.SourceMetadataHash(), second.InputHash(), gate.OutcomeIgnore, []gate.ReasonCode{gate.ReasonExcludedLabel})
	if err != nil {
		t.Fatal(err)
	}
	conflicting, err := storage.NewGateDecision(conflictingClassification, second.EvaluatedAtUnixMS())
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.CommitGateDecision(ctx, storage.GateDecisionCommit{Source: message, Next: conflicting}); !errors.Is(err, storage.ErrGateDecisionConflict) {
		t.Fatalf("same-input different-semantics error = %v", err)
	}

	changed, err := mail.Normalize(accountID.String(), mail.MessageInput{
		GmailMessageID: message.GmailMessageID(), GmailThreadID: message.GmailThreadID(), InternalDateMS: 1234,
		Subject: "synthetic behavior changed", To: []string{"owner@example.test"}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	history101 := persistenceHistoryID(t, "101")
	history102 := persistenceHistoryID(t, "102")
	if err := handle.CommitCurrentDiscovery(ctx, storage.CurrentDiscoveryCommit{AccountID: accountID, Expected: history101, Next: history102, Messages: []mail.Message{changed}}); err != nil {
		t.Fatal(err)
	}
	state, err = handle.GetGateDecision(ctx, accountID, message.GmailMessageID())
	if err != nil || state.Current {
		t.Fatalf("stale decision state = (%#v, %v)", state, err)
	}
	third := behaviorGateDecision(t, changed, config.Defaults().Gate, 3000)
	expected = second.Revision()
	if err := handle.CommitGateDecision(ctx, storage.GateDecisionCommit{Source: message, Expected: &expected, Next: third}); !errors.Is(err, storage.ErrGateDecisionStaleSource) {
		t.Fatalf("stale-source CAS error = %v", err)
	}
	if err := handle.CommitGateDecision(ctx, storage.GateDecisionCommit{Source: changed, Expected: &expected, Next: third}); err != nil {
		t.Fatalf("current-source CAS error = %v", err)
	}
}

func behaviorGateDecision(t *testing.T, message mail.Message, policy config.Gate, timestamp int64) storage.GateDecision {
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
