package gateeval

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/cryptobox"
	"github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
	"github.com/mandloideep/inboxgate/internal/storage/fake"
)

func evaluatorStore(t *testing.T) (*fake.Store, storage.AccountID, mail.Message) {
	t.Helper()
	store := fake.New()
	accountID, _ := storage.ParseAccountID("00112233445566778899aabbccddeeff")
	subject, _ := storage.ParseProviderSubject("synthetic-subject")
	if _, err := store.EnsureAccount(context.Background(), storage.AccountSeed{ID: accountID, ProviderSubject: subject}); err != nil {
		t.Fatal(err)
	}
	expected, _ := storage.ParseHistoryID("100")
	next, _ := storage.ParseHistoryID("101")
	if err := store.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: accountID, Next: expected}); err != nil {
		t.Fatal(err)
	}
	ring, err := cryptobox.ParseKeyring([]byte("igk1:k=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	if err != nil {
		t.Fatal(err)
	}
	defer ring.Close()
	envelopeText, err := ring.EncryptRefreshToken(accountID.String(), []byte("synthetic-refresh-material"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := storage.ParseCredentialEnvelope(envelopeText)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: accountID, Next: envelope}); err != nil {
		t.Fatal(err)
	}
	lifecycle, _ := store.GetAccountLifecycle(context.Background(), accountID)
	if err := store.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{
		AccountID: accountID, ExpectedState: lifecycle.State, ExpectedVersion: lifecycle.Version,
		ExpectedRevocationStatus: lifecycle.RevocationStatus, NextState: storage.AccountStateActive,
		RevocationStatus: storage.RevocationStatusNone,
	}); err != nil {
		t.Fatal(err)
	}
	message, _ := mail.Normalize(accountID.String(), mail.MessageInput{GmailMessageID: "synthetic-message", GmailThreadID: "synthetic-thread", SenderAddress: "person@example.test", To: []string{"owner@example.test"}, CC: []string{}, DeliveredTo: []string{}, Subject: "review", Labels: []string{}})
	if err := store.CommitCurrentDiscovery(context.Background(), storage.CurrentDiscoveryCommit{AccountID: accountID, Expected: expected, Next: next, Messages: []mail.Message{message}}); err != nil {
		t.Fatal(err)
	}
	return store, accountID, message
}

func TestEvaluatePersistsOnceAndReusesOriginalTimestamp(t *testing.T) {
	store, accountID, message := evaluatorStore(t)
	var clockReads atomic.Int64
	evaluator, err := New(config.Defaults().Gate, store, func() time.Time {
		clockReads.Add(1)
		return time.UnixMilli(1700000000123)
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := evaluator.Evaluate(context.Background(), accountID, message.GmailMessageID())
	if err != nil {
		t.Fatal(err)
	}
	second, err := evaluator.Evaluate(context.Background(), accountID, message.GmailMessageID())
	if err != nil {
		t.Fatal(err)
	}
	if !first.Equal(second) || first.EvaluatedAtUnixMS() != 1700000000123 || clockReads.Load() != 1 {
		t.Fatalf("first=%#v second=%#v clock_reads=%d", first, second, clockReads.Load())
	}
}

func TestPolicyChangeReplacesFromExactDurableRevision(t *testing.T) {
	store, accountID, message := evaluatorStore(t)
	first, err := New(config.Defaults().Gate, store, func() time.Time { return time.UnixMilli(1000) })
	if err != nil {
		t.Fatal(err)
	}
	initial, err := first.Evaluate(context.Background(), accountID, message.GmailMessageID())
	if err != nil {
		t.Fatal(err)
	}
	changedPolicy := config.Defaults().Gate
	changedPolicy.DirectRecipientIsCandidate = false
	second, err := New(changedPolicy, store, func() time.Time { return time.UnixMilli(2000) })
	if err != nil {
		t.Fatal(err)
	}
	changed, err := second.Evaluate(context.Background(), accountID, message.GmailMessageID())
	if err != nil {
		t.Fatal(err)
	}
	if changed.InputHash() == initial.InputHash() || changed.EvaluatedAtUnixMS() != 2000 {
		t.Fatalf("initial=%#v changed=%#v", initial, changed)
	}
	state, err := store.GetGateDecision(context.Background(), accountID, message.GmailMessageID())
	if err != nil || !state.Current || !state.Decision.Equal(changed) {
		t.Fatalf("durable state=%#v err=%v", state, err)
	}
}

type idempotentWinnerStore struct {
	Store
	winnerTimestamp int64
}

func (s *idempotentWinnerStore) CommitGateDecision(ctx context.Context, commit storage.GateDecisionCommit) error {
	winner, err := storage.DecodeGateDecision(int64(commit.Next.Version()), commit.Next.SourceMetadataHash(), commit.Next.InputHash(), commit.Next.Outcome().String(), commit.Next.ReasonJSON(), s.winnerTimestamp)
	if err != nil {
		return err
	}
	if err := s.Store.CommitGateDecision(ctx, storage.GateDecisionCommit{Source: commit.Source, Expected: commit.Expected, Next: winner}); err != nil {
		return err
	}
	return s.Store.CommitGateDecision(ctx, commit)
}

func TestConcurrentIdempotentWinnerReturnsDurableTimestamp(t *testing.T) {
	base, accountID, message := evaluatorStore(t)
	winner := &idempotentWinnerStore{Store: base, winnerTimestamp: 1000}
	evaluator, err := New(config.Defaults().Gate, winner, func() time.Time { return time.UnixMilli(2000) })
	if err != nil {
		t.Fatal(err)
	}
	decision, err := evaluator.Evaluate(context.Background(), accountID, message.GmailMessageID())
	if err != nil {
		t.Fatal(err)
	}
	state, err := base.GetGateDecision(context.Background(), accountID, message.GmailMessageID())
	if err != nil || decision.EvaluatedAtUnixMS() != 1000 || !decision.Equal(state.Decision) {
		t.Fatalf("returned=%#v durable=%#v err=%v", decision, state, err)
	}
}

type uncertainStore struct {
	Store
	applied     atomic.Bool
	commitCalls atomic.Int64
}

func (s *uncertainStore) CommitGateDecision(ctx context.Context, commit storage.GateDecisionCommit) error {
	s.commitCalls.Add(1)
	if err := s.Store.CommitGateDecision(ctx, commit); err != nil {
		return err
	}
	if s.applied.CompareAndSwap(false, true) {
		return storage.ErrGateDecisionRecoveryRequired
	}
	return nil
}

func TestFreshInvocationRecognizesAppliedUncertainCommitWithoutReplay(t *testing.T) {
	base, accountID, message := evaluatorStore(t)
	wrapped := &uncertainStore{Store: base}
	first, _ := New(config.Defaults().Gate, wrapped, func() time.Time { return time.UnixMilli(1000) })
	if _, err := first.Evaluate(context.Background(), accountID, message.GmailMessageID()); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("uncertain first result = %v", err)
	}
	if calls := wrapped.commitCalls.Load(); calls != 1 {
		t.Fatalf("uncertain first mutation attempts = %d, want 1", calls)
	}
	second, _ := New(config.Defaults().Gate, wrapped, func() time.Time { return time.UnixMilli(2000) })
	decision, err := second.Evaluate(context.Background(), accountID, message.GmailMessageID())
	if err != nil || decision.EvaluatedAtUnixMS() != 1000 || wrapped.commitCalls.Load() != 1 {
		t.Fatalf("restart decision=%#v mutation_attempts=%d err=%v", decision, wrapped.commitCalls.Load(), err)
	}
}

type racingStore struct {
	Store
	beforeCommit func()
}

func (s *racingStore) CommitGateDecision(ctx context.Context, commit storage.GateDecisionCommit) error {
	s.beforeCommit()
	return s.Store.CommitGateDecision(ctx, commit)
}

func TestMetadataChangeBetweenClassificationAndCommitFailsClosed(t *testing.T) {
	base, accountID, message := evaluatorStore(t)
	current, _ := base.GetSynchronizationCursor(context.Background(), accountID)
	next, _ := storage.ParseHistoryID("102")
	changed, _ := mail.Normalize(accountID.String(), mail.MessageInput{GmailMessageID: message.GmailMessageID(), GmailThreadID: message.GmailThreadID(), Subject: "changed", To: []string{}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{}})
	wrapped := &racingStore{Store: base, beforeCommit: func() {
		if err := base.CommitCurrentDiscovery(context.Background(), storage.CurrentDiscoveryCommit{AccountID: accountID, Expected: current.HistoryID, Next: next, Messages: []mail.Message{changed}}); err != nil {
			t.Fatal(err)
		}
	}}
	evaluator, _ := New(config.Defaults().Gate, wrapped, func() time.Time { return time.UnixMilli(1000) })
	if _, err := evaluator.Evaluate(context.Background(), accountID, message.GmailMessageID()); !errors.Is(err, ErrConflict) {
		t.Fatalf("metadata race error = %v", err)
	}
	state, err := base.GetGateDecision(context.Background(), accountID, message.GmailMessageID())
	if err == nil || !errors.Is(err, storage.ErrGateDecisionNotFound) || state.Current {
		t.Fatalf("stale decision was persisted: %#v %v", state, err)
	}
}

func TestEvaluatorUsesFixedErrorsAndReturnsNoIdentifiersOrPolicyValues(t *testing.T) {
	store, accountID, _ := evaluatorStore(t)
	policy := config.Defaults().Gate
	policy.SenderAllowDomains = []string{"sensitive-policy.example"}
	evaluator, _ := New(policy, store, func() time.Time { return time.UnixMilli(1000) })
	_, err := evaluator.Evaluate(context.Background(), accountID, "missing-sensitive-id")
	if !errors.Is(err, ErrMessageNotFound) {
		t.Fatalf("missing error = %v", err)
	}
	text := err.Error()
	for _, forbidden := range []string{accountID.String(), "missing-sensitive-id", "sensitive-policy.example", "SELECT", "http", "token"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("error disclosed %q: %q", forbidden, text)
		}
	}
	if _, err := evaluator.Evaluate(context.Background(), storage.AccountID{}, "bad id"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid request error = %v", err)
	}
}
