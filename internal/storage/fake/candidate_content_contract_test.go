package fake

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/gate"
	"github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
)

func candidateContentFixture(t *testing.T) (*Store, storage.AccountID, mail.Message, storage.GateDecision, storage.AccountLifecycle) {
	t.Helper()
	store := New()
	accountID, _ := storage.ParseAccountID("1234567890abcdef1234567890abcdef")
	subject, _ := storage.ParseProviderSubject("candidate-subject")
	if _, err := store.EnsureAccount(context.Background(), storage.AccountSeed{ID: accountID, ProviderSubject: subject}); err != nil {
		t.Fatal(err)
	}
	h100, _ := storage.ParseHistoryID("100")
	if err := store.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: accountID, Next: h100}); err != nil {
		t.Fatal(err)
	}
	binaryEnvelope := []byte{'I', 'G', 'C', 0, 1, 1, 9}
	binaryEnvelope = append(binaryEnvelope, []byte("synthetic")...)
	binaryEnvelope = append(binaryEnvelope, make([]byte, 12+32+16)...)
	envelope, _ := storage.ParseCredentialEnvelope("igc1." + base64.RawURLEncoding.EncodeToString(binaryEnvelope))
	if err := store.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: accountID, Next: envelope}); err != nil {
		t.Fatal(err)
	}
	pending, _ := store.GetAccountLifecycle(context.Background(), accountID)
	if err := store.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: accountID, ExpectedState: pending.State, ExpectedVersion: pending.Version, ExpectedRevocationStatus: pending.RevocationStatus, NextState: storage.AccountStateActive, RevocationStatus: storage.RevocationStatusNone}); err != nil {
		t.Fatal(err)
	}
	message, _ := mail.Normalize(accountID.String(), mail.MessageInput{GmailMessageID: "candidate-message", GmailThreadID: "candidate-thread", To: []string{"owner@example.test"}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{}})
	h101, _ := storage.ParseHistoryID("101")
	if err := store.CommitCurrentDiscovery(context.Background(), storage.CurrentDiscoveryCommit{AccountID: accountID, Expected: h100, Next: h101, Messages: []mail.Message{message}}); err != nil {
		t.Fatal(err)
	}
	classification, _ := gate.Classify(message, config.Defaults().Gate)
	decision, _ := storage.NewGateDecision(classification, 1000)
	if err := store.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: message, Next: decision}); err != nil {
		t.Fatal(err)
	}
	lifecycle, _ := store.GetAccountLifecycle(context.Background(), accountID)
	return store, accountID, message, decision, lifecycle
}

func candidateValue(t *testing.T, message mail.Message, decision storage.GateDecision, excerpt string, limit int, timestamp int64) mail.CandidateContent {
	t.Helper()
	value, err := mail.NewCandidateContent(mail.CandidateContentInput{RecordID: message.RecordID(), SourceMetadataHash: message.MetadataHash(), GateVersion: decision.Version(), GateInputHash: decision.InputHash(), SourceKind: mail.CandidateSourceTextPlain, Excerpt: excerpt, ExcerptLimit: limit, FetchedAtUnixMS: timestamp})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestCandidateContentInsertIdempotencyAndExactCAS(t *testing.T) {
	store, accountID, message, decision, lifecycle := candidateContentFixture(t)
	first := candidateValue(t, message, decision, strings.Repeat("a", 1024), 1024, 1000)
	commit := storage.CandidateContentCommit{Source: message, Gate: decision, LifecycleVersion: lifecycle.Version, Next: first}
	if err := store.CommitCandidateContent(context.Background(), commit); err != nil {
		t.Fatal(err)
	}
	retry := candidateValue(t, message, decision, strings.Repeat("a", 1024), 1024, 2000)
	commit.Next = retry
	if err := store.CommitCandidateContent(context.Background(), commit); err != nil {
		t.Fatal(err)
	}
	state, err := store.GetCandidateContent(context.Background(), accountID, message.GmailMessageID(), 1024)
	if err != nil || !state.Current || !state.Content.Equal(first) {
		t.Fatalf("state=%#v err=%v", state, err)
	}
	replacement := candidateValue(t, message, decision, strings.Repeat("b", 1024), 1024, 3000)
	commit.Next = replacement
	if err := store.CommitCandidateContent(context.Background(), commit); !errors.Is(err, storage.ErrCandidateContentConflict) {
		t.Fatalf("blind replacement=%v", err)
	}
	revision := first.Revision()
	commit.Expected = &revision
	if err := store.CommitCandidateContent(context.Background(), commit); err != nil {
		t.Fatal(err)
	}
}

func TestCandidateContentRejectsNoncandidateInactiveAndStaleSource(t *testing.T) {
	store, accountID, message, decision, lifecycle := candidateContentFixture(t)
	value := candidateValue(t, message, decision, strings.Repeat("x", 1024), 1024, 1000)
	changedDecision, _ := storage.DecodeGateDecision(int64(decision.Version()), decision.SourceMetadataHash(), decision.InputHash(), gate.OutcomeMetadataOnly.String(), `["no_candidate_signal"]`, decision.EvaluatedAtUnixMS())
	if err := store.CommitCandidateContent(context.Background(), storage.CandidateContentCommit{Source: message, Gate: changedDecision, LifecycleVersion: lifecycle.Version, Next: value}); !errors.Is(err, storage.ErrCandidateContentIneligible) {
		t.Fatalf("noncandidate=%v", err)
	}
	if err := store.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: accountID, ExpectedState: lifecycle.State, ExpectedVersion: lifecycle.Version, ExpectedRevocationStatus: lifecycle.RevocationStatus, NextState: storage.AccountStatePaused, RevocationStatus: storage.RevocationStatusNone}); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitCandidateContent(context.Background(), storage.CandidateContentCommit{Source: message, Gate: decision, LifecycleVersion: lifecycle.Version, Next: value}); !errors.Is(err, storage.ErrLifecycleConflict) {
		t.Fatalf("inactive=%v", err)
	}
	if _, err := store.GetCandidateContent(context.Background(), accountID, message.GmailMessageID(), 1024); !errors.Is(err, storage.ErrCandidateContentNotFound) {
		t.Fatalf("unexpected durable content: %v", err)
	}
}
