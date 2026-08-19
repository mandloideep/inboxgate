package turso

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/gate"
	"github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
	storagefake "github.com/mandloideep/inboxgate/internal/storage/fake"
)

func TestCandidateContentBehaviorContractAcrossFakeAndExactDriver(t *testing.T) {
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
			decision := behaviorGateDecision(t, message, config.Defaults().Gate, 1000)
			if decision.Outcome() != gate.OutcomeReviewCandidate {
				t.Fatalf("outcome=%s", decision.Outcome())
			}
			if err := handle.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: message, Next: decision}); err != nil {
				t.Fatal(err)
			}
			lifecycle, err := handle.GetAccountLifecycle(context.Background(), accountID)
			if err != nil {
				t.Fatal(err)
			}
			first, err := mail.NewCandidateContent(mail.CandidateContentInput{RecordID: message.RecordID(), SourceMetadataHash: message.MetadataHash(), GateVersion: decision.Version(), GateInputHash: decision.InputHash(), SourceKind: mail.CandidateSourceTextPlain, Excerpt: strings.Repeat("a", 1024), ExcerptLimit: 1024, FetchedAtUnixMS: 1000})
			if err != nil {
				t.Fatal(err)
			}
			commit := storage.CandidateContentCommit{Source: message, Gate: decision, LifecycleVersion: lifecycle.Version, Next: first}
			if err := handle.CommitCandidateContent(context.Background(), commit); err != nil {
				t.Fatal(err)
			}
			retry, _ := mail.NewCandidateContent(mail.CandidateContentInput{RecordID: message.RecordID(), SourceMetadataHash: message.MetadataHash(), GateVersion: decision.Version(), GateInputHash: decision.InputHash(), SourceKind: mail.CandidateSourceTextPlain, Excerpt: strings.Repeat("a", 1024), ExcerptLimit: 1024, FetchedAtUnixMS: 2000})
			commit.Next = retry
			if err := handle.CommitCandidateContent(context.Background(), commit); err != nil {
				t.Fatal(err)
			}
			state, err := handle.GetCandidateContent(context.Background(), accountID, message.GmailMessageID(), 1024)
			if err != nil || !state.Current || !state.Content.Equal(first) {
				t.Fatalf("state=%#v err=%v", state, err)
			}
			replacement, _ := mail.NewCandidateContent(mail.CandidateContentInput{RecordID: message.RecordID(), SourceMetadataHash: message.MetadataHash(), GateVersion: decision.Version(), GateInputHash: decision.InputHash(), SourceKind: mail.CandidateSourceTextPlain, Excerpt: strings.Repeat("b", 1024), ExcerptLimit: 1024, FetchedAtUnixMS: 2000})
			commit.Next = replacement
			if err := handle.CommitCandidateContent(context.Background(), commit); !errors.Is(err, storage.ErrCandidateContentConflict) {
				t.Fatalf("blind replacement=%v", err)
			}
			third, _ := mail.NewCandidateContent(mail.CandidateContentInput{RecordID: message.RecordID(), SourceMetadataHash: message.MetadataHash(), GateVersion: decision.Version(), GateInputHash: decision.InputHash(), SourceKind: mail.CandidateSourceTextPlain, Excerpt: strings.Repeat("c", 1024), ExcerptLimit: 1024, FetchedAtUnixMS: 4000})
			revision := first.Revision()
			start := make(chan struct{})
			results := make(chan error, 2)
			var ready sync.WaitGroup
			ready.Add(2)
			for _, next := range []mail.CandidateContent{replacement, third} {
				go func(next mail.CandidateContent) {
					ready.Done()
					<-start
					expected := revision
					results <- handle.CommitCandidateContent(context.Background(), storage.CandidateContentCommit{Source: message, Gate: decision, LifecycleVersion: lifecycle.Version, Expected: &expected, Next: next})
				}(next)
			}
			ready.Wait()
			close(start)
			successes, conflicts := 0, 0
			for range 2 {
				switch err := <-results; {
				case err == nil:
					successes++
				case errors.Is(err, storage.ErrCandidateContentConflict):
					conflicts++
				default:
					t.Fatalf("concurrent replacement error=%v", err)
				}
			}
			state, err = handle.GetCandidateContent(context.Background(), accountID, message.GmailMessageID(), 1024)
			if err != nil || !state.Current || successes != 1 || conflicts != 1 || !state.Content.SemanticEqual(replacement) && !state.Content.SemanticEqual(third) {
				t.Fatalf("concurrent state=%#v err=%v successes=%d conflicts=%d", state, err, successes, conflicts)
			}
		})
	}
}

func TestCandidateContentCurrentnessInvalidationAcrossFakeAndExactDriver(t *testing.T) {
	implementations := []struct {
		name string
		open func(*testing.T) storage.Handle
	}{
		{name: "fake", open: func(*testing.T) storage.Handle { return storagefake.New() }},
		{name: "exact-driver", open: func(t *testing.T) storage.Handle {
			return openPersistenceContractHandle(t, newMigrationProtocolServer(t).URL)
		}},
	}
	for _, implementation := range implementations {
		for _, test := range []struct {
			name         string
			requestLimit int
			mutate       func(*testing.T, storage.Handle, storage.AccountID, mail.Message, storage.GateDecision, storage.AccountLifecycle)
		}{
			{name: "limit", requestLimit: 2048},
			{name: "lifecycle", requestLimit: 1024, mutate: func(t *testing.T, handle storage.Handle, accountID storage.AccountID, _ mail.Message, _ storage.GateDecision, lifecycle storage.AccountLifecycle) {
				if err := handle.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: accountID, ExpectedState: lifecycle.State, ExpectedVersion: lifecycle.Version, ExpectedRevocationStatus: lifecycle.RevocationStatus, NextState: storage.AccountStatePaused, RevocationStatus: storage.RevocationStatusNone}); err != nil {
					t.Fatal(err)
				}
			}},
			{name: "message metadata", requestLimit: 1024, mutate: func(t *testing.T, handle storage.Handle, accountID storage.AccountID, message mail.Message, _ storage.GateDecision, _ storage.AccountLifecycle) {
				changed, err := mail.Normalize(accountID.String(), mail.MessageInput{GmailMessageID: message.GmailMessageID(), GmailThreadID: message.GmailThreadID(), InternalDateMS: 1234, Subject: "changed", To: []string{"owner@example.test"}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{}})
				if err != nil {
					t.Fatal(err)
				}
				if err := handle.CommitCurrentDiscovery(context.Background(), storage.CurrentDiscoveryCommit{AccountID: accountID, Expected: persistenceHistoryID(t, "101"), Next: persistenceHistoryID(t, "102"), Messages: []mail.Message{changed}}); err != nil {
					t.Fatal(err)
				}
			}},
			{name: "gate input revision", requestLimit: 1024, mutate: func(t *testing.T, handle storage.Handle, _ storage.AccountID, message mail.Message, decision storage.GateDecision, _ storage.AccountLifecycle) {
				policy := config.Defaults().Gate
				policy.MailingListIsBulkSignal = !policy.MailingListIsBulkSignal
				next := behaviorGateDecision(t, message, policy, 2000)
				expected := decision.Revision()
				if err := handle.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: message, Expected: &expected, Next: next}); err != nil {
					t.Fatal(err)
				}
			}},
			{name: "gate outcome", requestLimit: 1024, mutate: func(t *testing.T, handle storage.Handle, _ storage.AccountID, message mail.Message, decision storage.GateDecision, _ storage.AccountLifecycle) {
				policy := config.Defaults().Gate
				policy.DirectRecipientIsCandidate = false
				next := behaviorGateDecision(t, message, policy, 2000)
				expected := decision.Revision()
				if err := handle.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: message, Expected: &expected, Next: next}); err != nil {
					t.Fatal(err)
				}
			}},
		} {
			t.Run(implementation.name+"/"+test.name, func(t *testing.T) {
				handle := implementation.open(t)
				accountID, message := prepareGateDecisionBehaviorFixture(t, handle)
				decision := behaviorGateDecision(t, message, config.Defaults().Gate, 1000)
				if err := handle.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: message, Next: decision}); err != nil {
					t.Fatal(err)
				}
				lifecycle, err := handle.GetAccountLifecycle(context.Background(), accountID)
				if err != nil {
					t.Fatal(err)
				}
				content, err := mail.NewCandidateContent(mail.CandidateContentInput{RecordID: message.RecordID(), SourceMetadataHash: message.MetadataHash(), GateVersion: decision.Version(), GateInputHash: decision.InputHash(), SourceKind: mail.CandidateSourceTextPlain, Excerpt: strings.Repeat("x", 1024), ExcerptLimit: 1024, FetchedAtUnixMS: 1000})
				if err != nil {
					t.Fatal(err)
				}
				if err := handle.CommitCandidateContent(context.Background(), storage.CandidateContentCommit{Source: message, Gate: decision, LifecycleVersion: lifecycle.Version, Next: content}); err != nil {
					t.Fatal(err)
				}
				if test.mutate != nil {
					test.mutate(t, handle, accountID, message, decision, lifecycle)
				}
				state, err := handle.GetCandidateContent(context.Background(), accountID, message.GmailMessageID(), test.requestLimit)
				if err != nil || state.Current || !state.Content.Equal(content) {
					t.Fatalf("state=%#v err=%v", state, err)
				}
			})
		}
	}
}
