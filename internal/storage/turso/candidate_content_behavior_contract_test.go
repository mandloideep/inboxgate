package turso

import (
	"context"
	"errors"
	"strings"
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
			state, err := handle.GetCandidateContent(context.Background(), accountID, message.GmailMessageID(), 1024)
			if err != nil || !state.Current || !state.Content.Equal(first) {
				t.Fatalf("state=%#v err=%v", state, err)
			}
			replacement, _ := mail.NewCandidateContent(mail.CandidateContentInput{RecordID: message.RecordID(), SourceMetadataHash: message.MetadataHash(), GateVersion: decision.Version(), GateInputHash: decision.InputHash(), SourceKind: mail.CandidateSourceTextPlain, Excerpt: strings.Repeat("b", 1024), ExcerptLimit: 1024, FetchedAtUnixMS: 2000})
			commit.Next = replacement
			if err := handle.CommitCandidateContent(context.Background(), commit); !errors.Is(err, storage.ErrCandidateContentConflict) {
				t.Fatalf("blind replacement=%v", err)
			}
			revision := first.Revision()
			commit.Expected = &revision
			if err := handle.CommitCandidateContent(context.Background(), commit); err != nil {
				t.Fatal(err)
			}
		})
	}
}
