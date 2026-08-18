package turso

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/gate"
	"github.com/mandloideep/inboxgate/internal/storage"
)

func gateDecisionDriverFixture(t *testing.T) (*migrationProtocolServer, storage.Handle, storage.GateDecisionCommit) {
	t.Helper()
	server, handle, discovery := currentDiscoveryDriverFixtureWithTimeout(t, 1, 5*time.Second)
	if err := handle.CommitCurrentDiscovery(context.Background(), discovery); err != nil {
		t.Fatal(err)
	}
	classification, err := gate.Classify(discovery.Messages[0], config.Defaults().Gate)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := storage.NewGateDecision(classification, 1700000000123)
	if err != nil {
		t.Fatal(err)
	}
	return server, handle, storage.GateDecisionCommit{Source: discovery.Messages[0], Next: decision}
}

func TestGateDecisionExactDriverInsertReadAndIdempotency(t *testing.T) {
	server, handle, commit := gateDecisionDriverFixture(t)
	if err := handle.CommitGateDecision(context.Background(), commit); err != nil {
		t.Fatal(err)
	}
	state, err := handle.GetGateDecision(context.Background(), commit.SourceAccountID(), commit.SourceGmailMessageID())
	if err != nil || !state.Current || !state.Decision.Equal(commit.Next) {
		t.Fatalf("state=%#v err=%v", state, err)
	}
	if err := handle.CommitGateDecision(context.Background(), commit); err != nil {
		t.Fatalf("exact retry error = %v", err)
	}
	records := persistenceSQLRecords(server.persistenceRecords(), gateDecisionCommitSQL)
	if len(records) != 1 || records[0].wantRows {
		t.Fatalf("mutation records = %#v", records)
	}
	assertProtocolStatement(t, records[0], gateDecisionCommitSQL, []protocolValue{
		textProtocolValue(commit.Source.RecordID()), textProtocolValue(commit.SourceAccountID().String()), textProtocolValue(commit.SourceGmailMessageID()), textProtocolValue(commit.Source.MetadataHash()),
		integerProtocolValue(0), nullProtocolValue(), nullProtocolValue(), integerProtocolValue(int(commit.Next.Version())), textProtocolValue(commit.Next.InputHash()), textProtocolValue(commit.Next.Outcome().String()), textProtocolValue(commit.Next.ReasonJSON()), integerProtocolValue(int(commit.Next.EvaluatedAtUnixMS())),
	})
	if commit.Next.ReasonJSON() != `["no_candidate_signal"]` {
		t.Fatalf("canonical reasons = %q", commit.Next.ReasonJSON())
	}
	if countPersistenceSQL(server.persistenceRecords(), gateDecisionCommitSQL) != 1 {
		t.Fatal("gate mutation replayed")
	}
	changedPolicy := config.Defaults().Gate
	changedPolicy.DirectRecipientIsCandidate = false
	classification, err := gate.Classify(commit.Source, changedPolicy)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := storage.NewGateDecision(classification, 1700000000999)
	if err != nil {
		t.Fatal(err)
	}
	expected := commit.Next.Revision()
	if err := handle.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: commit.Source, Expected: &expected, Next: replacement}); err != nil {
		t.Fatal(err)
	}
	records = persistenceSQLRecords(server.persistenceRecords(), gateDecisionCommitSQL)
	if len(records) != 2 || records[1].wantRows {
		t.Fatalf("replacement mutation records = %#v", records)
	}
	assertProtocolStatement(t, records[1], gateDecisionCommitSQL, []protocolValue{
		textProtocolValue(commit.Source.RecordID()), textProtocolValue(commit.SourceAccountID().String()), textProtocolValue(commit.SourceGmailMessageID()), textProtocolValue(commit.Source.MetadataHash()),
		integerProtocolValue(1), integerProtocolValue(int(expected.Version())), textProtocolValue(expected.InputHash()), integerProtocolValue(int(replacement.Version())), textProtocolValue(replacement.InputHash()), textProtocolValue(replacement.Outcome().String()), textProtocolValue(replacement.ReasonJSON()), integerProtocolValue(int(replacement.EvaluatedAtUnixMS())),
	})
}

func TestGateDecisionExactDriverUncertainResponseUsesSeparateProofAndNoReplay(t *testing.T) {
	for _, tt := range []struct {
		mode        string
		wantSuccess bool
		wantClose   int
	}{
		{mode: "drop-before"},
		{mode: "clean-eof", wantClose: 1},
		{mode: "success-without-apply", wantClose: 1},
		{mode: "drop-after", wantSuccess: true},
		{mode: "malformed-after", wantSuccess: true},
		{mode: "apply-zero-affected", wantSuccess: true, wantClose: 1},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			server, handle, commit := gateDecisionDriverFixture(t)
			server.armPersistenceResponse(gateDecisionCommitSQL, tt.mode)
			err := handle.CommitGateDecision(context.Background(), commit)
			if tt.wantSuccess && err != nil {
				t.Fatalf("commit error = %v", err)
			}
			if !tt.wantSuccess && !errors.Is(err, storage.ErrGateDecisionRecoveryRequired) {
				t.Fatalf("commit error = %v", err)
			}
			if got := countPersistenceSQL(server.persistenceRecords(), gateDecisionCommitSQL); got != 1 {
				t.Fatalf("mutation attempts = %d", got)
			}
			baton := firstMutationBaton(t, server.persistenceRecords(), gateDecisionCommitSQL)
			if got := server.cursorSessionCloseCount(baton); got != tt.wantClose {
				t.Fatalf("mutation session close requests = %d, want %d", got, tt.wantClose)
			}
			if !server.cursorSessionWasNotReusedAfterMutation(baton, gateDecisionCommitSQL) {
				t.Fatal("mutation session was reused")
			}
			if !lookupStartedOnSeparateStreamAfterMutation(server.persistenceRecords(), gateDecisionCommitSQL, gateDecisionLookupSQL, baton) {
				t.Fatal("post-mutation proof did not use a separate physical stream")
			}
			if err := handle.CommitGateDecision(context.Background(), commit); err != nil {
				t.Fatalf("fresh reconciliation error = %v", err)
			}
			wantAttempts := 2
			if tt.wantSuccess {
				wantAttempts = 1
			}
			if got := countPersistenceSQL(server.persistenceRecords(), gateDecisionCommitSQL); got != wantAttempts {
				t.Fatalf("mutation attempts across explicit invocations = %d, want %d", got, wantAttempts)
			}
		})
	}
}

func lookupStartedOnSeparateStreamAfterMutation(records []migrationRequest, mutationSQL, lookupSQL, mutationBaton string) bool {
	mutationSeen := false
	for _, record := range records {
		if !mutationSeen && record.sql == mutationSQL && record.baton != nil && *record.baton == mutationBaton {
			mutationSeen = true
			continue
		}
		if mutationSeen && record.sql == lookupSQL && (record.baton == nil || *record.baton != mutationBaton) {
			return true
		}
	}
	return false
}

func TestGateDecisionExactDriverConflictStaleMalformedAndDisclosure(t *testing.T) {
	server, handle, commit := gateDecisionDriverFixture(t)
	if err := handle.CommitGateDecision(context.Background(), commit); err != nil {
		t.Fatal(err)
	}
	changedPolicy := config.Defaults().Gate
	changedPolicy.DirectRecipientIsCandidate = false
	classification, _ := gate.Classify(commit.Source, changedPolicy)
	changed, _ := storage.NewGateDecision(classification, 1700000000999)
	if err := handle.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: commit.Source, Next: changed}); !errors.Is(err, storage.ErrGateDecisionConflict) {
		t.Fatalf("blind replacement error = %v", err)
	}
	server.overridePersistenceRows(gateDecisionLookupSQL, [][]any{{integerValue(1), integerValue(1), integerValue(1), textValue(commit.Source.RecordID()), textValue(commit.Source.MetadataHash()), integerValue(1), integerValue(1), textValue(commit.Source.MetadataHash()), textValue(strings.Repeat("a", 64)), textValue("review_candidate"), textValue(`["private-value"]`), integerValue(1)}})
	_, err := handle.GetGateDecision(context.Background(), commit.SourceAccountID(), commit.SourceGmailMessageID())
	if !errors.Is(err, storage.ErrPersistenceInspect) {
		t.Fatalf("malformed row error = %v", err)
	}
	for _, forbidden := range []string{commit.SourceAccountID().String(), commit.SourceGmailMessageID(), commit.Source.MetadataHash(), "private-value", gateDecisionLookupSQL, server.URL} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error disclosed %q: %q", forbidden, err)
		}
	}
}

func TestGateDecisionExactDriverCancellationDoesNotMutate(t *testing.T) {
	server, handle, commit := gateDecisionDriverFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := handle.CommitGateDecision(ctx, commit); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled error = %v", err)
	}
	if got := countPersistenceSQL(server.persistenceRecords(), gateDecisionCommitSQL); got != 0 {
		t.Fatalf("mutations = %d", got)
	}
}
