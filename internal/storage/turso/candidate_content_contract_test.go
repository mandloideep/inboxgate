package turso

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
)

func candidateContentDriverFixture(t *testing.T) (*migrationProtocolServer, storage.Handle, storage.CandidateContentCommit) {
	t.Helper()
	server := newMigrationProtocolServer(t)
	handle := openPersistenceContractHandle(t, server.URL)
	accountID, message := prepareGateDecisionBehaviorFixture(t, handle)
	decision := behaviorGateDecision(t, message, config.Defaults().Gate, 1000)
	if err := handle.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: message, Next: decision}); err != nil {
		t.Fatal(err)
	}
	lifecycle, err := handle.GetAccountLifecycle(context.Background(), accountID)
	if err != nil {
		t.Fatal(err)
	}
	content, err := mail.NewCandidateContent(mail.CandidateContentInput{
		RecordID: message.RecordID(), SourceMetadataHash: message.MetadataHash(), GateVersion: decision.Version(), GateInputHash: decision.InputHash(),
		SourceKind: mail.CandidateSourceTextPlain, Excerpt: strings.Repeat("x", 1024), ExcerptLimit: 1024, FetchedAtUnixMS: 1700000000123,
	})
	if err != nil {
		t.Fatal(err)
	}
	return server, handle, storage.CandidateContentCommit{Source: message, Gate: decision, LifecycleVersion: lifecycle.Version, Next: content}
}

func TestCandidateContentExactDriverParametersAndIdempotency(t *testing.T) {
	server, handle, commit := candidateContentDriverFixture(t)
	if err := handle.CommitCandidateContent(context.Background(), commit); err != nil {
		t.Fatal(err)
	}
	if err := handle.CommitCandidateContent(context.Background(), commit); err != nil {
		t.Fatal(err)
	}
	records := persistenceSQLRecords(server.persistenceRecords(), candidateContentCommitSQL)
	if len(records) != 1 || records[0].wantRows {
		t.Fatalf("mutation records = %#v", records)
	}
	assertProtocolStatement(t, records[0], candidateContentCommitSQL, []protocolValue{
		textProtocolValue(commit.Source.RecordID()), textProtocolValue(commit.Source.AccountID()), textProtocolValue(commit.Source.GmailMessageID()), integerProtocolValue(int(commit.LifecycleVersion.Int64())), textProtocolValue(commit.Source.MetadataHash()),
		integerProtocolValue(int(commit.Gate.Version())), textProtocolValue(commit.Gate.InputHash()), textProtocolValue(commit.Gate.Outcome().String()), textProtocolValue(commit.Gate.ReasonJSON()), integerProtocolValue(int(commit.Gate.EvaluatedAtUnixMS())),
		integerProtocolValue(0), nullProtocolValue(), nullProtocolValue(), nullProtocolValue(), nullProtocolValue(), nullProtocolValue(),
		integerProtocolValue(int(commit.Next.ExtractorVersion())), textProtocolValue(commit.Next.SourceKind().String()), textProtocolValue(commit.Next.Excerpt()), integerProtocolValue(commit.Next.ExcerptBytes()), integerProtocolValue(commit.Next.ExcerptLimit()), integerProtocolValue(0), textProtocolValue(commit.Next.ContentHash()), integerProtocolValue(int(commit.Next.FetchedAtUnixMS())),
	})
}

func TestCandidateContentExactDriverUncertainResponseUsesSeparateProofAndNoReplay(t *testing.T) {
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
			server, handle, commit := candidateContentDriverFixture(t)
			server.armPersistenceResponse(candidateContentCommitSQL, tt.mode)
			err := handle.CommitCandidateContent(context.Background(), commit)
			if tt.wantSuccess && err != nil {
				t.Fatalf("commit error = %v", err)
			}
			if !tt.wantSuccess && !errors.Is(err, storage.ErrCandidateContentRecoveryRequired) {
				t.Fatalf("commit error = %v", err)
			}
			if got := countPersistenceSQL(server.persistenceRecords(), candidateContentCommitSQL); got != 1 {
				t.Fatalf("mutation attempts = %d", got)
			}
			baton := firstMutationBaton(t, server.persistenceRecords(), candidateContentCommitSQL)
			if got := server.cursorSessionCloseCount(baton); got != tt.wantClose {
				t.Fatalf("mutation session close requests = %d, want %d", got, tt.wantClose)
			}
			if !server.cursorSessionWasNotReusedAfterMutation(baton, candidateContentCommitSQL) {
				t.Fatal("mutation session was reused")
			}
			if !lookupStartedOnSeparateStreamAfterMutation(server.persistenceRecords(), candidateContentCommitSQL, candidateContentLookupSQL, baton) {
				t.Fatal("post-mutation proof did not use a separate physical stream")
			}
			if err := handle.Close(); err != nil {
				t.Fatalf("close original handle: %v", err)
			}
			fresh := openPersistenceContractHandle(t, server.URL)
			if err := fresh.CommitCandidateContent(context.Background(), commit); err != nil {
				t.Fatalf("fresh reconciliation error = %v", err)
			}
			wantAttempts := 2
			if tt.wantSuccess {
				wantAttempts = 1
			}
			if got := countPersistenceSQL(server.persistenceRecords(), candidateContentCommitSQL); got != wantAttempts {
				t.Fatalf("mutation attempts across invocations = %d, want %d", got, wantAttempts)
			}
		})
	}
}

func TestCandidateContentMalformedDurableRowsFailClosed(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*syntheticCandidateContent)
	}{
		{name: "extractor version", mutate: func(value *syntheticCandidateContent) { value.extractorVersion = 2 }},
		{name: "source kind", mutate: func(value *syntheticCandidateContent) { value.sourceKind = "raw" }},
		{name: "gate version overflow", mutate: func(value *syntheticCandidateContent) { value.gateVersion = 1 << 32 }},
		{name: "excerpt bytes", mutate: func(value *syntheticCandidateContent) { value.excerptBytes++ }},
		{name: "truncation integer", mutate: func(value *syntheticCandidateContent) { value.truncated = 2 }},
		{name: "excerpt limit below", mutate: func(value *syntheticCandidateContent) { value.excerptLimit = int64(mail.MinimumExcerptBytes - 1) }},
		{name: "excerpt limit above", mutate: func(value *syntheticCandidateContent) { value.excerptLimit = int64(mail.MaximumExcerptBytes + 1) }},
		{name: "content hash", mutate: func(value *syntheticCandidateContent) { value.contentHash = strings.Repeat("A", 64) }},
		{name: "timestamp", mutate: func(value *syntheticCandidateContent) { value.fetchedAt = -1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, handle, commit := candidateContentDriverFixture(t)
			if err := handle.CommitCandidateContent(context.Background(), commit); err != nil {
				t.Fatal(err)
			}
			server.mu.Lock()
			value := server.candidateContents[commit.Source.RecordID()]
			test.mutate(&value)
			server.candidateContents[commit.Source.RecordID()] = value
			server.mu.Unlock()
			accountID, _ := storage.ParseAccountID(commit.Source.AccountID())
			if _, err := handle.GetCandidateContent(context.Background(), accountID, commit.Source.GmailMessageID(), commit.Next.ExcerptLimit()); !errors.Is(err, storage.ErrPersistenceInspect) {
				t.Fatalf("malformed durable row error=%v", err)
			}
		})
	}
}

func TestCandidateContentGateInputMismatchIsReturnedOnlyAsStale(t *testing.T) {
	server, handle, commit := candidateContentDriverFixture(t)
	if err := handle.CommitCandidateContent(context.Background(), commit); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	value := server.candidateContents[commit.Source.RecordID()]
	value.gateInputHash = strings.Repeat("4", 64)
	server.candidateContents[commit.Source.RecordID()] = value
	server.mu.Unlock()
	accountID, _ := storage.ParseAccountID(commit.Source.AccountID())
	state, err := handle.GetCandidateContent(context.Background(), accountID, commit.Source.GmailMessageID(), commit.Next.ExcerptLimit())
	if err != nil || state.Current || state.Content.GateInputHash() != value.gateInputHash {
		t.Fatalf("stale gate-input state=%#v err=%v", state, err)
	}
}

func TestCandidateContentExactDriverExcerptLimitBoundaries(t *testing.T) {
	for _, limit := range []int{mail.MinimumExcerptBytes, mail.MaximumExcerptBytes} {
		t.Run(fmt.Sprintf("accepted-%d", limit), func(t *testing.T) {
			_, handle, commit := candidateContentDriverFixture(t)
			content, err := mail.NewCandidateContent(mail.CandidateContentInput{
				RecordID: commit.Source.RecordID(), SourceMetadataHash: commit.Source.MetadataHash(), GateVersion: commit.Gate.Version(), GateInputHash: commit.Gate.InputHash(),
				SourceKind: mail.CandidateSourceTextPlain, Excerpt: strings.Repeat("x", limit), ExcerptLimit: limit, FetchedAtUnixMS: 1700000000123,
			})
			if err != nil {
				t.Fatal(err)
			}
			commit.Next = content
			if err := handle.CommitCandidateContent(context.Background(), commit); err != nil {
				t.Fatal(err)
			}
			accountID, _ := storage.ParseAccountID(commit.Source.AccountID())
			state, err := handle.GetCandidateContent(context.Background(), accountID, commit.Source.GmailMessageID(), limit)
			if err != nil || !state.Current || !state.Content.Equal(content) {
				t.Fatalf("state=%#v err=%v", state, err)
			}
		})
	}
	_, handle, commit := candidateContentDriverFixture(t)
	accountID, _ := storage.ParseAccountID(commit.Source.AccountID())
	for _, limit := range []int{mail.MinimumExcerptBytes - 1, mail.MaximumExcerptBytes + 1} {
		if _, err := handle.GetCandidateContent(context.Background(), accountID, commit.Source.GmailMessageID(), limit); !errors.Is(err, storage.ErrInvalidValue) {
			t.Fatalf("limit=%d error=%v", limit, err)
		}
	}
}

func TestCandidateContentSQLAuthorityIsFixedAndNarrow(t *testing.T) {
	if strings.Count(candidateContentLookupSQL, "?") != 2 || strings.Count(candidateContentCommitSQL, "?") != 24 {
		t.Fatalf("placeholder inventory lookup=%d commit=%d", strings.Count(candidateContentLookupSQL, "?"), strings.Count(candidateContentCommitSQL, "?"))
	}
	for _, statement := range []string{candidateContentLookupSQL, candidateContentCommitSQL} {
		for _, forbidden := range []string{"DELETE ", "DROP ", "ALTER ", "ATTACH ", "PRAGMA ", ";"} {
			if strings.Contains(statement, forbidden) {
				t.Fatalf("statement contains %q", forbidden)
			}
		}
	}
}
