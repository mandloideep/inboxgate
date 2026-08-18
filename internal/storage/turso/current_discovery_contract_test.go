package turso

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
)

func currentDiscoveryDriverFixture(t *testing.T, count int) (*migrationProtocolServer, storage.Handle, storage.CurrentDiscoveryCommit) {
	return currentDiscoveryDriverFixtureWithTimeout(t, count, 5*time.Second)
}

func currentDiscoveryDriverFixtureWithTimeout(t *testing.T, count int, persistenceTimeout time.Duration) (*migrationProtocolServer, storage.Handle, storage.CurrentDiscoveryCommit) {
	t.Helper()
	server := newMigrationProtocolServer(t)
	accountID, _ := storage.ParseAccountID("00112233445566778899aabbccddeeff")
	expected, _ := storage.ParseHistoryID("100")
	next, _ := storage.ParseHistoryID("101")
	server.seedAccount(accountID.String(), "synthetic-current-subject")
	server.seedCursor(accountID.String(), expected.String())
	server.seedLifecycle(accountID.String(), "active", 2, nil, "none")
	messages := make([]mail.Message, 0, count)
	for index := 0; index < count; index++ {
		message, err := mail.Normalize(accountID.String(), mail.MessageInput{
			GmailMessageID: fmt.Sprintf("message-%04d", index), GmailThreadID: fmt.Sprintf("thread-%04d", index),
			InternalDateMS: int64(index), Subject: "synthetic", To: []string{}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{},
		})
		if err != nil {
			t.Fatal(err)
		}
		messages = append(messages, message)
	}
	commit := storage.CurrentDiscoveryCommit{AccountID: accountID, Expected: expected, Next: next, Messages: messages}
	handle := openMigrationContractHandleOptions(t, server.URL, Options{
		PingTimeout: 5 * time.Second, MigrationTimeout: 5 * time.Second, CleanupTimeout: 5 * time.Second, PersistenceTimeout: persistenceTimeout,
	})
	return server, handle, commit
}

func TestCurrentDiscoveryExactDriverCommitsCanonicalMessagesAndCursor(t *testing.T) {
	server, handle, commit := currentDiscoveryDriverFixture(t, 65)
	if err := handle.CommitCurrentDiscovery(context.Background(), commit); err != nil {
		t.Fatalf("CommitCurrentDiscovery() error = %v records=%#v", err, server.persistenceRecords())
	}
	cursor, err := handle.GetSynchronizationCursor(context.Background(), commit.AccountID)
	if err != nil || cursor.HistoryID != commit.Next {
		t.Fatalf("cursor = %#v, %v", cursor, err)
	}
	for _, index := range []int{0, 64} {
		message, err := handle.GetDiscoveredMessage(context.Background(), commit.AccountID, commit.Messages[index].GmailMessageID())
		if err != nil || !message.Equal(commit.Messages[index]) {
			t.Fatalf("message %d mismatch: %v", index, err)
		}
	}
	records := server.persistenceRecords()
	stageRecords := persistenceSQLRecords(records, currentDiscoveryStageSQL)
	if len(stageRecords) != 2 {
		t.Fatalf("stage statements = %d, want 2, records=%#v", len(stageRecords), records)
	}
	for index, record := range stageRecords {
		if len(record.args) != storage.CurrentDiscoveryStageParameters || record.namedArgCount != 0 || record.wantRows {
			t.Fatalf("stage %d shape = args:%d named:%d rows:%t", index, len(record.args), record.namedArgCount, record.wantRows)
		}
	}
	last := stageRecords[1].args
	if got := parseProtocolValue(last[2]); got != "1" {
		t.Fatalf("last chunk first present = %q", got)
	}
	if got := parseProtocolValue(last[10]); got != "0" || last[12].Type != "null" || last[17].Type != "null" {
		t.Fatal("last chunk padding is not exact present-zero with null data")
	}
	if countPersistenceSQL(records, currentDiscoveryFinalizeSQL) != 1 {
		t.Fatal("finalization was replayed")
	}
	if countPersistenceSQL(records, currentDiscoveryAttemptCreateSQL) != 1 || countPersistenceSQL(records, currentDiscoverySealSQL) != 1 {
		t.Fatal("attempt or seal mutation count differs from one")
	}
}

func TestCurrentDiscoveryFixedChunkCountsAtPublishedBounds(t *testing.T) {
	for _, tt := range []struct {
		count int
		want  int
	}{{0, 0}, {1, 1}, {64, 1}, {65, 2}, {500, 8}, {5000, 79}} {
		t.Run(fmt.Sprint(tt.count), func(t *testing.T) {
			_, _, commit := currentDiscoveryDriverFixture(t, tt.count)
			prepared, err := storage.PrepareCurrentDiscoveryCommit(commit)
			if err != nil {
				t.Fatal(err)
			}
			if prepared.StageChunkCount() != tt.want {
				t.Fatalf("chunks = %d, want %d", prepared.StageChunkCount(), tt.want)
			}
			for chunk := 0; chunk < prepared.StageChunkCount(); chunk++ {
				arguments := currentDiscoveryStageArguments(prepared, chunk)
				if len(arguments) != storage.CurrentDiscoveryStageParameters {
					t.Fatalf("chunk %d arguments = %d", chunk, len(arguments))
				}
			}
		})
	}
}

func TestCurrentDiscoveryExactDriverCommitsPublishedLargeBoundsWithExactStageWireShape(t *testing.T) {
	for _, tt := range []struct {
		count int
		stage int
	}{{count: 500, stage: 8}, {count: 5000, stage: 79}} {
		t.Run(fmt.Sprint(tt.count), func(t *testing.T) {
			server, handle, commit := currentDiscoveryDriverFixtureWithTimeout(t, tt.count, 30*time.Second)
			prepared, err := storage.PrepareCurrentDiscoveryCommit(commit)
			if err != nil {
				t.Fatal(err)
			}
			if err := handle.CommitCurrentDiscovery(context.Background(), commit); err != nil {
				t.Fatalf("CommitCurrentDiscovery() error = %v", err)
			}
			records := persistenceSQLRecords(server.persistenceRecords(), currentDiscoveryStageSQL)
			if len(records) != tt.stage {
				t.Fatalf("stage requests = %d, want %d", len(records), tt.stage)
			}
			messages := prepared.Messages()
			for chunk, record := range records {
				if len(record.args) != storage.CurrentDiscoveryStageParameters || record.namedArgCount != 0 || record.wantRows {
					t.Fatalf("stage %d shape = args:%d named:%d rows:%t", chunk, len(record.args), record.namedArgCount, record.wantRows)
				}
				if record.bodyBytes <= 0 || record.bodyBytes > storage.MaximumCurrentDiscoveryStageWireBytes {
					t.Fatalf("stage %d wire bytes = %d, maximum %d", chunk, record.bodyBytes, storage.MaximumCurrentDiscoveryStageWireBytes)
				}
				if record.args[0].Type != "text" || parseProtocolValue(record.args[0]) != prepared.AccountID().String() || record.args[1].Type != "text" || parseProtocolValue(record.args[1]) != prepared.AttemptID() {
					t.Fatalf("stage %d fixed identity arguments are not exact", chunk)
				}
				for slot := 0; slot < storage.CurrentDiscoveryStageChunkMessages; slot++ {
					index := chunk*storage.CurrentDiscoveryStageChunkMessages + slot
					base := 2 + slot*8
					if index >= len(messages) {
						if record.args[base].Type != "integer" || parseProtocolValue(record.args[base]) != "0" || record.args[base+1].Type != "integer" || parseProtocolValue(record.args[base+1]) != "0" {
							t.Fatalf("stage %d slot %d padding presence is not exact", chunk, slot)
						}
						for position := base + 2; position < base+8; position++ {
							if record.args[position].Type != "null" {
								t.Fatalf("stage %d slot %d padding argument %d type = %q", chunk, slot, position, record.args[position].Type)
							}
						}
						continue
					}
					message := messages[index]
					wantTypes := []string{"integer", "integer", "text", "text", "text", "integer", "text", "text"}
					wantValues := []string{"1", fmt.Sprint(index), message.RecordID(), message.GmailMessageID(), message.GmailThreadID(), fmt.Sprint(message.MetadataVersion()), string(message.CanonicalJSON()), message.MetadataHash()}
					for offset := range wantTypes {
						if record.args[base+offset].Type != wantTypes[offset] || parseProtocolValue(record.args[base+offset]) != wantValues[offset] {
							t.Fatalf("stage %d slot %d argument %d mismatch", chunk, slot, base+offset)
						}
					}
				}
			}
		})
	}
}

func TestCurrentDiscoveryExactDriverBoundsWorstAcceptedStageWireRequest(t *testing.T) {
	server, handle, commit := currentDiscoveryDriverFixtureWithTimeout(t, 0, 30*time.Second)
	commit.Messages = make([]mail.Message, 0, storage.CurrentDiscoveryStageChunkMessages)
	for index := 0; index < storage.CurrentDiscoveryStageChunkMessages; index++ {
		input := currentDiscoveryInputForCanonicalSize(t, index, mail.MaximumCanonicalJSONBytes)
		message, err := mail.Normalize(commit.AccountID.String(), input)
		if err != nil || len(message.CanonicalJSON()) != mail.MaximumCanonicalJSONBytes {
			t.Fatalf("message %d canonical bytes = %d, %v", index, len(message.CanonicalJSON()), err)
		}
		commit.Messages = append(commit.Messages, message)
	}
	if err := handle.CommitCurrentDiscovery(context.Background(), commit); err != nil {
		t.Fatalf("CommitCurrentDiscovery() error = %v", err)
	}
	for _, statement := range []string{currentDiscoveryAttemptCreateSQL, currentDiscoveryStageSQL, currentDiscoverySealSQL} {
		records := persistenceSQLRecords(server.persistenceRecords(), statement)
		if len(records) != 1 || records[0].bodyBytes <= 64*mail.MaximumCanonicalJSONBytes || records[0].bodyBytes > storage.MaximumCurrentDiscoveryStageWireBytes {
			t.Fatalf("worst accepted %s wire records = %d, bytes = %d, maximum = %d", currentDiscoveryStatementName(statement), len(records), records[0].bodyBytes, storage.MaximumCurrentDiscoveryStageWireBytes)
		}
	}
}

func currentDiscoveryInputForCanonicalSize(t *testing.T, index, target int) mail.MessageInput {
	t.Helper()
	for itemBytes := 100; itemBytes <= 500; itemBytes++ {
		input := mail.MessageInput{
			GmailMessageID: fmt.Sprintf("wire-message-%04d", index), GmailThreadID: fmt.Sprintf("wire-thread-%04d", index),
			To: currentDiscoveryFixedWidthValues("to", 100, itemBytes), CC: currentDiscoveryFixedWidthValues("cc", 100, itemBytes), DeliveredTo: currentDiscoveryFixedWidthValues("delivered", 10, itemBytes), Labels: []string{},
		}
		message, err := mail.Normalize("00112233445566778899aabbccddeeff", input)
		if err != nil {
			continue
		}
		remaining := target - len(message.CanonicalJSON())
		if remaining >= 0 && remaining <= 4096 {
			input.Subject = strings.Repeat("x", remaining)
			return input
		}
	}
	t.Fatal("could not construct worst accepted canonical message")
	return mail.MessageInput{}
}

func currentDiscoveryFixedWidthValues(prefix string, count, width int) []string {
	values := make([]string, count)
	for index := range values {
		suffix := prefix + fmt.Sprint(index)
		values[index] = strings.Repeat("x", width-len(suffix)) + suffix
	}
	return values
}

func TestCurrentDiscoveryDroppedFinalizeResponseUsesVisibilityWithoutReplay(t *testing.T) {
	server, handle, commit := currentDiscoveryDriverFixture(t, 1)
	server.armPersistenceResponse(currentDiscoveryFinalizeSQL, "drop-after")
	if err := handle.CommitCurrentDiscovery(context.Background(), commit); err != nil {
		t.Fatalf("CommitCurrentDiscovery() error = %v", err)
	}
	if got := countPersistenceSQL(server.persistenceRecords(), currentDiscoveryFinalizeSQL); got != 1 {
		t.Fatalf("finalize attempts = %d, want 1", got)
	}
}

func TestCurrentDiscoveryDroppedFinalizeBeforeDurabilityRequiresFreshReconciliation(t *testing.T) {
	server, handle, commit := currentDiscoveryDriverFixture(t, 1)
	server.armPersistenceResponse(currentDiscoveryFinalizeSQL, "drop-before")
	err := handle.CommitCurrentDiscovery(context.Background(), commit)
	if !errors.Is(err, storage.ErrPersistenceUnknown) {
		t.Fatalf("CommitCurrentDiscovery() error = %v, want unknown", err)
	}
	if got := countPersistenceSQL(server.persistenceRecords(), currentDiscoveryFinalizeSQL); got != 1 {
		t.Fatalf("same invocation finalize attempts = %d", got)
	}
	if err := handle.ReconcileCurrentDiscovery(context.Background(), commit.AccountID); err != nil {
		t.Fatalf("ReconcileCurrentDiscovery() error = %v", err)
	}
	if got := countPersistenceSQL(server.persistenceRecords(), currentDiscoveryFinalizeSQL); got != 2 {
		t.Fatalf("fresh invocation finalize attempts = %d, want 2 total", got)
	}
}

func TestCurrentDiscoveryEveryMutationUsesVisibilityWithoutReplay(t *testing.T) {
	for _, statement := range []string{currentDiscoveryAttemptCreateSQL, currentDiscoveryStageSQL, currentDiscoverySealSQL} {
		t.Run(currentDiscoveryStatementName(statement), func(t *testing.T) {
			server, handle, commit := currentDiscoveryDriverFixture(t, 1)
			server.armPersistenceResponse(statement, "drop-after")
			if err := handle.CommitCurrentDiscovery(context.Background(), commit); err != nil {
				t.Fatalf("CommitCurrentDiscovery() error = %v", err)
			}
			if got := countPersistenceSQL(server.persistenceRecords(), statement); got != 1 {
				t.Fatalf("mutation attempts = %d, want 1", got)
			}
		})
	}
}

func TestCurrentDiscoveryUncertainPreDurabilityMutationsNeverReplay(t *testing.T) {
	for _, statement := range []string{currentDiscoveryAttemptCreateSQL, currentDiscoveryStageSQL, currentDiscoverySealSQL} {
		t.Run(currentDiscoveryStatementName(statement), func(t *testing.T) {
			server, handle, commit := currentDiscoveryDriverFixture(t, 1)
			server.armPersistenceResponse(statement, "drop-before")
			err := handle.CommitCurrentDiscovery(context.Background(), commit)
			if !errors.Is(err, storage.ErrPersistenceUnknown) {
				t.Fatalf("CommitCurrentDiscovery() error = %v, want unknown", err)
			}
			if got := countPersistenceSQL(server.persistenceRecords(), statement); got != 1 {
				t.Fatalf("same-invocation mutation attempts = %d", got)
			}
			if err := handle.ReconcileCurrentDiscovery(context.Background(), commit.AccountID); err != nil {
				t.Fatalf("fresh ReconcileCurrentDiscovery() error = %v", err)
			}
			if got := countPersistenceSQL(server.persistenceRecords(), statement); got != 1 {
				t.Fatalf("fresh reconciliation replayed prior mutation: %d", got)
			}
		})
	}
}

func TestCurrentDiscoveryAbortUncertaintyUsesFreshReconciliation(t *testing.T) {
	for _, mode := range []string{"drop-after", "drop-before"} {
		t.Run(mode, func(t *testing.T) {
			server, handle, commit := currentDiscoveryDriverFixture(t, 1)
			prepared, _ := storage.PrepareCurrentDiscoveryCommit(commit)
			server.mu.Lock()
			server.currentAttempts[commit.AccountID.String()] = &syntheticCurrentDiscoveryAttempt{
				attemptID: prepared.AttemptID(), expected: prepared.Expected().String(), next: prepared.Next().String(),
				messageCount: prepared.MessageCount(), encodedBytes: int64(prepared.EncodedBytes()), manifestHash: prepared.ManifestHash(), manifestWitness: prepared.ManifestWitness(), state: "open", staging: make(map[int]syntheticDiscoveredMessage),
			}
			server.mu.Unlock()
			server.armPersistenceResponse(currentDiscoveryAbortSQL, mode)
			err := handle.ReconcileCurrentDiscovery(context.Background(), commit.AccountID)
			if mode == "drop-after" {
				if err != nil {
					t.Fatalf("ReconcileCurrentDiscovery() error = %v", err)
				}
			} else {
				if !errors.Is(err, storage.ErrPersistenceUnknown) {
					t.Fatalf("ReconcileCurrentDiscovery() error = %v, want unknown", err)
				}
				if err := handle.ReconcileCurrentDiscovery(context.Background(), commit.AccountID); err != nil {
					t.Fatalf("fresh reconciliation error = %v", err)
				}
			}
			want := 1
			if mode == "drop-before" {
				want = 2
			}
			if got := countPersistenceSQL(server.persistenceRecords(), currentDiscoveryAbortSQL); got != want {
				t.Fatalf("abort attempts = %d, want %d", got, want)
			}
			if err := handle.ReconcileCurrentDiscovery(context.Background(), commit.AccountID); err != nil {
				t.Fatalf("restart after cleanup error = %v", err)
			}
			if got := countPersistenceSQL(server.persistenceRecords(), currentDiscoveryAbortSQL); got != want {
				t.Fatalf("restart after cleanup replayed abort: %d", got)
			}
		})
	}
}

func TestCurrentDiscoveryAbortRacingStageCannotAdvanceCursor(t *testing.T) {
	server, handle, commit := currentDiscoveryDriverFixture(t, 1)
	started, release := server.stallPersistence(currentDiscoveryStageSQL)
	result := make(chan error, 1)
	go func() { result <- handle.CommitCurrentDiscovery(context.Background(), commit) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("staging did not reach race point")
	}
	if err := handle.ReconcileCurrentDiscovery(context.Background(), commit.AccountID); err != nil {
		t.Fatalf("abort racing stage error = %v", err)
	}
	close(release)
	if err := <-result; !errors.Is(err, storage.ErrPersistenceUnknown) {
		t.Fatalf("staging after abort error = %v, want unknown", err)
	}
	server.mu.Lock()
	attempt := server.currentAttempts[commit.AccountID.String()]
	cursor := server.cursors[commit.AccountID.String()]
	messageCount := len(server.discoveredMessages[commit.AccountID.String()])
	server.mu.Unlock()
	if attempt != nil || cursor != commit.Expected.String() || messageCount != 0 {
		t.Fatal("abort versus stage changed canonical state")
	}
}

func TestCurrentDiscoveryConcurrentFinalizersConverge(t *testing.T) {
	server, handle, commit := currentDiscoveryDriverFixture(t, 1)
	started, release := server.stallPersistence(currentDiscoveryFinalizeSQL)
	first := make(chan error, 1)
	go func() { first <- handle.CommitCurrentDiscovery(context.Background(), commit) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first finalizer did not reach race point")
	}
	second := make(chan error, 1)
	go func() { second <- handle.ReconcileCurrentDiscovery(context.Background(), commit.AccountID) }()
	if err := <-second; err != nil {
		t.Fatalf("second finalizer error = %v", err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first finalizer convergence error = %v", err)
	}
	if got := countPersistenceSQL(server.persistenceRecords(), currentDiscoveryFinalizeSQL); got != 2 {
		t.Fatalf("competing finalizer attempts = %d, want 2 single attempts", got)
	}
	if got := countPersistenceSQL(server.persistenceRecords(), currentDiscoveryAbortSQL); got != 0 {
		t.Fatalf("sealed attempt reached abort = %d", got)
	}
}

func TestCurrentDiscoveryConcurrentExactCommitsConverge(t *testing.T) {
	server, handle, commit := currentDiscoveryDriverFixture(t, 1)
	started, release := server.barrierPersistence(currentDiscoveryAttemptCreateSQL, 2)
	var wait sync.WaitGroup
	wait.Add(2)
	results := make(chan error, 2)
	for range 2 {
		go func() {
			defer wait.Done()
			results <- handle.CommitCurrentDiscovery(context.Background(), commit)
		}()
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("exact commits did not reach deterministic creation barrier")
	}
	close(release)
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent exact commit error = %v", err)
		}
	}
}

func TestCurrentDiscoveryConcurrentDifferentCommitsAllowOneWinner(t *testing.T) {
	server, handle, first := currentDiscoveryDriverFixture(t, 1)
	other, _ := mail.Normalize(first.AccountID.String(), mail.MessageInput{GmailMessageID: "other-message", GmailThreadID: "other-thread", To: []string{}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{}})
	second := first
	second.Messages = []mail.Message{other}
	started, release := server.barrierPersistence(currentDiscoveryAttemptCreateSQL, 2)
	var wait sync.WaitGroup
	wait.Add(2)
	results := make(chan error, 2)
	for _, commit := range []storage.CurrentDiscoveryCommit{first, second} {
		go func(value storage.CurrentDiscoveryCommit) {
			defer wait.Done()
			results <- handle.CommitCurrentDiscovery(context.Background(), value)
		}(commit)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("different commits did not reach deterministic creation barrier")
	}
	close(release)
	wait.Wait()
	close(results)
	successes := 0
	conflicts := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, storage.ErrCurrentDiscoveryConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent result = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
}

func TestCurrentDiscoveryAttemptCreationIsAtomicallyGatedByLifecycleAndCursor(t *testing.T) {
	for _, tt := range []struct {
		name      string
		cross     func(*testing.T, *migrationProtocolServer, storage.Handle, storage.CurrentDiscoveryCommit)
		wantError error
	}{
		{name: "pause", wantError: storage.ErrLifecycleConflict, cross: func(t *testing.T, _ *migrationProtocolServer, handle storage.Handle, commit storage.CurrentDiscoveryCommit) {
			transitionDiscoveryLifecycle(t, handle, commit.AccountID, storage.AccountStatePaused)
		}},
		{name: "revoke", wantError: storage.ErrLifecycleConflict, cross: func(t *testing.T, _ *migrationProtocolServer, handle storage.Handle, commit storage.CurrentDiscoveryCommit) {
			transitionDiscoveryLifecycle(t, handle, commit.AccountID, storage.AccountStateRevoked)
		}},
		{name: "cursor advance", wantError: storage.ErrCurrentDiscoveryConflict, cross: func(_ *testing.T, server *migrationProtocolServer, _ storage.Handle, commit storage.CurrentDiscoveryCommit) {
			server.seedCursor(commit.AccountID.String(), commit.Next.String())
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server, handle, commit := currentDiscoveryDriverFixture(t, 1)
			started, release := server.stallPersistence(currentDiscoveryAttemptCreateSQL)
			result := make(chan error, 1)
			go func() { result <- handle.CommitCurrentDiscovery(context.Background(), commit) }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("attempt creation did not reach race point")
			}
			tt.cross(t, server, handle, commit)
			close(release)
			if err := <-result; !errors.Is(err, tt.wantError) {
				t.Fatalf("attempt creation race error = %v, want %v", err, tt.wantError)
			}
			server.mu.Lock()
			attempt := server.currentAttempts[commit.AccountID.String()]
			server.mu.Unlock()
			if attempt != nil {
				t.Fatal("late attempt creation survived authority change")
			}
		})
	}
}

func TestCurrentDiscoveryAbortRetainsOpenAttemptAcrossNonActiveLifecycle(t *testing.T) {
	for _, state := range []storage.AccountState{storage.AccountStatePaused, storage.AccountStateReauthorizationRequired} {
		t.Run(state.String()+" before abort", func(t *testing.T) {
			server, handle, commit := currentDiscoveryDriverFixture(t, 1)
			seedOpenCurrentDiscoveryAttempt(t, server, commit)
			transitionDiscoveryLifecycle(t, handle, commit.AccountID, state)
			if err := handle.ReconcileCurrentDiscovery(context.Background(), commit.AccountID); !errors.Is(err, storage.ErrLifecycleConflict) {
				t.Fatalf("reconcile error = %v", err)
			}
			if countPersistenceSQL(server.persistenceRecords(), currentDiscoveryAbortSQL) != 0 {
				t.Fatal("non-active reconciliation reached abort mutation")
			}
			server.mu.Lock()
			attempt := server.currentAttempts[commit.AccountID.String()]
			server.mu.Unlock()
			if attempt == nil || attempt.state != "open" {
				t.Fatal("non-active reconciliation removed open attempt")
			}
		})
		t.Run("abort before "+state.String(), func(t *testing.T) {
			server, handle, commit := currentDiscoveryDriverFixture(t, 1)
			seedOpenCurrentDiscoveryAttempt(t, server, commit)
			started, release := server.stallPersistence(currentDiscoveryAbortSQL)
			result := make(chan error, 1)
			go func() { result <- handle.ReconcileCurrentDiscovery(context.Background(), commit.AccountID) }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("abort did not reach lifecycle race point")
			}
			transitionDiscoveryLifecycle(t, handle, commit.AccountID, state)
			close(release)
			if err := <-result; !errors.Is(err, storage.ErrLifecycleConflict) {
				t.Fatalf("abort lifecycle race error = %v", err)
			}
			server.mu.Lock()
			attempt := server.currentAttempts[commit.AccountID.String()]
			server.mu.Unlock()
			if attempt == nil || attempt.state != "open" {
				t.Fatal("racing lifecycle transition did not retain open attempt")
			}
		})
	}
}

func TestCurrentDiscoveryLifecycleRacingFinalizeIsDeterministic(t *testing.T) {
	for _, tt := range []struct {
		name          string
		next          storage.AccountState
		reason        *storage.ReauthorizationReason
		revocation    storage.RevocationStatus
		retainAttempt bool
	}{
		{name: "pause", next: storage.AccountStatePaused, revocation: storage.RevocationStatusNone, retainAttempt: true},
		{name: "reauthorization", next: storage.AccountStateReauthorizationRequired, reason: reauthorizationReason(storage.ReauthorizationReasonRefreshInvalidGrant), revocation: storage.RevocationStatusNone, retainAttempt: true},
		{name: "revoke", next: storage.AccountStateRevoked, revocation: storage.RevocationStatusPending},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server, handle, commit := currentDiscoveryDriverFixture(t, 1)
			started, release := server.stallPersistence(currentDiscoveryFinalizeSQL)
			result := make(chan error, 1)
			go func() { result <- handle.CommitCurrentDiscovery(context.Background(), commit) }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("finalization did not reach race point")
			}
			lifecycle, err := handle.GetAccountLifecycle(context.Background(), commit.AccountID)
			if err != nil {
				t.Fatal(err)
			}
			if err := handle.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{
				AccountID: commit.AccountID, ExpectedState: lifecycle.State, ExpectedVersion: lifecycle.Version, ExpectedRevocationStatus: lifecycle.RevocationStatus,
				NextState: tt.next, ReauthorizationReason: tt.reason, RevocationStatus: tt.revocation,
			}); err != nil {
				t.Fatal(err)
			}
			close(release)
			if err := <-result; !errors.Is(err, storage.ErrLifecycleConflict) {
				t.Fatalf("finalize race error = %v", err)
			}
			server.mu.Lock()
			attempt := server.currentAttempts[commit.AccountID.String()]
			cursor := server.cursors[commit.AccountID.String()]
			server.mu.Unlock()
			if cursor != commit.Expected.String() {
				t.Fatal("lifecycle race advanced the cursor")
			}
			if tt.retainAttempt && (attempt == nil || attempt.state != "sealed") {
				t.Fatal("non-revoked lifecycle race did not retain the sealed attempt")
			}
			if !tt.retainAttempt && attempt != nil {
				t.Fatal("revocation race retained noncanonical staging")
			}
		})
	}
}

func TestCurrentDiscoveryCanonicalMessagesSurviveRevocationCleanup(t *testing.T) {
	server, handle, commit := currentDiscoveryDriverFixture(t, 1)
	if err := handle.CommitCurrentDiscovery(context.Background(), commit); err != nil {
		t.Fatal(err)
	}
	transitionDiscoveryLifecycle(t, handle, commit.AccountID, storage.AccountStateRevoked)
	message, err := handle.GetDiscoveredMessage(context.Background(), commit.AccountID, commit.Messages[0].GmailMessageID())
	if err != nil || !message.Equal(commit.Messages[0]) {
		t.Fatalf("canonical message after revoke = %#v, %v", message, err)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.currentAttempts[commit.AccountID.String()] != nil || server.cursors[commit.AccountID.String()] != commit.Next.String() {
		t.Fatal("revocation cleanup changed canonical cursor or retained an attempt")
	}
}

func TestCurrentDiscoveryFinalizerRejectsCorruptedSealedManifestBeforeCanonicalMutation(t *testing.T) {
	for _, tt := range []struct {
		name    string
		corrupt func(*migrationProtocolServer, storage.CurrentDiscoveryCommit)
	}{
		{name: "manifest", corrupt: func(server *migrationProtocolServer, commit storage.CurrentDiscoveryCommit) {
			server.currentAttempts[commit.AccountID.String()].manifestHash = strings.Repeat("0", 64)
		}},
		{name: "manifest witness", corrupt: func(server *migrationProtocolServer, commit storage.CurrentDiscoveryCommit) {
			server.currentAttempts[commit.AccountID.String()].manifestWitness = strings.Repeat("0", len(server.currentAttempts[commit.AccountID.String()].manifestWitness))
		}},
		{name: "metadata", corrupt: func(server *migrationProtocolServer, commit storage.CurrentDiscoveryCommit) {
			attempt := server.currentAttempts[commit.AccountID.String()]
			message := attempt.staging[0]
			message.metadataJSON = `{}`
			attempt.staging[0] = message
		}},
		{name: "hash", corrupt: func(server *migrationProtocolServer, commit storage.CurrentDiscoveryCommit) {
			attempt := server.currentAttempts[commit.AccountID.String()]
			message := attempt.staging[0]
			message.metadataHash = strings.Repeat("0", 64)
			attempt.staging[0] = message
		}},
		{name: "record", corrupt: func(server *migrationProtocolServer, commit storage.CurrentDiscoveryCommit) {
			attempt := server.currentAttempts[commit.AccountID.String()]
			message := attempt.staging[0]
			message.recordID = strings.Repeat("0", 64)
			attempt.staging[0] = message
		}},
		{name: "record and row witness", corrupt: func(server *migrationProtocolServer, commit storage.CurrentDiscoveryCommit) {
			attempt := server.currentAttempts[commit.AccountID.String()]
			message := attempt.staging[0]
			message.recordID = strings.Repeat("0", 64)
			message.rowWitness = syntheticRowWitness(message)
			attempt.staging[0] = message
		}},
		{name: "thread", corrupt: func(server *migrationProtocolServer, commit storage.CurrentDiscoveryCommit) {
			attempt := server.currentAttempts[commit.AccountID.String()]
			message := attempt.staging[0]
			message.threadID = "different-thread"
			attempt.staging[0] = message
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server, handle, commit := currentDiscoveryDriverFixture(t, 1)
			started, release := server.stallPersistence(currentDiscoveryFinalizeSQL)
			result := make(chan error, 1)
			go func() { result <- handle.CommitCurrentDiscovery(context.Background(), commit) }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("finalizer did not reach corruption barrier")
			}
			server.mu.Lock()
			tt.corrupt(server, commit)
			server.mu.Unlock()
			close(release)
			if err := <-result; !errors.Is(err, storage.ErrCurrentDiscoveryRecoveryRequired) {
				t.Fatalf("corrupted finalizer error = %v", err)
			}
			assertRejectedFinalizerState(t, server, commit, commit.Expected.String(), 0)
		})
	}
}

func TestCurrentDiscoveryFinalizerClassifiesDurableIdentityConflicts(t *testing.T) {
	for _, tt := range []struct {
		name      string
		want      error
		seed      func(*migrationProtocolServer, storage.CurrentDiscoveryCommit)
		canonical int
	}{
		{name: "record collision", want: storage.ErrMessageIdentityCollision, canonical: 0, seed: func(server *migrationProtocolServer, commit storage.CurrentDiscoveryCommit) {
			message := syntheticDiscoveredMessage{recordID: commit.Messages[0].RecordID(), accountID: "ffeeddccbbaa99887766554433221100", messageID: "occupied-message", threadID: "occupied-thread", version: 1, metadataJSON: `{}`, metadataHash: strings.Repeat("0", 64)}
			server.discoveredRecords[message.recordID] = message
		}},
		{name: "thread drift", want: storage.ErrCurrentDiscoveryConflict, canonical: 1, seed: func(server *migrationProtocolServer, commit storage.CurrentDiscoveryCommit) {
			drifted, err := mail.Normalize(commit.AccountID.String(), mail.MessageInput{GmailMessageID: commit.Messages[0].GmailMessageID(), GmailThreadID: "different-thread", Subject: "synthetic", To: []string{}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{}})
			if err != nil {
				panic(err)
			}
			message := syntheticDiscoveredMessage{recordID: drifted.RecordID(), accountID: drifted.AccountID(), messageID: drifted.GmailMessageID(), threadID: drifted.GmailThreadID(), version: int64(drifted.MetadataVersion()), metadataJSON: string(drifted.CanonicalJSON()), metadataHash: drifted.MetadataHash(), encodedBytes: int64(currentDiscoveryEncodedSize(drifted))}
			server.discoveredMessages[commit.AccountID.String()] = map[string]syntheticDiscoveredMessage{message.messageID: message}
			server.discoveredRecords[message.recordID] = message
		}},
		{name: "natural key wrong derived record", want: storage.ErrCurrentDiscoveryRecoveryRequired, canonical: 1, seed: func(server *migrationProtocolServer, commit storage.CurrentDiscoveryCommit) {
			message := syntheticDiscoveredMessage{recordID: strings.Repeat("0", 64), accountID: commit.AccountID.String(), messageID: commit.Messages[0].GmailMessageID(), threadID: commit.Messages[0].GmailThreadID(), version: 1, metadataJSON: string(commit.Messages[0].CanonicalJSON()), metadataHash: commit.Messages[0].MetadataHash()}
			server.discoveredMessages[commit.AccountID.String()] = map[string]syntheticDiscoveredMessage{message.messageID: message}
			server.discoveredRecords[message.recordID] = message
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server, handle, commit := currentDiscoveryDriverFixture(t, 1)
			started, release := server.stallPersistence(currentDiscoveryFinalizeSQL)
			result := make(chan error, 1)
			go func() { result <- handle.CommitCurrentDiscovery(context.Background(), commit) }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("finalizer did not reach conflict barrier")
			}
			server.mu.Lock()
			tt.seed(server, commit)
			server.mu.Unlock()
			close(release)
			if err := <-result; !errors.Is(err, tt.want) {
				t.Fatalf("finalizer conflict error = %v, want %v", err, tt.want)
			}
			assertRejectedFinalizerState(t, server, commit, commit.Expected.String(), tt.canonical)
		})
	}
}

func TestCurrentDiscoveryFinalizerRejectsStaleCursorAndRetainsSealedAttempt(t *testing.T) {
	server, handle, commit := currentDiscoveryDriverFixture(t, 1)
	started, release := server.stallPersistence(currentDiscoveryFinalizeSQL)
	result := make(chan error, 1)
	go func() { result <- handle.CommitCurrentDiscovery(context.Background(), commit) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("finalizer did not reach cursor barrier")
	}
	server.seedCursor(commit.AccountID.String(), commit.Next.String())
	close(release)
	if err := <-result; !errors.Is(err, storage.ErrCurrentDiscoveryRecoveryRequired) {
		t.Fatalf("stale-cursor finalizer error = %v", err)
	}
	assertRejectedFinalizerState(t, server, commit, commit.Next.String(), 0)
}

func assertRejectedFinalizerState(t *testing.T, server *migrationProtocolServer, commit storage.CurrentDiscoveryCommit, cursor string, canonical int) {
	t.Helper()
	server.mu.Lock()
	defer server.mu.Unlock()
	attempt := server.currentAttempts[commit.AccountID.String()]
	if attempt == nil || attempt.state != "sealed" {
		t.Fatal("rejected finalizer did not retain sealed attempt")
	}
	if server.cursors[commit.AccountID.String()] != cursor {
		t.Fatal("rejected finalizer changed synchronization cursor")
	}
	if len(server.discoveredMessages[commit.AccountID.String()]) != canonical {
		t.Fatal("rejected finalizer changed canonical messages")
	}
}

func reauthorizationReason(reason storage.ReauthorizationReason) *storage.ReauthorizationReason {
	return &reason
}

func transitionDiscoveryLifecycle(t *testing.T, handle storage.Handle, accountID storage.AccountID, next storage.AccountState) {
	t.Helper()
	current, err := handle.GetAccountLifecycle(context.Background(), accountID)
	if err != nil {
		t.Fatal(err)
	}
	commit := storage.LifecycleCommit{
		AccountID: accountID, ExpectedState: current.State, ExpectedVersion: current.Version, ExpectedRevocationStatus: current.RevocationStatus,
		NextState: next, RevocationStatus: storage.RevocationStatusNone,
	}
	if next == storage.AccountStateReauthorizationRequired {
		reason := storage.ReauthorizationReasonRefreshInvalidGrant
		commit.ReauthorizationReason = &reason
	}
	if next == storage.AccountStateRevoked {
		commit.RevocationStatus = storage.RevocationStatusPending
	}
	if err := handle.CommitAccountLifecycle(context.Background(), commit); err != nil {
		t.Fatal(err)
	}
}

func TestCurrentDiscoveryChangedAuthorityRemainsCredentialFreeAndSanitized(t *testing.T) {
	var destinationRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		destinationRequests.Add(1)
		if request.Header.Get("Authorization") != "" {
			t.Error("credential-free current discovery sent an Authorization header")
		}
		http.Error(w, "raw current discovery marker", http.StatusBadGateway)
	}))
	t.Cleanup(destination.Close)
	server, handle, commit := currentDiscoveryDriverFixture(t, 1)
	server.redirectNextCursorBaseURL(destination.URL)
	_, firstErr := handle.GetDiscoveredMessage(context.Background(), commit.AccountID, commit.Messages[0].GmailMessageID())
	if !errors.Is(firstErr, storage.ErrMessageNotFound) {
		t.Fatalf("first lookup error = %v", firstErr)
	}
	_, err := handle.GetDiscoveredMessage(context.Background(), commit.AccountID, commit.Messages[0].GmailMessageID())
	if !errors.Is(err, storage.ErrPersistenceInspect) || destinationRequests.Load() != 1 {
		t.Fatalf("changed-authority lookup = %v, requests=%d", err, destinationRequests.Load())
	}
	for _, raw := range []string{"current discovery marker", commit.AccountID.String(), commit.Messages[0].GmailMessageID()} {
		if strings.Contains(err.Error(), raw) {
			t.Fatalf("sanitized error %q contains raw value", err)
		}
	}
}

func TestCurrentDiscoveryDriverFollowsCredentialFreeInitialRedirect(t *testing.T) {
	var redirectedRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		redirectedRequests.Add(1)
		if request.Header.Get("Authorization") != "" {
			t.Error("credential-free redirected current discovery sent an Authorization header")
		}
		http.Error(w, "raw redirected current discovery marker", http.StatusBadGateway)
	}))
	t.Cleanup(destination.Close)
	initial := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		http.Redirect(w, request, destination.URL+request.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(initial.Close)
	accountID, _ := storage.ParseAccountID("00112233445566778899aabbccddeeff")
	_, err := openPersistenceContractHandle(t, initial.URL).GetDiscoveredMessage(context.Background(), accountID, "synthetic-message")
	if !errors.Is(err, storage.ErrPersistenceInspect) || redirectedRequests.Load() != 1 || strings.Contains(err.Error(), "redirected current discovery") {
		t.Fatalf("redirected current discovery = %v, requests=%d", err, redirectedRequests.Load())
	}
}

func TestCurrentDiscoveryProtocolBaseURLCanDowngradeHTTPSWithoutCredential(t *testing.T) {
	var downgradedRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		downgradedRequests.Add(1)
		if request.TLS != nil {
			t.Error("protocol-provided destination unexpectedly retained HTTPS")
		}
		if request.Header.Get("Authorization") != "" {
			t.Error("credential-free downgraded current discovery sent an Authorization header")
		}
		http.Error(w, "raw downgrade marker", http.StatusBadGateway)
	}))
	t.Cleanup(destination.Close)
	initial := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeCurrentDiscoveryNotFound(w, destination.URL)
	}))
	t.Cleanup(initial.Close)
	previousTransport := http.DefaultTransport
	http.DefaultTransport = initial.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = previousTransport })
	accountID, _ := storage.ParseAccountID("00112233445566778899aabbccddeeff")
	adapter, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	database := adapter.open(initial.URL, "")
	t.Cleanup(func() { _ = database.Close() })
	connection, err := database.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	rows, err := connection.QueryContext(context.Background(), currentDiscoveryMessageLookupSQL, accountID.String(), "synthetic-message")
	if err != nil {
		t.Fatalf("first exact-driver HTTPS lookup error = %v", err)
	}
	for rows.Next() {
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("close first exact-driver rows = %v", err)
	}
	rows, err = connection.QueryContext(context.Background(), currentDiscoveryMessageLookupSQL, accountID.String(), "synthetic-message")
	if rows != nil {
		_ = rows.Close()
	}
	if err == nil || downgradedRequests.Load() != 1 {
		t.Fatalf("HTTPS-to-HTTP downgrade = %v, requests=%d", err, downgradedRequests.Load())
	}
}

func TestCurrentDiscoveryRedirectAndProtocolAuthorityPolicyByOperationFamily(t *testing.T) {
	prepared := currentDiscoveryTransportPrepared(t)
	for _, operation := range currentDiscoveryTransportOperations(prepared) {
		t.Run(operation.name+"/initial-redirect", func(t *testing.T) {
			var destinationRequests atomic.Int32
			destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				destinationRequests.Add(1)
				if request.Header.Get("Authorization") != "" {
					t.Error("credential-free redirect sent authorization")
				}
				http.Error(w, "raw redirect marker", http.StatusBadGateway)
			}))
			t.Cleanup(destination.Close)
			initial := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				http.Redirect(w, request, destination.URL+request.URL.Path, http.StatusTemporaryRedirect)
			}))
			t.Cleanup(initial.Close)
			connection, closeConnection := currentDiscoveryTransportConnection(t, initial.URL)
			defer closeConnection()
			err := executeCurrentDiscoveryTransportOperation(context.Background(), connection, operation)
			if err == nil || destinationRequests.Load() != 1 || strings.Contains(err.Error(), "raw redirect marker") {
				t.Fatalf("redirect error = %v, requests=%d", err, destinationRequests.Load())
			}
		})
		t.Run(operation.name+"/changed-authority", func(t *testing.T) {
			var destinationRequests atomic.Int32
			destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				destinationRequests.Add(1)
				if request.Header.Get("Authorization") != "" {
					t.Error("credential-free authority change sent authorization")
				}
				http.Error(w, "raw authority marker", http.StatusBadGateway)
			}))
			t.Cleanup(destination.Close)
			server := newMigrationProtocolServer(t)
			server.redirectNextCursorBaseURL(destination.URL)
			connection, closeConnection := currentDiscoveryTransportConnection(t, server.URL)
			defer closeConnection()
			if err := executeCurrentDiscoveryTransportOperation(context.Background(), connection, operation); err != nil {
				t.Fatalf("first authority operation = %v", err)
			}
			err := executeCurrentDiscoveryTransportOperation(context.Background(), connection, operation)
			if err == nil || destinationRequests.Load() != 1 || strings.Contains(err.Error(), "raw authority marker") {
				t.Fatalf("changed-authority error = %v, requests=%d", err, destinationRequests.Load())
			}
		})
		t.Run(operation.name+"/https-to-http", func(t *testing.T) {
			var destinationRequests atomic.Int32
			destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				destinationRequests.Add(1)
				if request.TLS != nil || request.Header.Get("Authorization") != "" {
					t.Error("credential-free downgrade retained HTTPS or sent authorization")
				}
				http.Error(w, "raw downgrade marker", http.StatusBadGateway)
			}))
			t.Cleanup(destination.Close)
			initial := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeCurrentDiscoveryTransportSuccess(w, destination.URL)
			}))
			t.Cleanup(initial.Close)
			previousTransport := http.DefaultTransport
			http.DefaultTransport = initial.Client().Transport
			t.Cleanup(func() { http.DefaultTransport = previousTransport })
			connection, closeConnection := currentDiscoveryTransportConnection(t, initial.URL)
			defer closeConnection()
			if err := executeCurrentDiscoveryTransportOperation(context.Background(), connection, operation); err != nil {
				t.Fatalf("first HTTPS operation = %v", err)
			}
			err := executeCurrentDiscoveryTransportOperation(context.Background(), connection, operation)
			if err == nil || destinationRequests.Load() != 1 || strings.Contains(err.Error(), "raw downgrade marker") {
				t.Fatalf("downgrade error = %v, requests=%d", err, destinationRequests.Load())
			}
		})
	}
}

func currentDiscoveryTransportPrepared(t *testing.T) storage.PreparedCurrentDiscovery {
	t.Helper()
	accountID, _ := storage.ParseAccountID("00112233445566778899aabbccddeeff")
	expected, _ := storage.ParseHistoryID("100")
	next, _ := storage.ParseHistoryID("101")
	message, err := mail.Normalize(accountID.String(), mail.MessageInput{GmailMessageID: "transport-message", GmailThreadID: "transport-thread", To: []string{}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := storage.PrepareCurrentDiscoveryCommit(storage.CurrentDiscoveryCommit{AccountID: accountID, Expected: expected, Next: next, Messages: []mail.Message{message}})
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

type currentDiscoveryTransportOperation struct {
	name      string
	statement string
	arguments []any
	mutation  bool
}

func currentDiscoveryTransportOperations(prepared storage.PreparedCurrentDiscovery) []currentDiscoveryTransportOperation {
	return []currentDiscoveryTransportOperation{
		{name: "attempt-read", statement: currentDiscoveryAttemptLookupSQL, arguments: []any{prepared.AccountID().String()}},
		{name: "stage-read", statement: currentDiscoveryStageLookupSQL, arguments: []any{prepared.AccountID().String()}},
		{name: "stage-proof-read", statement: currentDiscoveryStageProofSQL, arguments: currentDiscoveryStageArguments(prepared, 0)},
		{name: "canonical-proof-read", statement: currentDiscoveryProofSQL, arguments: currentDiscoveryStageArguments(prepared, 0)},
		{name: "record-read", statement: currentDiscoveryRecordLookupSQL, arguments: []any{prepared.Messages()[0].RecordID()}},
		{name: "natural-key-read", statement: currentDiscoveryNaturalKeyLookupSQL, arguments: []any{prepared.AccountID().String(), prepared.Messages()[0].GmailMessageID()}},
		{name: "attempt-create", statement: currentDiscoveryAttemptCreateSQL, arguments: []any{prepared.AccountID().String(), prepared.AttemptID(), prepared.Expected().String(), prepared.Next().String(), int64(prepared.MessageCount()), int64(prepared.EncodedBytes()), prepared.ManifestHash(), prepared.ManifestWitness()}, mutation: true},
		{name: "stage-mutation", statement: currentDiscoveryStageSQL, arguments: currentDiscoveryStageArguments(prepared, 0), mutation: true},
		{name: "seal-mutation", statement: currentDiscoverySealSQL, arguments: []any{prepared.AccountID().String(), prepared.AttemptID(), prepared.Expected().String(), prepared.Next().String(), int64(prepared.MessageCount()), int64(prepared.EncodedBytes()), prepared.ManifestHash(), prepared.ManifestWitness(), prepared.AccountID().String(), prepared.AttemptID(), prepared.AccountID().String(), prepared.AttemptID()}, mutation: true},
		{name: "finalize-mutation", statement: currentDiscoveryFinalizeSQL, arguments: []any{prepared.AccountID().String(), prepared.AttemptID(), prepared.ManifestHash()}, mutation: true},
		{name: "abort-mutation", statement: currentDiscoveryAbortSQL, arguments: []any{prepared.AccountID().String(), prepared.AttemptID()}, mutation: true},
	}
}

func currentDiscoveryTransportConnection(t *testing.T, baseURL string) (*sql.Conn, func()) {
	t.Helper()
	adapter, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	database := adapter.open(baseURL, "")
	connection, err := database.Conn(context.Background())
	if err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	return connection, func() {
		_ = connection.Close()
		_ = database.Close()
	}
}

func executeCurrentDiscoveryTransportOperation(ctx context.Context, connection *sql.Conn, operation currentDiscoveryTransportOperation) error {
	if operation.mutation {
		_, err := connection.ExecContext(ctx, operation.statement, operation.arguments...)
		return err
	}
	rows, err := connection.QueryContext(ctx, operation.statement, operation.arguments...)
	if err != nil {
		return err
	}
	for rows.Next() {
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	return rows.Close()
}

func writeCurrentDiscoveryTransportSuccess(w http.ResponseWriter, baseURL string) {
	encoder := json.NewEncoder(w)
	_ = encoder.Encode(map[string]any{"baton": "synthetic-transport-baton", "base_url": baseURL})
	_ = encoder.Encode(map[string]any{"type": "step_begin", "step": 0, "cols": []any{}})
	_ = encoder.Encode(map[string]any{"type": "step_end", "step": 0, "affected_row_count": 1})
	_ = encoder.Encode(map[string]any{"type": "step_begin", "step": 1, "cols": []any{}})
	_ = encoder.Encode(map[string]any{"type": "step_end", "step": 1})
}

func writeCurrentDiscoveryNotFound(w http.ResponseWriter, baseURL string) {
	encoder := json.NewEncoder(w)
	_ = encoder.Encode(map[string]any{"baton": "synthetic-downgrade-baton", "base_url": baseURL})
	_ = encoder.Encode(map[string]any{"type": "step_begin", "step": 0, "cols": []any{
		map[string]any{"name": "sentinel", "decltype": "INTEGER"}, map[string]any{"name": "account_count", "decltype": "INTEGER"}, map[string]any{"name": "message_count", "decltype": "INTEGER"},
		map[string]any{"name": "record_id", "decltype": "TEXT"}, map[string]any{"name": "account_id", "decltype": "TEXT"}, map[string]any{"name": "gmail_message_id", "decltype": "TEXT"},
		map[string]any{"name": "gmail_thread_id", "decltype": "TEXT"}, map[string]any{"name": "metadata_version", "decltype": "INTEGER"}, map[string]any{"name": "metadata_json", "decltype": "TEXT"}, map[string]any{"name": "metadata_hash", "decltype": "TEXT"},
	}})
	_ = encoder.Encode(map[string]any{"type": "row", "row": []any{integerValue(1), integerValue(0), integerValue(0), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue()}})
	_ = encoder.Encode(map[string]any{"type": "step_end", "step": 0, "affected_row_count": 0})
	_ = encoder.Encode(map[string]any{"type": "step_begin", "step": 1, "cols": []any{}})
	_ = encoder.Encode(map[string]any{"type": "step_end", "step": 1})
}

func TestCurrentDiscoveryMutationDiagnosticsAreFixedAndNeverReplayed(t *testing.T) {
	for _, statement := range []string{currentDiscoveryAttemptCreateSQL, currentDiscoveryStageSQL, currentDiscoverySealSQL, currentDiscoveryFinalizeSQL, currentDiscoveryAbortSQL} {
		t.Run(currentDiscoveryStatementName(statement), func(t *testing.T) {
			server, handle, commit := currentDiscoveryDriverFixture(t, 1)
			if statement == currentDiscoveryAbortSQL {
				seedOpenCurrentDiscoveryAttempt(t, server, commit)
			}
			server.failNextSQL(statement)
			var err error
			if statement == currentDiscoveryAbortSQL {
				err = handle.ReconcileCurrentDiscovery(context.Background(), commit.AccountID)
			} else {
				err = handle.CommitCurrentDiscovery(context.Background(), commit)
			}
			if !errors.Is(err, storage.ErrPersistenceUnknown) {
				t.Fatalf("CommitCurrentDiscovery() error = %v, want unknown", err)
			}
			if got := countPersistenceSQL(server.persistenceRecords(), statement); got != 1 {
				t.Fatalf("mutation attempts = %d, want 1", got)
			}
			for _, raw := range []string{"raw synthetic-token", commit.AccountID.String(), commit.Messages[0].GmailMessageID(), commit.Messages[0].MetadataHash()} {
				if strings.Contains(err.Error(), raw) {
					t.Fatalf("sanitized error %q contains raw value", err)
				}
			}
		})
	}
}

func TestCurrentDiscoveryMutationResponseMatrixUsesProofAndSessionDiscard(t *testing.T) {
	for _, statement := range []string{currentDiscoveryAttemptCreateSQL, currentDiscoveryStageSQL, currentDiscoverySealSQL, currentDiscoveryFinalizeSQL, currentDiscoveryAbortSQL} {
		for _, tt := range []struct {
			mode        string
			wantSuccess bool
		}{
			{mode: "clean-eof"},
			{mode: "success-without-apply"},
			{mode: "malformed-after", wantSuccess: true},
			{mode: "apply-zero-affected", wantSuccess: true},
		} {
			t.Run(currentDiscoveryStatementName(statement)+"/"+tt.mode, func(t *testing.T) {
				server, handle, commit := currentDiscoveryDriverFixture(t, 1)
				if statement == currentDiscoveryAbortSQL {
					seedOpenCurrentDiscoveryAttempt(t, server, commit)
				}
				server.armPersistenceResponse(statement, tt.mode)
				var err error
				if statement == currentDiscoveryAbortSQL {
					err = handle.ReconcileCurrentDiscovery(context.Background(), commit.AccountID)
				} else {
					err = handle.CommitCurrentDiscovery(context.Background(), commit)
				}
				if tt.wantSuccess && err != nil {
					t.Fatalf("operation error = %v", err)
				}
				if !tt.wantSuccess && !errors.Is(err, storage.ErrPersistenceUnknown) {
					t.Fatalf("operation error = %v, want unknown", err)
				}
				if got := countPersistenceSQL(server.persistenceRecords(), statement); got != 1 {
					t.Fatalf("mutation attempts = %d, want 1", got)
				}
				baton := firstMutationBaton(t, server.persistenceRecords(), statement)
				wantClose := 1
				if tt.mode == "malformed-after" {
					wantClose = 0
				}
				if server.cursorSessionCloseCount(baton) != wantClose || !server.cursorSessionWasNotReusedAfterMutation(baton, statement) {
					t.Fatal("unproven or malformed mutation session was not discarded without reuse")
				}
			})
		}
	}
}

func TestCurrentDiscoveryEveryMutationReservesItsConnectionAndVerifiesOnADistinctPhysicalSession(t *testing.T) {
	for _, statement := range []string{currentDiscoveryAttemptCreateSQL, currentDiscoveryStageSQL, currentDiscoverySealSQL, currentDiscoveryFinalizeSQL, currentDiscoveryAbortSQL} {
		t.Run(currentDiscoveryStatementName(statement), func(t *testing.T) {
			server, handle, commit := currentDiscoveryDriverFixture(t, 1)
			if statement == currentDiscoveryAbortSQL {
				seedOpenCurrentDiscoveryAttempt(t, server, commit)
				if err := handle.ReconcileCurrentDiscovery(context.Background(), commit.AccountID); err != nil {
					t.Fatal(err)
				}
			} else if err := handle.CommitCurrentDiscovery(context.Background(), commit); err != nil {
				t.Fatal(err)
			}
			records := server.rawRecords()
			found := false
			for index, record := range records {
				if record.sql != statement {
					continue
				}
				found = true
				if record.baton == nil {
					t.Fatal("mutation did not reserve a physical cursor session")
				}
				if index+1 >= len(records) || (records[index+1].baton != nil && *records[index+1].baton == *record.baton) {
					t.Fatal("mutation verification did not use a distinct physical cursor session")
				}
				break
			}
			if !found {
				t.Fatal("mutation was not recorded")
			}
			for _, record := range records {
				upper := strings.ToUpper(record.sql)
				if strings.HasPrefix(upper, "BEGIN ") || upper == "BEGIN" || strings.HasPrefix(upper, "COMMIT ") || upper == "COMMIT" || strings.HasPrefix(upper, "ROLLBACK ") || upper == "ROLLBACK" {
					t.Fatalf("current discovery used explicit transaction SQL %q", record.sql)
				}
			}
			server.mu.Lock()
			for _, pipeline := range server.pipelineRecords {
				for _, request := range pipeline.requests {
					if request.Type == "sequence" {
						server.mu.Unlock()
						t.Fatal("current discovery used a pipeline sequence")
					}
				}
			}
			server.mu.Unlock()
		})
	}
}

func TestCurrentDiscoveryInspectionResponseMatrixFailsClosed(t *testing.T) {
	for _, statement := range []string{currentDiscoveryAttemptLookupSQL, currentDiscoveryStageLookupSQL, currentDiscoveryMessageLookupSQL} {
		for _, mode := range []string{"clean-eof", "malformed-after"} {
			t.Run(currentDiscoveryStatementName(statement)+"/"+mode, func(t *testing.T) {
				server, handle, commit := currentDiscoveryDriverFixture(t, 1)
				if statement == currentDiscoveryStageLookupSQL {
					seedOpenCurrentDiscoveryAttempt(t, server, commit)
				}
				server.armPersistenceResponse(statement, mode)
				var err error
				if statement == currentDiscoveryMessageLookupSQL {
					_, err = handle.GetDiscoveredMessage(context.Background(), commit.AccountID, commit.Messages[0].GmailMessageID())
				} else {
					err = handle.ReconcileCurrentDiscovery(context.Background(), commit.AccountID)
				}
				if !errors.Is(err, storage.ErrPersistenceInspect) {
					t.Fatalf("inspection error = %v", err)
				}
			})
		}
	}
}

func TestCurrentDiscoveryReadDiagnosticsAndMalformedRowsFailClosed(t *testing.T) {
	server, handle, commit := currentDiscoveryDriverFixture(t, 1)
	server.failNextSQL(currentDiscoveryMessageLookupSQL)
	_, err := handle.GetDiscoveredMessage(context.Background(), commit.AccountID, commit.Messages[0].GmailMessageID())
	if !errors.Is(err, storage.ErrPersistenceInspect) || strings.Contains(err.Error(), "raw synthetic-token") {
		t.Fatalf("message diagnostic = %v", err)
	}
	server.overridePersistenceRows(currentDiscoveryMessageLookupSQL, [][]any{{integerValue(1), integerValue(1), integerValue(2), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue(), nullValue()}})
	_, err = handle.GetDiscoveredMessage(context.Background(), commit.AccountID, commit.Messages[0].GmailMessageID())
	if !errors.Is(err, storage.ErrPersistenceInspect) {
		t.Fatalf("malformed message row error = %v", err)
	}
}

func TestCurrentDiscoveryInspectionFamiliesRejectExcessiveRowsAndValues(t *testing.T) {
	t.Run("attempt rows", func(t *testing.T) {
		server, handle, commit := currentDiscoveryDriverFixture(t, 1)
		prepared, _ := storage.PrepareCurrentDiscoveryCommit(commit)
		row := currentDiscoveryAttemptRow(prepared, "open")
		server.overridePersistenceRows(currentDiscoveryAttemptLookupSQL, [][]any{row, row})
		if err := handle.ReconcileCurrentDiscovery(context.Background(), commit.AccountID); !errors.Is(err, storage.ErrPersistenceInspect) {
			t.Fatalf("attempt excessive rows error = %v", err)
		}
	})
	t.Run("attempt value", func(t *testing.T) {
		server, handle, commit := currentDiscoveryDriverFixture(t, 1)
		prepared, _ := storage.PrepareCurrentDiscoveryCommit(commit)
		row := currentDiscoveryAttemptRow(prepared, "open")
		row[4] = textValue(strings.Repeat("a", 1<<20))
		server.overridePersistenceRows(currentDiscoveryAttemptLookupSQL, [][]any{row})
		if err := handle.ReconcileCurrentDiscovery(context.Background(), commit.AccountID); !errors.Is(err, storage.ErrPersistenceInspect) {
			t.Fatalf("attempt oversized value error = %v", err)
		}
	})
	t.Run("stage rows", func(t *testing.T) {
		server, handle, commit := currentDiscoveryDriverFixture(t, storage.MaximumCurrentDiscoveryMessages)
		prepared, _ := storage.PrepareCurrentDiscoveryCommit(commit)
		seedOpenCurrentDiscoveryAttempt(t, server, commit)
		rows := make([][]any, 0, storage.MaximumCurrentDiscoveryMessages+1)
		for ordinal, message := range prepared.Messages() {
			rows = append(rows, currentDiscoveryStageRow(prepared, ordinal, message))
		}
		rows = append(rows, currentDiscoveryStageRow(prepared, 0, prepared.Messages()[0]))
		server.overridePersistenceRows(currentDiscoveryStageLookupSQL, rows)
		if err := handle.ReconcileCurrentDiscovery(context.Background(), commit.AccountID); !errors.Is(err, storage.ErrResultTooLarge) {
			t.Fatalf("stage excessive rows error = %v", err)
		}
	})
	t.Run("stage value", func(t *testing.T) {
		server, handle, commit := currentDiscoveryDriverFixture(t, 1)
		prepared, _ := storage.PrepareCurrentDiscoveryCommit(commit)
		seedOpenCurrentDiscoveryAttempt(t, server, commit)
		row := currentDiscoveryStageRow(prepared, 0, prepared.Messages()[0])
		row[7] = textValue(strings.Repeat("x", 1<<20))
		server.overridePersistenceRows(currentDiscoveryStageLookupSQL, [][]any{row})
		if err := handle.ReconcileCurrentDiscovery(context.Background(), commit.AccountID); !errors.Is(err, storage.ErrPersistenceInspect) {
			t.Fatalf("stage oversized value error = %v", err)
		}
	})
	t.Run("message rows", func(t *testing.T) {
		server, handle, commit := currentDiscoveryDriverFixture(t, 1)
		row := currentDiscoveryMessageRow(commit.Messages[0])
		server.overridePersistenceRows(currentDiscoveryMessageLookupSQL, [][]any{row, row})
		_, err := handle.GetDiscoveredMessage(context.Background(), commit.AccountID, commit.Messages[0].GmailMessageID())
		if !errors.Is(err, storage.ErrPersistenceInspect) {
			t.Fatalf("message excessive rows error = %v", err)
		}
	})
	t.Run("message value", func(t *testing.T) {
		server, handle, commit := currentDiscoveryDriverFixture(t, 1)
		row := currentDiscoveryMessageRow(commit.Messages[0])
		row[8] = textValue(strings.Repeat("x", 1<<20))
		server.overridePersistenceRows(currentDiscoveryMessageLookupSQL, [][]any{row})
		_, err := handle.GetDiscoveredMessage(context.Background(), commit.AccountID, commit.Messages[0].GmailMessageID())
		if !errors.Is(err, storage.ErrPersistenceInspect) {
			t.Fatalf("message oversized value error = %v", err)
		}
	})
}

func TestCurrentDiscoveryNewInspectionFamiliesRejectMalformedAndOversizedSuccessfulResponses(t *testing.T) {
	for _, statement := range []string{currentDiscoveryStageProofSQL, currentDiscoveryProofSQL, currentDiscoveryRecordLookupSQL, currentDiscoveryNaturalKeyLookupSQL} {
		for _, tt := range []struct {
			name string
			rows [][]any
		}{
			{name: "excessive rows", rows: currentDiscoveryInspectionRows(statement, false, true)},
			{name: "excessive value", rows: currentDiscoveryInspectionRows(statement, true, false)},
		} {
			t.Run(currentDiscoveryStatementName(statement)+"/"+tt.name, func(t *testing.T) {
				server, handle, commit := currentDiscoveryDriverFixture(t, 1)
				server.overridePersistenceRows(statement, tt.rows)
				err := invokeCurrentDiscoveryInspection(t, server, handle, commit, statement)
				if err == nil {
					t.Fatal("malformed successful inspection response was accepted")
				}
				server.mu.Lock()
				cursor := server.cursors[commit.AccountID.String()]
				server.mu.Unlock()
				wantCursor := commit.Expected.String()
				if statement == currentDiscoveryProofSQL {
					wantCursor = commit.Next.String()
				}
				if cursor != wantCursor {
					t.Fatalf("inspection failure changed cursor to %q, want %q", cursor, wantCursor)
				}
			})
		}
	}
}

func TestCurrentDiscoveryNewInspectionFamiliesFailClosedOnCleanEOFAndMalformedBodies(t *testing.T) {
	for _, statement := range []string{currentDiscoveryStageProofSQL, currentDiscoveryProofSQL, currentDiscoveryRecordLookupSQL, currentDiscoveryNaturalKeyLookupSQL} {
		for _, mode := range []string{"clean-eof", "malformed-after"} {
			t.Run(currentDiscoveryStatementName(statement)+"/"+mode, func(t *testing.T) {
				server, handle, commit := currentDiscoveryDriverFixture(t, 1)
				server.armPersistenceResponse(statement, mode)
				err := invokeCurrentDiscoveryInspection(t, server, handle, commit, statement)
				if err == nil || strings.Contains(err.Error(), "raw synthetic-token") {
					t.Fatalf("inspection response error = %v", err)
				}
				if got := countPersistenceSQL(server.persistenceRecords(), statement); got != 1 {
					t.Fatalf("inspection requests = %d, want one", got)
				}
			})
		}
	}
}

func currentDiscoveryInspectionRows(statement string, oversizedValue, excessiveRows bool) [][]any {
	var row []any
	if statement == currentDiscoveryRecordLookupSQL || statement == currentDiscoveryNaturalKeyLookupSQL {
		row = []any{integerValue(1), integerValue(0), nullValue(), nullValue()}
		if oversizedValue {
			row = []any{integerValue(1), integerValue(1), textValue(strings.Repeat("a", 1<<20)), textValue("message")}
		}
	} else {
		row = []any{integerValue(1), integerValue(1), integerValue(1)}
		if oversizedValue {
			row[2] = textValue(strings.Repeat("a", 1<<20))
		}
	}
	rows := [][]any{row}
	if excessiveRows {
		rows = append(rows, append([]any(nil), row...))
	}
	return rows
}

func invokeCurrentDiscoveryInspection(t *testing.T, server *migrationProtocolServer, handle storage.Handle, commit storage.CurrentDiscoveryCommit, statement string) error {
	t.Helper()
	return invokeCurrentDiscoveryInspectionContext(t, server, handle, commit, statement, context.Background())
}

func invokeCurrentDiscoveryInspectionContext(t *testing.T, server *migrationProtocolServer, handle storage.Handle, commit storage.CurrentDiscoveryCommit, statement string, ctx context.Context) error {
	t.Helper()
	prepareCurrentDiscoveryInspection(t, server, commit, statement)
	return runCurrentDiscoveryInspection(ctx, handle, commit, statement)
}

func prepareCurrentDiscoveryInspection(t *testing.T, server *migrationProtocolServer, commit storage.CurrentDiscoveryCommit, statement string) {
	t.Helper()
	switch statement {
	case currentDiscoveryProofSQL:
		seedSealedCurrentDiscoveryAndCanonical(t, server, commit)
	case currentDiscoveryRecordLookupSQL, currentDiscoveryNaturalKeyLookupSQL:
		server.failNextSQL(currentDiscoveryFinalizeSQL)
	}
}

func runCurrentDiscoveryInspection(ctx context.Context, handle storage.Handle, commit storage.CurrentDiscoveryCommit, statement string) error {
	switch statement {
	case currentDiscoveryStageProofSQL:
		return handle.CommitCurrentDiscovery(ctx, commit)
	case currentDiscoveryProofSQL:
		return handle.ReconcileCurrentDiscovery(ctx, commit.AccountID)
	case currentDiscoveryRecordLookupSQL, currentDiscoveryNaturalKeyLookupSQL:
		return handle.CommitCurrentDiscovery(ctx, commit)
	default:
		return storage.ErrInvalidValue
	}
}

func TestCurrentDiscoveryReadCancellationIsBoundedAndSanitized(t *testing.T) {
	for _, statement := range []string{currentDiscoveryAttemptLookupSQL, currentDiscoveryStageLookupSQL, currentDiscoveryMessageLookupSQL} {
		t.Run(currentDiscoveryStatementName(statement), func(t *testing.T) {
			server, handle, commit := currentDiscoveryDriverFixture(t, 1)
			if statement == currentDiscoveryStageLookupSQL {
				seedOpenCurrentDiscoveryAttempt(t, server, commit)
			}
			started, release := server.stallPersistence(statement)
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() {
				if statement == currentDiscoveryMessageLookupSQL {
					_, err := handle.GetDiscoveredMessage(ctx, commit.AccountID, commit.Messages[0].GmailMessageID())
					result <- err
					return
				}
				result <- handle.ReconcileCurrentDiscovery(ctx, commit.AccountID)
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("read did not reach protocol stage")
			}
			canceledAt := time.Now()
			cancel()
			err := <-result
			if !errors.Is(err, storage.ErrPersistenceInspect) || !errors.Is(err, context.Canceled) || time.Since(canceledAt) >= 500*time.Millisecond || strings.Contains(err.Error(), commit.Messages[0].GmailMessageID()) {
				t.Fatalf("canceled read error = %v elapsed=%v", err, time.Since(canceledAt))
			}
			close(release)
		})
	}
}

func TestCurrentDiscoveryNewInspectionHeaderAndBodyStallsAreBounded(t *testing.T) {
	for _, statement := range []string{currentDiscoveryStageProofSQL, currentDiscoveryProofSQL, currentDiscoveryRecordLookupSQL, currentDiscoveryNaturalKeyLookupSQL} {
		for _, body := range []bool{false, true} {
			name := "header"
			if body {
				name = "body"
			}
			t.Run(currentDiscoveryStatementName(statement)+"/"+name, func(t *testing.T) {
				server, handle, commit := currentDiscoveryDriverFixture(t, 1)
				prepareCurrentDiscoveryInspection(t, server, commit, statement)
				var started, release chan struct{}
				if body {
					started, release = server.stallPersistenceBody(statement)
				} else {
					started, release = server.stallPersistence(statement)
				}
				var releaseOnce sync.Once
				t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
				ctx, cancel := context.WithCancel(context.Background())
				result := make(chan error, 1)
				go func() { result <- runCurrentDiscoveryInspection(ctx, handle, commit, statement) }()
				select {
				case <-started:
				case <-time.After(time.Second):
					t.Fatal("new inspection did not reach transport stall")
				}
				canceledAt := time.Now()
				cancel()
				err := <-result
				if err == nil || !errors.Is(err, context.Canceled) || time.Since(canceledAt) >= 500*time.Millisecond || strings.Contains(err.Error(), commit.Messages[0].GmailMessageID()) {
					t.Fatalf("stalled inspection error = %v elapsed=%v", err, time.Since(canceledAt))
				}
				releaseOnce.Do(func() { close(release) })
			})
		}
	}
}

func TestCurrentDiscoveryResponseBodyStallIsBounded(t *testing.T) {
	for _, statement := range []string{currentDiscoveryAttemptLookupSQL, currentDiscoveryStageLookupSQL, currentDiscoveryMessageLookupSQL, currentDiscoveryAttemptCreateSQL, currentDiscoveryStageSQL, currentDiscoverySealSQL, currentDiscoveryFinalizeSQL, currentDiscoveryAbortSQL} {
		t.Run(currentDiscoveryStatementName(statement), func(t *testing.T) {
			server, handle, commit := currentDiscoveryDriverFixture(t, 1)
			if statement == currentDiscoveryStageLookupSQL {
				seedOpenCurrentDiscoveryAttempt(t, server, commit)
			}
			if statement == currentDiscoveryAbortSQL {
				seedOpenCurrentDiscoveryAttempt(t, server, commit)
			}
			started, release := server.stallPersistenceBody(statement)
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() {
				if statement == currentDiscoveryMessageLookupSQL {
					_, err := handle.GetDiscoveredMessage(ctx, commit.AccountID, commit.Messages[0].GmailMessageID())
					result <- err
					return
				}
				if statement == currentDiscoveryAttemptCreateSQL || statement == currentDiscoveryStageSQL || statement == currentDiscoverySealSQL || statement == currentDiscoveryFinalizeSQL {
					result <- handle.CommitCurrentDiscovery(ctx, commit)
					return
				}
				result <- handle.ReconcileCurrentDiscovery(ctx, commit.AccountID)
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("operation did not reach response-body stall")
			}
			canceledAt := time.Now()
			cancel()
			err := <-result
			if !errors.Is(err, context.Canceled) || time.Since(canceledAt) >= 500*time.Millisecond {
				t.Fatalf("body-stalled operation error = %v elapsed=%v", err, time.Since(canceledAt))
			}
			releaseOnce.Do(func() { close(release) })
		})
	}
}

func TestCurrentDiscoveryMutationCancellationNeverReplays(t *testing.T) {
	for _, statement := range []string{currentDiscoveryAttemptCreateSQL, currentDiscoveryStageSQL, currentDiscoverySealSQL, currentDiscoveryFinalizeSQL, currentDiscoveryAbortSQL} {
		t.Run(currentDiscoveryStatementName(statement), func(t *testing.T) {
			server, handle, commit := currentDiscoveryDriverFixture(t, 1)
			if statement == currentDiscoveryAbortSQL {
				seedOpenCurrentDiscoveryAttempt(t, server, commit)
			}
			started, release := server.stallPersistence(statement)
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() {
				if statement == currentDiscoveryAbortSQL {
					result <- handle.ReconcileCurrentDiscovery(ctx, commit.AccountID)
					return
				}
				result <- handle.CommitCurrentDiscovery(ctx, commit)
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("mutation did not reach protocol stage")
			}
			canceledAt := time.Now()
			cancel()
			err := <-result
			if !errors.Is(err, storage.ErrPersistenceUnknown) || !errors.Is(err, context.Canceled) || time.Since(canceledAt) >= 500*time.Millisecond {
				t.Fatalf("canceled mutation error = %v elapsed=%v", err, time.Since(canceledAt))
			}
			if got := countPersistenceSQL(server.persistenceRecords(), statement); got != 1 {
				t.Fatalf("mutation attempts = %d, want one", got)
			}
			close(release)
		})
	}
}

func currentDiscoveryStatementName(statement string) string {
	switch statement {
	case currentDiscoveryAttemptLookupSQL:
		return "attempt-lookup"
	case currentDiscoveryAttemptCreateSQL:
		return "attempt-create"
	case currentDiscoveryStageLookupSQL:
		return "stage-lookup"
	case currentDiscoveryStageSQL:
		return "stage"
	case currentDiscoveryStageProofSQL:
		return "stage-proof"
	case currentDiscoverySealSQL:
		return "seal"
	case currentDiscoveryFinalizeSQL:
		return "finalize"
	case currentDiscoveryAbortSQL:
		return "abort"
	case currentDiscoveryMessageLookupSQL:
		return "message-lookup"
	case currentDiscoveryRecordLookupSQL:
		return "record-lookup"
	case currentDiscoveryNaturalKeyLookupSQL:
		return "natural-key-lookup"
	case currentDiscoveryProofSQL:
		return "canonical-proof"
	default:
		return "mutation"
	}
}

func seedOpenCurrentDiscoveryAttempt(t *testing.T, server *migrationProtocolServer, commit storage.CurrentDiscoveryCommit) {
	t.Helper()
	prepared, err := storage.PrepareCurrentDiscoveryCommit(commit)
	if err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	server.currentAttempts[commit.AccountID.String()] = &syntheticCurrentDiscoveryAttempt{
		attemptID: prepared.AttemptID(), expected: prepared.Expected().String(), next: prepared.Next().String(),
		messageCount: prepared.MessageCount(), encodedBytes: int64(prepared.EncodedBytes()), manifestHash: prepared.ManifestHash(), manifestWitness: prepared.ManifestWitness(), state: "open", staging: make(map[int]syntheticDiscoveredMessage),
	}
	server.mu.Unlock()
}

func seedSealedCurrentDiscoveryAndCanonical(t *testing.T, server *migrationProtocolServer, commit storage.CurrentDiscoveryCommit) {
	t.Helper()
	prepared, err := storage.PrepareCurrentDiscoveryCommit(commit)
	if err != nil {
		t.Fatal(err)
	}
	staging := make(map[int]syntheticDiscoveredMessage, prepared.MessageCount())
	for index, message := range prepared.Messages() {
		staged := syntheticDiscoveredMessage{
			recordID: message.RecordID(), accountID: message.AccountID(), messageID: message.GmailMessageID(), threadID: message.GmailThreadID(),
			version: int64(message.MetadataVersion()), metadataJSON: string(message.CanonicalJSON()), metadataHash: message.MetadataHash(), encodedBytes: int64(currentDiscoveryEncodedSize(message)),
		}
		staged.rowWitness = syntheticRowWitness(staged)
		staging[index] = staged
	}
	server.mu.Lock()
	server.currentAttempts[commit.AccountID.String()] = &syntheticCurrentDiscoveryAttempt{
		attemptID: prepared.AttemptID(), expected: prepared.Expected().String(), next: prepared.Next().String(),
		messageCount: prepared.MessageCount(), encodedBytes: int64(prepared.EncodedBytes()), manifestHash: prepared.ManifestHash(), manifestWitness: prepared.ManifestWitness(), state: "sealed", staging: staging,
	}
	server.discoveredMessages[commit.AccountID.String()] = make(map[string]syntheticDiscoveredMessage, len(staging))
	for _, message := range staging {
		server.discoveredMessages[commit.AccountID.String()][message.messageID] = message
		server.discoveredRecords[message.recordID] = message
	}
	server.cursors[commit.AccountID.String()] = commit.Next.String()
	server.mu.Unlock()
}

func currentDiscoveryAttemptRow(prepared storage.PreparedCurrentDiscovery, state string) []any {
	return []any{
		integerValue(1), integerValue(1), integerValue(1), textValue(prepared.AccountID().String()), textValue(prepared.AttemptID()),
		textValue(prepared.Expected().String()), textValue(prepared.Next().String()), integerValue(int64(prepared.MessageCount())), integerValue(int64(prepared.EncodedBytes())), textValue(prepared.ManifestHash()), textValue(prepared.ManifestWitness()), textValue(state),
	}
}

func currentDiscoveryStageRow(prepared storage.PreparedCurrentDiscovery, ordinal int, message mail.Message) []any {
	return []any{
		integerValue(1), textValue(prepared.AttemptID()), integerValue(int64(ordinal)), textValue(message.RecordID()), textValue(message.GmailMessageID()), textValue(message.GmailThreadID()),
		integerValue(int64(message.MetadataVersion())), textValue(string(message.CanonicalJSON())), textValue(message.MetadataHash()), integerValue(int64(currentDiscoveryEncodedSize(message))), textValue(prepared.RowWitness(ordinal)),
	}
}

func currentDiscoveryMessageRow(message mail.Message) []any {
	return []any{
		integerValue(1), integerValue(1), integerValue(1), textValue(message.RecordID()), textValue(message.AccountID()), textValue(message.GmailMessageID()), textValue(message.GmailThreadID()),
		integerValue(int64(message.MetadataVersion())), textValue(string(message.CanonicalJSON())), textValue(message.MetadataHash()),
	}
}

func persistenceSQLRecords(records []migrationRequest, statement string) []migrationRequest {
	result := make([]migrationRequest, 0)
	for _, record := range records {
		if record.sql == statement {
			result = append(result, record)
		}
	}
	return result
}
