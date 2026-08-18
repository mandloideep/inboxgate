package fake

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
)

func activeDiscoveryStore(t *testing.T) (*Store, storage.CurrentDiscoveryCommit) {
	t.Helper()
	store := New()
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
	store.mu.Lock()
	lifecycle := store.lifecycles[accountID]
	lifecycle.State = storage.AccountStateActive
	store.lifecycles[accountID] = lifecycle
	store.mu.Unlock()
	message, err := mail.Normalize(accountID.String(), mail.MessageInput{GmailMessageID: "message-1", GmailThreadID: "thread-1", Subject: "first", To: []string{}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	return store, storage.CurrentDiscoveryCommit{AccountID: accountID, Expected: expected, Next: next, Messages: []mail.Message{message}}
}

func TestCommitCurrentDiscoveryAtomicallyPersistsMessagesAndCursor(t *testing.T) {
	store, commit := activeDiscoveryStore(t)
	if err := store.CommitCurrentDiscovery(context.Background(), commit); err != nil {
		t.Fatalf("CommitCurrentDiscovery() error = %v", err)
	}
	cursor, err := store.GetSynchronizationCursor(context.Background(), commit.AccountID)
	if err != nil || cursor.HistoryID != commit.Next {
		t.Fatalf("cursor = %#v, %v", cursor, err)
	}
	got, err := store.GetDiscoveredMessage(context.Background(), commit.AccountID, commit.Messages[0].GmailMessageID())
	if err != nil || !got.Equal(commit.Messages[0]) {
		t.Fatalf("message mismatch: %v", err)
	}
	if err := store.CommitCurrentDiscovery(context.Background(), commit); err != nil {
		t.Fatalf("exact retry error = %v", err)
	}
}

func TestCommitCurrentDiscoveryRejectsThreadDriftAndStaleCursorWithoutPartialWrites(t *testing.T) {
	store, commit := activeDiscoveryStore(t)
	if err := store.CommitCurrentDiscovery(context.Background(), commit); err != nil {
		t.Fatal(err)
	}
	threadDrift, _ := mail.Normalize(commit.AccountID.String(), mail.MessageInput{GmailMessageID: "message-1", GmailThreadID: "other-thread", To: []string{}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{}})
	next, _ := storage.ParseHistoryID("102")
	drift := storage.CurrentDiscoveryCommit{AccountID: commit.AccountID, Expected: commit.Next, Next: next, Messages: []mail.Message{threadDrift}}
	if err := store.CommitCurrentDiscovery(context.Background(), drift); !errors.Is(err, storage.ErrCurrentDiscoveryConflict) {
		t.Fatalf("thread drift error = %v", err)
	}
	cursor, _ := store.GetSynchronizationCursor(context.Background(), commit.AccountID)
	if cursor.HistoryID != commit.Next {
		t.Fatal("cursor advanced after rejected thread drift")
	}
}

func TestCommitCurrentDiscoveryConcurrentDifferentAttemptsAllowsOneWinner(t *testing.T) {
	store, first := activeDiscoveryStore(t)
	second := first
	message, _ := mail.Normalize(first.AccountID.String(), mail.MessageInput{GmailMessageID: "message-2", GmailThreadID: "thread-2", To: []string{}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{}})
	second.Messages = []mail.Message{message}
	var wait sync.WaitGroup
	wait.Add(2)
	errorsFound := make(chan error, 2)
	for _, commit := range []storage.CurrentDiscoveryCommit{first, second} {
		go func(value storage.CurrentDiscoveryCommit) {
			defer wait.Done()
			errorsFound <- store.CommitCurrentDiscovery(context.Background(), value)
		}(commit)
	}
	wait.Wait()
	close(errorsFound)
	successes := 0
	conflicts := 0
	for err := range errorsFound {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, storage.ErrCurrentDiscoveryConflict):
			conflicts++
		default:
			t.Fatalf("unexpected result = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
}

func TestCurrentDiscoveryLifecycleRules(t *testing.T) {
	for _, state := range []storage.AccountState{storage.AccountStatePaused, storage.AccountStateReauthorizationRequired} {
		t.Run(state.String(), func(t *testing.T) {
			store, commit := activeDiscoveryStore(t)
			store.mu.Lock()
			lifecycle := store.lifecycles[commit.AccountID]
			lifecycle.State = state
			if state == storage.AccountStateReauthorizationRequired {
				reason := storage.ReauthorizationReasonRefreshInvalidGrant
				lifecycle.ReauthorizationReason = &reason
			}
			store.lifecycles[commit.AccountID] = lifecycle
			store.mu.Unlock()
			if err := store.CommitCurrentDiscovery(context.Background(), commit); !errors.Is(err, storage.ErrLifecycleConflict) {
				t.Fatalf("commit error = %v", err)
			}
		})
	}
}

func TestCurrentDiscoveryBoundsAreRejectedBeforeMutation(t *testing.T) {
	store, commit := activeDiscoveryStore(t)
	commit.Messages = make([]mail.Message, storage.MaximumCurrentDiscoveryMessages+1)
	for index := range commit.Messages {
		commit.Messages[index], _ = mail.Normalize(commit.AccountID.String(), mail.MessageInput{GmailMessageID: fmt.Sprintf("m-%04d", index), GmailThreadID: "thread", To: []string{}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{}})
	}
	if err := store.CommitCurrentDiscovery(context.Background(), commit); !errors.Is(err, storage.ErrCurrentDiscoveryTooLarge) {
		t.Fatalf("error = %v", err)
	}
	cursor, _ := store.GetSynchronizationCursor(context.Background(), commit.AccountID)
	if cursor.HistoryID != commit.Expected {
		t.Fatal("cursor mutated after preflight bound rejection")
	}
}

func TestCurrentDiscoveryUpdatesOnlyMutableMetadata(t *testing.T) {
	store, first := activeDiscoveryStore(t)
	if err := store.CommitCurrentDiscovery(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	next, _ := storage.ParseHistoryID("102")
	updated, _ := mail.Normalize(first.AccountID.String(), mail.MessageInput{GmailMessageID: "message-1", GmailThreadID: "thread-1", Subject: "updated", To: []string{}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{"INBOX"}})
	second := storage.CurrentDiscoveryCommit{AccountID: first.AccountID, Expected: first.Next, Next: next, Messages: []mail.Message{updated}}
	if err := store.CommitCurrentDiscovery(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetDiscoveredMessage(context.Background(), first.AccountID, "message-1")
	if err != nil || !got.Equal(updated) || got.RecordID() != first.Messages[0].RecordID() {
		t.Fatalf("updated message = %#v, %v", got, err)
	}
}

func TestCurrentDiscoveryRecordCollisionRollsBackEverything(t *testing.T) {
	store, commit := activeDiscoveryStore(t)
	store.mu.Lock()
	store.records[commit.Messages[0].RecordID()] = messageNaturalKey{accountID: commit.AccountID, gmailMessageID: "different-message"}
	store.mu.Unlock()
	if err := store.CommitCurrentDiscovery(context.Background(), commit); !errors.Is(err, storage.ErrMessageIdentityCollision) {
		t.Fatalf("collision error = %v", err)
	}
	cursor, _ := store.GetSynchronizationCursor(context.Background(), commit.AccountID)
	if cursor.HistoryID != commit.Expected {
		t.Fatal("cursor moved after record collision")
	}
	if _, err := store.GetDiscoveredMessage(context.Background(), commit.AccountID, commit.Messages[0].GmailMessageID()); !errors.Is(err, storage.ErrMessageNotFound) {
		t.Fatalf("message lookup error = %v", err)
	}
}

func TestReconcileCurrentDiscoveryAbortsExactOpenAttempt(t *testing.T) {
	store, commit := activeDiscoveryStore(t)
	prepared, _ := storage.PrepareCurrentDiscoveryCommit(commit)
	store.mu.Lock()
	store.attempts[commit.AccountID] = &currentDiscoveryAttempt{prepared: prepared, state: "open", staged: prepared.Messages()[:1]}
	store.mu.Unlock()
	if err := store.ReconcileCurrentDiscovery(context.Background(), commit.AccountID); err != nil {
		t.Fatalf("ReconcileCurrentDiscovery() error = %v", err)
	}
	store.mu.Lock()
	attempt := store.attempts[commit.AccountID]
	store.mu.Unlock()
	if attempt != nil {
		t.Fatal("open noncanonical attempt survived exact abort")
	}
	cursor, _ := store.GetSynchronizationCursor(context.Background(), commit.AccountID)
	if cursor.HistoryID != commit.Expected {
		t.Fatal("open-attempt abort changed cursor")
	}
}

func TestReconcileCurrentDiscoveryRetainsOpenAttemptUntilActive(t *testing.T) {
	for _, state := range []storage.AccountState{storage.AccountStatePaused, storage.AccountStateReauthorizationRequired} {
		t.Run(state.String(), func(t *testing.T) {
			store, commit := activeDiscoveryStore(t)
			prepared, _ := storage.PrepareCurrentDiscoveryCommit(commit)
			store.mu.Lock()
			store.attempts[commit.AccountID] = &currentDiscoveryAttempt{prepared: prepared, state: "open", staged: prepared.Messages()[:1]}
			lifecycle := store.lifecycles[commit.AccountID]
			lifecycle.State = state
			store.lifecycles[commit.AccountID] = lifecycle
			store.mu.Unlock()
			if err := store.ReconcileCurrentDiscovery(context.Background(), commit.AccountID); !errors.Is(err, storage.ErrLifecycleConflict) {
				t.Fatalf("ReconcileCurrentDiscovery() error = %v", err)
			}
			store.mu.Lock()
			attempt := store.attempts[commit.AccountID]
			store.mu.Unlock()
			if attempt == nil {
				t.Fatal("open attempt was removed while lifecycle was inactive")
			}
		})
	}
}

func TestReconcileCurrentDiscoveryRetainsSealedAttemptUntilActive(t *testing.T) {
	store, commit := activeDiscoveryStore(t)
	prepared, _ := storage.PrepareCurrentDiscoveryCommit(commit)
	store.mu.Lock()
	store.attempts[commit.AccountID] = &currentDiscoveryAttempt{prepared: prepared, state: "sealed", staged: prepared.Messages()}
	lifecycle := store.lifecycles[commit.AccountID]
	lifecycle.State = storage.AccountStatePaused
	store.lifecycles[commit.AccountID] = lifecycle
	store.mu.Unlock()
	if err := store.ReconcileCurrentDiscovery(context.Background(), commit.AccountID); !errors.Is(err, storage.ErrLifecycleConflict) {
		t.Fatalf("paused reconcile error = %v", err)
	}
	store.mu.Lock()
	lifecycle = store.lifecycles[commit.AccountID]
	lifecycle.State = storage.AccountStateActive
	store.lifecycles[commit.AccountID] = lifecycle
	store.mu.Unlock()
	if err := store.ReconcileCurrentDiscovery(context.Background(), commit.AccountID); err != nil {
		t.Fatalf("active reconcile error = %v", err)
	}
	cursor, _ := store.GetSynchronizationCursor(context.Background(), commit.AccountID)
	if cursor.HistoryID != commit.Next {
		t.Fatal("sealed reconcile did not finalize cursor")
	}
}

func TestRevocationRemovesOnlyNoncanonicalCurrentDiscoveryAttempt(t *testing.T) {
	store, commit := activeDiscoveryStore(t)
	prepared, _ := storage.PrepareCurrentDiscoveryCommit(commit)
	store.mu.Lock()
	store.attempts[commit.AccountID] = &currentDiscoveryAttempt{prepared: prepared, state: "sealed", staged: prepared.Messages()}
	lifecycle := store.lifecycles[commit.AccountID]
	store.mu.Unlock()
	if err := store.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{
		AccountID: commit.AccountID, ExpectedState: lifecycle.State, ExpectedVersion: lifecycle.Version, ExpectedRevocationStatus: lifecycle.RevocationStatus,
		NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusPending,
	}); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	attempt := store.attempts[commit.AccountID]
	store.mu.Unlock()
	if attempt != nil {
		t.Fatal("revocation retained noncanonical staging")
	}
	cursor, _ := store.GetSynchronizationCursor(context.Background(), commit.AccountID)
	if cursor.HistoryID != commit.Expected {
		t.Fatal("revocation changed canonical cursor")
	}
}

func TestSynchronizationInitializationRejectsPresentCursorAndSealedAttempt(t *testing.T) {
	store, commit := activeDiscoveryStore(t)
	prepared, err := storage.PrepareCurrentDiscoveryCommit(commit)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	delete(store.cursors, commit.AccountID)
	store.attempts[commit.AccountID] = &currentDiscoveryAttempt{prepared: prepared, state: "sealed", staged: prepared.Messages()}
	store.mu.Unlock()
	if err := store.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: commit.AccountID, Next: commit.Expected}); !errors.Is(err, storage.ErrCursorConflict) {
		t.Fatalf("initialization with sealed attempt error = %v", err)
	}
	store.mu.Lock()
	delete(store.attempts, commit.AccountID)
	store.cursors[commit.AccountID] = commit.Expected
	store.mu.Unlock()
	if err := store.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: commit.AccountID, Next: commit.Expected}); !errors.Is(err, storage.ErrCursorConflict) {
		t.Fatalf("initialization over present cursor error = %v", err)
	}
}
