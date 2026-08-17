package storage_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/mandloideep/inboxgate/internal/storage"
	storagefake "github.com/mandloideep/inboxgate/internal/storage/fake"
)

func TestAccountValueContracts(t *testing.T) {
	t.Parallel()

	validID := "0123456789abcdef0123456789abcdef"
	if got, err := storage.ParseAccountID(validID); err != nil || got.String() != validID {
		t.Fatalf("ParseAccountID() = (%q, %v), want canonical value", got.String(), err)
	}
	for _, invalid := range []string{"", strings.Repeat("a", 31), strings.Repeat("a", 31) + "\x00", strings.Repeat("a", 32) + "\x00", strings.Repeat("a", 33), "0123456789abcdef0123456789abcdeF", "0123456789abcdef0123456789abcdeg"} {
		if _, err := storage.ParseAccountID(invalid); !errors.Is(err, storage.ErrInvalidValue) {
			t.Fatalf("ParseAccountID(%q) error = %v, want ErrInvalidValue", invalid, err)
		}
	}

	for _, valid := range []string{"!", "synthetic-subject", strings.Repeat("~", 255)} {
		if got, err := storage.ParseProviderSubject(valid); err != nil || got.String() != valid {
			t.Fatalf("ParseProviderSubject() = (%q, %v), want canonical value", got.String(), err)
		}
	}
	for _, invalid := range []string{"", " leading", "trailing ", "line\nbreak", "A\x00B", strings.Repeat("x", 256), "non-ascii-\u00e9"} {
		if _, err := storage.ParseProviderSubject(invalid); !errors.Is(err, storage.ErrInvalidValue) {
			t.Fatalf("ParseProviderSubject(%q) error = %v, want ErrInvalidValue", invalid, err)
		}
	}

	for _, valid := range []string{"1", "9", "10", "18446744073709551615"} {
		if got, err := storage.ParseHistoryID(valid); err != nil || got.String() != valid {
			t.Fatalf("ParseHistoryID(%q) = (%q, %v), want canonical value", valid, got.String(), err)
		}
	}
	for _, invalid := range []string{"", "0", "01", "+1", " 1", "1\x00x", "18446744073709551616", strings.Repeat("9", 21)} {
		if _, err := storage.ParseHistoryID(invalid); !errors.Is(err, storage.ErrInvalidValue) {
			t.Fatalf("ParseHistoryID(%q) error = %v, want ErrInvalidValue", invalid, err)
		}
	}
}

func TestFakeEnsureAccountIsIdempotentAndConflictSafe(t *testing.T) {
	t.Parallel()

	handle := storagefake.New()
	first := accountSeed(t, "0123456789abcdef0123456789abcdef", "subject-A")
	account, err := handle.EnsureAccount(context.Background(), first)
	if err != nil || account.ID != first.ID || account.ProviderSubject != first.ProviderSubject {
		t.Fatalf("EnsureAccount() = (%#v, %v), want inserted account", account, err)
	}
	account, err = handle.EnsureAccount(context.Background(), accountSeed(t, "11111111111111111111111111111111", "subject-A"))
	if err != nil || account.ID != first.ID {
		t.Fatalf("EnsureAccount() canonical identity = (%#v, %v), want first account", account, err)
	}
	_, err = handle.EnsureAccount(context.Background(), accountSeed(t, first.ID.String(), "subject-B"))
	if !errors.Is(err, storage.ErrAccountConflict) {
		t.Fatalf("EnsureAccount() conflict error = %v, want ErrAccountConflict", err)
	}
}

func TestFakeConcurrentEnsureAccountConverges(t *testing.T) {
	t.Parallel()

	handle := storagefake.New()
	seeds := []storage.AccountSeed{
		accountSeed(t, "22222222222222222222222222222222", "subject-concurrent"),
		accountSeed(t, "33333333333333333333333333333333", "subject-concurrent"),
	}
	start := make(chan struct{})
	results := make(chan storage.Account, len(seeds))
	errorsCh := make(chan error, len(seeds))
	var ready sync.WaitGroup
	ready.Add(len(seeds))
	for _, seed := range seeds {
		go func(seed storage.AccountSeed) {
			ready.Done()
			<-start
			account, err := handle.EnsureAccount(context.Background(), seed)
			results <- account
			errorsCh <- err
		}(seed)
	}
	ready.Wait()
	close(start)
	first := <-results
	second := <-results
	if err := <-errorsCh; err != nil {
		t.Fatalf("first EnsureAccount() error = %v", err)
	}
	if err := <-errorsCh; err != nil {
		t.Fatalf("second EnsureAccount() error = %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("concurrent account IDs = %q and %q, want convergence", first.ID, second.ID)
	}
}

func TestFakeSynchronizationCursorCASRules(t *testing.T) {
	t.Parallel()

	handle := storagefake.New()
	seed := accountSeed(t, "44444444444444444444444444444444", "subject-cursor")
	if _, err := handle.EnsureAccount(context.Background(), seed); err != nil {
		t.Fatalf("EnsureAccount() error = %v", err)
	}
	one := historyID(t, "1")
	two := historyID(t, "2")
	three := historyID(t, "3")
	if err := handle.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: seed.ID, Next: one}); err != nil {
		t.Fatalf("initial CommitSynchronization() error = %v", err)
	}
	cursor, err := handle.GetSynchronizationCursor(context.Background(), seed.ID)
	if err != nil || cursor.HistoryID != one {
		t.Fatalf("GetSynchronizationCursor() = (%#v, %v), want history 1", cursor, err)
	}
	if err := handle.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: seed.ID, Expected: &one, Next: two}); err != nil {
		t.Fatalf("advance CommitSynchronization() error = %v", err)
	}
	if err := handle.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: seed.ID, Expected: &one, Next: two}); err != nil {
		t.Fatalf("idempotent CommitSynchronization() error = %v", err)
	}
	if err := handle.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: seed.ID, Expected: &one, Next: three}); !errors.Is(err, storage.ErrCursorConflict) {
		t.Fatalf("stale CommitSynchronization() error = %v, want ErrCursorConflict", err)
	}
	if err := handle.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: seed.ID, Expected: &two, Next: one}); !errors.Is(err, storage.ErrCursorRegression) {
		t.Fatalf("regressing CommitSynchronization() error = %v, want ErrCursorRegression", err)
	}
	missing := accountID(t, "55555555555555555555555555555555")
	if err := handle.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: missing, Next: one}); !errors.Is(err, storage.ErrAccountNotFound) {
		t.Fatalf("missing-account CommitSynchronization() error = %v, want ErrAccountNotFound", err)
	}
}

func accountSeed(t *testing.T, id, subject string) storage.AccountSeed {
	t.Helper()
	return storage.AccountSeed{ID: accountID(t, id), ProviderSubject: providerSubject(t, subject)}
}

func accountID(t *testing.T, raw string) storage.AccountID {
	t.Helper()
	value, err := storage.ParseAccountID(raw)
	if err != nil {
		t.Fatalf("ParseAccountID() error = %v", err)
	}
	return value
}

func providerSubject(t *testing.T, raw string) storage.ProviderSubject {
	t.Helper()
	value, err := storage.ParseProviderSubject(raw)
	if err != nil {
		t.Fatalf("ParseProviderSubject() error = %v", err)
	}
	return value
}

func historyID(t *testing.T, raw string) storage.HistoryID {
	t.Helper()
	value, err := storage.ParseHistoryID(raw)
	if err != nil {
		t.Fatalf("ParseHistoryID() error = %v", err)
	}
	return value
}
