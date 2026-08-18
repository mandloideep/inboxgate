package turso

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/storage"
)

const (
	accountIDA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	accountIDB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	subjectA   = "synthetic-subject-A"
)

func TestEnsureAccountUsesExactParameterizedDriverContractAndSeparateProof(t *testing.T) {
	server := newMigrationProtocolServer(t)
	handle := openPersistenceContractHandle(t, server.URL)
	seed := persistenceSeed(t, accountIDA, subjectA)
	account, err := handle.EnsureAccount(context.Background(), seed)
	if err != nil || account.ID != seed.ID || account.ProviderSubject != seed.ProviderSubject {
		t.Fatalf("EnsureAccount() = (%#v, %v), want durable account", account, err)
	}
	records := server.persistenceRecords()
	if len(records) != 3 {
		t.Fatalf("persistence requests = %d, want preflight, insert, and verification", len(records))
	}
	assertProtocolStatement(t, records[0], accountLookupSQL, []protocolValue{
		textProtocolValue(accountIDA), textProtocolValue(storage.ProviderGmail), textProtocolValue(subjectA),
	})
	assertProtocolStatement(t, records[1], accountInsertSQL, []protocolValue{
		textProtocolValue(accountIDA), textProtocolValue(subjectA),
	})
	assertProtocolStatement(t, records[2], accountLookupSQL, []protocolValue{
		textProtocolValue(accountIDA), textProtocolValue(storage.ProviderGmail), textProtocolValue(subjectA),
	})
	for _, dynamic := range []string{accountIDA, subjectA} {
		if strings.Contains(accountInsertSQL, dynamic) || strings.Contains(accountLookupSQL, dynamic) {
			t.Fatalf("fixed SQL contains dynamic value %q", dynamic)
		}
	}
	if records[0].baton != nil || records[1].baton == nil || records[2].baton != nil {
		t.Fatalf("connection batons = (%v, %v, %v), want verification on a separate physical stream", records[0].baton, records[1].baton, records[2].baton)
	}

	canonical, err := handle.EnsureAccount(context.Background(), persistenceSeed(t, accountIDB, subjectA))
	if err != nil || canonical.ID != seed.ID {
		t.Fatalf("idempotent EnsureAccount() = (%#v, %v), want canonical first ID", canonical, err)
	}
	if got := countPersistenceSQL(server.persistenceRecords(), accountInsertSQL); got != 1 {
		t.Fatalf("insert attempts = %d, want one", got)
	}
}

func TestEnsureAccountRejectsCrossedIdentityWithoutMutation(t *testing.T) {
	server := newMigrationProtocolServer(t)
	server.seedAccount(accountIDA, subjectA)
	server.seedAccount(accountIDB, "synthetic-subject-B")
	handle := openPersistenceContractHandle(t, server.URL)
	_, err := handle.EnsureAccount(context.Background(), persistenceSeed(t, accountIDA, "synthetic-subject-B"))
	if !errors.Is(err, storage.ErrAccountConflict) {
		t.Fatalf("EnsureAccount() error = %v, want ErrAccountConflict", err)
	}
	if got := countPersistenceSQL(server.persistenceRecords(), accountInsertSQL); got != 0 {
		t.Fatalf("insert attempts = %d, want 0", got)
	}
}

func TestEnsureAccountUncertainWritesAreProvedOrReconciledWithoutReplay(t *testing.T) {
	tests := []struct {
		name        string
		mode        string
		wantSuccess bool
	}{
		{name: "drop before durability", mode: "drop-before"},
		{name: "clean eof before durability", mode: "clean-eof"},
		{name: "step begin eof before durability", mode: "step-begin-before"},
		{name: "successful response without mutation", mode: "success-without-apply"},
		{name: "drop after durability", mode: "drop-after", wantSuccess: true},
		{name: "malformed after durability", mode: "malformed-after", wantSuccess: true},
		{name: "step begin eof after durability", mode: "step-begin-after", wantSuccess: true},
		{name: "zero affected after durability", mode: "apply-zero-affected", wantSuccess: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			server.armPersistenceResponse(accountInsertSQL, tt.mode)
			handle := openPersistenceContractHandle(t, server.URL)
			seed := persistenceSeed(t, accountIDA, subjectA)
			_, err := handle.EnsureAccount(context.Background(), seed)
			if tt.wantSuccess {
				if err != nil {
					t.Fatalf("EnsureAccount() error = %v, want separately proved success", err)
				}
			} else if !errors.Is(err, storage.ErrPersistenceUnknown) {
				t.Fatalf("EnsureAccount() error = %v, want ErrPersistenceUnknown", err)
			}
			if got := countPersistenceSQL(server.persistenceRecords(), accountInsertSQL); got != 1 {
				t.Fatalf("same-invocation insert attempts = %d, want 1", got)
			}
			account, freshErr := handle.EnsureAccount(context.Background(), seed)
			if freshErr != nil || account.ID != seed.ID {
				t.Fatalf("fresh EnsureAccount() = (%#v, %v), want reconciliation", account, freshErr)
			}
			wantAttempts := 1
			if !tt.wantSuccess {
				wantAttempts = 2
			}
			if got := countPersistenceSQL(server.persistenceRecords(), accountInsertSQL); got != wantAttempts {
				t.Fatalf("insert attempts across invocations = %d, want %d", got, wantAttempts)
			}
			if tt.mode == "step-begin-before" {
				baton := firstMutationBaton(t, server.persistenceRecords(), accountInsertSQL)
				if got := server.cursorSessionCloseCount(baton); got != 1 {
					t.Fatalf("unproven account session close requests = %d, want 1", got)
				}
				if !server.cursorSessionWasClosedWithoutReuse(baton) {
					t.Fatalf("unproven account session %q was not closed and excluded from later reuse", baton)
				}
			}
		})
	}
}

func TestSynchronizationCursorInitializationAndDurabilityContract(t *testing.T) {
	server := newMigrationProtocolServer(t)
	server.seedAccount(accountIDA, subjectA)
	handle := openPersistenceContractHandle(t, server.URL)
	one := persistenceHistoryID(t, "1")
	commit := storage.SynchronizationCommit{AccountID: persistenceAccountID(t, accountIDA), Next: one}
	if err := handle.CommitSynchronization(context.Background(), commit); err != nil {
		t.Fatalf("initial CommitSynchronization() error = %v", err)
	}
	cursor, err := handle.GetSynchronizationCursor(context.Background(), commit.AccountID)
	if err != nil || cursor.HistoryID != one {
		t.Fatalf("GetSynchronizationCursor() = (%#v, %v), want history 1", cursor, err)
	}
	if err := handle.CommitSynchronization(context.Background(), commit); !errors.Is(err, storage.ErrCursorConflict) {
		t.Fatalf("present-cursor initialization error = %v", err)
	}
	records := server.persistenceRecords()
	if got := countPersistenceSQL(records, cursorCommitSQL); got != 1 {
		t.Fatalf("cursor mutation attempts = %d, want one initialization only", got)
	}
	mutations := make([]migrationRequest, 0, 1)
	for _, record := range records {
		if record.sql == cursorCommitSQL {
			mutations = append(mutations, record)
		}
	}
	assertProtocolStatement(t, mutations[0], cursorCommitSQL, []protocolValue{
		textProtocolValue(accountIDA), textProtocolValue("1"), textProtocolValue(accountIDA), textProtocolValue(accountIDA), textProtocolValue(accountIDA),
	})
	for index, record := range records {
		if record.sql == cursorCommitSQL && index+1 < len(records) && records[index+1].sql == cursorLookupSQL {
			if record.baton == nil || records[index+1].baton != nil {
				t.Fatalf("cursor mutation and verification batons = (%v, %v), want separate physical streams", record.baton, records[index+1].baton)
			}
			break
		}
	}
	for _, dynamic := range []string{accountIDA} {
		if strings.Contains(cursorCommitSQL, dynamic) {
			t.Fatalf("fixed cursor SQL contains dynamic value %q", dynamic)
		}
	}
}

func TestSynchronizationCursorRejectsExpectedPresentAndMissingBeforeMutation(t *testing.T) {
	server := newMigrationProtocolServer(t)
	server.seedAccount(accountIDA, subjectA)
	server.seedAccount(accountIDB, "synthetic-subject-B")
	server.seedCursor(accountIDA, "10")
	handle := openPersistenceContractHandle(t, server.URL)
	id := persistenceAccountID(t, accountIDA)
	ten := persistenceHistoryID(t, "10")
	eleven := persistenceHistoryID(t, "11")
	if err := handle.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: id, Expected: &ten, Next: eleven}); !errors.Is(err, storage.ErrInvalidValue) {
		t.Fatalf("expected-cursor initialization error = %v, want ErrInvalidValue", err)
	}
	if err := handle.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: id, Next: eleven}); !errors.Is(err, storage.ErrCursorConflict) {
		t.Fatalf("present cursor error = %v, want ErrCursorConflict", err)
	}
	missing := persistenceAccountID(t, accountIDB)
	if err := handle.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: missing, Expected: &ten, Next: eleven}); !errors.Is(err, storage.ErrInvalidValue) {
		t.Fatalf("non-nil expected error = %v, want ErrInvalidValue", err)
	}
	unknown := persistenceAccountID(t, "cccccccccccccccccccccccccccccccc")
	if err := handle.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: unknown, Next: eleven}); !errors.Is(err, storage.ErrAccountNotFound) {
		t.Fatalf("missing-account error = %v, want ErrAccountNotFound", err)
	}
	if got := countPersistenceSQL(server.persistenceRecords(), cursorCommitSQL); got != 0 {
		t.Fatalf("cursor mutation attempts = %d, want 0", got)
	}
}

func TestCursorUncertainWritesUseSeparateVisibilityAndNoSameInvocationReplay(t *testing.T) {
	tests := []struct {
		name        string
		mode        string
		wantSuccess bool
	}{
		{name: "drop before durability", mode: "drop-before"},
		{name: "clean eof before durability", mode: "clean-eof"},
		{name: "step begin eof before durability", mode: "step-begin-before"},
		{name: "successful response without mutation", mode: "success-without-apply"},
		{name: "drop after durability", mode: "drop-after", wantSuccess: true},
		{name: "malformed after durability", mode: "malformed-after", wantSuccess: true},
		{name: "step begin eof after durability", mode: "step-begin-after", wantSuccess: true},
		{name: "zero affected after durability", mode: "apply-zero-affected", wantSuccess: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			server.seedAccount(accountIDA, subjectA)
			server.armPersistenceResponse(cursorCommitSQL, tt.mode)
			handle := openPersistenceContractHandle(t, server.URL)
			commit := storage.SynchronizationCommit{AccountID: persistenceAccountID(t, accountIDA), Next: persistenceHistoryID(t, "20")}
			err := handle.CommitSynchronization(context.Background(), commit)
			if tt.wantSuccess {
				if err != nil {
					t.Fatalf("CommitSynchronization() error = %v, want separately proved success", err)
				}
			} else if !errors.Is(err, storage.ErrPersistenceUnknown) {
				t.Fatalf("CommitSynchronization() error = %v, want ErrPersistenceUnknown", err)
			}
			if got := countPersistenceSQL(server.persistenceRecords(), cursorCommitSQL); got != 1 {
				t.Fatalf("same-invocation cursor attempts = %d, want 1", got)
			}
			freshErr := handle.CommitSynchronization(context.Background(), commit)
			if tt.wantSuccess && !errors.Is(freshErr, storage.ErrCursorConflict) {
				t.Fatalf("fresh durable initialization error = %v, want conflict", freshErr)
			}
			if !tt.wantSuccess && freshErr != nil {
				t.Fatalf("fresh unresolved initialization error = %v", freshErr)
			}
			wantAttempts := 1
			if !tt.wantSuccess {
				wantAttempts = 2
			}
			if got := countPersistenceSQL(server.persistenceRecords(), cursorCommitSQL); got != wantAttempts {
				t.Fatalf("cursor attempts across invocations = %d, want %d", got, wantAttempts)
			}
			if tt.mode == "step-begin-before" {
				baton := firstMutationBaton(t, server.persistenceRecords(), cursorCommitSQL)
				if got := server.cursorSessionCloseCount(baton); got != 1 {
					t.Fatalf("unproven cursor session close requests = %d, want 1", got)
				}
				if !server.cursorSessionWasClosedWithoutReuse(baton) {
					t.Fatalf("unproven cursor session %q was not closed and excluded from later reuse", baton)
				}
			}
		})
	}
}

func TestPersistenceInspectionRejectsIncompleteMalformedOversizedAndRawFaults(t *testing.T) {
	tests := []struct {
		name string
		mode string
	}{
		{name: "clean eof", mode: "clean-eof"},
		{name: "malformed", mode: "malformed-after"},
		{name: "oversized semantic rows", mode: "oversized"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			server.armPersistenceResponse(accountLookupSQL, tt.mode)
			handle := openPersistenceContractHandle(t, server.URL)
			_, err := handle.EnsureAccount(context.Background(), persistenceSeed(t, accountIDA, subjectA))
			if !errors.Is(err, storage.ErrPersistenceInspect) {
				t.Fatalf("EnsureAccount() error = %v, want ErrPersistenceInspect", err)
			}
			if got := countPersistenceSQL(server.persistenceRecords(), accountInsertSQL); got != 0 {
				t.Fatalf("insert attempts = %d, want 0", got)
			}
		})
	}

	server := newMigrationProtocolServer(t)
	server.failNextSQL(accountLookupSQL)
	handle := openPersistenceContractHandle(t, server.URL)
	_, err := handle.EnsureAccount(context.Background(), persistenceSeed(t, accountIDA, subjectA))
	if !errors.Is(err, storage.ErrPersistenceInspect) {
		t.Fatalf("raw-fault EnsureAccount() error = %v, want ErrPersistenceInspect", err)
	}
	for _, raw := range []string{"raw", "synthetic-token", "SELECT", "private marker"} {
		if strings.Contains(err.Error(), raw) {
			t.Fatalf("sanitized error %q contains raw marker", err)
		}
	}
}

func TestPersistenceInspectionRejectsWrongTypesValuesAndRowCounts(t *testing.T) {
	tests := []struct {
		name      string
		statement string
		rows      [][]any
		cursor    bool
	}{
		{name: "text sentinel", statement: accountLookupSQL, rows: [][]any{{textValue("1"), integerValue(0), nullValue(), nullValue(), nullValue(), integerValue(0), nullValue(), nullValue(), nullValue()}}},
		{name: "text count", statement: accountLookupSQL, rows: [][]any{{integerValue(1), textValue("0"), nullValue(), nullValue(), nullValue(), integerValue(0), nullValue(), nullValue(), nullValue()}}},
		{name: "invalid provider", statement: accountLookupSQL, rows: [][]any{{integerValue(1), integerValue(1), textValue(accountIDA), textValue("other"), textValue(subjectA), integerValue(0), nullValue(), nullValue(), nullValue()}}},
		{name: "invalid subject", statement: accountLookupSQL, rows: [][]any{{integerValue(1), integerValue(1), textValue(accountIDA), textValue(storage.ProviderGmail), textValue("line\nbreak"), integerValue(0), nullValue(), nullValue(), nullValue()}}},
		{name: "duplicate sentinel", statement: accountLookupSQL, rows: [][]any{
			{integerValue(1), integerValue(0), nullValue(), nullValue(), nullValue(), integerValue(0), nullValue(), nullValue(), nullValue()},
			{integerValue(1), integerValue(0), nullValue(), nullValue(), nullValue(), integerValue(0), nullValue(), nullValue(), nullValue()},
		}},
		{name: "invalid history", statement: cursorLookupSQL, cursor: true, rows: [][]any{{integerValue(1), integerValue(1), textValue(accountIDA), integerValue(1), textValue(accountIDA), textValue("01")}}},
		{name: "cursor without account", statement: cursorLookupSQL, cursor: true, rows: [][]any{{integerValue(1), integerValue(0), nullValue(), integerValue(1), textValue(accountIDA), textValue("1")}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			server.seedAccount(accountIDA, subjectA)
			server.overridePersistenceRows(tt.statement, tt.rows)
			handle := openPersistenceContractHandle(t, server.URL)
			var err error
			if tt.cursor {
				_, err = handle.GetSynchronizationCursor(context.Background(), persistenceAccountID(t, accountIDA))
			} else {
				_, err = handle.EnsureAccount(context.Background(), persistenceSeed(t, accountIDA, subjectA))
			}
			if !errors.Is(err, storage.ErrPersistenceInspect) {
				t.Fatalf("operation error = %v, want ErrPersistenceInspect", err)
			}
		})
	}
}

func TestAccountAndCursorLookupResponseMatrixFailsClosed(t *testing.T) {
	absentAccountRow := []any{integerValue(1), integerValue(0), nullValue(), nullValue(), nullValue(), integerValue(0), nullValue(), nullValue(), nullValue()}
	absentCursorRow := []any{integerValue(1), integerValue(1), textValue(accountIDA), integerValue(0), nullValue(), nullValue()}
	tests := []struct {
		name      string
		statement string
		mode      string
		rows      [][]any
		columns   int
		cursor    bool
	}{
		{name: "account missing sentinel", statement: accountLookupSQL, mode: "success-without-apply"},
		{name: "account malformed body", statement: accountLookupSQL, mode: "malformed-after"},
		{name: "account missing column", statement: accountLookupSQL, rows: [][]any{absentAccountRow[:8]}, columns: 8},
		{name: "account extra column", statement: accountLookupSQL, rows: [][]any{append(append([]any{}, absentAccountRow...), nullValue())}, columns: 10},
		{name: "account duplicate rows", statement: accountLookupSQL, rows: [][]any{absentAccountRow, absentAccountRow}},
		{name: "account excess rows", statement: accountLookupSQL, mode: "oversized"},
		{name: "account oversized value", statement: accountLookupSQL, rows: [][]any{{integerValue(1), integerValue(1), textValue(accountIDA), textValue(storage.ProviderGmail), textValue(strings.Repeat("x", 256)), integerValue(0), nullValue(), nullValue(), nullValue()}}},
		{name: "cursor missing sentinel", statement: cursorLookupSQL, mode: "success-without-apply", cursor: true},
		{name: "cursor malformed body", statement: cursorLookupSQL, mode: "malformed-after", cursor: true},
		{name: "cursor missing column", statement: cursorLookupSQL, rows: [][]any{absentCursorRow[:5]}, columns: 5, cursor: true},
		{name: "cursor extra column", statement: cursorLookupSQL, rows: [][]any{append(append([]any{}, absentCursorRow...), nullValue())}, columns: 7, cursor: true},
		{name: "cursor duplicate rows", statement: cursorLookupSQL, rows: [][]any{absentCursorRow, absentCursorRow}, cursor: true},
		{name: "cursor excess rows", statement: cursorLookupSQL, mode: "oversized", cursor: true},
		{name: "cursor oversized value", statement: cursorLookupSQL, rows: [][]any{{integerValue(1), integerValue(1), textValue(accountIDA), integerValue(1), textValue(accountIDA), textValue(strings.Repeat("9", 21))}}, cursor: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			server.seedAccount(accountIDA, subjectA)
			if tt.mode != "" {
				server.armPersistenceResponse(tt.statement, tt.mode)
			} else {
				server.overridePersistenceRows(tt.statement, tt.rows)
			}
			if tt.columns != 0 {
				columns := make([]any, tt.columns)
				for index := range columns {
					columns[index] = map[string]any{"name": fmt.Sprintf("column_%d", index), "decltype": "TEXT"}
				}
				server.overridePersistenceColumns(tt.statement, columns)
			}
			handle := openPersistenceContractHandle(t, server.URL)
			var err error
			if tt.cursor {
				_, err = handle.GetSynchronizationCursor(context.Background(), persistenceAccountID(t, accountIDA))
			} else {
				_, err = handle.EnsureAccount(context.Background(), persistenceSeed(t, accountIDB, "synthetic-subject-B"))
			}
			if !errors.Is(err, storage.ErrPersistenceInspect) {
				t.Fatalf("operation error = %v, want ErrPersistenceInspect", err)
			}
			for _, marker := range []string{strings.Repeat("x", 256), strings.Repeat("9", 21)} {
				if strings.Contains(err.Error(), marker) {
					t.Fatalf("operation error %q reflected oversized value", err)
				}
			}
			if got := countPersistenceSQL(server.persistenceRecords(), accountInsertSQL) + countPersistenceSQL(server.persistenceRecords(), cursorCommitSQL); got != 0 {
				t.Fatalf("mutation attempts = %d, want 0 after lookup rejection", got)
			}
		})
	}
}

func TestPersistenceCancellationAfterMutationStartsIsBoundedAndNeverReplayed(t *testing.T) {
	server := newMigrationProtocolServer(t)
	started, release := server.stallPersistence(accountInsertSQL)
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	handle := openPersistenceContractHandle(t, server.URL)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := handle.EnsureAccount(ctx, persistenceSeed(t, accountIDA, subjectA))
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("EnsureAccount() did not reach the named mutation stage")
	}
	canceledAt := time.Now()
	cancel()
	var err error
	select {
	case err = <-result:
	case <-time.After(time.Second):
		t.Fatal("EnsureAccount() did not return after cancellation")
	}
	if elapsed := time.Since(canceledAt); elapsed >= 500*time.Millisecond {
		t.Fatalf("EnsureAccount() cancellation elapsed = %v, want bounded return", elapsed)
	}
	if !errors.Is(err, storage.ErrPersistenceUnknown) || !errors.Is(err, context.Canceled) {
		t.Fatalf("EnsureAccount() error = %v, want unknown outcome with cancellation", err)
	}
	if got := countPersistenceSQL(server.persistenceRecords(), accountInsertSQL); got != 1 {
		t.Fatalf("same-invocation insert attempts = %d, want 1", got)
	}
	releaseOnce.Do(func() { close(release) })
}

func TestEnsureAccountProtocolBaseURLCanChangeAuthority(t *testing.T) {
	var destinationRequests atomic.Int32
	var mutationRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destinationRequests.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("credential-free persistence request sent an Authorization header")
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			t.Errorf("read changed-authority request: %v", err)
		}
		if strings.Contains(string(body), accountInsertSQL) {
			mutationRequests.Add(1)
		}
		http.Error(w, "raw changed-authority account marker", http.StatusBadGateway)
	}))
	t.Cleanup(destination.Close)

	server := newMigrationProtocolServer(t)
	server.redirectNextCursorBaseURL(destination.URL)
	handle := openPersistenceContractHandle(t, server.URL)
	_, err := handle.EnsureAccount(context.Background(), persistenceSeed(t, accountIDA, subjectA))
	if !errors.Is(err, storage.ErrPersistenceUnknown) {
		t.Fatalf("EnsureAccount() error = %v, want ErrPersistenceUnknown", err)
	}
	if destinationRequests.Load() == 0 {
		t.Fatal("driver did not follow persistence protocol base_url authority")
	}
	if mutationRequests.Load() != 1 {
		t.Fatalf("changed-authority mutation requests = %d, want 1 without replay", mutationRequests.Load())
	}
	for _, raw := range []string{"changed-authority", accountIDA, subjectA} {
		if strings.Contains(err.Error(), raw) {
			t.Fatalf("sanitized error %q contains raw marker", err)
		}
	}
}

func TestEnsureAccountDriverFollowsCredentialFreeRedirect(t *testing.T) {
	var redirectedRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedRequests.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("credential-free redirected request sent an Authorization header")
		}
		http.Error(w, "raw redirect account marker", http.StatusBadGateway)
	}))
	t.Cleanup(destination.Close)
	initial := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(initial.Close)

	handle := openPersistenceContractHandle(t, initial.URL)
	_, err := handle.EnsureAccount(context.Background(), persistenceSeed(t, accountIDA, subjectA))
	if !errors.Is(err, storage.ErrPersistenceInspect) {
		t.Fatalf("EnsureAccount() error = %v, want ErrPersistenceInspect", err)
	}
	if redirectedRequests.Load() != 1 {
		t.Fatalf("redirected persistence requests = %d, want 1 without replay", redirectedRequests.Load())
	}
	for _, raw := range []string{"redirect account", accountIDA, subjectA} {
		if strings.Contains(err.Error(), raw) {
			t.Fatalf("sanitized error %q contains raw marker", err)
		}
	}
}

func TestPersistenceRejectsDriverBufferedOversizedSuccessfulValues(t *testing.T) {
	tests := []struct {
		name      string
		statement string
		rows      [][]any
		cursor    bool
	}{
		{
			name:      "account subject",
			statement: accountLookupSQL,
			rows: [][]any{{
				integerValue(1), integerValue(1), textValue(accountIDA), textValue(storage.ProviderGmail), textValue(strings.Repeat("x", 1<<20)),
				integerValue(0), nullValue(), nullValue(), nullValue(),
			}},
		},
		{
			name:      "cursor history",
			statement: cursorLookupSQL,
			rows: [][]any{{
				integerValue(1), integerValue(1), textValue(accountIDA), integerValue(1), textValue(accountIDA), textValue(strings.Repeat("9", 1<<20)),
			}},
			cursor: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			server.seedAccount(accountIDA, subjectA)
			server.overridePersistenceRows(tt.statement, tt.rows)
			handle := openPersistenceContractHandle(t, server.URL)
			var err error
			if tt.cursor {
				_, err = handle.GetSynchronizationCursor(context.Background(), persistenceAccountID(t, accountIDA))
			} else {
				_, err = handle.EnsureAccount(context.Background(), persistenceSeed(t, accountIDA, subjectA))
			}
			if !errors.Is(err, storage.ErrPersistenceInspect) {
				t.Fatalf("operation error = %v, want ErrPersistenceInspect", err)
			}
			if len(err.Error()) > 128 {
				t.Fatalf("sanitized error length = %d, want bounded category", len(err.Error()))
			}
			if got := countPersistenceSQL(server.persistenceRecords(), accountInsertSQL) + countPersistenceSQL(server.persistenceRecords(), cursorCommitSQL); got != 0 {
				t.Fatalf("mutation attempts = %d, want 0", got)
			}
		})
	}
}

func TestPersistenceRejectsRemoteOrCredentialedHandlesBeforeConnection(t *testing.T) {
	database := &migrationFakeDatabase{}
	adapter, err := newAdapter(Options{PersistenceTimeout: time.Second}, func(string, string) databaseHandle { return database })
	if err != nil {
		t.Fatalf("newAdapter() error = %v", err)
	}
	for _, endpoint := range []storage.Endpoint{
		{URL: "https://database.example", Token: "synthetic-token"},
		{URL: "https://database.example"},
	} {
		handle, openErr := adapter.Open(context.Background(), endpoint)
		if openErr != nil {
			t.Fatalf("Open() error = %v", openErr)
		}
		_, operationErr := handle.EnsureAccount(context.Background(), persistenceSeed(t, accountIDA, subjectA))
		if !errors.Is(operationErr, storage.ErrPersistenceNotAllowed) {
			t.Fatalf("EnsureAccount() error = %v, want ErrPersistenceNotAllowed", operationErr)
		}
	}
	if calls := database.connCalls.Load(); calls != 0 {
		t.Fatalf("connection attempts = %d, want 0", calls)
	}
}

func TestPersistenceConnectionAndCanceledContextFailuresAreSanitized(t *testing.T) {
	raw := "raw synthetic-token SELECT private account marker"
	database := &migrationFakeDatabase{conn: func(context.Context) (*sql.Conn, error) {
		return nil, errors.New(raw)
	}}
	adapter, err := newAdapter(Options{PersistenceTimeout: time.Second}, func(string, string) databaseHandle { return database })
	if err != nil {
		t.Fatalf("newAdapter() error = %v", err)
	}
	handle, err := adapter.Open(context.Background(), storage.Endpoint{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	_, err = handle.EnsureAccount(context.Background(), persistenceSeed(t, accountIDA, subjectA))
	if !errors.Is(err, storage.ErrPersistenceAcquire) {
		t.Fatalf("EnsureAccount() error = %v, want ErrPersistenceAcquire", err)
	}
	if strings.Contains(err.Error(), raw) {
		t.Fatalf("EnsureAccount() error %q contains raw diagnostic", err)
	}

	server := newMigrationProtocolServer(t)
	exactHandle := openPersistenceContractHandle(t, server.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = exactHandle.EnsureAccount(ctx, persistenceSeed(t, accountIDA, subjectA))
	if !errors.Is(err, storage.ErrPersistenceAcquire) || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled EnsureAccount() error = %v, want acquire category and context cancellation", err)
	}
	if got := len(server.persistenceRecords()); got != 0 {
		t.Fatalf("canceled persistence requests = %d, want 0", got)
	}
}

func TestPersistenceRejectsInvalidTypedValuesBeforeAnyRequest(t *testing.T) {
	server := newMigrationProtocolServer(t)
	handle := openPersistenceContractHandle(t, server.URL)
	if _, err := handle.EnsureAccount(context.Background(), storage.AccountSeed{}); !errors.Is(err, storage.ErrInvalidValue) {
		t.Fatalf("EnsureAccount() error = %v, want ErrInvalidValue", err)
	}
	if _, err := handle.GetSynchronizationCursor(context.Background(), storage.AccountID{}); !errors.Is(err, storage.ErrInvalidValue) {
		t.Fatalf("GetSynchronizationCursor() error = %v, want ErrInvalidValue", err)
	}
	if err := handle.CommitSynchronization(context.Background(), storage.SynchronizationCommit{}); !errors.Is(err, storage.ErrInvalidValue) {
		t.Fatalf("CommitSynchronization() error = %v, want ErrInvalidValue", err)
	}
	if got := len(server.persistenceRecords()); got != 0 {
		t.Fatalf("invalid-value persistence requests = %d, want 0", got)
	}
}

func TestConcurrentAccountAndCursorOperationsConverge(t *testing.T) {
	server := newMigrationProtocolServer(t)
	handle := openPersistenceContractHandle(t, server.URL)
	started, release := server.stallPersistence(accountInsertSQL)
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	results := make(chan storage.Account, 2)
	errorsCh := make(chan error, 2)
	go func() {
		account, err := handle.EnsureAccount(context.Background(), persistenceSeed(t, accountIDA, subjectA))
		results <- account
		errorsCh <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first EnsureAccount() did not reach the named insert stage")
	}
	go func() {
		account, err := handle.EnsureAccount(context.Background(), persistenceSeed(t, accountIDB, subjectA))
		results <- account
		errorsCh <- err
	}()
	releaseOnce.Do(func() { close(release) })
	first, second := <-results, <-results
	if err := <-errorsCh; err != nil {
		t.Fatalf("concurrent EnsureAccount() error = %v", err)
	}
	if err := <-errorsCh; err != nil {
		t.Fatalf("concurrent EnsureAccount() error = %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("concurrent identities = %q and %q, want convergence", first.ID, second.ID)
	}

	two, three := persistenceHistoryID(t, "2"), persistenceHistoryID(t, "3")
	start := make(chan struct{})
	commitErrors := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for _, next := range []storage.HistoryID{two, three} {
		go func(next storage.HistoryID) {
			ready.Done()
			<-start
			commitErrors <- handle.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: first.ID, Next: next})
		}(next)
	}
	ready.Wait()
	close(start)
	successes := 0
	for range 2 {
		if err := <-commitErrors; err == nil {
			successes++
		} else if !errors.Is(err, storage.ErrCursorConflict) && !errors.Is(err, storage.ErrPersistenceUnknown) {
			t.Fatalf("concurrent CommitSynchronization() error = %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent cursor successes = %d, want 1", successes)
	}
}

func runAccountCursorBehaviorContract(t *testing.T, handle storage.Handle) {
	t.Helper()
	accountA, err := handle.EnsureAccount(context.Background(), persistenceSeed(t, accountIDA, subjectA))
	if err != nil || accountA.ID.String() != accountIDA {
		t.Fatalf("EnsureAccount(A) = (%#v, %v), want account A", accountA, err)
	}
	accountB, err := handle.EnsureAccount(context.Background(), persistenceSeed(t, accountIDB, "synthetic-subject-B"))
	if err != nil || accountB.ID.String() != accountIDB {
		t.Fatalf("EnsureAccount(B) = (%#v, %v), want account B", accountB, err)
	}
	if _, err := handle.EnsureAccount(context.Background(), persistenceSeed(t, accountIDA, "synthetic-subject-B")); !errors.Is(err, storage.ErrAccountConflict) {
		t.Fatalf("crossed EnsureAccount() error = %v, want ErrAccountConflict", err)
	}
	if _, err := handle.GetSynchronizationCursor(context.Background(), accountB.ID); !errors.Is(err, storage.ErrCursorNotFound) {
		t.Fatalf("absent GetSynchronizationCursor() error = %v, want ErrCursorNotFound", err)
	}
	one := persistenceHistoryID(t, "1")
	if err := handle.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: accountB.ID, Expected: &one, Next: one}); !errors.Is(err, storage.ErrInvalidValue) {
		t.Fatalf("non-nil expected initialization error = %v, want ErrInvalidValue", err)
	}
	if err := handle.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: accountA.ID, Next: one}); err != nil {
		t.Fatalf("initial CommitSynchronization() error = %v", err)
	}
	cursor, err := handle.GetSynchronizationCursor(context.Background(), accountA.ID)
	if err != nil || cursor.HistoryID != one {
		t.Fatalf("GetSynchronizationCursor() = (%#v, %v), want history 1", cursor, err)
	}
	if err := handle.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: accountA.ID, Next: one}); !errors.Is(err, storage.ErrCursorConflict) {
		t.Fatalf("present-cursor initialization error = %v", err)
	}
	two := persistenceHistoryID(t, "2")
	three := persistenceHistoryID(t, "3")
	start := make(chan struct{})
	ready := make(chan struct{}, 2)
	results := make(chan error, 2)
	for _, next := range []storage.HistoryID{two, three} {
		go func(next storage.HistoryID) {
			ready <- struct{}{}
			<-start
			results <- handle.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: accountB.ID, Next: next})
		}(next)
	}
	<-ready
	<-ready
	close(start)
	successes := 0
	for range 2 {
		err := <-results
		if err == nil {
			successes++
			continue
		}
		if !errors.Is(err, storage.ErrCursorConflict) && !errors.Is(err, storage.ErrPersistenceUnknown) {
			t.Fatalf("concurrent CommitSynchronization() error = %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent CommitSynchronization() successes = %d, want 1", successes)
	}
	cursor, err = handle.GetSynchronizationCursor(context.Background(), accountB.ID)
	if err != nil || (cursor.HistoryID != two && cursor.HistoryID != three) {
		t.Fatalf("final GetSynchronizationCursor() = (%#v, %v), want history 2 or 3", cursor, err)
	}
}

func openPersistenceContractHandle(t *testing.T, endpoint string) storage.Handle {
	t.Helper()
	return openMigrationContractHandleOptions(t, endpoint, Options{
		PingTimeout:        5 * time.Second,
		MigrationTimeout:   5 * time.Second,
		CleanupTimeout:     5 * time.Second,
		PersistenceTimeout: 5 * time.Second,
	})
}

func persistenceSeed(t *testing.T, id, subject string) storage.AccountSeed {
	t.Helper()
	return storage.AccountSeed{ID: persistenceAccountID(t, id), ProviderSubject: persistenceSubject(t, subject)}
}

func persistenceAccountID(t *testing.T, raw string) storage.AccountID {
	t.Helper()
	id, err := storage.ParseAccountID(raw)
	if err != nil {
		t.Fatalf("ParseAccountID() error = %v", err)
	}
	return id
}

func persistenceSubject(t *testing.T, raw string) storage.ProviderSubject {
	t.Helper()
	subject, err := storage.ParseProviderSubject(raw)
	if err != nil {
		t.Fatalf("ParseProviderSubject() error = %v", err)
	}
	return subject
}

func persistenceHistoryID(t *testing.T, raw string) storage.HistoryID {
	t.Helper()
	historyID, err := storage.ParseHistoryID(raw)
	if err != nil {
		t.Fatalf("ParseHistoryID() error = %v", err)
	}
	return historyID
}

func assertProtocolStatement(t *testing.T, got migrationRequest, wantSQL string, wantArgs []protocolValue) {
	t.Helper()
	if got.sql != wantSQL || got.namedArgCount != 0 {
		t.Fatal("driver SQL or named arguments differ from exact contract")
	}
	if len(got.args) != len(wantArgs) {
		t.Fatalf("driver argument count = %d, want %d", len(got.args), len(wantArgs))
	}
	for index := range wantArgs {
		if got.args[index].Type != wantArgs[index].Type || string(got.args[index].Value) != string(wantArgs[index].Value) {
			t.Fatalf("driver argument %d differs from exact contract", index+1)
		}
	}
}

func nullProtocolValue() protocolValue {
	return protocolValue{Type: "null"}
}

func countPersistenceSQL(records []migrationRequest, statement string) int {
	count := 0
	for _, record := range records {
		if record.sql == statement {
			count++
		}
	}
	return count
}

func firstMutationBaton(t *testing.T, records []migrationRequest, statement string) string {
	t.Helper()
	for _, record := range records {
		if record.sql == statement {
			if record.baton == nil {
				t.Fatal("mutation did not continue a physical cursor session")
			}
			return *record.baton
		}
	}
	t.Fatal("mutation request was not recorded")
	return ""
}
