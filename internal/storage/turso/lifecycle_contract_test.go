package turso

import (
	"context"
	"errors"
	"io"
	"math"
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
	expectedLifecycleLookupSQL  = "WITH input(account_id) AS (VALUES (?)) SELECT 1, (SELECT COUNT(*) FROM inboxgate_accounts AS a, input WHERE a.account_id = input.account_id), COUNT(l.account_id), MAX(l.account_id), MAX(l.state), MAX(l.state_version), MAX(l.reauthorization_reason), MAX(l.revocation_status) FROM input LEFT JOIN inboxgate_account_lifecycle AS l ON l.account_id = input.account_id"
	expectedAccountListSQL      = "SELECT a.account_id, a.provider, l.state, l.state_version, l.reauthorization_reason, l.revocation_status, EXISTS (SELECT 1 FROM inboxgate_synchronization_cursors AS c WHERE c.account_id = a.account_id), EXISTS (SELECT 1 FROM inboxgate_provider_credentials AS p WHERE p.account_id = a.account_id) FROM inboxgate_accounts AS a LEFT JOIN inboxgate_account_lifecycle AS l ON l.account_id = a.account_id ORDER BY a.account_id COLLATE BINARY LIMIT 101"
	expectedLifecycleCommitSQL  = "UPDATE inboxgate_account_lifecycle SET state = ?, state_version = state_version + 1, reauthorization_reason = ?, revocation_status = ? WHERE account_id = ? AND state = ? AND state_version = ? AND revocation_status = ? AND state_version < 9223372036854775807 AND (? <> 'active' OR (EXISTS (SELECT 1 FROM inboxgate_synchronization_cursors WHERE account_id = ?) AND EXISTS (SELECT 1 FROM inboxgate_provider_credentials WHERE account_id = ?)))"
	expectedCredentialDeleteSQL = "DELETE FROM inboxgate_provider_credentials WHERE account_id = ? AND envelope = ? AND EXISTS (SELECT 1 FROM inboxgate_account_lifecycle WHERE account_id = ? AND state = 'revoked')"
)

func TestExactDriverLifecycleWireAndSeparateDurability(t *testing.T) {
	server := newMigrationProtocolServer(t)
	server.seedAccount(accountIDA, subjectA)
	server.seedCursor(accountIDA, "9")
	envelope := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 32, 31))
	server.seedCredential(accountIDA, envelope.KeyID().String(), envelope.String())
	handle := openPersistenceContractHandle(t, server.URL)

	current, err := handle.GetAccountLifecycle(context.Background(), persistenceAccountID(t, accountIDA))
	if err != nil || current.State != storage.AccountStatePending || current.Version.Int64() != 1 {
		t.Fatalf("GetAccountLifecycle() = (%#v, %v)", current, err)
	}
	commit := storage.LifecycleCommit{AccountID: current.AccountID, ExpectedState: current.State, ExpectedVersion: current.Version, ExpectedRevocationStatus: current.RevocationStatus, NextState: storage.AccountStateActive, RevocationStatus: storage.RevocationStatusNone}
	if err := handle.CommitAccountLifecycle(context.Background(), commit); err != nil {
		t.Fatalf("CommitAccountLifecycle() error = %v", err)
	}
	summaries, err := handle.ListAccounts(context.Background())
	if err != nil || len(summaries) != 1 || summaries[0].State != storage.AccountStateActive || !summaries[0].CursorPresent || !summaries[0].CredentialPresent {
		t.Fatalf("ListAccounts() = (%#v, %v)", summaries, err)
	}
	records := server.persistenceRecords()
	if got := countPersistenceSQL(records, lifecycleCommitSQL); got != 1 {
		t.Fatalf("lifecycle mutation attempts = %d, want 1", got)
	}
	if got := countPersistenceSQL(records, lifecycleLookupSQL); got != 3 {
		t.Fatalf("lifecycle inspections = %d, want explicit read, preflight, and separate verification", got)
	}
	if got := countPersistenceSQL(records, accountListSQL); got != 1 {
		t.Fatalf("account list requests = %d, want 1", got)
	}
	for _, record := range records {
		switch record.sql {
		case lifecycleLookupSQL:
			assertProtocolStatement(t, record, expectedLifecycleLookupSQL, []protocolValue{textProtocolValue(accountIDA)})
		case lifecycleCommitSQL:
			assertProtocolStatement(t, record, expectedLifecycleCommitSQL, []protocolValue{
				textProtocolValue("active"), nullProtocolValue(), textProtocolValue("none"), textProtocolValue(accountIDA), textProtocolValue("pending"), integerProtocolValue(1), textProtocolValue("none"), textProtocolValue("active"), textProtocolValue(accountIDA), textProtocolValue(accountIDA),
			})
		case accountListSQL:
			assertProtocolStatement(t, record, expectedAccountListSQL, nil)
		}
	}
}

func TestExactDriverConcurrentRevocationClaimHasOneWinner(t *testing.T) {
	server := newMigrationProtocolServer(t)
	server.seedAccount(accountIDA, subjectA)
	server.seedLifecycle(accountIDA, "revoked", 2, nil, "pending")
	accountID := persistenceAccountID(t, accountIDA)
	version, _ := storage.ParseLifecycleVersion(2)
	claim := storage.LifecycleCommit{AccountID: accountID, ExpectedState: storage.AccountStateRevoked, ExpectedVersion: version, ExpectedRevocationStatus: storage.RevocationStatusPending, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusAttempting}
	start := make(chan struct{})
	results := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for range 2 {
		go func() {
			handle := openPersistenceContractHandle(t, server.URL)
			ready.Done()
			<-start
			results <- handle.CommitAccountLifecycle(context.Background(), claim)
		}()
	}
	ready.Wait()
	close(start)
	successes := 0
	conflicts := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		} else if errors.Is(err, storage.ErrLifecycleConflict) {
			conflicts++
		} else {
			t.Fatalf("claim error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 || countPersistenceSQL(server.persistenceRecords(), lifecycleCommitSQL) != 2 {
		t.Fatalf("claim successes=%d conflicts=%d mutations=%d", successes, conflicts, countPersistenceSQL(server.persistenceRecords(), lifecycleCommitSQL))
	}
}

func TestExactDriverLifecycleAndCredentialConcurrencyMatrix(t *testing.T) {
	t.Run("identical pause and resume increment once", func(t *testing.T) {
		server := newMigrationProtocolServer(t)
		server.seedAccount(accountIDA, subjectA)
		server.seedCursor(accountIDA, "9")
		envelope := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 32, 76))
		server.seedCredential(accountIDA, envelope.KeyID().String(), envelope.String())
		server.seedLifecycle(accountIDA, "active", 2, nil, "none")
		accountID := persistenceAccountID(t, accountIDA)
		for _, transition := range []struct {
			expected storage.AccountState
			version  int64
			next     storage.AccountState
		}{
			{expected: storage.AccountStateActive, version: 2, next: storage.AccountStatePaused},
			{expected: storage.AccountStatePaused, version: 3, next: storage.AccountStateActive},
		} {
			version, _ := storage.ParseLifecycleVersion(transition.version)
			commit := storage.LifecycleCommit{AccountID: accountID, ExpectedState: transition.expected, ExpectedVersion: version, ExpectedRevocationStatus: storage.RevocationStatusNone, NextState: transition.next, RevocationStatus: storage.RevocationStatusNone}
			start := make(chan struct{})
			results := make(chan error, 2)
			var ready sync.WaitGroup
			ready.Add(2)
			for range 2 {
				go func() {
					handle := openPersistenceContractHandle(t, server.URL)
					ready.Done()
					<-start
					results <- handle.CommitAccountLifecycle(context.Background(), commit)
				}()
			}
			ready.Wait()
			close(start)
			for range 2 {
				if err := <-results; err != nil {
					t.Fatalf("identical transition error = %v", err)
				}
			}
			current, err := openPersistenceContractHandle(t, server.URL).GetAccountLifecycle(context.Background(), accountID)
			if err != nil || current.State != transition.next || current.Version.Int64() != transition.version+1 {
				t.Fatalf("identical transition durable state = (%#v, %v)", current, err)
			}
		}
	})

	t.Run("pause versus revoke has one durable winner", func(t *testing.T) {
		server := newMigrationProtocolServer(t)
		server.seedAccount(accountIDA, subjectA)
		server.seedLifecycle(accountIDA, "active", 2, nil, "none")
		accountID := persistenceAccountID(t, accountIDA)
		version, _ := storage.ParseLifecycleVersion(2)
		commits := []storage.LifecycleCommit{
			{AccountID: accountID, ExpectedState: storage.AccountStateActive, ExpectedVersion: version, ExpectedRevocationStatus: storage.RevocationStatusNone, NextState: storage.AccountStatePaused, RevocationStatus: storage.RevocationStatusNone},
			{AccountID: accountID, ExpectedState: storage.AccountStateActive, ExpectedVersion: version, ExpectedRevocationStatus: storage.RevocationStatusNone, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusPending},
		}
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, commit := range commits {
			go func(commit storage.LifecycleCommit) {
				handle := openPersistenceContractHandle(t, server.URL)
				<-start
				results <- handle.CommitAccountLifecycle(context.Background(), commit)
			}(commit)
		}
		close(start)
		successes := 0
		for range 2 {
			if err := <-results; err == nil {
				successes++
			} else if !errors.Is(err, storage.ErrLifecycleConflict) && !errors.Is(err, storage.ErrPersistenceUnknown) {
				t.Fatalf("different transition error = %v", err)
			}
		}
		current, err := openPersistenceContractHandle(t, server.URL).GetAccountLifecycle(context.Background(), accountID)
		if err != nil || successes != 1 || current.Version.Int64() != 3 || current.State != storage.AccountStatePaused && current.State != storage.AccountStateRevoked {
			t.Fatalf("different transition winner = (%#v, %v), successes=%d", current, err, successes)
		}
	})

	t.Run("credential insert versus delete and duplicate delete", func(t *testing.T) {
		server := newMigrationProtocolServer(t)
		server.seedAccount(accountIDA, subjectA)
		server.seedLifecycle(accountIDA, "revoked", 2, nil, "pending")
		envelope := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 32, 77))
		replacement := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 32, 78))
		server.seedCredential(accountIDA, envelope.KeyID().String(), envelope.String())
		accountID := persistenceAccountID(t, accountIDA)
		start := make(chan struct{})
		results := make(chan error, 2)
		go func() {
			<-start
			results <- openPersistenceContractHandle(t, server.URL).CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: accountID, Expected: &envelope, Next: replacement})
		}()
		go func() {
			<-start
			results <- openPersistenceContractHandle(t, server.URL).DeleteRevokedProviderCredential(context.Background(), storage.RevokedCredentialDelete{AccountID: accountID, Expected: envelope})
		}()
		close(start)
		conflicts := 0
		successes := 0
		for range 2 {
			if err := <-results; err == nil {
				successes++
			} else if errors.Is(err, storage.ErrLifecycleConflict) {
				conflicts++
			} else {
				t.Fatalf("credential race error = %v", err)
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Fatalf("credential race successes=%d conflicts=%d", successes, conflicts)
		}
		for range 2 {
			if err := openPersistenceContractHandle(t, server.URL).DeleteRevokedProviderCredential(context.Background(), storage.RevokedCredentialDelete{AccountID: accountID, Expected: envelope}); err != nil {
				t.Fatalf("duplicate delete error = %v", err)
			}
		}
		if _, err := openPersistenceContractHandle(t, server.URL).GetProviderCredential(context.Background(), accountID); !errors.Is(err, storage.ErrCredentialNotFound) {
			t.Fatalf("credential race durable value = %v", err)
		}
	})

	t.Run("list snapshot during lifecycle transition", func(t *testing.T) {
		server := newMigrationProtocolServer(t)
		server.seedAccount(accountIDA, subjectA)
		server.seedLifecycle(accountIDA, "active", 2, nil, "none")
		accountID := persistenceAccountID(t, accountIDA)
		version, _ := storage.ParseLifecycleVersion(2)
		commit := storage.LifecycleCommit{AccountID: accountID, ExpectedState: storage.AccountStateActive, ExpectedVersion: version, ExpectedRevocationStatus: storage.RevocationStatusNone, NextState: storage.AccountStatePaused, RevocationStatus: storage.RevocationStatusNone}
		result := make(chan error, 1)
		go func() {
			result <- openPersistenceContractHandle(t, server.URL).CommitAccountLifecycle(context.Background(), commit)
		}()
		for index := 0; index < 100; index++ {
			summaries, err := openPersistenceContractHandle(t, server.URL).ListAccounts(context.Background())
			if err != nil || len(summaries) != 1 {
				t.Fatalf("exact snapshot list = (%#v, %v)", summaries, err)
			}
			summary := summaries[0]
			active := summary.State == storage.AccountStateActive && summary.StateVersion.Int64() == 2 && summary.RevocationStatus == storage.RevocationStatusNone
			paused := summary.State == storage.AccountStatePaused && summary.StateVersion.Int64() == 3 && summary.RevocationStatus == storage.RevocationStatusNone
			if !active && !paused {
				t.Fatalf("crossed exact-driver list snapshot = %#v", summary)
			}
		}
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	})
}

func TestExactDriverLifecycleUncertaintyIsOneAttemptDiscardedAndFreshlyReconciled(t *testing.T) {
	for _, test := range []struct {
		mode        string
		wantClose   int
		wantSuccess bool
	}{
		{mode: "drop-before"},
		{mode: "clean-eof", wantClose: 1},
		{mode: "step-begin-before", wantClose: 1},
		{mode: "success-without-apply", wantClose: 1},
		{mode: "drop-after", wantSuccess: true},
		{mode: "malformed-after", wantSuccess: true},
		{mode: "step-begin-after", wantClose: 1, wantSuccess: true},
		{mode: "apply-zero-affected", wantClose: 1, wantSuccess: true},
	} {
		t.Run(test.mode, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			server.seedAccount(accountIDA, subjectA)
			server.seedLifecycle(accountIDA, "active", 2, nil, "none")
			server.armPersistenceResponse(lifecycleCommitSQL, test.mode)
			handle := openPersistenceContractHandle(t, server.URL)
			version, _ := storage.ParseLifecycleVersion(2)
			commit := storage.LifecycleCommit{AccountID: persistenceAccountID(t, accountIDA), ExpectedState: storage.AccountStateActive, ExpectedVersion: version, ExpectedRevocationStatus: storage.RevocationStatusNone, NextState: storage.AccountStatePaused, RevocationStatus: storage.RevocationStatusNone}
			err := handle.CommitAccountLifecycle(context.Background(), commit)
			if test.wantSuccess && err != nil {
				t.Fatalf("first CommitAccountLifecycle() error = %v, want separately proved success", err)
			}
			if !test.wantSuccess && !errors.Is(err, storage.ErrPersistenceUnknown) {
				t.Fatalf("first CommitAccountLifecycle() error = %v", err)
			}
			if got := countPersistenceSQL(server.persistenceRecords(), lifecycleCommitSQL); got != 1 {
				t.Fatalf("same-invocation lifecycle attempts = %d, want 1", got)
			}
			baton := firstMutationBaton(t, server.persistenceRecords(), lifecycleCommitSQL)
			if got := server.cursorSessionCloseCount(baton); got != test.wantClose {
				t.Fatalf("unproven lifecycle close requests = %d, want %d", got, test.wantClose)
			}
			if !server.cursorSessionWasNotReusedAfterMutation(baton, lifecycleCommitSQL) {
				t.Fatal("unproven lifecycle session was reused after discard")
			}
			if err := handle.CommitAccountLifecycle(context.Background(), commit); err != nil {
				t.Fatalf("fresh CommitAccountLifecycle() error = %v", err)
			}
			wantAttempts := 2
			if test.wantSuccess {
				wantAttempts = 1
			}
			if got := countPersistenceSQL(server.persistenceRecords(), lifecycleCommitSQL); got != wantAttempts {
				t.Fatalf("attempts across explicit invocations = %d, want %d", got, wantAttempts)
			}
		})
	}
}

func TestExactDriverAccountListFailsClosedOnMissingLifecycleMalformedAndOverflow(t *testing.T) {
	valid := []any{textValue(accountIDA), textValue(storage.ProviderGmail), textValue("active"), integerValue(2), nullValue(), textValue("none"), integerValue(1), integerValue(1)}
	tests := []struct {
		name    string
		rows    [][]any
		columns int
	}{
		{name: "missing lifecycle", rows: [][]any{{textValue(accountIDA), textValue(storage.ProviderGmail), nullValue(), nullValue(), nullValue(), nullValue(), integerValue(1), integerValue(1)}}},
		{name: "null account", rows: [][]any{{nullValue(), textValue(storage.ProviderGmail), textValue("active"), integerValue(2), nullValue(), textValue("none"), integerValue(1), integerValue(1)}}},
		{name: "typed account", rows: [][]any{{integerValue(1), textValue(storage.ProviderGmail), textValue("active"), integerValue(2), nullValue(), textValue("none"), integerValue(1), integerValue(1)}}},
		{name: "null provider", rows: [][]any{{textValue(accountIDA), nullValue(), textValue("active"), integerValue(2), nullValue(), textValue("none"), integerValue(1), integerValue(1)}}},
		{name: "wrong provider", rows: [][]any{{textValue(accountIDA), textValue("other"), textValue("active"), integerValue(2), nullValue(), textValue("none"), integerValue(1), integerValue(1)}}},
		{name: "typed provider", rows: [][]any{{textValue(accountIDA), integerValue(1), textValue("active"), integerValue(2), nullValue(), textValue("none"), integerValue(1), integerValue(1)}}},
		{name: "null state", rows: [][]any{{textValue(accountIDA), textValue(storage.ProviderGmail), nullValue(), integerValue(2), nullValue(), textValue("none"), integerValue(1), integerValue(1)}}},
		{name: "text version", rows: [][]any{{textValue(accountIDA), textValue(storage.ProviderGmail), textValue("active"), textValue("2"), nullValue(), textValue("none"), integerValue(1), integerValue(1)}}},
		{name: "null version", rows: [][]any{{textValue(accountIDA), textValue(storage.ProviderGmail), textValue("active"), nullValue(), nullValue(), textValue("none"), integerValue(1), integerValue(1)}}},
		{name: "typed reason", rows: [][]any{{textValue(accountIDA), textValue(storage.ProviderGmail), textValue("reauthorization_required"), integerValue(2), integerValue(1), textValue("none"), integerValue(1), integerValue(1)}}},
		{name: "missing required reason", rows: [][]any{{textValue(accountIDA), textValue(storage.ProviderGmail), textValue("reauthorization_required"), integerValue(2), nullValue(), textValue("none"), integerValue(1), integerValue(1)}}},
		{name: "reason outside reauthorization", rows: [][]any{{textValue(accountIDA), textValue(storage.ProviderGmail), textValue("active"), integerValue(2), textValue("refresh_invalid_grant"), textValue("none"), integerValue(1), integerValue(1)}}},
		{name: "null revocation", rows: [][]any{{textValue(accountIDA), textValue(storage.ProviderGmail), textValue("active"), integerValue(2), nullValue(), nullValue(), integerValue(1), integerValue(1)}}},
		{name: "crossed revocation", rows: [][]any{{textValue(accountIDA), textValue(storage.ProviderGmail), textValue("revoked"), integerValue(2), nullValue(), textValue("none"), integerValue(1), integerValue(1)}}},
		{name: "null cursor flag", rows: [][]any{{textValue(accountIDA), textValue(storage.ProviderGmail), textValue("active"), integerValue(2), nullValue(), textValue("none"), nullValue(), integerValue(1)}}},
		{name: "text cursor flag", rows: [][]any{{textValue(accountIDA), textValue(storage.ProviderGmail), textValue("active"), integerValue(2), nullValue(), textValue("none"), textValue("1"), integerValue(1)}}},
		{name: "null credential flag", rows: [][]any{{textValue(accountIDA), textValue(storage.ProviderGmail), textValue("active"), integerValue(2), nullValue(), textValue("none"), integerValue(1), nullValue()}}},
		{name: "text credential flag", rows: [][]any{{textValue(accountIDA), textValue(storage.ProviderGmail), textValue("active"), integerValue(2), nullValue(), textValue("none"), integerValue(1), textValue("1")}}},
		{name: "missing column", rows: [][]any{valid[:7]}},
		{name: "extra column", rows: [][]any{append(append([]any{}, valid...), nullValue())}, columns: 9},
		{name: "duplicate account", rows: [][]any{valid, valid}},
		{name: "invalid presence flag", rows: [][]any{{textValue(accountIDA), textValue(storage.ProviderGmail), textValue("active"), integerValue(2), nullValue(), textValue("none"), integerValue(2), integerValue(1)}}},
		{name: "oversized value", rows: [][]any{{textValue(accountIDA), textValue(storage.ProviderGmail), textValue(strings.Repeat("x", 1<<20)), integerValue(2), nullValue(), textValue("none"), integerValue(1), integerValue(1)}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			server.overridePersistenceRows(accountListSQL, tt.rows)
			if tt.columns > 0 {
				columns := make([]any, tt.columns)
				for index := range columns {
					columns[index] = map[string]any{"name": "synthetic", "decltype": "TEXT"}
				}
				server.overridePersistenceColumns(accountListSQL, columns)
			}
			handle := openPersistenceContractHandle(t, server.URL)
			if _, err := handle.ListAccounts(context.Background()); !errors.Is(err, storage.ErrPersistenceInspect) {
				t.Fatalf("ListAccounts() error = %v", err)
			}
		})
	}
	server := newMigrationProtocolServer(t)
	rows := make([][]any, storage.MaximumAccountList+1)
	for index := range rows {
		accountID := strings.Repeat("0", 30) + string("0123456789abcdef"[index/16]) + string("0123456789abcdef"[index%16])
		rows[index] = []any{textValue(accountID), textValue(storage.ProviderGmail), textValue("pending"), integerValue(1), nullValue(), textValue("none"), integerValue(0), integerValue(0)}
	}
	server.overridePersistenceRows(accountListSQL, rows)
	handle := openPersistenceContractHandle(t, server.URL)
	if _, err := handle.ListAccounts(context.Background()); !errors.Is(err, storage.ErrResultTooLarge) {
		t.Fatalf("overflow ListAccounts() error = %v", err)
	}
	rows = rows[:storage.MaximumAccountList]
	server.overridePersistenceRows(accountListSQL, rows)
	if summaries, err := handle.ListAccounts(context.Background()); err != nil || len(summaries) != storage.MaximumAccountList {
		t.Fatalf("exact-bound ListAccounts() = (%d, %v)", len(summaries), err)
	}
	server.overridePersistenceRows(accountListSQL, [][]any{rows[1], rows[0]})
	if _, err := handle.ListAccounts(context.Background()); !errors.Is(err, storage.ErrPersistenceInspect) {
		t.Fatalf("unsorted ListAccounts() error = %v", err)
	}
}

func TestExactDriverLifecycleInspectionMatrixFailsClosed(t *testing.T) {
	valid := []any{integerValue(1), integerValue(1), integerValue(1), textValue(accountIDA), textValue("active"), integerValue(2), nullValue(), textValue("none")}
	tests := []struct {
		name string
		rows [][]any
	}{
		{name: "missing sentinel", rows: nil},
		{name: "duplicate rows", rows: [][]any{valid, valid}},
		{name: "wrong sentinel", rows: [][]any{{textValue("1"), integerValue(1), integerValue(1), textValue(accountIDA), textValue("active"), integerValue(2), nullValue(), textValue("none")}}},
		{name: "missing column", rows: [][]any{{integerValue(1)}}},
		{name: "invalid state", rows: [][]any{{integerValue(1), integerValue(1), integerValue(1), textValue(accountIDA), textValue("disabled"), integerValue(2), nullValue(), textValue("none")}}},
		{name: "zero version", rows: [][]any{{integerValue(1), integerValue(1), integerValue(1), textValue(accountIDA), textValue("active"), integerValue(0), nullValue(), textValue("none")}}},
		{name: "reason on active", rows: [][]any{{integerValue(1), integerValue(1), integerValue(1), textValue(accountIDA), textValue("active"), integerValue(2), textValue("gmail_unauthorized_after_refresh"), textValue("none")}}},
		{name: "wrong revocation", rows: [][]any{{integerValue(1), integerValue(1), integerValue(1), textValue(accountIDA), textValue("active"), integerValue(2), nullValue(), textValue("pending")}}},
		{name: "superseded reason", rows: [][]any{{integerValue(1), integerValue(1), integerValue(1), textValue(accountIDA), textValue("reauthorization_required"), integerValue(2), textValue("credential_rejected"), textValue("none")}}},
		{name: "superseded manual status", rows: [][]any{{integerValue(1), integerValue(1), integerValue(1), textValue(accountIDA), textValue("revoked"), integerValue(2), nullValue(), textValue("manual")}}},
		{name: "nul value", rows: [][]any{{integerValue(1), integerValue(1), integerValue(1), textValue(accountIDA), textValue("active\x00"), integerValue(2), nullValue(), textValue("none")}}},
		{name: "oversized value", rows: [][]any{{integerValue(1), integerValue(1), integerValue(1), textValue(accountIDA), textValue(strings.Repeat("x", 1<<20)), integerValue(2), nullValue(), textValue("none")}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			server.seedAccount(accountIDA, subjectA)
			server.overridePersistenceRows(lifecycleLookupSQL, tt.rows)
			handle := openPersistenceContractHandle(t, server.URL)
			_, err := handle.GetAccountLifecycle(context.Background(), persistenceAccountID(t, accountIDA))
			if !errors.Is(err, storage.ErrPersistenceInspect) {
				t.Fatalf("GetAccountLifecycle() error = %v", err)
			}
			if strings.Contains(err.Error(), accountIDA) || strings.Contains(err.Error(), "disabled") {
				t.Fatal("inspection error reflected remote data")
			}
		})
	}
}

func TestExactDriverRevokedCredentialDeleteWireNoReplayAndVisibility(t *testing.T) {
	server := newMigrationProtocolServer(t)
	envelope := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 32, 32))
	server.seedAccount(accountIDA, subjectA)
	server.seedLifecycle(accountIDA, "revoked", 3, nil, "pending")
	server.seedCredential(accountIDA, envelope.KeyID().String(), envelope.String())
	handle := openPersistenceContractHandle(t, server.URL)
	if err := handle.DeleteRevokedProviderCredential(context.Background(), storage.RevokedCredentialDelete{AccountID: persistenceAccountID(t, accountIDA), Expected: envelope}); err != nil {
		t.Fatalf("DeleteRevokedProviderCredential() error = %v", err)
	}
	if _, err := handle.GetProviderCredential(context.Background(), persistenceAccountID(t, accountIDA)); !errors.Is(err, storage.ErrCredentialNotFound) {
		t.Fatalf("credential lookup error = %v", err)
	}
	records := server.persistenceRecords()
	if got := countPersistenceSQL(records, revokedCredentialDeleteSQL); got != 1 {
		t.Fatalf("delete attempts = %d, want 1", got)
	}
	for _, record := range records {
		if record.sql == revokedCredentialDeleteSQL {
			assertProtocolStatement(t, record, expectedCredentialDeleteSQL, []protocolValue{textProtocolValue(accountIDA), textProtocolValue(envelope.String()), textProtocolValue(accountIDA)})
		}
	}
}

func TestExactDriverRevokedCredentialDeleteUncertaintyNoReplayAndFreshReconciliation(t *testing.T) {
	for _, tt := range []struct {
		mode        string
		wantSuccess bool
		wantClose   int
	}{
		{mode: "drop-before"},
		{mode: "clean-eof", wantClose: 1},
		{mode: "step-begin-before", wantClose: 1},
		{mode: "success-without-apply", wantClose: 1},
		{mode: "drop-after", wantSuccess: true},
		{mode: "malformed-after", wantSuccess: true},
		{mode: "step-begin-after", wantSuccess: true, wantClose: 1},
		{mode: "apply-zero-affected", wantSuccess: true, wantClose: 1},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			envelope := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 32, 44))
			server.seedAccount(accountIDA, subjectA)
			server.seedLifecycle(accountIDA, "revoked", 3, nil, "pending")
			server.seedCredential(accountIDA, envelope.KeyID().String(), envelope.String())
			server.armPersistenceResponse(revokedCredentialDeleteSQL, tt.mode)
			handle := openPersistenceContractHandle(t, server.URL)
			operation := storage.RevokedCredentialDelete{AccountID: persistenceAccountID(t, accountIDA), Expected: envelope}
			err := handle.DeleteRevokedProviderCredential(context.Background(), operation)
			if tt.wantSuccess && err != nil {
				t.Fatalf("first delete error = %v, want separately proved success", err)
			}
			if !tt.wantSuccess && !errors.Is(err, storage.ErrPersistenceUnknown) {
				t.Fatalf("first delete error = %v, want unknown", err)
			}
			if got := countPersistenceSQL(server.persistenceRecords(), revokedCredentialDeleteSQL); got != 1 {
				t.Fatalf("same-invocation delete attempts = %d, want 1", got)
			}
			baton := firstMutationBaton(t, server.persistenceRecords(), revokedCredentialDeleteSQL)
			if got := server.cursorSessionCloseCount(baton); got != tt.wantClose {
				t.Fatalf("unproven delete close requests = %d, want %d", got, tt.wantClose)
			}
			if !server.cursorSessionWasNotReusedAfterMutation(baton, revokedCredentialDeleteSQL) {
				t.Fatal("unproven delete session was reused")
			}
			if err := handle.DeleteRevokedProviderCredential(context.Background(), operation); err != nil {
				t.Fatalf("fresh delete error = %v", err)
			}
			wantAttempts := 2
			if tt.wantSuccess {
				wantAttempts = 1
			}
			if got := countPersistenceSQL(server.persistenceRecords(), revokedCredentialDeleteSQL); got != wantAttempts {
				t.Fatalf("delete attempts across invocations = %d, want %d", got, wantAttempts)
			}
		})
	}
}

func TestLifecycleOperationsRejectCredentialedAndNonLoopbackBeforeConnection(t *testing.T) {
	accountID := persistenceAccountID(t, accountIDA)
	version, _ := storage.ParseLifecycleVersion(1)
	envelope := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 32, 79))
	for _, endpoint := range []storage.Endpoint{{URL: "https://127.0.0.1", Token: "synthetic-token"}, {URL: "https://192.0.2.1"}} {
		calls := 0
		adapter, err := newAdapter(Options{}, func(string, string) databaseHandle { calls++; return &migrationFakeDatabase{} })
		if err != nil {
			t.Fatal(err)
		}
		handle, err := adapter.Open(context.Background(), endpoint)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := handle.ListAccounts(context.Background()); !errors.Is(err, storage.ErrPersistenceNotAllowed) {
			t.Fatalf("ListAccounts() error = %v", err)
		}
		if _, err := handle.GetAccountLifecycle(context.Background(), accountID); !errors.Is(err, storage.ErrPersistenceNotAllowed) {
			t.Fatalf("GetAccountLifecycle() error = %v", err)
		}
		if err := handle.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: accountID, ExpectedState: storage.AccountStatePending, ExpectedVersion: version, ExpectedRevocationStatus: storage.RevocationStatusNone, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusPending}); !errors.Is(err, storage.ErrPersistenceNotAllowed) {
			t.Fatalf("CommitAccountLifecycle() error = %v", err)
		}
		if err := handle.DeleteRevokedProviderCredential(context.Background(), storage.RevokedCredentialDelete{AccountID: accountID, Expected: envelope}); !errors.Is(err, storage.ErrPersistenceNotAllowed) {
			t.Fatalf("DeleteRevokedProviderCredential() error = %v", err)
		}
		if calls != 1 {
			t.Fatalf("driver construction calls = %d, want initial open only", calls)
		}
	}
}

func TestLifecycleMaximumVersionCannotMutate(t *testing.T) {
	server := newMigrationProtocolServer(t)
	server.seedAccount(accountIDA, subjectA)
	server.seedLifecycle(accountIDA, "active", math.MaxInt64, nil, "none")
	handle := openPersistenceContractHandle(t, server.URL)
	version, _ := storage.ParseLifecycleVersion(math.MaxInt64)
	err := handle.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: persistenceAccountID(t, accountIDA), ExpectedState: storage.AccountStateActive, ExpectedVersion: version, ExpectedRevocationStatus: storage.RevocationStatusNone, NextState: storage.AccountStatePaused, RevocationStatus: storage.RevocationStatusNone})
	if !errors.Is(err, storage.ErrLifecycleOverflow) || countPersistenceSQL(server.persistenceRecords(), lifecycleCommitSQL) != 0 {
		t.Fatalf("overflow transition = %v", err)
	}
}

func TestLifecycleAndRevokedDeleteCancellationAreBoundedUnknownAndNeverReplayed(t *testing.T) {
	for _, tt := range []struct {
		name      string
		statement string
		operation func(*handle, storage.AccountID, storage.CredentialEnvelope) error
	}{
		{
			name: "lifecycle claim", statement: lifecycleCommitSQL,
			operation: func(handle *handle, accountID storage.AccountID, _ storage.CredentialEnvelope) error {
				version, _ := storage.ParseLifecycleVersion(2)
				return handle.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: accountID, ExpectedState: storage.AccountStateRevoked, ExpectedVersion: version, ExpectedRevocationStatus: storage.RevocationStatusPending, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusAttempting})
			},
		},
		{
			name: "credential delete", statement: revokedCredentialDeleteSQL,
			operation: func(handle *handle, accountID storage.AccountID, envelope storage.CredentialEnvelope) error {
				return handle.DeleteRevokedProviderCredential(context.Background(), storage.RevokedCredentialDelete{AccountID: accountID, Expected: envelope})
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			envelope := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 32, 75))
			server.seedAccount(accountIDA, subjectA)
			server.seedLifecycle(accountIDA, "revoked", 2, nil, "pending")
			server.seedCredential(accountIDA, envelope.KeyID().String(), envelope.String())
			started, release := server.stallPersistence(tt.statement)
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			handle := openPersistenceContractHandle(t, server.URL)
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() {
				if tt.statement == lifecycleCommitSQL {
					version, _ := storage.ParseLifecycleVersion(2)
					result <- handle.CommitAccountLifecycle(ctx, storage.LifecycleCommit{AccountID: persistenceAccountID(t, accountIDA), ExpectedState: storage.AccountStateRevoked, ExpectedVersion: version, ExpectedRevocationStatus: storage.RevocationStatusPending, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusAttempting})
					return
				}
				result <- handle.DeleteRevokedProviderCredential(ctx, storage.RevokedCredentialDelete{AccountID: persistenceAccountID(t, accountIDA), Expected: envelope})
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("operation did not reach named mutation")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, storage.ErrPersistenceUnknown) || !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled operation error = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("canceled operation did not return")
			}
			if got := countPersistenceSQL(server.persistenceRecords(), tt.statement); got != 1 {
				t.Fatalf("mutation attempts = %d, want 1", got)
			}
			releaseOnce.Do(func() { close(release) })
		})
	}
}

func TestLifecycleListAndLookupCancellationAreBoundedSanitizedAndNeverReplayed(t *testing.T) {
	for _, tt := range []struct {
		name      string
		statement string
		operation func(context.Context, storage.Handle, storage.AccountID) error
	}{
		{name: "list", statement: accountListSQL, operation: func(ctx context.Context, handle storage.Handle, _ storage.AccountID) error {
			_, err := handle.ListAccounts(ctx)
			return err
		}},
		{name: "lookup", statement: lifecycleLookupSQL, operation: func(ctx context.Context, handle storage.Handle, accountID storage.AccountID) error {
			_, err := handle.GetAccountLifecycle(ctx, accountID)
			return err
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := newMigrationProtocolServer(t)
			server.seedAccount(accountIDA, subjectA)
			started, release := server.stallPersistence(tt.statement)
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			handle := openPersistenceContractHandle(t, server.URL)
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() { result <- tt.operation(ctx, handle, persistenceAccountID(t, accountIDA)) }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("read operation did not reach its named protocol stage")
			}
			canceledAt := time.Now()
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, storage.ErrPersistenceInspect) || !errors.Is(err, context.Canceled) || len(err.Error()) > 128 {
					t.Fatalf("canceled read error = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("canceled read did not return")
			}
			if time.Since(canceledAt) >= 500*time.Millisecond || countPersistenceSQL(server.persistenceRecords(), tt.statement) != 1 {
				t.Fatalf("canceled read elapsed=%v attempts=%d", time.Since(canceledAt), countPersistenceSQL(server.persistenceRecords(), tt.statement))
			}
			releaseOnce.Do(func() { close(release) })
		})
	}
}

func TestLifecycleListAndLookupChangedAuthorityAndRemoteDiagnosticsRemainCredentialFree(t *testing.T) {
	for _, tt := range []struct {
		name      string
		operation func(storage.Handle, storage.AccountID) error
	}{
		{name: "list", operation: func(handle storage.Handle, _ storage.AccountID) error {
			_, err := handle.ListAccounts(context.Background())
			return err
		}},
		{name: "lookup", operation: func(handle storage.Handle, accountID storage.AccountID) error {
			_, err := handle.GetAccountLifecycle(context.Background(), accountID)
			return err
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var destinationRequests atomic.Int32
			destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				destinationRequests.Add(1)
				if request.Header.Get("Authorization") != "" {
					t.Error("credential-free lifecycle read sent an Authorization header")
				}
				http.Error(w, "raw lifecycle read diagnostic marker", http.StatusBadGateway)
			}))
			t.Cleanup(destination.Close)
			server := newMigrationProtocolServer(t)
			server.seedAccount(accountIDA, subjectA)
			server.redirectNextCursorBaseURL(destination.URL)
			handle := openPersistenceContractHandle(t, server.URL)
			accountID := persistenceAccountID(t, accountIDA)
			if err := tt.operation(handle, accountID); err != nil {
				t.Fatalf("first lifecycle read establishing base_url = %v", err)
			}
			err := tt.operation(handle, accountID)
			if !errors.Is(err, storage.ErrPersistenceInspect) || destinationRequests.Load() != 1 || strings.Contains(err.Error(), "diagnostic marker") || strings.Contains(err.Error(), accountIDA) {
				t.Fatalf("changed-authority lifecycle read = %v, requests=%d", err, destinationRequests.Load())
			}
		})
	}
}

func TestLifecycleProtocolBaseURLCanChangeAuthorityWithoutRawDiagnosticsOrReplay(t *testing.T) {
	var destinationRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		destinationRequests.Add(1)
		if request.Header.Get("Authorization") != "" {
			t.Error("credential-free lifecycle request sent an Authorization header")
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20))
		if err != nil {
			t.Errorf("read changed-authority lifecycle request: %v", err)
		}
		_ = body
		http.Error(w, "raw changed-authority lifecycle marker", http.StatusBadGateway)
	}))
	t.Cleanup(destination.Close)

	server := newMigrationProtocolServer(t)
	server.seedAccount(accountIDA, subjectA)
	server.seedLifecycle(accountIDA, "active", 2, nil, "none")
	server.redirectNextCursorBaseURL(destination.URL)
	handle := openPersistenceContractHandle(t, server.URL)
	version, _ := storage.ParseLifecycleVersion(2)
	err := handle.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: persistenceAccountID(t, accountIDA), ExpectedState: storage.AccountStateActive, ExpectedVersion: version, ExpectedRevocationStatus: storage.RevocationStatusNone, NextState: storage.AccountStatePaused, RevocationStatus: storage.RevocationStatusNone})
	if !errors.Is(err, storage.ErrPersistenceUnknown) || destinationRequests.Load() != 1 {
		t.Fatalf("changed-authority lifecycle = %v, destination requests=%d", err, destinationRequests.Load())
	}
	for _, raw := range []string{"changed-authority", accountIDA} {
		if strings.Contains(err.Error(), raw) {
			t.Fatalf("sanitized lifecycle error %q contains raw marker", err)
		}
	}
}

func TestRevokedDeleteProtocolBaseURLCanChangeAuthorityWithoutCredentialOrMutation(t *testing.T) {
	var destinationRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		destinationRequests.Add(1)
		if request.Header.Get("Authorization") != "" {
			t.Error("credential-free revoked-delete request sent an Authorization header")
		}
		http.Error(w, "raw changed-authority delete marker", http.StatusBadGateway)
	}))
	t.Cleanup(destination.Close)
	server := newMigrationProtocolServer(t)
	server.seedAccount(accountIDA, subjectA)
	server.seedLifecycle(accountIDA, "revoked", 2, nil, "pending")
	envelope := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 32, 83))
	server.seedCredential(accountIDA, envelope.KeyID().String(), envelope.String())
	server.redirectNextCursorBaseURL(destination.URL)
	err := openPersistenceContractHandle(t, server.URL).DeleteRevokedProviderCredential(context.Background(), storage.RevokedCredentialDelete{AccountID: persistenceAccountID(t, accountIDA), Expected: envelope})
	if !errors.Is(err, storage.ErrPersistenceInspect) || destinationRequests.Load() != 1 || countPersistenceSQL(server.persistenceRecords(), revokedCredentialDeleteSQL) != 0 || strings.Contains(err.Error(), "delete marker") || strings.Contains(err.Error(), envelope.String()) {
		t.Fatalf("changed-authority revoked delete = %v, requests=%d, mutations=%d", err, destinationRequests.Load(), countPersistenceSQL(server.persistenceRecords(), revokedCredentialDeleteSQL))
	}
}

func TestLifecycleMutationRedirectsStayCredentialFreeAndDoNotReachMutation(t *testing.T) {
	for _, tt := range []struct {
		name      string
		operation func(storage.Handle, storage.AccountID, storage.CredentialEnvelope) error
		statement string
	}{
		{name: "lifecycle cas", statement: lifecycleCommitSQL, operation: func(handle storage.Handle, accountID storage.AccountID, _ storage.CredentialEnvelope) error {
			version, _ := storage.ParseLifecycleVersion(2)
			return handle.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: accountID, ExpectedState: storage.AccountStateActive, ExpectedVersion: version, ExpectedRevocationStatus: storage.RevocationStatusNone, NextState: storage.AccountStatePaused, RevocationStatus: storage.RevocationStatusNone})
		}},
		{name: "revoked delete", statement: revokedCredentialDeleteSQL, operation: func(handle storage.Handle, accountID storage.AccountID, envelope storage.CredentialEnvelope) error {
			return handle.DeleteRevokedProviderCredential(context.Background(), storage.RevokedCredentialDelete{AccountID: accountID, Expected: envelope})
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var redirectedRequests atomic.Int32
			destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				redirectedRequests.Add(1)
				if request.Header.Get("Authorization") != "" {
					t.Error("credential-free redirected lifecycle mutation sent an Authorization header")
				}
				http.Error(w, "raw redirected lifecycle mutation marker", http.StatusBadGateway)
			}))
			t.Cleanup(destination.Close)
			initial := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				http.Redirect(w, request, destination.URL+request.URL.Path, http.StatusTemporaryRedirect)
			}))
			t.Cleanup(initial.Close)
			envelope := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 32, 84))
			err := tt.operation(openPersistenceContractHandle(t, initial.URL), persistenceAccountID(t, accountIDA), envelope)
			if !errors.Is(err, storage.ErrPersistenceInspect) || redirectedRequests.Load() != 1 || strings.Contains(err.Error(), "mutation marker") || strings.Contains(err.Error(), envelope.String()) {
				t.Fatalf("redirected lifecycle mutation = %v, requests=%d", err, redirectedRequests.Load())
			}
		})
	}
}

func TestLifecycleDriverFollowsCredentialFreeRedirectWithoutRawDiagnosticsOrReplay(t *testing.T) {
	for _, tt := range []struct {
		name      string
		operation func(storage.Handle) error
	}{
		{name: "list", operation: func(handle storage.Handle) error { _, err := handle.ListAccounts(context.Background()); return err }},
		{name: "lookup", operation: func(handle storage.Handle) error {
			_, err := handle.GetAccountLifecycle(context.Background(), persistenceAccountID(t, accountIDA))
			return err
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var redirectedRequests atomic.Int32
			destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				redirectedRequests.Add(1)
				if request.Header.Get("Authorization") != "" {
					t.Error("credential-free redirected lifecycle request sent an Authorization header")
				}
				http.Error(w, "raw redirect lifecycle marker", http.StatusBadGateway)
			}))
			t.Cleanup(destination.Close)
			initial := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				http.Redirect(w, request, destination.URL+request.URL.Path, http.StatusTemporaryRedirect)
			}))
			t.Cleanup(initial.Close)

			err := tt.operation(openPersistenceContractHandle(t, initial.URL))
			if !errors.Is(err, storage.ErrPersistenceInspect) || redirectedRequests.Load() != 1 {
				t.Fatalf("redirected lifecycle = %v, requests=%d", err, redirectedRequests.Load())
			}
			for _, raw := range []string{"redirect lifecycle", accountIDA} {
				if strings.Contains(err.Error(), raw) {
					t.Fatalf("sanitized lifecycle error %q contains raw marker", err)
				}
			}
		})
	}
}
