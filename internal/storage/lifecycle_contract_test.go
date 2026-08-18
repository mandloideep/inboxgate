package storage_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"

	"github.com/mandloideep/inboxgate/internal/storage"
	storagefake "github.com/mandloideep/inboxgate/internal/storage/fake"
)

func TestLifecycleValueContracts(t *testing.T) {
	t.Parallel()

	states := []string{"pending", "active", "paused", "reauthorization_required", "revoked"}
	for _, text := range states {
		state, err := storage.ParseAccountState(text)
		if err != nil || state.String() != text {
			t.Fatalf("ParseAccountState(%q) = (%q, %v)", text, state.String(), err)
		}
	}
	for _, text := range []string{"", "ACTIVE", "pending\x00", "disabled"} {
		if _, err := storage.ParseAccountState(text); !errors.Is(err, storage.ErrInvalidValue) {
			t.Fatalf("ParseAccountState(%q) error = %v", text, err)
		}
	}
	for _, value := range []int64{1, math.MaxInt64} {
		version, err := storage.ParseLifecycleVersion(value)
		if err != nil || version.Int64() != value {
			t.Fatalf("ParseLifecycleVersion(%d) = (%d, %v)", value, version.Int64(), err)
		}
	}
	for _, value := range []int64{math.MinInt64, -1, 0} {
		if _, err := storage.ParseLifecycleVersion(value); !errors.Is(err, storage.ErrInvalidValue) {
			t.Fatalf("ParseLifecycleVersion(%d) error = %v", value, err)
		}
	}
	for _, text := range []string{"refresh_invalid_grant", "refresh_admin_policy_enforced", "gmail_unauthorized_after_refresh", "gmail_domain_policy"} {
		reason, err := storage.ParseReauthorizationReason(text)
		if err != nil || reason.String() != text {
			t.Fatalf("ParseReauthorizationReason(%q) = (%q, %v)", text, reason.String(), err)
		}
	}
	for _, text := range []string{"none", "pending", "attempting", "confirmed", "manual_action_required"} {
		status, err := storage.ParseRevocationStatus(text)
		if err != nil || status.String() != text {
			t.Fatalf("ParseRevocationStatus(%q) = (%q, %v)", text, status.String(), err)
		}
	}
	for _, text := range []string{"", "NONE", "pending\x00", "failed", "manual"} {
		if _, err := storage.ParseRevocationStatus(text); !errors.Is(err, storage.ErrInvalidValue) {
			t.Fatalf("ParseRevocationStatus(%q) error = %v", text, err)
		}
	}
	for _, text := range []string{"", "SCOPE_LOST", "scope_lost\x00", "expired", "credential_rejected", "scope_lost", "identity_changed", "provider_disabled"} {
		if _, err := storage.ParseReauthorizationReason(text); !errors.Is(err, storage.ErrInvalidValue) {
			t.Fatalf("ParseReauthorizationReason(%q) error = %v", text, err)
		}
	}
}

func TestLifecycleTransitionGraphIsExact(t *testing.T) {
	accountID, _ := storage.ParseAccountID("09090909090909090909090909090909")
	version, _ := storage.ParseLifecycleVersion(1)
	states := []storage.AccountState{storage.AccountStatePending, storage.AccountStateActive, storage.AccountStatePaused, storage.AccountStateReauthorizationRequired, storage.AccountStateRevoked}
	allowed := map[[2]storage.AccountState]bool{
		{storage.AccountStatePending, storage.AccountStateActive}:                  true,
		{storage.AccountStatePending, storage.AccountStateRevoked}:                 true,
		{storage.AccountStateActive, storage.AccountStatePaused}:                   true,
		{storage.AccountStateActive, storage.AccountStateReauthorizationRequired}:  true,
		{storage.AccountStateActive, storage.AccountStateRevoked}:                  true,
		{storage.AccountStatePaused, storage.AccountStateActive}:                   true,
		{storage.AccountStatePaused, storage.AccountStateRevoked}:                  true,
		{storage.AccountStateReauthorizationRequired, storage.AccountStateRevoked}: true,
	}
	for _, current := range states {
		for _, next := range states {
			commit := storage.LifecycleCommit{AccountID: accountID, ExpectedState: current, ExpectedVersion: version, ExpectedRevocationStatus: storage.RevocationStatusNone, NextState: next, RevocationStatus: storage.RevocationStatusNone}
			if next == storage.AccountStateReauthorizationRequired {
				reason := storage.ReauthorizationReasonRefreshInvalidGrant
				commit.ReauthorizationReason = &reason
			}
			if next == storage.AccountStateRevoked {
				commit.RevocationStatus = storage.RevocationStatusPending
			}
			err := storage.ValidateLifecycleCommit(commit)
			if allowed[[2]storage.AccountState{current, next}] && err != nil {
				t.Fatalf("allowed transition %s -> %s error = %v", current.String(), next.String(), err)
			}
			if !allowed[[2]storage.AccountState{current, next}] && !errors.Is(err, storage.ErrLifecycleConflict) {
				t.Fatalf("forbidden transition %s -> %s error = %v", current.String(), next.String(), err)
			}
		}
	}
	claim := storage.LifecycleCommit{AccountID: accountID, ExpectedState: storage.AccountStateRevoked, ExpectedVersion: version, ExpectedRevocationStatus: storage.RevocationStatusPending, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusAttempting}
	if err := storage.ValidateLifecycleCommit(claim); err != nil {
		t.Fatalf("revocation claim error = %v", err)
	}
	for _, status := range []storage.RevocationStatus{storage.RevocationStatusConfirmed, storage.RevocationStatusManualActionRequired} {
		commit := storage.LifecycleCommit{AccountID: accountID, ExpectedState: storage.AccountStateRevoked, ExpectedVersion: version, ExpectedRevocationStatus: storage.RevocationStatusAttempting, NextState: storage.AccountStateRevoked, RevocationStatus: status}
		if err := storage.ValidateLifecycleCommit(commit); err != nil {
			t.Fatalf("revoked finalization %s error = %v", status.String(), err)
		}
		commit.ExpectedRevocationStatus = storage.RevocationStatusConfirmed
		if err := storage.ValidateLifecycleCommit(commit); !errors.Is(err, storage.ErrLifecycleConflict) {
			t.Fatalf("finalized status flip error = %v", err)
		}
	}
}

func TestFakeLifecycleBackfillTriggerListAndTransitions(t *testing.T) {
	t.Parallel()

	handle := storagefake.New()
	complete := accountSeed(t, "10101010101010101010101010101010", "lifecycle-complete")
	incomplete := accountSeed(t, "20202020202020202020202020202020", "lifecycle-incomplete")
	for _, seed := range []storage.AccountSeed{complete, incomplete} {
		if _, err := handle.EnsureAccount(context.Background(), seed); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := handle.GetAccountLifecycle(context.Background(), complete.ID)
	if err != nil || pending.State != storage.AccountStatePending || pending.Version.Int64() != 1 || pending.ReauthorizationReason != nil || pending.RevocationStatus != storage.RevocationStatusNone {
		t.Fatalf("trigger lifecycle = (%#v, %v), want pending version 1", pending, err)
	}
	if err := handle.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: complete.ID, Next: historyID(t, "7")}); err != nil {
		t.Fatal(err)
	}
	envelope := credentialEnvelope(t, structuralEnvelope("active", 32, 8))
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: complete.ID, Next: envelope}); err != nil {
		t.Fatal(err)
	}
	if err := handle.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{
		AccountID: complete.ID, ExpectedState: storage.AccountStatePending, ExpectedVersion: pending.Version,
		ExpectedRevocationStatus: storage.RevocationStatusNone, NextState: storage.AccountStateActive, RevocationStatus: storage.RevocationStatusNone,
	}); err != nil {
		t.Fatalf("activate complete account: %v", err)
	}
	active, err := handle.GetAccountLifecycle(context.Background(), complete.ID)
	if err != nil || active.State != storage.AccountStateActive || active.Version.Int64() != 2 {
		t.Fatalf("active lifecycle = (%#v, %v)", active, err)
	}
	if err := handle.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{
		AccountID: incomplete.ID, ExpectedState: storage.AccountStatePending, ExpectedVersion: pending.Version,
		ExpectedRevocationStatus: storage.RevocationStatusNone, NextState: storage.AccountStateActive, RevocationStatus: storage.RevocationStatusNone,
	}); !errors.Is(err, storage.ErrLifecycleIncomplete) {
		t.Fatalf("incomplete activation error = %v", err)
	}

	summaries, err := handle.ListAccounts(context.Background())
	if err != nil || len(summaries) != 2 {
		t.Fatalf("ListAccounts() = (%#v, %v)", summaries, err)
	}
	if summaries[0].AccountID.String() != complete.ID.String() || summaries[0].Provider != storage.ProviderGmail || summaries[0].State != storage.AccountStateActive || !summaries[0].CursorPresent || !summaries[0].CredentialPresent {
		t.Fatalf("first summary = %#v", summaries[0])
	}
	if summaries[1].AccountID.String() != incomplete.ID.String() || summaries[1].State != storage.AccountStatePending || summaries[1].CursorPresent || summaries[1].CredentialPresent {
		t.Fatalf("second summary = %#v", summaries[1])
	}

	pause := storage.LifecycleCommit{AccountID: complete.ID, ExpectedState: storage.AccountStateActive, ExpectedVersion: active.Version, ExpectedRevocationStatus: storage.RevocationStatusNone, NextState: storage.AccountStatePaused, RevocationStatus: storage.RevocationStatusNone}
	if err := handle.CommitAccountLifecycle(context.Background(), pause); err != nil {
		t.Fatal(err)
	}
	if err := handle.CommitAccountLifecycle(context.Background(), pause); err != nil {
		t.Fatalf("idempotent pause: %v", err)
	}
	paused, _ := handle.GetAccountLifecycle(context.Background(), complete.ID)
	if paused.Version.Int64() != 3 || paused.State != storage.AccountStatePaused {
		t.Fatalf("paused lifecycle = %#v", paused)
	}
	if err := handle.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: complete.ID, ExpectedState: storage.AccountStateActive, ExpectedVersion: active.Version, ExpectedRevocationStatus: storage.RevocationStatusNone, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusPending}); !errors.Is(err, storage.ErrLifecycleConflict) {
		t.Fatalf("stale transition error = %v", err)
	}
}

func TestFakeLifecycleReauthorizationRevocationAndExactCredentialDeletion(t *testing.T) {
	t.Parallel()

	handle := storagefake.New()
	seed := accountSeed(t, "30303030303030303030303030303030", "lifecycle-terminal")
	if _, err := handle.EnsureAccount(context.Background(), seed); err != nil {
		t.Fatal(err)
	}
	if err := handle.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: seed.ID, Next: historyID(t, "8")}); err != nil {
		t.Fatal(err)
	}
	envelope := credentialEnvelope(t, structuralEnvelope("active", 32, 9))
	other := credentialEnvelope(t, structuralEnvelope("active", 32, 10))
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: seed.ID, Next: envelope}); err != nil {
		t.Fatal(err)
	}
	pending, _ := handle.GetAccountLifecycle(context.Background(), seed.ID)
	if err := handle.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: seed.ID, ExpectedState: pending.State, ExpectedVersion: pending.Version, ExpectedRevocationStatus: storage.RevocationStatusNone, NextState: storage.AccountStateActive, RevocationStatus: storage.RevocationStatusNone}); err != nil {
		t.Fatal(err)
	}
	active, _ := handle.GetAccountLifecycle(context.Background(), seed.ID)
	reason := storage.ReauthorizationReasonGmailUnauthorizedAfterRefresh
	if err := handle.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: seed.ID, ExpectedState: active.State, ExpectedVersion: active.Version, ExpectedRevocationStatus: storage.RevocationStatusNone, NextState: storage.AccountStateReauthorizationRequired, ReauthorizationReason: &reason, RevocationStatus: storage.RevocationStatusNone}); err != nil {
		t.Fatal(err)
	}
	reauthorization, _ := handle.GetAccountLifecycle(context.Background(), seed.ID)
	if reauthorization.ReauthorizationReason == nil || *reauthorization.ReauthorizationReason != reason {
		t.Fatalf("reauthorization lifecycle = %#v", reauthorization)
	}
	if err := handle.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: seed.ID, ExpectedState: reauthorization.State, ExpectedVersion: reauthorization.Version, ExpectedRevocationStatus: storage.RevocationStatusNone, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusPending}); err != nil {
		t.Fatal(err)
	}
	revoked, _ := handle.GetAccountLifecycle(context.Background(), seed.ID)
	if err := handle.DeleteRevokedProviderCredential(context.Background(), storage.RevokedCredentialDelete{AccountID: seed.ID, Expected: other}); !errors.Is(err, storage.ErrCredentialConflict) {
		t.Fatalf("wrong credential delete error = %v", err)
	}
	if err := handle.DeleteRevokedProviderCredential(context.Background(), storage.RevokedCredentialDelete{AccountID: seed.ID, Expected: envelope}); err != nil {
		t.Fatal(err)
	}
	if _, err := handle.GetProviderCredential(context.Background(), seed.ID); !errors.Is(err, storage.ErrCredentialNotFound) {
		t.Fatalf("credential after delete error = %v", err)
	}
	if err := handle.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: seed.ID, ExpectedState: revoked.State, ExpectedVersion: revoked.Version, ExpectedRevocationStatus: storage.RevocationStatusPending, NextState: storage.AccountStateActive, RevocationStatus: storage.RevocationStatusNone}); !errors.Is(err, storage.ErrLifecycleConflict) {
		t.Fatalf("revoked terminal transition error = %v", err)
	}
}

func TestFakeCredentialCommitRejectsEveryRevokedLifecycle(t *testing.T) {
	handle := storagefake.New()
	seed := accountSeed(t, "35353535353535353535353535353535", "revoked-credential-guard")
	if _, err := handle.EnsureAccount(context.Background(), seed); err != nil {
		t.Fatal(err)
	}
	envelope := credentialEnvelope(t, structuralEnvelope("active", 32, 70))
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: seed.ID, Next: envelope}); err != nil {
		t.Fatal(err)
	}
	pending, _ := handle.GetAccountLifecycle(context.Background(), seed.ID)
	if err := handle.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: seed.ID, ExpectedState: pending.State, ExpectedVersion: pending.Version, ExpectedRevocationStatus: pending.RevocationStatus, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusPending}); err != nil {
		t.Fatal(err)
	}
	replacement := credentialEnvelope(t, structuralEnvelope("active", 32, 71))
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: seed.ID, Expected: &envelope, Next: replacement}); !errors.Is(err, storage.ErrLifecycleConflict) {
		t.Fatalf("revoked replacement error = %v", err)
	}
	if err := handle.DeleteRevokedProviderCredential(context.Background(), storage.RevokedCredentialDelete{AccountID: seed.ID, Expected: envelope}); err != nil {
		t.Fatal(err)
	}
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: seed.ID, Next: replacement}); !errors.Is(err, storage.ErrLifecycleConflict) {
		t.Fatalf("revoked initialization error = %v", err)
	}
}

func TestFakeLifecycleConcurrentCASHasOneWinnerAndVersionNeverOverflows(t *testing.T) {
	t.Parallel()

	handle := storagefake.New()
	seed := accountSeed(t, "40404040404040404040404040404040", "lifecycle-concurrent")
	if _, err := handle.EnsureAccount(context.Background(), seed); err != nil {
		t.Fatal(err)
	}
	current, _ := handle.GetAccountLifecycle(context.Background(), seed.ID)
	start := make(chan struct{})
	results := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for _, state := range []storage.AccountState{storage.AccountStateRevoked, storage.AccountStateRevoked} {
		go func(state storage.AccountState) {
			ready.Done()
			<-start
			results <- handle.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: seed.ID, ExpectedState: current.State, ExpectedVersion: current.Version, ExpectedRevocationStatus: storage.RevocationStatusNone, NextState: state, RevocationStatus: storage.RevocationStatusPending})
		}(state)
	}
	ready.Wait()
	close(start)
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		} else if !errors.Is(err, storage.ErrLifecycleConflict) {
			t.Fatalf("concurrent transition error = %v", err)
		}
	}
	if successes != 2 {
		t.Fatalf("concurrent same-target successes = %d, want idempotent 2", successes)
	}
	if got, _ := handle.GetAccountLifecycle(context.Background(), seed.ID); got.Version.Int64() != 2 {
		t.Fatalf("version after idempotent race = %d, want 2", got.Version.Int64())
	}
	maxVersion, _ := storage.ParseLifecycleVersion(math.MaxInt64)
	commit := storage.LifecycleCommit{AccountID: seed.ID, ExpectedState: storage.AccountStateRevoked, ExpectedVersion: maxVersion, ExpectedRevocationStatus: storage.RevocationStatusAttempting, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusConfirmed}
	if err := storage.ValidateLifecycleCommit(commit); !errors.Is(err, storage.ErrLifecycleOverflow) {
		t.Fatalf("maximum-version transition error = %v", err)
	}
}

func TestFakeAccountListAcceptsExactBoundRejectsOverflowAndReturnsAtomicSnapshots(t *testing.T) {
	makeStore := func(count int) *storagefake.Store {
		t.Helper()
		handle := storagefake.New()
		for index := 0; index < count; index++ {
			seed := accountSeed(t, fmt.Sprintf("%032x", index+1), fmt.Sprintf("list-subject-%03d", index+1))
			if _, err := handle.EnsureAccount(context.Background(), seed); err != nil {
				t.Fatal(err)
			}
		}
		return handle
	}
	exact := makeStore(storage.MaximumAccountList)
	summaries, err := exact.ListAccounts(context.Background())
	if err != nil || len(summaries) != storage.MaximumAccountList {
		t.Fatalf("exact-bound fake list = (%d, %v)", len(summaries), err)
	}
	for index, summary := range summaries {
		if index > 0 && summaries[index-1].AccountID.String() >= summary.AccountID.String() {
			t.Fatal("fake list was not bytewise ordered")
		}
		if summary.State != storage.AccountStatePending || summary.StateVersion.Int64() != 1 || summary.RevocationStatus != storage.RevocationStatusNone {
			t.Fatalf("fake summary crossed a lifecycle snapshot: %#v", summary)
		}
	}
	if _, err := makeStore(storage.MaximumAccountList + 1).ListAccounts(context.Background()); !errors.Is(err, storage.ErrResultTooLarge) {
		t.Fatalf("overflow fake list error = %v", err)
	}

	seed := accountSeed(t, "ffffffffffffffffffffffffffffffff", "snapshot-race")
	tracing := storagefake.New()
	if _, err := tracing.EnsureAccount(context.Background(), seed); err != nil {
		t.Fatal(err)
	}
	current, _ := tracing.GetAccountLifecycle(context.Background(), seed.ID)
	commit := storage.LifecycleCommit{AccountID: seed.ID, ExpectedState: current.State, ExpectedVersion: current.Version, ExpectedRevocationStatus: current.RevocationStatus, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusPending}
	start := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		<-start
		result <- tracing.CommitAccountLifecycle(context.Background(), commit)
	}()
	close(start)
	for index := 0; index < 100; index++ {
		rows, listErr := tracing.ListAccounts(context.Background())
		if listErr != nil || len(rows) != 1 {
			t.Fatalf("snapshot list = (%#v, %v)", rows, listErr)
		}
		row := rows[0]
		pending := row.State == storage.AccountStatePending && row.StateVersion.Int64() == 1 && row.RevocationStatus == storage.RevocationStatusNone
		revoked := row.State == storage.AccountStateRevoked && row.StateVersion.Int64() == 2 && row.RevocationStatus == storage.RevocationStatusPending
		if !pending && !revoked {
			t.Fatalf("crossed fake list snapshot = %#v", row)
		}
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestFakeLifecycleAndCredentialConcurrencyMatrix(t *testing.T) {
	t.Run("identical pause and resume increment once", func(t *testing.T) {
		handle, accountID, _ := seedFakeActiveLifecycle(t, "41414141414141414141414141414141", "fake-identical", 79)
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
			for range 2 {
				go func() {
					<-start
					results <- handle.CommitAccountLifecycle(context.Background(), commit)
				}()
			}
			close(start)
			for range 2 {
				if err := <-results; err != nil {
					t.Fatalf("identical fake transition error = %v", err)
				}
			}
			current, _ := handle.GetAccountLifecycle(context.Background(), accountID)
			if current.State != transition.next || current.Version.Int64() != transition.version+1 {
				t.Fatalf("identical fake transition = %#v", current)
			}
		}
	})

	t.Run("pause versus revoke has one durable winner", func(t *testing.T) {
		handle, accountID, _ := seedFakeActiveLifecycle(t, "42424242424242424242424242424242", "fake-different", 80)
		version, _ := storage.ParseLifecycleVersion(2)
		commits := []storage.LifecycleCommit{
			{AccountID: accountID, ExpectedState: storage.AccountStateActive, ExpectedVersion: version, ExpectedRevocationStatus: storage.RevocationStatusNone, NextState: storage.AccountStatePaused, RevocationStatus: storage.RevocationStatusNone},
			{AccountID: accountID, ExpectedState: storage.AccountStateActive, ExpectedVersion: version, ExpectedRevocationStatus: storage.RevocationStatusNone, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusPending},
		}
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, commit := range commits {
			go func(commit storage.LifecycleCommit) {
				<-start
				results <- handle.CommitAccountLifecycle(context.Background(), commit)
			}(commit)
		}
		close(start)
		successes, conflicts := 0, 0
		for range 2 {
			if err := <-results; err == nil {
				successes++
			} else if errors.Is(err, storage.ErrLifecycleConflict) {
				conflicts++
			} else {
				t.Fatalf("different fake transition error = %v", err)
			}
		}
		current, _ := handle.GetAccountLifecycle(context.Background(), accountID)
		if successes != 1 || conflicts != 1 || current.Version.Int64() != 3 || current.State != storage.AccountStatePaused && current.State != storage.AccountStateRevoked {
			t.Fatalf("different fake transition = %#v, successes=%d conflicts=%d", current, successes, conflicts)
		}
	})

	t.Run("credential insert versus delete and duplicate delete", func(t *testing.T) {
		handle, accountID, envelope := seedFakeActiveLifecycle(t, "43434343434343434343434343434343", "fake-credential-race", 81)
		active, _ := handle.GetAccountLifecycle(context.Background(), accountID)
		if err := handle.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: accountID, ExpectedState: active.State, ExpectedVersion: active.Version, ExpectedRevocationStatus: active.RevocationStatus, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusPending}); err != nil {
			t.Fatal(err)
		}
		replacement := credentialEnvelope(t, structuralEnvelope("active", 32, 82))
		start := make(chan struct{})
		results := make(chan error, 2)
		go func() {
			<-start
			results <- handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: accountID, Expected: &envelope, Next: replacement})
		}()
		go func() {
			<-start
			results <- handle.DeleteRevokedProviderCredential(context.Background(), storage.RevokedCredentialDelete{AccountID: accountID, Expected: envelope})
		}()
		close(start)
		successes, conflicts := 0, 0
		for range 2 {
			if err := <-results; err == nil {
				successes++
			} else if errors.Is(err, storage.ErrLifecycleConflict) {
				conflicts++
			} else {
				t.Fatalf("fake credential race error = %v", err)
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Fatalf("fake credential race successes=%d conflicts=%d", successes, conflicts)
		}
		deleteResults := make(chan error, 2)
		for range 2 {
			go func() {
				deleteResults <- handle.DeleteRevokedProviderCredential(context.Background(), storage.RevokedCredentialDelete{AccountID: accountID, Expected: envelope})
			}()
		}
		for range 2 {
			if err := <-deleteResults; err != nil {
				t.Fatalf("duplicate fake delete error = %v", err)
			}
		}
	})
}

func seedFakeActiveLifecycle(t *testing.T, rawID, subject string, fill byte) (*storagefake.Store, storage.AccountID, storage.CredentialEnvelope) {
	t.Helper()
	handle := storagefake.New()
	seed := accountSeed(t, rawID, subject)
	if _, err := handle.EnsureAccount(context.Background(), seed); err != nil {
		t.Fatal(err)
	}
	history, _ := storage.ParseHistoryID("1")
	if err := handle.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: seed.ID, Next: history}); err != nil {
		t.Fatal(err)
	}
	envelope := credentialEnvelope(t, structuralEnvelope("active", 32, fill))
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: seed.ID, Next: envelope}); err != nil {
		t.Fatal(err)
	}
	pending, _ := handle.GetAccountLifecycle(context.Background(), seed.ID)
	if err := handle.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: seed.ID, ExpectedState: pending.State, ExpectedVersion: pending.Version, ExpectedRevocationStatus: pending.RevocationStatus, NextState: storage.AccountStateActive, RevocationStatus: storage.RevocationStatusNone}); err != nil {
		t.Fatal(err)
	}
	return handle, seed.ID, envelope
}
