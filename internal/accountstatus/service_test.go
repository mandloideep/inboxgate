package accountstatus

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/storage"
)

const (
	accountIDA = "0000000000000000000000000000000a"
	accountIDB = "0000000000000000000000000000000b"
)

type sourceStub struct {
	accounts []storage.AccountSummary
	err      error
	calls    atomic.Int64
	wait     bool
}

func (source *sourceStub) ListAccounts(ctx context.Context) ([]storage.AccountSummary, error) {
	source.calls.Add(1)
	if source.wait {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return append([]storage.AccountSummary(nil), source.accounts...), source.err
}

func summary(t *testing.T, rawID string, state storage.AccountState, cursor bool) storage.AccountSummary {
	t.Helper()
	id, err := storage.ParseAccountID(rawID)
	if err != nil {
		t.Fatal(err)
	}
	version, err := storage.ParseLifecycleVersion(2)
	if err != nil {
		t.Fatal(err)
	}
	return storage.AccountSummary{
		AccountID: id, Provider: storage.ProviderGmail, State: state, StateVersion: version,
		RevocationStatus: storage.RevocationStatusNone, CursorPresent: cursor,
	}
}

func operatorConfiguration() config.Config {
	configuration := config.Defaults()
	configuration.MCP.Enabled = true
	configuration.MCP.EnableOperatorTools = true
	return configuration
}

func TestSnapshotUsesOneBoundedSortedSourceReadAndReturnsFreshValues(t *testing.T) {
	source := &sourceStub{accounts: []storage.AccountSummary{
		summary(t, accountIDA, storage.AccountStateActive, false),
		summary(t, accountIDB, storage.AccountStatePaused, true),
	}}
	service, err := New(source, config.CapabilityRegistry(operatorConfiguration()))
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if source.calls.Load() != 1 || len(first.Accounts) != 2 {
		t.Fatalf("source calls = %d, accounts = %d", source.calls.Load(), len(first.Accounts))
	}
	if first.Accounts[0].AccountID != accountIDA || first.Accounts[1].AccountID != accountIDB {
		t.Fatalf("account order = %#v", first.Accounts)
	}
	first.Accounts[0].AccountID = strings.Repeat("f", 32)
	second, err := service.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if source.calls.Load() != 2 || second.Accounts[0].AccountID != accountIDA {
		t.Fatal("prior result mutation affected a fresh snapshot")
	}
}

func TestSnapshotAcceptsZeroOneAndOneHundredAndRejectsOneHundredOne(t *testing.T) {
	for _, count := range []int{0, 1, 100, 101} {
		t.Run(string(rune('a'+count%26)), func(t *testing.T) {
			accounts := make([]storage.AccountSummary, 0, count)
			for index := 0; index < count; index++ {
				accounts = append(accounts, summary(t, strings.Repeat("0", 30)+byteHex(index), storage.AccountStateActive, index%2 == 0))
			}
			service, err := New(&sourceStub{accounts: accounts}, config.CapabilityRegistry(operatorConfiguration()))
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.Snapshot(context.Background())
			if count <= 100 && (err != nil || len(result.Accounts) != count) {
				t.Fatalf("Snapshot() = (%d, %v), want %d accounts", len(result.Accounts), err, count)
			}
			if count == 101 && !errors.Is(err, ErrUnavailable) {
				t.Fatalf("Snapshot() error = %v, want fixed unavailable", err)
			}
		})
	}
}

func byteHex(value int) string {
	const alphabet = "0123456789abcdef"
	return string([]byte{alphabet[(value>>4)&15], alphabet[value&15]})
}

func TestSnapshotRejectsMalformedDuplicateAndUnsortedSourceRows(t *testing.T) {
	validA := summary(t, accountIDA, storage.AccountStateActive, false)
	validB := summary(t, accountIDB, storage.AccountStatePaused, true)
	badReason := storage.ReauthorizationReasonRefreshInvalidGrant
	invalid := []struct {
		name     string
		accounts []storage.AccountSummary
	}{
		{name: "zero value", accounts: []storage.AccountSummary{{}}},
		{name: "duplicate", accounts: []storage.AccountSummary{validA, validA}},
		{name: "unsorted", accounts: []storage.AccountSummary{validB, validA}},
		{name: "provider", accounts: []storage.AccountSummary{func() storage.AccountSummary { value := validA; value.Provider = "other"; return value }()}},
		{name: "reason outside state", accounts: []storage.AccountSummary{func() storage.AccountSummary { value := validA; value.ReauthorizationReason = &badReason; return value }()}},
		{name: "revocation outside state", accounts: []storage.AccountSummary{func() storage.AccountSummary {
			value := validA
			value.RevocationStatus = storage.RevocationStatusPending
			return value
		}()}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			service, err := New(&sourceStub{accounts: test.accounts}, config.CapabilityRegistry(operatorConfiguration()))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.Snapshot(context.Background()); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), accountIDA) {
				t.Fatalf("Snapshot() error = %v", err)
			}
		})
	}
}

func TestSynchronizationTruthComesOnlyFromExactRegistryAndCursorPresence(t *testing.T) {
	configuration := operatorConfiguration()
	service, err := New(&sourceStub{accounts: []storage.AccountSummary{
		summary(t, accountIDA, storage.AccountStateActive, false),
		summary(t, accountIDB, storage.AccountStateActive, true),
	}}, config.CapabilityRegistry(configuration))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.CurrentSync.ImplementationStatus != config.ImplementationStatusNotImplemented ||
		snapshot.CurrentSync.ConfigurationStatus != config.ConfigurationStatusDisabled || snapshot.CurrentSync.Enabled {
		t.Fatalf("current sync truth = %#v", snapshot.CurrentSync)
	}
	if snapshot.Backfill.ImplementationStatus != config.ImplementationStatusNotImplemented ||
		snapshot.Backfill.ConfigurationStatus != config.ConfigurationStatusDisabled || snapshot.Backfill.Enabled {
		t.Fatalf("backfill truth = %#v", snapshot.Backfill)
	}
	if snapshot.Accounts[0].CursorStatus != CursorStatusUninitialized || snapshot.Accounts[1].CursorStatus != CursorStatusInitialized {
		t.Fatalf("cursor statuses = %#v", snapshot.Accounts)
	}
	for _, account := range snapshot.Accounts {
		if account.CurrentExecutionStatus != AvailabilityNotAvailable || account.CurrentStaleStatus != PersistenceNotPersisted || account.LastSuccessAt != nil || account.LastErrorCategory != nil ||
			account.BackfillExecutionStatus != AvailabilityNotAvailable || account.BackfillCheckpointStatus != PersistenceNotPersisted || account.BackfillProgress != nil {
			t.Fatalf("unpersisted status was fabricated: %#v", account)
		}
	}
}

func TestRegistryCompositionFailsClosedOnMissingDuplicateMalformedOrEnabledEntries(t *testing.T) {
	base := config.CapabilityRegistry(operatorConfiguration())
	tests := []struct {
		name   string
		mutate func([]config.Capability) []config.Capability
	}{
		{name: "missing current", mutate: func(values []config.Capability) []config.Capability {
			return removeCapability(values, config.CapabilityGmailCurrentSync)
		}},
		{name: "missing backfill", mutate: func(values []config.Capability) []config.Capability {
			return removeCapability(values, config.CapabilityGmailBackfill)
		}},
		{name: "duplicate", mutate: func(values []config.Capability) []config.Capability { return append(values, values[0]) }},
		{name: "unexpected current enabled", mutate: func(values []config.Capability) []config.Capability {
			for index := range values {
				if values[index].Name == config.CapabilityGmailCurrentSync {
					values[index].Enabled = true
				}
			}
			return values
		}},
		{name: "unexpected backfill enabled", mutate: func(values []config.Capability) []config.Capability {
			for index := range values {
				if values[index].Name == config.CapabilityGmailBackfill {
					values[index].Enabled = true
				}
			}
			return values
		}},
		{name: "malformed status", mutate: func(values []config.Capability) []config.Capability {
			for index := range values {
				if values[index].Name == config.CapabilityGmailCurrentSync {
					values[index].ImplementationStatus = "other"
				}
			}
			return values
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry := append([]config.Capability(nil), base...)
			if _, err := New(&sourceStub{}, test.mutate(registry)); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("New() error = %v", err)
			}
		})
	}
}

func removeCapability(values []config.Capability, name config.CapabilityName) []config.Capability {
	result := make([]config.Capability, 0, len(values))
	for _, value := range values {
		if value.Name != name {
			result = append(result, value)
		}
	}
	return result
}

func TestSourceFailureCancellationAndDeadlineAreFixedAndNeverRetried(t *testing.T) {
	source := &sourceStub{err: errors.New("raw SQL synthetic secret marker")}
	service, err := New(source, config.CapabilityRegistry(operatorConfiguration()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Snapshot(context.Background()); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "raw SQL") || source.calls.Load() != 1 {
		t.Fatalf("source failure = %v, calls = %d", err, source.calls.Load())
	}

	blocked := &sourceStub{wait: true}
	service, err = New(blocked, config.CapabilityRegistry(operatorConfiguration()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := service.Snapshot(ctx); !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) || blocked.calls.Load() != 1 {
		t.Fatalf("deadline failure = %v, calls = %d", err, blocked.calls.Load())
	}
}

func FuzzSnapshotCompositionIsBoundedAndDeterministic(f *testing.F) {
	f.Add(uint8(0), false)
	f.Add(uint8(2), true)
	f.Fuzz(func(t *testing.T, count uint8, cursor bool) {
		bounded := int(count % 102)
		accounts := make([]storage.AccountSummary, 0, bounded)
		for index := 0; index < bounded; index++ {
			accounts = append(accounts, summary(t, strings.Repeat("0", 30)+byteHex(index), storage.AccountStateActive, cursor))
		}
		service, err := New(&sourceStub{accounts: accounts}, config.CapabilityRegistry(operatorConfiguration()))
		if err != nil {
			t.Fatal(err)
		}
		first, firstErr := service.Snapshot(context.Background())
		second, secondErr := service.Snapshot(context.Background())
		if (firstErr != nil) != (bounded > storage.MaximumAccountList) || !reflect.DeepEqual(first, second) || (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("count=%d first=(%#v,%v) second=(%#v,%v)", bounded, first, firstErr, second, secondErr)
		}
	})
}
