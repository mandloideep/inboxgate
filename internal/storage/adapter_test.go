package storage_test

import (
	"context"
	"testing"

	"github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
)

func TestAdapterContractAllowsReplacementWithoutDriverTypes(t *testing.T) {
	t.Parallel()

	want := storage.Endpoint{URL: "turso://database.example", Token: "synthetic-token"}
	adapter := &fakeAdapter{handle: &fakeHandle{}}

	handle, err := adapter.Open(context.Background(), want)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if adapter.got != want {
		t.Fatalf("Open() endpoint = %#v, want %#v", adapter.got, want)
	}
	if err := handle.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

type fakeAdapter struct {
	got    storage.Endpoint
	handle storage.Handle
}

func (a *fakeAdapter) Open(_ context.Context, endpoint storage.Endpoint) (storage.Handle, error) {
	a.got = endpoint
	return a.handle, nil
}

type fakeHandle struct{}

func (h *fakeHandle) Ping(context.Context) error { return nil }
func (h *fakeHandle) Migrate(context.Context) (storage.MigrationResult, error) {
	return storage.MigrationResult{}, nil
}
func (h *fakeHandle) EnsureAccount(context.Context, storage.AccountSeed) (storage.Account, error) {
	return storage.Account{}, nil
}
func (h *fakeHandle) GetSynchronizationCursor(context.Context, storage.AccountID) (storage.SynchronizationCursor, error) {
	return storage.SynchronizationCursor{}, nil
}
func (h *fakeHandle) CommitSynchronization(context.Context, storage.SynchronizationCommit) error {
	return nil
}
func (h *fakeHandle) GetProviderCredential(context.Context, storage.AccountID) (storage.ProviderCredential, error) {
	return storage.ProviderCredential{}, nil
}
func (h *fakeHandle) CommitProviderCredential(context.Context, storage.ProviderCredentialCommit) error {
	return nil
}
func (h *fakeHandle) ListAccounts(context.Context) ([]storage.AccountSummary, error) { return nil, nil }
func (h *fakeHandle) GetAccountLifecycle(context.Context, storage.AccountID) (storage.AccountLifecycle, error) {
	return storage.AccountLifecycle{}, nil
}
func (h *fakeHandle) CommitAccountLifecycle(context.Context, storage.LifecycleCommit) error {
	return nil
}
func (h *fakeHandle) DeleteRevokedProviderCredential(context.Context, storage.RevokedCredentialDelete) error {
	return nil
}
func (h *fakeHandle) CommitCurrentDiscovery(context.Context, storage.CurrentDiscoveryCommit) error {
	return nil
}
func (h *fakeHandle) ReconcileCurrentDiscovery(context.Context, storage.AccountID) error { return nil }
func (h *fakeHandle) GetDiscoveredMessage(context.Context, storage.AccountID, string) (mail.Message, error) {
	return mail.Message{}, nil
}
func (h *fakeHandle) GetGateDecision(context.Context, storage.AccountID, string) (storage.GateDecisionState, error) {
	return storage.GateDecisionState{}, nil
}
func (h *fakeHandle) CommitGateDecision(context.Context, storage.GateDecisionCommit) error {
	return nil
}
func (h *fakeHandle) Close() error { return nil }

var _ storage.Adapter = (*fakeAdapter)(nil)
var _ storage.Handle = (*fakeHandle)(nil)
