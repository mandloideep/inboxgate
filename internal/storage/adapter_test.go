package storage_test

import (
	"context"
	"testing"

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
func (h *fakeHandle) Close() error { return nil }

var _ storage.Adapter = (*fakeAdapter)(nil)
var _ storage.Handle = (*fakeHandle)(nil)
