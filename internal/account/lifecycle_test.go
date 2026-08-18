package account

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/cryptobox"
	"github.com/mandloideep/inboxgate/internal/storage"
	storagefake "github.com/mandloideep/inboxgate/internal/storage/fake"
)

func TestManagerPauseResumeAndTypedReauthorization(t *testing.T) {
	t.Parallel()

	store := storagefake.New()
	id := seedActiveAccount(t, store, "51515151515151515151515151515151", "manager-state")
	manager := New(store, nil)
	if err := manager.Pause(context.Background(), id); err != nil {
		t.Fatalf("Pause() error = %v", err)
	}
	if err := manager.Pause(context.Background(), id); err != nil {
		t.Fatalf("idempotent Pause() error = %v", err)
	}
	paused, _ := store.GetAccountLifecycle(context.Background(), id)
	if paused.State != storage.AccountStatePaused || paused.Version.Int64() != 3 {
		t.Fatalf("paused lifecycle = %#v", paused)
	}
	if err := manager.Resume(context.Background(), id); err != nil {
		t.Fatalf("Resume() error = %v", err)
	}
	if err := manager.MarkReauthorizationRequired(context.Background(), id, storage.ReauthorizationReasonRefreshInvalidGrant); err != nil {
		t.Fatalf("MarkReauthorizationRequired() error = %v", err)
	}
	state, _ := store.GetAccountLifecycle(context.Background(), id)
	if state.State != storage.AccountStateReauthorizationRequired || state.ReauthorizationReason == nil || *state.ReauthorizationReason != storage.ReauthorizationReasonRefreshInvalidGrant {
		t.Fatalf("reauthorization lifecycle = %#v", state)
	}
	if err := manager.Resume(context.Background(), id); !errors.Is(err, ErrTransition) {
		t.Fatalf("Resume() from reauthorization error = %v", err)
	}
}

func TestManagerRevokePersistsIntentBeforeOneFixedProviderRequestAndDeletesCredential(t *testing.T) {
	var requests atomic.Int32
	var sawDurableIntent atomic.Bool
	store := storagefake.New()
	id := seedActiveAccount(t, store, "61616161616161616161616161616161", "manager-revoke")
	ring := testKeyring(t)
	t.Cleanup(func() { _ = ring.Close() })
	envelopeText, err := ring.EncryptRefreshToken(id.String(), []byte("synthetic-revocation-token"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := storage.ParseCredentialEnvelope(envelopeText)
	current, _ := store.GetProviderCredential(context.Background(), id)
	if err := store.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: id, Expected: &current.Envelope, Next: envelope}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		lifecycle, lifecycleErr := store.GetAccountLifecycle(context.Background(), id)
		if lifecycleErr == nil && lifecycle.State == storage.AccountStateRevoked && lifecycle.RevocationStatus == storage.RevocationStatusAttempting {
			sawDurableIntent.Store(true)
		}
		if request.Method != http.MethodPost || request.URL.Path != "/revoke" || request.URL.RawQuery != "" || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" || request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("unexpected revocation request")
		}
		body, _ := io.ReadAll(request.Body)
		values, parseErr := url.ParseQuery(string(body))
		if parseErr != nil || len(values) != 1 || len(values["token"]) != 1 || values.Get("token") != "synthetic-revocation-token" {
			t.Errorf("revocation body has wrong shape")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	manager := newManager(store, ring, managerDependencies{revocationEndpoint: server.URL + "/revoke", transport: server.Client().Transport})
	result, err := manager.Revoke(context.Background(), id)
	if err != nil || result != RevocationConfirmed {
		t.Fatalf("Revoke() = (%q, %v)", result, err)
	}
	if requests.Load() != 1 || !sawDurableIntent.Load() {
		t.Fatalf("provider requests = %d, durable intent = %v", requests.Load(), sawDurableIntent.Load())
	}
	state, _ := store.GetAccountLifecycle(context.Background(), id)
	if state.RevocationStatus != storage.RevocationStatusConfirmed || state.Version.Int64() != 5 {
		t.Fatalf("final lifecycle = %#v", state)
	}
	if _, err := store.GetProviderCredential(context.Background(), id); !errors.Is(err, storage.ErrCredentialNotFound) {
		t.Fatalf("credential after revoke error = %v", err)
	}
	result, err = manager.Revoke(context.Background(), id)
	if err != nil || result != RevocationConfirmed || requests.Load() != 1 {
		t.Fatalf("repeated Revoke() = (%q, %v), requests %d", result, err, requests.Load())
	}
}

func TestManagerRevocationRestartAndEveryProviderOutcomeFailClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		status     int
		wantResult RevocationResult
	}{
		{name: "bad request is manual", status: http.StatusBadRequest, wantResult: RevocationManual},
		{name: "server error is manual", status: http.StatusServiceUnavailable, wantResult: RevocationManual},
		{name: "success is confirmed", status: http.StatusOK, wantResult: RevocationConfirmed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := storagefake.New()
			id := seedActiveAccount(t, store, "71717171717171717171717171717171", "manager-restart")
			ring := testKeyring(t)
			t.Cleanup(func() { _ = ring.Close() })
			envelopeText, _ := ring.EncryptRefreshToken(id.String(), []byte("synthetic-restart-token"))
			envelope, _ := storage.ParseCredentialEnvelope(envelopeText)
			old, _ := store.GetProviderCredential(context.Background(), id)
			if err := store.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: id, Expected: &old.Envelope, Next: envelope}); err != nil {
				t.Fatal(err)
			}
			active, _ := store.GetAccountLifecycle(context.Background(), id)
			if err := store.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: id, ExpectedState: active.State, ExpectedVersion: active.Version, ExpectedRevocationStatus: active.RevocationStatus, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusPending}); err != nil {
				t.Fatal(err)
			}
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(tt.status)
			}))
			defer server.Close()
			fresh := newManager(store, ring, managerDependencies{revocationEndpoint: server.URL, transport: server.Client().Transport})
			result, err := fresh.Revoke(context.Background(), id)
			if result != tt.wantResult || (tt.wantResult == RevocationConfirmed && err != nil) || (tt.wantResult == RevocationManual && !errors.Is(err, ErrProviderRevocation)) {
				t.Fatalf("fresh Revoke() = (%q, %v)", result, err)
			}
			if requests.Load() != 1 {
				t.Fatalf("provider requests = %d, want 1", requests.Load())
			}
			if _, err := store.GetProviderCredential(context.Background(), id); !errors.Is(err, storage.ErrCredentialNotFound) {
				t.Fatalf("credential cleanup error = %v", err)
			}
		})
	}
}

func TestManagerRevokeMissingOrUndecryptableCredentialIsManualWithoutProviderCall(t *testing.T) {
	t.Parallel()

	store := storagefake.New()
	id := seedActiveAccount(t, store, "81818181818181818181818181818181", "manager-missing")
	credential, _ := store.GetProviderCredential(context.Background(), id)
	active, _ := store.GetAccountLifecycle(context.Background(), id)
	if err := store.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: id, ExpectedState: active.State, ExpectedVersion: active.Version, ExpectedRevocationStatus: active.RevocationStatus, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusPending}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteRevokedProviderCredential(context.Background(), storage.RevokedCredentialDelete{AccountID: id, Expected: credential.Envelope}); err != nil {
		t.Fatal(err)
	}
	manager := New(store, testKeyring(t))
	result, err := manager.Revoke(context.Background(), id)
	if result != RevocationManual || !errors.Is(err, ErrProviderRevocation) {
		t.Fatalf("Revoke() without credential = (%q, %v)", result, err)
	}
}

func TestManagerUnknownKeyAndAuthenticationFailureFinalizeManualWithoutProvider(t *testing.T) {
	for _, tt := range []struct {
		name     string
		envelope func(*testing.T, storage.AccountID, *cryptobox.Keyring) storage.CredentialEnvelope
	}{
		{
			name: "unknown key",
			envelope: func(t *testing.T, accountID storage.AccountID, _ *cryptobox.Keyring) storage.CredentialEnvelope {
				otherKey := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("o", 32)))
				other, err := cryptobox.ParseKeyring([]byte("igk1:other=" + otherKey))
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				text, err := other.EncryptRefreshToken(accountID.String(), []byte("synthetic-unknown-key-token"))
				if err != nil {
					t.Fatal(err)
				}
				parsed, _ := storage.ParseCredentialEnvelope(text)
				return parsed
			},
		},
		{
			name: "authentication failure",
			envelope: func(t *testing.T, accountID storage.AccountID, ring *cryptobox.Keyring) storage.CredentialEnvelope {
				text, err := ring.EncryptRefreshToken(accountID.String(), []byte("synthetic-auth-failure-token"))
				if err != nil {
					t.Fatal(err)
				}
				last := byte('A')
				if text[len(text)-1] == 'A' {
					last = 'B'
				}
				text = text[:len(text)-1] + string(last)
				parsed, err := storage.ParseCredentialEnvelope(text)
				if err != nil {
					t.Fatal(err)
				}
				return parsed
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := storagefake.New()
			id := seedActiveAccount(t, store, "86868686868686868686868686868686", "manager-decrypt-failure")
			ring := testKeyring(t)
			t.Cleanup(func() { _ = ring.Close() })
			next := tt.envelope(t, id, ring)
			current, _ := store.GetProviderCredential(context.Background(), id)
			if err := store.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: id, Expected: &current.Envelope, Next: next}); err != nil {
				t.Fatal(err)
			}
			var requests atomic.Int32
			manager := newManager(store, ring, managerDependencies{transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				requests.Add(1)
				return nil, errors.New("provider must not be called")
			})})
			result, err := manager.Revoke(context.Background(), id)
			if result != RevocationManual || !errors.Is(err, ErrProviderRevocation) || requests.Load() != 0 {
				t.Fatalf("Revoke() = (%q, %v), requests=%d", result, err, requests.Load())
			}
			lifecycle, _ := store.GetAccountLifecycle(context.Background(), id)
			if lifecycle.RevocationStatus != storage.RevocationStatusManualActionRequired {
				t.Fatalf("decrypt-failure lifecycle = %#v", lifecycle)
			}
			if _, err := store.GetProviderCredential(context.Background(), id); !errors.Is(err, storage.ErrCredentialNotFound) {
				t.Fatalf("decrypt-failure credential = %v", err)
			}
		})
	}
}

func TestManagerRestartFromAttemptingNeverCallsProviderAndFinalizesManual(t *testing.T) {
	store := storagefake.New()
	id := seedActiveAccount(t, store, "83838383838383838383838383838383", "manager-attempting-restart")
	active, _ := store.GetAccountLifecycle(context.Background(), id)
	intent := storage.LifecycleCommit{AccountID: id, ExpectedState: active.State, ExpectedVersion: active.Version, ExpectedRevocationStatus: active.RevocationStatus, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusPending}
	if err := store.CommitAccountLifecycle(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	pending, _ := store.GetAccountLifecycle(context.Background(), id)
	claim := storage.LifecycleCommit{AccountID: id, ExpectedState: pending.State, ExpectedVersion: pending.Version, ExpectedRevocationStatus: pending.RevocationStatus, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusAttempting}
	if err := store.CommitAccountLifecycle(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	t.Cleanup(server.Close)
	manager := newManager(store, testKeyring(t), managerDependencies{revocationEndpoint: server.URL, transport: server.Client().Transport})
	result, err := manager.Revoke(context.Background(), id)
	if result != RevocationManual || !errors.Is(err, ErrProviderRevocation) || requests.Load() != 0 {
		t.Fatalf("attempting restart = (%q, %v), requests=%d", result, err, requests.Load())
	}
	final, _ := store.GetAccountLifecycle(context.Background(), id)
	if final.RevocationStatus != storage.RevocationStatusManualActionRequired || final.Version.Int64() != 5 {
		t.Fatalf("attempting restart lifecycle = %#v", final)
	}
	if _, err := store.GetProviderCredential(context.Background(), id); !errors.Is(err, storage.ErrCredentialNotFound) {
		t.Fatalf("attempting restart credential = %v", err)
	}
}

func TestCredentialInspectionFailureAfterClaimStaysAttemptingUntilFreshNoProviderCleanup(t *testing.T) {
	base := storagefake.New()
	id := seedActiveAccount(t, base, "82828282828282828282828282828282", "manager-credential-inspection")
	store := &credentialInspectionFailureStore{Handle: base}
	ring := testKeyring(t)
	t.Cleanup(func() { _ = ring.Close() })
	var requests atomic.Int32
	manager := newManager(store, ring, managerDependencies{transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("provider must not be called")
	})})
	result, err := manager.Revoke(context.Background(), id)
	if result != "" || !errors.Is(err, ErrRecoveryRequired) || requests.Load() != 0 {
		t.Fatalf("credential inspection failure = (%q, %v), requests=%d", result, err, requests.Load())
	}
	claimed, _ := base.GetAccountLifecycle(context.Background(), id)
	if claimed.RevocationStatus != storage.RevocationStatusAttempting {
		t.Fatalf("credential inspection failure lifecycle = %#v", claimed)
	}
	if _, err := base.GetProviderCredential(context.Background(), id); err != nil {
		t.Fatalf("credential inspection failure removed ciphertext: %v", err)
	}
	fresh := newManager(base, ring, managerDependencies{transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("provider must not be called")
	})})
	result, err = fresh.Revoke(context.Background(), id)
	if result != RevocationManual || !errors.Is(err, ErrProviderRevocation) || requests.Load() != 0 {
		t.Fatalf("fresh credential cleanup = (%q, %v), requests=%d", result, err, requests.Load())
	}
	final, _ := base.GetAccountLifecycle(context.Background(), id)
	if final.RevocationStatus != storage.RevocationStatusManualActionRequired {
		t.Fatalf("fresh credential cleanup lifecycle = %#v", final)
	}
	if _, err := base.GetProviderCredential(context.Background(), id); !errors.Is(err, storage.ErrCredentialNotFound) {
		t.Fatalf("fresh credential cleanup retained ciphertext: %v", err)
	}
}

type credentialInspectionFailureStore struct {
	storage.Handle
	failed atomic.Bool
}

func (s *credentialInspectionFailureStore) GetProviderCredential(ctx context.Context, accountID storage.AccountID) (storage.ProviderCredential, error) {
	if s.failed.CompareAndSwap(false, true) {
		return storage.ProviderCredential{}, storage.ErrPersistenceInspect
	}
	return s.Handle.GetProviderCredential(ctx, accountID)
}

func TestManagerFinalizedRestartDeletesRemainingCredentialWithoutProvider(t *testing.T) {
	for _, status := range []storage.RevocationStatus{storage.RevocationStatusConfirmed, storage.RevocationStatusManualActionRequired} {
		t.Run(status.String(), func(t *testing.T) {
			store := storagefake.New()
			id := seedActiveAccount(t, store, "87878787878787878787878787878787", "manager-finalized-restart")
			active, _ := store.GetAccountLifecycle(context.Background(), id)
			intent := storage.LifecycleCommit{AccountID: id, ExpectedState: active.State, ExpectedVersion: active.Version, ExpectedRevocationStatus: active.RevocationStatus, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusPending}
			if err := store.CommitAccountLifecycle(context.Background(), intent); err != nil {
				t.Fatal(err)
			}
			pending, _ := store.GetAccountLifecycle(context.Background(), id)
			claim := storage.LifecycleCommit{AccountID: id, ExpectedState: pending.State, ExpectedVersion: pending.Version, ExpectedRevocationStatus: pending.RevocationStatus, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusAttempting}
			if err := store.CommitAccountLifecycle(context.Background(), claim); err != nil {
				t.Fatal(err)
			}
			attempting, _ := store.GetAccountLifecycle(context.Background(), id)
			final := storage.LifecycleCommit{AccountID: id, ExpectedState: attempting.State, ExpectedVersion: attempting.Version, ExpectedRevocationStatus: attempting.RevocationStatus, NextState: storage.AccountStateRevoked, RevocationStatus: status}
			if err := store.CommitAccountLifecycle(context.Background(), final); err != nil {
				t.Fatal(err)
			}
			var requests atomic.Int32
			manager := newManager(store, testKeyring(t), managerDependencies{transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				requests.Add(1)
				return nil, errors.New("provider must not be called")
			})})
			result, err := manager.Revoke(context.Background(), id)
			if status == storage.RevocationStatusConfirmed {
				if result != RevocationConfirmed || err != nil {
					t.Fatalf("confirmed restart = (%q, %v)", result, err)
				}
			} else if result != RevocationManual || !errors.Is(err, ErrProviderRevocation) {
				t.Fatalf("manual restart = (%q, %v)", result, err)
			}
			if requests.Load() != 0 {
				t.Fatalf("finalized restart provider requests = %d", requests.Load())
			}
			if _, err := store.GetProviderCredential(context.Background(), id); !errors.Is(err, storage.ErrCredentialNotFound) {
				t.Fatalf("finalized restart credential = %v", err)
			}
		})
	}
}

func TestReauthorizationIdempotencyRequiresSameReason(t *testing.T) {
	store := storagefake.New()
	id := seedActiveAccount(t, store, "84848484848484848484848484848484", "manager-reason")
	manager := New(store, nil)
	if err := manager.MarkReauthorizationRequired(context.Background(), id, storage.ReauthorizationReasonRefreshInvalidGrant); err != nil {
		t.Fatal(err)
	}
	if err := manager.MarkReauthorizationRequired(context.Background(), id, storage.ReauthorizationReasonRefreshInvalidGrant); err != nil {
		t.Fatalf("same reason idempotency = %v", err)
	}
	if err := manager.MarkReauthorizationRequired(context.Background(), id, storage.ReauthorizationReasonGmailDomainPolicy); !errors.Is(err, ErrTransition) {
		t.Fatalf("different reason idempotency = %v", err)
	}
}

func TestTransitionUnknownOutcomeWithFailedFreshReadRequiresRecovery(t *testing.T) {
	base := storagefake.New()
	id := seedActiveAccount(t, base, "86868686868686868686868686868686", "manager-transition-recovery")
	store := &transitionProofFailureStore{Handle: base}
	manager := New(store, nil)
	if err := manager.Pause(context.Background(), id); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("Pause() error = %v, want recovery required", err)
	}
	if store.commits.Load() != 1 || store.reads.Load() != 2 {
		t.Fatalf("transition calls = %d commits and %d reads, want one commit and one fresh proof read", store.commits.Load(), store.reads.Load())
	}
}

type transitionProofFailureStore struct {
	storage.Handle
	reads   atomic.Int32
	commits atomic.Int32
}

func (s *transitionProofFailureStore) GetAccountLifecycle(ctx context.Context, accountID storage.AccountID) (storage.AccountLifecycle, error) {
	if s.reads.Add(1) == 2 {
		return storage.AccountLifecycle{}, storage.ErrPersistenceInspect
	}
	return s.Handle.GetAccountLifecycle(ctx, accountID)
}

func (s *transitionProofFailureStore) CommitAccountLifecycle(context.Context, storage.LifecycleCommit) error {
	s.commits.Add(1)
	return storage.ErrPersistenceUnknown
}

func TestRevokeReservesCompleteVersionBudgetBeforeMutationCredentialOrProvider(t *testing.T) {
	maximum := int64(^uint64(0) >> 1)
	for _, tt := range []struct {
		name    string
		rawID   string
		state   storage.AccountState
		status  storage.RevocationStatus
		version int64
	}{
		{name: "revoked pending needs claim and finalization", rawID: "85858585858585858585858585858585", state: storage.AccountStateRevoked, status: storage.RevocationStatusPending, version: maximum - 1},
		{name: "active needs intent claim and finalization", rawID: "85858585858585858585858585858586", state: storage.AccountStateActive, status: storage.RevocationStatusNone, version: maximum - 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			accountID, _ := storage.ParseAccountID(tt.rawID)
			version, _ := storage.ParseLifecycleVersion(tt.version)
			store := &overflowObservedStore{lifecycle: storage.AccountLifecycle{AccountID: accountID, State: tt.state, Version: version, RevocationStatus: tt.status}}
			var providerCalls atomic.Int32
			manager := newManager(store, nil, managerDependencies{transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				providerCalls.Add(1)
				return nil, errors.New("provider must not be called")
			})})
			result, err := manager.Revoke(context.Background(), accountID)
			if result != "" || !errors.Is(err, ErrRecoveryRequired) || store.otherCalls.Load() != 0 || providerCalls.Load() != 0 {
				t.Fatalf("overflow Revoke() = (%q, %v), later calls=%d, provider calls=%d", result, err, store.otherCalls.Load(), providerCalls.Load())
			}
		})
	}
}

func TestRevokeFinalizedMaximumVersionStillDeletesResidualCredentialWithoutProvider(t *testing.T) {
	for _, status := range []storage.RevocationStatus{storage.RevocationStatusConfirmed, storage.RevocationStatusManualActionRequired} {
		t.Run(status.String(), func(t *testing.T) {
			accountID, _ := storage.ParseAccountID("89898989898989898989898989898989")
			version, _ := storage.ParseLifecycleVersion(int64(^uint64(0) >> 1))
			ring := testKeyring(t)
			t.Cleanup(func() { _ = ring.Close() })
			envelopeText, err := ring.EncryptRefreshToken(accountID.String(), []byte("synthetic-finalized-overflow-token"))
			if err != nil {
				t.Fatal(err)
			}
			envelope, _ := storage.ParseCredentialEnvelope(envelopeText)
			store := &finalizedMaximumStore{lifecycle: storage.AccountLifecycle{AccountID: accountID, State: storage.AccountStateRevoked, Version: version, RevocationStatus: status}, credential: storage.ProviderCredential{AccountID: accountID, KeyID: envelope.KeyID(), Envelope: envelope}}
			var providerCalls atomic.Int32
			manager := newManager(store, nil, managerDependencies{transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				providerCalls.Add(1)
				return nil, errors.New("provider must not be called")
			})})
			result, revokeErr := manager.Revoke(context.Background(), accountID)
			if status == storage.RevocationStatusConfirmed {
				if result != RevocationConfirmed || revokeErr != nil {
					t.Fatalf("confirmed maximum restart = (%q, %v)", result, revokeErr)
				}
			} else if result != RevocationManual || !errors.Is(revokeErr, ErrProviderRevocation) {
				t.Fatalf("manual maximum restart = (%q, %v)", result, revokeErr)
			}
			if providerCalls.Load() != 0 || store.deleteCalls.Load() != 1 || !store.deleted.Load() {
				t.Fatalf("maximum restart provider calls=%d delete calls=%d deleted=%v", providerCalls.Load(), store.deleteCalls.Load(), store.deleted.Load())
			}
		})
	}
}

type overflowObservedStore struct {
	storage.Handle
	lifecycle  storage.AccountLifecycle
	otherCalls atomic.Int32
}

func (s *overflowObservedStore) GetAccountLifecycle(context.Context, storage.AccountID) (storage.AccountLifecycle, error) {
	return s.lifecycle, nil
}

func (s *overflowObservedStore) GetProviderCredential(context.Context, storage.AccountID) (storage.ProviderCredential, error) {
	s.otherCalls.Add(1)
	return storage.ProviderCredential{}, storage.ErrCredentialNotFound
}

func (s *overflowObservedStore) CommitAccountLifecycle(context.Context, storage.LifecycleCommit) error {
	s.otherCalls.Add(1)
	return nil
}

type finalizedMaximumStore struct {
	storage.Handle
	lifecycle   storage.AccountLifecycle
	credential  storage.ProviderCredential
	deleted     atomic.Bool
	deleteCalls atomic.Int32
}

func (s *finalizedMaximumStore) GetAccountLifecycle(context.Context, storage.AccountID) (storage.AccountLifecycle, error) {
	return s.lifecycle, nil
}

func (s *finalizedMaximumStore) GetProviderCredential(context.Context, storage.AccountID) (storage.ProviderCredential, error) {
	if s.deleted.Load() {
		return storage.ProviderCredential{}, storage.ErrCredentialNotFound
	}
	return s.credential, nil
}

func (s *finalizedMaximumStore) DeleteRevokedProviderCredential(_ context.Context, operation storage.RevokedCredentialDelete) error {
	s.deleteCalls.Add(1)
	if operation.AccountID != s.credential.AccountID || operation.Expected != s.credential.Envelope {
		return storage.ErrCredentialConflict
	}
	s.deleted.Store(true)
	return nil
}

func TestManagerConcurrentRevocationMakesOneProviderRequest(t *testing.T) {
	store := storagefake.New()
	id := seedActiveAccount(t, store, "91919191919191919191919191919191", "manager-concurrent")
	ring := testKeyring(t)
	t.Cleanup(func() { _ = ring.Close() })
	envelopeText, err := ring.EncryptRefreshToken(id.String(), []byte("synthetic-concurrent-revocation-token"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := storage.ParseCredentialEnvelope(envelopeText)
	current, _ := store.GetProviderCredential(context.Background(), id)
	if err := store.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: id, Expected: &current.Envelope, Next: envelope}); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			close(started)
		}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	manager := newManager(store, ring, managerDependencies{revocationEndpoint: server.URL, transport: server.Client().Transport})
	results := make(chan RevocationResult, 2)
	errorsFound := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			ready.Done()
			<-start
			result, revokeErr := manager.Revoke(context.Background(), id)
			results <- result
			errorsFound <- revokeErr
		}()
	}
	ready.Wait()
	close(start)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("provider request did not start")
	}
	if requests.Load() != 1 {
		t.Fatalf("concurrent provider requests before release = %d, want 1", requests.Load())
	}
	close(release)
	for range 2 {
		if result, revokeErr := <-results, <-errorsFound; result != RevocationConfirmed || revokeErr != nil {
			t.Fatalf("concurrent Revoke() = (%q, %v)", result, revokeErr)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("concurrent provider requests = %d, want 1", requests.Load())
	}
}

func TestIndependentManagersUseOneDurableProviderClaim(t *testing.T) {
	base := storagefake.New()
	id := seedActiveAccount(t, base, "93939393939393939393939393939393", "manager-cross-process")
	ring := testKeyring(t)
	t.Cleanup(func() { _ = ring.Close() })
	active, _ := base.GetAccountLifecycle(context.Background(), id)
	intent := storage.LifecycleCommit{AccountID: id, ExpectedState: active.State, ExpectedVersion: active.Version, ExpectedRevocationStatus: active.RevocationStatus, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusPending}
	if err := base.CommitAccountLifecycle(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	store := &pendingLifecycleReadBarrier{Handle: base, AccountID: id, Ready: ready, Release: release}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	managers := []*Manager{
		newManager(store, ring, managerDependencies{revocationEndpoint: server.URL, transport: server.Client().Transport}),
		newManager(store, ring, managerDependencies{revocationEndpoint: server.URL, transport: server.Client().Transport}),
	}
	type outcome struct {
		result RevocationResult
		err    error
	}
	outcomes := make(chan outcome, 2)
	for _, manager := range managers {
		go func(manager *Manager) {
			result, revokeErr := manager.Revoke(context.Background(), id)
			outcomes <- outcome{result: result, err: revokeErr}
		}(manager)
	}
	for range 2 {
		select {
		case <-ready:
		case <-time.After(time.Second):
			t.Fatal("independent managers did not read the same pending version")
		}
	}
	close(release)
	confirmed := 0
	recovery := 0
	for range 2 {
		outcome := <-outcomes
		if outcome.result == RevocationConfirmed && outcome.err == nil {
			confirmed++
		} else if outcome.result == "" && errors.Is(outcome.err, ErrRecoveryRequired) {
			recovery++
		} else {
			t.Fatalf("independent Revoke() = (%q, %v)", outcome.result, outcome.err)
		}
	}
	if confirmed != 1 || recovery != 1 || requests.Load() != 1 {
		t.Fatalf("confirmed=%d recovery=%d provider requests=%d", confirmed, recovery, requests.Load())
	}
	final, _ := base.GetAccountLifecycle(context.Background(), id)
	if final.RevocationStatus != storage.RevocationStatusConfirmed {
		t.Fatalf("final lifecycle = %#v", final)
	}
	if _, err := base.GetProviderCredential(context.Background(), id); !errors.Is(err, storage.ErrCredentialNotFound) {
		t.Fatalf("credential after concurrent revocation = %v", err)
	}
}

func TestConcurrentResumeVersusReauthorizationUsesObservedPausedState(t *testing.T) {
	base := storagefake.New()
	id := seedActiveAccount(t, base, "97979797979797979797979797979797", "manager-resume-reauth")
	if err := New(base, nil).Pause(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	store := &lifecycleReadBarrier{Handle: base, AccountID: id, State: storage.AccountStatePaused, Ready: ready, Release: release}
	managerA := New(store, nil)
	managerB := New(store, nil)
	results := make(chan error, 2)
	go func() { results <- managerA.Resume(context.Background(), id) }()
	go func() {
		results <- managerB.MarkReauthorizationRequired(context.Background(), id, storage.ReauthorizationReasonRefreshInvalidGrant)
	}()
	for range 2 {
		select {
		case <-ready:
		case <-time.After(time.Second):
			t.Fatal("resume and reauthorization did not observe the same paused state")
		}
	}
	close(release)
	successes, transitions := 0, 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		} else if errors.Is(err, ErrTransition) {
			transitions++
		} else {
			t.Fatalf("resume versus reauthorization error = %v", err)
		}
	}
	current, _ := base.GetAccountLifecycle(context.Background(), id)
	if successes != 1 || transitions != 1 || current.State != storage.AccountStateActive || current.Version.Int64() != 4 {
		t.Fatalf("resume versus reauthorization = %#v, successes=%d transitions=%d", current, successes, transitions)
	}
}

type lifecycleReadBarrier struct {
	storage.Handle
	AccountID storage.AccountID
	State     storage.AccountState
	Ready     chan<- struct{}
	Release   <-chan struct{}
	reads     atomic.Int32
}

func (s *lifecycleReadBarrier) GetAccountLifecycle(ctx context.Context, accountID storage.AccountID) (storage.AccountLifecycle, error) {
	lifecycle, err := s.Handle.GetAccountLifecycle(ctx, accountID)
	if err == nil && accountID == s.AccountID && lifecycle.State == s.State && s.reads.Add(1) <= 2 {
		s.Ready <- struct{}{}
		select {
		case <-s.Release:
		case <-ctx.Done():
			return storage.AccountLifecycle{}, ctx.Err()
		}
	}
	return lifecycle, err
}

type pendingLifecycleReadBarrier struct {
	storage.Handle
	AccountID storage.AccountID
	Ready     chan<- struct{}
	Release   <-chan struct{}
	reads     atomic.Int32
}

func (s *pendingLifecycleReadBarrier) GetAccountLifecycle(ctx context.Context, accountID storage.AccountID) (storage.AccountLifecycle, error) {
	lifecycle, err := s.Handle.GetAccountLifecycle(ctx, accountID)
	if err == nil && accountID == s.AccountID && lifecycle.State == storage.AccountStateRevoked && lifecycle.RevocationStatus == storage.RevocationStatusPending && s.reads.Add(1) <= 2 {
		s.Ready <- struct{}{}
		select {
		case <-s.Release:
		case <-ctx.Done():
			return storage.AccountLifecycle{}, ctx.Err()
		}
	}
	return lifecycle, err
}

func TestManagerProviderTransportBoundsRedirectAndCancellation(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		bodyBytes  int
		redirect   bool
		cancel     bool
		wantResult RevocationResult
		wantError  error
	}{
		{name: "exact maximum response", status: http.StatusOK, bodyBytes: maximumRevocationBodyBytes, wantResult: RevocationConfirmed},
		{name: "one byte oversized response", status: http.StatusOK, bodyBytes: maximumRevocationBodyBytes + 1, wantResult: RevocationManual, wantError: ErrProviderRevocation},
		{name: "redirect rejected", redirect: true, wantResult: RevocationManual, wantError: ErrProviderRevocation},
		{name: "caller cancellation finalizes manual", cancel: true, wantResult: RevocationManual, wantError: ErrProviderRevocation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := storagefake.New()
			id := seedActiveAccount(t, store, "92929292929292929292929292929292", "manager-transport")
			ring := testKeyring(t)
			t.Cleanup(func() { _ = ring.Close() })
			envelopeText, _ := ring.EncryptRefreshToken(id.String(), []byte("synthetic-transport-revocation-token"))
			envelope, _ := storage.ParseCredentialEnvelope(envelopeText)
			current, _ := store.GetProviderCredential(context.Background(), id)
			if err := store.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: id, Expected: &current.Envelope, Next: envelope}); err != nil {
				t.Fatal(err)
			}
			var requests atomic.Int32
			var redirected atomic.Int32
			started := make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				requests.Add(1)
				if request.URL.Path == "/sink" {
					redirected.Add(1)
					w.WriteHeader(http.StatusOK)
					return
				}
				if tt.redirect {
					http.Redirect(w, request, "/sink", http.StatusFound)
					return
				}
				if tt.cancel {
					close(started)
					<-release
					return
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write(bytes.Repeat([]byte{'x'}, tt.bodyBytes))
			}))
			t.Cleanup(server.Close)
			manager := newManager(store, ring, managerDependencies{revocationEndpoint: server.URL, transport: server.Client().Transport})
			ctx := context.Background()
			if tt.cancel {
				cancelCtx, cancel := context.WithCancel(context.Background())
				ctx = cancelCtx
				go func() {
					<-started
					cancel()
				}()
			}
			result, revokeErr := manager.Revoke(ctx, id)
			if tt.cancel {
				releaseOnce.Do(func() { close(release) })
			}
			if result != tt.wantResult || !errors.Is(revokeErr, tt.wantError) {
				t.Fatalf("Revoke() = (%q, %v), want (%q, %v)", result, revokeErr, tt.wantResult, tt.wantError)
			}
			if requests.Load() != 1 || redirected.Load() != 0 {
				t.Fatalf("provider requests = %d, redirected requests = %d", requests.Load(), redirected.Load())
			}
			lifecycle, _ := store.GetAccountLifecycle(context.Background(), id)
			if tt.cancel {
				if lifecycle.RevocationStatus != storage.RevocationStatusManualActionRequired {
					t.Fatalf("canceled lifecycle = %#v", lifecycle)
				}
			} else if lifecycle.RevocationStatus == storage.RevocationStatusPending {
				t.Fatalf("provider outcome was not finalized: %#v", lifecycle)
			}
			if _, err := store.GetProviderCredential(context.Background(), id); !errors.Is(err, storage.ErrCredentialNotFound) {
				t.Fatalf("provider outcome retained credential: %v", err)
			}
		})
	}
}

func TestProductionRevocationTransportIsFreshProxyDisabledVerifiedTLSWithExactDeadline(t *testing.T) {
	first := revocationTransport()
	second := revocationTransport()
	t.Cleanup(first.CloseIdleConnections)
	t.Cleanup(second.CloseIdleConnections)
	if first == second || first.Proxy != nil || second.Proxy != nil || first.DialContext == nil || second.DialContext == nil {
		t.Fatal("production revocation transports were shared, proxy-enabled, or lacked owned dialing")
	}
	if first.TLSClientConfig == nil || second.TLSClientConfig == nil || first.TLSClientConfig.InsecureSkipVerify || second.TLSClientConfig.InsecureSkipVerify || first.TLSClientConfig.MinVersion != tls.VersionTLS12 || second.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("production revocation transport did not require verified TLS 1.2 or newer")
	}
	if first.ResponseHeaderTimeout != 5*time.Second || first.TLSHandshakeTimeout != 5*time.Second || revocationDeadline != 15*time.Second {
		t.Fatal("production revocation transport or operation deadline changed")
	}
	var remaining time.Duration
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		deadline, ok := request.Context().Deadline()
		if !ok {
			return nil, errors.New("missing request deadline")
		}
		remaining = time.Until(deadline)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header), Request: request}, nil
	})
	manager := &Manager{revocationEndpoint: productionRevocationEndpoint, transport: transport}
	confirmed, err := manager.revokeProvider(context.Background(), []byte("synthetic-deadline-token"))
	if err != nil || !confirmed || remaining <= 14*time.Second || remaining > 15*time.Second {
		t.Fatalf("production revocation deadline = %v, confirmed=%v, error=%v", remaining, confirmed, err)
	}
}

func TestManagerBodyStallAndTransportFailureFinalizeWithIndependentCleanup(t *testing.T) {
	for _, tt := range []struct {
		name      string
		transport http.RoundTripper
		server    string
	}{
		{name: "header stall", server: "header"},
		{name: "body stall", server: "body"},
		{name: "transport failure", transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("raw transport marker") })},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := storagefake.New()
			id := seedActiveAccount(t, store, "94949494949494949494949494949494", "manager-cleanup")
			ring := testKeyring(t)
			t.Cleanup(func() { _ = ring.Close() })
			transport := tt.transport
			endpoint := "https://oauth2.googleapis.com/revoke"
			release := make(chan struct{})
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			if tt.server != "" {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					if tt.server == "header" {
						<-release
						return
					}
					w.WriteHeader(http.StatusOK)
					if flusher, ok := w.(http.Flusher); ok {
						flusher.Flush()
					}
					<-release
				}))
				t.Cleanup(server.Close)
				endpoint = server.URL
				transport = server.Client().Transport
			}
			manager := newManager(store, ring, managerDependencies{revocationEndpoint: endpoint, transport: transport, cleanupTimeout: time.Second})
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			started := time.Now()
			result, err := manager.Revoke(ctx, id)
			cancel()
			releaseOnce.Do(func() { close(release) })
			if result != RevocationManual || !errors.Is(err, ErrProviderRevocation) || time.Since(started) >= 500*time.Millisecond {
				t.Fatalf("Revoke() = (%q, %v) after %v", result, err, time.Since(started))
			}
			lifecycle, _ := store.GetAccountLifecycle(context.Background(), id)
			if lifecycle.RevocationStatus != storage.RevocationStatusManualActionRequired {
				t.Fatalf("cleanup lifecycle = %#v", lifecycle)
			}
			if _, err := store.GetProviderCredential(context.Background(), id); !errors.Is(err, storage.ErrCredentialNotFound) {
				t.Fatalf("cleanup credential = %v", err)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestManagerRevocationStorageUncertaintyMatrix(t *testing.T) {
	for _, tt := range []struct {
		name           string
		mode           string
		wantResult     RevocationResult
		wantRecovery   bool
		wantRequests   int32
		wantStatus     storage.RevocationStatus
		wantCredential bool
		freshCleanup   bool
	}{
		{name: "intent before durability", mode: "intent-before", wantRecovery: true, wantStatus: storage.RevocationStatusNone, wantCredential: true},
		{name: "intent after durability", mode: "intent-after", wantResult: RevocationConfirmed, wantRequests: 1, wantStatus: storage.RevocationStatusConfirmed},
		{name: "intent proof failure", mode: "intent-proof-failure", wantRecovery: true, wantStatus: storage.RevocationStatusPending, wantCredential: true},
		{name: "claim after durability", mode: "claim-after", wantRecovery: true, wantStatus: storage.RevocationStatusAttempting, wantCredential: true, freshCleanup: true},
		{name: "finalization after durability", mode: "final-after", wantResult: RevocationConfirmed, wantRequests: 1, wantStatus: storage.RevocationStatusConfirmed},
		{name: "deletion after durability", mode: "delete-after", wantResult: RevocationConfirmed, wantRequests: 1, wantStatus: storage.RevocationStatusConfirmed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			base := storagefake.New()
			id := seedActiveAccount(t, base, "95959595959595959595959595959595", "manager-uncertainty")
			store := &revocationFaultStore{Handle: base, mode: tt.mode}
			ring := testKeyring(t)
			t.Cleanup(func() { _ = ring.Close() })
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(server.Close)
			manager := newManager(store, ring, managerDependencies{revocationEndpoint: server.URL, transport: server.Client().Transport})
			result, err := manager.Revoke(context.Background(), id)
			if tt.wantRecovery {
				if result != "" || !errors.Is(err, ErrRecoveryRequired) {
					t.Fatalf("Revoke() = (%q, %v), want recovery", result, err)
				}
			} else if result != tt.wantResult || err != nil {
				t.Fatalf("Revoke() = (%q, %v), want %q", result, err, tt.wantResult)
			}
			if requests.Load() != tt.wantRequests {
				t.Fatalf("provider requests = %d, want %d", requests.Load(), tt.wantRequests)
			}
			lifecycle, _ := base.GetAccountLifecycle(context.Background(), id)
			if lifecycle.RevocationStatus != tt.wantStatus {
				t.Fatalf("lifecycle = %#v, want status %s", lifecycle, tt.wantStatus.String())
			}
			_, credentialErr := base.GetProviderCredential(context.Background(), id)
			if tt.wantCredential != (credentialErr == nil) {
				t.Fatalf("credential error = %v, want present %v", credentialErr, tt.wantCredential)
			}
			if tt.freshCleanup {
				fresh := newManager(base, ring, managerDependencies{revocationEndpoint: server.URL, transport: server.Client().Transport})
				result, err := fresh.Revoke(context.Background(), id)
				if result != RevocationManual || !errors.Is(err, ErrProviderRevocation) || requests.Load() != 0 {
					t.Fatalf("fresh cleanup = (%q, %v), requests=%d", result, err, requests.Load())
				}
				if _, err := base.GetProviderCredential(context.Background(), id); !errors.Is(err, storage.ErrCredentialNotFound) {
					t.Fatalf("fresh cleanup credential = %v", err)
				}
			}
		})
	}
}

func TestManagerRevocationRecoveryFaultsRequireFreshExplicitReconciliationWithoutReplay(t *testing.T) {
	for _, tt := range []struct {
		name                 string
		mode                 string
		statusAfterFirst     storage.RevocationStatus
		credentialAfterFirst bool
		providerAfterFirst   int32
		firstRestartRecovery bool
		finalResult          RevocationResult
		finalError           error
		finalProvider        int32
	}{
		{name: "claim before durability", mode: "claim-before", statusAfterFirst: storage.RevocationStatusPending, credentialAfterFirst: true, finalResult: RevocationConfirmed, finalProvider: 1},
		{name: "claim proof failure", mode: "claim-proof-failure", statusAfterFirst: storage.RevocationStatusAttempting, credentialAfterFirst: true, firstRestartRecovery: true, finalResult: RevocationManual, finalError: ErrProviderRevocation},
		{name: "finalization before durability", mode: "final-before", statusAfterFirst: storage.RevocationStatusAttempting, credentialAfterFirst: true, providerAfterFirst: 1, finalResult: RevocationManual, finalError: ErrProviderRevocation, finalProvider: 1},
		{name: "finalization proof failure", mode: "final-proof-failure", statusAfterFirst: storage.RevocationStatusConfirmed, credentialAfterFirst: true, providerAfterFirst: 1, finalResult: RevocationConfirmed, finalProvider: 1},
		{name: "deletion before durability", mode: "delete-before", statusAfterFirst: storage.RevocationStatusConfirmed, credentialAfterFirst: true, providerAfterFirst: 1, finalResult: RevocationConfirmed, finalProvider: 1},
		{name: "deletion proof failure", mode: "delete-proof-failure", statusAfterFirst: storage.RevocationStatusConfirmed, providerAfterFirst: 1, finalResult: RevocationConfirmed, finalProvider: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			base := storagefake.New()
			id := seedActiveAccount(t, base, "96969696969696969696969696969696", "manager-recovery-fault")
			store := &revocationRecoveryFaultStore{Handle: base, mode: tt.mode}
			ring := testKeyring(t)
			t.Cleanup(func() { _ = ring.Close() })
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(server.Close)
			manager := newManager(store, ring, managerDependencies{revocationEndpoint: server.URL, transport: server.Client().Transport})
			if result, err := manager.Revoke(context.Background(), id); result != "" || !errors.Is(err, ErrRecoveryRequired) {
				t.Fatalf("first Revoke() = (%q, %v), want recovery", result, err)
			}
			lifecycle, _ := base.GetAccountLifecycle(context.Background(), id)
			if lifecycle.RevocationStatus != tt.statusAfterFirst || requests.Load() != tt.providerAfterFirst {
				t.Fatalf("first durable status=%s provider=%d", lifecycle.RevocationStatus.String(), requests.Load())
			}
			_, credentialErr := base.GetProviderCredential(context.Background(), id)
			if tt.credentialAfterFirst != (credentialErr == nil) {
				t.Fatalf("first credential error=%v, want present=%v", credentialErr, tt.credentialAfterFirst)
			}
			if store.claimCalls.Load() > 1 || store.finalCalls.Load() > 1 || store.deleteCalls.Load() > 1 {
				t.Fatalf("same invocation replayed claim=%d final=%d delete=%d", store.claimCalls.Load(), store.finalCalls.Load(), store.deleteCalls.Load())
			}
			fresh := newManager(store, ring, managerDependencies{revocationEndpoint: server.URL, transport: server.Client().Transport})
			if tt.firstRestartRecovery {
				if result, err := fresh.Revoke(context.Background(), id); result != "" || !errors.Is(err, ErrRecoveryRequired) {
					t.Fatalf("first restart = (%q, %v), want recovery", result, err)
				}
				fresh = newManager(base, ring, managerDependencies{revocationEndpoint: server.URL, transport: server.Client().Transport})
			}
			result, err := fresh.Revoke(context.Background(), id)
			if result != tt.finalResult || !errors.Is(err, tt.finalError) || requests.Load() != tt.finalProvider {
				t.Fatalf("fresh reconciliation = (%q, %v), provider=%d", result, err, requests.Load())
			}
			if _, err := base.GetProviderCredential(context.Background(), id); !errors.Is(err, storage.ErrCredentialNotFound) {
				t.Fatalf("fresh reconciliation credential = %v", err)
			}
		})
	}
}

type revocationRecoveryFaultStore struct {
	storage.Handle
	mode                string
	claimCalls          atomic.Int32
	finalCalls          atomic.Int32
	deleteCalls         atomic.Int32
	claimFaulted        atomic.Bool
	finalFaulted        atomic.Bool
	deleteFaulted       atomic.Bool
	failLifecycleReads  atomic.Int32
	failCredentialReads atomic.Int32
}

func (s *revocationRecoveryFaultStore) GetAccountLifecycle(ctx context.Context, accountID storage.AccountID) (storage.AccountLifecycle, error) {
	if s.failLifecycleReads.Load() > 0 && s.failLifecycleReads.Add(-1) >= 0 {
		return storage.AccountLifecycle{}, storage.ErrPersistenceInspect
	}
	return s.Handle.GetAccountLifecycle(ctx, accountID)
}

func (s *revocationRecoveryFaultStore) GetProviderCredential(ctx context.Context, accountID storage.AccountID) (storage.ProviderCredential, error) {
	if s.failCredentialReads.Load() > 0 && s.failCredentialReads.Add(-1) >= 0 {
		return storage.ProviderCredential{}, storage.ErrPersistenceInspect
	}
	return s.Handle.GetProviderCredential(ctx, accountID)
}

func (s *revocationRecoveryFaultStore) CommitAccountLifecycle(ctx context.Context, commit storage.LifecycleCommit) error {
	if commit.RevocationStatus == storage.RevocationStatusAttempting {
		s.claimCalls.Add(1)
		fault := s.claimFaulted.CompareAndSwap(false, true)
		if fault && s.mode == "claim-before" {
			return storage.ErrPersistenceUnknown
		}
		err := s.Handle.CommitAccountLifecycle(ctx, commit)
		if err == nil && fault && s.mode == "claim-proof-failure" {
			s.failLifecycleReads.Store(1)
			return storage.ErrPersistenceUnknown
		}
		return err
	}
	if commit.RevocationStatus == storage.RevocationStatusConfirmed || commit.RevocationStatus == storage.RevocationStatusManualActionRequired {
		s.finalCalls.Add(1)
		fault := s.finalFaulted.CompareAndSwap(false, true)
		if fault && s.mode == "final-before" {
			return storage.ErrPersistenceUnknown
		}
		err := s.Handle.CommitAccountLifecycle(ctx, commit)
		if err == nil && fault && s.mode == "final-proof-failure" {
			s.failLifecycleReads.Store(1)
			return storage.ErrPersistenceUnknown
		}
		return err
	}
	return s.Handle.CommitAccountLifecycle(ctx, commit)
}

func (s *revocationRecoveryFaultStore) DeleteRevokedProviderCredential(ctx context.Context, operation storage.RevokedCredentialDelete) error {
	s.deleteCalls.Add(1)
	fault := s.deleteFaulted.CompareAndSwap(false, true)
	if fault && s.mode == "delete-before" {
		return storage.ErrPersistenceUnknown
	}
	err := s.Handle.DeleteRevokedProviderCredential(ctx, operation)
	if err == nil && fault && s.mode == "delete-proof-failure" {
		s.failCredentialReads.Store(1)
		return storage.ErrPersistenceUnknown
	}
	return err
}

type revocationFaultStore struct {
	storage.Handle
	mode         string
	mu           sync.Mutex
	failNextRead bool
	triggered    bool
}

func (s *revocationFaultStore) GetAccountLifecycle(ctx context.Context, accountID storage.AccountID) (storage.AccountLifecycle, error) {
	s.mu.Lock()
	if s.failNextRead {
		s.failNextRead = false
		s.mu.Unlock()
		return storage.AccountLifecycle{}, storage.ErrPersistenceInspect
	}
	s.mu.Unlock()
	return s.Handle.GetAccountLifecycle(ctx, accountID)
}

func (s *revocationFaultStore) CommitAccountLifecycle(ctx context.Context, commit storage.LifecycleCommit) error {
	isIntent := commit.NextState == storage.AccountStateRevoked && commit.RevocationStatus == storage.RevocationStatusPending
	isClaim := commit.RevocationStatus == storage.RevocationStatusAttempting
	isFinal := commit.RevocationStatus == storage.RevocationStatusConfirmed || commit.RevocationStatus == storage.RevocationStatusManualActionRequired
	s.mu.Lock()
	mode := s.mode
	trigger := !s.triggered && (isIntent && strings.HasPrefix(mode, "intent-") || isClaim && mode == "claim-after" || isFinal && mode == "final-after")
	if trigger {
		s.triggered = true
	}
	s.mu.Unlock()
	if trigger && mode == "intent-before" {
		return storage.ErrPersistenceUnknown
	}
	err := s.Handle.CommitAccountLifecycle(ctx, commit)
	if err != nil {
		return err
	}
	if trigger && mode == "intent-after" {
		return storage.ErrPersistenceUnknown
	}
	if trigger && mode == "intent-proof-failure" {
		s.mu.Lock()
		s.failNextRead = true
		s.mu.Unlock()
		return storage.ErrPersistenceUnknown
	}
	if trigger && mode == "claim-after" {
		return storage.ErrPersistenceUnknown
	}
	if trigger && mode == "final-after" {
		return storage.ErrPersistenceUnknown
	}
	return nil
}

func (s *revocationFaultStore) DeleteRevokedProviderCredential(ctx context.Context, operation storage.RevokedCredentialDelete) error {
	err := s.Handle.DeleteRevokedProviderCredential(ctx, operation)
	if err == nil && s.mode == "delete-after" {
		return storage.ErrPersistenceUnknown
	}
	return err
}

func seedActiveAccount(t *testing.T, store *storagefake.Store, rawID, subject string) storage.AccountID {
	t.Helper()
	id, _ := storage.ParseAccountID(rawID)
	providerSubject, _ := storage.ParseProviderSubject(subject)
	if _, err := store.EnsureAccount(context.Background(), storage.AccountSeed{ID: id, ProviderSubject: providerSubject}); err != nil {
		t.Fatal(err)
	}
	history, _ := storage.ParseHistoryID("1")
	if err := store.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: id, Next: history}); err != nil {
		t.Fatal(err)
	}
	ring := testKeyring(t)
	t.Cleanup(func() { _ = ring.Close() })
	envelopeText, _ := ring.EncryptRefreshToken(id.String(), []byte("synthetic-seed-token"))
	envelope, _ := storage.ParseCredentialEnvelope(envelopeText)
	if err := store.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: id, Next: envelope}); err != nil {
		t.Fatal(err)
	}
	pending, _ := store.GetAccountLifecycle(context.Background(), id)
	if err := store.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: id, ExpectedState: pending.State, ExpectedVersion: pending.Version, ExpectedRevocationStatus: pending.RevocationStatus, NextState: storage.AccountStateActive, RevocationStatus: storage.RevocationStatusNone}); err != nil {
		t.Fatal(err)
	}
	return id
}

func testKeyring(t *testing.T) *cryptobox.Keyring {
	t.Helper()
	key := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	ring, err := cryptobox.ParseKeyring([]byte("igk1:active=" + key))
	if err != nil {
		t.Fatal(err)
	}
	return ring
}
