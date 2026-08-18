// Package account implements bounded operator account lifecycle operations.
package account

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mandloideep/inboxgate/internal/cryptobox"
	"github.com/mandloideep/inboxgate/internal/storage"
)

const (
	productionRevocationEndpoint = "https://oauth2.googleapis.com/revoke"
	maximumRevocationBodyBytes   = 16_384
	revocationDeadline           = 15 * time.Second
	revocationCleanupDeadline    = 15 * time.Second
)

var (
	ErrTransition         = errors.New("account lifecycle: transition rejected")
	ErrRecoveryRequired   = errors.New("account lifecycle: recovery required")
	ErrProviderRevocation = errors.New("account lifecycle: provider revocation requires owner action")
)

type RevocationResult string

const (
	RevocationConfirmed RevocationResult = "confirmed"
	RevocationManual    RevocationResult = "manual"
)

type keyringResolver func() (*cryptobox.Keyring, error)

type managerDependencies struct {
	revocationEndpoint string
	transport          http.RoundTripper
	cleanupTimeout     time.Duration
}

type Manager struct {
	revocationMu       sync.Mutex
	store              storage.Handle
	resolveKeyring     keyringResolver
	revocationEndpoint string
	transport          http.RoundTripper
	cleanupTimeout     time.Duration
}

func New(store storage.Handle, ring *cryptobox.Keyring) *Manager {
	return newManagerWithResolver(store, func() (*cryptobox.Keyring, error) {
		if ring == nil {
			return nil, ErrRecoveryRequired
		}
		return ring, nil
	}, managerDependencies{})
}

func NewWithKeyringResolver(store storage.Handle, resolver func() (*cryptobox.Keyring, error)) *Manager {
	return newManagerWithResolver(store, resolver, managerDependencies{})
}

func newManager(store storage.Handle, ring *cryptobox.Keyring, dependencies managerDependencies) *Manager {
	return newManagerWithResolver(store, func() (*cryptobox.Keyring, error) {
		if ring == nil {
			return nil, ErrRecoveryRequired
		}
		return ring, nil
	}, dependencies)
}

func newManagerWithResolver(store storage.Handle, resolver keyringResolver, dependencies managerDependencies) *Manager {
	if dependencies.revocationEndpoint == "" {
		dependencies.revocationEndpoint = productionRevocationEndpoint
	}
	if dependencies.transport == nil {
		dependencies.transport = revocationTransport()
	}
	if dependencies.cleanupTimeout <= 0 {
		dependencies.cleanupTimeout = revocationCleanupDeadline
	}
	return &Manager{store: store, resolveKeyring: resolver, revocationEndpoint: dependencies.revocationEndpoint, transport: dependencies.transport, cleanupTimeout: dependencies.cleanupTimeout}
}

func (m *Manager) List(ctx context.Context) ([]storage.AccountSummary, error) {
	if m == nil || m.store == nil {
		return nil, ErrRecoveryRequired
	}
	return m.store.ListAccounts(ctx)
}

func (m *Manager) Pause(ctx context.Context, accountID storage.AccountID) error {
	return m.transition(ctx, accountID, storage.AccountStateActive, storage.AccountStatePaused, nil, storage.RevocationStatusNone, storage.AccountStatePaused)
}

func (m *Manager) Resume(ctx context.Context, accountID storage.AccountID) error {
	return m.transition(ctx, accountID, storage.AccountStatePaused, storage.AccountStateActive, nil, storage.RevocationStatusNone, storage.AccountStateActive)
}

func (m *Manager) MarkReauthorizationRequired(ctx context.Context, accountID storage.AccountID, reason storage.ReauthorizationReason) error {
	return m.transition(ctx, accountID, storage.AccountStateActive, storage.AccountStateReauthorizationRequired, &reason, storage.RevocationStatusNone, storage.AccountStateReauthorizationRequired)
}

func (m *Manager) transition(ctx context.Context, accountID storage.AccountID, expected, next storage.AccountState, reason *storage.ReauthorizationReason, revocation storage.RevocationStatus, idempotent storage.AccountState) error {
	if m == nil || m.store == nil {
		return ErrRecoveryRequired
	}
	current, err := m.store.GetAccountLifecycle(ctx, accountID)
	if err != nil {
		return fixedStorageError(err)
	}
	if current.State == idempotent {
		if idempotent == storage.AccountStateReauthorizationRequired {
			if current.ReauthorizationReason == nil || reason == nil || *current.ReauthorizationReason != *reason {
				return ErrTransition
			}
		}
		return nil
	}
	if current.State != expected {
		return ErrTransition
	}
	commit := storage.LifecycleCommit{AccountID: accountID, ExpectedState: current.State, ExpectedVersion: current.Version, ExpectedRevocationStatus: current.RevocationStatus, NextState: next, ReauthorizationReason: reason, RevocationStatus: revocation}
	if err := m.store.CommitAccountLifecycle(ctx, commit); err == nil {
		return nil
	}
	verified, verificationErr := m.store.GetAccountLifecycle(ctx, accountID)
	if verificationErr == nil && storage.LifecycleMatchesCommit(verified, commit) {
		return nil
	}
	if verificationErr != nil {
		return ErrRecoveryRequired
	}
	return ErrTransition
}

func (m *Manager) Revoke(ctx context.Context, accountID storage.AccountID) (RevocationResult, error) {
	if m == nil || m.store == nil {
		return "", ErrRecoveryRequired
	}
	m.revocationMu.Lock()
	defer m.revocationMu.Unlock()
	lifecycle, err := m.store.GetAccountLifecycle(ctx, accountID)
	if err != nil {
		return "", fixedStorageError(err)
	}
	if lifecycle.State == storage.AccountStateRevoked && (lifecycle.RevocationStatus == storage.RevocationStatusConfirmed || lifecycle.RevocationStatus == storage.RevocationStatusManualActionRequired) {
		return m.reconcileFinalized(ctx, lifecycle)
	}
	remainingTransitions := int64(3)
	if lifecycle.State == storage.AccountStateRevoked {
		switch lifecycle.RevocationStatus {
		case storage.RevocationStatusPending:
			remainingTransitions = 2
		case storage.RevocationStatusAttempting:
			remainingTransitions = 1
		default:
			return "", ErrRecoveryRequired
		}
	} else if lifecycle.State != storage.AccountStatePending && lifecycle.State != storage.AccountStateActive && lifecycle.State != storage.AccountStatePaused && lifecycle.State != storage.AccountStateReauthorizationRequired {
		return "", ErrTransition
	}
	if lifecycle.Version.Int64() > math.MaxInt64-remainingTransitions {
		return "", ErrRecoveryRequired
	}
	if lifecycle.State != storage.AccountStateRevoked {
		intent := storage.LifecycleCommit{AccountID: accountID, ExpectedState: lifecycle.State, ExpectedVersion: lifecycle.Version, ExpectedRevocationStatus: lifecycle.RevocationStatus, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusPending}
		if err := m.store.CommitAccountLifecycle(ctx, intent); err != nil {
			verified, verificationErr := m.store.GetAccountLifecycle(ctx, accountID)
			if verificationErr != nil || !storage.LifecycleMatchesCommit(verified, intent) {
				return "", ErrRecoveryRequired
			}
		}
		lifecycle, err = m.store.GetAccountLifecycle(ctx, accountID)
		if err != nil || !storage.LifecycleMatchesCommit(lifecycle, intent) {
			return "", ErrRecoveryRequired
		}
	}
	if lifecycle.RevocationStatus == storage.RevocationStatusAttempting {
		return m.finalizeWithoutProvider(lifecycle)
	}
	if lifecycle.RevocationStatus != storage.RevocationStatusPending {
		return "", ErrRecoveryRequired
	}
	claim := storage.LifecycleCommit{AccountID: accountID, ExpectedState: storage.AccountStateRevoked, ExpectedVersion: lifecycle.Version, ExpectedRevocationStatus: storage.RevocationStatusPending, NextState: storage.AccountStateRevoked, RevocationStatus: storage.RevocationStatusAttempting}
	if err := m.store.CommitAccountLifecycle(ctx, claim); err != nil {
		return "", ErrRecoveryRequired
	}
	claimed, err := m.store.GetAccountLifecycle(ctx, accountID)
	if err != nil || !storage.LifecycleMatchesCommit(claimed, claim) || claimed.Version.Int64() != lifecycle.Version.Int64()+1 {
		return "", ErrRecoveryRequired
	}
	credential, credentialErr := m.store.GetProviderCredential(ctx, accountID)
	if credentialErr != nil && !errors.Is(credentialErr, storage.ErrCredentialNotFound) {
		return "", ErrRecoveryRequired
	}
	if errors.Is(credentialErr, storage.ErrCredentialNotFound) {
		return m.finalizeAttempt(claimed, nil, storage.RevocationStatusManualActionRequired, ErrProviderRevocation)
	}
	status := storage.RevocationStatusManualActionRequired
	providerErr := ErrProviderRevocation
	ring, resolveErr := m.resolveKeyring()
	if resolveErr == nil && ring != nil {
		plaintext, decryptErr := ring.DecryptRefreshToken(accountID.String(), credential.Envelope.String())
		if decryptErr == nil {
			confirmed, requestErr := m.revokeProvider(ctx, plaintext)
			clear(plaintext)
			if requestErr == nil && confirmed {
				status = storage.RevocationStatusConfirmed
				providerErr = nil
			}
		}
	}
	return m.finalizeAttempt(claimed, &credential, status, providerErr)
}

func (m *Manager) finalizeWithoutProvider(lifecycle storage.AccountLifecycle) (RevocationResult, error) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), m.cleanupTimeout)
	defer cancel()
	credential, err := m.store.GetProviderCredential(cleanupCtx, lifecycle.AccountID)
	if err != nil && !errors.Is(err, storage.ErrCredentialNotFound) {
		return "", ErrRecoveryRequired
	}
	if errors.Is(err, storage.ErrCredentialNotFound) {
		return m.finalizeAttemptWithContext(cleanupCtx, lifecycle, nil, storage.RevocationStatusManualActionRequired, ErrProviderRevocation)
	}
	return m.finalizeAttemptWithContext(cleanupCtx, lifecycle, &credential, storage.RevocationStatusManualActionRequired, ErrProviderRevocation)
}

func (m *Manager) finalizeAttempt(lifecycle storage.AccountLifecycle, credential *storage.ProviderCredential, status storage.RevocationStatus, providerErr error) (RevocationResult, error) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), m.cleanupTimeout)
	defer cancel()
	return m.finalizeAttemptWithContext(cleanupCtx, lifecycle, credential, status, providerErr)
}

func (m *Manager) finalizeAttemptWithContext(ctx context.Context, lifecycle storage.AccountLifecycle, credential *storage.ProviderCredential, status storage.RevocationStatus, providerErr error) (RevocationResult, error) {
	final := storage.LifecycleCommit{AccountID: lifecycle.AccountID, ExpectedState: storage.AccountStateRevoked, ExpectedVersion: lifecycle.Version, ExpectedRevocationStatus: storage.RevocationStatusAttempting, NextState: storage.AccountStateRevoked, RevocationStatus: status}
	if err := m.store.CommitAccountLifecycle(ctx, final); err != nil {
		verified, verificationErr := m.store.GetAccountLifecycle(ctx, lifecycle.AccountID)
		if verificationErr != nil || !storage.LifecycleMatchesCommit(verified, final) {
			return "", ErrRecoveryRequired
		}
	}
	if credential != nil {
		if err := m.deleteCredential(ctx, lifecycle.AccountID, credential.Envelope); err != nil {
			return "", err
		}
	}
	if status == storage.RevocationStatusConfirmed {
		return RevocationConfirmed, nil
	}
	return RevocationManual, providerErr
}

func (m *Manager) reconcileFinalized(ctx context.Context, lifecycle storage.AccountLifecycle) (RevocationResult, error) {
	credential, err := m.store.GetProviderCredential(ctx, lifecycle.AccountID)
	if err == nil {
		if err := m.deleteCredential(ctx, lifecycle.AccountID, credential.Envelope); err != nil {
			return "", err
		}
	} else if !errors.Is(err, storage.ErrCredentialNotFound) {
		return "", ErrRecoveryRequired
	}
	if lifecycle.RevocationStatus == storage.RevocationStatusConfirmed {
		return RevocationConfirmed, nil
	}
	return RevocationManual, ErrProviderRevocation
}

func (m *Manager) deleteCredential(ctx context.Context, accountID storage.AccountID, envelope storage.CredentialEnvelope) error {
	if err := m.store.DeleteRevokedProviderCredential(ctx, storage.RevokedCredentialDelete{AccountID: accountID, Expected: envelope}); err != nil {
		credential, inspectErr := m.store.GetProviderCredential(ctx, accountID)
		if errors.Is(inspectErr, storage.ErrCredentialNotFound) {
			return nil
		}
		if inspectErr == nil && credential.Envelope != envelope {
			return ErrRecoveryRequired
		}
		return ErrRecoveryRequired
	}
	_, err := m.store.GetProviderCredential(ctx, accountID)
	if !errors.Is(err, storage.ErrCredentialNotFound) {
		return ErrRecoveryRequired
	}
	return nil
}

func (m *Manager) revokeProvider(ctx context.Context, token []byte) (bool, error) {
	requestCtx, cancel := context.WithTimeout(ctx, revocationDeadline)
	defer cancel()
	body := url.Values{"token": []string{string(token)}}.Encode()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, m.revocationEndpoint, strings.NewReader(body))
	body = ""
	if err != nil {
		return false, ErrProviderRevocation
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Transport: m.transport, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrProviderRevocation }}
	response, err := client.Do(request)
	if err != nil {
		return false, fixedProviderError(requestCtx)
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maximumRevocationBodyBytes+1))
	clear(responseBody)
	if readErr != nil || len(responseBody) > maximumRevocationBodyBytes {
		return false, fixedProviderError(requestCtx)
	}
	return response.StatusCode == http.StatusOK, nil
}

func revocationTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       30 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

func fixedProviderError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrProviderRevocation, err)
	}
	return ErrProviderRevocation
}

func fixedStorageError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(ErrRecoveryRequired, err)
	}
	if errors.Is(err, storage.ErrAccountNotFound) {
		return ErrTransition
	}
	return ErrRecoveryRequired
}
