// Package fake provides a credential-free storage replacement for contract tests.
package fake

import (
	"context"
	"sort"
	"sync"

	"github.com/mandloideep/inboxgate/internal/storage"
)

type Store struct {
	mu          sync.Mutex
	accounts    map[storage.AccountID]storage.Account
	bySubject   map[storage.ProviderSubject]storage.AccountID
	cursors     map[storage.AccountID]storage.HistoryID
	credentials map[storage.AccountID]storage.ProviderCredential
	lifecycles  map[storage.AccountID]storage.AccountLifecycle
}

func New() *Store {
	return &Store{
		accounts:    make(map[storage.AccountID]storage.Account),
		bySubject:   make(map[storage.ProviderSubject]storage.AccountID),
		cursors:     make(map[storage.AccountID]storage.HistoryID),
		credentials: make(map[storage.AccountID]storage.ProviderCredential),
		lifecycles:  make(map[storage.AccountID]storage.AccountLifecycle),
	}
}

func (s *Store) Ping(ctx context.Context) error { return ctx.Err() }

func (s *Store) Migrate(ctx context.Context) (storage.MigrationResult, error) {
	if err := ctx.Err(); err != nil {
		return storage.MigrationResult{}, err
	}
	return storage.MigrationResult{Current: 4}, nil
}

func (s *Store) EnsureAccount(ctx context.Context, seed storage.AccountSeed) (storage.Account, error) {
	if err := ctx.Err(); err != nil {
		return storage.Account{}, err
	}
	if err := storage.ValidateAccountSeed(seed); err != nil {
		return storage.Account{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if canonicalID, ok := s.bySubject[seed.ProviderSubject]; ok {
		if existing, occupied := s.accounts[seed.ID]; occupied && existing.ProviderSubject != seed.ProviderSubject {
			return storage.Account{}, storage.ErrAccountConflict
		}
		return s.accounts[canonicalID], nil
	}
	if _, occupied := s.accounts[seed.ID]; occupied {
		return storage.Account{}, storage.ErrAccountConflict
	}
	account := storage.Account{ID: seed.ID, ProviderSubject: seed.ProviderSubject}
	s.accounts[seed.ID] = account
	s.bySubject[seed.ProviderSubject] = seed.ID
	version, _ := storage.ParseLifecycleVersion(1)
	s.lifecycles[seed.ID] = storage.AccountLifecycle{AccountID: seed.ID, State: storage.AccountStatePending, Version: version, RevocationStatus: storage.RevocationStatusNone}
	return account, nil
}

func (s *Store) GetSynchronizationCursor(ctx context.Context, accountID storage.AccountID) (storage.SynchronizationCursor, error) {
	if err := ctx.Err(); err != nil {
		return storage.SynchronizationCursor{}, err
	}
	if parsed, err := storage.ParseAccountID(accountID.String()); err != nil || parsed != accountID {
		return storage.SynchronizationCursor{}, storage.ErrInvalidValue
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts[accountID]; !ok {
		return storage.SynchronizationCursor{}, storage.ErrAccountNotFound
	}
	historyID, ok := s.cursors[accountID]
	if !ok {
		return storage.SynchronizationCursor{}, storage.ErrCursorNotFound
	}
	return storage.SynchronizationCursor{AccountID: accountID, HistoryID: historyID}, nil
}

func (s *Store) CommitSynchronization(ctx context.Context, commit storage.SynchronizationCommit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := storage.ValidateSynchronizationCommit(commit); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts[commit.AccountID]; !ok {
		return storage.ErrAccountNotFound
	}
	current, exists := s.cursors[commit.AccountID]
	if exists && current == commit.Next {
		return nil
	}
	if exists && commit.Next.Compare(current) < 0 {
		return storage.ErrCursorRegression
	}
	if !exists {
		if commit.Expected != nil {
			return storage.ErrCursorConflict
		}
		s.cursors[commit.AccountID] = commit.Next
		return nil
	}
	if commit.Expected == nil || *commit.Expected != current {
		return storage.ErrCursorConflict
	}
	s.cursors[commit.AccountID] = commit.Next
	return nil
}

func (s *Store) GetProviderCredential(ctx context.Context, accountID storage.AccountID) (storage.ProviderCredential, error) {
	if err := ctx.Err(); err != nil {
		return storage.ProviderCredential{}, err
	}
	if parsed, err := storage.ParseAccountID(accountID.String()); err != nil || parsed != accountID {
		return storage.ProviderCredential{}, storage.ErrInvalidValue
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts[accountID]; !ok {
		return storage.ProviderCredential{}, storage.ErrAccountNotFound
	}
	credential, ok := s.credentials[accountID]
	if !ok {
		return storage.ProviderCredential{}, storage.ErrCredentialNotFound
	}
	return credential, nil
}

func (s *Store) CommitProviderCredential(ctx context.Context, commit storage.ProviderCredentialCommit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := storage.ValidateProviderCredentialCommit(commit); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts[commit.AccountID]; !ok {
		return storage.ErrAccountNotFound
	}
	if lifecycle, ok := s.lifecycles[commit.AccountID]; !ok || lifecycle.State == storage.AccountStateRevoked {
		return storage.ErrLifecycleConflict
	}
	current, exists := s.credentials[commit.AccountID]
	if exists && current.Envelope == commit.Next {
		return nil
	}
	if !exists {
		if commit.Expected != nil {
			return storage.ErrCredentialConflict
		}
		s.credentials[commit.AccountID] = storage.ProviderCredential{AccountID: commit.AccountID, KeyID: commit.Next.KeyID(), Envelope: commit.Next}
		return nil
	}
	if commit.Expected == nil || current.Envelope != *commit.Expected {
		return storage.ErrCredentialConflict
	}
	s.credentials[commit.AccountID] = storage.ProviderCredential{AccountID: commit.AccountID, KeyID: commit.Next.KeyID(), Envelope: commit.Next}
	return nil
}

func (s *Store) ListAccounts(ctx context.Context) ([]storage.AccountSummary, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]storage.AccountID, 0, len(s.lifecycles))
	for id := range s.lifecycles {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left].String() < ids[right].String() })
	if len(ids) > storage.MaximumAccountList {
		return nil, storage.ErrResultTooLarge
	}
	result := make([]storage.AccountSummary, 0, len(ids))
	for _, id := range ids {
		lifecycle := s.lifecycles[id]
		_, cursorPresent := s.cursors[id]
		_, credentialPresent := s.credentials[id]
		result = append(result, storage.AccountSummary{
			AccountID: id, Provider: storage.ProviderGmail, State: lifecycle.State, StateVersion: lifecycle.Version,
			ReauthorizationReason: lifecycle.ReauthorizationReason, RevocationStatus: lifecycle.RevocationStatus,
			CursorPresent: cursorPresent, CredentialPresent: credentialPresent,
		})
	}
	return result, nil
}

func (s *Store) GetAccountLifecycle(ctx context.Context, accountID storage.AccountID) (storage.AccountLifecycle, error) {
	if err := ctx.Err(); err != nil {
		return storage.AccountLifecycle{}, err
	}
	if parsed, err := storage.ParseAccountID(accountID.String()); err != nil || parsed != accountID {
		return storage.AccountLifecycle{}, storage.ErrInvalidValue
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lifecycle, ok := s.lifecycles[accountID]
	if !ok {
		if _, accountExists := s.accounts[accountID]; accountExists {
			return storage.AccountLifecycle{}, storage.ErrLifecycleNotFound
		}
		return storage.AccountLifecycle{}, storage.ErrAccountNotFound
	}
	return lifecycle, nil
}

func (s *Store) CommitAccountLifecycle(ctx context.Context, commit storage.LifecycleCommit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := storage.ValidateLifecycleCommit(commit); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.lifecycles[commit.AccountID]
	if !ok {
		if _, accountExists := s.accounts[commit.AccountID]; accountExists {
			return storage.ErrLifecycleNotFound
		}
		return storage.ErrAccountNotFound
	}
	if storage.LifecycleMatchesCommit(current, commit) {
		if storage.LifecycleCommitIsRevocationClaim(commit) {
			return storage.ErrLifecycleConflict
		}
		return nil
	}
	if current.State != commit.ExpectedState || current.Version != commit.ExpectedVersion || current.RevocationStatus != commit.ExpectedRevocationStatus {
		return storage.ErrLifecycleConflict
	}
	if commit.NextState == storage.AccountStateActive {
		if _, ok := s.cursors[commit.AccountID]; !ok {
			return storage.ErrLifecycleIncomplete
		}
		if _, ok := s.credentials[commit.AccountID]; !ok {
			return storage.ErrLifecycleIncomplete
		}
	}
	version, _ := storage.ParseLifecycleVersion(current.Version.Int64() + 1)
	s.lifecycles[commit.AccountID] = storage.AccountLifecycle{
		AccountID: commit.AccountID, State: commit.NextState, Version: version,
		ReauthorizationReason: commit.ReauthorizationReason, RevocationStatus: commit.RevocationStatus,
	}
	return nil
}

func (s *Store) DeleteRevokedProviderCredential(ctx context.Context, operation storage.RevokedCredentialDelete) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := storage.ValidateRevokedCredentialDelete(operation); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lifecycle, ok := s.lifecycles[operation.AccountID]
	if !ok {
		if _, accountExists := s.accounts[operation.AccountID]; accountExists {
			return storage.ErrLifecycleNotFound
		}
		return storage.ErrAccountNotFound
	}
	if lifecycle.State != storage.AccountStateRevoked {
		return storage.ErrLifecycleConflict
	}
	credential, exists := s.credentials[operation.AccountID]
	if !exists {
		return nil
	}
	if credential.Envelope != operation.Expected {
		return storage.ErrCredentialConflict
	}
	delete(s.credentials, operation.AccountID)
	return nil
}

func (s *Store) Close() error { return nil }

var _ storage.Handle = (*Store)(nil)
