// Package fake provides a credential-free storage replacement for contract tests.
package fake

import (
	"context"
	"sync"

	"github.com/mandloideep/inboxgate/internal/storage"
)

type Store struct {
	mu        sync.Mutex
	accounts  map[storage.AccountID]storage.Account
	bySubject map[storage.ProviderSubject]storage.AccountID
	cursors   map[storage.AccountID]storage.HistoryID
}

func New() *Store {
	return &Store{
		accounts:  make(map[storage.AccountID]storage.Account),
		bySubject: make(map[storage.ProviderSubject]storage.AccountID),
		cursors:   make(map[storage.AccountID]storage.HistoryID),
	}
}

func (s *Store) Ping(ctx context.Context) error { return ctx.Err() }

func (s *Store) Migrate(ctx context.Context) (storage.MigrationResult, error) {
	if err := ctx.Err(); err != nil {
		return storage.MigrationResult{}, err
	}
	return storage.MigrationResult{Current: 2}, nil
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

func (s *Store) Close() error { return nil }

var _ storage.Handle = (*Store)(nil)
