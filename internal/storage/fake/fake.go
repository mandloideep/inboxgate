// Package fake provides a credential-free storage replacement for contract tests.
package fake

import (
	"context"
	"sort"
	"sync"

	"github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
)

type Store struct {
	mu          sync.Mutex
	accounts    map[storage.AccountID]storage.Account
	bySubject   map[storage.ProviderSubject]storage.AccountID
	cursors     map[storage.AccountID]storage.HistoryID
	credentials map[storage.AccountID]storage.ProviderCredential
	lifecycles  map[storage.AccountID]storage.AccountLifecycle
	messages    map[storage.AccountID]map[string]mail.Message
	records     map[string]messageNaturalKey
	attempts    map[storage.AccountID]*currentDiscoveryAttempt
	decisions   map[string]storage.GateDecision
}

type messageNaturalKey struct {
	accountID      storage.AccountID
	gmailMessageID string
}

type currentDiscoveryAttempt struct {
	prepared storage.PreparedCurrentDiscovery
	state    string
	staged   []mail.Message
}

func New() *Store {
	return &Store{
		accounts:    make(map[storage.AccountID]storage.Account),
		bySubject:   make(map[storage.ProviderSubject]storage.AccountID),
		cursors:     make(map[storage.AccountID]storage.HistoryID),
		credentials: make(map[storage.AccountID]storage.ProviderCredential),
		lifecycles:  make(map[storage.AccountID]storage.AccountLifecycle),
		messages:    make(map[storage.AccountID]map[string]mail.Message),
		records:     make(map[string]messageNaturalKey),
		attempts:    make(map[storage.AccountID]*currentDiscoveryAttempt),
		decisions:   make(map[string]storage.GateDecision),
	}
}

func (s *Store) Ping(ctx context.Context) error { return ctx.Err() }

func (s *Store) Migrate(ctx context.Context) (storage.MigrationResult, error) {
	if err := ctx.Err(); err != nil {
		return storage.MigrationResult{}, err
	}
	return storage.MigrationResult{Current: 6}, nil
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
	if _, exists := s.cursors[commit.AccountID]; exists || s.attempts[commit.AccountID] != nil {
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
	if commit.NextState == storage.AccountStateRevoked {
		delete(s.attempts, commit.AccountID)
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

func (s *Store) CommitCurrentDiscovery(ctx context.Context, commit storage.CurrentDiscoveryCommit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	prepared, err := storage.PrepareCurrentDiscoveryCommit(commit)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currentDiscoveryDurable(prepared) {
		return nil
	}
	lifecycle, ok := s.lifecycles[prepared.AccountID()]
	if !ok {
		if _, exists := s.accounts[prepared.AccountID()]; exists {
			return storage.ErrLifecycleNotFound
		}
		return storage.ErrAccountNotFound
	}
	if lifecycle.State != storage.AccountStateActive {
		return storage.ErrLifecycleConflict
	}
	cursor, ok := s.cursors[prepared.AccountID()]
	if !ok {
		return storage.ErrCursorNotFound
	}
	if cursor != prepared.Expected() {
		return storage.ErrCurrentDiscoveryConflict
	}
	if existing := s.attempts[prepared.AccountID()]; existing != nil {
		if existing.prepared.AttemptID() != prepared.AttemptID() {
			return storage.ErrCurrentDiscoveryConflict
		}
		if existing.state == "sealed" {
			return s.finalizeCurrentDiscovery(existing.prepared)
		}
	} else {
		s.attempts[prepared.AccountID()] = &currentDiscoveryAttempt{prepared: prepared, state: "open"}
	}
	attempt := s.attempts[prepared.AccountID()]
	attempt.staged = prepared.Messages()
	attempt.state = "sealed"
	return s.finalizeCurrentDiscovery(prepared)
}

func (s *Store) ReconcileCurrentDiscovery(ctx context.Context, accountID storage.AccountID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if parsed, err := storage.ParseAccountID(accountID.String()); err != nil || parsed != accountID {
		return storage.ErrInvalidValue
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	attempt := s.attempts[accountID]
	if attempt == nil {
		return nil
	}
	prepared := attempt.prepared
	cursor, ok := s.cursors[accountID]
	if attempt.state == "open" {
		if !ok || cursor != prepared.Expected() || len(attempt.staged) > prepared.MessageCount() {
			return storage.ErrCurrentDiscoveryRecoveryRequired
		}
		lifecycle, lifecycleExists := s.lifecycles[accountID]
		if !lifecycleExists {
			return storage.ErrCurrentDiscoveryRecoveryRequired
		}
		if lifecycle.State != storage.AccountStateActive {
			return storage.ErrLifecycleConflict
		}
		delete(s.attempts, accountID)
		return nil
	}
	rebuilt, err := storage.PrepareCurrentDiscoveryCommit(storage.CurrentDiscoveryCommit{AccountID: prepared.AccountID(), Expected: prepared.Expected(), Next: prepared.Next(), Messages: attempt.staged})
	if err != nil || rebuilt.AttemptID() != prepared.AttemptID() || rebuilt.ManifestHash() != prepared.ManifestHash() || rebuilt.EncodedBytes() != prepared.EncodedBytes() {
		return storage.ErrCurrentDiscoveryRecoveryRequired
	}
	if !ok || cursor != prepared.Expected() {
		return storage.ErrCurrentDiscoveryRecoveryRequired
	}
	if attempt.state != "sealed" || len(attempt.staged) != prepared.MessageCount() {
		return storage.ErrCurrentDiscoveryRecoveryRequired
	}
	lifecycle, ok := s.lifecycles[accountID]
	if !ok {
		return storage.ErrCurrentDiscoveryRecoveryRequired
	}
	if lifecycle.State != storage.AccountStateActive {
		return storage.ErrLifecycleConflict
	}
	return s.finalizeCurrentDiscovery(prepared)
}

func (s *Store) GetDiscoveredMessage(ctx context.Context, accountID storage.AccountID, gmailMessageID string) (mail.Message, error) {
	if err := ctx.Err(); err != nil {
		return mail.Message{}, err
	}
	if parsed, err := storage.ParseAccountID(accountID.String()); err != nil || parsed != accountID || storage.ValidateGmailMessageID(gmailMessageID) != nil {
		return mail.Message{}, storage.ErrInvalidValue
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts[accountID]; !ok {
		return mail.Message{}, storage.ErrAccountNotFound
	}
	message, ok := s.messages[accountID][gmailMessageID]
	if !ok {
		return mail.Message{}, storage.ErrMessageNotFound
	}
	decoded, err := mail.DecodeCanonical(accountID.String(), message.GmailMessageID(), message.GmailThreadID(), message.MetadataVersion(), message.CanonicalJSON(), message.MetadataHash())
	if err != nil || decoded.RecordID() != message.RecordID() {
		return mail.Message{}, storage.ErrCurrentDiscoveryRecoveryRequired
	}
	return decoded, nil
}

func (s *Store) GetGateDecision(ctx context.Context, accountID storage.AccountID, gmailMessageID string) (storage.GateDecisionState, error) {
	if err := ctx.Err(); err != nil {
		return storage.GateDecisionState{}, err
	}
	if parsed, err := storage.ParseAccountID(accountID.String()); err != nil || parsed != accountID || storage.ValidateGmailMessageID(gmailMessageID) != nil {
		return storage.GateDecisionState{}, storage.ErrInvalidValue
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.accounts[accountID]; !exists {
		return storage.GateDecisionState{}, storage.ErrAccountNotFound
	}
	message, exists := s.messages[accountID][gmailMessageID]
	if !exists {
		return storage.GateDecisionState{}, storage.ErrMessageNotFound
	}
	decision, exists := s.decisions[message.RecordID()]
	if !exists {
		return storage.GateDecisionState{}, storage.ErrGateDecisionNotFound
	}
	decoded, err := storage.DecodeGateDecision(int64(decision.Version()), decision.SourceMetadataHash(), decision.InputHash(), decision.Outcome().String(), decision.ReasonJSON(), decision.EvaluatedAtUnixMS())
	if err != nil || !decoded.Equal(decision) {
		return storage.GateDecisionState{}, storage.ErrGateDecisionRecoveryRequired
	}
	return storage.GateDecisionState{Decision: decoded, Current: decoded.SourceMetadataHash() == message.MetadataHash()}, nil
}

func (s *Store) CommitGateDecision(ctx context.Context, commit storage.GateDecisionCommit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	accountID := commit.SourceAccountID()
	if parsed, err := storage.ParseAccountID(commit.Source.AccountID()); err != nil || parsed != accountID || storage.ValidateGmailMessageID(commit.SourceGmailMessageID()) != nil || !commit.Source.Valid() || !commit.Next.Valid() || (commit.Expected != nil && !commit.Expected.Valid()) {
		return storage.ErrInvalidValue
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.accounts[accountID]; !exists {
		return storage.ErrAccountNotFound
	}
	message, exists := s.messages[accountID][commit.SourceGmailMessageID()]
	if !exists {
		return storage.ErrMessageNotFound
	}
	if message.RecordID() != commit.Source.RecordID() || !message.MutableMetadataEqual(commit.Source) {
		return storage.ErrGateDecisionStaleSource
	}
	if message.MetadataHash() != commit.Next.SourceMetadataHash() {
		return storage.ErrInvalidValue
	}
	current, exists := s.decisions[message.RecordID()]
	if exists && current.SemanticEqual(commit.Next) {
		return nil
	}
	if !exists {
		if commit.Expected != nil {
			return storage.ErrGateDecisionConflict
		}
		s.decisions[message.RecordID()] = commit.Next
		return nil
	}
	if current.Revision() == commit.Next.Revision() {
		return storage.ErrGateDecisionConflict
	}
	if commit.Expected == nil || current.Revision() != *commit.Expected {
		return storage.ErrGateDecisionConflict
	}
	s.decisions[message.RecordID()] = commit.Next
	return nil
}

func (s *Store) finalizeCurrentDiscovery(prepared storage.PreparedCurrentDiscovery) error {
	attempt := s.attempts[prepared.AccountID()]
	if attempt == nil || attempt.state != "sealed" || attempt.prepared.AttemptID() != prepared.AttemptID() || len(attempt.staged) != prepared.MessageCount() {
		return storage.ErrCurrentDiscoveryRecoveryRequired
	}
	if lifecycle := s.lifecycles[prepared.AccountID()]; lifecycle.State != storage.AccountStateActive {
		return storage.ErrLifecycleConflict
	}
	if cursor, ok := s.cursors[prepared.AccountID()]; !ok || cursor != prepared.Expected() {
		return storage.ErrCurrentDiscoveryConflict
	}
	for _, message := range attempt.staged {
		key := messageNaturalKey{accountID: prepared.AccountID(), gmailMessageID: message.GmailMessageID()}
		if occupied, ok := s.records[message.RecordID()]; ok && occupied != key {
			return storage.ErrMessageIdentityCollision
		}
		if existing, ok := s.messages[prepared.AccountID()][message.GmailMessageID()]; ok {
			if existing.RecordID() != message.RecordID() {
				return storage.ErrCurrentDiscoveryRecoveryRequired
			}
			if existing.GmailThreadID() != message.GmailThreadID() {
				return storage.ErrCurrentDiscoveryConflict
			}
		}
	}
	if s.messages[prepared.AccountID()] == nil {
		s.messages[prepared.AccountID()] = make(map[string]mail.Message)
	}
	for _, message := range attempt.staged {
		s.messages[prepared.AccountID()][message.GmailMessageID()] = message
		s.records[message.RecordID()] = messageNaturalKey{accountID: prepared.AccountID(), gmailMessageID: message.GmailMessageID()}
	}
	s.cursors[prepared.AccountID()] = prepared.Next()
	delete(s.attempts, prepared.AccountID())
	return nil
}

func (s *Store) currentDiscoveryDurable(prepared storage.PreparedCurrentDiscovery) bool {
	if s.attempts[prepared.AccountID()] != nil {
		return false
	}
	if cursor, ok := s.cursors[prepared.AccountID()]; !ok || cursor != prepared.Next() {
		return false
	}
	for _, expected := range prepared.Messages() {
		stored, ok := s.messages[prepared.AccountID()][expected.GmailMessageID()]
		if !ok || !stored.Equal(expected) {
			return false
		}
	}
	return true
}

func (s *Store) Close() error { return nil }

var _ storage.Handle = (*Store)(nil)
