// Package accountstatus composes bounded, read-only account status snapshots.
package accountstatus

import (
	"context"
	"errors"
	"strings"

	"github.com/mandloideep/inboxgate/internal/accountstatusview"
	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/storage"
)

const OutputVersion = accountstatusview.OutputVersion

var ErrUnavailable = errors.New("account status unavailable")

type Source interface {
	ListAccounts(context.Context) ([]storage.AccountSummary, error)
}

type CursorStatus = accountstatusview.CursorStatus
type Availability = accountstatusview.Availability
type Persistence = accountstatusview.Persistence
type CapabilityStatus = accountstatusview.CapabilityStatus
type Account = accountstatusview.Account
type Snapshot = accountstatusview.Snapshot

const (
	CursorStatusInitialized   = accountstatusview.CursorStatusInitialized
	CursorStatusUninitialized = accountstatusview.CursorStatusUninitialized
	AvailabilityNotAvailable  = accountstatusview.AvailabilityNotAvailable
	PersistenceNotPersisted   = accountstatusview.PersistenceNotPersisted
)

type Service struct {
	source      Source
	currentSync CapabilityStatus
	backfill    CapabilityStatus
}

func New(source Source, registry []config.Capability) (*Service, error) {
	if source == nil {
		return nil, ErrUnavailable
	}
	currentSync, currentOK := exactCapability(registry, config.CapabilityGmailCurrentSync)
	backfill, backfillOK := exactCapability(registry, config.CapabilityGmailBackfill)
	if !currentOK || !backfillOK {
		return nil, ErrUnavailable
	}
	return &Service{source: source, currentSync: currentSync, backfill: backfill}, nil
}

func exactCapability(registry []config.Capability, name config.CapabilityName) (CapabilityStatus, bool) {
	var match config.Capability
	count := 0
	for _, capability := range registry {
		if capability.Name == name {
			match = capability
			count++
		}
	}
	if count != 1 || match.ImplementationStatus != config.ImplementationStatusNotImplemented ||
		match.ConfigurationStatus != config.ConfigurationStatusDisabled || match.Enabled {
		return CapabilityStatus{}, false
	}
	return CapabilityStatus{
		ImplementationStatus: match.ImplementationStatus,
		ConfigurationStatus:  match.ConfigurationStatus,
		Enabled:              match.Enabled,
	}, true
}

func (service *Service) Snapshot(ctx context.Context) (Snapshot, error) {
	if service == nil || service.source == nil {
		return Snapshot{}, ErrUnavailable
	}
	summaries, err := service.source.ListAccounts(ctx)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return Snapshot{}, errors.Join(ErrUnavailable, contextErr)
		}
		return Snapshot{}, ErrUnavailable
	}
	if len(summaries) > storage.MaximumAccountList {
		return Snapshot{}, ErrUnavailable
	}
	result := Snapshot{
		Accounts:    make([]Account, 0, len(summaries)),
		CurrentSync: service.currentSync,
		Backfill:    service.backfill,
	}
	previous := ""
	for _, summary := range summaries {
		account, ok := composeAccount(summary)
		if !ok || previous != "" && strings.Compare(previous, account.AccountID) >= 0 {
			return Snapshot{}, ErrUnavailable
		}
		previous = account.AccountID
		result.Accounts = append(result.Accounts, account)
	}
	return result, nil
}

func composeAccount(summary storage.AccountSummary) (Account, bool) {
	accountID := summary.AccountID.String()
	parsedID, idErr := storage.ParseAccountID(accountID)
	state := summary.State.String()
	parsedState, stateErr := storage.ParseAccountState(state)
	version := summary.StateVersion.Int64()
	parsedVersion, versionErr := storage.ParseLifecycleVersion(version)
	revocation := summary.RevocationStatus.String()
	parsedRevocation, revocationErr := storage.ParseRevocationStatus(revocation)
	if idErr != nil || parsedID != summary.AccountID || summary.Provider != storage.ProviderGmail ||
		stateErr != nil || parsedState != summary.State || versionErr != nil || parsedVersion != summary.StateVersion ||
		revocationErr != nil || parsedRevocation != summary.RevocationStatus || !validLifecycleShape(summary) {
		return Account{}, false
	}
	var reason *string
	if summary.ReauthorizationReason != nil {
		value := summary.ReauthorizationReason.String()
		parsed, err := storage.ParseReauthorizationReason(value)
		if err != nil || parsed != *summary.ReauthorizationReason {
			return Account{}, false
		}
		reason = &value
	}
	cursor := CursorStatusUninitialized
	if summary.CursorPresent {
		cursor = CursorStatusInitialized
	}
	return Account{
		AccountID: accountID, Provider: summary.Provider, State: state, StateVersion: version,
		ReauthorizationReason: reason, RevocationStatus: revocation, CursorStatus: cursor,
		CurrentExecutionStatus: AvailabilityNotAvailable, CurrentStaleStatus: PersistenceNotPersisted,
		BackfillExecutionStatus: AvailabilityNotAvailable, BackfillCheckpointStatus: PersistenceNotPersisted,
	}, true
}

func validLifecycleShape(summary storage.AccountSummary) bool {
	if summary.State == storage.AccountStateReauthorizationRequired {
		return summary.ReauthorizationReason != nil && summary.RevocationStatus == storage.RevocationStatusNone
	}
	if summary.ReauthorizationReason != nil {
		return false
	}
	if summary.State == storage.AccountStateRevoked {
		return summary.RevocationStatus == storage.RevocationStatusPending ||
			summary.RevocationStatus == storage.RevocationStatusAttempting ||
			summary.RevocationStatus == storage.RevocationStatusConfirmed ||
			summary.RevocationStatus == storage.RevocationStatusManualActionRequired
	}
	return summary.RevocationStatus == storage.RevocationStatusNone
}
