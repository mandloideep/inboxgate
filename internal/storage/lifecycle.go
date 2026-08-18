package storage

import (
	"errors"
	"math"
)

const MaximumAccountList = 100

var (
	ErrLifecycleNotFound   = errors.New("storage: account lifecycle not found")
	ErrLifecycleConflict   = errors.New("storage: account lifecycle conflict")
	ErrLifecycleIncomplete = errors.New("storage: account lifecycle incomplete")
	ErrLifecycleOverflow   = errors.New("storage: account lifecycle version overflow")
	ErrResultTooLarge      = errors.New("storage: result too large")
)

type AccountState struct {
	value string
}

var (
	AccountStatePending                 = AccountState{value: "pending"}
	AccountStateActive                  = AccountState{value: "active"}
	AccountStatePaused                  = AccountState{value: "paused"}
	AccountStateReauthorizationRequired = AccountState{value: "reauthorization_required"}
	AccountStateRevoked                 = AccountState{value: "revoked"}
)

func ParseAccountState(value string) (AccountState, error) {
	switch value {
	case AccountStatePending.value:
		return AccountStatePending, nil
	case AccountStateActive.value:
		return AccountStateActive, nil
	case AccountStatePaused.value:
		return AccountStatePaused, nil
	case AccountStateReauthorizationRequired.value:
		return AccountStateReauthorizationRequired, nil
	case AccountStateRevoked.value:
		return AccountStateRevoked, nil
	default:
		return AccountState{}, ErrInvalidValue
	}
}

func (state AccountState) String() string { return state.value }

func (state AccountState) valid() bool {
	parsed, err := ParseAccountState(state.value)
	return err == nil && parsed == state
}

type LifecycleVersion struct {
	value int64
}

func ParseLifecycleVersion(value int64) (LifecycleVersion, error) {
	if value < 1 {
		return LifecycleVersion{}, ErrInvalidValue
	}
	return LifecycleVersion{value: value}, nil
}

func (version LifecycleVersion) Int64() int64 { return version.value }

func (version LifecycleVersion) valid() bool { return version.value >= 1 }

type ReauthorizationReason struct {
	value string
}

var (
	ReauthorizationReasonRefreshInvalidGrant           = ReauthorizationReason{value: "refresh_invalid_grant"}
	ReauthorizationReasonRefreshAdminPolicyEnforced    = ReauthorizationReason{value: "refresh_admin_policy_enforced"}
	ReauthorizationReasonGmailUnauthorizedAfterRefresh = ReauthorizationReason{value: "gmail_unauthorized_after_refresh"}
	ReauthorizationReasonGmailDomainPolicy             = ReauthorizationReason{value: "gmail_domain_policy"}
)

func ParseReauthorizationReason(value string) (ReauthorizationReason, error) {
	switch value {
	case ReauthorizationReasonRefreshInvalidGrant.value:
		return ReauthorizationReasonRefreshInvalidGrant, nil
	case ReauthorizationReasonRefreshAdminPolicyEnforced.value:
		return ReauthorizationReasonRefreshAdminPolicyEnforced, nil
	case ReauthorizationReasonGmailUnauthorizedAfterRefresh.value:
		return ReauthorizationReasonGmailUnauthorizedAfterRefresh, nil
	case ReauthorizationReasonGmailDomainPolicy.value:
		return ReauthorizationReasonGmailDomainPolicy, nil
	default:
		return ReauthorizationReason{}, ErrInvalidValue
	}
}

func (reason ReauthorizationReason) String() string { return reason.value }

func (reason ReauthorizationReason) valid() bool {
	parsed, err := ParseReauthorizationReason(reason.value)
	return err == nil && parsed == reason
}

type RevocationStatus struct {
	value string
}

var (
	RevocationStatusNone                 = RevocationStatus{value: "none"}
	RevocationStatusPending              = RevocationStatus{value: "pending"}
	RevocationStatusAttempting           = RevocationStatus{value: "attempting"}
	RevocationStatusConfirmed            = RevocationStatus{value: "confirmed"}
	RevocationStatusManualActionRequired = RevocationStatus{value: "manual_action_required"}
)

func ParseRevocationStatus(value string) (RevocationStatus, error) {
	switch value {
	case RevocationStatusNone.value:
		return RevocationStatusNone, nil
	case RevocationStatusPending.value:
		return RevocationStatusPending, nil
	case RevocationStatusAttempting.value:
		return RevocationStatusAttempting, nil
	case RevocationStatusConfirmed.value:
		return RevocationStatusConfirmed, nil
	case RevocationStatusManualActionRequired.value:
		return RevocationStatusManualActionRequired, nil
	default:
		return RevocationStatus{}, ErrInvalidValue
	}
}

func (status RevocationStatus) String() string { return status.value }

func (status RevocationStatus) valid() bool {
	parsed, err := ParseRevocationStatus(status.value)
	return err == nil && parsed == status
}

type AccountLifecycle struct {
	AccountID             AccountID
	State                 AccountState
	Version               LifecycleVersion
	ReauthorizationReason *ReauthorizationReason
	RevocationStatus      RevocationStatus
}

type AccountSummary struct {
	AccountID             AccountID
	Provider              string
	State                 AccountState
	StateVersion          LifecycleVersion
	ReauthorizationReason *ReauthorizationReason
	RevocationStatus      RevocationStatus
	CursorPresent         bool
	CredentialPresent     bool
}

type LifecycleCommit struct {
	AccountID                AccountID
	ExpectedState            AccountState
	ExpectedVersion          LifecycleVersion
	ExpectedRevocationStatus RevocationStatus
	NextState                AccountState
	ReauthorizationReason    *ReauthorizationReason
	RevocationStatus         RevocationStatus
}

type RevokedCredentialDelete struct {
	AccountID AccountID
	Expected  CredentialEnvelope
}

func ValidateLifecycleCommit(commit LifecycleCommit) error {
	if !commit.AccountID.valid() || !commit.ExpectedState.valid() || !commit.ExpectedVersion.valid() || !commit.ExpectedRevocationStatus.valid() || !commit.NextState.valid() || !commit.RevocationStatus.valid() || (commit.ReauthorizationReason != nil && !commit.ReauthorizationReason.valid()) {
		return ErrInvalidValue
	}
	if commit.ExpectedVersion.value == math.MaxInt64 {
		return ErrLifecycleOverflow
	}
	if !validExpectedLifecycleShape(commit.ExpectedState, commit.ExpectedRevocationStatus) || !validLifecycleShape(commit.NextState, commit.ReauthorizationReason, commit.RevocationStatus) || !validLifecycleTransition(commit.ExpectedState, commit.ExpectedRevocationStatus, commit.NextState, commit.RevocationStatus) {
		return ErrLifecycleConflict
	}
	return nil
}

func validExpectedLifecycleShape(state AccountState, revocation RevocationStatus) bool {
	if state == AccountStateRevoked {
		return revocation == RevocationStatusPending || revocation == RevocationStatusAttempting || revocation == RevocationStatusConfirmed || revocation == RevocationStatusManualActionRequired
	}
	return revocation == RevocationStatusNone
}

func ValidateRevokedCredentialDelete(operation RevokedCredentialDelete) error {
	if !operation.AccountID.valid() || !operation.Expected.valid() {
		return ErrInvalidValue
	}
	return nil
}

func validLifecycleShape(state AccountState, reason *ReauthorizationReason, revocation RevocationStatus) bool {
	if state == AccountStateReauthorizationRequired {
		return reason != nil && reason.valid() && revocation == RevocationStatusNone
	}
	if reason != nil {
		return false
	}
	if state == AccountStateRevoked {
		return revocation == RevocationStatusPending || revocation == RevocationStatusAttempting || revocation == RevocationStatusConfirmed || revocation == RevocationStatusManualActionRequired
	}
	return revocation == RevocationStatusNone
}

func validLifecycleTransition(current AccountState, currentRevocation RevocationStatus, next AccountState, revocation RevocationStatus) bool {
	switch current {
	case AccountStatePending:
		return currentRevocation == RevocationStatusNone && (next == AccountStateActive || next == AccountStateRevoked && revocation == RevocationStatusPending)
	case AccountStateActive:
		return currentRevocation == RevocationStatusNone && (next == AccountStatePaused || next == AccountStateReauthorizationRequired || next == AccountStateRevoked && revocation == RevocationStatusPending)
	case AccountStatePaused:
		return currentRevocation == RevocationStatusNone && (next == AccountStateActive || next == AccountStateRevoked && revocation == RevocationStatusPending)
	case AccountStateReauthorizationRequired:
		return currentRevocation == RevocationStatusNone && next == AccountStateRevoked && revocation == RevocationStatusPending
	case AccountStateRevoked:
		return next == AccountStateRevoked && (currentRevocation == RevocationStatusPending && revocation == RevocationStatusAttempting || currentRevocation == RevocationStatusAttempting && (revocation == RevocationStatusConfirmed || revocation == RevocationStatusManualActionRequired))
	default:
		return false
	}
}

func LifecycleMatchesCommit(current AccountLifecycle, commit LifecycleCommit) bool {
	if current.AccountID != commit.AccountID || current.State != commit.NextState || current.RevocationStatus != commit.RevocationStatus {
		return false
	}
	if current.ReauthorizationReason == nil || commit.ReauthorizationReason == nil {
		return current.ReauthorizationReason == nil && commit.ReauthorizationReason == nil
	}
	return *current.ReauthorizationReason == *commit.ReauthorizationReason
}

func LifecycleCommitIsRevocationClaim(commit LifecycleCommit) bool {
	return commit.ExpectedState == AccountStateRevoked && commit.ExpectedRevocationStatus == RevocationStatusPending && commit.NextState == AccountStateRevoked && commit.RevocationStatus == RevocationStatusAttempting
}
