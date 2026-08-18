package turso

import (
	"context"
	"database/sql"

	"github.com/mandloideep/inboxgate/internal/storage"
)

const (
	lifecycleLookupSQL         = "WITH input(account_id) AS (VALUES (?)) SELECT 1, (SELECT COUNT(*) FROM inboxgate_accounts AS a, input WHERE a.account_id = input.account_id), COUNT(l.account_id), MAX(l.account_id), MAX(l.state), MAX(l.state_version), MAX(l.reauthorization_reason), MAX(l.revocation_status) FROM input LEFT JOIN inboxgate_account_lifecycle AS l ON l.account_id = input.account_id"
	accountListSQL             = "SELECT a.account_id, a.provider, l.state, l.state_version, l.reauthorization_reason, l.revocation_status, EXISTS (SELECT 1 FROM inboxgate_synchronization_cursors AS c WHERE c.account_id = a.account_id), EXISTS (SELECT 1 FROM inboxgate_provider_credentials AS p WHERE p.account_id = a.account_id) FROM inboxgate_accounts AS a LEFT JOIN inboxgate_account_lifecycle AS l ON l.account_id = a.account_id ORDER BY a.account_id COLLATE BINARY LIMIT 101"
	lifecycleCommitSQL         = "UPDATE inboxgate_account_lifecycle SET state = ?, state_version = state_version + 1, reauthorization_reason = ?, revocation_status = ? WHERE account_id = ? AND state = ? AND state_version = ? AND revocation_status = ? AND state_version < 9223372036854775807 AND (? <> 'active' OR (EXISTS (SELECT 1 FROM inboxgate_synchronization_cursors WHERE account_id = ?) AND EXISTS (SELECT 1 FROM inboxgate_provider_credentials WHERE account_id = ?)))"
	revokedCredentialDeleteSQL = "DELETE FROM inboxgate_provider_credentials WHERE account_id = ? AND envelope = ? AND EXISTS (SELECT 1 FROM inboxgate_account_lifecycle WHERE account_id = ? AND state = 'revoked')"
)

func (h *handle) ListAccounts(ctx context.Context) ([]storage.AccountSummary, error) {
	if !h.migrationAllowed {
		return nil, storage.ErrPersistenceNotAllowed
	}
	operationCtx, cancel := context.WithTimeout(ctx, h.persistenceTimeout)
	defer cancel()
	connection, err := h.database.Conn(operationCtx)
	if err != nil {
		return nil, safePersistenceError(storage.ErrPersistenceAcquire, operationCtx)
	}
	defer connection.Close()
	rows, err := connection.QueryContext(operationCtx, accountListSQL)
	if err != nil {
		return nil, safePersistenceError(storage.ErrPersistenceInspect, operationCtx)
	}
	defer rows.Close()
	result := make([]storage.AccountSummary, 0)
	for rows.Next() {
		if len(result) == storage.MaximumAccountList {
			return nil, storage.ErrResultTooLarge
		}
		var rawAccountID, rawProvider, rawState, rawVersion, rawReason, rawRevocation, rawCursor, rawCredential any
		if err := rows.Scan(&rawAccountID, &rawProvider, &rawState, &rawVersion, &rawReason, &rawRevocation, &rawCursor, &rawCredential); err != nil {
			return nil, storage.ErrPersistenceInspect
		}
		summary, err := decodeAccountSummary(rawAccountID, rawProvider, rawState, rawVersion, rawReason, rawRevocation, rawCursor, rawCredential)
		if err != nil {
			return nil, err
		}
		if len(result) > 0 && result[len(result)-1].AccountID.String() >= summary.AccountID.String() {
			return nil, storage.ErrPersistenceInspect
		}
		result = append(result, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, safePersistenceError(storage.ErrPersistenceInspect, operationCtx)
	}
	return result, nil
}

func (h *handle) GetAccountLifecycle(ctx context.Context, accountID storage.AccountID) (storage.AccountLifecycle, error) {
	if !h.migrationAllowed {
		return storage.AccountLifecycle{}, storage.ErrPersistenceNotAllowed
	}
	if parsed, err := storage.ParseAccountID(accountID.String()); err != nil || parsed != accountID {
		return storage.AccountLifecycle{}, storage.ErrInvalidValue
	}
	operationCtx, cancel := context.WithTimeout(ctx, h.persistenceTimeout)
	defer cancel()
	return h.inspectLifecycle(operationCtx, accountID)
}

func (h *handle) inspectLifecycle(ctx context.Context, accountID storage.AccountID) (storage.AccountLifecycle, error) {
	connection, err := h.database.Conn(ctx)
	if err != nil {
		return storage.AccountLifecycle{}, safePersistenceError(storage.ErrPersistenceAcquire, ctx)
	}
	defer connection.Close()
	rows, err := connection.QueryContext(ctx, lifecycleLookupSQL, accountID.String())
	if err != nil {
		return storage.AccountLifecycle{}, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	defer rows.Close()
	count := 0
	var lifecycle storage.AccountLifecycle
	for rows.Next() {
		count++
		if count > 1 {
			return storage.AccountLifecycle{}, storage.ErrPersistenceInspect
		}
		var rawSentinel, rawAccountCount, rawCount, rawAccountID, rawState, rawVersion, rawReason, rawRevocation any
		if err := rows.Scan(&rawSentinel, &rawAccountCount, &rawCount, &rawAccountID, &rawState, &rawVersion, &rawReason, &rawRevocation); err != nil {
			return storage.AccountLifecycle{}, storage.ErrPersistenceInspect
		}
		sentinel, sentinelOK := exactInteger(rawSentinel)
		accountCount, accountCountOK := exactInteger(rawAccountCount)
		rowCount, countOK := exactInteger(rawCount)
		if !sentinelOK || sentinel != 1 || !accountCountOK || accountCount < 0 || accountCount > 1 || !countOK || rowCount < 0 || rowCount > 1 || rowCount > accountCount {
			return storage.AccountLifecycle{}, storage.ErrPersistenceInspect
		}
		if accountCount == 0 {
			if rowCount != 0 || rawAccountID != nil || rawState != nil || rawVersion != nil || rawReason != nil || rawRevocation != nil {
				return storage.AccountLifecycle{}, storage.ErrPersistenceInspect
			}
			return storage.AccountLifecycle{}, storage.ErrAccountNotFound
		}
		if rowCount == 0 {
			if rawAccountID != nil || rawState != nil || rawVersion != nil || rawReason != nil || rawRevocation != nil {
				return storage.AccountLifecycle{}, storage.ErrPersistenceInspect
			}
			return storage.AccountLifecycle{}, storage.ErrLifecycleNotFound
		}
		lifecycle, err = decodeLifecycle(rawAccountID, rawState, rawVersion, rawReason, rawRevocation)
		if err != nil || lifecycle.AccountID != accountID {
			return storage.AccountLifecycle{}, storage.ErrPersistenceInspect
		}
	}
	if err := rows.Err(); err != nil {
		return storage.AccountLifecycle{}, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	if count != 1 {
		return storage.AccountLifecycle{}, storage.ErrPersistenceInspect
	}
	return lifecycle, nil
}

func (h *handle) CommitAccountLifecycle(ctx context.Context, commit storage.LifecycleCommit) error {
	if !h.migrationAllowed {
		return storage.ErrPersistenceNotAllowed
	}
	if err := storage.ValidateLifecycleCommit(commit); err != nil {
		return err
	}
	operationCtx, cancel := context.WithTimeout(ctx, h.persistenceTimeout)
	defer cancel()
	initial, err := h.inspectLifecycle(operationCtx, commit.AccountID)
	if err != nil {
		return err
	}
	if storage.LifecycleMatchesCommit(initial, commit) {
		if storage.LifecycleCommitIsRevocationClaim(commit) {
			return storage.ErrLifecycleConflict
		}
		return nil
	}
	if initial.State != commit.ExpectedState || initial.Version != commit.ExpectedVersion || initial.RevocationStatus != commit.ExpectedRevocationStatus {
		return storage.ErrLifecycleConflict
	}
	if commit.NextState == storage.AccountStateActive {
		cursor, cursorErr := h.inspectCursor(operationCtx, commit.AccountID)
		credential, credentialErr := h.inspectCredential(operationCtx, commit.AccountID)
		if cursorErr != nil || credentialErr != nil {
			return storage.ErrPersistenceInspect
		}
		if cursor.historyID == nil || credential.credential == nil {
			return storage.ErrLifecycleIncomplete
		}
	}
	connection, err := h.database.Conn(operationCtx)
	if err != nil {
		return safePersistenceError(storage.ErrPersistenceAcquire, operationCtx)
	}
	var reason any
	if commit.ReauthorizationReason != nil {
		reason = commit.ReauthorizationReason.String()
	}
	result, mutationErr := connection.ExecContext(operationCtx, lifecycleCommitSQL,
		commit.NextState.String(), reason, commit.RevocationStatus.String(), commit.AccountID.String(), commit.ExpectedState.String(), commit.ExpectedVersion.Int64(), commit.ExpectedRevocationStatus.String(), commit.NextState.String(), commit.AccountID.String(), commit.AccountID.String())
	mutationConfirmed := exactOneRow(result, mutationErr)
	mutationConfirmedZero := false
	if mutationErr == nil && result != nil {
		rowsAffected, rowsAffectedErr := result.RowsAffected()
		mutationConfirmedZero = rowsAffectedErr == nil && rowsAffected == 0
	}
	verified, verificationErr := h.inspectLifecycle(operationCtx, commit.AccountID)
	success := verificationErr == nil && storage.LifecycleMatchesCommit(verified, commit) && verified.Version.Int64() == commit.ExpectedVersion.Int64()+1
	if mutationErr != nil || !mutationConfirmed || !success {
		discardPersistenceConnection(connection)
	} else {
		_ = connection.Close()
	}
	if storage.LifecycleCommitIsRevocationClaim(commit) && success && !mutationConfirmed {
		if mutationConfirmedZero {
			return storage.ErrLifecycleConflict
		}
		return safePersistenceError(storage.ErrPersistenceUnknown, operationCtx)
	}
	if success {
		return nil
	}
	return safePersistenceError(storage.ErrPersistenceUnknown, operationCtx)
}

func (h *handle) DeleteRevokedProviderCredential(ctx context.Context, operation storage.RevokedCredentialDelete) error {
	if !h.migrationAllowed {
		return storage.ErrPersistenceNotAllowed
	}
	if err := storage.ValidateRevokedCredentialDelete(operation); err != nil {
		return err
	}
	operationCtx, cancel := context.WithTimeout(ctx, h.persistenceTimeout)
	defer cancel()
	lifecycle, err := h.inspectLifecycle(operationCtx, operation.AccountID)
	if err != nil {
		return err
	}
	if lifecycle.State != storage.AccountStateRevoked {
		return storage.ErrLifecycleConflict
	}
	initial, err := h.inspectCredential(operationCtx, operation.AccountID)
	if err != nil {
		return err
	}
	if initial.credential == nil {
		return nil
	}
	if initial.credential.Envelope != operation.Expected {
		return storage.ErrCredentialConflict
	}
	connection, err := h.database.Conn(operationCtx)
	if err != nil {
		return safePersistenceError(storage.ErrPersistenceAcquire, operationCtx)
	}
	result, mutationErr := connection.ExecContext(operationCtx, revokedCredentialDeleteSQL, operation.AccountID.String(), operation.Expected.String(), operation.AccountID.String())
	mutationConfirmed := exactOneRow(result, mutationErr)
	verified, verificationErr := h.inspectCredential(operationCtx, operation.AccountID)
	success := verificationErr == nil && verified.credential == nil
	if mutationErr != nil || !mutationConfirmed || !success {
		discardPersistenceConnection(connection)
	} else {
		_ = connection.Close()
	}
	if success {
		return nil
	}
	return safePersistenceError(storage.ErrPersistenceUnknown, operationCtx)
}

func exactOneRow(result sql.Result, err error) bool {
	if err != nil || result == nil {
		return false
	}
	rowsAffected, rowsAffectedErr := result.RowsAffected()
	return rowsAffectedErr == nil && rowsAffected == 1
}

func decodeLifecycle(rawAccountID, rawState, rawVersion, rawReason, rawRevocation any) (storage.AccountLifecycle, error) {
	accountText, accountOK := exactText(rawAccountID)
	stateText, stateOK := exactText(rawState)
	versionValue, versionOK := exactInteger(rawVersion)
	revocationText, revocationOK := exactText(rawRevocation)
	if !accountOK || !stateOK || !versionOK || !revocationOK {
		return storage.AccountLifecycle{}, storage.ErrPersistenceInspect
	}
	accountID, err := storage.ParseAccountID(accountText)
	if err != nil {
		return storage.AccountLifecycle{}, storage.ErrPersistenceInspect
	}
	state, err := storage.ParseAccountState(stateText)
	if err != nil {
		return storage.AccountLifecycle{}, storage.ErrPersistenceInspect
	}
	version, err := storage.ParseLifecycleVersion(versionValue)
	if err != nil {
		return storage.AccountLifecycle{}, storage.ErrPersistenceInspect
	}
	revocation, err := storage.ParseRevocationStatus(revocationText)
	if err != nil {
		return storage.AccountLifecycle{}, storage.ErrPersistenceInspect
	}
	var reason *storage.ReauthorizationReason
	if rawReason != nil {
		reasonText, ok := exactText(rawReason)
		if !ok {
			return storage.AccountLifecycle{}, storage.ErrPersistenceInspect
		}
		parsed, err := storage.ParseReauthorizationReason(reasonText)
		if err != nil {
			return storage.AccountLifecycle{}, storage.ErrPersistenceInspect
		}
		reason = &parsed
	}
	commitShape := storage.LifecycleCommit{AccountID: accountID, ExpectedState: state, ExpectedVersion: version, ExpectedRevocationStatus: revocation, NextState: state, ReauthorizationReason: reason, RevocationStatus: revocation}
	if !decodedLifecycleShapeValid(commitShape) {
		return storage.AccountLifecycle{}, storage.ErrPersistenceInspect
	}
	return storage.AccountLifecycle{AccountID: accountID, State: state, Version: version, ReauthorizationReason: reason, RevocationStatus: revocation}, nil
}

func decodedLifecycleShapeValid(value storage.LifecycleCommit) bool {
	if value.NextState == storage.AccountStateReauthorizationRequired {
		return value.ReauthorizationReason != nil && value.RevocationStatus == storage.RevocationStatusNone
	}
	if value.ReauthorizationReason != nil {
		return false
	}
	if value.NextState == storage.AccountStateRevoked {
		return value.RevocationStatus == storage.RevocationStatusPending || value.RevocationStatus == storage.RevocationStatusAttempting || value.RevocationStatus == storage.RevocationStatusConfirmed || value.RevocationStatus == storage.RevocationStatusManualActionRequired
	}
	return value.RevocationStatus == storage.RevocationStatusNone
}

func decodeAccountSummary(rawAccountID, rawProvider, rawState, rawVersion, rawReason, rawRevocation, rawCursor, rawCredential any) (storage.AccountSummary, error) {
	lifecycle, err := decodeLifecycle(rawAccountID, rawState, rawVersion, rawReason, rawRevocation)
	provider, providerOK := exactText(rawProvider)
	cursor, cursorOK := exactInteger(rawCursor)
	credential, credentialOK := exactInteger(rawCredential)
	if err != nil || !providerOK || provider != storage.ProviderGmail || !cursorOK || !credentialOK || (cursor != 0 && cursor != 1) || (credential != 0 && credential != 1) {
		return storage.AccountSummary{}, storage.ErrPersistenceInspect
	}
	return storage.AccountSummary{
		AccountID: lifecycle.AccountID, Provider: provider, State: lifecycle.State, StateVersion: lifecycle.Version,
		ReauthorizationReason: lifecycle.ReauthorizationReason, RevocationStatus: lifecycle.RevocationStatus,
		CursorPresent: cursor == 1, CredentialPresent: credential == 1,
	}, nil
}
