package turso

import (
	"context"

	"github.com/mandloideep/inboxgate/internal/storage"
)

const (
	credentialLookupSQL = "WITH input(account_id) AS (VALUES (?)), account_match AS (SELECT inboxgate_accounts.account_id FROM inboxgate_accounts, input WHERE inboxgate_accounts.account_id = input.account_id), credential_match AS (SELECT inboxgate_provider_credentials.account_id, inboxgate_provider_credentials.key_id, inboxgate_provider_credentials.envelope FROM inboxgate_provider_credentials, input WHERE inboxgate_provider_credentials.account_id = input.account_id) SELECT 1, (SELECT COUNT(*) FROM account_match), (SELECT account_id FROM account_match), (SELECT COUNT(*) FROM credential_match), (SELECT account_id FROM credential_match), (SELECT key_id FROM credential_match), (SELECT envelope FROM credential_match)"
	credentialCommitSQL = "INSERT INTO inboxgate_provider_credentials (account_id, key_id, envelope) SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM inboxgate_accounts WHERE account_id = ?) AND (? IS NULL OR EXISTS (SELECT 1 FROM inboxgate_provider_credentials WHERE account_id = ? AND envelope = ?)) ON CONFLICT(account_id) DO UPDATE SET key_id = excluded.key_id, envelope = excluded.envelope WHERE ? IS NOT NULL AND inboxgate_provider_credentials.envelope = ?"
)

type credentialInspection struct {
	accountExists bool
	credential    *storage.ProviderCredential
}

func (h *handle) GetProviderCredential(ctx context.Context, accountID storage.AccountID) (storage.ProviderCredential, error) {
	if !h.migrationAllowed {
		return storage.ProviderCredential{}, storage.ErrPersistenceNotAllowed
	}
	if parsed, err := storage.ParseAccountID(accountID.String()); err != nil || parsed != accountID {
		return storage.ProviderCredential{}, storage.ErrInvalidValue
	}
	operationCtx, cancel := context.WithTimeout(ctx, h.persistenceTimeout)
	defer cancel()
	inspection, err := h.inspectCredential(operationCtx, accountID)
	if err != nil {
		return storage.ProviderCredential{}, err
	}
	if !inspection.accountExists {
		return storage.ProviderCredential{}, storage.ErrAccountNotFound
	}
	if inspection.credential == nil {
		return storage.ProviderCredential{}, storage.ErrCredentialNotFound
	}
	return *inspection.credential, nil
}

func (h *handle) CommitProviderCredential(ctx context.Context, commit storage.ProviderCredentialCommit) error {
	if !h.migrationAllowed {
		return storage.ErrPersistenceNotAllowed
	}
	if err := storage.ValidateProviderCredentialCommit(commit); err != nil {
		return err
	}
	operationCtx, cancel := context.WithTimeout(ctx, h.persistenceTimeout)
	defer cancel()
	initial, err := h.inspectCredential(operationCtx, commit.AccountID)
	if err != nil {
		return err
	}
	if err, decided := classifyCredentialCommit(commit, initial); decided {
		return err
	}
	connection, err := h.database.Conn(operationCtx)
	if err != nil {
		return safePersistenceError(storage.ErrPersistenceAcquire, operationCtx)
	}
	var expected any
	if commit.Expected != nil {
		expected = commit.Expected.String()
	}
	mutationResult, mutationErr := connection.ExecContext(operationCtx, credentialCommitSQL,
		commit.AccountID.String(), commit.Next.KeyID().String(), commit.Next.String(), commit.AccountID.String(), expected, commit.AccountID.String(), expected, expected, expected)
	mutationConfirmed := false
	if mutationErr == nil {
		rowsAffected, rowsAffectedErr := mutationResult.RowsAffected()
		mutationConfirmed = rowsAffectedErr == nil && rowsAffected == 1
	}
	verified, verificationErr := h.inspectCredential(operationCtx, commit.AccountID)
	success := verificationErr == nil && verified.credential != nil && verified.credential.Envelope == commit.Next && verified.credential.KeyID == commit.Next.KeyID()
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

func classifyCredentialCommit(commit storage.ProviderCredentialCommit, inspection credentialInspection) (error, bool) {
	if !inspection.accountExists {
		return storage.ErrAccountNotFound, true
	}
	if inspection.credential == nil {
		if commit.Expected != nil {
			return storage.ErrCredentialConflict, true
		}
		return nil, false
	}
	if inspection.credential.Envelope == commit.Next {
		return nil, true
	}
	if commit.Expected == nil || inspection.credential.Envelope != *commit.Expected {
		return storage.ErrCredentialConflict, true
	}
	return nil, false
}

func (h *handle) inspectCredential(ctx context.Context, accountID storage.AccountID) (credentialInspection, error) {
	connection, err := h.database.Conn(ctx)
	if err != nil {
		return credentialInspection{}, safePersistenceError(storage.ErrPersistenceAcquire, ctx)
	}
	defer connection.Close()
	rows, err := connection.QueryContext(ctx, credentialLookupSQL, accountID.String())
	if err != nil {
		return credentialInspection{}, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	defer rows.Close()
	count := 0
	var inspection credentialInspection
	for rows.Next() {
		count++
		if count > 1 {
			return credentialInspection{}, storage.ErrPersistenceInspect
		}
		var sentinelRaw, accountCountRaw, storedAccountID, credentialCountRaw, credentialAccountID, rawKeyID, rawEnvelope any
		if err := rows.Scan(&sentinelRaw, &accountCountRaw, &storedAccountID, &credentialCountRaw, &credentialAccountID, &rawKeyID, &rawEnvelope); err != nil {
			return credentialInspection{}, storage.ErrPersistenceInspect
		}
		sentinel, sentinelOK := exactInteger(sentinelRaw)
		accountCount, accountCountOK := exactInteger(accountCountRaw)
		credentialCount, credentialCountOK := exactInteger(credentialCountRaw)
		if !sentinelOK || sentinel != 1 || !accountCountOK || !credentialCountOK {
			return credentialInspection{}, storage.ErrPersistenceInspect
		}
		if accountCount == 0 {
			if storedAccountID != nil {
				return credentialInspection{}, storage.ErrPersistenceInspect
			}
		} else if id, ok := exactText(storedAccountID); accountCount == 1 && ok && id == accountID.String() {
			inspection.accountExists = true
		} else {
			return credentialInspection{}, storage.ErrPersistenceInspect
		}
		if credentialCount == 0 {
			if credentialAccountID != nil || rawKeyID != nil || rawEnvelope != nil {
				return credentialInspection{}, storage.ErrPersistenceInspect
			}
			continue
		}
		credentialID, credentialIDOK := exactText(credentialAccountID)
		keyText, keyOK := exactText(rawKeyID)
		envelopeText, envelopeOK := exactText(rawEnvelope)
		if credentialCount != 1 || !credentialIDOK || credentialID != accountID.String() || !keyOK || !envelopeOK {
			return credentialInspection{}, storage.ErrPersistenceInspect
		}
		keyID, err := storage.ParseCredentialKeyID(keyText)
		if err != nil {
			return credentialInspection{}, storage.ErrPersistenceInspect
		}
		envelope, err := storage.ParseCredentialEnvelope(envelopeText)
		if err != nil || envelope.KeyID() != keyID {
			return credentialInspection{}, storage.ErrPersistenceInspect
		}
		inspection.credential = &storage.ProviderCredential{AccountID: accountID, KeyID: keyID, Envelope: envelope}
	}
	if err := rows.Err(); err != nil {
		return credentialInspection{}, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	if count != 1 || (inspection.credential != nil && !inspection.accountExists) {
		return credentialInspection{}, storage.ErrPersistenceInspect
	}
	return inspection, nil
}
