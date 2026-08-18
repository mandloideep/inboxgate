package turso

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"

	"github.com/mandloideep/inboxgate/internal/storage"
)

const (
	accountLookupSQL = "WITH input(account_id, provider, provider_subject) AS (VALUES (?, ?, ?)), by_id AS (SELECT inboxgate_accounts.account_id, inboxgate_accounts.provider, inboxgate_accounts.provider_subject FROM inboxgate_accounts, input WHERE inboxgate_accounts.account_id = input.account_id), by_subject AS (SELECT inboxgate_accounts.account_id, inboxgate_accounts.provider, inboxgate_accounts.provider_subject FROM inboxgate_accounts, input WHERE inboxgate_accounts.provider = input.provider AND inboxgate_accounts.provider_subject = input.provider_subject) SELECT 1, (SELECT COUNT(*) FROM by_id), (SELECT account_id FROM by_id), (SELECT provider FROM by_id), (SELECT provider_subject FROM by_id), (SELECT COUNT(*) FROM by_subject), (SELECT account_id FROM by_subject), (SELECT provider FROM by_subject), (SELECT provider_subject FROM by_subject)"
	accountInsertSQL = "INSERT INTO inboxgate_accounts (account_id, provider, provider_subject) VALUES (?, 'gmail', ?) ON CONFLICT DO NOTHING"
	cursorLookupSQL  = "WITH input(account_id) AS (VALUES (?)), account_match AS (SELECT inboxgate_accounts.account_id FROM inboxgate_accounts, input WHERE inboxgate_accounts.account_id = input.account_id), cursor_match AS (SELECT inboxgate_synchronization_cursors.account_id, inboxgate_synchronization_cursors.history_id FROM inboxgate_synchronization_cursors, input WHERE inboxgate_synchronization_cursors.account_id = input.account_id) SELECT 1, (SELECT COUNT(*) FROM account_match), (SELECT account_id FROM account_match), (SELECT COUNT(*) FROM cursor_match), (SELECT account_id FROM cursor_match), (SELECT history_id FROM cursor_match)"
	cursorCommitSQL  = "INSERT INTO inboxgate_synchronization_cursors (account_id, history_id) SELECT ?, ? WHERE EXISTS (SELECT 1 FROM inboxgate_accounts WHERE account_id = ?) AND NOT EXISTS (SELECT 1 FROM inboxgate_synchronization_cursors WHERE account_id = ?) AND NOT EXISTS (SELECT 1 FROM inboxgate_current_sync_attempts WHERE account_id = ?) ON CONFLICT DO NOTHING"
)

func (h *handle) EnsureAccount(ctx context.Context, seed storage.AccountSeed) (storage.Account, error) {
	if !h.migrationAllowed {
		return storage.Account{}, storage.ErrPersistenceNotAllowed
	}
	if err := storage.ValidateAccountSeed(seed); err != nil {
		return storage.Account{}, err
	}
	operationCtx, cancel := context.WithTimeout(ctx, h.persistenceTimeout)
	defer cancel()

	initial, err := h.inspectAccount(operationCtx, seed)
	if err != nil {
		return storage.Account{}, err
	}
	if account, decided, err := resolveAccount(seed, initial); decided {
		return account, err
	}

	connection, err := h.database.Conn(operationCtx)
	if err != nil {
		return storage.Account{}, safePersistenceError(storage.ErrPersistenceAcquire, operationCtx)
	}
	_, mutationErr := connection.ExecContext(operationCtx, accountInsertSQL, seed.ID.String(), seed.ProviderSubject.String())
	verified, verificationErr := h.inspectAccount(operationCtx, seed)
	account, decided, resolutionErr := resolveAccount(seed, verified)
	if mutationErr != nil || verificationErr != nil || !decided {
		discardPersistenceConnection(connection)
	} else {
		_ = connection.Close()
	}
	if verificationErr != nil {
		return storage.Account{}, safePersistenceError(storage.ErrPersistenceUnknown, operationCtx)
	}
	if decided {
		return account, resolutionErr
	}
	return storage.Account{}, safePersistenceError(storage.ErrPersistenceUnknown, operationCtx)
}

type accountInspection struct {
	byID      *storage.Account
	bySubject *storage.Account
}

func (h *handle) inspectAccount(ctx context.Context, seed storage.AccountSeed) (accountInspection, error) {
	connection, err := h.database.Conn(ctx)
	if err != nil {
		return accountInspection{}, safePersistenceError(storage.ErrPersistenceAcquire, ctx)
	}
	defer connection.Close()
	rows, err := connection.QueryContext(ctx, accountLookupSQL, seed.ID.String(), storage.ProviderGmail, seed.ProviderSubject.String())
	if err != nil {
		return accountInspection{}, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	defer rows.Close()
	count := 0
	var inspection accountInspection
	for rows.Next() {
		count++
		if count > 1 {
			return accountInspection{}, storage.ErrPersistenceInspect
		}
		var sentinelRaw, idCountRaw, idID, idProvider, idSubject any
		var subjectCountRaw, subjectID, subjectProvider, subjectSubject any
		if err := rows.Scan(&sentinelRaw, &idCountRaw, &idID, &idProvider, &idSubject, &subjectCountRaw, &subjectID, &subjectProvider, &subjectSubject); err != nil {
			return accountInspection{}, storage.ErrPersistenceInspect
		}
		sentinel, ok := exactInteger(sentinelRaw)
		if !ok || sentinel != 1 {
			return accountInspection{}, storage.ErrPersistenceInspect
		}
		idCount, ok := exactInteger(idCountRaw)
		if !ok {
			return accountInspection{}, storage.ErrPersistenceInspect
		}
		subjectCount, ok := exactInteger(subjectCountRaw)
		if !ok {
			return accountInspection{}, storage.ErrPersistenceInspect
		}
		inspection.byID, err = decodeAccount(idCount, idID, idProvider, idSubject)
		if err != nil {
			return accountInspection{}, err
		}
		inspection.bySubject, err = decodeAccount(subjectCount, subjectID, subjectProvider, subjectSubject)
		if err != nil {
			return accountInspection{}, err
		}
		if inspection.byID != nil && inspection.byID.ID != seed.ID {
			return accountInspection{}, storage.ErrPersistenceInspect
		}
		if inspection.bySubject != nil && inspection.bySubject.ProviderSubject != seed.ProviderSubject {
			return accountInspection{}, storage.ErrPersistenceInspect
		}
	}
	if err := rows.Err(); err != nil {
		return accountInspection{}, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	if count != 1 {
		return accountInspection{}, storage.ErrPersistenceInspect
	}
	return inspection, nil
}

func decodeAccount(count int64, rawID, provider, subject any) (*storage.Account, error) {
	if count == 0 {
		if rawID != nil || provider != nil || subject != nil {
			return nil, storage.ErrPersistenceInspect
		}
		return nil, nil
	}
	idText, idOK := exactText(rawID)
	providerText, providerOK := exactText(provider)
	subjectText, subjectOK := exactText(subject)
	if count != 1 || !idOK || !providerOK || !subjectOK || providerText != storage.ProviderGmail {
		return nil, storage.ErrPersistenceInspect
	}
	id, err := storage.ParseAccountID(idText)
	if err != nil {
		return nil, storage.ErrPersistenceInspect
	}
	providerSubject, err := storage.ParseProviderSubject(subjectText)
	if err != nil {
		return nil, storage.ErrPersistenceInspect
	}
	return &storage.Account{ID: id, ProviderSubject: providerSubject}, nil
}

func resolveAccount(seed storage.AccountSeed, inspection accountInspection) (storage.Account, bool, error) {
	if inspection.bySubject != nil {
		if inspection.byID != nil && *inspection.byID != *inspection.bySubject {
			return storage.Account{}, true, storage.ErrAccountConflict
		}
		return *inspection.bySubject, true, nil
	}
	if inspection.byID != nil {
		return storage.Account{}, true, storage.ErrAccountConflict
	}
	return storage.Account{}, false, nil
}

func (h *handle) GetSynchronizationCursor(ctx context.Context, accountID storage.AccountID) (storage.SynchronizationCursor, error) {
	if !h.migrationAllowed {
		return storage.SynchronizationCursor{}, storage.ErrPersistenceNotAllowed
	}
	if parsed, err := storage.ParseAccountID(accountID.String()); err != nil || parsed != accountID {
		return storage.SynchronizationCursor{}, storage.ErrInvalidValue
	}
	operationCtx, cancel := context.WithTimeout(ctx, h.persistenceTimeout)
	defer cancel()
	inspection, err := h.inspectCursor(operationCtx, accountID)
	if err != nil {
		return storage.SynchronizationCursor{}, err
	}
	if !inspection.accountExists {
		return storage.SynchronizationCursor{}, storage.ErrAccountNotFound
	}
	if inspection.historyID == nil {
		return storage.SynchronizationCursor{}, storage.ErrCursorNotFound
	}
	return storage.SynchronizationCursor{AccountID: accountID, HistoryID: *inspection.historyID}, nil
}

type cursorInspection struct {
	accountExists bool
	historyID     *storage.HistoryID
}

func (h *handle) inspectCursor(ctx context.Context, accountID storage.AccountID) (cursorInspection, error) {
	connection, err := h.database.Conn(ctx)
	if err != nil {
		return cursorInspection{}, safePersistenceError(storage.ErrPersistenceAcquire, ctx)
	}
	defer connection.Close()
	rows, err := connection.QueryContext(ctx, cursorLookupSQL, accountID.String())
	if err != nil {
		return cursorInspection{}, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	defer rows.Close()
	count := 0
	var inspection cursorInspection
	for rows.Next() {
		count++
		if count > 1 {
			return cursorInspection{}, storage.ErrPersistenceInspect
		}
		var sentinelRaw, accountCountRaw, storedAccountID, cursorCountRaw, cursorAccountID, rawHistoryID any
		if err := rows.Scan(&sentinelRaw, &accountCountRaw, &storedAccountID, &cursorCountRaw, &cursorAccountID, &rawHistoryID); err != nil {
			return cursorInspection{}, storage.ErrPersistenceInspect
		}
		sentinel, sentinelOK := exactInteger(sentinelRaw)
		accountCount, accountCountOK := exactInteger(accountCountRaw)
		cursorCount, cursorCountOK := exactInteger(cursorCountRaw)
		if !sentinelOK || sentinel != 1 || !accountCountOK || !cursorCountOK {
			return cursorInspection{}, storage.ErrPersistenceInspect
		}
		if accountCount == 0 {
			if storedAccountID != nil {
				return cursorInspection{}, storage.ErrPersistenceInspect
			}
		} else if storedID, ok := exactText(storedAccountID); accountCount == 1 && ok && storedID == accountID.String() {
			inspection.accountExists = true
		} else {
			return cursorInspection{}, storage.ErrPersistenceInspect
		}
		if cursorCount == 0 {
			if cursorAccountID != nil || rawHistoryID != nil {
				return cursorInspection{}, storage.ErrPersistenceInspect
			}
		} else if cursorID, cursorIDOK := exactText(cursorAccountID); cursorCount == 1 && cursorIDOK && cursorID == accountID.String() {
			historyText, historyOK := exactText(rawHistoryID)
			if !historyOK {
				return cursorInspection{}, storage.ErrPersistenceInspect
			}
			historyID, err := storage.ParseHistoryID(historyText)
			if err != nil {
				return cursorInspection{}, storage.ErrPersistenceInspect
			}
			inspection.historyID = &historyID
		} else {
			return cursorInspection{}, storage.ErrPersistenceInspect
		}
	}
	if err := rows.Err(); err != nil {
		return cursorInspection{}, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	if count != 1 || (inspection.historyID != nil && !inspection.accountExists) {
		return cursorInspection{}, storage.ErrPersistenceInspect
	}
	return inspection, nil
}

func exactInteger(value any) (int64, bool) {
	integer, ok := value.(int64)
	return integer, ok
}

func exactText(value any) (string, bool) {
	text, ok := value.(string)
	return text, ok
}

func (h *handle) CommitSynchronization(ctx context.Context, commit storage.SynchronizationCommit) error {
	if !h.migrationAllowed {
		return storage.ErrPersistenceNotAllowed
	}
	if err := storage.ValidateSynchronizationCommit(commit); err != nil {
		return err
	}
	operationCtx, cancel := context.WithTimeout(ctx, h.persistenceTimeout)
	defer cancel()
	initial, err := h.inspectCursor(operationCtx, commit.AccountID)
	if err != nil {
		return err
	}
	if err, decided := classifyCursorCommit(commit, initial); decided {
		return err
	}

	connection, err := h.database.Conn(operationCtx)
	if err != nil {
		return safePersistenceError(storage.ErrPersistenceAcquire, operationCtx)
	}
	_, mutationErr := connection.ExecContext(operationCtx, cursorCommitSQL,
		commit.AccountID.String(), commit.Next.String(), commit.AccountID.String(), commit.AccountID.String(), commit.AccountID.String())
	verified, verificationErr := h.inspectCursor(operationCtx, commit.AccountID)
	success := verificationErr == nil && verified.historyID != nil && *verified.historyID == commit.Next
	if mutationErr != nil || !success {
		discardPersistenceConnection(connection)
	} else {
		_ = connection.Close()
	}
	if success {
		return nil
	}
	if inspection, inspectErr := h.inspectCurrentDiscovery(operationCtx, commit.AccountID); inspectErr == nil && inspection.attemptExists {
		return storage.ErrCursorConflict
	}
	return safePersistenceError(storage.ErrPersistenceUnknown, operationCtx)
}

func classifyCursorCommit(commit storage.SynchronizationCommit, inspection cursorInspection) (error, bool) {
	if !inspection.accountExists {
		return storage.ErrAccountNotFound, true
	}
	if inspection.historyID == nil {
		if commit.Expected != nil {
			return storage.ErrCursorConflict, true
		}
		return nil, false
	}
	return storage.ErrCursorConflict, true
}

func discardPersistenceConnection(connection *sql.Conn) {
	_ = connection.Raw(func(any) error { return driver.ErrBadConn })
	_ = connection.Close()
}

func safePersistenceError(category error, ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(category, err)
	}
	return category
}
