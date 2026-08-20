package turso

import (
	"context"
	"database/sql"
	"strings"

	"github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
)

const reviewCandidateSelectSQL = "SELECT messages.account_id, messages.gmail_message_id, messages.gmail_thread_id, messages.metadata_version, messages.metadata_json, messages.metadata_hash, decisions.gate_version, decisions.source_metadata_hash, decisions.input_hash, decisions.outcome, decisions.reason_codes, decisions.evaluated_at_unix_ms FROM inboxgate_accounts AS accounts JOIN inboxgate_account_lifecycle AS lifecycle ON lifecycle.account_id = accounts.account_id AND lifecycle.state = 'active' JOIN inboxgate_messages AS messages ON messages.account_id = accounts.account_id JOIN inboxgate_gate_decisions AS decisions ON decisions.record_id = messages.record_id AND decisions.source_metadata_hash = messages.metadata_hash WHERE (? = 0 OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ? OR messages.account_id = ?) AND decisions.outcome IN ('review_candidate', 'urgent_review_candidate') AND (? = 'all' OR (? = 'standard' AND decisions.outcome = 'review_candidate') OR (? = 'urgent' AND decisions.outcome = 'urgent_review_candidate')) AND (? = 0 OR (messages.account_id COLLATE BINARY, messages.gmail_thread_id COLLATE BINARY, messages.gmail_message_id COLLATE BINARY) > (?, ?, ?)) ORDER BY messages.account_id COLLATE BINARY, messages.gmail_thread_id COLLATE BINARY, messages.gmail_message_id COLLATE BINARY LIMIT ?"

const currentGateInspectionSelectSQL = "SELECT messages.account_id, messages.gmail_message_id, messages.gmail_thread_id, messages.metadata_version, messages.metadata_json, messages.metadata_hash, decisions.gate_version, decisions.source_metadata_hash, decisions.input_hash, decisions.outcome, decisions.reason_codes, decisions.evaluated_at_unix_ms FROM inboxgate_accounts AS accounts JOIN inboxgate_account_lifecycle AS lifecycle ON lifecycle.account_id = accounts.account_id AND lifecycle.state = 'active' JOIN inboxgate_messages AS messages ON messages.account_id = accounts.account_id AND messages.gmail_message_id = ? JOIN inboxgate_gate_decisions AS decisions ON decisions.record_id = messages.record_id AND decisions.source_metadata_hash = messages.metadata_hash WHERE accounts.account_id = ? LIMIT 2"

func (h *handle) ListReviewCandidates(ctx context.Context, query storage.ReviewCandidateQuery) ([]storage.ReviewCandidateRow, error) {
	if !h.migrationAllowed {
		return nil, storage.ErrPersistenceNotAllowed
	}
	if query.Limit() != storage.MaximumReviewSourceRows || query.RequestedPageSize() < 1 || query.RequestedPageSize() > 10 || !query.Urgency().Valid() || !query.After().Valid() {
		return nil, storage.ErrInvalidValue
	}
	operationCtx, cancel := context.WithTimeout(ctx, h.persistenceTimeout)
	defer cancel()
	connection, err := h.database.Conn(operationCtx)
	if err != nil {
		return nil, safePersistenceError(storage.ErrPersistenceAcquire, operationCtx)
	}
	defer connection.Close()
	arguments := make([]any, 0, 30)
	accounts := query.AccountIDs()
	arguments = append(arguments, int64(len(accounts)))
	for index := 0; index < storage.MaximumReviewAccountSelectors; index++ {
		value := ""
		if index < len(accounts) {
			value = accounts[index].String()
		}
		arguments = append(arguments, value)
	}
	arguments = append(arguments, string(query.Urgency()), string(query.Urgency()), string(query.Urgency()))
	after := query.After()
	afterPresent := int64(0)
	afterAccount, afterThread, afterMessage := "", "", ""
	if after.Present {
		afterPresent = 1
		afterAccount, afterThread, afterMessage = after.AccountID().String(), after.ThreadID(), after.MessageID()
	}
	arguments = append(arguments, afterPresent, afterAccount, afterThread, afterMessage, query.Limit())
	rows, err := connection.QueryContext(operationCtx, reviewCandidateSelectSQL, arguments...)
	if err != nil {
		return nil, safePersistenceError(storage.ErrPersistenceInspect, operationCtx)
	}
	defer rows.Close()
	result := make([]storage.ReviewCandidateRow, 0, query.Limit())
	accounts = query.AccountIDs()
	after = query.After()
	for rows.Next() {
		if len(result) == query.Limit() {
			return nil, storage.ErrResultTooLarge
		}
		message, decision, decodeErr := decodeReviewInspectionRow(rows)
		if decodeErr != nil {
			return nil, storage.ErrPersistenceInspect
		}
		rowAccount, parseErr := storage.ParseAccountID(message.AccountID())
		rowKey, keyErr := storage.NewReviewCursorKey(rowAccount, message.GmailThreadID(), message.GmailMessageID())
		if parseErr != nil || keyErr != nil || !reviewQuerySelectsAccount(accounts, rowAccount) || after.Present && compareReviewCursorKeys(after, rowKey) >= 0 {
			return nil, storage.ErrPersistenceInspect
		}
		row, decodeErr := storage.NewReviewCandidateRow(message, decision)
		if decodeErr != nil {
			return nil, storage.ErrPersistenceInspect
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, safePersistenceError(storage.ErrPersistenceInspect, operationCtx)
	}
	return result, nil
}

func (h *handle) GetCurrentGateInspection(ctx context.Context, accountID storage.AccountID, gmailMessageID string) (storage.CurrentGateInspection, error) {
	if !h.migrationAllowed {
		return storage.CurrentGateInspection{}, storage.ErrPersistenceNotAllowed
	}
	if parsed, err := storage.ParseAccountID(accountID.String()); err != nil || parsed != accountID || storage.ValidateGmailMessageID(gmailMessageID) != nil {
		return storage.CurrentGateInspection{}, storage.ErrInvalidValue
	}
	operationCtx, cancel := context.WithTimeout(ctx, h.persistenceTimeout)
	defer cancel()
	connection, err := h.database.Conn(operationCtx)
	if err != nil {
		return storage.CurrentGateInspection{}, safePersistenceError(storage.ErrPersistenceAcquire, operationCtx)
	}
	defer connection.Close()
	rows, err := connection.QueryContext(operationCtx, currentGateInspectionSelectSQL, gmailMessageID, accountID.String())
	if err != nil {
		return storage.CurrentGateInspection{}, safePersistenceError(storage.ErrPersistenceInspect, operationCtx)
	}
	defer rows.Close()
	count := 0
	var result storage.CurrentGateInspection
	for rows.Next() {
		count++
		if count > 1 {
			return storage.CurrentGateInspection{}, storage.ErrPersistenceInspect
		}
		message, decision, decodeErr := decodeReviewInspectionRow(rows)
		if decodeErr != nil {
			return storage.CurrentGateInspection{}, storage.ErrPersistenceInspect
		}
		if message.AccountID() != accountID.String() || message.GmailMessageID() != gmailMessageID {
			return storage.CurrentGateInspection{}, storage.ErrPersistenceInspect
		}
		result, decodeErr = storage.NewCurrentGateInspection(message, decision)
		if decodeErr != nil {
			return storage.CurrentGateInspection{}, storage.ErrPersistenceInspect
		}
	}
	if err := rows.Err(); err != nil {
		return storage.CurrentGateInspection{}, safePersistenceError(storage.ErrPersistenceInspect, operationCtx)
	}
	if count != 1 {
		return storage.CurrentGateInspection{}, storage.ErrReviewInspectionNotFound
	}
	return result, nil
}

type reviewRowScanner interface {
	Scan(...any) error
}

func decodeReviewInspectionRow(row reviewRowScanner) (mail.Message, storage.GateDecision, error) {
	var rawAccount, rawMessage, rawThread, rawMetadataVersion, rawMetadataJSON, rawMetadataHash any
	var rawGateVersion, rawSourceHash, rawInputHash, rawOutcome, rawReasons, rawEvaluated any
	if err := row.Scan(&rawAccount, &rawMessage, &rawThread, &rawMetadataVersion, &rawMetadataJSON, &rawMetadataHash, &rawGateVersion, &rawSourceHash, &rawInputHash, &rawOutcome, &rawReasons, &rawEvaluated); err != nil {
		return mail.Message{}, storage.GateDecision{}, err
	}
	account, accountOK := exactText(rawAccount)
	messageID, messageOK := exactText(rawMessage)
	threadID, threadOK := exactText(rawThread)
	metadataVersion, metadataVersionOK := exactInteger(rawMetadataVersion)
	metadataJSON, metadataJSONOK := exactText(rawMetadataJSON)
	metadataHash, metadataHashOK := exactText(rawMetadataHash)
	gateVersion, gateVersionOK := exactInteger(rawGateVersion)
	sourceHash, sourceHashOK := exactText(rawSourceHash)
	inputHash, inputHashOK := exactText(rawInputHash)
	outcome, outcomeOK := exactText(rawOutcome)
	reasons, reasonsOK := exactText(rawReasons)
	evaluated, evaluatedOK := exactInteger(rawEvaluated)
	if !accountOK || !messageOK || !threadOK || !metadataVersionOK || metadataVersion < 0 || metadataVersion > int64(^uint32(0)) || !metadataJSONOK || !metadataHashOK || !gateVersionOK || !sourceHashOK || !inputHashOK || !outcomeOK || !reasonsOK || !evaluatedOK {
		return mail.Message{}, storage.GateDecision{}, storage.ErrPersistenceInspect
	}
	message, err := mail.DecodeCanonical(account, messageID, threadID, uint32(metadataVersion), []byte(metadataJSON), metadataHash)
	if err != nil {
		return mail.Message{}, storage.GateDecision{}, storage.ErrPersistenceInspect
	}
	decision, err := storage.DecodeGateDecision(gateVersion, sourceHash, inputHash, outcome, reasons, evaluated)
	if err != nil {
		return mail.Message{}, storage.GateDecision{}, storage.ErrPersistenceInspect
	}
	return message, decision, nil
}

var _ reviewRowScanner = (*sql.Rows)(nil)

func reviewQuerySelectsAccount(accounts []storage.AccountID, account storage.AccountID) bool {
	if len(accounts) == 0 {
		return true
	}
	for _, selected := range accounts {
		if selected == account {
			return true
		}
	}
	return false
}

func compareReviewCursorKeys(left, right storage.ReviewCursorKey) int {
	if value := strings.Compare(left.AccountID().String(), right.AccountID().String()); value != 0 {
		return value
	}
	if value := strings.Compare(left.ThreadID(), right.ThreadID()); value != 0 {
		return value
	}
	return strings.Compare(left.MessageID(), right.MessageID())
}
