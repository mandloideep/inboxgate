package turso

import (
	"context"
	"database/sql"
	"errors"

	"github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
)

var errCurrentDiscoverySnapshotChanged = errors.New("current discovery snapshot changed")

const (
	currentDiscoveryAttemptCreateSQL    = "WITH input(account_id, attempt_id, expected_history_id, next_history_id, message_count, encoded_bytes, manifest_hash, manifest_witness) AS (VALUES (?, ?, ?, ?, ?, ?, ?, ?)) INSERT INTO inboxgate_current_sync_attempts (account_id, attempt_id, expected_history_id, next_history_id, message_count, encoded_bytes, manifest_hash, manifest_witness, state) SELECT input.account_id, input.attempt_id, input.expected_history_id, input.next_history_id, input.message_count, input.encoded_bytes, input.manifest_hash, input.manifest_witness, 'open' FROM input JOIN inboxgate_account_lifecycle AS lifecycle ON lifecycle.account_id = input.account_id AND lifecycle.state = 'active' JOIN inboxgate_synchronization_cursors AS cursors ON cursors.account_id = input.account_id AND cursors.history_id = input.expected_history_id ON CONFLICT DO NOTHING"
	currentDiscoveryAttemptLookupSQL    = "WITH input(account_id) AS (VALUES (?)) SELECT 1, (SELECT COUNT(*) FROM inboxgate_accounts AS accounts, input WHERE accounts.account_id = input.account_id), COUNT(attempts.account_id), MAX(attempts.account_id), MAX(attempts.attempt_id), MAX(attempts.expected_history_id), MAX(attempts.next_history_id), MAX(attempts.message_count), MAX(attempts.encoded_bytes), MAX(attempts.manifest_hash), MAX(attempts.manifest_witness), MAX(attempts.state) FROM input LEFT JOIN inboxgate_current_sync_attempts AS attempts ON attempts.account_id = input.account_id"
	currentDiscoveryStageLookupSQL      = "WITH input(account_id) AS (VALUES (?)) SELECT 1, attempts.attempt_id, staging.ordinal, staging.record_id, staging.gmail_message_id, staging.gmail_thread_id, staging.metadata_version, staging.metadata_json, staging.metadata_hash, staging.encoded_bytes, staging.row_witness FROM input LEFT JOIN inboxgate_current_sync_attempts AS attempts ON attempts.account_id = input.account_id LEFT JOIN inboxgate_current_sync_staging AS staging ON staging.account_id = attempts.account_id AND staging.attempt_id = attempts.attempt_id ORDER BY staging.ordinal LIMIT 5002"
	currentDiscoverySealSQL             = "UPDATE inboxgate_current_sync_attempts SET state = 'sealed' WHERE account_id = ? AND attempt_id = ? AND state = 'open' AND expected_history_id = ? AND next_history_id = ? AND message_count = ? AND encoded_bytes = ? AND manifest_hash = ? AND manifest_witness = ? AND (SELECT COUNT(*) FROM inboxgate_current_sync_staging WHERE account_id = ? AND attempt_id = ?) = message_count AND COALESCE((SELECT SUM(inboxgate_current_sync_staging.encoded_bytes) FROM inboxgate_current_sync_staging WHERE account_id = ? AND attempt_id = ?), 0) = encoded_bytes"
	currentDiscoveryFinalizeSQL         = "INSERT INTO inboxgate_current_sync_finalize (account_id, attempt_id, manifest_hash) VALUES (?, ?, ?)"
	currentDiscoveryAbortSQL            = "INSERT INTO inboxgate_current_sync_abort (account_id, attempt_id) VALUES (?, ?)"
	currentDiscoveryMessageLookupSQL    = "WITH input(account_id, gmail_message_id) AS (VALUES (?, ?)) SELECT 1, (SELECT COUNT(*) FROM inboxgate_accounts AS accounts, input WHERE accounts.account_id = input.account_id), COUNT(messages.record_id), MAX(messages.record_id), MAX(messages.account_id), MAX(messages.gmail_message_id), MAX(messages.gmail_thread_id), MAX(messages.metadata_version), MAX(messages.metadata_json), MAX(messages.metadata_hash) FROM input LEFT JOIN inboxgate_messages AS messages ON messages.account_id = input.account_id AND messages.gmail_message_id = input.gmail_message_id"
	currentDiscoveryRecordLookupSQL     = "WITH input(record_id) AS (VALUES (?)) SELECT 1, COUNT(messages.record_id), MAX(messages.account_id), MAX(messages.gmail_message_id) FROM input LEFT JOIN inboxgate_messages AS messages ON messages.record_id = input.record_id"
	currentDiscoveryNaturalKeyLookupSQL = "WITH input(account_id, gmail_message_id) AS (VALUES (?, ?)) SELECT 1, COUNT(messages.record_id), MAX(messages.record_id), MAX(messages.gmail_thread_id) FROM input LEFT JOIN inboxgate_messages AS messages ON messages.account_id = input.account_id AND messages.gmail_message_id = input.gmail_message_id"

	currentDiscoveryStageSlot           = "(?, ?, ?, ?, ?, ?, ?, ?)"
	currentDiscoveryStageSlots8         = currentDiscoveryStageSlot + "," + currentDiscoveryStageSlot + "," + currentDiscoveryStageSlot + "," + currentDiscoveryStageSlot + "," + currentDiscoveryStageSlot + "," + currentDiscoveryStageSlot + "," + currentDiscoveryStageSlot + "," + currentDiscoveryStageSlot
	currentDiscoveryStageSlots64        = currentDiscoveryStageSlots8 + "," + currentDiscoveryStageSlots8 + "," + currentDiscoveryStageSlots8 + "," + currentDiscoveryStageSlots8 + "," + currentDiscoveryStageSlots8 + "," + currentDiscoveryStageSlots8 + "," + currentDiscoveryStageSlots8 + "," + currentDiscoveryStageSlots8
	currentDiscoveryRowWitnessSQL       = "printf('%08x', length(CAST(staged.record_id AS BLOB))) || lower(hex(CAST(staged.record_id AS BLOB))) || printf('%08x', length(CAST(staged.gmail_message_id AS BLOB))) || lower(hex(CAST(staged.gmail_message_id AS BLOB))) || printf('%08x', length(CAST(staged.gmail_thread_id AS BLOB))) || lower(hex(CAST(staged.gmail_thread_id AS BLOB))) || printf('%08x', staged.metadata_version) || printf('%08x', length(CAST(staged.metadata_json AS BLOB))) || lower(hex(CAST(staged.metadata_json AS BLOB))) || printf('%08x', length(CAST(staged.metadata_hash AS BLOB))) || lower(hex(CAST(staged.metadata_hash AS BLOB)))"
	currentDiscoveryStoredRowWitnessSQL = "printf('%08x', length(CAST(staging.record_id AS BLOB))) || lower(hex(CAST(staging.record_id AS BLOB))) || printf('%08x', length(CAST(staging.gmail_message_id AS BLOB))) || lower(hex(CAST(staging.gmail_message_id AS BLOB))) || printf('%08x', length(CAST(staging.gmail_thread_id AS BLOB))) || lower(hex(CAST(staging.gmail_thread_id AS BLOB))) || printf('%08x', staging.metadata_version) || printf('%08x', length(CAST(staging.metadata_json AS BLOB))) || lower(hex(CAST(staging.metadata_json AS BLOB))) || printf('%08x', length(CAST(staging.metadata_hash AS BLOB))) || lower(hex(CAST(staging.metadata_hash AS BLOB)))"
	currentDiscoveryStageSQL            = "WITH input(account_id, attempt_id) AS (VALUES (?, ?)), staged(present, ordinal, record_id, gmail_message_id, gmail_thread_id, metadata_version, metadata_json, metadata_hash) AS (VALUES " + currentDiscoveryStageSlots64 + ") INSERT INTO inboxgate_current_sync_staging (account_id, attempt_id, ordinal, record_id, gmail_message_id, gmail_thread_id, metadata_version, metadata_json, metadata_hash, encoded_bytes, row_witness) SELECT input.account_id, input.attempt_id, staged.ordinal, staged.record_id, staged.gmail_message_id, staged.gmail_thread_id, staged.metadata_version, staged.metadata_json, staged.metadata_hash, 4 + length(CAST(staged.record_id AS BLOB)) + 4 + length(CAST(staged.gmail_message_id AS BLOB)) + 4 + length(CAST(staged.gmail_thread_id AS BLOB)) + 4 + 4 + length(CAST(staged.metadata_json AS BLOB)) + 4 + length(CAST(staged.metadata_hash AS BLOB)), " + currentDiscoveryRowWitnessSQL + " FROM input JOIN inboxgate_current_sync_attempts AS attempts ON attempts.account_id = input.account_id AND attempts.attempt_id = input.attempt_id CROSS JOIN staged WHERE staged.present = 1 AND typeof(staged.present) = 'integer' AND typeof(staged.ordinal) = 'integer' AND attempts.state = 'open' AND staged.ordinal BETWEEN 0 AND attempts.message_count - 1 ON CONFLICT (account_id, attempt_id, ordinal) DO NOTHING"
	currentDiscoveryStageProofSQL       = "WITH input(account_id, attempt_id) AS (VALUES (?, ?)), expected(present, ordinal, record_id, gmail_message_id, gmail_thread_id, metadata_version, metadata_json, metadata_hash) AS (VALUES " + currentDiscoveryStageSlots64 + ") SELECT 1, COALESCE(SUM(CASE WHEN expected.present = 1 THEN 1 ELSE 0 END), 0), COALESCE(SUM(CASE WHEN expected.present = 1 AND attempts.state = 'open' AND staging.ordinal = expected.ordinal AND staging.record_id = expected.record_id AND staging.gmail_message_id = expected.gmail_message_id AND staging.gmail_thread_id = expected.gmail_thread_id AND staging.metadata_version = expected.metadata_version AND staging.metadata_json = expected.metadata_json AND staging.metadata_hash = expected.metadata_hash AND staging.row_witness = " + currentDiscoveryStoredRowWitnessSQL + " THEN 1 ELSE 0 END), 0) FROM input CROSS JOIN expected LEFT JOIN inboxgate_current_sync_attempts AS attempts ON attempts.account_id = input.account_id AND attempts.attempt_id = input.attempt_id LEFT JOIN inboxgate_current_sync_staging AS staging ON staging.account_id = input.account_id AND staging.attempt_id = input.attempt_id AND staging.ordinal = expected.ordinal"
	currentDiscoveryProofSQL            = "WITH input(account_id, attempt_id) AS (VALUES (?, ?)), expected(present, ordinal, record_id, gmail_message_id, gmail_thread_id, metadata_version, metadata_json, metadata_hash) AS (VALUES " + currentDiscoveryStageSlots64 + ") SELECT 1, COALESCE(SUM(CASE WHEN expected.present = 1 THEN 1 ELSE 0 END), 0), COALESCE(SUM(CASE WHEN expected.present = 1 AND messages.record_id = expected.record_id AND messages.account_id = input.account_id AND messages.gmail_message_id = expected.gmail_message_id AND messages.gmail_thread_id = expected.gmail_thread_id AND messages.metadata_version = expected.metadata_version AND messages.metadata_json = expected.metadata_json AND messages.metadata_hash = expected.metadata_hash THEN 1 ELSE 0 END), 0) FROM input CROSS JOIN expected LEFT JOIN inboxgate_messages AS messages ON messages.account_id = input.account_id AND messages.gmail_message_id = expected.gmail_message_id"
)

type currentDiscoveryInspection struct {
	accountExists   bool
	attemptExists   bool
	accountID       storage.AccountID
	attemptID       string
	expected        storage.HistoryID
	next            storage.HistoryID
	messageCount    int
	encodedBytes    uint64
	manifestHash    string
	manifestWitness string
	state           string
	messages        []mail.Message
	rowWitnesses    []string
}

func (h *handle) CommitCurrentDiscovery(ctx context.Context, commit storage.CurrentDiscoveryCommit) error {
	if !h.migrationAllowed {
		return storage.ErrPersistenceNotAllowed
	}
	prepared, err := storage.PrepareCurrentDiscoveryCommit(commit)
	if err != nil {
		return err
	}
	operationCtx, cancel := context.WithTimeout(ctx, h.persistenceTimeout)
	defer cancel()
	if durable, proofErr := h.proveCurrentDiscovery(operationCtx, prepared); proofErr == nil && durable {
		return nil
	}
	inspection, err := h.inspectCurrentDiscovery(operationCtx, prepared.AccountID())
	if err != nil {
		return err
	}
	if inspection.attemptExists {
		if err := matchCurrentDiscoveryInspection(prepared, inspection, true); err != nil {
			return err
		}
		cursor, cursorErr := h.inspectCursor(operationCtx, prepared.AccountID())
		if cursorErr != nil || cursor.historyID == nil {
			return storage.ErrCurrentDiscoveryRecoveryRequired
		}
		if *cursor.historyID != prepared.Expected() {
			if durable, proofErr := h.proveCurrentDiscovery(operationCtx, prepared); proofErr == nil && durable {
				return nil
			}
			return storage.ErrCurrentDiscoveryRecoveryRequired
		}
	} else {
		if !inspection.accountExists {
			return storage.ErrAccountNotFound
		}
		cursor, cursorErr := h.inspectCursor(operationCtx, prepared.AccountID())
		lifecycle, lifecycleErr := h.inspectLifecycle(operationCtx, prepared.AccountID())
		if cursorErr != nil || lifecycleErr != nil {
			return storage.ErrPersistenceInspect
		}
		if cursor.historyID == nil {
			return storage.ErrCursorNotFound
		}
		if *cursor.historyID != prepared.Expected() {
			return storage.ErrCurrentDiscoveryConflict
		}
		if lifecycle.State != storage.AccountStateActive {
			return storage.ErrLifecycleConflict
		}
		args := []any{prepared.AccountID().String(), prepared.AttemptID(), prepared.Expected().String(), prepared.Next().String(), int64(prepared.MessageCount()), int64(prepared.EncodedBytes()), prepared.ManifestHash(), prepared.ManifestWitness()}
		if err := h.mutateCurrentDiscovery(operationCtx, currentDiscoveryAttemptCreateSQL, args, func() (bool, error) {
			visible, inspectErr := h.inspectCurrentDiscovery(operationCtx, prepared.AccountID())
			return inspectErr == nil && matchCurrentDiscoveryInspection(prepared, visible, false) == nil, inspectErr
		}); err != nil {
			if durable, proofErr := h.proveCurrentDiscovery(operationCtx, prepared); proofErr == nil && durable {
				return nil
			}
			visible, inspectErr := h.inspectCurrentDiscovery(operationCtx, prepared.AccountID())
			if inspectErr == nil && visible.attemptExists && visible.attemptID != prepared.AttemptID() {
				return storage.ErrCurrentDiscoveryConflict
			}
			if inspectErr == nil && !visible.attemptExists {
				if visibleLifecycle, lifecycleErr := h.inspectLifecycle(operationCtx, prepared.AccountID()); lifecycleErr == nil && visibleLifecycle.State != storage.AccountStateActive {
					return storage.ErrLifecycleConflict
				}
				if visibleCursor, cursorErr := h.inspectCursor(operationCtx, prepared.AccountID()); cursorErr == nil && (visibleCursor.historyID == nil || *visibleCursor.historyID != prepared.Expected()) {
					return storage.ErrCurrentDiscoveryConflict
				}
			}
			return err
		}
		inspection, err = h.inspectCurrentDiscovery(operationCtx, prepared.AccountID())
		if err != nil {
			return err
		}
	}
	if inspection.state == "sealed" {
		return h.finalizeCurrentDiscovery(operationCtx, prepared)
	}
	for chunk := 0; chunk < prepared.StageChunkCount(); chunk++ {
		end := (chunk + 1) * storage.CurrentDiscoveryStageChunkMessages
		if end > prepared.MessageCount() {
			end = prepared.MessageCount()
		}
		if len(inspection.messages) >= end {
			continue
		}
		if len(inspection.messages) != chunk*storage.CurrentDiscoveryStageChunkMessages {
			return storage.ErrCurrentDiscoveryRecoveryRequired
		}
		args := currentDiscoveryStageArguments(prepared, chunk)
		if len(args) != storage.CurrentDiscoveryStageParameters {
			return storage.ErrCurrentDiscoveryRecoveryRequired
		}
		if err := h.mutateCurrentDiscovery(operationCtx, currentDiscoveryStageSQL, args, func() (bool, error) {
			return h.inspectCurrentDiscoveryStageChunk(operationCtx, prepared, chunk)
		}); err != nil {
			if errors.Is(err, storage.ErrPersistenceInspect) || errors.Is(err, storage.ErrPersistenceAcquire) {
				return err
			}
			recovered := false
			for range 3 {
				if durable, proofErr := h.proveCurrentDiscovery(operationCtx, prepared); proofErr == nil && durable {
					return nil
				}
				visible, inspectErr := h.inspectCurrentDiscovery(operationCtx, prepared.AccountID())
				if inspectErr != nil {
					continue
				}
				if visible.state == "sealed" && matchCurrentDiscoveryInspection(prepared, visible, true) == nil {
					return h.finalizeCurrentDiscovery(operationCtx, prepared)
				}
				if visible.state == "open" && matchCurrentDiscoveryInspection(prepared, visible, true) == nil && len(visible.messages) >= end {
					inspection = visible
					recovered = true
					break
				}
			}
			if !recovered {
				return err
			}
		}
		inspection.messages = prepared.Messages()[:end]
	}
	sealArgs := []any{prepared.AccountID().String(), prepared.AttemptID(), prepared.Expected().String(), prepared.Next().String(), int64(prepared.MessageCount()), int64(prepared.EncodedBytes()), prepared.ManifestHash(), prepared.ManifestWitness(), prepared.AccountID().String(), prepared.AttemptID(), prepared.AccountID().String(), prepared.AttemptID()}
	if err := h.mutateCurrentDiscovery(operationCtx, currentDiscoverySealSQL, sealArgs, func() (bool, error) {
		visible, inspectErr := h.inspectCurrentDiscovery(operationCtx, prepared.AccountID())
		return inspectErr == nil && visible.state == "sealed" && matchCurrentDiscoveryInspection(prepared, visible, true) == nil, inspectErr
	}); err != nil {
		if durable, proofErr := h.proveCurrentDiscovery(operationCtx, prepared); proofErr == nil && durable {
			return nil
		}
		return err
	}
	return h.finalizeCurrentDiscovery(operationCtx, prepared)
}

func (h *handle) ReconcileCurrentDiscovery(ctx context.Context, accountID storage.AccountID) error {
	if !h.migrationAllowed {
		return storage.ErrPersistenceNotAllowed
	}
	if parsed, err := storage.ParseAccountID(accountID.String()); err != nil || parsed != accountID {
		return storage.ErrInvalidValue
	}
	operationCtx, cancel := context.WithTimeout(ctx, h.persistenceTimeout)
	defer cancel()
	inspection, err := h.inspectCurrentDiscovery(operationCtx, accountID)
	if err != nil {
		return err
	}
	if !inspection.attemptExists {
		return nil
	}
	cursor, err := h.inspectCursor(operationCtx, accountID)
	if err != nil || cursor.historyID == nil {
		return storage.ErrCurrentDiscoveryRecoveryRequired
	}
	if inspection.state == "open" {
		if *cursor.historyID != inspection.expected || len(inspection.messages) > inspection.messageCount {
			return storage.ErrCurrentDiscoveryRecoveryRequired
		}
		lifecycle, lifecycleErr := h.inspectLifecycle(operationCtx, accountID)
		if lifecycleErr != nil {
			return storage.ErrPersistenceInspect
		}
		if lifecycle.State != storage.AccountStateActive {
			return storage.ErrLifecycleConflict
		}
		var stagedBytes uint64
		for _, message := range inspection.messages {
			stagedBytes += uint64(currentDiscoveryEncodedSize(message))
		}
		if stagedBytes > inspection.encodedBytes {
			return storage.ErrCurrentDiscoveryRecoveryRequired
		}
		args := []any{accountID.String(), inspection.attemptID}
		mutationErr := h.mutateCurrentDiscovery(operationCtx, currentDiscoveryAbortSQL, args, func() (bool, error) {
			visible, inspectErr := h.inspectCurrentDiscovery(operationCtx, accountID)
			return inspectErr == nil && !visible.attemptExists, inspectErr
		})
		if mutationErr == nil {
			return nil
		}
		if visibleLifecycle, inspectErr := h.inspectLifecycle(operationCtx, accountID); inspectErr == nil && visibleLifecycle.State != storage.AccountStateActive {
			return storage.ErrLifecycleConflict
		}
		return mutationErr
	}
	if inspection.state != "sealed" {
		return storage.ErrCurrentDiscoveryRecoveryRequired
	}
	prepared, err := storage.PrepareCurrentDiscoveryCommit(storage.CurrentDiscoveryCommit{AccountID: accountID, Expected: inspection.expected, Next: inspection.next, Messages: inspection.messages})
	if err != nil || matchCurrentDiscoveryInspection(prepared, inspection, true) != nil {
		return storage.ErrCurrentDiscoveryRecoveryRequired
	}
	if *cursor.historyID != prepared.Expected() {
		durable, proofErr := h.proveCurrentDiscovery(operationCtx, prepared)
		if proofErr != nil {
			return proofErr
		}
		if durable {
			return nil
		}
		return storage.ErrCurrentDiscoveryRecoveryRequired
	}
	return h.finalizeCurrentDiscovery(operationCtx, prepared)
}

func (h *handle) GetDiscoveredMessage(ctx context.Context, accountID storage.AccountID, gmailMessageID string) (mail.Message, error) {
	if !h.migrationAllowed {
		return mail.Message{}, storage.ErrPersistenceNotAllowed
	}
	if parsed, err := storage.ParseAccountID(accountID.String()); err != nil || parsed != accountID || storage.ValidateGmailMessageID(gmailMessageID) != nil {
		return mail.Message{}, storage.ErrInvalidValue
	}
	operationCtx, cancel := context.WithTimeout(ctx, h.persistenceTimeout)
	defer cancel()
	return h.inspectDiscoveredMessage(operationCtx, accountID, gmailMessageID)
}

func (h *handle) finalizeCurrentDiscovery(ctx context.Context, prepared storage.PreparedCurrentDiscovery) error {
	inspection, err := h.inspectCurrentDiscovery(ctx, prepared.AccountID())
	if err != nil {
		return err
	}
	if !inspection.attemptExists {
		if durable, proofErr := h.proveCurrentDiscovery(ctx, prepared); proofErr == nil && durable {
			return nil
		}
		return storage.ErrCurrentDiscoveryRecoveryRequired
	}
	if inspection.state != "sealed" || matchCurrentDiscoveryInspection(prepared, inspection, true) != nil {
		return storage.ErrCurrentDiscoveryRecoveryRequired
	}
	lifecycle, err := h.inspectLifecycle(ctx, prepared.AccountID())
	if err != nil {
		return err
	}
	if lifecycle.State != storage.AccountStateActive {
		return storage.ErrLifecycleConflict
	}
	args := []any{prepared.AccountID().String(), prepared.AttemptID(), prepared.ManifestHash()}
	err = h.mutateCurrentDiscovery(ctx, currentDiscoveryFinalizeSQL, args, func() (bool, error) {
		return h.proveCurrentDiscovery(ctx, prepared)
	})
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return err
	}
	if conflictErr := h.classifyCurrentDiscoveryConflict(ctx, prepared); conflictErr != nil {
		return conflictErr
	}
	visible, inspectErr := h.inspectCurrentDiscovery(ctx, prepared.AccountID())
	if inspectErr != nil {
		return storage.ErrCurrentDiscoveryRecoveryRequired
	}
	if inspectErr == nil {
		lifecycle, lifecycleErr := h.inspectLifecycle(ctx, prepared.AccountID())
		if lifecycleErr == nil && lifecycle.State != storage.AccountStateActive {
			return storage.ErrLifecycleConflict
		}
		if visible.attemptExists && visible.state == "sealed" {
			if matchCurrentDiscoveryInspection(prepared, visible, true) != nil {
				return storage.ErrCurrentDiscoveryRecoveryRequired
			}
			cursor, cursorErr := h.inspectCursor(ctx, prepared.AccountID())
			if cursorErr == nil && (cursor.historyID == nil || *cursor.historyID != prepared.Expected()) {
				return storage.ErrCurrentDiscoveryRecoveryRequired
			}
			return err
		}
	}
	return err
}

func (h *handle) classifyCurrentDiscoveryConflict(ctx context.Context, prepared storage.PreparedCurrentDiscovery) error {
	for _, expected := range prepared.Messages() {
		ownerAccount, ownerMessage, exists, err := h.inspectDiscoveredRecordKey(ctx, expected.RecordID())
		if err != nil {
			return err
		}
		if exists && (ownerAccount != expected.AccountID() || ownerMessage != expected.GmailMessageID()) {
			return storage.ErrMessageIdentityCollision
		}
		recordID, threadID, exists, err := h.inspectDiscoveredNaturalKey(ctx, prepared.AccountID(), expected.GmailMessageID())
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		if recordID != expected.RecordID() {
			return storage.ErrCurrentDiscoveryRecoveryRequired
		}
		if threadID != expected.GmailThreadID() {
			return storage.ErrCurrentDiscoveryConflict
		}
	}
	return nil
}

func (h *handle) inspectDiscoveredNaturalKey(ctx context.Context, accountID storage.AccountID, gmailMessageID string) (string, string, bool, error) {
	connection, err := h.database.Conn(ctx)
	if err != nil {
		return "", "", false, safePersistenceError(storage.ErrPersistenceAcquire, ctx)
	}
	defer connection.Close()
	rows, err := connection.QueryContext(ctx, currentDiscoveryNaturalKeyLookupSQL, accountID.String(), gmailMessageID)
	if err != nil {
		return "", "", false, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	defer rows.Close()
	count := 0
	var recordID, threadID string
	exists := false
	for rows.Next() {
		count++
		var rawSentinel, rawCount, rawRecordID, rawThreadID any
		if err := rows.Scan(&rawSentinel, &rawCount, &rawRecordID, &rawThreadID); err != nil {
			return "", "", false, storage.ErrPersistenceInspect
		}
		sentinel, sentinelOK := exactInteger(rawSentinel)
		rowCount, rowCountOK := exactInteger(rawCount)
		if !sentinelOK || sentinel != 1 || !rowCountOK || rowCount < 0 || rowCount > 1 {
			return "", "", false, storage.ErrPersistenceInspect
		}
		if rowCount == 0 {
			if rawRecordID != nil || rawThreadID != nil {
				return "", "", false, storage.ErrPersistenceInspect
			}
			continue
		}
		var recordOK, threadOK bool
		recordID, recordOK = exactText(rawRecordID)
		threadID, threadOK = exactText(rawThreadID)
		if !recordOK || !threadOK || !validLowerHexText(recordID) || storage.ValidateGmailMessageID(threadID) != nil {
			return "", "", false, storage.ErrPersistenceInspect
		}
		exists = true
	}
	if err := rows.Err(); err != nil || count != 1 {
		return "", "", false, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	return recordID, threadID, exists, nil
}

func (h *handle) inspectDiscoveredRecordKey(ctx context.Context, recordID string) (string, string, bool, error) {
	connection, err := h.database.Conn(ctx)
	if err != nil {
		return "", "", false, safePersistenceError(storage.ErrPersistenceAcquire, ctx)
	}
	defer connection.Close()
	rows, err := connection.QueryContext(ctx, currentDiscoveryRecordLookupSQL, recordID)
	if err != nil {
		return "", "", false, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	defer rows.Close()
	count := 0
	var accountID, messageID string
	exists := false
	for rows.Next() {
		count++
		var rawSentinel, rawCount, rawAccountID, rawMessageID any
		if err := rows.Scan(&rawSentinel, &rawCount, &rawAccountID, &rawMessageID); err != nil {
			return "", "", false, storage.ErrPersistenceInspect
		}
		sentinel, sentinelOK := exactInteger(rawSentinel)
		rowCount, rowCountOK := exactInteger(rawCount)
		if !sentinelOK || sentinel != 1 || !rowCountOK || rowCount < 0 || rowCount > 1 {
			return "", "", false, storage.ErrPersistenceInspect
		}
		if rowCount == 0 {
			if rawAccountID != nil || rawMessageID != nil {
				return "", "", false, storage.ErrPersistenceInspect
			}
			continue
		}
		accountID, sentinelOK = exactText(rawAccountID)
		messageID, rowCountOK = exactText(rawMessageID)
		if !sentinelOK || !rowCountOK {
			return "", "", false, storage.ErrPersistenceInspect
		}
		if _, err := storage.ParseAccountID(accountID); err != nil || storage.ValidateGmailMessageID(messageID) != nil {
			return "", "", false, storage.ErrPersistenceInspect
		}
		exists = true
	}
	if err := rows.Err(); err != nil || count != 1 {
		return "", "", false, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	return accountID, messageID, exists, nil
}

func (h *handle) mutateCurrentDiscovery(ctx context.Context, statement string, args []any, verify func() (bool, error)) error {
	connection, err := h.database.Conn(ctx)
	if err != nil {
		return safePersistenceError(storage.ErrPersistenceAcquire, ctx)
	}
	result, mutationErr := connection.ExecContext(ctx, statement, args...)
	acknowledged := mutationErr == nil && currentDiscoveryAcknowledged(statement, result)
	verified, verificationErr := verify()
	if !acknowledged || verificationErr != nil || !verified {
		discardPersistenceConnection(connection)
	} else {
		_ = connection.Close()
	}
	if verified && verificationErr == nil {
		return nil
	}
	if verificationErr != nil {
		return errors.Join(safePersistenceError(storage.ErrPersistenceUnknown, ctx), verificationErr)
	}
	return safePersistenceError(storage.ErrPersistenceUnknown, ctx)
}

func currentDiscoveryAcknowledged(statement string, result sql.Result) bool {
	if result == nil {
		return false
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false
	}
	if statement == currentDiscoveryStageSQL {
		return affected >= 1 && affected <= storage.CurrentDiscoveryStageChunkMessages
	}
	return affected == 1
}

func currentDiscoveryStageArguments(prepared storage.PreparedCurrentDiscovery, chunk int) []any {
	arguments := make([]any, 0, storage.CurrentDiscoveryStageParameters)
	arguments = append(arguments, prepared.AccountID().String(), prepared.AttemptID())
	messages := prepared.Messages()
	start := chunk * storage.CurrentDiscoveryStageChunkMessages
	for slot := 0; slot < storage.CurrentDiscoveryStageChunkMessages; slot++ {
		index := start + slot
		if index >= len(messages) {
			arguments = append(arguments, int64(0), int64(0), nil, nil, nil, nil, nil, nil)
			continue
		}
		message := messages[index]
		arguments = append(arguments, int64(1), int64(index), message.RecordID(), message.GmailMessageID(), message.GmailThreadID(), int64(message.MetadataVersion()), string(message.CanonicalJSON()), message.MetadataHash())
	}
	return arguments
}

func matchCurrentDiscoveryInspection(prepared storage.PreparedCurrentDiscovery, inspection currentDiscoveryInspection, requireStaging bool) error {
	if !inspection.attemptExists || inspection.accountID != prepared.AccountID() || inspection.attemptID != prepared.AttemptID() || inspection.expected != prepared.Expected() || inspection.next != prepared.Next() || inspection.messageCount != prepared.MessageCount() || inspection.encodedBytes != prepared.EncodedBytes() || inspection.manifestHash != prepared.ManifestHash() || inspection.manifestWitness != prepared.ManifestWitness() || (inspection.state != "open" && inspection.state != "sealed") {
		return storage.ErrCurrentDiscoveryConflict
	}
	if len(inspection.messages) > prepared.MessageCount() {
		return storage.ErrCurrentDiscoveryRecoveryRequired
	}
	expected := prepared.Messages()
	for index, message := range inspection.messages {
		if !message.Equal(expected[index]) || index >= len(inspection.rowWitnesses) || inspection.rowWitnesses[index] != prepared.RowWitness(index) {
			return storage.ErrCurrentDiscoveryRecoveryRequired
		}
	}
	if requireStaging && inspection.state == "sealed" && len(inspection.messages) != prepared.MessageCount() {
		return storage.ErrCurrentDiscoveryRecoveryRequired
	}
	return nil
}

func (h *handle) proveCurrentDiscovery(ctx context.Context, prepared storage.PreparedCurrentDiscovery) (bool, error) {
	cursor, err := h.inspectCursor(ctx, prepared.AccountID())
	if err != nil {
		return false, err
	}
	if cursor.historyID == nil || *cursor.historyID != prepared.Next() {
		return false, nil
	}
	for chunk := 0; chunk < prepared.StageChunkCount(); chunk++ {
		matched, inspectErr := h.inspectCurrentDiscoveryProofChunk(ctx, prepared, chunk)
		if inspectErr != nil {
			return false, inspectErr
		}
		if !matched {
			return false, nil
		}
	}
	inspection, err := h.inspectCurrentDiscovery(ctx, prepared.AccountID())
	return err == nil && !inspection.attemptExists, err
}

func (h *handle) inspectCurrentDiscoveryProofChunk(ctx context.Context, prepared storage.PreparedCurrentDiscovery, chunk int) (bool, error) {
	return h.inspectCurrentDiscoveryChunkMatch(ctx, currentDiscoveryProofSQL, prepared, chunk)
}

func (h *handle) inspectCurrentDiscoveryStageChunk(ctx context.Context, prepared storage.PreparedCurrentDiscovery, chunk int) (bool, error) {
	return h.inspectCurrentDiscoveryChunkMatch(ctx, currentDiscoveryStageProofSQL, prepared, chunk)
}

func (h *handle) inspectCurrentDiscoveryChunkMatch(ctx context.Context, statement string, prepared storage.PreparedCurrentDiscovery, chunk int) (bool, error) {
	connection, err := h.database.Conn(ctx)
	if err != nil {
		return false, safePersistenceError(storage.ErrPersistenceAcquire, ctx)
	}
	defer connection.Close()
	rows, err := connection.QueryContext(ctx, statement, currentDiscoveryStageArguments(prepared, chunk)...)
	if err != nil {
		return false, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	defer rows.Close()
	count := 0
	matched := false
	for rows.Next() {
		count++
		var rawSentinel, rawExpected, rawMatched any
		if err := rows.Scan(&rawSentinel, &rawExpected, &rawMatched); err != nil {
			return false, storage.ErrPersistenceInspect
		}
		sentinel, sentinelOK := exactInteger(rawSentinel)
		expected, expectedOK := exactInteger(rawExpected)
		matches, matchesOK := exactInteger(rawMatched)
		start := chunk * storage.CurrentDiscoveryStageChunkMessages
		want := prepared.MessageCount() - start
		if want > storage.CurrentDiscoveryStageChunkMessages {
			want = storage.CurrentDiscoveryStageChunkMessages
		}
		if !sentinelOK || sentinel != 1 || !expectedOK || !matchesOK || expected != int64(want) || matches < 0 || matches > expected {
			return false, storage.ErrPersistenceInspect
		}
		matched = matches == expected
	}
	if err := rows.Err(); err != nil || count != 1 {
		return false, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	return matched, nil
}

func (h *handle) inspectCurrentDiscovery(ctx context.Context, accountID storage.AccountID) (currentDiscoveryInspection, error) {
	for range 3 {
		inspection, err := h.inspectCurrentDiscoveryOnce(ctx, accountID)
		if !errors.Is(err, errCurrentDiscoverySnapshotChanged) {
			return inspection, err
		}
	}
	return currentDiscoveryInspection{}, storage.ErrCurrentDiscoveryRecoveryRequired
}

func (h *handle) inspectCurrentDiscoveryOnce(ctx context.Context, accountID storage.AccountID) (currentDiscoveryInspection, error) {
	connection, err := h.database.Conn(ctx)
	if err != nil {
		return currentDiscoveryInspection{}, safePersistenceError(storage.ErrPersistenceAcquire, ctx)
	}
	defer connection.Close()
	rows, err := connection.QueryContext(ctx, currentDiscoveryAttemptLookupSQL, accountID.String())
	if err != nil {
		return currentDiscoveryInspection{}, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	defer rows.Close()
	var inspection currentDiscoveryInspection
	count := 0
	for rows.Next() {
		count++
		var rawSentinel, rawAccountCount, rawAttemptCount, rawAccountID, rawAttemptID, rawExpected, rawNext, rawMessageCount, rawEncodedBytes, rawManifestHash, rawManifestWitness, rawState any
		if err := rows.Scan(&rawSentinel, &rawAccountCount, &rawAttemptCount, &rawAccountID, &rawAttemptID, &rawExpected, &rawNext, &rawMessageCount, &rawEncodedBytes, &rawManifestHash, &rawManifestWitness, &rawState); err != nil {
			return currentDiscoveryInspection{}, storage.ErrPersistenceInspect
		}
		sentinel, sentinelOK := exactInteger(rawSentinel)
		accountCount, accountOK := exactInteger(rawAccountCount)
		attemptCount, attemptOK := exactInteger(rawAttemptCount)
		if !sentinelOK || sentinel != 1 || !accountOK || accountCount < 0 || accountCount > 1 || !attemptOK || attemptCount < 0 || attemptCount > 1 || attemptCount > accountCount {
			return currentDiscoveryInspection{}, storage.ErrPersistenceInspect
		}
		inspection.accountExists = accountCount == 1
		if attemptCount == 0 {
			if rawAccountID != nil || rawAttemptID != nil || rawExpected != nil || rawNext != nil || rawMessageCount != nil || rawEncodedBytes != nil || rawManifestHash != nil || rawManifestWitness != nil || rawState != nil {
				return currentDiscoveryInspection{}, storage.ErrPersistenceInspect
			}
			continue
		}
		accountText, accountTextOK := exactText(rawAccountID)
		attemptText, attemptTextOK := exactText(rawAttemptID)
		expectedText, expectedOK := exactText(rawExpected)
		nextText, nextOK := exactText(rawNext)
		messageCount, messageCountOK := exactInteger(rawMessageCount)
		encodedBytes, encodedBytesOK := exactInteger(rawEncodedBytes)
		manifestHash, manifestOK := exactText(rawManifestHash)
		manifestWitness, witnessOK := exactText(rawManifestWitness)
		state, stateOK := exactText(rawState)
		parsedAccount, accountErr := storage.ParseAccountID(accountText)
		parsedExpected, expectedErr := storage.ParseHistoryID(expectedText)
		parsedNext, nextErr := storage.ParseHistoryID(nextText)
		if !accountTextOK || !attemptTextOK || !expectedOK || !nextOK || !messageCountOK || !encodedBytesOK || !manifestOK || !witnessOK || !stateOK || accountErr != nil || expectedErr != nil || nextErr != nil || parsedAccount != accountID || !validLowerHexText(attemptText) || !validLowerHexText(manifestHash) || !validBoundedLowerHexText(manifestWitness, 78, storage.MaximumCurrentDiscoveryManifestWitnessBytes) || len(manifestWitness) != 78+2*int(encodedBytes) || messageCount < 0 || messageCount > storage.MaximumCurrentDiscoveryMessages || encodedBytes < 0 || encodedBytes > storage.MaximumCurrentDiscoveryEncodedBytes || parsedNext.Compare(parsedExpected) <= 0 || (state != "open" && state != "sealed") {
			return currentDiscoveryInspection{}, storage.ErrPersistenceInspect
		}
		inspection.attemptExists = true
		inspection.accountID = parsedAccount
		inspection.attemptID = attemptText
		inspection.expected = parsedExpected
		inspection.next = parsedNext
		inspection.messageCount = int(messageCount)
		inspection.encodedBytes = uint64(encodedBytes)
		inspection.manifestHash = manifestHash
		inspection.manifestWitness = manifestWitness
		inspection.state = state
	}
	if err := rows.Err(); err != nil || count != 1 {
		return currentDiscoveryInspection{}, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	if !inspection.attemptExists {
		return inspection, nil
	}
	stageRows, err := connection.QueryContext(ctx, currentDiscoveryStageLookupSQL, accountID.String())
	if err != nil {
		return currentDiscoveryInspection{}, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	defer stageRows.Close()
	rowCount := 0
	var encodedTotal uint64
	for stageRows.Next() {
		rowCount++
		if rowCount > storage.MaximumCurrentDiscoveryMessages {
			return currentDiscoveryInspection{}, storage.ErrResultTooLarge
		}
		var rawSentinel, rawAttemptID, rawOrdinal, rawRecordID, rawMessageID, rawThreadID, rawVersion, rawJSON, rawHash, rawEncodedBytes, rawRowWitness any
		if err := stageRows.Scan(&rawSentinel, &rawAttemptID, &rawOrdinal, &rawRecordID, &rawMessageID, &rawThreadID, &rawVersion, &rawJSON, &rawHash, &rawEncodedBytes, &rawRowWitness); err != nil {
			return currentDiscoveryInspection{}, storage.ErrPersistenceInspect
		}
		sentinel, sentinelOK := exactInteger(rawSentinel)
		attemptText, attemptOK := exactText(rawAttemptID)
		if sentinelOK && sentinel == 1 && rawAttemptID == nil && rawOrdinal == nil && rawRecordID == nil && rawMessageID == nil && rawThreadID == nil && rawVersion == nil && rawJSON == nil && rawHash == nil && rawEncodedBytes == nil && rawRowWitness == nil && rowCount == 1 {
			return currentDiscoveryInspection{}, errCurrentDiscoverySnapshotChanged
		}
		if !sentinelOK || sentinel != 1 || !attemptOK || attemptText != inspection.attemptID {
			return currentDiscoveryInspection{}, storage.ErrPersistenceInspect
		}
		if rawOrdinal == nil {
			if rawRecordID != nil || rawMessageID != nil || rawThreadID != nil || rawVersion != nil || rawJSON != nil || rawHash != nil || rawEncodedBytes != nil || rawRowWitness != nil || rowCount != 1 {
				return currentDiscoveryInspection{}, storage.ErrPersistenceInspect
			}
			continue
		}
		ordinal, ordinalOK := exactInteger(rawOrdinal)
		recordID, recordOK := exactText(rawRecordID)
		messageID, messageOK := exactText(rawMessageID)
		threadID, threadOK := exactText(rawThreadID)
		version, versionOK := exactInteger(rawVersion)
		metadataJSON, jsonOK := exactText(rawJSON)
		metadataHash, hashOK := exactText(rawHash)
		encodedBytes, encodedOK := exactInteger(rawEncodedBytes)
		rowWitness, rowWitnessOK := exactText(rawRowWitness)
		if !ordinalOK || ordinal != int64(len(inspection.messages)) || ordinal < 0 || ordinal >= storage.MaximumCurrentDiscoveryMessages || !recordOK || !messageOK || !threadOK || !versionOK || version != int64(mail.MetadataVersion1) || !jsonOK || !hashOK || !encodedOK || !rowWitnessOK || !validBoundedLowerHexText(rowWitness, 2, 2*storage.MaximumCurrentDiscoveryEncodedBytes) || encodedBytes <= 0 || len(rowWitness) != 2*int(encodedBytes) {
			return currentDiscoveryInspection{}, storage.ErrPersistenceInspect
		}
		message, decodeErr := mail.DecodeCanonical(accountID.String(), messageID, threadID, uint32(version), []byte(metadataJSON), metadataHash)
		if decodeErr != nil || message.RecordID() != recordID || uint32(encodedBytes) != currentDiscoveryEncodedSize(message) {
			return currentDiscoveryInspection{}, storage.ErrPersistenceInspect
		}
		encodedTotal += uint64(encodedBytes)
		if encodedTotal > storage.MaximumCurrentDiscoveryEncodedBytes {
			return currentDiscoveryInspection{}, storage.ErrResultTooLarge
		}
		inspection.messages = append(inspection.messages, message)
		inspection.rowWitnesses = append(inspection.rowWitnesses, rowWitness)
	}
	if err := stageRows.Err(); err != nil || rowCount == 0 {
		return currentDiscoveryInspection{}, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	return inspection, nil
}

func (h *handle) inspectDiscoveredMessage(ctx context.Context, accountID storage.AccountID, gmailMessageID string) (mail.Message, error) {
	connection, err := h.database.Conn(ctx)
	if err != nil {
		return mail.Message{}, safePersistenceError(storage.ErrPersistenceAcquire, ctx)
	}
	defer connection.Close()
	rows, err := connection.QueryContext(ctx, currentDiscoveryMessageLookupSQL, accountID.String(), gmailMessageID)
	if err != nil {
		return mail.Message{}, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	defer rows.Close()
	count := 0
	var result mail.Message
	accountExists := false
	messageExists := false
	for rows.Next() {
		count++
		var rawSentinel, rawAccountCount, rawMessageCount, rawRecordID, rawAccountID, rawMessageID, rawThreadID, rawVersion, rawJSON, rawHash any
		if err := rows.Scan(&rawSentinel, &rawAccountCount, &rawMessageCount, &rawRecordID, &rawAccountID, &rawMessageID, &rawThreadID, &rawVersion, &rawJSON, &rawHash); err != nil {
			return mail.Message{}, storage.ErrPersistenceInspect
		}
		sentinel, sentinelOK := exactInteger(rawSentinel)
		accountCount, accountOK := exactInteger(rawAccountCount)
		messageCount, messageOK := exactInteger(rawMessageCount)
		if !sentinelOK || sentinel != 1 || !accountOK || accountCount < 0 || accountCount > 1 || !messageOK || messageCount < 0 || messageCount > 1 || messageCount > accountCount {
			return mail.Message{}, storage.ErrPersistenceInspect
		}
		if accountCount == 0 {
			if rawRecordID != nil || rawAccountID != nil || rawMessageID != nil || rawThreadID != nil || rawVersion != nil || rawJSON != nil || rawHash != nil {
				return mail.Message{}, storage.ErrPersistenceInspect
			}
			continue
		}
		accountExists = true
		if messageCount == 0 {
			if rawRecordID != nil || rawAccountID != nil || rawMessageID != nil || rawThreadID != nil || rawVersion != nil || rawJSON != nil || rawHash != nil {
				return mail.Message{}, storage.ErrPersistenceInspect
			}
			continue
		}
		messageExists = true
		recordID, recordOK := exactText(rawRecordID)
		storedAccount, storedAccountOK := exactText(rawAccountID)
		storedMessage, storedMessageOK := exactText(rawMessageID)
		threadID, threadOK := exactText(rawThreadID)
		version, versionOK := exactInteger(rawVersion)
		metadataJSON, jsonOK := exactText(rawJSON)
		metadataHash, hashOK := exactText(rawHash)
		if !recordOK || !storedAccountOK || storedAccount != accountID.String() || !storedMessageOK || storedMessage != gmailMessageID || !threadOK || !versionOK || version != int64(mail.MetadataVersion1) || !jsonOK || !hashOK {
			return mail.Message{}, storage.ErrPersistenceInspect
		}
		decoded, decodeErr := mail.DecodeCanonical(storedAccount, storedMessage, threadID, uint32(version), []byte(metadataJSON), metadataHash)
		if decodeErr != nil || decoded.RecordID() != recordID {
			return mail.Message{}, storage.ErrPersistenceInspect
		}
		result = decoded
	}
	if err := rows.Err(); err != nil || count != 1 {
		return mail.Message{}, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	if !accountExists {
		return mail.Message{}, storage.ErrAccountNotFound
	}
	if !messageExists {
		return mail.Message{}, storage.ErrMessageNotFound
	}
	return result, nil
}

func currentDiscoveryEncodedSize(message mail.Message) uint32 {
	return uint32(4 + len(message.RecordID()) + 4 + len(message.GmailMessageID()) + 4 + len(message.GmailThreadID()) + 4 + 4 + len(message.CanonicalJSON()) + 4 + len(message.MetadataHash()))
}

func validLowerHexText(value string) bool {
	return validBoundedLowerHexText(value, 64, 64)
}

func validBoundedLowerHexText(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || len(value)%2 != 0 {
		return false
	}
	for _, character := range []byte(value) {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
