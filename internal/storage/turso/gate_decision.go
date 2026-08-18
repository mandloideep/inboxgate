package turso

import (
	"context"

	"github.com/mandloideep/inboxgate/internal/storage"
)

const (
	gateDecisionLookupSQL = "WITH input(account_id, gmail_message_id) AS (VALUES (?, ?)) SELECT 1, (SELECT COUNT(*) FROM inboxgate_accounts AS accounts, input WHERE accounts.account_id = input.account_id), COUNT(messages.record_id), MAX(messages.record_id), MAX(messages.metadata_hash), COUNT(decisions.record_id), MAX(decisions.gate_version), MAX(decisions.source_metadata_hash), MAX(decisions.input_hash), MAX(decisions.outcome), MAX(decisions.reason_codes), MAX(decisions.evaluated_at_unix_ms) FROM input LEFT JOIN inboxgate_messages AS messages ON messages.account_id = input.account_id AND messages.gmail_message_id = input.gmail_message_id LEFT JOIN inboxgate_gate_decisions AS decisions ON decisions.record_id = messages.record_id"
	gateDecisionCommitSQL = "WITH input(record_id, account_id, gmail_message_id, source_metadata_hash, expected_present, expected_version, expected_input_hash, gate_version, input_hash, outcome, reason_codes, evaluated_at_unix_ms) AS (VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)) INSERT INTO inboxgate_gate_decisions (record_id, gate_version, source_metadata_hash, input_hash, outcome, reason_codes, evaluated_at_unix_ms) SELECT input.record_id, input.gate_version, input.source_metadata_hash, input.input_hash, input.outcome, input.reason_codes, input.evaluated_at_unix_ms FROM input JOIN inboxgate_messages AS messages ON messages.record_id = input.record_id AND messages.account_id = input.account_id AND messages.gmail_message_id = input.gmail_message_id AND messages.metadata_hash = input.source_metadata_hash WHERE (input.expected_present = 0 AND NOT EXISTS (SELECT 1 FROM inboxgate_gate_decisions AS current WHERE current.record_id = input.record_id)) OR (input.expected_present = 1 AND EXISTS (SELECT 1 FROM inboxgate_gate_decisions AS current WHERE current.record_id = input.record_id AND current.gate_version = input.expected_version AND current.input_hash = input.expected_input_hash)) ON CONFLICT(record_id) DO UPDATE SET gate_version = excluded.gate_version, source_metadata_hash = excluded.source_metadata_hash, input_hash = excluded.input_hash, outcome = excluded.outcome, reason_codes = excluded.reason_codes, evaluated_at_unix_ms = excluded.evaluated_at_unix_ms WHERE EXISTS (SELECT 1 FROM input WHERE input.expected_present = 1 AND inboxgate_gate_decisions.gate_version = input.expected_version AND inboxgate_gate_decisions.input_hash = input.expected_input_hash)"
)

type gateDecisionInspection struct {
	accountExists bool
	messageExists bool
	recordID      string
	metadataHash  string
	decision      *storage.GateDecision
}

func (h *handle) GetGateDecision(ctx context.Context, accountID storage.AccountID, gmailMessageID string) (storage.GateDecisionState, error) {
	if !h.migrationAllowed {
		return storage.GateDecisionState{}, storage.ErrPersistenceNotAllowed
	}
	if parsed, err := storage.ParseAccountID(accountID.String()); err != nil || parsed != accountID || storage.ValidateGmailMessageID(gmailMessageID) != nil {
		return storage.GateDecisionState{}, storage.ErrInvalidValue
	}
	operationCtx, cancel := context.WithTimeout(ctx, h.persistenceTimeout)
	defer cancel()
	inspection, err := h.inspectGateDecision(operationCtx, accountID, gmailMessageID)
	if err != nil {
		return storage.GateDecisionState{}, err
	}
	if !inspection.accountExists {
		return storage.GateDecisionState{}, storage.ErrAccountNotFound
	}
	if !inspection.messageExists {
		return storage.GateDecisionState{}, storage.ErrMessageNotFound
	}
	if inspection.decision == nil {
		return storage.GateDecisionState{}, storage.ErrGateDecisionNotFound
	}
	return storage.GateDecisionState{Decision: *inspection.decision, Current: inspection.decision.SourceMetadataHash() == inspection.metadataHash}, nil
}

func (h *handle) CommitGateDecision(ctx context.Context, commit storage.GateDecisionCommit) error {
	if !h.migrationAllowed {
		return storage.ErrPersistenceNotAllowed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	accountID := commit.SourceAccountID()
	if parsed, err := storage.ParseAccountID(commit.Source.AccountID()); err != nil || parsed != accountID || storage.ValidateGmailMessageID(commit.SourceGmailMessageID()) != nil || !commit.Source.Valid() || !commit.Next.Valid() || (commit.Expected != nil && !commit.Expected.Valid()) {
		return storage.ErrInvalidValue
	}
	operationCtx, cancel := context.WithTimeout(ctx, h.persistenceTimeout)
	defer cancel()
	initial, err := h.inspectGateDecision(operationCtx, accountID, commit.SourceGmailMessageID())
	if err != nil {
		return err
	}
	if err := resolveGateDecisionCommit(commit, initial); err != nil {
		return err
	}
	if initial.decision != nil && initial.decision.SemanticEqual(commit.Next) {
		return nil
	}
	connection, err := h.database.Conn(operationCtx)
	if err != nil {
		return safePersistenceError(storage.ErrPersistenceAcquire, operationCtx)
	}
	expectedPresent := int64(0)
	var expectedVersion, expectedInput any
	if commit.Expected != nil {
		expectedPresent = 1
		expectedVersion = int64(commit.Expected.Version())
		expectedInput = commit.Expected.InputHash()
	}
	result, mutationErr := connection.ExecContext(operationCtx, gateDecisionCommitSQL,
		commit.Source.RecordID(), accountID.String(), commit.SourceGmailMessageID(), commit.Source.MetadataHash(),
		expectedPresent, expectedVersion, expectedInput, int64(commit.Next.Version()), commit.Next.InputHash(), commit.Next.Outcome().String(), commit.Next.ReasonJSON(), commit.Next.EvaluatedAtUnixMS())
	mutationConfirmed := exactOneRow(result, mutationErr)
	verified, verificationErr := h.inspectGateDecision(operationCtx, accountID, commit.SourceGmailMessageID())
	success := verificationErr == nil && verified.decision != nil && verified.metadataHash == commit.Source.MetadataHash() && verified.decision.Equal(commit.Next)
	if mutationErr != nil || !mutationConfirmed || !success {
		discardPersistenceConnection(connection)
	} else {
		_ = connection.Close()
	}
	if success {
		return nil
	}
	if verificationErr != nil {
		return safePersistenceError(storage.ErrGateDecisionRecoveryRequired, operationCtx)
	}
	if classification := resolveGateDecisionCommit(commit, verified); classification != nil {
		return classification
	}
	return safePersistenceError(storage.ErrGateDecisionRecoveryRequired, operationCtx)
}

func resolveGateDecisionCommit(commit storage.GateDecisionCommit, inspection gateDecisionInspection) error {
	if !inspection.accountExists {
		return storage.ErrAccountNotFound
	}
	if !inspection.messageExists {
		return storage.ErrMessageNotFound
	}
	if inspection.recordID != commit.Source.RecordID() || inspection.metadataHash != commit.Source.MetadataHash() {
		return storage.ErrGateDecisionStaleSource
	}
	if inspection.metadataHash != commit.Next.SourceMetadataHash() {
		return storage.ErrInvalidValue
	}
	if inspection.decision == nil {
		if commit.Expected != nil {
			return storage.ErrGateDecisionConflict
		}
		return nil
	}
	if inspection.decision.SemanticEqual(commit.Next) {
		return nil
	}
	if inspection.decision.Revision() == commit.Next.Revision() {
		return storage.ErrGateDecisionConflict
	}
	if commit.Expected == nil || inspection.decision.Revision() != *commit.Expected {
		return storage.ErrGateDecisionConflict
	}
	return nil
}

func (h *handle) inspectGateDecision(ctx context.Context, accountID storage.AccountID, gmailMessageID string) (gateDecisionInspection, error) {
	connection, err := h.database.Conn(ctx)
	if err != nil {
		return gateDecisionInspection{}, safePersistenceError(storage.ErrPersistenceAcquire, ctx)
	}
	defer connection.Close()
	rows, err := connection.QueryContext(ctx, gateDecisionLookupSQL, accountID.String(), gmailMessageID)
	if err != nil {
		return gateDecisionInspection{}, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	defer rows.Close()
	count := 0
	var inspection gateDecisionInspection
	for rows.Next() {
		count++
		var rawSentinel, rawAccountCount, rawMessageCount, rawRecordID, rawMetadataHash, rawDecisionCount any
		var rawVersion, rawSourceHash, rawInputHash, rawOutcome, rawReasons, rawTimestamp any
		if err := rows.Scan(&rawSentinel, &rawAccountCount, &rawMessageCount, &rawRecordID, &rawMetadataHash, &rawDecisionCount, &rawVersion, &rawSourceHash, &rawInputHash, &rawOutcome, &rawReasons, &rawTimestamp); err != nil {
			return gateDecisionInspection{}, storage.ErrPersistenceInspect
		}
		sentinel, sentinelOK := exactInteger(rawSentinel)
		accountCount, accountOK := exactInteger(rawAccountCount)
		messageCount, messageOK := exactInteger(rawMessageCount)
		decisionCount, decisionOK := exactInteger(rawDecisionCount)
		if !sentinelOK || sentinel != 1 || !accountOK || accountCount < 0 || accountCount > 1 || !messageOK || messageCount < 0 || messageCount > 1 || messageCount > accountCount || !decisionOK || decisionCount < 0 || decisionCount > 1 || decisionCount > messageCount {
			return gateDecisionInspection{}, storage.ErrPersistenceInspect
		}
		inspection.accountExists = accountCount == 1
		inspection.messageExists = messageCount == 1
		if !inspection.messageExists {
			if rawRecordID != nil || rawMetadataHash != nil || rawVersion != nil || rawSourceHash != nil || rawInputHash != nil || rawOutcome != nil || rawReasons != nil || rawTimestamp != nil {
				return gateDecisionInspection{}, storage.ErrPersistenceInspect
			}
			continue
		}
		recordID, recordOK := exactText(rawRecordID)
		metadataHash, metadataOK := exactText(rawMetadataHash)
		if !recordOK || !metadataOK || !validLowerHexText(recordID) || !validLowerHexText(metadataHash) {
			return gateDecisionInspection{}, storage.ErrPersistenceInspect
		}
		inspection.recordID = recordID
		inspection.metadataHash = metadataHash
		if decisionCount == 0 {
			if rawVersion != nil || rawSourceHash != nil || rawInputHash != nil || rawOutcome != nil || rawReasons != nil || rawTimestamp != nil {
				return gateDecisionInspection{}, storage.ErrPersistenceInspect
			}
			continue
		}
		version, versionOK := exactInteger(rawVersion)
		sourceHash, sourceOK := exactText(rawSourceHash)
		inputHash, inputOK := exactText(rawInputHash)
		outcome, outcomeOK := exactText(rawOutcome)
		reasons, reasonsOK := exactText(rawReasons)
		timestamp, timestampOK := exactInteger(rawTimestamp)
		if !versionOK || !sourceOK || !inputOK || !outcomeOK || !reasonsOK || !timestampOK {
			return gateDecisionInspection{}, storage.ErrPersistenceInspect
		}
		decision, decodeErr := storage.DecodeGateDecision(version, sourceHash, inputHash, outcome, reasons, timestamp)
		if decodeErr != nil {
			return gateDecisionInspection{}, storage.ErrPersistenceInspect
		}
		inspection.decision = &decision
	}
	if err := rows.Err(); err != nil || count != 1 {
		return gateDecisionInspection{}, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	return inspection, nil
}
