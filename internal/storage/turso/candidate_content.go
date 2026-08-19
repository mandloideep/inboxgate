package turso

import (
	"context"

	"github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
)

const (
	candidateContentLookupSQL = "WITH input(account_id, gmail_message_id) AS (VALUES (?, ?)) SELECT 1, (SELECT COUNT(*) FROM inboxgate_accounts AS accounts, input WHERE accounts.account_id = input.account_id), COUNT(DISTINCT lifecycle.account_id), MAX(lifecycle.state), MAX(lifecycle.state_version), COUNT(DISTINCT messages.record_id), MAX(messages.record_id), MAX(messages.metadata_hash), COUNT(DISTINCT decisions.record_id), MAX(decisions.gate_version), MAX(decisions.source_metadata_hash), MAX(decisions.input_hash), MAX(decisions.outcome), MAX(decisions.reason_codes), MAX(decisions.evaluated_at_unix_ms), COUNT(DISTINCT content.record_id), MAX(content.extractor_version), MAX(content.source_metadata_hash), MAX(content.gate_version), MAX(content.gate_input_hash), MAX(content.source_kind), MAX(content.excerpt), MAX(content.excerpt_bytes), MAX(content.excerpt_limit), MAX(content.truncated), MAX(content.content_hash), MAX(content.fetched_at_unix_ms) FROM input LEFT JOIN inboxgate_account_lifecycle AS lifecycle ON lifecycle.account_id = input.account_id LEFT JOIN inboxgate_messages AS messages ON messages.account_id = input.account_id AND messages.gmail_message_id = input.gmail_message_id LEFT JOIN inboxgate_gate_decisions AS decisions ON decisions.record_id = messages.record_id LEFT JOIN inboxgate_candidate_content AS content ON content.record_id = messages.record_id"
	candidateContentCommitSQL = "WITH input(record_id, account_id, gmail_message_id, lifecycle_version, source_metadata_hash, gate_version, gate_input_hash, gate_outcome, gate_reason_codes, gate_evaluated_at_unix_ms, expected_present, expected_extractor_version, expected_source_metadata_hash, expected_gate_input_hash, expected_excerpt_limit, expected_content_hash, extractor_version, source_kind, excerpt, excerpt_bytes, excerpt_limit, truncated, content_hash, fetched_at_unix_ms) AS (VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)) INSERT INTO inboxgate_candidate_content (record_id, extractor_version, source_metadata_hash, gate_version, gate_input_hash, source_kind, excerpt, excerpt_bytes, excerpt_limit, truncated, content_hash, fetched_at_unix_ms) SELECT input.record_id, input.extractor_version, input.source_metadata_hash, input.gate_version, input.gate_input_hash, input.source_kind, input.excerpt, input.excerpt_bytes, input.excerpt_limit, input.truncated, input.content_hash, input.fetched_at_unix_ms FROM input JOIN inboxgate_account_lifecycle AS lifecycle ON lifecycle.account_id = input.account_id AND lifecycle.state = 'active' AND lifecycle.state_version = input.lifecycle_version JOIN inboxgate_messages AS messages ON messages.record_id = input.record_id AND messages.account_id = input.account_id AND messages.gmail_message_id = input.gmail_message_id AND messages.metadata_hash = input.source_metadata_hash JOIN inboxgate_gate_decisions AS decisions ON decisions.record_id = input.record_id AND decisions.gate_version = input.gate_version AND decisions.source_metadata_hash = input.source_metadata_hash AND decisions.input_hash = input.gate_input_hash AND decisions.outcome = input.gate_outcome AND decisions.reason_codes = input.gate_reason_codes AND decisions.evaluated_at_unix_ms = input.gate_evaluated_at_unix_ms AND decisions.outcome IN ('review_candidate', 'urgent_review_candidate') WHERE (input.expected_present = 0 AND NOT EXISTS (SELECT 1 FROM inboxgate_candidate_content AS current WHERE current.record_id = input.record_id)) OR (input.expected_present = 1 AND EXISTS (SELECT 1 FROM inboxgate_candidate_content AS current WHERE current.record_id = input.record_id AND current.extractor_version = input.expected_extractor_version AND current.source_metadata_hash = input.expected_source_metadata_hash AND current.gate_input_hash = input.expected_gate_input_hash AND current.excerpt_limit = input.expected_excerpt_limit AND current.content_hash = input.expected_content_hash)) ON CONFLICT(record_id) DO UPDATE SET extractor_version = excluded.extractor_version, source_metadata_hash = excluded.source_metadata_hash, gate_version = excluded.gate_version, gate_input_hash = excluded.gate_input_hash, source_kind = excluded.source_kind, excerpt = excluded.excerpt, excerpt_bytes = excluded.excerpt_bytes, excerpt_limit = excluded.excerpt_limit, truncated = excluded.truncated, content_hash = excluded.content_hash, fetched_at_unix_ms = excluded.fetched_at_unix_ms WHERE EXISTS (SELECT 1 FROM input WHERE input.expected_present = 1 AND inboxgate_candidate_content.extractor_version = input.expected_extractor_version AND inboxgate_candidate_content.source_metadata_hash = input.expected_source_metadata_hash AND inboxgate_candidate_content.gate_input_hash = input.expected_gate_input_hash AND inboxgate_candidate_content.excerpt_limit = input.expected_excerpt_limit AND inboxgate_candidate_content.content_hash = input.expected_content_hash)"
)

type candidateContentInspection struct {
	accountExists bool
	lifecycle     *storage.AccountLifecycle
	messageExists bool
	recordID      string
	metadataHash  string
	decision      *storage.GateDecision
	content       *mail.CandidateContent
}

func (h *handle) GetCandidateContent(ctx context.Context, accountID storage.AccountID, gmailMessageID string, excerptLimit int) (storage.CandidateContentState, error) {
	if !h.migrationAllowed {
		return storage.CandidateContentState{}, storage.ErrPersistenceNotAllowed
	}
	if parsed, err := storage.ParseAccountID(accountID.String()); err != nil || parsed != accountID || storage.ValidateGmailMessageID(gmailMessageID) != nil || excerptLimit < mail.MinimumExcerptBytes || excerptLimit > mail.MaximumExcerptBytes {
		return storage.CandidateContentState{}, storage.ErrInvalidValue
	}
	operationCtx, cancel := context.WithTimeout(ctx, h.persistenceTimeout)
	defer cancel()
	inspection, err := h.inspectCandidateContent(operationCtx, accountID, gmailMessageID)
	if err != nil {
		return storage.CandidateContentState{}, err
	}
	if !inspection.accountExists {
		return storage.CandidateContentState{}, storage.ErrAccountNotFound
	}
	if !inspection.messageExists {
		return storage.CandidateContentState{}, storage.ErrMessageNotFound
	}
	if inspection.content == nil {
		return storage.CandidateContentState{}, storage.ErrCandidateContentNotFound
	}
	current := candidateContentInspectionCurrent(inspection, excerptLimit)
	return storage.CandidateContentState{Content: *inspection.content, Current: current}, nil
}

func (h *handle) CommitCandidateContent(ctx context.Context, commit storage.CandidateContentCommit) error {
	if !h.migrationAllowed {
		return storage.ErrPersistenceNotAllowed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := storage.ValidateCandidateContentCommit(commit); err != nil {
		return err
	}
	accountID, _ := storage.ParseAccountID(commit.Source.AccountID())
	operationCtx, cancel := context.WithTimeout(ctx, h.persistenceTimeout)
	defer cancel()
	initial, err := h.inspectCandidateContent(operationCtx, accountID, commit.Source.GmailMessageID())
	if err != nil {
		return err
	}
	if err := resolveCandidateContentCommit(commit, initial); err != nil {
		return err
	}
	if initial.content != nil && initial.content.SemanticEqual(commit.Next) {
		return nil
	}
	connection, err := h.database.Conn(operationCtx)
	if err != nil {
		return safePersistenceError(storage.ErrPersistenceAcquire, operationCtx)
	}
	expectedPresent := int64(0)
	var expectedExtractor, expectedSource, expectedGateInput, expectedLimit, expectedHash any
	if commit.Expected != nil {
		expectedPresent = 1
		expectedExtractor = int64(commit.Expected.ExtractorVersion())
		expectedSource = commit.Expected.SourceMetadataHash()
		expectedGateInput = commit.Expected.GateInputHash()
		expectedLimit = int64(commit.Expected.ExcerptLimit())
		expectedHash = commit.Expected.ContentHash()
	}
	result, mutationErr := connection.ExecContext(operationCtx, candidateContentCommitSQL,
		commit.Source.RecordID(), accountID.String(), commit.Source.GmailMessageID(), commit.LifecycleVersion.Int64(), commit.Source.MetadataHash(),
		int64(commit.Gate.Version()), commit.Gate.InputHash(), commit.Gate.Outcome().String(), commit.Gate.ReasonJSON(), commit.Gate.EvaluatedAtUnixMS(),
		expectedPresent, expectedExtractor, expectedSource, expectedGateInput, expectedLimit, expectedHash,
		int64(commit.Next.ExtractorVersion()), commit.Next.SourceKind().String(), commit.Next.Excerpt(), int64(commit.Next.ExcerptBytes()),
		int64(commit.Next.ExcerptLimit()), boolIntegerValue(commit.Next.Truncated()), commit.Next.ContentHash(), commit.Next.FetchedAtUnixMS())
	mutationConfirmed := exactOneRow(result, mutationErr)
	verified, verificationErr := h.inspectCandidateContent(operationCtx, accountID, commit.Source.GmailMessageID())
	success := verificationErr == nil && verified.content != nil && candidateContentCommitSourceMatches(commit, verified) && verified.content.SemanticEqual(commit.Next)
	if mutationErr != nil || !mutationConfirmed || !success {
		discardPersistenceConnection(connection)
	} else {
		_ = connection.Close()
	}
	if success {
		return nil
	}
	if verificationErr != nil {
		return safePersistenceError(storage.ErrCandidateContentRecoveryRequired, operationCtx)
	}
	if classification := resolveCandidateContentCommit(commit, verified); classification != nil {
		return classification
	}
	return safePersistenceError(storage.ErrCandidateContentRecoveryRequired, operationCtx)
}

func resolveCandidateContentCommit(commit storage.CandidateContentCommit, inspection candidateContentInspection) error {
	if !inspection.accountExists {
		return storage.ErrAccountNotFound
	}
	if inspection.lifecycle == nil || inspection.lifecycle.State != storage.AccountStateActive || inspection.lifecycle.Version != commit.LifecycleVersion {
		return storage.ErrLifecycleConflict
	}
	if !inspection.messageExists {
		return storage.ErrMessageNotFound
	}
	if inspection.recordID != commit.Source.RecordID() || inspection.metadataHash != commit.Source.MetadataHash() {
		return storage.ErrCandidateContentStaleSource
	}
	if inspection.decision == nil || !inspection.decision.Equal(commit.Gate) || !storage.CandidateOutcome(inspection.decision.Outcome()) || inspection.decision.SourceMetadataHash() != inspection.metadataHash {
		return storage.ErrCandidateContentIneligible
	}
	if inspection.content == nil {
		if commit.Expected != nil {
			return storage.ErrCandidateContentConflict
		}
		return nil
	}
	if inspection.content.SemanticEqual(commit.Next) {
		return nil
	}
	if commit.Expected == nil || inspection.content.Revision() != *commit.Expected {
		return storage.ErrCandidateContentConflict
	}
	return nil
}

func candidateContentCommitSourceMatches(commit storage.CandidateContentCommit, inspection candidateContentInspection) bool {
	return inspection.lifecycle != nil && inspection.lifecycle.State == storage.AccountStateActive && inspection.lifecycle.Version == commit.LifecycleVersion &&
		inspection.recordID == commit.Source.RecordID() && inspection.metadataHash == commit.Source.MetadataHash() && inspection.decision != nil && inspection.decision.Equal(commit.Gate)
}

func candidateContentInspectionCurrent(inspection candidateContentInspection, excerptLimit int) bool {
	return inspection.lifecycle != nil && inspection.lifecycle.State == storage.AccountStateActive && inspection.messageExists && inspection.decision != nil && inspection.content != nil &&
		storage.CandidateOutcome(inspection.decision.Outcome()) && inspection.decision.SourceMetadataHash() == inspection.metadataHash &&
		inspection.content.SourceMetadataHash() == inspection.metadataHash && inspection.content.GateVersion() == inspection.decision.Version() &&
		inspection.content.GateInputHash() == inspection.decision.InputHash() && inspection.content.ExtractorVersion() == mail.CandidateExtractorVersion1 &&
		inspection.content.ExcerptLimit() == excerptLimit
}

func (h *handle) inspectCandidateContent(ctx context.Context, accountID storage.AccountID, gmailMessageID string) (candidateContentInspection, error) {
	connection, err := h.database.Conn(ctx)
	if err != nil {
		return candidateContentInspection{}, safePersistenceError(storage.ErrPersistenceAcquire, ctx)
	}
	defer connection.Close()
	rows, err := connection.QueryContext(ctx, candidateContentLookupSQL, accountID.String(), gmailMessageID)
	if err != nil {
		return candidateContentInspection{}, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	defer rows.Close()
	count := 0
	var inspection candidateContentInspection
	for rows.Next() {
		count++
		var raw [27]any
		pointers := make([]any, len(raw))
		for index := range raw {
			pointers[index] = &raw[index]
		}
		if err := rows.Scan(pointers...); err != nil {
			return candidateContentInspection{}, storage.ErrPersistenceInspect
		}
		sentinel, okSentinel := exactInteger(raw[0])
		accountCount, okAccount := exactInteger(raw[1])
		lifecycleCount, okLifecycle := exactInteger(raw[2])
		messageCount, okMessage := exactInteger(raw[5])
		decisionCount, okDecision := exactInteger(raw[8])
		contentCount, okContent := exactInteger(raw[15])
		if !okSentinel || sentinel != 1 || !validOptionalCount(accountCount, okAccount) || !validOptionalCount(lifecycleCount, okLifecycle) || lifecycleCount > accountCount || !validOptionalCount(messageCount, okMessage) || messageCount > accountCount || !validOptionalCount(decisionCount, okDecision) || decisionCount > messageCount || !validOptionalCount(contentCount, okContent) || contentCount > messageCount {
			return candidateContentInspection{}, storage.ErrPersistenceInspect
		}
		inspection.accountExists = accountCount == 1
		if lifecycleCount == 1 {
			stateText, stateOK := exactText(raw[3])
			versionValue, versionOK := exactInteger(raw[4])
			state, stateErr := storage.ParseAccountState(stateText)
			version, versionErr := storage.ParseLifecycleVersion(versionValue)
			if !stateOK || !versionOK || stateErr != nil || versionErr != nil {
				return candidateContentInspection{}, storage.ErrPersistenceInspect
			}
			inspection.lifecycle = &storage.AccountLifecycle{AccountID: accountID, State: state, Version: version, RevocationStatus: lifecycleRevocationForInspection(state)}
		} else if raw[3] != nil || raw[4] != nil {
			return candidateContentInspection{}, storage.ErrPersistenceInspect
		}
		inspection.messageExists = messageCount == 1
		if inspection.messageExists {
			recordID, recordOK := exactText(raw[6])
			metadataHash, metadataOK := exactText(raw[7])
			if !recordOK || !metadataOK || !validLowerHexText(recordID) || !validLowerHexText(metadataHash) {
				return candidateContentInspection{}, storage.ErrPersistenceInspect
			}
			inspection.recordID, inspection.metadataHash = recordID, metadataHash
		} else if raw[6] != nil || raw[7] != nil {
			return candidateContentInspection{}, storage.ErrPersistenceInspect
		}
		if decisionCount == 1 {
			version, versionOK := exactInteger(raw[9])
			source, sourceOK := exactText(raw[10])
			input, inputOK := exactText(raw[11])
			outcome, outcomeOK := exactText(raw[12])
			reasons, reasonsOK := exactText(raw[13])
			timestamp, timestampOK := exactInteger(raw[14])
			decision, decodeErr := storage.DecodeGateDecision(version, source, input, outcome, reasons, timestamp)
			if !versionOK || !sourceOK || !inputOK || !outcomeOK || !reasonsOK || !timestampOK || decodeErr != nil {
				return candidateContentInspection{}, storage.ErrPersistenceInspect
			}
			inspection.decision = &decision
		} else if anyNonNil(raw[9:15]) {
			return candidateContentInspection{}, storage.ErrPersistenceInspect
		}
		if contentCount == 1 {
			extractor, extractorOK := exactInteger(raw[16])
			source, sourceOK := exactText(raw[17])
			gateVersion, gateVersionOK := exactInteger(raw[18])
			gateInput, gateInputOK := exactText(raw[19])
			kind, kindOK := exactText(raw[20])
			excerpt, excerptOK := exactText(raw[21])
			excerptBytes, excerptBytesOK := exactInteger(raw[22])
			excerptLimit, excerptLimitOK := exactInteger(raw[23])
			truncated, truncatedOK := exactInteger(raw[24])
			hashText, hashOK := exactText(raw[25])
			fetchedAt, fetchedOK := exactInteger(raw[26])
			content, decodeErr := mail.DecodeCandidateContent(extractor, inspection.recordID, source, gateVersion, gateInput, kind, excerpt, excerptBytes, excerptLimit, truncated, hashText, fetchedAt)
			if !extractorOK || !sourceOK || !gateVersionOK || !gateInputOK || !kindOK || !excerptOK || !excerptBytesOK || !excerptLimitOK || !truncatedOK || !hashOK || !fetchedOK || decodeErr != nil {
				return candidateContentInspection{}, storage.ErrPersistenceInspect
			}
			inspection.content = &content
		} else if anyNonNil(raw[16:27]) {
			return candidateContentInspection{}, storage.ErrPersistenceInspect
		}
	}
	if err := rows.Err(); err != nil || count != 1 {
		return candidateContentInspection{}, safePersistenceError(storage.ErrPersistenceInspect, ctx)
	}
	return inspection, nil
}

func validOptionalCount(value int64, ok bool) bool { return ok && value >= 0 && value <= 1 }

func anyNonNil(values []any) bool {
	for _, value := range values {
		if value != nil {
			return true
		}
	}
	return false
}

func lifecycleRevocationForInspection(state storage.AccountState) storage.RevocationStatus {
	if state == storage.AccountStateRevoked {
		return storage.RevocationStatusConfirmed
	}
	return storage.RevocationStatusNone
}

func boolIntegerValue(value bool) int64 {
	if value {
		return 1
	}
	return 0
}
