package storage

import (
	"context"
	"errors"
	"slices"

	"github.com/mandloideep/inboxgate/internal/gate"
	"github.com/mandloideep/inboxgate/internal/mail"
)

const (
	MaximumReviewAccountSelectors = 16
	MaximumReviewSourceRows       = 101
	MaximumReviewScanRows         = 100
)

var ErrReviewInspectionNotFound = errors.New("storage: review inspection not found")

type ReviewUrgency string

const (
	ReviewUrgencyAll      ReviewUrgency = "all"
	ReviewUrgencyStandard ReviewUrgency = "standard"
	ReviewUrgencyUrgent   ReviewUrgency = "urgent"
)

func (urgency ReviewUrgency) Valid() bool {
	return urgency == ReviewUrgencyAll || urgency == ReviewUrgencyStandard || urgency == ReviewUrgencyUrgent
}

type ReviewCursorKey struct {
	accountID AccountID
	threadID  string
	messageID string
	Present   bool
}

func NewReviewCursorKey(accountID AccountID, threadID, messageID string) (ReviewCursorKey, error) {
	if !accountID.valid() || ValidateGmailMessageID(threadID) != nil || ValidateGmailMessageID(messageID) != nil || len(threadID)+len(messageID) > 255 {
		return ReviewCursorKey{}, ErrInvalidValue
	}
	return ReviewCursorKey{accountID: accountID, threadID: threadID, messageID: messageID, Present: true}, nil
}

func (key ReviewCursorKey) AccountID() AccountID { return key.accountID }
func (key ReviewCursorKey) ThreadID() string     { return key.threadID }
func (key ReviewCursorKey) MessageID() string    { return key.messageID }
func (key ReviewCursorKey) Valid() bool {
	if !key.Present {
		return key == (ReviewCursorKey{})
	}
	parsed, err := NewReviewCursorKey(key.accountID, key.threadID, key.messageID)
	return err == nil && parsed == key
}

type ReviewCandidateQuery struct {
	accountIDs        []AccountID
	urgency           ReviewUrgency
	requestedPageSize int
	after             ReviewCursorKey
	limit             int
}

func NewReviewCandidateQuery(accountIDs []AccountID, urgency ReviewUrgency, requestedPageSize int, after ReviewCursorKey, limit int) (ReviewCandidateQuery, error) {
	if len(accountIDs) > MaximumReviewAccountSelectors || !urgency.Valid() || requestedPageSize < 1 || requestedPageSize > 10 || !after.Valid() || limit != MaximumReviewSourceRows {
		return ReviewCandidateQuery{}, ErrInvalidValue
	}
	for index, accountID := range accountIDs {
		if !accountID.valid() || (index > 0 && accountIDs[index-1].String() >= accountID.String()) {
			return ReviewCandidateQuery{}, ErrInvalidValue
		}
	}
	return ReviewCandidateQuery{accountIDs: slices.Clone(accountIDs), urgency: urgency, requestedPageSize: requestedPageSize, after: after, limit: limit}, nil
}

func (query ReviewCandidateQuery) AccountIDs() []AccountID { return slices.Clone(query.accountIDs) }
func (query ReviewCandidateQuery) Urgency() ReviewUrgency  { return query.urgency }
func (query ReviewCandidateQuery) RequestedPageSize() int  { return query.requestedPageSize }
func (query ReviewCandidateQuery) After() ReviewCursorKey  { return query.after }
func (query ReviewCandidateQuery) Limit() int              { return query.limit }

type ReviewCandidateRow struct {
	Message  mail.Message
	Decision GateDecision
}

func NewReviewCandidateRow(message mail.Message, decision GateDecision) (ReviewCandidateRow, error) {
	row := ReviewCandidateRow{Message: message, Decision: decision}
	if !row.Valid() {
		return ReviewCandidateRow{}, ErrInvalidValue
	}
	return row, nil
}

func (row ReviewCandidateRow) Valid() bool {
	return row.Message.Valid() && row.Decision.Valid() && row.Message.MetadataHash() == row.Decision.SourceMetadataHash() &&
		(row.Decision.Outcome() == gate.OutcomeReviewCandidate || row.Decision.Outcome() == gate.OutcomeUrgentReviewCandidate)
}

type CurrentGateInspection struct {
	Message  mail.Message
	Decision GateDecision
}

func NewCurrentGateInspection(message mail.Message, decision GateDecision) (CurrentGateInspection, error) {
	inspection := CurrentGateInspection{Message: message, Decision: decision}
	if !inspection.Valid() {
		return CurrentGateInspection{}, ErrInvalidValue
	}
	return inspection, nil
}

func (inspection CurrentGateInspection) Valid() bool {
	return inspection.Message.Valid() && inspection.Decision.Valid() && inspection.Message.MetadataHash() == inspection.Decision.SourceMetadataHash()
}

type ReviewInspectionSource interface {
	ListReviewCandidates(context.Context, ReviewCandidateQuery) ([]ReviewCandidateRow, error)
	GetCurrentGateInspection(context.Context, AccountID, string) (CurrentGateInspection, error)
}

// DecodeReviewCandidateRow rejects incomplete durable projections.
// Complete storage rows must be decoded through the adapter-owned canonical decoder.
func DecodeReviewCandidateRow(accountID, threadID, messageID string, date int64, outcome, reasons []byte) (ReviewCandidateRow, error) {
	_ = reasons
	if _, err := ParseAccountID(accountID); err != nil || ValidateGmailMessageID(threadID) != nil || ValidateGmailMessageID(messageID) != nil || date < 0 || len(outcome) == 0 {
		return ReviewCandidateRow{}, ErrInvalidValue
	}
	return ReviewCandidateRow{}, ErrInvalidValue
}
