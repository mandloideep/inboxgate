// Package reviewinspect exposes bounded current gate inspection over a narrow read source.
package reviewinspect

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/gate"
	"github.com/mandloideep/inboxgate/internal/reviewinspectview"
	"github.com/mandloideep/inboxgate/internal/storage"
)

const (
	OutputVersion1             = reviewinspectview.OutputVersion1
	MaximumCursorBytes         = reviewinspectview.MaximumCursorBytes
	MaximumInternalDateUnixMS  = reviewinspectview.MaximumInternalDateUnixMS
	ContentTrustUntrustedEmail = reviewinspectview.ContentTrustUntrustedEmail
	UrgencyAll                 = reviewinspectview.UrgencyAll
	UrgencyStandard            = reviewinspectview.UrgencyStandard
	UrgencyUrgent              = reviewinspectview.UrgencyUrgent
	cursorPrefix               = "igrc2."
	cursorMACDomain            = "inboxgate/review-cursor/v2"
	cursorMACKeyBytes          = 32
)

var (
	ErrInvalidRequest = errors.New("review inspection: invalid request")
	ErrUnavailable    = errors.New("review inspection: unavailable")
)

type ListRequest = reviewinspectview.ListRequest
type Candidate = reviewinspectview.Candidate
type CandidatePage = reviewinspectview.CandidatePage
type GateReasonRequest = reviewinspectview.GateReasonRequest
type GateReason = reviewinspectview.GateReason

type Service struct {
	source       storage.ReviewInspectionSource
	policy       config.Gate
	review       config.Review
	cursorMACKey [cursorMACKeyBytes]byte
}

func New(source storage.ReviewInspectionSource, policy config.Gate, review config.Review) (*Service, error) {
	return newWithCursorEntropy(source, policy, review, rand.Reader)
}

func newWithCursorEntropy(source storage.ReviewInspectionSource, policy config.Gate, review config.Review, entropy io.Reader) (*Service, error) {
	if source == nil || gate.ValidatePolicy(policy) != nil || review.DefaultPageSize == 0 || review.MaximumPageSize == 0 {
		return nil, ErrInvalidRequest
	}
	if entropy == nil {
		return nil, ErrUnavailable
	}
	var key [cursorMACKeyBytes]byte
	n, err := entropy.Read(key[:])
	if err != nil || n != len(key) {
		clear(key[:])
		return nil, ErrUnavailable
	}
	return newWithCursorKey(source, policy, review, key)
}

func newWithCursorKey(source storage.ReviewInspectionSource, policy config.Gate, review config.Review, key [cursorMACKeyBytes]byte) (*Service, error) {
	if source == nil || gate.ValidatePolicy(policy) != nil || review.DefaultPageSize == 0 || review.MaximumPageSize == 0 {
		return nil, ErrInvalidRequest
	}
	return &Service{source: source, policy: policy, review: review, cursorMACKey: key}, nil
}

func (service *Service) List(ctx context.Context, request ListRequest) (CandidatePage, error) {
	accountIDs, urgency, pageSize, binding, cursor, err := service.normalizeList(request)
	if err != nil {
		return CandidatePage{}, ErrInvalidRequest
	}
	query, err := storage.NewReviewCandidateQuery(accountIDs, urgency, pageSize, cursor, storage.MaximumReviewSourceRows)
	if err != nil {
		return CandidatePage{}, ErrInvalidRequest
	}
	rows, err := service.source.ListReviewCandidates(ctx, query)
	if err != nil || ctx.Err() != nil || len(rows) > storage.MaximumReviewSourceRows {
		return CandidatePage{}, ErrUnavailable
	}
	var previous storage.ReviewCursorKey
	for _, row := range rows {
		if !row.Valid() {
			return CandidatePage{}, ErrUnavailable
		}
		accountID, parseErr := storage.ParseAccountID(row.Message.AccountID())
		key, keyErr := storage.NewReviewCursorKey(accountID, row.Message.GmailThreadID(), row.Message.GmailMessageID())
		if parseErr != nil || keyErr != nil || !selectedAccount(accountIDs, accountID) || cursor.Present && compareKey(cursor, key) >= 0 || previous.Present && compareKey(previous, key) >= 0 {
			return CandidatePage{}, ErrUnavailable
		}
		previous = key
	}
	result := CandidatePage{OutputVersion: OutputVersion1, Candidates: make([]Candidate, 0, pageSize)}
	var continuation storage.ReviewCursorKey
	scanned := 0
	for _, row := range rows {
		if scanned == storage.MaximumReviewScanRows {
			break
		}
		scanned++
		accountID, _ := storage.ParseAccountID(row.Message.AccountID())
		key, _ := storage.NewReviewCursorKey(accountID, row.Message.GmailThreadID(), row.Message.GmailMessageID())
		continuation = key
		current, classifyErr := gate.Classify(row.Message, service.policy)
		if classifyErr != nil || !classificationMatchesDecision(current, row.Decision) {
			continue
		}
		if request.InternalDateMinUnixMS != nil && row.Message.InternalDateUnixMS() < *request.InternalDateMinUnixMS || request.InternalDateMaxUnixMS != nil && row.Message.InternalDateUnixMS() > *request.InternalDateMaxUnixMS {
			continue
		}
		rowUrgency := UrgencyStandard
		if current.Outcome() == gate.OutcomeUrgentReviewCandidate {
			rowUrgency = UrgencyUrgent
		}
		if urgency == storage.ReviewUrgencyStandard && rowUrgency != UrgencyStandard || urgency == storage.ReviewUrgencyUrgent && rowUrgency != UrgencyUrgent {
			continue
		}
		sender, senderTruncated, previewErr := Preview(row.Message.SenderDisplay(), 256)
		subject, subjectTruncated, subjectErr := Preview(row.Message.Subject(), 512)
		if previewErr != nil || subjectErr != nil {
			return CandidatePage{}, ErrUnavailable
		}
		result.Candidates = append(result.Candidates, Candidate{
			AccountID: row.Message.AccountID(), GmailThreadID: row.Message.GmailThreadID(), GmailMessageID: row.Message.GmailMessageID(),
			InternalDateUnixMS: row.Message.InternalDateUnixMS(), Urgency: rowUrgency, Outcome: current.Outcome().String(),
			SenderDisplayPreview: sender, SenderDisplayTruncated: senderTruncated, SenderAddress: row.Message.SenderAddress(),
			SubjectPreview: subject, SubjectTruncated: subjectTruncated, HasAttachments: row.Message.HasAttachments(), ContentTrust: ContentTrustUntrustedEmail,
		})
		if len(result.Candidates) == pageSize {
			break
		}
	}
	if continuation.Present && (len(result.Candidates) == pageSize || len(rows) > scanned) {
		encoded, encodeErr := service.encodeCursor(binding, continuation)
		if encodeErr != nil {
			return CandidatePage{}, ErrUnavailable
		}
		result.NextCursor = &encoded
	}
	return result, nil
}

func (service *Service) GateReason(ctx context.Context, request GateReasonRequest) (GateReason, error) {
	accountID, err := storage.ParseAccountID(request.AccountID)
	if err != nil || storage.ValidateGmailMessageID(request.GmailMessageID) != nil || request.GmailThreadID != "" {
		return GateReason{}, ErrInvalidRequest
	}
	inspection, err := service.source.GetCurrentGateInspection(ctx, accountID, request.GmailMessageID)
	if err != nil || ctx.Err() != nil || !inspection.Valid() || inspection.Message.AccountID() != request.AccountID || inspection.Message.GmailMessageID() != request.GmailMessageID {
		return GateReason{}, ErrUnavailable
	}
	current, err := gate.Classify(inspection.Message, service.policy)
	if err != nil || !classificationMatchesDecision(current, inspection.Decision) {
		return GateReason{}, ErrUnavailable
	}
	reasons := make([]string, len(current.ReasonCodes()))
	for index, reason := range current.ReasonCodes() {
		reasons[index] = reason.String()
	}
	return GateReason{
		OutputVersion: OutputVersion1, AccountID: request.AccountID, GmailThreadID: inspection.Message.GmailThreadID(), GmailMessageID: request.GmailMessageID,
		GateVersion: current.Version(), Outcome: current.Outcome().String(), ReasonCodes: reasons, EvaluatedAtUnixMS: inspection.Decision.EvaluatedAtUnixMS(),
		SourceCurrent: true, PolicyCurrent: true,
	}, nil
}

func classificationMatchesDecision(classification gate.Classification, decision storage.GateDecision) bool {
	return classification.Version() == decision.Version() && classification.SourceMetadataHash() == decision.SourceMetadataHash() && classification.InputHash() == decision.InputHash() && classification.Outcome() == decision.Outcome() && slices.Equal(classification.ReasonCodes(), decision.ReasonCodes())
}

func Preview(value string, maximum int) (string, bool, error) {
	if maximum < 1 || !utf8.ValidString(value) {
		return "", false, ErrInvalidRequest
	}
	if len(value) <= maximum {
		return value, false, nil
	}
	end := maximum
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end], true, nil
}

func (service *Service) normalizeList(request ListRequest) ([]storage.AccountID, storage.ReviewUrgency, int, []byte, storage.ReviewCursorKey, error) {
	if request.AccountIDs != nil && len(request.AccountIDs) == 0 || len(request.AccountIDs) > storage.MaximumReviewAccountSelectors || request.InternalDateMinUnixMS != nil && (*request.InternalDateMinUnixMS < 0 || *request.InternalDateMinUnixMS > MaximumInternalDateUnixMS) || request.InternalDateMaxUnixMS != nil && (*request.InternalDateMaxUnixMS < 0 || *request.InternalDateMaxUnixMS > MaximumInternalDateUnixMS) || request.InternalDateMinUnixMS != nil && request.InternalDateMaxUnixMS != nil && *request.InternalDateMinUnixMS > *request.InternalDateMaxUnixMS {
		return nil, "", 0, nil, storage.ReviewCursorKey{}, ErrInvalidRequest
	}
	accounts := make([]storage.AccountID, len(request.AccountIDs))
	for index, value := range request.AccountIDs {
		account, err := storage.ParseAccountID(value)
		if err != nil || index > 0 && request.AccountIDs[index-1] >= value {
			return nil, "", 0, nil, storage.ReviewCursorKey{}, ErrInvalidRequest
		}
		accounts[index] = account
	}
	urgency := storage.ReviewUrgency(request.Urgency)
	if urgency == "" {
		urgency = storage.ReviewUrgencyAll
	}
	if !urgency.Valid() {
		return nil, "", 0, nil, storage.ReviewCursorKey{}, ErrInvalidRequest
	}
	maximum := min(service.review.MaximumPageSize, 10)
	pageSize := request.PageSize
	if pageSize == 0 {
		pageSize = min(service.review.DefaultPageSize, maximum)
	}
	if pageSize < 1 || pageSize > maximum {
		return nil, "", 0, nil, storage.ReviewCursorKey{}, ErrInvalidRequest
	}
	binding, err := service.requestBinding(request, urgency, pageSize)
	if err != nil {
		return nil, "", 0, nil, storage.ReviewCursorKey{}, ErrInvalidRequest
	}
	var cursor storage.ReviewCursorKey
	if request.Cursor != "" {
		cursor, err = service.decodeCursor(request.Cursor, binding)
		if err != nil {
			return nil, "", 0, nil, storage.ReviewCursorKey{}, ErrInvalidRequest
		}
	}
	return accounts, urgency, int(pageSize), binding, cursor, nil
}

func (service *Service) requestBinding(request ListRequest, urgency storage.ReviewUrgency, pageSize uint64) ([]byte, error) {
	type digestInput struct {
		Domain      string      `json:"domain"`
		Version     int         `json:"version"`
		AccountIDs  []string    `json:"account_ids"`
		AllAccounts bool        `json:"all_accounts"`
		Urgency     string      `json:"urgency"`
		Minimum     *int64      `json:"minimum"`
		Maximum     *int64      `json:"maximum"`
		PageSize    uint64      `json:"page_size"`
		Policy      config.Gate `json:"policy"`
	}
	encoded, err := json.Marshal(digestInput{Domain: cursorMACDomain, Version: 2, AccountIDs: request.AccountIDs, AllAccounts: request.AccountIDs == nil, Urgency: string(urgency), Minimum: request.InternalDateMinUnixMS, Maximum: request.InternalDateMaxUnixMS, PageSize: pageSize, Policy: service.policy})
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func (service *Service) encodeCursor(binding []byte, key storage.ReviewCursorKey) (string, error) {
	if !key.Present || len(key.ThreadID())+len(key.MessageID()) > 255 {
		return "", ErrUnavailable
	}
	accountBytes, err := hex.DecodeString(key.AccountID().String())
	if err != nil || len(accountBytes) != 16 {
		return "", ErrUnavailable
	}
	payload := make([]byte, 0, 51+len(key.ThreadID())+len(key.MessageID()))
	payload = append(payload, 2)
	payload = append(payload, accountBytes...)
	payload = append(payload, byte(len(key.ThreadID())))
	payload = append(payload, key.ThreadID()...)
	payload = append(payload, byte(len(key.MessageID())))
	payload = append(payload, key.MessageID()...)
	payload = append(payload, service.cursorMAC(binding, payload)...)
	encoded := cursorPrefix + base64.RawURLEncoding.EncodeToString(payload)
	if len(encoded) > MaximumCursorBytes {
		return "", ErrUnavailable
	}
	return encoded, nil
}

func (service *Service) decodeCursor(value string, binding []byte) (storage.ReviewCursorKey, error) {
	if len(value) > MaximumCursorBytes || !strings.HasPrefix(value, cursorPrefix) || strings.Contains(value, "=") {
		return storage.ReviewCursorKey{}, ErrInvalidRequest
	}
	raw := value[len(cursorPrefix):]
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != raw || len(payload) < 53 || payload[0] != 2 {
		return storage.ReviewCursorKey{}, ErrInvalidRequest
	}
	tagStart := len(payload) - sha256.Size
	if tagStart < 21 || !hmac.Equal(payload[tagStart:], service.cursorMAC(binding, payload[:tagStart])) {
		return storage.ReviewCursorKey{}, ErrInvalidRequest
	}
	accountID, err := storage.ParseAccountID(hex.EncodeToString(payload[1:17]))
	if err != nil {
		return storage.ReviewCursorKey{}, ErrInvalidRequest
	}
	threadLength := int(payload[17])
	threadEnd := 18 + threadLength
	if threadLength == 0 || threadEnd >= tagStart {
		return storage.ReviewCursorKey{}, ErrInvalidRequest
	}
	messageLength := int(payload[threadEnd])
	if messageLength == 0 || threadEnd+1+messageLength != tagStart {
		return storage.ReviewCursorKey{}, ErrInvalidRequest
	}
	key, err := storage.NewReviewCursorKey(accountID, string(payload[18:threadEnd]), string(payload[threadEnd+1:tagStart]))
	if err != nil {
		return storage.ReviewCursorKey{}, ErrInvalidRequest
	}
	return key, nil
}

func (service *Service) cursorMAC(binding, payload []byte) []byte {
	mac := hmac.New(sha256.New, service.cursorMACKey[:])
	_, _ = mac.Write([]byte(cursorMACDomain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(binding)
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func selectedAccount(accounts []storage.AccountID, candidate storage.AccountID) bool {
	return len(accounts) == 0 || slices.Contains(accounts, candidate)
}

func compareKey(left, right storage.ReviewCursorKey) int {
	if value := strings.Compare(left.AccountID().String(), right.AccountID().String()); value != 0 {
		return value
	}
	if value := strings.Compare(left.ThreadID(), right.ThreadID()); value != 0 {
		return value
	}
	return strings.Compare(left.MessageID(), right.MessageID())
}
