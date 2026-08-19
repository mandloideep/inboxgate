package storage

import (
	"errors"

	"github.com/mandloideep/inboxgate/internal/gate"
	"github.com/mandloideep/inboxgate/internal/mail"
)

var (
	ErrCandidateContentNotFound         = errors.New("storage: candidate content not found")
	ErrCandidateContentConflict         = errors.New("storage: candidate content conflict")
	ErrCandidateContentStaleSource      = errors.New("storage: candidate content source changed")
	ErrCandidateContentIneligible       = errors.New("storage: candidate content ineligible")
	ErrCandidateContentRecoveryRequired = errors.New("storage: candidate content recovery required")
)

// CandidateContentState includes whether one durable excerpt is current for the requested limit.
type CandidateContentState struct {
	Content mail.CandidateContent
	Current bool
}

// CandidateContentCommit binds one excerpt to exact current authority and source state.
type CandidateContentCommit struct {
	Source           mail.Message
	Gate             GateDecision
	LifecycleVersion LifecycleVersion
	Expected         *mail.CandidateContentRevision
	Next             mail.CandidateContent
}

func ValidateCandidateContentCommit(commit CandidateContentCommit) error {
	accountID, err := ParseAccountID(commit.Source.AccountID())
	if err != nil || !accountID.valid() || !commit.Source.Valid() || ValidateGmailMessageID(commit.Source.GmailMessageID()) != nil ||
		!commit.Gate.Valid() || !commit.LifecycleVersion.valid() ||
		!commit.Next.Valid() || commit.Next.RecordID() != commit.Source.RecordID() ||
		commit.Next.SourceMetadataHash() != commit.Source.MetadataHash() ||
		commit.Next.GateVersion() != commit.Gate.Version() || commit.Next.GateInputHash() != commit.Gate.InputHash() ||
		commit.Gate.SourceMetadataHash() != commit.Source.MetadataHash() {
		return ErrInvalidValue
	}
	if commit.Expected != nil && !commit.Expected.Valid() {
		return ErrInvalidValue
	}
	return nil
}

func candidateOutcome(outcome gate.Outcome) bool {
	return outcome == gate.OutcomeReviewCandidate || outcome == gate.OutcomeUrgentReviewCandidate
}

// CandidateOutcome reports whether a gate outcome authorizes bounded content extraction.
func CandidateOutcome(outcome gate.Outcome) bool { return candidateOutcome(outcome) }
