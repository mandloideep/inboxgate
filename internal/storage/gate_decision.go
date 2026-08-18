package storage

import (
	"encoding/json"
	"errors"
	"slices"

	"github.com/mandloideep/inboxgate/internal/gate"
	"github.com/mandloideep/inboxgate/internal/mail"
)

const MaximumGateEvaluationUnixMS int64 = 253402300799999

var (
	ErrGateDecisionNotFound         = errors.New("storage: gate decision not found")
	ErrGateDecisionConflict         = errors.New("storage: gate decision conflict")
	ErrGateDecisionStaleSource      = errors.New("storage: gate decision source changed")
	ErrGateDecisionRecoveryRequired = errors.New("storage: gate decision recovery required")
)

// GateDecision is one fully validated durable gate result.
type GateDecision struct {
	version            uint32
	sourceMetadataHash string
	inputHash          string
	outcome            gate.Outcome
	reasons            []gate.ReasonCode
	reasonJSON         string
	evaluatedAtUnixMS  int64
}

// GateDecisionRevision is the exact durable compare-and-swap identity.
type GateDecisionRevision struct {
	version   uint32
	inputHash string
}

// GateDecisionState includes whether the decision refers to current metadata.
type GateDecisionState struct {
	Decision GateDecision
	Current  bool
}

// GateDecisionCommit binds one classification to the exact canonical source row.
type GateDecisionCommit struct {
	Source   mail.Message
	Expected *GateDecisionRevision
	Next     GateDecision
}

func NewGateDecision(classification gate.Classification, evaluatedAtUnixMS int64) (GateDecision, error) {
	if !classification.Valid() || evaluatedAtUnixMS < 0 || evaluatedAtUnixMS > MaximumGateEvaluationUnixMS {
		return GateDecision{}, ErrInvalidValue
	}
	reasonBytes, err := json.Marshal(classification.ReasonCodes())
	if err != nil || len(reasonBytes) > gate.MaximumReasonJSONBytes {
		return GateDecision{}, ErrInvalidValue
	}
	return GateDecision{
		version: classification.Version(), sourceMetadataHash: classification.SourceMetadataHash(), inputHash: classification.InputHash(),
		outcome: classification.Outcome(), reasons: classification.ReasonCodes(), reasonJSON: string(reasonBytes), evaluatedAtUnixMS: evaluatedAtUnixMS,
	}, nil
}

func DecodeGateDecision(version int64, sourceMetadataHash, inputHash, outcome, reasonJSON string, evaluatedAtUnixMS int64) (GateDecision, error) {
	if version < 0 || version > int64(^uint32(0)) || len(reasonJSON) > gate.MaximumReasonJSONBytes || evaluatedAtUnixMS < 0 || evaluatedAtUnixMS > MaximumGateEvaluationUnixMS {
		return GateDecision{}, ErrInvalidValue
	}
	var reasons []gate.ReasonCode
	if err := json.Unmarshal([]byte(reasonJSON), &reasons); err != nil {
		return GateDecision{}, ErrInvalidValue
	}
	canonical, err := json.Marshal(reasons)
	if err != nil || string(canonical) != reasonJSON {
		return GateDecision{}, ErrInvalidValue
	}
	classification, err := gate.DecodeClassification(uint32(version), sourceMetadataHash, inputHash, gate.Outcome(outcome), reasons)
	if err != nil {
		return GateDecision{}, ErrInvalidValue
	}
	return NewGateDecision(classification, evaluatedAtUnixMS)
}

func (decision GateDecision) Version() uint32                { return decision.version }
func (decision GateDecision) SourceMetadataHash() string     { return decision.sourceMetadataHash }
func (decision GateDecision) InputHash() string              { return decision.inputHash }
func (decision GateDecision) Outcome() gate.Outcome          { return decision.outcome }
func (decision GateDecision) ReasonCodes() []gate.ReasonCode { return slices.Clone(decision.reasons) }
func (decision GateDecision) ReasonJSON() string             { return decision.reasonJSON }
func (decision GateDecision) EvaluatedAtUnixMS() int64       { return decision.evaluatedAtUnixMS }
func (decision GateDecision) Revision() GateDecisionRevision {
	return GateDecisionRevision{version: decision.version, inputHash: decision.inputHash}
}
func (revision GateDecisionRevision) Version() uint32   { return revision.version }
func (revision GateDecisionRevision) InputHash() string { return revision.inputHash }

func (decision GateDecision) Equal(other GateDecision) bool {
	return decision.version == other.version && decision.sourceMetadataHash == other.sourceMetadataHash && decision.inputHash == other.inputHash && decision.outcome == other.outcome && slices.Equal(decision.reasons, other.reasons) && decision.reasonJSON == other.reasonJSON && decision.evaluatedAtUnixMS == other.evaluatedAtUnixMS
}

// SemanticEqual compares durable meaning while ignoring the first-observation timestamp.
func (decision GateDecision) SemanticEqual(other GateDecision) bool {
	return decision.version == other.version && decision.sourceMetadataHash == other.sourceMetadataHash && decision.inputHash == other.inputHash && decision.outcome == other.outcome && slices.Equal(decision.reasons, other.reasons) && decision.reasonJSON == other.reasonJSON
}

func (decision GateDecision) Valid() bool {
	decoded, err := DecodeGateDecision(int64(decision.version), decision.sourceMetadataHash, decision.inputHash, decision.outcome.String(), decision.reasonJSON, decision.evaluatedAtUnixMS)
	return err == nil && decision.Equal(decoded)
}

func (revision GateDecisionRevision) Valid() bool {
	return revision.version == gate.Version1 && validGateHash(revision.inputHash)
}

func (commit GateDecisionCommit) SourceAccountID() AccountID {
	accountID, _ := ParseAccountID(commit.Source.AccountID())
	return accountID
}

func (commit GateDecisionCommit) SourceGmailMessageID() string { return commit.Source.GmailMessageID() }

func ValidateGateDecisionCommit(commit GateDecisionCommit) error {
	accountID, err := ParseAccountID(commit.Source.AccountID())
	if err != nil || !accountID.valid() || ValidateGmailMessageID(commit.Source.GmailMessageID()) != nil || !commit.Source.Valid() || !commit.Next.Valid() || commit.Source.MetadataHash() != commit.Next.SourceMetadataHash() {
		return ErrInvalidValue
	}
	if commit.Expected != nil && !commit.Expected.Valid() {
		return ErrInvalidValue
	}
	return nil
}

func validGateHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range []byte(value) {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
