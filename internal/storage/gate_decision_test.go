package storage

import (
	"errors"
	"testing"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/gate"
	"github.com/mandloideep/inboxgate/internal/mail"
)

func storageGateFixture(t *testing.T) (mail.Message, gate.Classification, GateDecision) {
	t.Helper()
	message, err := mail.Normalize("00112233445566778899aabbccddeeff", mail.MessageInput{
		GmailMessageID: "synthetic-message", GmailThreadID: "synthetic-thread", SenderAddress: "person@example.test",
		To: []string{"owner@example.test"}, CC: []string{}, DeliveredTo: []string{}, Subject: "review", Labels: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := config.Defaults().Gate
	policy.SenderAllowDomains = []string{"example.test"}
	policy.SubjectCandidateTerms = []string{"review"}
	classification, err := gate.Classify(message, policy)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := NewGateDecision(classification, 1700000000123)
	if err != nil {
		t.Fatal(err)
	}
	return message, classification, decision
}

func TestGateDecisionRoundTripAndCanonicalReasons(t *testing.T) {
	_, classification, decision := storageGateFixture(t)
	if decision.Version() != gate.Version1 || decision.SourceMetadataHash() != classification.SourceMetadataHash() || decision.InputHash() != classification.InputHash() || decision.Outcome() != classification.Outcome() || decision.EvaluatedAtUnixMS() != 1700000000123 {
		t.Fatalf("decision = %#v", decision)
	}
	if decision.ReasonJSON() != `["direct_recipient","owner_candidate_term","sender_allow_domain"]` {
		t.Fatalf("ReasonJSON() = %q", decision.ReasonJSON())
	}
	decoded, err := DecodeGateDecision(int64(decision.Version()), decision.SourceMetadataHash(), decision.InputHash(), decision.Outcome().String(), decision.ReasonJSON(), decision.EvaluatedAtUnixMS())
	if err != nil || !decision.Equal(decoded) {
		t.Fatalf("DecodeGateDecision() = %#v, %v", decoded, err)
	}
	reasons := decision.ReasonCodes()
	reasons[0] = gate.ReasonExcludedLabel
	if decision.ReasonCodes()[0] != gate.ReasonDirectRecipient {
		t.Fatal("decision exposes mutable reasons")
	}
	revision := decision.Revision()
	if revision.Version() != decision.Version() || revision.InputHash() != decision.InputHash() || !revision.Valid() {
		t.Fatalf("revision = %#v", revision)
	}
}

func TestGateDecisionRejectsMalformedDurableValues(t *testing.T) {
	_, _, valid := storageGateFixture(t)
	tests := []struct {
		name, source, input, outcome, reasons string
		version, timestamp                    int64
	}{
		{name: "zero version", version: 0, source: valid.SourceMetadataHash(), input: valid.InputHash(), outcome: valid.Outcome().String(), reasons: valid.ReasonJSON(), timestamp: 1},
		{name: "unsupported version", version: 2, source: valid.SourceMetadataHash(), input: valid.InputHash(), outcome: valid.Outcome().String(), reasons: valid.ReasonJSON(), timestamp: 1},
		{name: "source", version: 1, source: valid.SourceMetadataHash()[:63], input: valid.InputHash(), outcome: valid.Outcome().String(), reasons: valid.ReasonJSON(), timestamp: 1},
		{name: "input", version: 1, source: valid.SourceMetadataHash(), input: "A" + valid.InputHash()[1:], outcome: valid.Outcome().String(), reasons: valid.ReasonJSON(), timestamp: 1},
		{name: "outcome", version: 1, source: valid.SourceMetadataHash(), input: valid.InputHash(), outcome: "other", reasons: valid.ReasonJSON(), timestamp: 1},
		{name: "noncanonical json", version: 1, source: valid.SourceMetadataHash(), input: valid.InputHash(), outcome: valid.Outcome().String(), reasons: `[ "direct_recipient" ]`, timestamp: 1},
		{name: "unknown reason", version: 1, source: valid.SourceMetadataHash(), input: valid.InputHash(), outcome: valid.Outcome().String(), reasons: `["private-value"]`, timestamp: 1},
		{name: "nul", version: 1, source: valid.SourceMetadataHash(), input: valid.InputHash(), outcome: valid.Outcome().String(), reasons: "[\"direct_recipient\"]\x00", timestamp: 1},
		{name: "negative timestamp", version: 1, source: valid.SourceMetadataHash(), input: valid.InputHash(), outcome: valid.Outcome().String(), reasons: valid.ReasonJSON(), timestamp: -1},
		{name: "late timestamp", version: 1, source: valid.SourceMetadataHash(), input: valid.InputHash(), outcome: valid.Outcome().String(), reasons: valid.ReasonJSON(), timestamp: MaximumGateEvaluationUnixMS + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecodeGateDecision(tt.version, tt.source, tt.input, tt.outcome, tt.reasons, tt.timestamp); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("DecodeGateDecision() error = %v", err)
			}
		})
	}
}

func TestPrepareGateDecisionCommitBindsSourceClassificationAndRevision(t *testing.T) {
	message, _, decision := storageGateFixture(t)
	commit := GateDecisionCommit{Source: message, Next: decision}
	if err := ValidateGateDecisionCommit(commit); err != nil {
		t.Fatal(err)
	}
	other, _ := mail.Normalize(message.AccountID(), mail.MessageInput{GmailMessageID: message.GmailMessageID(), GmailThreadID: message.GmailThreadID(), Subject: "changed", To: []string{}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{}})
	if err := ValidateGateDecisionCommit(GateDecisionCommit{Source: other, Next: decision}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("mismatched source error = %v", err)
	}
}
