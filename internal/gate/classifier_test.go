package gate

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/mail"
)

func gateMessage(t *testing.T, mutate func(*mail.MessageInput)) mail.Message {
	t.Helper()
	input := mail.MessageInput{
		GmailMessageID: "synthetic-message", GmailThreadID: "synthetic-thread",
		SenderAddress: "Person <notice@mail.example.test>", To: []string{"owner@example.test"},
		Subject: "Please Review Today", Labels: []string{"CATEGORY_PROMOTIONS"},
		CC: []string{}, DeliveredTo: []string{},
	}
	if mutate != nil {
		mutate(&input)
	}
	message, err := mail.Normalize("00112233445566778899aabbccddeeff", input)
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func gatePolicy() config.Gate {
	policy := config.Defaults().Gate
	policy.SenderAllowDomains = []string{"example.test"}
	policy.SubjectCandidateTerms = []string{"review"}
	policy.SubjectUrgentTerms = []string{"today"}
	return policy
}

func TestVocabularyIsClosedAndBounded(t *testing.T) {
	outcomes := []Outcome{OutcomeIgnore, OutcomeMetadataOnly, OutcomeReviewCandidate, OutcomeUrgentReviewCandidate}
	for _, outcome := range outcomes {
		if !outcome.Valid() {
			t.Fatalf("supported outcome %q is invalid", outcome)
		}
	}
	if Outcome("other").Valid() || len(outcomes) != 4 {
		t.Fatal("outcome vocabulary is not closed")
	}
	reasons := []ReasonCode{
		ReasonExcludedLabel, ReasonSenderBlockDomain, ReasonSenderAllowDomain, ReasonBulkCategory,
		ReasonMailingList, ReasonAutomatedMessage, ReasonOwnerCandidateTerm, ReasonOwnerUrgentTerm,
		ReasonDirectRecipient, ReasonNoCandidateSignal,
	}
	for _, reason := range reasons {
		if !reason.Valid() || len(reason) > MaximumReasonCodeBytes {
			t.Fatalf("supported reason %q is invalid", reason)
		}
	}
	if ReasonCode("matched-example.test").Valid() || len(reasons) != MaximumReasonCodes || MaximumReasonCodes != 10 || MaximumReasonCodeBytes != 32 || MaximumReasonJSONBytes != 512 {
		t.Fatal("reason vocabulary or bounds are not closed")
	}
}

func TestClassifierKnownVectorAndCompleteSortedReasons(t *testing.T) {
	classification, err := Classify(gateMessage(t, nil), gatePolicy())
	if err != nil {
		t.Fatal(err)
	}
	wantReasons := []ReasonCode{ReasonBulkCategory, ReasonDirectRecipient, ReasonOwnerCandidateTerm, ReasonOwnerUrgentTerm, ReasonSenderAllowDomain}
	if classification.Version() != Version1 || classification.SourceMetadataHash() != "16757363f64e439299de341f3ab41eff1a3e4cc0fe05d1cb8ce635b6a86ab4da" || classification.InputHash() != "7e2e224906e81a5c447266f33cb9af81bd6f75231fb51655bd1294dc35a7af45" || classification.Outcome() != OutcomeUrgentReviewCandidate || !slices.Equal(classification.ReasonCodes(), wantReasons) {
		t.Fatalf("classification = version %d source %q input %q outcome %q reasons %q", classification.Version(), classification.SourceMetadataHash(), classification.InputHash(), classification.Outcome(), classification.ReasonCodes())
	}
	reasons := classification.ReasonCodes()
	reasons[0] = ReasonExcludedLabel
	if !slices.Equal(classification.ReasonCodes(), wantReasons) {
		t.Fatal("classification exposes mutable reason codes")
	}
}

func TestFixedPrecedenceAndConservativeSignals(t *testing.T) {
	tests := []struct {
		name   string
		policy func() config.Gate
		mutate func(*mail.MessageInput)
		want   Outcome
		reason ReasonCode
	}{
		{name: "spam exclusion", policy: gatePolicy, mutate: func(v *mail.MessageInput) { v.Labels = []string{"SPAM"} }, want: OutcomeIgnore, reason: ReasonExcludedLabel},
		{name: "trash exclusion", policy: gatePolicy, mutate: func(v *mail.MessageInput) { v.Labels = []string{"TRASH"} }, want: OutcomeIgnore, reason: ReasonExcludedLabel},
		{name: "configured exclusion", policy: func() config.Gate { p := gatePolicy(); p.ExcludedLabels = []string{"SYNTHETIC"}; return p }, mutate: func(v *mail.MessageInput) { v.Labels = []string{"SYNTHETIC"} }, want: OutcomeIgnore, reason: ReasonExcludedLabel},
		{name: "blocked domain wins", policy: func() config.Gate { p := gatePolicy(); p.SenderBlockDomains = []string{"mail.example.test"}; return p }, want: OutcomeIgnore, reason: ReasonSenderBlockDomain},
		{name: "allowed urgent", policy: gatePolicy, want: OutcomeUrgentReviewCandidate, reason: ReasonOwnerUrgentTerm},
		{name: "urgent alone follows bulk precedence", policy: func() config.Gate {
			p := gatePolicy()
			p.SenderAllowDomains = nil
			p.SubjectCandidateTerms = nil
			return p
		}, want: OutcomeMetadataOnly, reason: ReasonBulkCategory},
		{name: "urgent alone falls through to direct", policy: func() config.Gate {
			p := gatePolicy()
			p.SenderAllowDomains = nil
			p.SubjectCandidateTerms = nil
			p.SuppressGmailCategories = nil
			return p
		}, mutate: func(v *mail.MessageInput) { v.Labels = nil }, want: OutcomeReviewCandidate, reason: ReasonDirectRecipient},
		{name: "urgent alone is not an ordinary candidate", policy: func() config.Gate {
			p := gatePolicy()
			p.SenderAllowDomains = nil
			p.SubjectCandidateTerms = nil
			p.SuppressGmailCategories = nil
			p.DirectRecipientIsCandidate = false
			return p
		}, mutate: func(v *mail.MessageInput) { v.Labels = nil }, want: OutcomeMetadataOnly, reason: ReasonOwnerUrgentTerm},
		{name: "candidate overrides bulk", policy: gatePolicy, want: OutcomeReviewCandidate, reason: ReasonOwnerCandidateTerm, mutate: func(v *mail.MessageInput) { v.Subject = "please review" }},
		{name: "category suppresses direct", policy: func() config.Gate { p := config.Defaults().Gate; return p }, want: OutcomeMetadataOnly, reason: ReasonBulkCategory},
		{name: "list id suppresses", policy: func() config.Gate { p := config.Defaults().Gate; p.SuppressGmailCategories = nil; return p }, mutate: func(v *mail.MessageInput) { v.Labels = nil; v.ListID = "list.example.test" }, want: OutcomeMetadataOnly, reason: ReasonMailingList},
		{name: "list unsubscribe suppresses", policy: func() config.Gate { p := config.Defaults().Gate; p.SuppressGmailCategories = nil; return p }, mutate: func(v *mail.MessageInput) { v.Labels = nil; v.ListUnsubscribe = true }, want: OutcomeMetadataOnly, reason: ReasonMailingList},
		{name: "auto submitted suppresses", policy: func() config.Gate { p := config.Defaults().Gate; p.SuppressGmailCategories = nil; return p }, mutate: func(v *mail.MessageInput) { v.Labels = nil; v.AutoSubmitted = "auto-generated" }, want: OutcomeMetadataOnly, reason: ReasonAutomatedMessage},
		{name: "precedence suppresses", policy: func() config.Gate { p := config.Defaults().Gate; p.SuppressGmailCategories = nil; return p }, mutate: func(v *mail.MessageInput) { v.Labels = nil; v.Precedence = "LIST" }, want: OutcomeMetadataOnly, reason: ReasonAutomatedMessage},
		{name: "auto submitted no is absent", policy: func() config.Gate { p := config.Defaults().Gate; p.SuppressGmailCategories = nil; return p }, mutate: func(v *mail.MessageInput) { v.Labels = nil; v.AutoSubmitted = "NO" }, want: OutcomeReviewCandidate, reason: ReasonDirectRecipient},
		{name: "direct disabled", policy: func() config.Gate {
			p := config.Defaults().Gate
			p.SuppressGmailCategories = nil
			p.DirectRecipientIsCandidate = false
			return p
		}, mutate: func(v *mail.MessageInput) { v.Labels = nil }, want: OutcomeMetadataOnly, reason: ReasonNoCandidateSignal},
		{name: "missing optional metadata", policy: func() config.Gate { p := config.Defaults().Gate; p.SuppressGmailCategories = nil; return p }, mutate: func(v *mail.MessageInput) {
			*v = mail.MessageInput{GmailMessageID: v.GmailMessageID, GmailThreadID: v.GmailThreadID, To: []string{}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{}}
		}, want: OutcomeMetadataOnly, reason: ReasonNoCandidateSignal},
		{name: "empty recipients are not direct evidence", policy: func() config.Gate { p := config.Defaults().Gate; p.SuppressGmailCategories = nil; return p }, mutate: func(v *mail.MessageInput) {
			v.To = []string{""}
			v.CC = []string{""}
			v.DeliveredTo = []string{""}
			v.Labels = nil
		}, want: OutcomeMetadataOnly, reason: ReasonNoCandidateSignal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classification, err := Classify(gateMessage(t, tt.mutate), tt.policy())
			if err != nil {
				t.Fatal(err)
			}
			if classification.Outcome() != tt.want || !slices.Contains(classification.ReasonCodes(), tt.reason) {
				t.Fatalf("outcome=%q reasons=%q, want %q containing %q", classification.Outcome(), classification.ReasonCodes(), tt.want, tt.reason)
			}
		})
	}
}

func TestDomainMatchingIsBoundaryAwareAndBlockWins(t *testing.T) {
	tests := []struct {
		name, sender string
		allow, block []string
		want         Outcome
		reason       ReasonCode
	}{
		{name: "exact", sender: "person@EXAMPLE.TEST", allow: []string{"example.test"}, want: OutcomeReviewCandidate, reason: ReasonSenderAllowDomain},
		{name: "subdomain", sender: "person@Mail.Example.Test", allow: []string{"example.test"}, want: OutcomeReviewCandidate, reason: ReasonSenderAllowDomain},
		{name: "boundary", sender: "person@notexample.test", allow: []string{"example.test"}, want: OutcomeMetadataOnly, reason: ReasonNoCandidateSignal},
		{name: "malformed", sender: "person@@example.test", allow: []string{"example.test"}, want: OutcomeMetadataOnly, reason: ReasonNoCandidateSignal},
		{name: "quoted local part uses final at", sender: `"robot@campaign"@news.blocked.test`, block: []string{"blocked.test"}, want: OutcomeIgnore, reason: ReasonSenderBlockDomain},
		{name: "ancestor block wins", sender: "person@news.mail.example.test", allow: []string{"mail.example.test"}, block: []string{"example.test"}, want: OutcomeIgnore, reason: ReasonSenderBlockDomain},
		{name: "descendant block wins", sender: "person@news.mail.example.test", allow: []string{"example.test"}, block: []string{"news.mail.example.test"}, want: OutcomeIgnore, reason: ReasonSenderBlockDomain},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := config.Defaults().Gate
			policy.SuppressGmailCategories = nil
			policy.DirectRecipientIsCandidate = false
			policy.SenderAllowDomains = tt.allow
			policy.SenderBlockDomains = tt.block
			classification, err := Classify(gateMessage(t, func(v *mail.MessageInput) { v.SenderAddress = tt.sender; v.Subject = ""; v.Labels = nil }), policy)
			if err != nil {
				t.Fatal(err)
			}
			if classification.Outcome() != tt.want || !slices.Contains(classification.ReasonCodes(), tt.reason) {
				t.Fatalf("outcome=%q reasons=%q", classification.Outcome(), classification.ReasonCodes())
			}
		})
	}
}

func TestSubjectTermsUseLiteralUnicodeEqualFoldWithoutNormalization(t *testing.T) {
	policy := config.Defaults().Gate
	policy.SuppressGmailCategories = nil
	policy.DirectRecipientIsCandidate = false
	policy.SubjectCandidateTerms = []string{"straße", "[x].*"}
	for _, subject := range []string{"Bitte STRAẞE prüfen", "literal [X].* value"} {
		classification, err := Classify(gateMessage(t, func(v *mail.MessageInput) { v.Subject = subject; v.Labels = nil }), policy)
		if err != nil || classification.Outcome() != OutcomeReviewCandidate {
			t.Fatalf("subject %q classification=%#v err=%v", subject, classification, err)
		}
	}
	classification, err := Classify(gateMessage(t, func(v *mail.MessageInput) { v.Subject = "Cafe\u0301"; v.Labels = nil }), func() config.Gate { p := policy; p.SubjectCandidateTerms = []string{"Café"}; return p }())
	if err != nil || classification.Outcome() != OutcomeMetadataOnly {
		t.Fatalf("normalization-equivalent subject matched: %#v %v", classification, err)
	}
}

func TestValidatePolicyRejectsEqualFoldDuplicateSubjectTerms(t *testing.T) {
	for _, list := range []struct {
		name string
		set  func(*config.Gate, []string)
	}{
		{name: "candidate", set: func(policy *config.Gate, terms []string) { policy.SubjectCandidateTerms = terms }},
		{name: "urgent", set: func(policy *config.Gate, terms []string) { policy.SubjectUrgentTerms = terms }},
	} {
		for _, terms := range [][]string{{"review", "REVIEW"}, {"straße", "STRAẞE"}} {
			t.Run(list.name+"/"+terms[0], func(t *testing.T) {
				policy := config.Defaults().Gate
				list.set(&policy, terms)
				if err := ValidatePolicy(policy); !errors.Is(err, ErrInvalidClassification) {
					t.Fatalf("ValidatePolicy(%q) error = %v, want ErrInvalidClassification", terms, err)
				}
				if _, err := Classify(gateMessage(t, nil), policy); !errors.Is(err, ErrInvalidClassification) {
					t.Fatalf("Classify(%q) error = %v, want ErrInvalidClassification", terms, err)
				}
			})
		}
	}
}

func TestSubjectTermMatchingAtPublishedBoundsIsStructurallyBounded(t *testing.T) {
	if MaximumFoldedSubjectBytes != 16384 || MaximumFoldedTermBytes != 512 || MaximumSubjectTermSearches != 512 {
		t.Fatal("published literal matching bounds changed")
	}
	terms := make([]string, 256)
	for index := range terms {
		terms[index] = strings.Repeat("a", 124) + fmt.Sprintf("%04x", index)
	}
	policy := config.Defaults().Gate
	policy.SuppressGmailCategories = nil
	policy.DirectRecipientIsCandidate = false
	policy.SubjectCandidateTerms = slices.Clone(terms)
	policy.SubjectUrgentTerms = slices.Clone(terms)
	message := gateMessage(t, func(value *mail.MessageInput) {
		value.Subject = strings.Repeat("a", 4096)
		value.Labels = nil
	})
	classification, err := Classify(message, policy)
	if err != nil || classification.Outcome() != OutcomeMetadataOnly {
		t.Fatalf("classification=%#v err=%v", classification, err)
	}
	foldedSubject, ok := foldLiteral(strings.Repeat("a", 4096), MaximumFoldedSubjectBytes)
	if !ok || len(foldedSubject) > MaximumFoldedSubjectBytes {
		t.Fatalf("folded subject bytes = %d", len(foldedSubject))
	}
	_, candidateSearches, candidateOK := containsAnyFold(foldedSubject, terms)
	_, urgentSearches, urgentOK := containsAnyFold(foldedSubject, terms)
	if !candidateOK || !urgentOK || candidateSearches+urgentSearches != MaximumSubjectTermSearches {
		t.Fatalf("literal searches = %d + %d", candidateSearches, urgentSearches)
	}
	allocations := testing.AllocsPerRun(3, func() {
		folded, valid := foldLiteral(strings.Repeat("a", 4096), MaximumFoldedSubjectBytes)
		if !valid {
			panic("valid maximum subject rejected")
		}
		_, _, _ = containsAnyFold(folded, terms)
		_, _, _ = containsAnyFold(folded, terms)
	})
	if allocations > 530 {
		t.Fatalf("maximum-bound literal allocations = %.0f, want at most 530", allocations)
	}
}

func TestInputHashBindsEveryPolicyAndMetadataFieldButNotListOrder(t *testing.T) {
	message := gateMessage(t, nil)
	base := gatePolicy()
	baseline, err := Classify(message, base)
	if err != nil {
		t.Fatal(err)
	}
	reordered := base
	reordered.ExcludedLabels = []string{"TRASH", "SPAM"}
	reordered.SuppressGmailCategories = []string{"CATEGORY_SOCIAL", "CATEGORY_PROMOTIONS"}
	reordered.SubjectCandidateTerms = []string{"z", "review"}
	ordered := base
	ordered.SubjectCandidateTerms = []string{"review", "z"}
	a, _ := Classify(message, reordered)
	b, _ := Classify(message, ordered)
	if a.InputHash() != b.InputHash() {
		t.Fatal("configuration list order changed input hash")
	}
	mutations := []func(*config.Gate){
		func(p *config.Gate) { p.ExcludedLabels = append(p.ExcludedLabels, "SYNTHETIC") },
		func(p *config.Gate) {
			p.SuppressGmailCategories = append(p.SuppressGmailCategories, "CATEGORY_UPDATES")
		},
		func(p *config.Gate) { p.DirectRecipientIsCandidate = !p.DirectRecipientIsCandidate },
		func(p *config.Gate) { p.MailingListIsBulkSignal = !p.MailingListIsBulkSignal },
		func(p *config.Gate) { p.SenderAllowDomains = append(p.SenderAllowDomains, "other.test") },
		func(p *config.Gate) { p.SenderBlockDomains = append(p.SenderBlockDomains, "blocked.test") },
		func(p *config.Gate) { p.SubjectCandidateTerms = append(p.SubjectCandidateTerms, "other") },
		func(p *config.Gate) { p.SubjectUrgentTerms = append(p.SubjectUrgentTerms, "soon") },
	}
	for index, mutate := range mutations {
		changed := base
		changed.ExcludedLabels = slices.Clone(base.ExcludedLabels)
		changed.SuppressGmailCategories = slices.Clone(base.SuppressGmailCategories)
		changed.SenderAllowDomains = slices.Clone(base.SenderAllowDomains)
		changed.SenderBlockDomains = slices.Clone(base.SenderBlockDomains)
		changed.SubjectCandidateTerms = slices.Clone(base.SubjectCandidateTerms)
		changed.SubjectUrgentTerms = slices.Clone(base.SubjectUrgentTerms)
		mutate(&changed)
		got, classifyErr := Classify(message, changed)
		if classifyErr != nil || got.InputHash() == baseline.InputHash() {
			t.Fatalf("policy mutation %d did not change input hash: %v", index, classifyErr)
		}
	}
	changedMessage := gateMessage(t, func(v *mail.MessageInput) { v.Subject += " changed" })
	changed, err := Classify(changedMessage, base)
	if err != nil || changed.SourceMetadataHash() == baseline.SourceMetadataHash() || changed.InputHash() == baseline.InputHash() {
		t.Fatalf("metadata change did not change hashes: %v", err)
	}
}

func TestDecodeClassificationRejectsMalformedSemanticValues(t *testing.T) {
	valid, err := Classify(gateMessage(t, nil), gatePolicy())
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name    string
		version uint32
		source  string
		input   string
		outcome Outcome
		reasons []ReasonCode
	}{
		{name: "version", version: 2, source: valid.SourceMetadataHash(), input: valid.InputHash(), outcome: valid.Outcome(), reasons: valid.ReasonCodes()},
		{name: "source hash", version: 1, source: "A" + valid.SourceMetadataHash()[1:], input: valid.InputHash(), outcome: valid.Outcome(), reasons: valid.ReasonCodes()},
		{name: "input hash", version: 1, source: valid.SourceMetadataHash(), input: valid.InputHash()[:63], outcome: valid.Outcome(), reasons: valid.ReasonCodes()},
		{name: "outcome", version: 1, source: valid.SourceMetadataHash(), input: valid.InputHash(), outcome: "other", reasons: valid.ReasonCodes()},
		{name: "empty reasons", version: 1, source: valid.SourceMetadataHash(), input: valid.InputHash(), outcome: valid.Outcome()},
		{name: "duplicate reasons", version: 1, source: valid.SourceMetadataHash(), input: valid.InputHash(), outcome: valid.Outcome(), reasons: []ReasonCode{ReasonBulkCategory, ReasonBulkCategory}},
		{name: "unsorted reasons", version: 1, source: valid.SourceMetadataHash(), input: valid.InputHash(), outcome: valid.Outcome(), reasons: []ReasonCode{ReasonSenderAllowDomain, ReasonBulkCategory}},
		{name: "unknown reason", version: 1, source: valid.SourceMetadataHash(), input: valid.InputHash(), outcome: valid.Outcome(), reasons: []ReasonCode{"sensitive-value"}},
		{name: "no signal mixed", version: 1, source: valid.SourceMetadataHash(), input: valid.InputHash(), outcome: valid.Outcome(), reasons: []ReasonCode{ReasonBulkCategory, ReasonNoCandidateSignal}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, decodeErr := DecodeClassification(tt.version, tt.source, tt.input, tt.outcome, tt.reasons); !errors.Is(decodeErr, ErrInvalidClassification) {
				t.Fatalf("DecodeClassification() error = %v", decodeErr)
			}
		})
	}
}
