// Package gate classifies bounded normalized message metadata with one fixed policy.
package gate

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"net"
	netmail "net/mail"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/mail"
)

const (
	Version1                   uint32 = 1
	MaximumReasonCodes                = 10
	MaximumReasonCodeBytes            = 32
	MaximumReasonJSONBytes            = 512
	MaximumFoldedSubjectBytes         = 16384
	MaximumFoldedTermBytes            = 512
	MaximumSubjectTermSearches        = 512
	inputHashDomain                   = "inboxgate/gate-input/v1"
)

var ErrInvalidClassification = errors.New("gate: invalid classification")

type Outcome string

const (
	OutcomeIgnore                Outcome = "ignore"
	OutcomeMetadataOnly          Outcome = "metadata_only"
	OutcomeReviewCandidate       Outcome = "review_candidate"
	OutcomeUrgentReviewCandidate Outcome = "urgent_review_candidate"
)

func (outcome Outcome) String() string { return string(outcome) }

func (outcome Outcome) Valid() bool {
	switch outcome {
	case OutcomeIgnore, OutcomeMetadataOnly, OutcomeReviewCandidate, OutcomeUrgentReviewCandidate:
		return true
	default:
		return false
	}
}

type ReasonCode string

const (
	ReasonExcludedLabel      ReasonCode = "excluded_label"
	ReasonSenderBlockDomain  ReasonCode = "sender_block_domain"
	ReasonSenderAllowDomain  ReasonCode = "sender_allow_domain"
	ReasonBulkCategory       ReasonCode = "bulk_category"
	ReasonMailingList        ReasonCode = "mailing_list"
	ReasonAutomatedMessage   ReasonCode = "automated_message"
	ReasonOwnerCandidateTerm ReasonCode = "owner_candidate_term"
	ReasonOwnerUrgentTerm    ReasonCode = "owner_urgent_term"
	ReasonDirectRecipient    ReasonCode = "direct_recipient"
	ReasonNoCandidateSignal  ReasonCode = "no_candidate_signal"
)

func (reason ReasonCode) String() string { return string(reason) }

func (reason ReasonCode) Valid() bool {
	switch reason {
	case ReasonExcludedLabel, ReasonSenderBlockDomain, ReasonSenderAllowDomain, ReasonBulkCategory, ReasonMailingList, ReasonAutomatedMessage, ReasonOwnerCandidateTerm, ReasonOwnerUrgentTerm, ReasonDirectRecipient, ReasonNoCandidateSignal:
		return true
	default:
		return false
	}
}

// Classification is one immutable versioned semantic result.
type Classification struct {
	version            uint32
	sourceMetadataHash string
	inputHash          string
	outcome            Outcome
	reasons            []ReasonCode
}

func (classification Classification) Version() uint32 { return classification.version }
func (classification Classification) SourceMetadataHash() string {
	return classification.sourceMetadataHash
}
func (classification Classification) InputHash() string { return classification.inputHash }
func (classification Classification) Outcome() Outcome  { return classification.outcome }
func (classification Classification) ReasonCodes() []ReasonCode {
	return slices.Clone(classification.reasons)
}

func (classification Classification) Equal(other Classification) bool {
	return classification.version == other.version && classification.sourceMetadataHash == other.sourceMetadataHash && classification.inputHash == other.inputHash && classification.outcome == other.outcome && slices.Equal(classification.reasons, other.reasons)
}

func (classification Classification) Valid() bool {
	decoded, err := DecodeClassification(classification.version, classification.sourceMetadataHash, classification.inputHash, classification.outcome, classification.reasons)
	return err == nil && classification.Equal(decoded)
}

// Classify applies gate version 1 to one canonical message.
func Classify(message mail.Message, policy config.Gate) (Classification, error) {
	if !message.Valid() || ValidatePolicy(policy) != nil {
		return Classification{}, ErrInvalidClassification
	}
	projection, err := message.GateProjection()
	if err != nil {
		return Classification{}, ErrInvalidClassification
	}
	reasons := make([]ReasonCode, 0, MaximumReasonCodes)
	hasExcluded := intersectsExact(projection.Labels(), policy.ExcludedLabels)
	if hasExcluded {
		reasons = append(reasons, ReasonExcludedLabel)
	}
	domain := senderDomain(projection.SenderAddress())
	hasBlock := domain != "" && matchesAnyDomain(domain, policy.SenderBlockDomains)
	hasAllow := domain != "" && matchesAnyDomain(domain, policy.SenderAllowDomains)
	if hasBlock {
		reasons = append(reasons, ReasonSenderBlockDomain)
	}
	if hasAllow {
		reasons = append(reasons, ReasonSenderAllowDomain)
	}
	hasBulkCategory := intersectsExact(projection.Labels(), policy.SuppressGmailCategories)
	if hasBulkCategory {
		reasons = append(reasons, ReasonBulkCategory)
	}
	hasMailingList := policy.MailingListIsBulkSignal && (projection.ListID() != "" || projection.ListUnsubscribe())
	if hasMailingList {
		reasons = append(reasons, ReasonMailingList)
	}
	hasAutomated := automated(projection.AutoSubmitted(), projection.Precedence())
	if hasAutomated {
		reasons = append(reasons, ReasonAutomatedMessage)
	}
	foldedSubject, ok := foldLiteral(projection.Subject(), MaximumFoldedSubjectBytes)
	if !ok {
		return Classification{}, ErrInvalidClassification
	}
	hasCandidateTerm, candidateSearches, ok := containsAnyFold(foldedSubject, policy.SubjectCandidateTerms)
	if !ok || candidateSearches > MaximumSubjectTermSearches/2 {
		return Classification{}, ErrInvalidClassification
	}
	if hasCandidateTerm {
		reasons = append(reasons, ReasonOwnerCandidateTerm)
	}
	hasUrgentTerm, urgentSearches, ok := containsAnyFold(foldedSubject, policy.SubjectUrgentTerms)
	if !ok || candidateSearches+urgentSearches > MaximumSubjectTermSearches {
		return Classification{}, ErrInvalidClassification
	}
	if hasUrgentTerm {
		reasons = append(reasons, ReasonOwnerUrgentTerm)
	}
	hasDirect := policy.DirectRecipientIsCandidate && hasUsableRecipient(projection.To(), projection.CC(), projection.DeliveredTo())
	if hasDirect {
		reasons = append(reasons, ReasonDirectRecipient)
	}
	if len(reasons) == 0 {
		reasons = append(reasons, ReasonNoCandidateSignal)
	}
	slices.Sort(reasons)

	var outcome Outcome
	switch {
	case hasExcluded || hasBlock:
		outcome = OutcomeIgnore
	case hasAllow && hasUrgentTerm:
		outcome = OutcomeUrgentReviewCandidate
	case hasAllow || hasCandidateTerm:
		outcome = OutcomeReviewCandidate
	case hasBulkCategory || hasMailingList || hasAutomated:
		outcome = OutcomeMetadataOnly
	case policy.DirectRecipientIsCandidate && hasDirect:
		outcome = OutcomeReviewCandidate
	default:
		outcome = OutcomeMetadataOnly
	}
	return DecodeClassification(Version1, message.MetadataHash(), deriveInputHash(message.MetadataHash(), policy), outcome, reasons)
}

// DecodeClassification validates one complete durable semantic value.
func DecodeClassification(version uint32, sourceMetadataHash, inputHash string, outcome Outcome, reasons []ReasonCode) (Classification, error) {
	if version != Version1 || !validLowerHex(sourceMetadataHash) || !validLowerHex(inputHash) || !outcome.Valid() || len(reasons) == 0 || len(reasons) > MaximumReasonCodes {
		return Classification{}, ErrInvalidClassification
	}
	copyReasons := slices.Clone(reasons)
	for index, reason := range copyReasons {
		if !reason.Valid() || len(reason) > MaximumReasonCodeBytes || (index > 0 && copyReasons[index-1] >= reason) {
			return Classification{}, ErrInvalidClassification
		}
	}
	if slices.Contains(copyReasons, ReasonNoCandidateSignal) && len(copyReasons) != 1 {
		return Classification{}, ErrInvalidClassification
	}
	return Classification{version: version, sourceMetadataHash: sourceMetadataHash, inputHash: inputHash, outcome: outcome, reasons: copyReasons}, nil
}

// ValidatePolicy validates the complete gate policy without accepting a broader configuration.
func ValidatePolicy(policy config.Gate) error {
	if policy.Version != uint64(Version1) || !validUniqueLabels(policy.ExcludedLabels, 32) || !validCategories(policy.SuppressGmailCategories) || !validDomains(policy.SenderAllowDomains) || !validDomains(policy.SenderBlockDomains) || !validTerms(policy.SubjectCandidateTerms) || !validTerms(policy.SubjectUrgentTerms) {
		return ErrInvalidClassification
	}
	allow := make(map[string]struct{}, len(policy.SenderAllowDomains))
	for _, domain := range policy.SenderAllowDomains {
		allow[domain] = struct{}{}
	}
	for _, domain := range policy.SenderBlockDomains {
		if _, exists := allow[domain]; exists {
			return ErrInvalidClassification
		}
	}
	return nil
}

func deriveInputHash(source string, policy config.Gate) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(inputHashDomain))
	_, _ = digest.Write([]byte{0})
	writeUint32(digest, Version1)
	writeLengthPrefixed(digest, source)
	writeBool(digest, policy.DirectRecipientIsCandidate)
	writeBool(digest, policy.MailingListIsBulkSignal)
	writeList(digest, "excluded_labels", policy.ExcludedLabels)
	writeList(digest, "suppress_gmail_categories", policy.SuppressGmailCategories)
	writeList(digest, "sender_allow_domains", policy.SenderAllowDomains)
	writeList(digest, "sender_block_domains", policy.SenderBlockDomains)
	writeList(digest, "subject_candidate_terms", policy.SubjectCandidateTerms)
	writeList(digest, "subject_urgent_terms", policy.SubjectUrgentTerms)
	return hex.EncodeToString(digest.Sum(nil))
}

func writeUint32(writer hash.Hash, value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	_, _ = writer.Write(encoded[:])
}

func writeLengthPrefixed(writer hash.Hash, value string) {
	writeUint32(writer, uint32(len(value)))
	_, _ = writer.Write([]byte(value))
}

func writeBool(writer hash.Hash, value bool) {
	if value {
		_, _ = writer.Write([]byte{1})
		return
	}
	_, _ = writer.Write([]byte{0})
}

func writeList(writer hash.Hash, name string, values []string) {
	writeLengthPrefixed(writer, name)
	ordered := slices.Clone(values)
	slices.Sort(ordered)
	writeUint32(writer, uint32(len(ordered)))
	for _, value := range ordered {
		writeLengthPrefixed(writer, value)
	}
}

func intersectsExact(left, right []string) bool {
	set := make(map[string]struct{}, len(right))
	for _, value := range right {
		set[value] = struct{}{}
	}
	for _, value := range left {
		if _, exists := set[value]; exists {
			return true
		}
	}
	return false
}

func senderDomain(value string) string {
	value = strings.TrimSpace(value)
	address, err := netmail.ParseAddress(value)
	if err != nil {
		return ""
	}
	separator := strings.LastIndexByte(address.Address, '@')
	if separator <= 0 || separator == len(address.Address)-1 {
		return ""
	}
	domain := strings.ToLower(address.Address[separator+1:])
	if !validDomain(domain) {
		return ""
	}
	return domain
}

func hasUsableRecipient(lists ...[]string) bool {
	for _, values := range lists {
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				return true
			}
		}
	}
	return false
}

func matchesAnyDomain(domain string, policies []string) bool {
	for _, policy := range policies {
		if domain == policy || strings.HasSuffix(domain, "."+policy) {
			return true
		}
	}
	return false
}

func automated(autoSubmitted, precedence string) bool {
	autoSubmitted = strings.TrimSpace(autoSubmitted)
	if autoSubmitted != "" && !strings.EqualFold(autoSubmitted, "no") {
		return true
	}
	for _, value := range []string{"bulk", "junk", "list"} {
		if strings.EqualFold(strings.TrimSpace(precedence), value) {
			return true
		}
	}
	return false
}

func containsAnyFold(foldedSubject string, terms []string) (bool, int, bool) {
	for index, term := range terms {
		foldedTerm, ok := foldLiteral(term, MaximumFoldedTermBytes)
		if !ok {
			return false, index, false
		}
		if strings.Contains(foldedSubject, foldedTerm) {
			return true, index + 1, true
		}
	}
	return false, len(terms), true
}

func foldLiteral(value string, maximumBytes int) (string, bool) {
	var folded strings.Builder
	folded.Grow(len(value))
	for _, character := range value {
		canonical := canonicalFoldRune(character)
		if folded.Len()+utf8.RuneLen(canonical) > maximumBytes {
			return "", false
		}
		folded.WriteRune(canonical)
	}
	return folded.String(), true
}

func canonicalFoldRune(value rune) rune {
	canonical := value
	for folded := unicode.SimpleFold(value); folded != value; folded = unicode.SimpleFold(folded) {
		if folded < canonical {
			canonical = folded
		}
	}
	return canonical
}

func validLowerHex(value string) bool {
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

func validUniqueLabels(values []string, maximum int) bool {
	if len(values) > maximum {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if len(value) == 0 || len(value) > 128 {
			return false
		}
		for _, character := range []byte(value) {
			if !(character >= 'A' && character <= 'Z') && !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '_' && character != '-' {
				return false
			}
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validCategories(values []string) bool {
	if len(values) > 5 {
		return false
	}
	allowed := map[string]struct{}{"CATEGORY_FORUMS": {}, "CATEGORY_PERSONAL": {}, "CATEGORY_PROMOTIONS": {}, "CATEGORY_SOCIAL": {}, "CATEGORY_UPDATES": {}}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := allowed[value]; !exists {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validDomains(values []string) bool {
	if len(values) > 256 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validDomain(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validDomain(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) || net.ParseIP(value) != nil || strings.ContainsAny(value, ":/*_@") || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, character := range []byte(value) {
		if character > 0x7f {
			return false
		}
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range []byte(label) {
			if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validTerms(values []string) bool {
	if len(values) > 256 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || len(value) > 128 || value != strings.TrimSpace(value) || !utf8.ValidString(value) {
			return false
		}
		for _, character := range value {
			if unicode.IsControl(character) {
				return false
			}
		}
		folded, ok := foldLiteral(value, MaximumFoldedTermBytes)
		if !ok {
			return false
		}
		if _, exists := seen[folded]; exists {
			return false
		}
		seen[folded] = struct{}{}
	}
	return true
}
