package reviewinspect

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/gate"
	"github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
)

const (
	reviewAccountA = "0000000000000000000000000000000a"
	reviewAccountB = "0000000000000000000000000000000b"
)

type reviewSourceStub struct {
	rows        []storage.ReviewCandidateRow
	reason      storage.CurrentGateInspection
	err         error
	listCalls   atomic.Int64
	reasonCalls atomic.Int64
	wait        bool
	queries     []storage.ReviewCandidateQuery
}

func (source *reviewSourceStub) ListReviewCandidates(ctx context.Context, query storage.ReviewCandidateQuery) ([]storage.ReviewCandidateRow, error) {
	source.listCalls.Add(1)
	source.queries = append(source.queries, query)
	if source.wait {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return append([]storage.ReviewCandidateRow(nil), source.rows...), source.err
}

func (source *reviewSourceStub) GetCurrentGateInspection(ctx context.Context, accountID storage.AccountID, gmailMessageID string) (storage.CurrentGateInspection, error) {
	source.reasonCalls.Add(1)
	if source.wait {
		<-ctx.Done()
		return storage.CurrentGateInspection{}, ctx.Err()
	}
	return source.reason, source.err
}

func reviewMessage(t *testing.T, accountID, threadID, messageID, senderDisplay, subject string, date int64, attachments uint16) mail.Message {
	t.Helper()
	message, err := mail.Normalize(accountID, mail.MessageInput{
		GmailMessageID: messageID, GmailThreadID: threadID, InternalDateMS: date,
		SenderDisplay: senderDisplay, SenderAddress: "sender@example.test", To: []string{"owner@example.test"},
		Subject: subject, Labels: []string{"INBOX"}, AttachmentCount: attachments,
	})
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func reviewDecision(t *testing.T, message mail.Message, policy config.Gate, evaluated int64) storage.GateDecision {
	t.Helper()
	classification, err := gate.Classify(message, policy)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := storage.NewGateDecision(classification, evaluated)
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

func reviewRow(t *testing.T, accountID, threadID, messageID string, date int64) storage.ReviewCandidateRow {
	t.Helper()
	message := reviewMessage(t, accountID, threadID, messageID, "Sender", "Subject", date, 1)
	return storage.ReviewCandidateRow{Message: message, Decision: reviewDecision(t, message, config.Defaults().Gate, 1000)}
}

func reviewService(t *testing.T, source *reviewSourceStub, mutate ...func(*config.Config)) *Service {
	t.Helper()
	configuration := config.Defaults()
	configuration.MCP.Enabled = true
	configuration.Capabilities.MailReviewRead = true
	for _, apply := range mutate {
		apply(&configuration)
	}
	service, err := New(source, configuration.Gate, configuration.Review)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestListNormalizesClosedFiltersAndUsesOneFixedBoundedQuery(t *testing.T) {
	source := &reviewSourceStub{}
	service := reviewService(t, source)
	minimum := int64(10)
	maximum := int64(20)
	page, err := service.List(context.Background(), ListRequest{
		AccountIDs: []string{reviewAccountA, reviewAccountB}, Urgency: UrgencyAll,
		InternalDateMinUnixMS: &minimum, InternalDateMaxUnixMS: &maximum, PageSize: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if source.listCalls.Load() != 1 || source.reasonCalls.Load() != 0 || len(source.queries) != 1 {
		t.Fatalf("calls = list %d reason %d queries %d", source.listCalls.Load(), source.reasonCalls.Load(), len(source.queries))
	}
	query := source.queries[0]
	if query.Limit() != 101 || query.Urgency() != storage.ReviewUrgencyAll || len(query.AccountIDs()) != 2 || query.After().Present {
		t.Fatalf("query = %#v", query)
	}
	if page.OutputVersion != OutputVersion1 || page.Candidates == nil || len(page.Candidates) != 0 || page.NextCursor != nil {
		t.Fatalf("empty page = %#v", page)
	}
}

func TestListRequestRejectsSelectorUrgencyDatePageAndCursorBoundsBeforeSource(t *testing.T) {
	validAccounts := make([]string, 16)
	for index := range validAccounts {
		validAccounts[index] = strings.Repeat("0", 30) + byteHex(index+1)
	}
	tooMany := append(append([]string(nil), validAccounts...), strings.Repeat("f", 32))
	minimum := int64(11)
	maximum := int64(10)
	negative := int64(-1)
	overDate := int64(MaximumInternalDateUnixMS + 1)
	tests := []ListRequest{
		{AccountIDs: []string{}},
		{AccountIDs: tooMany},
		{AccountIDs: []string{reviewAccountA, reviewAccountA}},
		{AccountIDs: []string{reviewAccountB, reviewAccountA}},
		{AccountIDs: []string{strings.ToUpper(reviewAccountA)}},
		{Urgency: "URGENT"},
		{Urgency: "other"},
		{InternalDateMinUnixMS: &minimum, InternalDateMaxUnixMS: &maximum},
		{InternalDateMinUnixMS: &negative},
		{InternalDateMaxUnixMS: &overDate},
		{PageSize: 11},
		{Cursor: strings.Repeat("x", MaximumCursorBytes+1)},
		{Cursor: "igrc1.="},
		{Cursor: "other.AA"},
	}
	for index, request := range tests {
		source := &reviewSourceStub{}
		service := reviewService(t, source)
		if _, err := service.List(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("case %d error = %v", index, err)
		}
		if source.listCalls.Load() != 0 {
			t.Errorf("case %d source calls = %d", index, source.listCalls.Load())
		}
	}
}

func byteHex(value int) string {
	const alphabet = "0123456789abcdef"
	return string([]byte{alphabet[(value>>4)&15], alphabet[value&15]})
}

func TestListDefaultsPageSizeToTenAndCapsConfiguredValues(t *testing.T) {
	tests := []struct {
		defaults uint64
		maximum  uint64
		want     int
	}{
		{defaults: 1, maximum: 1, want: 1},
		{defaults: 10, maximum: 10, want: 10},
		{defaults: 25, maximum: 100, want: 10},
	}
	for _, test := range tests {
		source := &reviewSourceStub{}
		service := reviewService(t, source, func(configuration *config.Config) {
			configuration.Review.DefaultPageSize = test.defaults
			configuration.Review.MaximumPageSize = test.maximum
		})
		if _, err := service.List(context.Background(), ListRequest{}); err != nil {
			t.Fatal(err)
		}
		if source.queries[0].RequestedPageSize() != test.want {
			t.Fatalf("defaults=%d maximum=%d requested=%d want=%d", test.defaults, test.maximum, source.queries[0].RequestedPageSize(), test.want)
		}
	}
}

func TestListAcceptsZeroOneTenOneHundredAndOneHundredOneAndRejectsOneHundredTwoRows(t *testing.T) {
	for _, count := range []int{0, 1, 10, 100, 101, 102} {
		rows := make([]storage.ReviewCandidateRow, 0, count)
		for index := 0; index < count; index++ {
			rows = append(rows, reviewRow(t, reviewAccountA, "thread-"+byteHex(index), "message-"+byteHex(index), int64(index)))
		}
		service := reviewService(t, &reviewSourceStub{rows: rows})
		page, err := service.List(context.Background(), ListRequest{PageSize: 10})
		if count == 102 {
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("102 rows error = %v", err)
			}
			continue
		}
		if err != nil || len(page.Candidates) > 10 {
			t.Fatalf("count=%d candidates=%d error=%v", count, len(page.Candidates), err)
		}
		if count > 10 && page.NextCursor == nil {
			t.Fatalf("count=%d missing continuation", count)
		}
	}
}

func TestListFiltersDatesAndStalePolicyWithinOneHundredRowScan(t *testing.T) {
	policy := config.Defaults().Gate
	stalePolicy := policy
	stalePolicy.DirectRecipientIsCandidate = false
	rows := make([]storage.ReviewCandidateRow, 0, 100)
	for index := 0; index < 100; index++ {
		message := reviewMessage(t, reviewAccountA, "t"+byteHex(index), "m"+byteHex(index), "Sender", "Subject", int64(index), 0)
		decisionPolicy := policy
		if index%2 == 0 {
			decisionPolicy = stalePolicy
		}
		rows = append(rows, storage.ReviewCandidateRow{Message: message, Decision: reviewDecision(t, message, decisionPolicy, 1000)})
	}
	minimum := int64(200)
	page, err := reviewService(t, &reviewSourceStub{rows: rows}).List(context.Background(), ListRequest{InternalDateMinUnixMS: &minimum, PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Candidates) != 0 || page.NextCursor == nil {
		t.Fatalf("filtered page = %#v", page)
	}
}

func TestCandidatePreviewsAreUTF8BoundedMarkedUntrustedAndExcludeContent(t *testing.T) {
	message := reviewMessage(t, reviewAccountA, "thread", "message", strings.Repeat("é", 200), strings.Repeat("🙂", 200), 42, 1)
	row := storage.ReviewCandidateRow{Message: message, Decision: reviewDecision(t, message, config.Defaults().Gate, 1000)}
	page, err := reviewService(t, &reviewSourceStub{rows: []storage.ReviewCandidateRow{row}}).List(context.Background(), ListRequest{PageSize: 1})
	if err != nil || len(page.Candidates) != 1 {
		t.Fatalf("List() = %#v, %v", page, err)
	}
	candidate := page.Candidates[0]
	if !utf8.ValidString(candidate.SenderDisplayPreview) || len(candidate.SenderDisplayPreview) > 256 || !candidate.SenderDisplayTruncated {
		t.Fatalf("sender preview = %q bytes=%d truncated=%t", candidate.SenderDisplayPreview, len(candidate.SenderDisplayPreview), candidate.SenderDisplayTruncated)
	}
	if !utf8.ValidString(candidate.SubjectPreview) || len(candidate.SubjectPreview) > 512 || !candidate.SubjectTruncated {
		t.Fatalf("subject preview bytes=%d truncated=%t", len(candidate.SubjectPreview), candidate.SubjectTruncated)
	}
	if candidate.ContentTrust != ContentTrustUntrustedEmail || candidate.SenderAddress != "sender@example.test" || !candidate.HasAttachments {
		t.Fatalf("candidate = %#v", candidate)
	}
	if candidate.Excerpt != "" || candidate.ContentHash != "" || candidate.SourceKind != "" || candidate.FetchedAtUnixMS != 0 {
		t.Fatalf("candidate exposed content fields = %#v", candidate)
	}
}

func TestCursorIsCanonicalExclusiveAndBoundToEveryRequestAndPolicyField(t *testing.T) {
	row := reviewRow(t, reviewAccountA, "thread", "message", 42)
	service := reviewService(t, &reviewSourceStub{rows: []storage.ReviewCandidateRow{row}})
	page, err := service.List(context.Background(), ListRequest{AccountIDs: []string{reviewAccountA}, Urgency: UrgencyStandard, PageSize: 1})
	if err != nil || page.NextCursor == nil || len(*page.NextCursor) > MaximumCursorBytes || !strings.HasPrefix(*page.NextCursor, "igrc1.") || strings.Contains(*page.NextCursor, "=") {
		t.Fatalf("cursor = %#v error=%v", page.NextCursor, err)
	}

	changed := []ListRequest{
		{AccountIDs: []string{reviewAccountB}, Urgency: UrgencyStandard, PageSize: 1, Cursor: *page.NextCursor},
		{AccountIDs: []string{reviewAccountA}, Urgency: UrgencyUrgent, PageSize: 1, Cursor: *page.NextCursor},
		{AccountIDs: []string{reviewAccountA}, Urgency: UrgencyStandard, PageSize: 2, Cursor: *page.NextCursor},
	}
	for index, request := range changed {
		source := &reviewSourceStub{}
		service := reviewService(t, source)
		if _, err := service.List(context.Background(), request); !errors.Is(err, ErrInvalidRequest) || source.listCalls.Load() != 0 {
			t.Errorf("changed request %d = %v calls=%d", index, err, source.listCalls.Load())
		}
	}

	policySource := &reviewSourceStub{}
	changedPolicyService := reviewService(t, policySource, func(configuration *config.Config) {
		configuration.Gate.SubjectCandidateTerms = []string{"changed"}
	})
	if _, err := changedPolicyService.List(context.Background(), ListRequest{AccountIDs: []string{reviewAccountA}, Urgency: UrgencyStandard, PageSize: 1, Cursor: *page.NextCursor}); !errors.Is(err, ErrInvalidRequest) || policySource.listCalls.Load() != 0 {
		t.Fatalf("changed policy cursor = %v calls=%d", err, policySource.listCalls.Load())
	}
}

func TestSourceRowsMustBeStrictlySortedUniqueConsistentAndCursorEncodable(t *testing.T) {
	first := reviewRow(t, reviewAccountA, "thread-a", "message-a", 1)
	second := reviewRow(t, reviewAccountA, "thread-b", "message-b", 2)
	invalid := [][]storage.ReviewCandidateRow{
		{first, first},
		{second, first},
		{{}},
		{{Message: first.Message, Decision: second.Decision}},
		{{Message: reviewMessage(t, reviewAccountA, strings.Repeat("t", 200), strings.Repeat("m", 100), "Sender", "Subject", 1, 0), Decision: first.Decision}},
	}
	for index, rows := range invalid {
		if _, err := reviewService(t, &reviewSourceStub{rows: rows}).List(context.Background(), ListRequest{PageSize: 1}); !errors.Is(err, ErrUnavailable) {
			t.Errorf("case %d error = %v", index, err)
		}
	}
}

func TestGateReasonReturnsAllCurrentOutcomesAndClosedSortedReasons(t *testing.T) {
	policies := []config.Gate{config.Defaults().Gate}
	excluded := config.Defaults().Gate
	excluded.ExcludedLabels = []string{"INBOX"}
	policies = append(policies, excluded)
	bulk := config.Defaults().Gate
	bulk.DirectRecipientIsCandidate = false
	policies = append(policies, bulk)
	urgent := config.Defaults().Gate
	urgent.SenderAllowDomains = []string{"example.test"}
	urgent.SubjectUrgentTerms = []string{"subject"}
	policies = append(policies, urgent)

	for _, policy := range policies {
		message := reviewMessage(t, reviewAccountA, "thread", "message", "Sender", "Subject", 42, 0)
		decision := reviewDecision(t, message, policy, 1000)
		service := reviewService(t, &reviewSourceStub{reason: storage.CurrentGateInspection{Message: message, Decision: decision}}, func(configuration *config.Config) {
			configuration.Gate = policy
		})
		result, err := service.GateReason(context.Background(), GateReasonRequest{AccountID: reviewAccountA, GmailMessageID: "message"})
		if err != nil || !result.SourceCurrent || !result.PolicyCurrent || result.Outcome != decision.Outcome().String() || !reflect.DeepEqual(result.ReasonCodes, stringsToReasons(decision.ReasonCodes())) {
			t.Fatalf("policy outcome %q result=%#v error=%v", decision.Outcome(), result, err)
		}
	}

	message := reviewMessage(t, reviewAccountA, "thread", "message", "Sender", "Subject", 42, 0)
	stalePolicy := config.Defaults().Gate
	stalePolicy.DirectRecipientIsCandidate = false
	source := &reviewSourceStub{reason: storage.CurrentGateInspection{Message: message, Decision: reviewDecision(t, message, stalePolicy, 1000)}}
	result, err := reviewService(t, source).GateReason(context.Background(), GateReasonRequest{AccountID: reviewAccountA, GmailMessageID: "message"})
	if !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(result, GateReason{}) || source.reasonCalls.Load() != 1 {
		t.Fatalf("stale policy result=%#v error=%v calls=%d", result, err, source.reasonCalls.Load())
	}
}

func stringsToReasons(values []gate.ReasonCode) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.String()
	}
	return result
}

func TestGateReasonInvalidMissingStaleCanceledAndFailedAreOneUnavailableCategory(t *testing.T) {
	invalid := []GateReasonRequest{
		{},
		{AccountID: strings.ToUpper(reviewAccountA), GmailMessageID: "message"},
		{AccountID: reviewAccountA, GmailMessageID: ""},
		{AccountID: reviewAccountA, GmailMessageID: strings.Repeat("m", 256)},
		{AccountID: reviewAccountA, GmailMessageID: "message", GmailThreadID: "thread"},
	}
	for index, request := range invalid {
		source := &reviewSourceStub{}
		if _, err := reviewService(t, source).GateReason(context.Background(), request); !errors.Is(err, ErrInvalidRequest) || source.reasonCalls.Load() != 0 {
			t.Errorf("invalid %d = %v calls=%d", index, err, source.reasonCalls.Load())
		}
	}

	for _, source := range []*reviewSourceStub{{err: errors.New("raw SQL synthetic secret")}, {}, {wait: true}} {
		service := reviewService(t, source)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		_, err := service.GateReason(ctx, GateReasonRequest{AccountID: reviewAccountA, GmailMessageID: "message"})
		cancel()
		if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "raw SQL") || source.reasonCalls.Load() != 1 {
			t.Fatalf("source=%#v error=%v calls=%d", source, err, source.reasonCalls.Load())
		}
	}
}

func TestResultsAndSourceInputsAreDefensiveAndNoRetryOccurs(t *testing.T) {
	row := reviewRow(t, reviewAccountA, "thread", "message", 42)
	source := &reviewSourceStub{rows: []storage.ReviewCandidateRow{row}}
	service := reviewService(t, source)
	first, err := service.List(context.Background(), ListRequest{PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	first.Candidates[0].SubjectPreview = "mutated"
	second, err := service.List(context.Background(), ListRequest{PageSize: 1})
	if err != nil || second.Candidates[0].SubjectPreview == "mutated" || source.listCalls.Load() != 2 {
		t.Fatalf("defensive result=%#v error=%v calls=%d", second, err, source.listCalls.Load())
	}

	failing := &reviewSourceStub{err: errors.New("private source detail")}
	if _, err := reviewService(t, failing).List(context.Background(), ListRequest{}); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "private") || failing.listCalls.Load() != 1 {
		t.Fatalf("failure=%v calls=%d", err, failing.listCalls.Load())
	}
}

func FuzzListRequestAndCursorDecodingRemainClosedAndBounded(f *testing.F) {
	f.Add(reviewAccountA, UrgencyAll, uint64(10), "")
	f.Add("bad", "urgent", uint64(11), "igrc1.=")
	f.Fuzz(func(t *testing.T, account, urgency string, pageSize uint64, cursor string) {
		if len(account) > 64 || len(urgency) > 32 || len(cursor) > 500 {
			return
		}
		source := &reviewSourceStub{}
		service := reviewService(t, source)
		_, _ = service.List(context.Background(), ListRequest{AccountIDs: []string{account}, Urgency: urgency, PageSize: pageSize, Cursor: cursor})
		if source.listCalls.Load() > 1 {
			t.Fatalf("source calls = %d", source.listCalls.Load())
		}
	})
}

func FuzzPreviewTruncationNeverSplitsUTF8OrExceedsLimit(f *testing.F) {
	f.Add("plain")
	f.Add(strings.Repeat("🙂", 200))
	f.Fuzz(func(t *testing.T, value string) {
		preview, truncated, err := Preview(value, 256)
		if err != nil {
			return
		}
		if !utf8.ValidString(preview) || len(preview) > 256 || truncated != (len(value) > 256) {
			t.Fatalf("preview bytes=%d valid=%t truncated=%t input=%d", len(preview), utf8.ValidString(preview), truncated, len(value))
		}
	})
}
