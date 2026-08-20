package reviewinspect

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
)

func TestListRejectsValidRowsOutsideSelectorAndAtOrBeforeCursor(t *testing.T) {
	t.Run("outside requested account selector", func(t *testing.T) {
		source := &reviewSourceStub{rows: []storage.ReviewCandidateRow{
			reviewRow(t, reviewAccountB, "thread", "message", 42),
		}}
		page, err := reviewService(t, source).List(context.Background(), ListRequest{
			AccountIDs: []string{reviewAccountA},
			PageSize:   1,
		})
		if !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(page, CandidatePage{}) || source.listCalls.Load() != 1 {
			t.Fatalf("List() = %#v, %v, calls %d", page, err, source.listCalls.Load())
		}
	})

	t.Run("not strictly after decoded cursor", func(t *testing.T) {
		row := reviewRow(t, reviewAccountA, "thread", "message", 42)
		firstSource := &reviewSourceStub{rows: []storage.ReviewCandidateRow{row}}
		service := reviewService(t, firstSource)
		first, err := service.List(context.Background(), ListRequest{PageSize: 1})
		if err != nil || first.NextCursor == nil {
			t.Fatalf("first List() = %#v, %v", first, err)
		}

		secondSource := &reviewSourceStub{rows: []storage.ReviewCandidateRow{row}}
		service.source = secondSource
		page, err := service.List(context.Background(), ListRequest{PageSize: 1, Cursor: *first.NextCursor})
		if !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(page, CandidatePage{}) || secondSource.listCalls.Load() != 1 {
			t.Fatalf("continued List() = %#v, %v, calls %d", page, err, secondSource.listCalls.Load())
		}
	})
}

func TestGateReasonRejectsValidInspectionForDifferentIdentity(t *testing.T) {
	tests := []struct {
		name      string
		accountID string
		messageID string
		requestID string
	}{
		{name: "account", accountID: reviewAccountB, messageID: "message", requestID: "message"},
		{name: "message", accountID: reviewAccountA, messageID: "different", requestID: "message"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message := reviewMessage(t, test.accountID, "thread", test.messageID, "Sender", "Subject", 42, 0)
			source := &reviewSourceStub{reason: storage.CurrentGateInspection{
				Message:  message,
				Decision: reviewDecision(t, message, config.Defaults().Gate, 1000),
			}}
			result, err := reviewService(t, source).GateReason(context.Background(), GateReasonRequest{
				AccountID:      reviewAccountA,
				GmailMessageID: test.requestID,
			})
			if !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(result, GateReason{}) || source.reasonCalls.Load() != 1 {
				t.Fatalf("GateReason() = %#v, %v, calls %d", result, err, source.reasonCalls.Load())
			}
		})
	}
}

func TestCursorBindsDatePresenceAndValuesBeforeSource(t *testing.T) {
	minimum := int64(10)
	maximum := int64(20)
	row := reviewRow(t, reviewAccountA, "thread", "message", 15)
	first, err := reviewService(t, &reviewSourceStub{rows: []storage.ReviewCandidateRow{row}}).List(context.Background(), ListRequest{
		InternalDateMinUnixMS: &minimum,
		InternalDateMaxUnixMS: &maximum,
		PageSize:              1,
	})
	if err != nil || first.NextCursor == nil {
		t.Fatalf("first List() = %#v, %v", first, err)
	}

	changedMinimum := int64(11)
	changedMaximum := int64(21)
	tests := []ListRequest{
		{InternalDateMaxUnixMS: &maximum, PageSize: 1, Cursor: *first.NextCursor},
		{InternalDateMinUnixMS: &minimum, PageSize: 1, Cursor: *first.NextCursor},
		{InternalDateMinUnixMS: &changedMinimum, InternalDateMaxUnixMS: &maximum, PageSize: 1, Cursor: *first.NextCursor},
		{InternalDateMinUnixMS: &minimum, InternalDateMaxUnixMS: &changedMaximum, PageSize: 1, Cursor: *first.NextCursor},
	}
	for index, request := range tests {
		source := &reviewSourceStub{}
		page, err := reviewService(t, source).List(context.Background(), request)
		if !errors.Is(err, ErrInvalidRequest) || !reflect.DeepEqual(page, CandidatePage{}) || source.listCalls.Load() != 0 {
			t.Errorf("case %d = %#v, %v, calls %d", index, page, err, source.listCalls.Load())
		}
	}
}

func TestListDateBoundsAreInclusive(t *testing.T) {
	minimum := int64(10)
	maximum := int64(20)
	rows := []storage.ReviewCandidateRow{
		reviewRow(t, reviewAccountA, "thread-09", "message-09", minimum-1),
		reviewRow(t, reviewAccountA, "thread-10", "message-10", minimum),
		reviewRow(t, reviewAccountA, "thread-20", "message-20", maximum),
		reviewRow(t, reviewAccountA, "thread-21", "message-21", maximum+1),
	}
	source := &reviewSourceStub{rows: rows}
	page, err := reviewService(t, source).List(context.Background(), ListRequest{
		InternalDateMinUnixMS: &minimum,
		InternalDateMaxUnixMS: &maximum,
		PageSize:              10,
	})
	if err != nil || source.listCalls.Load() != 1 || page.NextCursor != nil || len(page.Candidates) != 2 {
		t.Fatalf("List() = %#v, %v, calls %d", page, err, source.listCalls.Load())
	}
	if got := []string{page.Candidates[0].GmailMessageID, page.Candidates[1].GmailMessageID}; !reflect.DeepEqual(got, []string{"message-10", "message-20"}) {
		t.Fatalf("message IDs = %q", got)
	}
}

func TestListRowCountMatrixHasExactOrderAndContinuation(t *testing.T) {
	for _, count := range []int{0, 1, 10, 100, 101, 102} {
		t.Run(fmt.Sprintf("rows_%d", count), func(t *testing.T) {
			rows := make([]storage.ReviewCandidateRow, 0, count)
			for index := 0; index < count; index++ {
				key := fmt.Sprintf("%03d", index)
				rows = append(rows, reviewRow(t, reviewAccountA, "thread-"+key, "message-"+key, int64(index)))
			}
			source := &reviewSourceStub{rows: rows}
			page, err := reviewService(t, source).List(context.Background(), ListRequest{PageSize: 10})
			if source.listCalls.Load() != 1 {
				t.Fatalf("source calls = %d", source.listCalls.Load())
			}
			if count == 102 {
				if !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(page, CandidatePage{}) {
					t.Fatalf("List() = %#v, %v", page, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			wantCount := min(count, 10)
			if len(page.Candidates) != wantCount {
				t.Fatalf("candidate count = %d, want %d", len(page.Candidates), wantCount)
			}
			for index, candidate := range page.Candidates {
				want := fmt.Sprintf("message-%03d", index)
				if candidate.GmailMessageID != want {
					t.Fatalf("candidate %d ID = %q, want %q", index, candidate.GmailMessageID, want)
				}
			}
			wantCursor := count >= 10
			if (page.NextCursor != nil) != wantCursor {
				t.Fatalf("next cursor present = %t, want %t", page.NextCursor != nil, wantCursor)
			}
		})
	}
}

func TestPreviewLiteralBoundaries(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		maximum   int
		want      string
		truncated bool
	}{
		{name: "sender exact", value: strings.Repeat("s", 256), maximum: 256, want: strings.Repeat("s", 256)},
		{name: "sender over", value: strings.Repeat("s", 257), maximum: 256, want: strings.Repeat("s", 256), truncated: true},
		{name: "subject exact", value: strings.Repeat("u", 512), maximum: 512, want: strings.Repeat("u", 512)},
		{name: "subject over", value: strings.Repeat("u", 513), maximum: 512, want: strings.Repeat("u", 512), truncated: true},
		{name: "split multibyte", value: strings.Repeat("a", 255) + "é", maximum: 256, want: strings.Repeat("a", 255), truncated: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, truncated, err := Preview(test.value, test.maximum)
			if err != nil || got != test.want || truncated != test.truncated {
				t.Fatalf("Preview() = %q, %t, %v", got, truncated, err)
			}
		})
	}
}

func TestGateReasonLiteralOutcomesAndCompleteReasonVocabulary(t *testing.T) {
	type scenario struct {
		name        string
		mutateInput func(*mail.MessageInput)
		mutateGate  func(*config.Gate)
		wantOutcome string
		wantReasons []string
	}
	tests := []scenario{
		{name: "excluded", mutateGate: func(policy *config.Gate) { policy.ExcludedLabels = []string{"INBOX"} }, wantOutcome: "ignore", wantReasons: []string{"direct_recipient", "excluded_label"}},
		{name: "blocked", mutateGate: func(policy *config.Gate) { policy.SenderBlockDomains = []string{"example.test"} }, wantOutcome: "ignore", wantReasons: []string{"direct_recipient", "sender_block_domain"}},
		{name: "allowed", mutateGate: func(policy *config.Gate) { policy.SenderAllowDomains = []string{"example.test"} }, wantOutcome: "review_candidate", wantReasons: []string{"direct_recipient", "sender_allow_domain"}},
		{name: "bulk", mutateInput: func(input *mail.MessageInput) { input.Labels = []string{"CATEGORY_PROMOTIONS"} }, wantOutcome: "metadata_only", wantReasons: []string{"bulk_category", "direct_recipient"}},
		{name: "mailing list", mutateInput: func(input *mail.MessageInput) { input.ListID = "list.example.test" }, wantOutcome: "metadata_only", wantReasons: []string{"direct_recipient", "mailing_list"}},
		{name: "automated", mutateInput: func(input *mail.MessageInput) { input.AutoSubmitted = "auto-generated" }, wantOutcome: "metadata_only", wantReasons: []string{"automated_message", "direct_recipient"}},
		{name: "candidate term", mutateGate: func(policy *config.Gate) { policy.SubjectCandidateTerms = []string{"subject"} }, wantOutcome: "review_candidate", wantReasons: []string{"direct_recipient", "owner_candidate_term"}},
		{name: "urgent term", mutateGate: func(policy *config.Gate) {
			policy.SenderAllowDomains = []string{"example.test"}
			policy.SubjectUrgentTerms = []string{"subject"}
		}, wantOutcome: "urgent_review_candidate", wantReasons: []string{"direct_recipient", "owner_urgent_term", "sender_allow_domain"}},
		{name: "direct", wantOutcome: "review_candidate", wantReasons: []string{"direct_recipient"}},
		{name: "no signal", mutateGate: func(policy *config.Gate) { policy.DirectRecipientIsCandidate = false }, wantOutcome: "metadata_only", wantReasons: []string{"no_candidate_signal"}},
	}
	observed := map[string]struct{}{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := mail.MessageInput{
				GmailMessageID: "message", GmailThreadID: "thread", InternalDateMS: 42,
				SenderAddress: "sender@example.test", To: []string{"owner@example.test"}, Subject: "Subject", Labels: []string{"INBOX"},
			}
			if test.mutateInput != nil {
				test.mutateInput(&input)
			}
			message, err := mail.Normalize(reviewAccountA, input)
			if err != nil {
				t.Fatal(err)
			}
			policy := config.Defaults().Gate
			if test.mutateGate != nil {
				test.mutateGate(&policy)
			}
			decision := reviewDecision(t, message, policy, 1000)
			service := reviewService(t, &reviewSourceStub{reason: storage.CurrentGateInspection{Message: message, Decision: decision}}, func(configuration *config.Config) {
				configuration.Gate = policy
			})
			result, err := service.GateReason(context.Background(), GateReasonRequest{AccountID: reviewAccountA, GmailMessageID: "message"})
			if err != nil || result.Outcome != test.wantOutcome || !reflect.DeepEqual(result.ReasonCodes, test.wantReasons) {
				t.Fatalf("GateReason() = %#v, %v", result, err)
			}
			for _, reason := range result.ReasonCodes {
				observed[reason] = struct{}{}
			}
		})
	}
	wantVocabulary := []string{
		"automated_message", "bulk_category", "direct_recipient", "excluded_label", "mailing_list",
		"no_candidate_signal", "owner_candidate_term", "owner_urgent_term", "sender_allow_domain", "sender_block_domain",
	}
	gotVocabulary := make([]string, 0, len(observed))
	for reason := range observed {
		gotVocabulary = append(gotVocabulary, reason)
	}
	slices.Sort(gotVocabulary)
	if !reflect.DeepEqual(gotVocabulary, wantVocabulary) {
		t.Fatalf("reason vocabulary = %q, want %q", gotVocabulary, wantVocabulary)
	}
}

func TestCursorIsBoundToServiceInstance(t *testing.T) {
	row := reviewRow(t, reviewAccountA, "thread", "message", 42)
	configuration := config.Defaults()
	firstService, err := New(&reviewSourceStub{rows: []storage.ReviewCandidateRow{row}}, configuration.Gate, configuration.Review)
	if err != nil {
		t.Fatal(err)
	}
	first, err := firstService.List(context.Background(), ListRequest{PageSize: 1})
	if err != nil || first.NextCursor == nil {
		t.Fatalf("first List() = %#v, %v", first, err)
	}
	secondService, err := New(&reviewSourceStub{rows: []storage.ReviewCandidateRow{row}}, configuration.Gate, configuration.Review)
	if err != nil {
		t.Fatal(err)
	}
	second, err := secondService.List(context.Background(), ListRequest{PageSize: 1})
	if err != nil || second.NextCursor == nil {
		t.Fatalf("second List() = %#v, %v", second, err)
	}
	if *first.NextCursor == *second.NextCursor {
		t.Fatal("independent review services emitted an interchangeable cursor")
	}

	continuedSource := &reviewSourceStub{}
	continuedService, err := New(continuedSource, configuration.Gate, configuration.Review)
	if err != nil {
		t.Fatal(err)
	}
	page, err := continuedService.List(context.Background(), ListRequest{PageSize: 1, Cursor: *first.NextCursor})
	if !errors.Is(err, ErrInvalidRequest) || !reflect.DeepEqual(page, CandidatePage{}) || continuedSource.listCalls.Load() != 0 {
		t.Fatalf("foreign cursor List() = %#v, %v, calls %d", page, err, continuedSource.listCalls.Load())
	}
}

func TestCursorRejectsEveryPayloadMutationAndWrongKeyBeforeSource(t *testing.T) {
	row := reviewRow(t, reviewAccountA, "thread", "message", 42)
	service := reviewService(t, &reviewSourceStub{rows: []storage.ReviewCandidateRow{row}})
	page, err := service.List(context.Background(), ListRequest{PageSize: 1})
	if err != nil || page.NextCursor == nil || !strings.HasPrefix(*page.NextCursor, "igrc2.") {
		t.Fatalf("List() = %#v, %v", page, err)
	}
	raw := strings.TrimPrefix(*page.NextCursor, "igrc2.")
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	for index := range payload {
		mutated := append([]byte(nil), payload...)
		mutated[index] ^= 1
		cursor := "igrc2." + base64.RawURLEncoding.EncodeToString(mutated)
		source := &reviewSourceStub{}
		mutatedService := reviewService(t, source)
		result, listErr := mutatedService.List(context.Background(), ListRequest{PageSize: 1, Cursor: cursor})
		if !errors.Is(listErr, ErrInvalidRequest) || !reflect.DeepEqual(result, CandidatePage{}) || source.listCalls.Load() != 0 {
			t.Fatalf("mutation %d = %#v, %v, calls %d", index, result, listErr, source.listCalls.Load())
		}
	}

	configuration := config.Defaults()
	wrongKey := [32]byte{99}
	foreignSource := &reviewSourceStub{}
	foreign, err := newWithCursorKey(foreignSource, configuration.Gate, configuration.Review, wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	result, err := foreign.List(context.Background(), ListRequest{PageSize: 1, Cursor: *page.NextCursor})
	if !errors.Is(err, ErrInvalidRequest) || !reflect.DeepEqual(result, CandidatePage{}) || foreignSource.listCalls.Load() != 0 {
		t.Fatalf("wrong-key cursor = %#v, %v, calls %d", result, err, foreignSource.listCalls.Load())
	}
}

func TestCursorVersionTwoBytesMatchIndependentLiteralVector(t *testing.T) {
	row := reviewRow(t, reviewAccountA, "thread", "message", 42)
	page, err := reviewService(t, &reviewSourceStub{rows: []storage.ReviewCandidateRow{row}}).List(context.Background(), ListRequest{PageSize: 1})
	if err != nil || page.NextCursor == nil {
		t.Fatalf("List() = %#v, %v", page, err)
	}
	prefix := []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 6}
	prefix = append(prefix, "thread"...)
	prefix = append(prefix, 7)
	prefix = append(prefix, "message"...)
	binding := `{"domain":"inboxgate/review-cursor/v2","version":2,"account_ids":null,"all_accounts":true,"urgency":"all","minimum":null,"maximum":null,"page_size":1,"policy":{"Version":1,"ExcludedLabels":["SPAM","TRASH"],"SuppressGmailCategories":["CATEGORY_PROMOTIONS","CATEGORY_SOCIAL"],"DirectRecipientIsCandidate":true,"MailingListIsBulkSignal":true,"SenderAllowDomains":[],"SenderBlockDomains":[],"SubjectCandidateTerms":[],"SubjectUrgentTerms":[]}}`
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("inboxgate/review-cursor/v2"))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(binding))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(prefix)
	wantPayload := append(append([]byte(nil), prefix...), mac.Sum(nil)...)
	want := "igrc2." + base64.RawURLEncoding.EncodeToString(wantPayload)
	if *page.NextCursor != want {
		t.Fatalf("cursor = %q, want independent literal %q", *page.NextCursor, want)
	}
}

type failingCursorEntropy struct {
	short bool
}

func (entropy failingCursorEntropy) Read(destination []byte) (int, error) {
	if entropy.short {
		if len(destination) > 0 {
			destination[0] = 1
		}
		return 1, nil
	}
	return 0, errors.New("synthetic entropy detail")
}

func TestReviewServiceConstructionFailsClosedOnEntropyFailure(t *testing.T) {
	configuration := config.Defaults()
	for _, entropy := range []failingCursorEntropy{{}, {short: true}} {
		service, err := newWithCursorEntropy(&reviewSourceStub{}, configuration.Gate, configuration.Review, entropy)
		if !errors.Is(err, ErrUnavailable) || service != nil || strings.Contains(err.Error(), "synthetic") {
			t.Fatalf("New() = %#v, %v", service, err)
		}
	}
}
