package reviewinspect

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/mandloideep/inboxgate/internal/config"
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

func TestCursorIsBoundToServiceInstance(t *testing.T) {
	row := reviewRow(t, reviewAccountA, "thread", "message", 42)
	first, err := reviewService(t, &reviewSourceStub{rows: []storage.ReviewCandidateRow{row}}).List(context.Background(), ListRequest{PageSize: 1})
	if err != nil || first.NextCursor == nil {
		t.Fatalf("first List() = %#v, %v", first, err)
	}
	second, err := reviewService(t, &reviewSourceStub{rows: []storage.ReviewCandidateRow{row}}).List(context.Background(), ListRequest{PageSize: 1})
	if err != nil || second.NextCursor == nil {
		t.Fatalf("second List() = %#v, %v", second, err)
	}
	if *first.NextCursor == *second.NextCursor {
		t.Fatal("independent review services emitted an interchangeable cursor")
	}

	continuedSource := &reviewSourceStub{}
	continuedService := reviewService(t, continuedSource)
	page, err := continuedService.List(context.Background(), ListRequest{PageSize: 1, Cursor: *first.NextCursor})
	if !errors.Is(err, ErrInvalidRequest) || !reflect.DeepEqual(page, CandidatePage{}) || continuedSource.listCalls.Load() != 0 {
		t.Fatalf("foreign cursor List() = %#v, %v, calls %d", page, err, continuedSource.listCalls.Load())
	}
}
