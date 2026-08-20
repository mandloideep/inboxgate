//go:build race

package reviewinspect

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/storage"
)

type policyRaceSource struct{}

func (policyRaceSource) ListReviewCandidates(context.Context, storage.ReviewCandidateQuery) ([]storage.ReviewCandidateRow, error) {
	return []storage.ReviewCandidateRow{}, nil
}

func (policyRaceSource) GetCurrentGateInspection(context.Context, storage.AccountID, string) (storage.CurrentGateInspection, error) {
	return storage.CurrentGateInspection{}, storage.ErrReviewInspectionNotFound
}

type cursorRaceSource struct {
	row            storage.ReviewCandidateRow
	calls          atomic.Int64
	invalidQueries atomic.Int64
}

func (source *cursorRaceSource) ListReviewCandidates(_ context.Context, query storage.ReviewCandidateQuery) ([]storage.ReviewCandidateRow, error) {
	source.calls.Add(1)
	after := query.After()
	if query.Limit() != storage.MaximumReviewSourceRows || query.RequestedPageSize() != 1 || query.Urgency() != storage.ReviewUrgencyAll || len(query.AccountIDs()) != 0 ||
		after.Present && (after.AccountID().String() != reviewAccountA || after.ThreadID() != "thread" || after.MessageID() != "message") {
		source.invalidQueries.Add(1)
		return nil, storage.ErrInvalidValue
	}
	if after.Present {
		return []storage.ReviewCandidateRow{}, nil
	}
	return []storage.ReviewCandidateRow{source.row}, nil
}

func (source *cursorRaceSource) GetCurrentGateInspection(context.Context, storage.AccountID, string) (storage.CurrentGateInspection, error) {
	return storage.CurrentGateInspection{}, storage.ErrReviewInspectionNotFound
}

func TestReviewServicePolicyIsolatedFromConcurrentCallerMutation(t *testing.T) {
	configuration := config.Defaults()
	service, err := newWithCursorKey(policyRaceSource{}, configuration.Gate, configuration.Review, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errors := make(chan error, 4)
	var wait sync.WaitGroup
	wait.Add(5)
	go func() {
		defer wait.Done()
		<-start
		for index := 0; index < 2_000; index++ {
			if index%2 == 0 {
				configuration.Gate.ExcludedLabels[0] = "SPAM"
			} else {
				configuration.Gate.ExcludedLabels[0] = "TRASH"
			}
		}
	}()
	for range 4 {
		go func() {
			defer wait.Done()
			<-start
			for range 500 {
				if _, listErr := service.List(context.Background(), ListRequest{}); listErr != nil {
					errors <- listErr
					return
				}
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errors)
	for listErr := range errors {
		t.Fatalf("List() error = %v", listErr)
	}
}

func TestReviewServiceConcurrentCursorEncodeAndDecode(t *testing.T) {
	configuration := config.Defaults()
	source := &cursorRaceSource{row: reviewRow(t, reviewAccountA, "thread", "message", 42)}
	service, err := newWithCursorKey(source, configuration.Gate, configuration.Review, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	expectedFirst, err := service.List(context.Background(), ListRequest{PageSize: 1})
	if err != nil || expectedFirst.NextCursor == nil || len(expectedFirst.Candidates) != 1 {
		t.Fatalf("first List() = %#v, %v", expectedFirst, err)
	}
	cursor := *expectedFirst.NextCursor
	expectedContinuation := CandidatePage{OutputVersion: OutputVersion1, Candidates: []Candidate{}}

	const (
		workersPerPath = 4
		iterations     = 50
	)
	start := make(chan struct{})
	errors := make(chan error, workersPerPath*2)
	var wait sync.WaitGroup
	run := func(request ListRequest, want CandidatePage, operation string) {
		defer wait.Done()
		<-start
		for iteration := 0; iteration < iterations; iteration++ {
			page, listErr := service.List(context.Background(), request)
			if listErr != nil || !reflect.DeepEqual(page, want) {
				errors <- fmt.Errorf("%s iteration %d = %#v, %v", operation, iteration, page, listErr)
				return
			}
		}
	}
	for range workersPerPath {
		wait.Add(2)
		go run(ListRequest{PageSize: 1}, expectedFirst.Clone(), "encode")
		go run(ListRequest{PageSize: 1, Cursor: cursor}, expectedContinuation.Clone(), "decode")
	}
	close(start)
	wait.Wait()
	close(errors)
	for listErr := range errors {
		t.Error(listErr)
	}
	wantCalls := int64(1 + workersPerPath*2*iterations)
	if source.calls.Load() != wantCalls || source.invalidQueries.Load() != 0 {
		t.Fatalf("source calls = %d, want %d; invalid queries = %d", source.calls.Load(), wantCalls, source.invalidQueries.Load())
	}
}
