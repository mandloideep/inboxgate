//go:build race

package reviewinspect

import (
	"context"
	"sync"
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
