package storage

import (
	"context"
	"strings"
	"testing"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/gate"
	"github.com/mandloideep/inboxgate/internal/mail"
)

func TestReviewCandidateQueryIsClosedBoundedAndDefensive(t *testing.T) {
	account, err := ParseAccountID("0000000000000000000000000000000a")
	if err != nil {
		t.Fatal(err)
	}
	query, err := NewReviewCandidateQuery([]AccountID{account}, ReviewUrgencyAll, 10, ReviewCursorKey{}, 101)
	if err != nil {
		t.Fatal(err)
	}
	accounts := query.AccountIDs()
	accounts[0] = AccountID{}
	if got := query.AccountIDs(); len(got) != 1 || got[0] != account || query.Limit() != 101 || query.RequestedPageSize() != 10 {
		t.Fatalf("query = %#v", query)
	}
	for _, limit := range []int{0, 100, 102} {
		if _, err := NewReviewCandidateQuery(nil, ReviewUrgencyAll, 10, ReviewCursorKey{}, limit); err == nil {
			t.Errorf("limit %d accepted", limit)
		}
	}
}

func TestReviewCandidateAndGateInspectionDecodeOnlyExistingClosedValues(t *testing.T) {
	message, err := mail.Normalize("0000000000000000000000000000000a", mail.MessageInput{
		GmailMessageID: "message", GmailThreadID: "thread", InternalDateMS: 1,
		SenderAddress: "sender@example.test", To: []string{"owner@example.test"}, Subject: "Subject",
	})
	if err != nil {
		t.Fatal(err)
	}
	classification, err := gate.Classify(message, config.Defaults().Gate)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := NewGateDecision(classification, 1)
	if err != nil {
		t.Fatal(err)
	}
	row, err := NewReviewCandidateRow(message, decision)
	if err != nil || !row.Valid() {
		t.Fatalf("row = %#v error=%v", row, err)
	}
	inspection, err := NewCurrentGateInspection(message, decision)
	if err != nil || !inspection.Valid() {
		t.Fatalf("inspection = %#v error=%v", inspection, err)
	}
	changed, _ := mail.Normalize(message.AccountID(), mail.MessageInput{GmailMessageID: "message", GmailThreadID: "thread", InternalDateMS: 2})
	if _, err := NewReviewCandidateRow(changed, decision); err == nil {
		t.Fatal("stale source decision accepted")
	}
	if _, err := DecodeReviewCandidateRow(strings.Repeat("x", 32), "thread", "message", 1, nil, nil); err == nil {
		t.Fatal("malformed durable row accepted")
	}
}

func TestReviewReadSourceInterfaceCarriesNoMutationOrGenericAuthority(t *testing.T) {
	var _ ReviewInspectionSource = (interface {
		ListReviewCandidates(context.Context, ReviewCandidateQuery) ([]ReviewCandidateRow, error)
		GetCurrentGateInspection(context.Context, AccountID, string) (CurrentGateInspection, error)
	})(nil)
}
