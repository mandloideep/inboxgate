package storage

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mandloideep/inboxgate/internal/mail"
)

func currentDiscoveryFixture(t *testing.T, count int) CurrentDiscoveryCommit {
	t.Helper()
	accountID, _ := ParseAccountID("00112233445566778899aabbccddeeff")
	expected, _ := ParseHistoryID("100")
	next, _ := ParseHistoryID("101")
	messages := make([]mail.Message, 0, count)
	for index := 0; index < count; index++ {
		message, err := mail.Normalize(accountID.String(), mail.MessageInput{
			GmailMessageID: fmt.Sprintf("message-%04d", index), GmailThreadID: fmt.Sprintf("thread-%04d", index),
			InternalDateMS: int64(index), To: []string{}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{},
		})
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		messages = append(messages, message)
	}
	return CurrentDiscoveryCommit{AccountID: accountID, Expected: expected, Next: next, Messages: messages}
}

func TestPrepareCurrentDiscoveryKnownAnswerAndDuplicateRules(t *testing.T) {
	commit := currentDiscoveryFixture(t, 2)
	commit.Messages = append(commit.Messages, commit.Messages[0])
	prepared, err := PrepareCurrentDiscoveryCommit(commit)
	if err != nil {
		t.Fatalf("PrepareCurrentDiscoveryCommit() error = %v", err)
	}
	if prepared.MessageCount() != 2 {
		t.Fatalf("MessageCount() = %d, want duplicate collapse to 2", prepared.MessageCount())
	}
	if prepared.AttemptID() != "10d2ce8e9a5171e15fc1410b1ce897b510ceea4313f8e19f66c341c321a0bc7e" {
		t.Fatalf("AttemptID() = %q, want known vector", prepared.AttemptID())
	}
	if prepared.ManifestHash() == prepared.AttemptID() || len(prepared.ManifestHash()) != 64 {
		t.Fatal("manifest and attempt hashes are not separately domain-bound")
	}
	if len(prepared.ManifestWitness()) != 78+2*int(prepared.EncodedBytes()) || !strings.HasPrefix(prepared.ManifestWitness(), "696e626f78676174652f63757272656e742d73796e632d6d616e69666573742f76310000000002") {
		t.Fatalf("ManifestWitness() = %q", prepared.ManifestWitness())
	}
	if prepared.RowWitness(0) == "" || !strings.Contains(prepared.ManifestWitness(), prepared.RowWitness(0)+prepared.RowWitness(1)) {
		t.Fatal("manifest witness does not contain exact ordered row witnesses")
	}
	if prepared.Messages()[0].GmailMessageID() >= prepared.Messages()[1].GmailMessageID() {
		t.Fatal("messages are not bytewise ordered")
	}

	conflict := currentDiscoveryFixture(t, 1)
	other, _ := mail.Normalize(conflict.AccountID.String(), mail.MessageInput{GmailMessageID: "message-0000", GmailThreadID: "other-thread", To: []string{}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{}})
	conflict.Messages = append(conflict.Messages, other)
	if _, err := PrepareCurrentDiscoveryCommit(conflict); !errors.Is(err, ErrCurrentDiscoveryConflict) {
		t.Fatalf("conflicting duplicate error = %v", err)
	}
}

func TestPrepareCurrentDiscoveryPublishedMessageBounds(t *testing.T) {
	for _, count := range []int{0, 1, 64, 65, 500, 5000} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			prepared, err := PrepareCurrentDiscoveryCommit(currentDiscoveryFixture(t, count))
			if err != nil {
				t.Fatalf("count %d error = %v", count, err)
			}
			wantChunks := (count + CurrentDiscoveryStageChunkMessages - 1) / CurrentDiscoveryStageChunkMessages
			if prepared.StageChunkCount() != wantChunks {
				t.Fatalf("StageChunkCount() = %d, want %d", prepared.StageChunkCount(), wantChunks)
			}
		})
	}
	if _, err := PrepareCurrentDiscoveryCommit(currentDiscoveryFixture(t, 5001)); !errors.Is(err, ErrCurrentDiscoveryTooLarge) {
		t.Fatalf("5001 messages error = %v, want too large", err)
	}
	if CurrentDiscoveryStageParameters != 514 || MaximumCurrentDiscoveryPages != 10 || MaximumCurrentDiscoveryPageMessages != 500 || MaximumCurrentDiscoveryMessages != 5000 || MaximumCurrentDiscoveryEncodedBytes != 16777216 || MaximumCurrentDiscoveryManifestWitnessBytes != 33554510 || MaximumCurrentDiscoveryStageWireBytes != 40*1024*1024 {
		t.Fatal("compiled current discovery bounds changed")
	}
}

func TestPrepareCurrentDiscoveryRejectsIdentityAndCursorViolations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*CurrentDiscoveryCommit)
	}{
		{name: "equal cursor", mutate: func(v *CurrentDiscoveryCommit) { v.Next = v.Expected }},
		{name: "regressing cursor", mutate: func(v *CurrentDiscoveryCommit) { v.Expected, v.Next = v.Next, v.Expected }},
		{name: "wrong account", mutate: func(v *CurrentDiscoveryCommit) {
			id, _ := ParseAccountID("11112233445566778899aabbccddeeff")
			v.AccountID = id
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			commit := currentDiscoveryFixture(t, 1)
			tt.mutate(&commit)
			if _, err := PrepareCurrentDiscoveryCommit(commit); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("error = %v, want invalid value", err)
			}
		})
	}
}

func TestPrepareCurrentDiscoveryExactAggregateByteBoundary(t *testing.T) {
	exact := currentDiscoveryMessagesAtEncodedBytes(t, MaximumCurrentDiscoveryEncodedBytes)
	commit := currentDiscoveryFixture(t, 0)
	commit.Messages = exact
	prepared, err := PrepareCurrentDiscoveryCommit(commit)
	if err != nil {
		t.Fatalf("exact aggregate error = %v", err)
	}
	if prepared.EncodedBytes() != MaximumCurrentDiscoveryEncodedBytes {
		t.Fatalf("encoded bytes = %d", prepared.EncodedBytes())
	}
	commit.Messages = currentDiscoveryMessagesAtEncodedBytes(t, MaximumCurrentDiscoveryEncodedBytes+1)
	if _, err := PrepareCurrentDiscoveryCommit(commit); !errors.Is(err, ErrCurrentDiscoveryTooLarge) {
		t.Fatalf("over-bound aggregate error = %v", err)
	}
}

func currentDiscoveryMessagesAtEncodedBytes(t *testing.T, target int) []mail.Message {
	t.Helper()
	accountID, _ := ParseAccountID("00112233445566778899aabbccddeeff")
	base := make([]mail.Message, 0, MaximumCurrentDiscoveryMessages)
	baseTotal := 0
	maximumTotal := 0
	for index := 0; index < MaximumCurrentDiscoveryMessages; index++ {
		message, err := mail.Normalize(accountID.String(), mail.MessageInput{
			GmailMessageID: fmt.Sprintf("boundary-%04d", index), GmailThreadID: fmt.Sprintf("thread-%04d", index),
			To: []string{}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{},
		})
		if err != nil {
			t.Fatal(err)
		}
		base = append(base, message)
		baseTotal += int(encodedMessageSize(message))
		maximumTotal = baseTotal + len(base)*4096
		if maximumTotal >= target {
			break
		}
	}
	if baseTotal > target || maximumTotal < target {
		t.Fatalf("cannot construct target %d from %d messages: base=%d max=%d", target, len(base), baseTotal, maximumTotal)
	}
	remaining := target - baseTotal
	result := make([]mail.Message, len(base))
	for index := range base {
		length := remaining
		if length > 4096 {
			length = 4096
		}
		remaining -= length
		message, err := mail.Normalize(accountID.String(), mail.MessageInput{
			GmailMessageID: fmt.Sprintf("boundary-%04d", index), GmailThreadID: fmt.Sprintf("thread-%04d", index), Subject: strings.Repeat("x", length),
			To: []string{}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{},
		})
		if err != nil {
			t.Fatal(err)
		}
		result[index] = message
	}
	if remaining != 0 {
		t.Fatalf("unallocated target bytes = %d", remaining)
	}
	return result
}
