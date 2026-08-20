package turso

import (
	"errors"
	"reflect"
	"testing"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/gate"
	"github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
)

type reviewInspectionValueScanner struct {
	values []any
}

func (scanner reviewInspectionValueScanner) Scan(destinations ...any) error {
	if len(destinations) != len(scanner.values) {
		return errors.New("synthetic scan cardinality")
	}
	for index, destination := range destinations {
		pointer, ok := destination.(*any)
		if !ok {
			return errors.New("synthetic scan destination")
		}
		*pointer = scanner.values[index]
	}
	return nil
}

func FuzzReviewInspectionTursoDecoder(f *testing.F) {
	f.Add(uint8(255), uint8(0), "", int64(0))
	f.Add(uint8(0), uint8(0), "malformed-account", int64(0))
	f.Add(uint8(3), uint8(1), "", int64(-1))
	f.Add(uint8(10), uint8(2), "", int64(0))
	f.Fuzz(func(t *testing.T, field, kind uint8, text string, number int64) {
		if len(text) > 1024 {
			return
		}
		accountID := "0000000000000000000000000000000a"
		message, err := mail.Normalize(accountID, mail.MessageInput{
			GmailMessageID: "message", GmailThreadID: "thread", InternalDateMS: 42,
			SenderAddress: "sender@example.test", To: []string{"owner@example.test"}, Subject: "Subject", Labels: []string{"INBOX"},
		})
		if err != nil {
			t.Fatal(err)
		}
		classification, err := gate.Classify(message, config.Defaults().Gate)
		if err != nil {
			t.Fatal(err)
		}
		decision, err := storage.NewGateDecision(classification, 43)
		if err != nil {
			t.Fatal(err)
		}
		values := []any{
			message.AccountID(), message.GmailMessageID(), message.GmailThreadID(), int64(message.MetadataVersion()),
			string(message.CanonicalJSON()), message.MetadataHash(), int64(decision.Version()), decision.SourceMetadataHash(),
			decision.InputHash(), decision.Outcome().String(), decision.ReasonJSON(), decision.EvaluatedAtUnixMS(),
		}
		if int(field) < len(values) {
			switch kind % 3 {
			case 0:
				values[field] = text
			case 1:
				values[field] = number
			case 2:
				values[field] = []byte(text)
			}
		}
		decodedMessage, decodedDecision, decodeErr := decodeReviewInspectionRow(reviewInspectionValueScanner{values: values})
		if field == 255 {
			if decodeErr != nil || decodedMessage.AccountID() != accountID || !decodedDecision.Valid() {
				t.Fatalf("valid row decode = %#v %#v %v", decodedMessage, decodedDecision, decodeErr)
			}
			return
		}
		if decodeErr != nil && (!reflect.DeepEqual(decodedMessage, mail.Message{}) || !reflect.DeepEqual(decodedDecision, storage.GateDecision{})) {
			t.Fatalf("failed decode returned partial message or decision: %v", decodeErr)
		}
	})
}
