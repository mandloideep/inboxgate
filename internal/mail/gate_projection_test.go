package mail

import "testing"

func TestGateProjectionIsTypedAndDefensivelyCopied(t *testing.T) {
	input := MessageInput{
		GmailMessageID: "synthetic-message", GmailThreadID: "synthetic-thread",
		SenderAddress: "Sender <person@example.test>", To: []string{"owner@example.test"},
		CC: []string{"copy@example.test"}, DeliveredTo: []string{"delivery@example.test"},
		Subject: "Synthetic subject", Labels: []string{"INBOX"}, ListID: "list.example.test",
		ListUnsubscribe: true, AutoSubmitted: "auto-generated", Precedence: "bulk",
	}
	message, err := Normalize("00112233445566778899aabbccddeeff", input)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := message.GateProjection()
	if err != nil {
		t.Fatalf("GateProjection() error = %v", err)
	}
	if projection.SenderAddress() != input.SenderAddress || projection.Subject() != input.Subject || projection.ListID() != input.ListID || !projection.ListUnsubscribe() || projection.AutoSubmitted() != input.AutoSubmitted || projection.Precedence() != input.Precedence {
		t.Fatalf("projection lost scalar metadata")
	}
	to := projection.To()
	cc := projection.CC()
	delivered := projection.DeliveredTo()
	labels := projection.Labels()
	to[0], cc[0], delivered[0], labels[0] = "changed", "changed", "changed", "changed"
	if projection.To()[0] != input.To[0] || projection.CC()[0] != input.CC[0] || projection.DeliveredTo()[0] != input.DeliveredTo[0] || projection.Labels()[0] != input.Labels[0] {
		t.Fatal("projection exposes mutable internal slices")
	}
	input.To[0] = "changed"
	if projection.To()[0] != "owner@example.test" {
		t.Fatal("projection aliases caller input")
	}
}

func TestZeroMessageHasNoGateProjection(t *testing.T) {
	if _, err := (Message{}).GateProjection(); err == nil {
		t.Fatal("zero message produced a gate projection")
	}
}
