package mail

import (
	"encoding/hex"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
)

const testAccountID = "00112233445566778899aabbccddeeff"

func validInput() MessageInput {
	return MessageInput{
		GmailMessageID:  "message-1",
		GmailThreadID:   "thread-1",
		RFCMessageID:    "<synthetic-1@example.invalid>",
		InternalDateMS:  1735689600000,
		SenderDisplay:   "Synthetic Sender",
		SenderAddress:   "sender@example.invalid",
		To:              []string{"recipient@example.invalid"},
		CC:              []string{},
		DeliveredTo:     []string{"recipient@example.invalid"},
		Subject:         "Synthetic subject",
		Labels:          []string{"INBOX", "Label_1"},
		SizeEstimate:    4096,
		AttachmentCount: 1,
		ListID:          "list.example.invalid",
		AutoSubmitted:   "no",
		Precedence:      "list",
		ListUnsubscribe: true,
	}
}

func TestNormalizeAcceptsExactPublishedMaximaAndCanonicalizesLists(t *testing.T) {
	input := validInput()
	input.GmailMessageID = strings.Repeat("m", 255)
	input.GmailThreadID = strings.Repeat("t", 255)
	input.RFCMessageID = strings.Repeat("r", 998)
	input.InternalDateMS = math.MaxInt64
	input.SenderDisplay = strings.Repeat("d", 512)
	input.SenderAddress = strings.Repeat("s", 512)
	input.Subject = strings.Repeat("u", 4096)
	input.ListID = strings.Repeat("l", 512)
	input.AutoSubmitted = strings.Repeat("a", 128)
	input.Precedence = strings.Repeat("p", 128)
	input.SizeEstimate = math.MaxUint32
	input.AttachmentCount = 1000
	input.To = []string{"z@example.invalid", "a@example.invalid", "z@example.invalid"}
	input.CC = []string{"c@example.invalid", "b@example.invalid", "b@example.invalid"}
	input.DeliveredTo = []string{"y@example.invalid", "x@example.invalid", "x@example.invalid"}
	input.Labels = []string{"z", "a", "z"}
	message, err := Normalize(testAccountID, input)
	if err != nil {
		t.Fatalf("Normalize() exact maxima error = %v", err)
	}
	canonical := string(message.CanonicalJSON())
	for _, exact := range []string{
		`"internal_date_ms":"` + strconv.FormatInt(math.MaxInt64, 10) + `"`,
		`"to":["a@example.invalid","z@example.invalid"]`,
		`"cc":["b@example.invalid","c@example.invalid"]`,
		`"delivered_to":["x@example.invalid","y@example.invalid"]`,
		`"labels":["a","z"]`,
		`"size_estimate":4294967295`,
		`"attachment_count":1000`,
	} {
		if !strings.Contains(canonical, exact) {
			t.Fatalf("canonical maxima missing %s", exact)
		}
	}
}

func TestNormalizeAcceptsEachExactCollectionAndEntryMaximumSeparately(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*MessageInput)
	}{
		{name: "100 to", mutate: func(input *MessageInput) { input.To = fixedWidthValues("to", 100, 32) }},
		{name: "100 cc", mutate: func(input *MessageInput) { input.CC = fixedWidthValues("cc", 100, 32) }},
		{name: "10 delivered to", mutate: func(input *MessageInput) { input.DeliveredTo = fixedWidthValues("delivered", 10, 32) }},
		{name: "128 labels", mutate: func(input *MessageInput) { input.Labels = fixedWidthValues("label", 128, 24) }},
		{name: "512 byte address", mutate: func(input *MessageInput) { input.To = []string{strings.Repeat("a", 512)} }},
		{name: "128 byte label", mutate: func(input *MessageInput) { input.Labels = []string{strings.Repeat("l", 128)} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := validInput()
			tt.mutate(&input)
			if _, err := Normalize(testAccountID, input); err != nil {
				t.Fatalf("Normalize() exact accepted maximum error = %v", err)
			}
		})
	}
}

func TestNormalizeRejectsInvalidUTF8AndIdentityASCIIEdges(t *testing.T) {
	for _, mutate := range []func(*MessageInput){
		func(input *MessageInput) { input.GmailMessageID = "message\x00id" },
		func(input *MessageInput) { input.GmailThreadID = "thread\x00id" },
		func(input *MessageInput) { input.GmailMessageID = "message\x80" },
		func(input *MessageInput) { input.GmailThreadID = "thread\x80" },
		func(input *MessageInput) { input.Subject = string([]byte{'x', 0xff}) },
		func(input *MessageInput) { input.To = []string{string([]byte{'x', 0xff})} },
	} {
		input := validInput()
		mutate(&input)
		if _, err := Normalize(testAccountID, input); !errors.Is(err, ErrInvalidMetadata) {
			t.Fatalf("Normalize() invalid byte error = %v", err)
		}
	}
}

func TestNormalizeEnforcesExactCanonicalJSONByteBoundary(t *testing.T) {
	exact := inputForCanonicalSize(t, MaximumCanonicalJSONBytes)
	message, err := Normalize(testAccountID, exact)
	if err != nil || len(message.CanonicalJSON()) != MaximumCanonicalJSONBytes {
		t.Fatalf("exact canonical boundary = (%d, %v)", len(message.CanonicalJSON()), err)
	}
	exact.Subject += "x"
	if _, err := Normalize(testAccountID, exact); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("canonical max+1 error = %v", err)
	}
}

func inputForCanonicalSize(t *testing.T, target int) MessageInput {
	t.Helper()
	for itemBytes := 100; itemBytes <= 500; itemBytes++ {
		input := validInput()
		input.Subject = ""
		input.To = fixedWidthValues("to", 100, itemBytes)
		input.CC = fixedWidthValues("cc", 100, itemBytes)
		input.DeliveredTo = fixedWidthValues("delivered", 10, itemBytes)
		message, err := Normalize(testAccountID, input)
		if err != nil {
			continue
		}
		remaining := target - len(message.CanonicalJSON())
		if remaining < 0 || remaining >= 4096 {
			continue
		}
		input.Subject = strings.Repeat("x", remaining)
		return input
	}
	t.Fatal("could not construct exact canonical JSON boundary")
	return MessageInput{}
}

func fixedWidthValues(prefix string, count, width int) []string {
	result := make([]string, count)
	for index := range result {
		suffix := prefix + strconv.Itoa(index)
		result[index] = strings.Repeat("x", width-len(suffix)) + suffix
	}
	return result
}

func TestNormalizeProducesCanonicalUntrustedMetadata(t *testing.T) {
	input := validInput()
	input.Labels = []string{"Label_1", "INBOX", "INBOX"}
	message, err := Normalize(testAccountID, input)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	wantRecordID := "77a594ab17d0283de80c7bfc9706298f4a6d57ec2e39d8d7513ee4eafa64a903"
	if message.RecordID() != wantRecordID {
		t.Fatalf("RecordID() = %q, want known vector %q", message.RecordID(), wantRecordID)
	}
	if message.AccountID() != testAccountID || message.GmailMessageID() != input.GmailMessageID || message.GmailThreadID() != input.GmailThreadID {
		t.Fatalf("message identity = %q/%q/%q", message.AccountID(), message.GmailMessageID(), message.GmailThreadID())
	}
	wantJSON := `{"version":1,"rfc_message_id":"<synthetic-1@example.invalid>","internal_date_ms":"1735689600000","sender_display":"Synthetic Sender","sender_address":"sender@example.invalid","to":["recipient@example.invalid"],"cc":[],"delivered_to":["recipient@example.invalid"],"subject":"Synthetic subject","labels":["INBOX","Label_1"],"size_estimate":4096,"attachment_count":1,"has_attachments":true,"list_id":"list.example.invalid","auto_submitted":"no","precedence":"list","list_unsubscribe":true,"discovery_source":"current_sync"}`
	if got := string(message.CanonicalJSON()); got != wantJSON {
		t.Fatalf("CanonicalJSON() = %s\nwant = %s", got, wantJSON)
	}
	if len(message.MetadataHash()) != 64 {
		t.Fatalf("MetadataHash() length = %d", len(message.MetadataHash()))
	}
	if _, err := hex.DecodeString(message.MetadataHash()); err != nil {
		t.Fatalf("MetadataHash() is not lowercase hex: %v", err)
	}
	if message.DiscoverySource() != DiscoverySourceCurrentSync || !message.Untrusted() {
		t.Fatal("normalized metadata lost source or untrusted marker")
	}
	decoded, err := DecodeCanonical(testAccountID, input.GmailMessageID, input.GmailThreadID, MetadataVersion1, message.CanonicalJSON(), message.MetadataHash())
	if err != nil {
		t.Fatalf("DecodeCanonical() error = %v", err)
	}
	if !message.Equal(decoded) {
		t.Fatal("canonical decode did not round trip exactly")
	}
}

func TestNormalizeRejectsEveryPublishedBound(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*MessageInput)
	}{
		{name: "empty message id", mutate: func(v *MessageInput) { v.GmailMessageID = "" }},
		{name: "message id too long", mutate: func(v *MessageInput) { v.GmailMessageID = strings.Repeat("m", 256) }},
		{name: "message id control", mutate: func(v *MessageInput) { v.GmailMessageID = "m\n" }},
		{name: "thread id too long", mutate: func(v *MessageInput) { v.GmailThreadID = strings.Repeat("t", 256) }},
		{name: "rfc message id too long", mutate: func(v *MessageInput) { v.RFCMessageID = strings.Repeat("x", 999) }},
		{name: "rfc message id control", mutate: func(v *MessageInput) { v.RFCMessageID = "<x>\x00" }},
		{name: "negative date", mutate: func(v *MessageInput) { v.InternalDateMS = -1 }},
		{name: "sender display too long", mutate: func(v *MessageInput) { v.SenderDisplay = strings.Repeat("x", 513) }},
		{name: "sender address control", mutate: func(v *MessageInput) { v.SenderAddress = "x\r@example.invalid" }},
		{name: "too many to", mutate: func(v *MessageInput) { v.To = repeatStrings("x@example.invalid", 101) }},
		{name: "too many cc", mutate: func(v *MessageInput) { v.CC = repeatStrings("x@example.invalid", 101) }},
		{name: "too many delivered to", mutate: func(v *MessageInput) { v.DeliveredTo = repeatStrings("x@example.invalid", 11) }},
		{name: "address too long", mutate: func(v *MessageInput) { v.To = []string{strings.Repeat("x", 513)} }},
		{name: "subject too long", mutate: func(v *MessageInput) { v.Subject = strings.Repeat("x", 4097) }},
		{name: "subject control", mutate: func(v *MessageInput) { v.Subject = "x\x7f" }},
		{name: "unicode control", mutate: func(v *MessageInput) { v.Subject = "x\u0085" }},
		{name: "too many labels", mutate: func(v *MessageInput) { v.Labels = numberedStrings("label", 129) }},
		{name: "empty label", mutate: func(v *MessageInput) { v.Labels = []string{""} }},
		{name: "label too long", mutate: func(v *MessageInput) { v.Labels = []string{strings.Repeat("x", 129)} }},
		{name: "attachment count", mutate: func(v *MessageInput) { v.AttachmentCount = 1001 }},
		{name: "list id too long", mutate: func(v *MessageInput) { v.ListID = strings.Repeat("x", 513) }},
		{name: "auto submitted control", mutate: func(v *MessageInput) { v.AutoSubmitted = "x\n" }},
		{name: "precedence too long", mutate: func(v *MessageInput) { v.Precedence = strings.Repeat("x", 129) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := validInput()
			tt.mutate(&input)
			if _, err := Normalize(testAccountID, input); !errors.Is(err, ErrInvalidMetadata) {
				t.Fatalf("Normalize() error = %v, want ErrInvalidMetadata", err)
			}
		})
	}
	for _, accountID := range []string{"", strings.Repeat("0", 31), strings.Repeat("A", 32), strings.Repeat("g", 32)} {
		if _, err := Normalize(accountID, validInput()); !errors.Is(err, ErrInvalidMetadata) {
			t.Fatalf("Normalize(%q) error = %v", accountID, err)
		}
	}
}

func TestDecodeCanonicalRejectsNoncanonicalAndTamperedValues(t *testing.T) {
	message, err := Normalize(testAccountID, validInput())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		version uint32
		body    []byte
		hash    string
	}{
		{name: "unknown version", version: 2, body: message.CanonicalJSON(), hash: message.MetadataHash()},
		{name: "unknown field", version: 1, body: append(message.CanonicalJSON()[:len(message.CanonicalJSON())-1], []byte(`,"extra":true}`)...), hash: message.MetadataHash()},
		{name: "trailing data", version: 1, body: append(message.CanonicalJSON(), ' '), hash: message.MetadataHash()},
		{name: "tampered hash", version: 1, body: message.CanonicalJSON(), hash: strings.Repeat("0", 64)},
		{name: "uppercase hash", version: 1, body: message.CanonicalJSON(), hash: strings.ToUpper(message.MetadataHash())},
		{name: "oversized", version: 1, body: []byte(strings.Repeat("x", MaximumCanonicalJSONBytes+1)), hash: message.MetadataHash()},
		{name: "duplicate field", version: 1, body: []byte(`{"version":1,"version":1}`), hash: message.MetadataHash()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecodeCanonical(testAccountID, message.GmailMessageID(), message.GmailThreadID(), tt.version, tt.body, tt.hash); !errors.Is(err, ErrInvalidMetadata) {
				t.Fatalf("DecodeCanonical() error = %v, want ErrInvalidMetadata", err)
			}
		})
	}
}

func repeatStrings(value string, count int) []string {
	result := make([]string, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func numberedStrings(prefix string, count int) []string {
	result := make([]string, count)
	for index := range result {
		result[index] = prefix + string(rune('A'+index%26)) + string(rune('a'+index/26))
	}
	return result
}
