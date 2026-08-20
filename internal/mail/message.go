// Package mail owns InboxGate's bounded normalized message vocabulary.
//
// Every value in this package is untrusted email data.
package mail

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MetadataVersion1           uint32 = 1
	MaximumCanonicalJSONBytes         = 65536
	DiscoverySourceCurrentSync        = "current_sync"
	messageRecordDomain               = "inboxgate/message-record/v1"
)

var ErrInvalidMetadata = errors.New("mail: invalid normalized metadata")

// MessageInput is the bounded provider-neutral input accepted for current discovery.
type MessageInput struct {
	GmailMessageID  string
	GmailThreadID   string
	RFCMessageID    string
	InternalDateMS  int64
	SenderDisplay   string
	SenderAddress   string
	To              []string
	CC              []string
	DeliveredTo     []string
	Subject         string
	Labels          []string
	SizeEstimate    uint32
	AttachmentCount uint16
	ListID          string
	AutoSubmitted   string
	Precedence      string
	ListUnsubscribe bool
}

type canonicalMetadata struct {
	Version         uint32   `json:"version"`
	RFCMessageID    string   `json:"rfc_message_id"`
	InternalDateMS  string   `json:"internal_date_ms"`
	SenderDisplay   string   `json:"sender_display"`
	SenderAddress   string   `json:"sender_address"`
	To              []string `json:"to"`
	CC              []string `json:"cc"`
	DeliveredTo     []string `json:"delivered_to"`
	Subject         string   `json:"subject"`
	Labels          []string `json:"labels"`
	SizeEstimate    uint32   `json:"size_estimate"`
	AttachmentCount uint16   `json:"attachment_count"`
	HasAttachments  bool     `json:"has_attachments"`
	ListID          string   `json:"list_id"`
	AutoSubmitted   string   `json:"auto_submitted"`
	Precedence      string   `json:"precedence"`
	ListUnsubscribe bool     `json:"list_unsubscribe"`
	DiscoverySource string   `json:"discovery_source"`
}

// Message is one fully validated canonical metadata record.
type Message struct {
	accountID      string
	recordID       string
	gmailMessageID string
	gmailThreadID  string
	metadata       canonicalMetadata
	canonicalJSON  []byte
	metadataHash   string
}

// Normalize validates and canonicalizes one untrusted metadata record.
func Normalize(accountID string, input MessageInput) (Message, error) {
	if !validAccountID(accountID) || !validVisibleASCII(input.GmailMessageID, 1, 255) || !validVisibleASCII(input.GmailThreadID, 1, 255) || input.InternalDateMS < 0 {
		return Message{}, ErrInvalidMetadata
	}
	if !validText(input.RFCMessageID, 998) || !validText(input.SenderDisplay, 512) || !validText(input.SenderAddress, 512) || !validText(input.Subject, 4096) || !validText(input.ListID, 512) || !validText(input.AutoSubmitted, 128) || !validText(input.Precedence, 128) {
		return Message{}, ErrInvalidMetadata
	}
	to, ok := canonicalTextList(input.To, 100, 512)
	if !ok {
		return Message{}, ErrInvalidMetadata
	}
	cc, ok := canonicalTextList(input.CC, 100, 512)
	if !ok {
		return Message{}, ErrInvalidMetadata
	}
	deliveredTo, ok := canonicalTextList(input.DeliveredTo, 10, 512)
	if !ok {
		return Message{}, ErrInvalidMetadata
	}
	labels, ok := canonicalLabels(input.Labels)
	if !ok || input.AttachmentCount > 1000 {
		return Message{}, ErrInvalidMetadata
	}
	metadata := canonicalMetadata{
		Version:         MetadataVersion1,
		RFCMessageID:    input.RFCMessageID,
		InternalDateMS:  strconv.FormatInt(input.InternalDateMS, 10),
		SenderDisplay:   input.SenderDisplay,
		SenderAddress:   input.SenderAddress,
		To:              to,
		CC:              cc,
		DeliveredTo:     deliveredTo,
		Subject:         input.Subject,
		Labels:          labels,
		SizeEstimate:    input.SizeEstimate,
		AttachmentCount: input.AttachmentCount,
		HasAttachments:  input.AttachmentCount != 0,
		ListID:          input.ListID,
		AutoSubmitted:   input.AutoSubmitted,
		Precedence:      input.Precedence,
		ListUnsubscribe: input.ListUnsubscribe,
		DiscoverySource: DiscoverySourceCurrentSync,
	}
	canonical, err := encodeCanonical(metadata)
	if err != nil || len(canonical) > MaximumCanonicalJSONBytes {
		return Message{}, ErrInvalidMetadata
	}
	hash := sha256.Sum256(canonical)
	return Message{
		accountID:      accountID,
		recordID:       deriveRecordID(accountID, input.GmailMessageID),
		gmailMessageID: input.GmailMessageID,
		gmailThreadID:  input.GmailThreadID,
		metadata:       metadata,
		canonicalJSON:  canonical,
		metadataHash:   hex.EncodeToString(hash[:]),
	}, nil
}

func encodeCanonical(metadata canonicalMetadata) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(metadata); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}

// DecodeCanonical validates a complete storage value before returning it.
func DecodeCanonical(accountID, gmailMessageID, gmailThreadID string, version uint32, body []byte, hashText string) (Message, error) {
	if version != MetadataVersion1 || len(body) == 0 || len(body) > MaximumCanonicalJSONBytes || !utf8.Valid(body) || !validLowerHex(hashText, 64) {
		return Message{}, ErrInvalidMetadata
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var metadata canonicalMetadata
	if err := decoder.Decode(&metadata); err != nil || decoder.More() {
		return Message{}, ErrInvalidMetadata
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return Message{}, ErrInvalidMetadata
	}
	internalDate, err := strconv.ParseInt(metadata.InternalDateMS, 10, 64)
	if err != nil || internalDate < 0 || strconv.FormatInt(internalDate, 10) != metadata.InternalDateMS || metadata.Version != version || metadata.DiscoverySource != DiscoverySourceCurrentSync || metadata.HasAttachments != (metadata.AttachmentCount != 0) {
		return Message{}, ErrInvalidMetadata
	}
	input := MessageInput{
		GmailMessageID: gmailMessageID, GmailThreadID: gmailThreadID, RFCMessageID: metadata.RFCMessageID,
		InternalDateMS: internalDate, SenderDisplay: metadata.SenderDisplay, SenderAddress: metadata.SenderAddress,
		To: metadata.To, CC: metadata.CC, DeliveredTo: metadata.DeliveredTo, Subject: metadata.Subject, Labels: metadata.Labels,
		SizeEstimate: metadata.SizeEstimate, AttachmentCount: metadata.AttachmentCount, ListID: metadata.ListID,
		AutoSubmitted: metadata.AutoSubmitted, Precedence: metadata.Precedence, ListUnsubscribe: metadata.ListUnsubscribe,
	}
	message, err := Normalize(accountID, input)
	if err != nil || !bytes.Equal(message.canonicalJSON, body) || message.metadataHash != hashText {
		return Message{}, ErrInvalidMetadata
	}
	return message, nil
}

func deriveRecordID(accountID, gmailMessageID string) string {
	hash := sha256.New()
	hash.Write([]byte(messageRecordDomain))
	hash.Write([]byte{0})
	writeLengthPrefixed(hash, accountID)
	writeLengthPrefixed(hash, gmailMessageID)
	return hex.EncodeToString(hash.Sum(nil))
}

type byteWriter interface {
	Write([]byte) (int, error)
}

func writeLengthPrefixed(writer byteWriter, value string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write([]byte(value))
}

func validAccountID(value string) bool {
	return validLowerHex(value, 32)
}

func validLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range []byte(value) {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func validVisibleASCII(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validText(value string, maximum int) bool {
	if len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func canonicalTextList(values []string, maximumCount, maximumBytes int) ([]string, bool) {
	if len(values) > maximumCount {
		return nil, false
	}
	result := append([]string{}, values...)
	for _, value := range result {
		if !validText(value, maximumBytes) {
			return nil, false
		}
	}
	slices.Sort(result)
	result = slices.Compact(result)
	return result, true
}

func canonicalLabels(values []string) ([]string, bool) {
	result := append([]string{}, values...)
	for _, value := range result {
		if !validVisibleASCII(value, 1, 128) {
			return nil, false
		}
	}
	slices.Sort(result)
	result = slices.Compact(result)
	if len(result) > 128 {
		return nil, false
	}
	return result, true
}

func (message Message) AccountID() string       { return message.accountID }
func (message Message) RecordID() string        { return message.recordID }
func (message Message) GmailMessageID() string  { return message.gmailMessageID }
func (message Message) GmailThreadID() string   { return message.gmailThreadID }
func (message Message) MetadataVersion() uint32 { return message.metadata.Version }
func (message Message) CanonicalJSON() []byte   { return bytes.Clone(message.canonicalJSON) }
func (message Message) MetadataHash() string    { return message.metadataHash }
func (message Message) DiscoverySource() string { return message.metadata.DiscoverySource }
func (message Message) Untrusted() bool         { return message.metadata.Version == MetadataVersion1 }
func (message Message) InternalDateUnixMS() int64 {
	value, _ := strconv.ParseInt(message.metadata.InternalDateMS, 10, 64)
	return value
}
func (message Message) SenderDisplay() string { return message.metadata.SenderDisplay }
func (message Message) SenderAddress() string { return message.metadata.SenderAddress }
func (message Message) Subject() string       { return message.metadata.Subject }
func (message Message) HasAttachments() bool  { return message.metadata.HasAttachments }

// Equal reports exact canonical identity and metadata equality.
func (message Message) Equal(other Message) bool {
	return message.accountID == other.accountID && message.recordID == other.recordID && message.gmailMessageID == other.gmailMessageID && message.gmailThreadID == other.gmailThreadID && message.metadataHash == other.metadataHash && bytes.Equal(message.canonicalJSON, other.canonicalJSON)
}

// Valid reports whether the value is a complete canonical message.
func (message Message) Valid() bool {
	decoded, err := DecodeCanonical(message.accountID, message.gmailMessageID, message.gmailThreadID, message.metadata.Version, message.canonicalJSON, message.metadataHash)
	return err == nil && decoded.recordID == message.recordID && message.Equal(decoded)
}

// MutableMetadataEqual reports whether only the canonical metadata is equal.
func (message Message) MutableMetadataEqual(other Message) bool {
	return message.metadataHash == other.metadataHash && bytes.Equal(message.canonicalJSON, other.canonicalJSON)
}

// CompareGmailMessageID orders messages by binary Gmail message ID.
func CompareGmailMessageID(left, right Message) int {
	return strings.Compare(left.gmailMessageID, right.gmailMessageID)
}
