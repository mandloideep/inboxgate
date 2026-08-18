package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/mandloideep/inboxgate/internal/mail"
)

const (
	MaximumCurrentDiscoveryPages                = 10
	MaximumCurrentDiscoveryPageMessages         = 500
	MaximumCurrentDiscoveryMessages             = 5000
	MaximumCurrentDiscoveryEncodedBytes         = 16777216
	MaximumCurrentDiscoveryManifestWitnessBytes = 78 + (2 * MaximumCurrentDiscoveryEncodedBytes)
	MaximumCurrentDiscoveryStageWireBytes       = 40 * 1024 * 1024
	CurrentDiscoveryStageChunkMessages          = 64
	CurrentDiscoveryStageParameters             = 514
	currentDiscoveryAttemptDomain               = "inboxgate/current-sync/v1"
	currentDiscoveryManifestDomain              = "inboxgate/current-sync-manifest/v1"
)

var (
	ErrCurrentDiscoveryTooLarge         = errors.New("storage: current discovery too large")
	ErrCurrentDiscoveryConflict         = errors.New("storage: current discovery conflict")
	ErrCurrentDiscoveryRecoveryRequired = errors.New("storage: current discovery recovery required")
	ErrMessageNotFound                  = errors.New("storage: discovered message not found")
	ErrMessageIdentityCollision         = errors.New("storage: message identity collision")
)

// CurrentDiscoveryCommit is one complete bounded normalized page chain.
type CurrentDiscoveryCommit struct {
	AccountID AccountID
	Expected  HistoryID
	Next      HistoryID
	Messages  []mail.Message
}

// PreparedCurrentDiscovery is the canonical immutable storage plan derived from a commit.
type PreparedCurrentDiscovery struct {
	accountID       AccountID
	expected        HistoryID
	next            HistoryID
	messages        []mail.Message
	encodedSizes    []uint32
	encodedBytes    uint64
	attemptID       string
	manifestHash    string
	manifestWitness string
}

// PrepareCurrentDiscoveryCommit validates, orders, deduplicates, bounds, and hashes a commit.
func PrepareCurrentDiscoveryCommit(commit CurrentDiscoveryCommit) (PreparedCurrentDiscovery, error) {
	if !commit.AccountID.valid() || !commit.Expected.valid() || !commit.Next.valid() || commit.Next.Compare(commit.Expected) <= 0 {
		return PreparedCurrentDiscovery{}, ErrInvalidValue
	}
	if len(commit.Messages) > MaximumCurrentDiscoveryMessages {
		return PreparedCurrentDiscovery{}, ErrCurrentDiscoveryTooLarge
	}
	messages := append([]mail.Message{}, commit.Messages...)
	for _, message := range messages {
		if !message.Valid() || message.AccountID() != commit.AccountID.String() {
			return PreparedCurrentDiscovery{}, ErrInvalidValue
		}
	}
	slices.SortFunc(messages, mail.CompareGmailMessageID)
	unique := messages[:0]
	for _, message := range messages {
		if len(unique) == 0 || unique[len(unique)-1].GmailMessageID() != message.GmailMessageID() {
			unique = append(unique, message)
			continue
		}
		if !unique[len(unique)-1].Equal(message) {
			return PreparedCurrentDiscovery{}, ErrCurrentDiscoveryConflict
		}
	}
	messages = unique
	encodedSizes := make([]uint32, len(messages))
	var encodedBytes uint64
	for index, message := range messages {
		size := encodedMessageSize(message)
		encodedSizes[index] = size
		encodedBytes += uint64(size)
		if encodedBytes > MaximumCurrentDiscoveryEncodedBytes {
			return PreparedCurrentDiscovery{}, ErrCurrentDiscoveryTooLarge
		}
	}
	attemptHash := sha256.New()
	writeHashDomain(attemptHash, currentDiscoveryAttemptDomain)
	writeHashText(attemptHash, commit.AccountID.String())
	writeHashText(attemptHash, commit.Expected.String())
	writeHashText(attemptHash, commit.Next.String())
	writeHashUint32(attemptHash, uint32(len(messages)))
	manifestHash := sha256.New()
	var manifestPreimage bytes.Buffer
	writeHashDomain(manifestHash, currentDiscoveryManifestDomain)
	writeHashUint32(manifestHash, uint32(len(messages)))
	writeHashDomain(&manifestPreimage, currentDiscoveryManifestDomain)
	writeHashUint32(&manifestPreimage, uint32(len(messages)))
	for _, message := range messages {
		writeEncodedMessage(attemptHash, message)
		writeEncodedMessage(manifestHash, message)
		writeEncodedMessage(&manifestPreimage, message)
	}
	return PreparedCurrentDiscovery{
		accountID: commit.AccountID, expected: commit.Expected, next: commit.Next, messages: messages,
		encodedSizes: encodedSizes, encodedBytes: encodedBytes,
		attemptID: hex.EncodeToString(attemptHash.Sum(nil)), manifestHash: hex.EncodeToString(manifestHash.Sum(nil)),
		manifestWitness: hex.EncodeToString(manifestPreimage.Bytes()),
	}, nil
}

func encodedMessageSize(message mail.Message) uint32 {
	return uint32(4 + len(message.RecordID()) + 4 + len(message.GmailMessageID()) + 4 + len(message.GmailThreadID()) + 4 + 4 + len(message.CanonicalJSON()) + 4 + len(message.MetadataHash()))
}

func writeEncodedMessage(writer io.Writer, message mail.Message) {
	writeHashText(writer, message.RecordID())
	writeHashText(writer, message.GmailMessageID())
	writeHashText(writer, message.GmailThreadID())
	writeHashUint32(writer, message.MetadataVersion())
	metadata := message.CanonicalJSON()
	writeHashUint32(writer, uint32(len(metadata)))
	_, _ = writer.Write(metadata)
	writeHashText(writer, message.MetadataHash())
}

func writeHashDomain(writer io.Writer, value string) {
	_, _ = writer.Write([]byte(value))
	_, _ = writer.Write([]byte{0})
}

func writeHashText(writer io.Writer, value string) {
	writeHashUint32(writer, uint32(len(value)))
	_, _ = writer.Write([]byte(value))
}

func writeHashUint32(writer io.Writer, value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	_, _ = writer.Write(encoded[:])
}

func (prepared PreparedCurrentDiscovery) AccountID() AccountID    { return prepared.accountID }
func (prepared PreparedCurrentDiscovery) Expected() HistoryID     { return prepared.expected }
func (prepared PreparedCurrentDiscovery) Next() HistoryID         { return prepared.next }
func (prepared PreparedCurrentDiscovery) AttemptID() string       { return prepared.attemptID }
func (prepared PreparedCurrentDiscovery) ManifestHash() string    { return prepared.manifestHash }
func (prepared PreparedCurrentDiscovery) ManifestWitness() string { return prepared.manifestWitness }
func (prepared PreparedCurrentDiscovery) MessageCount() int       { return len(prepared.messages) }
func (prepared PreparedCurrentDiscovery) EncodedBytes() uint64    { return prepared.encodedBytes }
func (prepared PreparedCurrentDiscovery) Messages() []mail.Message {
	return append([]mail.Message{}, prepared.messages...)
}
func (prepared PreparedCurrentDiscovery) StageChunkCount() int {
	return (len(prepared.messages) + CurrentDiscoveryStageChunkMessages - 1) / CurrentDiscoveryStageChunkMessages
}
func (prepared PreparedCurrentDiscovery) EncodedSize(index int) uint32 {
	if index < 0 || index >= len(prepared.encodedSizes) {
		return 0
	}
	return prepared.encodedSizes[index]
}

func (prepared PreparedCurrentDiscovery) RowWitness(index int) string {
	if index < 0 || index >= len(prepared.messages) {
		return ""
	}
	var encoded bytes.Buffer
	writeEncodedMessage(&encoded, prepared.messages[index])
	return hex.EncodeToString(encoded.Bytes())
}

func preparedCurrentDiscoveryValid(prepared PreparedCurrentDiscovery) bool {
	commit := CurrentDiscoveryCommit{AccountID: prepared.accountID, Expected: prepared.expected, Next: prepared.next, Messages: prepared.messages}
	rebuilt, err := PrepareCurrentDiscoveryCommit(commit)
	return err == nil && rebuilt.attemptID == prepared.attemptID && rebuilt.manifestHash == prepared.manifestHash && rebuilt.manifestWitness == prepared.manifestWitness && rebuilt.encodedBytes == prepared.encodedBytes
}

// ValidateGmailMessageID validates the binary visible-ASCII natural-key component.
func ValidateGmailMessageID(value string) error {
	if len(value) == 0 || len(value) > 255 || strings.IndexFunc(value, func(character rune) bool {
		return character < 0x21 || character > 0x7e
	}) >= 0 {
		return ErrInvalidValue
	}
	return nil
}
