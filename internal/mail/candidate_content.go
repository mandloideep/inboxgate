package mail

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	CandidateExtractorVersion1    uint32 = 1
	MinimumExcerptBytes                  = 1024
	MaximumExcerptBytes                  = 65536
	MaximumDecodedContentBytes           = 512 * 1024
	MaximumContentFetchedAtUnixMS int64  = 253402300799999
	candidateContentHashDomain           = "inboxgate/candidate-content/v1"
)

var ErrInvalidCandidateContent = errors.New("mail: invalid candidate content")

// CandidateSourceKind is the closed selected source vocabulary.
type CandidateSourceKind string

const (
	CandidateSourceTextPlain CandidateSourceKind = "text_plain"
	CandidateSourceTextHTML  CandidateSourceKind = "text_html"
)

func (kind CandidateSourceKind) String() string { return string(kind) }

func (kind CandidateSourceKind) Valid() bool {
	return kind == CandidateSourceTextPlain || kind == CandidateSourceTextHTML
}

// ContentTrust prevents sanitized email text from being interpreted as authority.
type ContentTrust string

const ContentTrustUntrustedEmail ContentTrust = "untrusted_email"

// CandidateContentInput is the complete source-bound input for one sanitized excerpt.
type CandidateContentInput struct {
	RecordID           string
	SourceMetadataHash string
	GateVersion        uint32
	GateInputHash      string
	SourceKind         CandidateSourceKind
	Excerpt            string
	ExcerptLimit       int
	Truncated          bool
	FetchedAtUnixMS    int64
}

// CandidateContent is one fully validated sanitized untrusted email excerpt.
type CandidateContent struct {
	extractorVersion   uint32
	recordID           string
	sourceMetadataHash string
	gateVersion        uint32
	gateInputHash      string
	sourceKind         CandidateSourceKind
	excerpt            string
	excerptBytes       int
	excerptLimit       int
	truncated          bool
	contentHash        string
	fetchedAtUnixMS    int64
}

// CandidateContentRevision is the exact durable compare-and-swap identity.
type CandidateContentRevision struct {
	extractorVersion   uint32
	sourceMetadataHash string
	gateInputHash      string
	excerptLimit       int
	contentHash        string
}

// NewCandidateContent validates one complete value and derives its content hash.
func NewCandidateContent(input CandidateContentInput) (CandidateContent, error) {
	if !validCandidateContentInput(input) {
		return CandidateContent{}, ErrInvalidCandidateContent
	}
	hashText := deriveCandidateContentHash(CandidateExtractorVersion1, input.GateVersion, input.SourceKind, input.ExcerptLimit, input.Truncated, input.Excerpt)
	return CandidateContent{
		extractorVersion: CandidateExtractorVersion1, recordID: input.RecordID, sourceMetadataHash: input.SourceMetadataHash,
		gateVersion: input.GateVersion, gateInputHash: input.GateInputHash, sourceKind: input.SourceKind,
		excerpt: input.Excerpt, excerptBytes: len(input.Excerpt), excerptLimit: input.ExcerptLimit,
		truncated: input.Truncated, contentHash: hashText, fetchedAtUnixMS: input.FetchedAtUnixMS,
	}, nil
}

// DecodeCandidateContent validates every durable field before returning it.
func DecodeCandidateContent(extractorVersion int64, recordID, sourceMetadataHash string, gateVersion int64, gateInputHash, sourceKind, excerpt string, excerptBytes, excerptLimit, truncated int64, contentHash string, fetchedAtUnixMS int64) (CandidateContent, error) {
	if extractorVersion != int64(CandidateExtractorVersion1) || gateVersion < 1 || gateVersion > int64(^uint32(0)) || excerptBytes < 0 || excerptBytes > int64(MaximumExcerptBytes) || excerptLimit < MinimumExcerptBytes || excerptLimit > MaximumExcerptBytes || (truncated != 0 && truncated != 1) || !validLowerHex(contentHash, 64) {
		return CandidateContent{}, ErrInvalidCandidateContent
	}
	input := CandidateContentInput{
		RecordID: recordID, SourceMetadataHash: sourceMetadataHash, GateVersion: uint32(gateVersion), GateInputHash: gateInputHash,
		SourceKind: CandidateSourceKind(sourceKind), Excerpt: excerpt, ExcerptLimit: int(excerptLimit),
		Truncated: truncated == 1, FetchedAtUnixMS: fetchedAtUnixMS,
	}
	content, err := NewCandidateContent(input)
	if err != nil || int64(content.excerptBytes) != excerptBytes || content.contentHash != contentHash {
		return CandidateContent{}, ErrInvalidCandidateContent
	}
	return content, nil
}

func validCandidateContentInput(input CandidateContentInput) bool {
	return validLowerHex(input.RecordID, 64) && validLowerHex(input.SourceMetadataHash, 64) && input.GateVersion > 0 &&
		validLowerHex(input.GateInputHash, 64) && input.SourceKind.Valid() && input.Excerpt != "" &&
		canonicalCandidateExcerpt(input.Excerpt) &&
		input.ExcerptLimit >= MinimumExcerptBytes && input.ExcerptLimit <= MaximumExcerptBytes && len(input.Excerpt) <= input.ExcerptLimit &&
		input.FetchedAtUnixMS >= 0 && input.FetchedAtUnixMS <= MaximumContentFetchedAtUnixMS
}

func canonicalCandidateExcerpt(value string) bool {
	if value == "" || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.Contains(value, "\n\n\n") {
		return false
	}
	for _, line := range strings.Split(value, "\n") {
		if strings.TrimRight(line, " \t") != line {
			return false
		}
	}
	for _, character := range value {
		if character != '\n' && character != '\t' && unicode.IsControl(character) || unsafeCandidateExcerptRune(character) {
			return false
		}
	}
	return true
}

func unsafeCandidateExcerptRune(value rune) bool {
	if value == 0x00ad || value == 0x061c || value == 0x200b || value == 0x200c || value == 0x200d || value == 0x200e || value == 0x200f || value == 0x2060 || value == 0xfeff {
		return true
	}
	return value >= 0x202a && value <= 0x202e || value >= 0x2066 && value <= 0x2069 || value >= 0xfe00 && value <= 0xfe0f || value >= 0xe0100 && value <= 0xe01ef
}

func deriveCandidateContentHash(extractorVersion, gateVersion uint32, kind CandidateSourceKind, limit int, truncated bool, excerpt string) string {
	digest := sha256.New()
	digest.Write([]byte(candidateContentHashDomain))
	digest.Write([]byte{0})
	writeCandidateUint32(digest, extractorVersion)
	writeCandidateUint32(digest, gateVersion)
	writeCandidateBytes(digest, []byte(kind))
	writeCandidateUint32(digest, uint32(limit))
	if truncated {
		digest.Write([]byte{1})
	} else {
		digest.Write([]byte{0})
	}
	writeCandidateBytes(digest, []byte(excerpt))
	return hex.EncodeToString(digest.Sum(nil))
}

func writeCandidateUint32(writer hash.Hash, value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	_, _ = writer.Write(encoded[:])
}

func writeCandidateBytes(writer hash.Hash, value []byte) {
	writeCandidateUint32(writer, uint32(len(value)))
	_, _ = writer.Write(value)
}

func (content CandidateContent) ExtractorVersion() uint32        { return content.extractorVersion }
func (content CandidateContent) RecordID() string                { return content.recordID }
func (content CandidateContent) SourceMetadataHash() string      { return content.sourceMetadataHash }
func (content CandidateContent) GateVersion() uint32             { return content.gateVersion }
func (content CandidateContent) GateInputHash() string           { return content.gateInputHash }
func (content CandidateContent) SourceKind() CandidateSourceKind { return content.sourceKind }
func (content CandidateContent) Excerpt() string                 { return content.excerpt }
func (content CandidateContent) ExcerptBytes() int               { return content.excerptBytes }
func (content CandidateContent) ExcerptLimit() int               { return content.excerptLimit }
func (content CandidateContent) Truncated() bool                 { return content.truncated }
func (content CandidateContent) ContentHash() string             { return content.contentHash }
func (content CandidateContent) FetchedAtUnixMS() int64          { return content.fetchedAtUnixMS }
func (content CandidateContent) ContentTrust() ContentTrust      { return ContentTrustUntrustedEmail }

func (content CandidateContent) Revision() CandidateContentRevision {
	return CandidateContentRevision{
		extractorVersion: content.extractorVersion, sourceMetadataHash: content.sourceMetadataHash,
		gateInputHash: content.gateInputHash, excerptLimit: content.excerptLimit, contentHash: content.contentHash,
	}
}

func (content CandidateContent) Equal(other CandidateContent) bool {
	return content.extractorVersion == other.extractorVersion && content.recordID == other.recordID &&
		content.sourceMetadataHash == other.sourceMetadataHash && content.gateVersion == other.gateVersion &&
		content.gateInputHash == other.gateInputHash && content.sourceKind == other.sourceKind &&
		content.excerpt == other.excerpt && content.excerptBytes == other.excerptBytes && content.excerptLimit == other.excerptLimit &&
		content.truncated == other.truncated && content.contentHash == other.contentHash && content.fetchedAtUnixMS == other.fetchedAtUnixMS
}

// SemanticEqual compares durable meaning while ignoring the first fetched timestamp.
func (content CandidateContent) SemanticEqual(other CandidateContent) bool {
	return content.extractorVersion == other.extractorVersion && content.recordID == other.recordID &&
		content.sourceMetadataHash == other.sourceMetadataHash && content.gateVersion == other.gateVersion &&
		content.gateInputHash == other.gateInputHash && content.sourceKind == other.sourceKind &&
		content.excerpt == other.excerpt && content.excerptBytes == other.excerptBytes && content.excerptLimit == other.excerptLimit &&
		content.truncated == other.truncated && content.contentHash == other.contentHash
}

func (content CandidateContent) Valid() bool {
	decoded, err := DecodeCandidateContent(
		int64(content.extractorVersion), content.recordID, content.sourceMetadataHash, int64(content.gateVersion),
		content.gateInputHash, content.sourceKind.String(), content.excerpt, int64(content.excerptBytes), int64(content.excerptLimit),
		boolToInteger(content.truncated), content.contentHash, content.fetchedAtUnixMS,
	)
	return err == nil && content.Equal(decoded)
}

func (revision CandidateContentRevision) ExtractorVersion() uint32 { return revision.extractorVersion }
func (revision CandidateContentRevision) SourceMetadataHash() string {
	return revision.sourceMetadataHash
}
func (revision CandidateContentRevision) GateInputHash() string { return revision.gateInputHash }
func (revision CandidateContentRevision) ExcerptLimit() int     { return revision.excerptLimit }
func (revision CandidateContentRevision) ContentHash() string   { return revision.contentHash }

func (revision CandidateContentRevision) Valid() bool {
	return revision.extractorVersion == CandidateExtractorVersion1 && validLowerHex(revision.sourceMetadataHash, 64) &&
		validLowerHex(revision.gateInputHash, 64) && revision.excerptLimit >= MinimumExcerptBytes &&
		revision.excerptLimit <= MaximumExcerptBytes && validLowerHex(revision.contentHash, 64)
}

func boolToInteger(value bool) int64 {
	if value {
		return 1
	}
	return 0
}
