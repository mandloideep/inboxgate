package mail

import (
	"strings"
	"testing"
)

func TestCandidateContentKnownVectorAndRoundTrip(t *testing.T) {
	input := CandidateContentInput{
		RecordID: strings.Repeat("1", 64), SourceMetadataHash: strings.Repeat("2", 64),
		GateVersion: 1, GateInputHash: strings.Repeat("3", 64), SourceKind: CandidateSourceTextPlain,
		Excerpt: "first line\nsecond line", ExcerptLimit: 1024, Truncated: false, FetchedAtUnixMS: 1700000000123,
	}
	content, err := NewCandidateContent(input)
	if err != nil {
		t.Fatal(err)
	}
	if content.ContentHash() != "24c6b640fa2c199cce21fb1c8e75de9378313db558448a7f2fe937a9d9703926" {
		t.Fatalf("content hash = %s", content.ContentHash())
	}
	if content.ExcerptBytes() != len(input.Excerpt) || content.ContentTrust() != ContentTrustUntrustedEmail || !content.Valid() {
		t.Fatalf("content = %#v", content)
	}
	decoded, err := DecodeCandidateContent(
		int64(content.ExtractorVersion()), content.RecordID(), content.SourceMetadataHash(), int64(content.GateVersion()),
		content.GateInputHash(), content.SourceKind().String(), content.Excerpt(), int64(content.ExcerptBytes()),
		int64(content.ExcerptLimit()), boolInteger(content.Truncated()), content.ContentHash(), content.FetchedAtUnixMS(),
	)
	if err != nil || !decoded.Equal(content) {
		t.Fatalf("decoded=%#v err=%v", decoded, err)
	}
}

func TestCandidateContentRejectsEveryBoundaryViolation(t *testing.T) {
	valid := CandidateContentInput{
		RecordID: strings.Repeat("1", 64), SourceMetadataHash: strings.Repeat("2", 64), GateVersion: 1,
		GateInputHash: strings.Repeat("3", 64), SourceKind: CandidateSourceTextHTML, Excerpt: strings.Repeat("x", MinimumExcerptBytes),
		ExcerptLimit: MinimumExcerptBytes, Truncated: true, FetchedAtUnixMS: MaximumContentFetchedAtUnixMS,
	}
	tests := []struct {
		name string
		edit func(*CandidateContentInput)
	}{
		{"empty excerpt", func(v *CandidateContentInput) { v.Excerpt = "" }},
		{"invalid utf8", func(v *CandidateContentInput) { v.Excerpt = string([]byte{0xff}) }},
		{"nul", func(v *CandidateContentInput) { v.Excerpt = "x\x00y" }},
		{"limit below", func(v *CandidateContentInput) { v.ExcerptLimit = MinimumExcerptBytes - 1 }},
		{"limit above", func(v *CandidateContentInput) { v.ExcerptLimit = MaximumExcerptBytes + 1 }},
		{"excerpt one over", func(v *CandidateContentInput) { v.Excerpt = strings.Repeat("x", v.ExcerptLimit+1) }},
		{"bad record", func(v *CandidateContentInput) { v.RecordID = strings.Repeat("A", 64) }},
		{"bad metadata hash", func(v *CandidateContentInput) { v.SourceMetadataHash = strings.Repeat("g", 64) }},
		{"bad gate input", func(v *CandidateContentInput) { v.GateInputHash = strings.Repeat("3", 63) }},
		{"zero gate version", func(v *CandidateContentInput) { v.GateVersion = 0 }},
		{"unknown kind", func(v *CandidateContentInput) { v.SourceKind = CandidateSourceKind("raw") }},
		{"negative timestamp", func(v *CandidateContentInput) { v.FetchedAtUnixMS = -1 }},
		{"timestamp one over", func(v *CandidateContentInput) { v.FetchedAtUnixMS = MaximumContentFetchedAtUnixMS + 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := valid
			tt.edit(&candidate)
			if _, err := NewCandidateContent(candidate); err == nil {
				t.Fatal("invalid candidate content accepted")
			}
		})
	}
}

func TestCandidateContentRejectsNoncanonicalExcerptInConstructionAndDecode(t *testing.T) {
	valid := CandidateContentInput{
		RecordID: strings.Repeat("1", 64), SourceMetadataHash: strings.Repeat("2", 64), GateVersion: 1,
		GateInputHash: strings.Repeat("3", 64), SourceKind: CandidateSourceTextPlain, ExcerptLimit: 1024,
		FetchedAtUnixMS: 1700000000123,
	}
	for _, excerpt := range []string{
		" leading", "trailing ", "line one \nline two", "line one\t\nline two", "line one\r\nline two",
		"line one\n\n\nline two", "left\u202eright", "left\u200bright", "left\x01right",
	} {
		t.Run(strings.ReplaceAll(excerpt, "\n", "_"), func(t *testing.T) {
			input := valid
			input.Excerpt = excerpt
			if _, err := NewCandidateContent(input); err == nil {
				t.Fatalf("constructor accepted noncanonical excerpt %q", excerpt)
			}
			hashText := deriveCandidateContentHash(CandidateExtractorVersion1, input.GateVersion, input.SourceKind, input.ExcerptLimit, false, excerpt)
			if _, err := DecodeCandidateContent(
				int64(CandidateExtractorVersion1), input.RecordID, input.SourceMetadataHash, int64(input.GateVersion), input.GateInputHash,
				input.SourceKind.String(), excerpt, int64(len(excerpt)), int64(input.ExcerptLimit), 0, hashText, input.FetchedAtUnixMS,
			); err == nil {
				t.Fatalf("durable decode accepted noncanonical excerpt %q", excerpt)
			}
		})
	}
}

func boolInteger(value bool) int64 {
	if value {
		return 1
	}
	return 0
}
