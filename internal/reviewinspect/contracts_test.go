package reviewinspect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReviewInspectionDocumentationStatesAuthorizationTrustAndNoExcerptBoundary(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	files := []string{
		"docs/product-specification.md",
		"docs/threat-model.md",
		"docs/known-risks.md",
		"docs/owner-readiness.md",
		"README.md",
	}
	required := []string{
		"mail_list_review_candidates",
		"mail_get_gate_reason",
		"untrusted_email",
		"Candidate excerpts are explicitly excluded",
		"one owner-approved",
		"TURSO-005",
	}
	for _, path := range files {
		contents, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		text := string(contents)
		for _, phrase := range required {
			if !strings.Contains(text, phrase) {
				t.Errorf("%s missing %q", path, phrase)
			}
		}
	}
}

func TestReviewInspectionCIWiresEveryBoundedFuzzTarget(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, target := range []string{
		"FuzzListRequestAndCursorDecodingRemainClosedAndBounded",
		"FuzzPreviewTruncationNeverSplitsUTF8OrExceedsLimit",
		"FuzzReviewInspectionTursoDecoder",
		"FuzzReviewToolEnvelopesRemainBoundedAndClosed",
	} {
		if !strings.Contains(text, target) {
			t.Errorf("Makefile does not gate %s", target)
		}
	}
}

func TestReviewInspectionPackageImportsNoBroadAuthority(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	for _, directory := range []string{"internal/reviewinspect", "internal/mcp"} {
		entries, err := os.ReadDir(filepath.Join(root, directory))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			contents, err := os.ReadFile(filepath.Join(root, directory, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			text := string(contents)
			for _, forbidden := range []string{"internal/gmail", "internal/cryptobox", "database/sql", "os/exec", "net/url", "internal/storage/turso"} {
				if strings.Contains(text, forbidden) {
					t.Errorf("%s imports broad authority %q", entry.Name(), forbidden)
				}
			}
		}
	}
}
