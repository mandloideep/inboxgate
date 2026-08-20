package main

import (
	"os"
	"strings"
	"testing"
)

func TestReviewReadRuntimeUsesOneSharedCredentialFreeSource(t *testing.T) {
	contents, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, required := range []string{
		"configuration.Capabilities.MailReviewRead",
		"sharedMCPSource",
		"accountstatus.New(sharedMCPSource",
		"reviewinspect.New(sharedMCPSource",
		"databaseToken",
		"accountEnrollmentStorageAllowed",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("runtime composition missing %q", required)
		}
	}
	if strings.Count(text, "openMCPReadSource(") != 2 {
		t.Fatalf("shared MCP source open symbol count = %d, want declaration and one call", strings.Count(text, "openMCPReadSource("))
	}
	if strings.Contains(text, "openMCPReviewSource(") {
		t.Fatal("review tools have a second storage opener")
	}
}

func TestReviewReadShutdownStopsAdmissionBeforeOneSharedSourceClose(t *testing.T) {
	contents, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	start := strings.Index(text, "type mcpReadCloser struct")
	if start < 0 {
		t.Fatal("shared MCP closer is missing")
	}
	closer := text[start:]
	handlerClose := strings.Index(closer, "handler.Close()")
	sourceClose := strings.Index(closer, "source.Close()")
	if handlerClose < 0 || sourceClose < 0 || handlerClose > sourceClose || strings.Count(closer[:sourceClose+len("source.Close()")], "source.Close()") != 1 {
		t.Fatalf("shared close ordering is not handler then one source close")
	}
	if strings.Contains(text, "defer mcpCloser.Close()") {
		t.Fatal("runServe retains a second shared MCP close owner")
	}
}
