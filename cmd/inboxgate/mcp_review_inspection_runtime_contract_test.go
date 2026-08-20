package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mandloideep/inboxgate/internal/config"
	inboxmcp "github.com/mandloideep/inboxgate/internal/mcp"
	"github.com/mandloideep/inboxgate/internal/storage"
)

type combinedReviewRuntimeSource struct {
	storage.Handle
	accountCalls atomic.Int64
	reviewCalls  atomic.Int64
	closeCalls   atomic.Int64
}

func (source *combinedReviewRuntimeSource) ListAccounts(context.Context) ([]storage.AccountSummary, error) {
	source.accountCalls.Add(1)
	return []storage.AccountSummary{}, nil
}

func (source *combinedReviewRuntimeSource) ListReviewCandidates(context.Context, storage.ReviewCandidateQuery) ([]storage.ReviewCandidateRow, error) {
	source.reviewCalls.Add(1)
	return []storage.ReviewCandidateRow{}, nil
}

func (source *combinedReviewRuntimeSource) Close() error {
	source.closeCalls.Add(1)
	return nil
}

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

func TestCombinedAccountStatusAndReviewRuntimeUsesOneInjectedHandle(t *testing.T) {
	configuration := config.Defaults()
	configuration.MCP.Enabled = true
	configuration.MCP.EnableOperatorTools = true
	configuration.Capabilities.MailReviewRead = true
	source := &combinedReviewRuntimeSource{}
	var opens atomic.Int64
	originalOpen := openOperatorAccountStatusSource
	openOperatorAccountStatusSource = func(context.Context, storage.Endpoint) (storage.Handle, error) {
		opens.Add(1)
		return source, nil
	}
	t.Cleanup(func() { openOperatorAccountStatusSource = originalOpen })

	handle, accountStatus, reviewInspection, err := openMCPReadServices(context.Background(), configuration, storage.Endpoint{URL: "http://127.0.0.1:1"})
	if err != nil || handle != source || accountStatus == nil || reviewInspection == nil || opens.Load() != 1 {
		t.Fatalf("services = handle %#v account %#v review %#v error %v opens %d", handle, accountStatus, reviewInspection, err, opens.Load())
	}
	if snapshot, snapshotErr := accountStatus.Snapshot(context.Background()); snapshotErr != nil || snapshot.Accounts == nil || source.accountCalls.Load() != 1 {
		t.Fatalf("Snapshot() = %#v, %v, calls %d", snapshot, snapshotErr, source.accountCalls.Load())
	}

	token := generatedMCPToken(t)
	handler, err := inboxmcp.New(inboxmcp.Options{
		Configuration: configuration, BinaryVersion: "dev", BearerToken: []byte(token), AuditOutput: io.Discard,
		AccountStatus: accountStatus, ReviewInspection: reviewInspection,
	})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mail_list_review_candidates","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"synthetic-client","version":"1.0.0"}}}}`
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+configuration.MCP.Path, strings.NewReader(body))
	request.Host = "127.0.0.1"
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Mcp-Protocol-Version", "2026-07-28")
	request.Header.Set("Mcp-Method", "tools/call")
	request.Header.Set("Mcp-Name", "mail_list_review_candidates")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"candidates":[]`) || source.reviewCalls.Load() != 1 {
		t.Fatalf("review response = %d %q calls %d", response.Code, response.Body.String(), source.reviewCalls.Load())
	}
	closer := &mcpReadCloser{handler: handler, source: handle}
	if closeErr := closer.Close(); closeErr != nil || source.closeCalls.Load() != 1 {
		t.Fatalf("Close() = %v, source calls %d", closeErr, source.closeCalls.Load())
	}
}
