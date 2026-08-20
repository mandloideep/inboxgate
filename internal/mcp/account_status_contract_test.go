package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/accountstatus"
	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/storage"
)

const (
	accountsListTool   = "accounts_list"
	mailSyncStatusTool = "mail_sync_status"
	operatorAccountID  = "0000000000000000000000000000000a"
)

type operatorSource struct {
	accounts []storage.AccountSummary
	err      error
	calls    atomic.Int64
	wait     bool
}

func (source *operatorSource) ListAccounts(ctx context.Context) ([]storage.AccountSummary, error) {
	source.calls.Add(1)
	if source.wait {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return append([]storage.AccountSummary(nil), source.accounts...), source.err
}

func operatorSummary(t *testing.T, rawID string, cursor bool) storage.AccountSummary {
	t.Helper()
	id, err := storage.ParseAccountID(rawID)
	if err != nil {
		t.Fatal(err)
	}
	version, err := storage.ParseLifecycleVersion(2)
	if err != nil {
		t.Fatal(err)
	}
	return storage.AccountSummary{AccountID: id, Provider: storage.ProviderGmail, State: storage.AccountStateActive, StateVersion: version, RevocationStatus: storage.RevocationStatusNone, CursorPresent: cursor}
}

func operatorHandler(t *testing.T, source *operatorSource, modifiers ...Option) *Handler {
	t.Helper()
	configuration := config.Defaults()
	configuration.MCP.Enabled = true
	configuration.MCP.EnableOperatorTools = true
	service, err := accountstatus.New(source, config.CapabilityRegistry(configuration))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
		Configuration: configuration, BinaryVersion: "dev", BearerToken: []byte(canonicalToken()),
		AuditOutput: io.Discard, AccountStatus: service,
	}, modifiers...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })
	return handler
}

func operatorRequestBody(name string, arguments string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":` + arguments + `,` + validMeta() + `}}`
}

func operatorRequest(t *testing.T, name string, arguments string) *http.Request {
	t.Helper()
	request := validRequest(t, "tools/call", operatorRequestBody(name, arguments))
	request.Header.Set("Mcp-Name", name)
	return request
}

func structuredResult(t *testing.T, responseBody []byte) json.RawMessage {
	t.Helper()
	var envelope struct {
		Result struct {
			StructuredContent json.RawMessage `json:"structuredContent"`
			Content           []any           `json:"content"`
			IsError           bool            `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(responseBody, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Result.IsError || len(envelope.Result.Content) != 0 || len(envelope.Result.StructuredContent) == 0 {
		t.Fatalf("tool result is not structured-only: %s", responseBody)
	}
	return envelope.Result.StructuredContent
}

func TestOperatorGateControlsExactBytewiseToolInventory(t *testing.T) {
	defaultHandler := newContractHandler(t, config.Defaults())
	defaultResponse := perform(t, defaultHandler, validRequest(t, "tools/list", requestBody("tools/list")))
	if names := listedToolNames(t, defaultResponse.Body.Bytes()); !reflect.DeepEqual(names, []string{systemCapabilitiesTool}) {
		t.Fatalf("default tools = %#v", names)
	}

	operator := operatorHandler(t, &operatorSource{})
	response := perform(t, operator, validRequest(t, "tools/list", requestBody("tools/list")))
	if names := listedToolNames(t, response.Body.Bytes()); !reflect.DeepEqual(names, []string{accountsListTool, mailSyncStatusTool, systemCapabilitiesTool}) {
		t.Fatalf("operator tools = %#v", names)
	}
	var envelope struct {
		Result struct {
			Tools []struct {
				Name        string         `json:"name"`
				InputSchema map[string]any `json:"inputSchema"`
				Annotations map[string]any `json:"annotations"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	wantSchema := map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}
	wantAnnotations := map[string]any{"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false}
	for _, tool := range envelope.Result.Tools {
		if !reflect.DeepEqual(tool.InputSchema, wantSchema) || !reflect.DeepEqual(tool.Annotations, wantAnnotations) {
			t.Errorf("tool %q contract = schema %#v annotations %#v", tool.Name, tool.InputSchema, tool.Annotations)
		}
	}
}

func listedToolNames(t *testing.T, body []byte) []string {
	t.Helper()
	var envelope struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(envelope.Result.Tools))
	for _, tool := range envelope.Result.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func TestDisabledOperatorToolsAreUnknownAndNeverCallSource(t *testing.T) {
	configuration := config.Defaults()
	configuration.MCP.Enabled = true
	source := &operatorSource{accounts: []storage.AccountSummary{operatorSummary(t, operatorAccountID, true)}}
	service, err := accountstatus.New(source, config.CapabilityRegistry(configuration))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{Configuration: configuration, BinaryVersion: "dev", BearerToken: []byte(canonicalToken()), AuditOutput: io.Discard, AccountStatus: service})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	for _, name := range []string{accountsListTool, mailSyncStatusTool} {
		response := perform(t, handler, operatorRequest(t, name, `{}`))
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"code":-32601`) {
			t.Fatalf("disabled %q = %d %q", name, response.Code, response.Body.String())
		}
	}
	if source.calls.Load() != 0 {
		t.Fatalf("disabled source calls = %d", source.calls.Load())
	}
}

func TestAuthenticationStructureAndArgumentsFinishBeforeAccountRead(t *testing.T) {
	source := &operatorSource{accounts: []storage.AccountSummary{operatorSummary(t, operatorAccountID, true)}}
	handler := operatorHandler(t, source)
	requests := []*http.Request{
		operatorRequest(t, accountsListTool, `{"account_id":"`+operatorAccountID+`"}`),
		operatorRequest(t, mailSyncStatusTool, `{"page_size":1}`),
		operatorRequest(t, accountsListTool, `[]`),
		operatorRequest(t, accountsListTool, `{`),
		operatorRequest(t, "unknown", `{}`),
	}
	unauthorized := operatorRequest(t, accountsListTool, `{}`)
	unauthorized.Header.Set("Authorization", "Bearer "+base64AlternativeToken())
	requests = append(requests, unauthorized)
	for _, request := range requests {
		response := perform(t, handler, request)
		if response.Code != http.StatusOK && response.Code != http.StatusUnauthorized {
			t.Fatalf("prevalidation response = %d %q", response.Code, response.Body.String())
		}
	}
	if source.calls.Load() != 0 {
		t.Fatalf("invalid request source calls = %d", source.calls.Load())
	}
}

func base64AlternativeToken() string {
	return "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE"
}

func TestAccountsListExactGoldenOmitsSensitiveAndUnpersistedFields(t *testing.T) {
	source := &operatorSource{accounts: []storage.AccountSummary{operatorSummary(t, operatorAccountID, true)}}
	handler := operatorHandler(t, source)
	response := perform(t, handler, operatorRequest(t, accountsListTool, `{}`))
	if response.Code != http.StatusOK || source.calls.Load() != 1 {
		t.Fatalf("accounts_list = %d calls=%d body=%q", response.Code, source.calls.Load(), response.Body.String())
	}
	got := structuredResult(t, response.Body.Bytes())
	want := `{"output_version":1,"accounts":[{"account_id":"` + operatorAccountID + `","provider":"gmail","state":"active","state_version":2,"reauthorization_reason":null,"revocation_status":"none"}]}`
	if string(got) != want {
		t.Fatalf("accounts_list golden\n got %s\nwant %s", got, want)
	}
	for _, forbidden := range []string{"cursor_present", "credential_present", "history_id", "provider_subject", "email", "display_name", "secret", "endpoint"} {
		if strings.Contains(string(got), forbidden) {
			t.Errorf("accounts_list exposed %q", forbidden)
		}
	}
}

func TestMailSyncStatusExactGoldenUsesUnavailableAndNotPersisted(t *testing.T) {
	source := &operatorSource{accounts: []storage.AccountSummary{operatorSummary(t, operatorAccountID, false)}}
	handler := operatorHandler(t, source)
	response := perform(t, handler, operatorRequest(t, mailSyncStatusTool, `{}`))
	if response.Code != http.StatusOK || source.calls.Load() != 1 {
		t.Fatalf("mail_sync_status = %d calls=%d body=%q", response.Code, source.calls.Load(), response.Body.String())
	}
	got := structuredResult(t, response.Body.Bytes())
	want := `{"output_version":1,"accounts":[{"account_id":"` + operatorAccountID + `","current_sync":{"implementation_status":"not_implemented","configuration_status":"disabled","enabled":false,"execution_status":"not_available","cursor_status":"uninitialized","stale_status":"not_persisted","last_success_at":null,"last_error_category":null},"backfill":{"implementation_status":"not_implemented","configuration_status":"disabled","enabled":false,"execution_status":"not_available","checkpoint_status":"not_persisted","progress":null}}]}`
	if string(got) != want {
		t.Fatalf("mail_sync_status golden\n got %s\nwant %s", got, want)
	}
	for _, forbidden := range []string{"history_id", "fresh", "successful", "connected", "last_success_at\":\"", "progress\":0", "progress\":1"} {
		if strings.Contains(string(got), forbidden) {
			t.Errorf("mail_sync_status fabricated or exposed %q", forbidden)
		}
	}
}

func TestEachSuccessfulCallUsesOneFreshSnapshotAndNoRetryOrPartialOutput(t *testing.T) {
	source := &operatorSource{accounts: []storage.AccountSummary{operatorSummary(t, operatorAccountID, true)}}
	handler := operatorHandler(t, source)
	first := perform(t, handler, operatorRequest(t, accountsListTool, `{}`))
	second := perform(t, handler, operatorRequest(t, mailSyncStatusTool, `{}`))
	if first.Code != http.StatusOK || second.Code != http.StatusOK || source.calls.Load() != 2 {
		t.Fatalf("statuses = (%d,%d), calls = %d", first.Code, second.Code, source.calls.Load())
	}

	source.err = errors.New("raw upstream SQL and synthetic secret marker")
	failure := perform(t, handler, operatorRequest(t, accountsListTool, `{}`))
	if failure.Code != http.StatusOK || !strings.Contains(failure.Body.String(), `"code":-32603`) || strings.Contains(failure.Body.String(), "raw upstream") || source.calls.Load() != 3 {
		t.Fatalf("source failure = %d %q calls=%d", failure.Code, failure.Body.String(), source.calls.Load())
	}
}

func TestAccountReadHonorsClientCancellationFiveSecondDeadlineAndResponseCap(t *testing.T) {
	blocked := &operatorSource{wait: true}
	deadline := operatorHandler(t, blocked, withApplicationTimeout(20*time.Millisecond))
	started := time.Now()
	response := perform(t, deadline, operatorRequest(t, accountsListTool, `{}`))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"code":-32603`) || time.Since(started) >= time.Second || blocked.calls.Load() != 1 {
		t.Fatalf("deadline response = %d %q elapsed=%v calls=%d", response.Code, response.Body.String(), time.Since(started), blocked.calls.Load())
	}

	canceledSource := &operatorSource{wait: true}
	canceled := operatorHandler(t, canceledSource)
	ctx, cancel := context.WithCancel(context.Background())
	request := operatorRequest(t, mailSyncStatusTool, `{}`).WithContext(ctx)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- perform(t, canceled, request) }()
	for canceledSource.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("client cancellation did not stop account read")
	}

	limitedSource := &operatorSource{accounts: []storage.AccountSummary{operatorSummary(t, operatorAccountID, true)}}
	limited := operatorHandler(t, limitedSource, withResponseLimit(256))
	tooLarge := perform(t, limited, operatorRequest(t, mailSyncStatusTool, `{}`))
	if tooLarge.Code != http.StatusInternalServerError || tooLarge.Body.String() != "internal_error\n" || strings.Contains(tooLarge.Body.String(), operatorAccountID) {
		t.Fatalf("response cap = %d %q", tooLarge.Code, tooLarge.Body.String())
	}
}

func TestOperatorAuditUsesFixedOperationsAndNoAccountData(t *testing.T) {
	configuration := config.Defaults()
	configuration.MCP.Enabled = true
	configuration.MCP.EnableOperatorTools = true
	source := &operatorSource{accounts: []storage.AccountSummary{operatorSummary(t, operatorAccountID, true)}}
	service, err := accountstatus.New(source, config.CapabilityRegistry(configuration))
	if err != nil {
		t.Fatal(err)
	}
	var audit bytes.Buffer
	handler, err := New(Options{Configuration: configuration, BinaryVersion: "dev", BearerToken: []byte(canonicalToken()), AuditOutput: &audit, AccountStatus: service})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	for _, test := range []struct{ name, operation string }{{accountsListTool, "mcp.accounts_list"}, {mailSyncStatusTool, "mcp.mail_sync_status"}} {
		audit.Reset()
		perform(t, handler, operatorRequest(t, test.name, `{}`))
		if !strings.Contains(audit.String(), `"operation":"`+test.operation+`"`) || strings.Contains(audit.String(), operatorAccountID) || strings.Contains(audit.String(), `"name":"`+test.name+`"`) {
			t.Fatalf("audit for %q = %s", test.name, audit.String())
		}
	}
}

func TestOperatorSurfaceHasNoGenericOrMutationAuthority(t *testing.T) {
	source := &operatorSource{}
	handler := operatorHandler(t, source)
	for _, name := range []string{"sql_query", "gmail_request", "shell_exec", "url_fetch", "vikunja_write", "account_pause", "sync_run", "backfill_start", "review_write"} {
		response := perform(t, handler, operatorRequest(t, name, `{}`))
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"code":-32601`) {
			t.Errorf("tool %q response = %d %q", name, response.Code, response.Body.String())
		}
	}
	if source.calls.Load() != 0 {
		t.Fatalf("unknown tools made %d account calls", source.calls.Load())
	}
}

func FuzzOperatorSummaryRenderingIsBoundedAndClosedWorld(f *testing.F) {
	f.Add(accountsListTool, false)
	f.Add(mailSyncStatusTool, true)
	f.Fuzz(func(t *testing.T, name string, cursor bool) {
		if name != accountsListTool && name != mailSyncStatusTool {
			return
		}
		source := &operatorSource{accounts: []storage.AccountSummary{operatorSummary(t, operatorAccountID, cursor)}}
		handler := operatorHandler(t, source)
		response := perform(t, handler, operatorRequest(t, name, `{}`))
		if response.Code != http.StatusOK || response.Body.Len() > MaximumResponseBytes || source.calls.Load() != 1 {
			t.Fatalf("tool=%q cursor=%t response=%d bytes=%d calls=%d", name, cursor, response.Code, response.Body.Len(), source.calls.Load())
		}
	})
}
