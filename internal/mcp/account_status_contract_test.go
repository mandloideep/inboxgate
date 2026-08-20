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
	"strconv"
	"strings"
	"sync"
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
	started  chan struct{}
	observed chan error
	once     sync.Once
}

func (source *operatorSource) ListAccounts(ctx context.Context) ([]storage.AccountSummary, error) {
	source.calls.Add(1)
	if source.wait {
		if source.started != nil {
			source.once.Do(func() { close(source.started) })
		}
		<-ctx.Done()
		if source.observed != nil {
			source.observed <- ctx.Err()
		}
		return nil, ctx.Err()
	}
	return append([]storage.AccountSummary(nil), source.accounts...), source.err
}

func operatorLifecycleSummary(t *testing.T, state storage.AccountState, versionValue int64, reason *storage.ReauthorizationReason, revocation storage.RevocationStatus, cursor bool) storage.AccountSummary {
	t.Helper()
	id, err := storage.ParseAccountID(operatorAccountID)
	if err != nil {
		t.Fatal(err)
	}
	version, err := storage.ParseLifecycleVersion(versionValue)
	if err != nil {
		t.Fatal(err)
	}
	return storage.AccountSummary{AccountID: id, Provider: storage.ProviderGmail, State: state, StateVersion: version, ReauthorizationReason: reason, RevocationStatus: revocation, CursorPresent: cursor}
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

	disabledConfiguration := config.Defaults()
	disabledConfiguration.MCP.Enabled = false
	disabledConfiguration.MCP.EnableOperatorTools = true
	disabled, err := New(Options{Configuration: disabledConfiguration, BinaryVersion: "dev", BearerToken: []byte(canonicalToken()), AuditOutput: io.Discard})
	if err != nil {
		t.Fatalf("MCP-disabled operator construction = %v", err)
	}
	defer disabled.Close()
	disabledList := perform(t, disabled, validRequest(t, "tools/list", requestBody("tools/list")))
	if names := listedToolNames(t, disabledList.Body.Bytes()); !reflect.DeepEqual(names, []string{systemCapabilitiesTool}) {
		t.Fatalf("MCP-disabled operator tools = %#v", names)
	}
	for _, name := range []string{accountsListTool, mailSyncStatusTool} {
		response := perform(t, disabled, operatorRequest(t, name, `{}`))
		if response.Code != http.StatusOK || response.Body.String() != `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}` {
			t.Fatalf("MCP-disabled operator call %q = %d %q", name, response.Code, response.Body.String())
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

func TestAccountsListExactlyRendersEveryLifecycleVocabularyValue(t *testing.T) {
	reasons := []storage.ReauthorizationReason{
		storage.ReauthorizationReasonRefreshInvalidGrant,
		storage.ReauthorizationReasonRefreshAdminPolicyEnforced,
		storage.ReauthorizationReasonGmailUnauthorizedAfterRefresh,
		storage.ReauthorizationReasonGmailDomainPolicy,
	}
	revocations := []storage.RevocationStatus{
		storage.RevocationStatusPending,
		storage.RevocationStatusAttempting,
		storage.RevocationStatusConfirmed,
		storage.RevocationStatusManualActionRequired,
	}
	tests := []struct {
		name       string
		state      storage.AccountState
		version    int64
		reason     *storage.ReauthorizationReason
		revocation storage.RevocationStatus
	}{
		{name: "pending", state: storage.AccountStatePending, version: 1, revocation: storage.RevocationStatusNone},
		{name: "active", state: storage.AccountStateActive, version: 2, revocation: storage.RevocationStatusNone},
		{name: "paused", state: storage.AccountStatePaused, version: 2, revocation: storage.RevocationStatusNone},
	}
	for index := range reasons {
		reason := reasons[index]
		tests = append(tests, struct {
			name       string
			state      storage.AccountState
			version    int64
			reason     *storage.ReauthorizationReason
			revocation storage.RevocationStatus
		}{name: reason.String(), state: storage.AccountStateReauthorizationRequired, version: 2, reason: &reason, revocation: storage.RevocationStatusNone})
	}
	for index, revocation := range revocations {
		version := int64(2)
		if index == len(revocations)-1 {
			version = int64(^uint64(0) >> 1)
		}
		tests = append(tests, struct {
			name       string
			state      storage.AccountState
			version    int64
			reason     *storage.ReauthorizationReason
			revocation storage.RevocationStatus
		}{name: revocation.String(), state: storage.AccountStateRevoked, version: version, revocation: revocation})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := &operatorSource{accounts: []storage.AccountSummary{operatorLifecycleSummary(t, test.state, test.version, test.reason, test.revocation, false)}}
			got := structuredResult(t, perform(t, operatorHandler(t, source), operatorRequest(t, accountsListTool, `{}`)).Body.Bytes())
			reason := "null"
			if test.reason != nil {
				reason = `"` + test.reason.String() + `"`
			}
			want := `{"output_version":1,"accounts":[{"account_id":"` + operatorAccountID + `","provider":"gmail","state":"` + test.state.String() + `","state_version":` + strconv.FormatInt(test.version, 10) + `,"reauthorization_reason":` + reason + `,"revocation_status":"` + test.revocation.String() + `"}]}`
			if string(got) != want || source.calls.Load() != 1 {
				t.Fatalf("render = %s, want %s, calls=%d", got, want, source.calls.Load())
			}
		})
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

func TestMailSyncStatusExactlyRendersBothCursorLiteralsAndNullUnavailableFacts(t *testing.T) {
	for _, test := range []struct {
		name, cursor string
		present      bool
	}{{name: "uninitialized", cursor: "uninitialized"}, {name: "initialized", cursor: "initialized", present: true}} {
		t.Run(test.name, func(t *testing.T) {
			source := &operatorSource{accounts: []storage.AccountSummary{operatorSummary(t, operatorAccountID, test.present)}}
			got := structuredResult(t, perform(t, operatorHandler(t, source), operatorRequest(t, mailSyncStatusTool, `{}`)).Body.Bytes())
			want := `{"output_version":1,"accounts":[{"account_id":"` + operatorAccountID + `","current_sync":{"implementation_status":"not_implemented","configuration_status":"disabled","enabled":false,"execution_status":"not_available","cursor_status":"` + test.cursor + `","stale_status":"not_persisted","last_success_at":null,"last_error_category":null},"backfill":{"implementation_status":"not_implemented","configuration_status":"disabled","enabled":false,"execution_status":"not_available","checkpoint_status":"not_persisted","progress":null}}]}`
			if string(got) != want || strings.Contains(string(got), "history_id") || source.calls.Load() != 1 {
				t.Fatalf("status = %s, want %s, calls=%d", got, want, source.calls.Load())
			}
		})
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

	canceledSource := &operatorSource{wait: true, started: make(chan struct{}), observed: make(chan error, 1)}
	canceled := operatorHandler(t, canceledSource)
	ctx, cancel := context.WithCancel(context.Background())
	request := operatorRequest(t, mailSyncStatusTool, `{}`).WithContext(ctx)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- perform(t, canceled, request) }()
	select {
	case <-canceledSource.started:
	case <-time.After(time.Second):
		t.Fatal("account source did not start")
	}
	cancel()
	select {
	case response := <-done:
		want := `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"internal error"}}`
		if response.Code != http.StatusOK || response.Body.String() != want || strings.Contains(response.Body.String(), "data") || canceledSource.calls.Load() != 1 {
			t.Fatalf("canceled response = %d %q calls=%d", response.Code, response.Body.String(), canceledSource.calls.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("client cancellation did not stop account read")
	}
	select {
	case observed := <-canceledSource.observed:
		if !errors.Is(observed, context.Canceled) {
			t.Fatalf("source context = %v", observed)
		}
	case <-time.After(time.Second):
		t.Fatal("source did not observe cancellation")
	}

	limitedSource := &operatorSource{accounts: []storage.AccountSummary{operatorSummary(t, operatorAccountID, true)}}
	limited := operatorHandler(t, limitedSource, withResponseLimit(256))
	requestWithID := operatorRequest(t, mailSyncStatusTool, `{}`)
	requestWithID.Body = io.NopCloser(strings.NewReader(strings.Replace(operatorRequestBody(mailSyncStatusTool, `{}`), `"id":1`, `"id":"original-id"`, 1)))
	tooLarge := perform(t, limited, requestWithID)
	wantOverflow := `{"jsonrpc":"2.0","id":"original-id","error":{"code":-32603,"message":"internal error"}}`
	if tooLarge.Code != http.StatusOK || tooLarge.Body.String() != wantOverflow || strings.Contains(tooLarge.Body.String(), operatorAccountID) || strings.Contains(tooLarge.Body.String(), "structuredContent") || strings.Contains(tooLarge.Body.String(), "data") || limitedSource.calls.Load() != 1 {
		t.Fatalf("response cap = %d %q", tooLarge.Code, tooLarge.Body.String())
	}

	tinySource := &operatorSource{accounts: []storage.AccountSummary{operatorSummary(t, operatorAccountID, true)}}
	tiny := operatorHandler(t, tinySource, withResponseLimit(32))
	tinyResponse := perform(t, tiny, operatorRequest(t, mailSyncStatusTool, `{}`))
	if tinyResponse.Code != http.StatusInternalServerError || tinyResponse.Body.String() != "internal_error\n" || tinySource.calls.Load() != 1 {
		t.Fatalf("tiny response cap = %d %q calls=%d", tinyResponse.Code, tinyResponse.Body.String(), tinySource.calls.Load())
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
	f.Add(uint8(0), false)
	f.Add(uint8(1), true)
	f.Fuzz(func(t *testing.T, selection uint8, cursor bool) {
		name := []string{accountsListTool, mailSyncStatusTool}[selection%2]
		source := &operatorSource{accounts: []storage.AccountSummary{operatorSummary(t, operatorAccountID, cursor)}}
		handler := operatorHandler(t, source)
		response := perform(t, handler, operatorRequest(t, name, `{}`))
		if response.Code != http.StatusOK || response.Body.Len() > MaximumResponseBytes || source.calls.Load() != 1 || strings.Contains(response.Body.String(), "history_id") || strings.Contains(response.Body.String(), "credential_present") {
			t.Fatalf("tool=%q cursor=%t response=%d bytes=%d calls=%d", name, cursor, response.Code, response.Body.Len(), source.calls.Load())
		}
		structured := string(structuredResult(t, response.Body.Bytes()))
		if name == accountsListTool {
			if strings.Contains(structured, "cursor_status") || !strings.Contains(structured, `"state":"active"`) {
				t.Fatalf("accounts output = %s", structured)
			}
			return
		}
		cursorLiteral := map[bool]string{false: "uninitialized", true: "initialized"}[cursor]
		for _, required := range []string{`"cursor_status":"` + cursorLiteral + `"`, `"execution_status":"not_available"`, `"last_success_at":null`, `"last_error_category":null`, `"progress":null`} {
			if !strings.Contains(structured, required) {
				t.Fatalf("status output missing %s: %s", required, structured)
			}
		}
	})
}
