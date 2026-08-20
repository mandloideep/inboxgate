package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/reviewinspect"
)

const (
	listReviewCandidatesTool = "mail_list_review_candidates"
	getGateReasonTool        = "mail_get_gate_reason"
)

type reviewInspectionStub struct {
	page        reviewinspect.CandidatePage
	reason      reviewinspect.GateReason
	err         error
	listCalls   atomic.Int64
	reasonCalls atomic.Int64
	wait        bool
	started     chan struct{}
	once        sync.Once
}

func (service *reviewInspectionStub) List(ctx context.Context, request reviewinspect.ListRequest) (reviewinspect.CandidatePage, error) {
	service.listCalls.Add(1)
	if service.wait {
		service.once.Do(func() {
			if service.started != nil {
				close(service.started)
			}
		})
		<-ctx.Done()
		return reviewinspect.CandidatePage{}, ctx.Err()
	}
	return service.page.Clone(), service.err
}

func (service *reviewInspectionStub) GateReason(ctx context.Context, request reviewinspect.GateReasonRequest) (reviewinspect.GateReason, error) {
	service.reasonCalls.Add(1)
	if service.wait {
		service.once.Do(func() {
			if service.started != nil {
				close(service.started)
			}
		})
		<-ctx.Done()
		return reviewinspect.GateReason{}, ctx.Err()
	}
	return service.reason.Clone(), service.err
}

func reviewInspectionConfiguration() config.Config {
	configuration := config.Defaults()
	configuration.MCP.Enabled = true
	configuration.Capabilities.MailReviewRead = true
	return configuration
}

func reviewInspectionHandler(t *testing.T, service *reviewInspectionStub, audit io.Writer, modifiers ...Option) *Handler {
	t.Helper()
	handler, err := New(Options{
		Configuration: reviewInspectionConfiguration(), BinaryVersion: "dev", BearerToken: []byte(canonicalToken()),
		AuditOutput: audit, ReviewInspection: service,
	}, modifiers...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })
	return handler
}

func reviewToolRequest(t *testing.T, name, arguments string) *http.Request {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":` + arguments + `,` + validMeta() + `}}`
	request := validRequest(t, "tools/call", body)
	request.Header.Set("Mcp-Name", name)
	return request
}

func TestReviewReadDualGateControlsExactInventorySchemasAnnotationsAndDescriptions(t *testing.T) {
	disabled := newContractHandler(t, config.Defaults())
	disabledResponse := perform(t, disabled, validRequest(t, "tools/list", requestBody("tools/list")))
	if names := listedToolNames(t, disabledResponse.Body.Bytes()); !reflect.DeepEqual(names, []string{systemCapabilitiesTool}) {
		t.Fatalf("disabled tools = %#v", names)
	}

	handler := reviewInspectionHandler(t, &reviewInspectionStub{}, io.Discard)
	response := perform(t, handler, validRequest(t, "tools/list", requestBody("tools/list")))
	if names := listedToolNames(t, response.Body.Bytes()); !reflect.DeepEqual(names, []string{getGateReasonTool, listReviewCandidatesTool, systemCapabilitiesTool}) {
		t.Fatalf("review tools = %#v", names)
	}
	var envelope struct {
		Result struct {
			Tools []struct {
				Name        string         `json:"name"`
				Description string         `json:"description"`
				InputSchema map[string]any `json:"inputSchema"`
				Annotations map[string]any `json:"annotations"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	wantAnnotations := map[string]any{"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false}
	for _, tool := range envelope.Result.Tools {
		if tool.Name == systemCapabilitiesTool {
			continue
		}
		if !reflect.DeepEqual(tool.Annotations, wantAnnotations) || !strings.Contains(tool.Description, "untrusted") || !strings.Contains(tool.Description, "cannot authorize") {
			t.Errorf("tool %q annotations=%#v description=%q", tool.Name, tool.Annotations, tool.Description)
		}
		if tool.InputSchema["type"] != "object" || tool.InputSchema["additionalProperties"] != false {
			t.Errorf("tool %q schema=%#v", tool.Name, tool.InputSchema)
		}
	}
}

func TestReviewSchemasAreClosedAndExact(t *testing.T) {
	handler := reviewInspectionHandler(t, &reviewInspectionStub{}, io.Discard)
	response := perform(t, handler, validRequest(t, "tools/list", requestBody("tools/list")))
	schemas := toolSchemasByName(t, response.Body.Bytes())
	wantList := map[string]any{
		"type": "object", "additionalProperties": false,
		"properties": map[string]any{
			"account_ids":               map[string]any{"type": "array", "minItems": float64(1), "maxItems": float64(16), "uniqueItems": true, "items": map[string]any{"type": "string", "pattern": "^[0-9a-f]{32}$"}},
			"urgency":                   map[string]any{"type": "string", "enum": []any{"all", "standard", "urgent"}},
			"internal_date_min_unix_ms": map[string]any{"type": "integer", "minimum": float64(0), "maximum": float64(253402300799999)},
			"internal_date_max_unix_ms": map[string]any{"type": "integer", "minimum": float64(0), "maximum": float64(253402300799999)},
			"page_size":                 map[string]any{"type": "integer", "minimum": float64(1), "maximum": float64(10)},
			"cursor":                    map[string]any{"type": "string", "maxLength": float64(414)},
		},
	}
	wantReason := map[string]any{
		"type": "object", "additionalProperties": false, "required": []any{"account_id", "gmail_message_id"},
		"properties": map[string]any{
			"account_id":       map[string]any{"type": "string", "pattern": "^[0-9a-f]{32}$"},
			"gmail_message_id": map[string]any{"type": "string", "minLength": float64(1), "maxLength": float64(255), "pattern": "^[!-~]+$"},
		},
	}
	if !reflect.DeepEqual(schemas[listReviewCandidatesTool], wantList) {
		t.Fatalf("list schema = %#v, want %#v", schemas[listReviewCandidatesTool], wantList)
	}
	if !reflect.DeepEqual(schemas[getGateReasonTool], wantReason) {
		t.Fatalf("reason schema = %#v, want %#v", schemas[getGateReasonTool], wantReason)
	}
}

func toolSchemasByName(t *testing.T, body []byte) map[string]map[string]any {
	t.Helper()
	var envelope struct {
		Result struct {
			Tools []struct {
				Name        string         `json:"name"`
				InputSchema map[string]any `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	result := make(map[string]map[string]any, len(envelope.Result.Tools))
	for _, tool := range envelope.Result.Tools {
		result[tool.Name] = tool.InputSchema
	}
	return result
}

func assertReviewListSchema(t *testing.T, schema map[string]any) {
	t.Helper()
	properties, ok := schema["properties"].(map[string]any)
	if !ok || schema["type"] != "object" || schema["additionalProperties"] != false {
		t.Fatalf("list schema = %#v", schema)
	}
	want := []string{"account_ids", "cursor", "internal_date_max_unix_ms", "internal_date_min_unix_ms", "page_size", "urgency"}
	got := make([]string, 0, len(properties))
	for name := range properties {
		got = append(got, name)
	}
	slices.Sort(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("list properties = %#v", got)
	}
}

func assertGateReasonSchema(t *testing.T, schema map[string]any) {
	t.Helper()
	properties, ok := schema["properties"].(map[string]any)
	if !ok || schema["type"] != "object" || schema["additionalProperties"] != false || len(properties) != 2 {
		t.Fatalf("reason schema = %#v", schema)
	}
	required, ok := schema["required"].([]any)
	if !ok || !reflect.DeepEqual(required, []any{"account_id", "gmail_message_id"}) {
		t.Fatalf("reason required = %#v", schema["required"])
	}
}

func TestReviewAuthenticationAndInvalidInputsFinishBeforeSource(t *testing.T) {
	service := &reviewInspectionStub{}
	handler := reviewInspectionHandler(t, service, io.Discard)
	requests := []*http.Request{
		reviewToolRequest(t, listReviewCandidatesTool, `[]`),
		reviewToolRequest(t, listReviewCandidatesTool, `{"account_ids":[]}`),
		reviewToolRequest(t, listReviewCandidatesTool, `{"page_size":11}`),
		reviewToolRequest(t, listReviewCandidatesTool, `{"cursor":"igrc2.="}`),
		reviewToolRequest(t, getGateReasonTool, `{}`),
		reviewToolRequest(t, getGateReasonTool, `{"account_id":"0000000000000000000000000000000a","gmail_message_id":"m","gmail_thread_id":"t"}`),
		reviewToolRequest(t, "sql_query", `{}`),
	}
	unauthorized := reviewToolRequest(t, listReviewCandidatesTool, `{}`)
	unauthorized.Header.Set("Authorization", "Bearer QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE")
	requests = append(requests, unauthorized)
	for _, request := range requests {
		perform(t, handler, request)
	}
	if service.listCalls.Load() != 0 || service.reasonCalls.Load() != 0 {
		t.Fatalf("invalid calls = list %d reason %d", service.listCalls.Load(), service.reasonCalls.Load())
	}
}

func TestCandidateGoldenIsBoundedUntrustedAndContentFree(t *testing.T) {
	next := "igrc2.AA"
	service := &reviewInspectionStub{page: reviewinspect.CandidatePage{
		OutputVersion: 1,
		Candidates: []reviewinspect.Candidate{{
			AccountID: "0000000000000000000000000000000a", GmailThreadID: "thread", GmailMessageID: "message",
			InternalDateUnixMS: 42, Urgency: "standard", Outcome: "review_candidate",
			SenderDisplayPreview: "Sender", SenderAddress: "sender@example.test", SubjectPreview: "Subject",
			HasAttachments: true, ContentTrust: "untrusted_email",
		}},
		NextCursor: &next,
	}}
	handler := reviewInspectionHandler(t, service, io.Discard)
	response := perform(t, handler, reviewToolRequest(t, listReviewCandidatesTool, `{}`))
	if response.Code != http.StatusOK || response.Body.Len() > MaximumResponseBytes || service.listCalls.Load() != 1 {
		t.Fatalf("response=%d bytes=%d calls=%d body=%q", response.Code, response.Body.Len(), service.listCalls.Load(), response.Body.String())
	}
	content := string(structuredResult(t, response.Body.Bytes()))
	for _, required := range []string{"untrusted_email", "sender@example.test", "review_candidate", "igrc2."} {
		if !strings.Contains(content, required) {
			t.Errorf("result misses %q: %s", required, content)
		}
	}
	for _, forbidden := range []string{"excerpt", "content_hash", "source_kind", "fetched_at", "canonical_json", "provider_subject", "rfc_message_id", "label", "recipient", "url", "endpoint", "credential"} {
		if strings.Contains(content, forbidden) {
			t.Errorf("result exposes %q: %s", forbidden, content)
		}
	}
}

func TestGateReasonGoldenIsCurrentClosedAndContentFree(t *testing.T) {
	service := &reviewInspectionStub{reason: reviewinspect.GateReason{
		OutputVersion: 1, AccountID: "0000000000000000000000000000000a", GmailThreadID: "thread", GmailMessageID: "message",
		GateVersion: 1, Outcome: "ignore", ReasonCodes: []string{"excluded_label"}, EvaluatedAtUnixMS: 42,
		SourceCurrent: true, PolicyCurrent: true,
	}}
	handler := reviewInspectionHandler(t, service, io.Discard)
	response := perform(t, handler, reviewToolRequest(t, getGateReasonTool, `{"account_id":"0000000000000000000000000000000a","gmail_message_id":"message"}`))
	content := string(structuredResult(t, response.Body.Bytes()))
	if service.reasonCalls.Load() != 1 || !strings.Contains(content, `"source_current":true`) || !strings.Contains(content, `"policy_current":true`) || !strings.Contains(content, `"excluded_label"`) {
		t.Fatalf("reason calls=%d content=%s", service.reasonCalls.Load(), content)
	}
	for _, forbidden := range []string{"subject", "sender", "excerpt", "input_hash", "metadata_hash", "canonical_json"} {
		if strings.Contains(content, forbidden) {
			t.Errorf("reason exposes %q: %s", forbidden, content)
		}
	}
}

func TestReviewFailuresAreFixedNoPartialNoRetryAndResponseBounded(t *testing.T) {
	service := &reviewInspectionStub{err: errors.New("raw SQL private value https://private.invalid")}
	handler := reviewInspectionHandler(t, service, io.Discard)
	for _, name := range []string{listReviewCandidatesTool, getGateReasonTool} {
		arguments := `{}`
		if name == getGateReasonTool {
			arguments = `{"account_id":"0000000000000000000000000000000a","gmail_message_id":"message"}`
		}
		response := perform(t, handler, reviewToolRequest(t, name, arguments))
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"code":-32603`) || strings.Contains(response.Body.String(), "raw SQL") || strings.Contains(response.Body.String(), "private.invalid") {
			t.Fatalf("%s failure=%d %q", name, response.Code, response.Body.String())
		}
	}
	if service.listCalls.Load() != 1 || service.reasonCalls.Load() != 1 {
		t.Fatalf("calls=list %d reason %d", service.listCalls.Load(), service.reasonCalls.Load())
	}

	large := &reviewInspectionStub{page: reviewinspect.CandidatePage{Candidates: make([]reviewinspect.Candidate, 10)}}
	limited := reviewInspectionHandler(t, large, io.Discard, withResponseLimit(256))
	requestWithID := reviewToolRequest(t, listReviewCandidatesTool, `{}`)
	requestWithID.Body = io.NopCloser(strings.NewReader(strings.Replace(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+listReviewCandidatesTool+`","arguments":{},`+validMeta()+`}}`,
		`"id":1`, `"id":"original-review-id"`, 1,
	)))
	response := perform(t, limited, requestWithID)
	wantOverflow := `{"jsonrpc":"2.0","id":"original-review-id","error":{"code":-32603,"message":"internal error"}}`
	if response.Code != http.StatusOK || response.Body.String() != wantOverflow || strings.Contains(response.Body.String(), "structuredContent") || strings.Contains(response.Body.String(), "data") {
		t.Fatalf("overflow=%d %q", response.Code, response.Body.String())
	}

	tiny := reviewInspectionHandler(t, &reviewInspectionStub{reason: reviewinspect.GateReason{OutputVersion: 1}}, io.Discard, withResponseLimit(32))
	tinyResponse := perform(t, tiny, reviewToolRequest(t, getGateReasonTool, `{"account_id":"0000000000000000000000000000000a","gmail_message_id":"message"}`))
	if tinyResponse.Code != http.StatusInternalServerError || tinyResponse.Body.String() != "internal_error\n" {
		t.Fatalf("tiny overflow=%d %q", tinyResponse.Code, tinyResponse.Body.String())
	}
}

func TestReviewCancellationDeadlineAndCloseReachSource(t *testing.T) {
	for _, action := range []string{"deadline", "close"} {
		service := &reviewInspectionStub{wait: true, started: make(chan struct{})}
		handler := reviewInspectionHandler(t, service, io.Discard, withApplicationTimeout(20*time.Millisecond))
		done := make(chan struct{})
		go func() {
			perform(t, handler, reviewToolRequest(t, listReviewCandidatesTool, `{}`))
			close(done)
		}()
		<-service.started
		if action == "close" {
			_ = handler.Close()
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("%s did not stop source", action)
		}
	}
}

func TestReviewAuditsUseOnlyFixedOperations(t *testing.T) {
	listAccount := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	reasonAccount := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	inputCursor := "igrc2.AUDITCURSORCANARY"
	outputCursor := "igrc2.OUTPUTCURSORCANARY"
	tests := []struct {
		name, operation, arguments, wantOutcome string
		service                                 *reviewInspectionStub
		canaries                                []string
	}{
		{
			name: listReviewCandidatesTool, operation: "mcp.mail_list_review_candidates", wantOutcome: "success",
			arguments: `{"account_ids":["` + listAccount + `"],"urgency":"urgent","internal_date_min_unix_ms":123,"internal_date_max_unix_ms":456,"page_size":1,"cursor":"` + inputCursor + `"}`,
			service:   &reviewInspectionStub{page: reviewinspect.CandidatePage{OutputVersion: 1, Candidates: []reviewinspect.Candidate{{AccountID: listAccount, GmailThreadID: "audit-thread-canary", GmailMessageID: "audit-list-message-canary", SenderDisplayPreview: "audit-sender-canary", SenderAddress: "audit-address@example.test", SubjectPreview: "audit-subject-canary", ContentTrust: "untrusted_email"}}, NextCursor: &outputCursor}},
			canaries:  []string{listAccount, inputCursor, outputCursor, "audit-thread-canary", "audit-list-message-canary", "audit-sender-canary", "audit-address@example.test", "audit-subject-canary"},
		},
		{
			name: getGateReasonTool, operation: "mcp.mail_get_gate_reason", wantOutcome: "success",
			arguments: `{"account_id":"` + reasonAccount + `","gmail_message_id":"audit-reason-message-canary"}`,
			service:   &reviewInspectionStub{reason: reviewinspect.GateReason{OutputVersion: 1, AccountID: reasonAccount, GmailThreadID: "audit-reason-thread-canary", GmailMessageID: "audit-reason-message-canary", Outcome: "ignore", ReasonCodes: []string{"excluded_label"}, SourceCurrent: true, PolicyCurrent: true}},
			canaries:  []string{reasonAccount, "audit-reason-thread-canary", "audit-reason-message-canary", "excluded_label"},
		},
		{
			name: getGateReasonTool, operation: "mcp.mail_get_gate_reason", wantOutcome: "failure",
			arguments: `{"account_id":"` + reasonAccount + `","gmail_message_id":"audit-failure-message-canary"}`,
			service:   &reviewInspectionStub{err: errors.New("audit-source-error-canary")},
			canaries:  []string{reasonAccount, "audit-failure-message-canary", "audit-source-error-canary"},
		},
	}
	wantKeys := []string{"duration_ms", "event", "level", "method", "msg", "operation", "outcome", "status", "time"}
	for _, test := range tests {
		var audit bytes.Buffer
		handler := reviewInspectionHandler(t, test.service, &audit)
		perform(t, handler, reviewToolRequest(t, test.name, test.arguments))
		raw := strings.TrimSpace(audit.String())
		fields := decodeAuditFields(t, "json", raw)
		keys := make([]string, 0, len(fields))
		for key := range fields {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		if !reflect.DeepEqual(keys, wantKeys) || fields["event"] != "mcp_request" || fields["msg"] != "mcp_request" || fields["operation"] != test.operation || fields["method"] != "POST" || fields["status"] != float64(http.StatusOK) || fields["outcome"] != test.wantOutcome || fields["level"] != "INFO" {
			t.Fatalf("audit fields = %#v", fields)
		}
		duration, durationOK := fields["duration_ms"].(float64)
		timestamp, timeOK := fields["time"].(string)
		if !durationOK || duration < 0 || duration > 60_000 || !timeOK {
			t.Fatalf("audit bounds = %#v", fields)
		}
		if _, err := time.Parse(time.RFC3339Nano, timestamp); err != nil {
			t.Fatalf("audit time = %q: %v", timestamp, err)
		}
		for _, canary := range append(test.canaries, canonicalToken()) {
			if strings.Contains(raw, canary) {
				t.Errorf("raw audit exposes %q: %s", canary, raw)
			}
			for key, value := range fields {
				if strings.Contains(fmt.Sprint(value), canary) {
					t.Errorf("decoded audit field %q exposes %q: %#v", key, canary, value)
				}
			}
		}
	}
}

func TestReviewSurfaceHasNoGmailOAuthContentMutationSQLShellURLOrVikunjaAuthority(t *testing.T) {
	service := &reviewInspectionStub{}
	handler := reviewInspectionHandler(t, service, io.Discard)
	for _, name := range []string{"gmail_request", "oauth_token", "mail_get_excerpt", "mail_record_review", "sql_query", "shell_exec", "url_fetch", "vikunja_write", "backfill_start"} {
		response := perform(t, handler, reviewToolRequest(t, name, `{}`))
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"code":-32601`) {
			t.Errorf("tool %q = %d %q", name, response.Code, response.Body.String())
		}
	}
	if service.listCalls.Load() != 0 || service.reasonCalls.Load() != 0 {
		t.Fatalf("unknown authority reached service")
	}
}

func FuzzReviewToolEnvelopesRemainBoundedAndClosed(f *testing.F) {
	f.Add(listReviewCandidatesTool, `{}`)
	f.Add(getGateReasonTool, `{"account_id":"0000000000000000000000000000000a","gmail_message_id":"message"}`)
	f.Fuzz(func(t *testing.T, name, arguments string) {
		if len(name) > 64 || len(arguments) > 2048 || !json.Valid([]byte(arguments)) {
			return
		}
		service := &reviewInspectionStub{}
		handler := reviewInspectionHandler(t, service, io.Discard)
		response := perform(t, handler, reviewToolRequest(t, name, arguments))
		if response.Body.Len() > MaximumResponseBytes || service.listCalls.Load()+service.reasonCalls.Load() > 1 {
			t.Fatalf("name=%q bytes=%d calls=%d", name, response.Body.Len(), service.listCalls.Load()+service.reasonCalls.Load())
		}
	})
}
