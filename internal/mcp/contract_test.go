package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/config"
)

const (
	protocolVersion = "2026-07-28"
	mcpPath         = "/mcp"
)

var syntheticTokenBytes = bytes.Repeat([]byte{0x5a}, 32)

func canonicalToken() string {
	return base64.RawURLEncoding.EncodeToString(syntheticTokenBytes)
}

func validMeta() string {
	return `"_meta":{` +
		`"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientCapabilities":{},` +
		`"io.modelcontextprotocol/clientInfo":{"name":"synthetic-client","version":"1.0.0"}` +
		`}`
}

func requestBody(method string) string {
	params := "{" + validMeta() + "}"
	if method == "tools/call" {
		params = `{"name":"system_capabilities","arguments":{},` + validMeta() + "}"
	}
	return `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":` + params + "}"
}

func newContractHandler(t *testing.T, configuration config.Config, options ...Option) *Handler {
	t.Helper()
	handler, err := New(Options{
		Configuration: configuration,
		BinaryVersion: "dev",
		BinaryCommit:  "",
		BearerToken:   []byte(canonicalToken()),
		AuditOutput:   io.Discard,
	}, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })
	return handler
}

func validRequest(t *testing.T, method, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+mcpPath, strings.NewReader(body))
	request.Host = "127.0.0.1"
	request.Header.Set("Authorization", "Bearer "+canonicalToken())
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("MCP-Protocol-Version", protocolVersion)
	request.Header.Set("Mcp-Method", method)
	if method == "tools/call" {
		request.Header.Set("Mcp-Name", "system_capabilities")
	}
	return request
}

func perform(t *testing.T, handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestBearerTokenCanonicalContract(t *testing.T) {
	canonical := canonicalToken()
	parsed, err := ParseBearerToken(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed, syntheticTokenBytes) {
		t.Fatal("canonical token decoded to unexpected bytes")
	}
	clear(parsed)

	invalid := []string{
		"",
		canonical[:42],
		canonical + "A",
		canonical + "=",
		" " + canonical,
		canonical + " ",
		strings.Repeat("A", 42) + "+",
		strings.Repeat("A", 42) + "/",
		canonical[:20] + "\n" + canonical[21:],
		canonical[:20] + "\x00" + canonical[21:],
		base64.URLEncoding.EncodeToString(syntheticTokenBytes),
	}
	for index, value := range invalid {
		if decoded, err := ParseBearerToken(value); err == nil || decoded != nil {
			t.Errorf("invalid token case %d accepted", index)
		}
	}
}

func TestAuthorizationIsOneExactHeaderAndFailuresAreIndistinguishable(t *testing.T) {
	handler := newContractHandler(t, config.Defaults())
	tests := []struct {
		name   string
		values []string
	}{
		{name: "missing"},
		{name: "empty", values: []string{""}},
		{name: "wrong", values: []string{"Bearer " + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32))}},
		{name: "basic", values: []string{"Basic " + canonicalToken()}},
		{name: "lowercase", values: []string{"bearer " + canonicalToken()}},
		{name: "extra space", values: []string{"Bearer  " + canonicalToken()}},
		{name: "leading space", values: []string{" Bearer " + canonicalToken()}},
		{name: "trailing space", values: []string{"Bearer " + canonicalToken() + " "}},
		{name: "padded", values: []string{"Bearer " + canonicalToken() + "="}},
		{name: "comma joined", values: []string{"Bearer " + canonicalToken() + ", Bearer " + canonicalToken()}},
		{name: "duplicate", values: []string{"Bearer " + canonicalToken(), "Bearer " + canonicalToken()}},
	}
	var referenceHeader http.Header
	var referenceBody string
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validRequest(t, "tools/list", requestBody("tools/list"))
			request.Header.Del("Authorization")
			for _, value := range test.values {
				request.Header.Add("Authorization", value)
			}
			response := perform(t, handler, request)
			if response.Code != http.StatusUnauthorized || response.Body.String() != "unauthorized\n" || response.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatalf("status = %d, body category = %q", response.Code, response.Body.String())
			}
			assertSecurityHeaders(t, response.Header())
			if referenceHeader == nil {
				referenceHeader = response.Header().Clone()
				referenceBody = response.Body.String()
			} else if !reflect.DeepEqual(response.Header(), referenceHeader) || response.Body.String() != referenceBody {
				t.Fatal("credential failures are distinguishable")
			}
		})
	}
}

func TestAuthenticationPrecedesBodyAndRoutingDisclosure(t *testing.T) {
	handler := newContractHandler(t, config.Defaults())
	for _, body := range []string{"", "not-json", strings.Repeat("x", MaximumRequestBytes+1)} {
		request := validRequest(t, "private/method", body)
		request.Header.Del("Authorization")
		request.Header.Set("Content-Type", "text/private")
		request.Header.Set("Mcp-Name", "private-tool")
		response := perform(t, handler, request)
		if response.Code != http.StatusUnauthorized || response.Body.String() != "unauthorized\n" {
			t.Fatalf("unauthenticated response = %d %q", response.Code, response.Body.String())
		}
	}
}

func TestTransportRouteMethodMediaOriginAndHostContract(t *testing.T) {
	handler := newContractHandler(t, config.Defaults())
	tests := []struct {
		name       string
		mutate     func(*http.Request)
		wantStatus int
		wantBody   string
		wantAllow  string
	}{
		{name: "success", wantStatus: http.StatusOK},
		{name: "query", mutate: func(r *http.Request) { r.URL.RawQuery = "private=value" }, wantStatus: http.StatusNotFound, wantBody: "not_found\n"},
		{name: "trailing slash", mutate: func(r *http.Request) { r.URL.Path = "/mcp/" }, wantStatus: http.StatusNotFound, wantBody: "not_found\n"},
		{name: "encoded path", mutate: func(r *http.Request) { r.URL.Path = "/mcp"; r.URL.RawPath = "/%6dcp" }, wantStatus: http.StatusNotFound, wantBody: "not_found\n"},
		{name: "repeated slash", mutate: func(r *http.Request) { r.URL.Path = "//mcp" }, wantStatus: http.StatusNotFound, wantBody: "not_found\n"},
		{name: "dot segment", mutate: func(r *http.Request) { r.URL.Path = "/x/../mcp" }, wantStatus: http.StatusNotFound, wantBody: "not_found\n"},
		{name: "get", mutate: func(r *http.Request) { r.Method = http.MethodGet }, wantStatus: http.StatusMethodNotAllowed, wantBody: "method_not_allowed\n", wantAllow: "POST"},
		{name: "head", mutate: func(r *http.Request) { r.Method = http.MethodHead }, wantStatus: http.StatusMethodNotAllowed, wantBody: "", wantAllow: "POST"},
		{name: "delete", mutate: func(r *http.Request) { r.Method = http.MethodDelete }, wantStatus: http.StatusMethodNotAllowed, wantBody: "method_not_allowed\n", wantAllow: "POST"},
		{name: "options", mutate: func(r *http.Request) { r.Method = http.MethodOptions }, wantStatus: http.StatusMethodNotAllowed, wantBody: "method_not_allowed\n", wantAllow: "POST"},
		{name: "missing content type", mutate: func(r *http.Request) { r.Header.Del("Content-Type") }, wantStatus: http.StatusUnsupportedMediaType, wantBody: "unsupported_media_type\n"},
		{name: "text content type", mutate: func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, wantStatus: http.StatusUnsupportedMediaType, wantBody: "unsupported_media_type\n"},
		{name: "parameterized content type", mutate: func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") }, wantStatus: http.StatusUnsupportedMediaType, wantBody: "unsupported_media_type\n"},
		{name: "duplicate content type", mutate: func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }, wantStatus: http.StatusUnsupportedMediaType, wantBody: "unsupported_media_type\n"},
		{name: "suffix content type", mutate: func(r *http.Request) { r.Header.Set("Content-Type", "application/problem+json") }, wantStatus: http.StatusUnsupportedMediaType, wantBody: "unsupported_media_type\n"},
		{name: "event stream", mutate: func(r *http.Request) { r.Header.Set("Content-Type", "text/event-stream") }, wantStatus: http.StatusUnsupportedMediaType, wantBody: "unsupported_media_type\n"},
		{name: "unacceptable", mutate: func(r *http.Request) { r.Header.Set("Accept", "text/event-stream") }, wantStatus: http.StatusNotAcceptable, wantBody: "not_acceptable\n"},
		{name: "wildcard accept", mutate: func(r *http.Request) { r.Header.Set("Accept", "*/*") }, wantStatus: http.StatusOK},
		{name: "origin", mutate: func(r *http.Request) { r.Header.Set("Origin", "https://private.invalid") }, wantStatus: http.StatusForbidden, wantBody: "forbidden\n"},
		{name: "cors request", mutate: func(r *http.Request) { r.Header.Set("Access-Control-Request-Method", "POST") }, wantStatus: http.StatusForbidden, wantBody: "forbidden\n"},
		{name: "cross site fetch", mutate: func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, wantStatus: http.StatusForbidden, wantBody: "forbidden\n"},
		{name: "invalid host whitespace", mutate: func(r *http.Request) { r.Host = "bad host" }, wantStatus: http.StatusBadRequest, wantBody: "invalid_mcp_request\n"},
		{name: "invalid host comma", mutate: func(r *http.Request) { r.Host = "one.invalid,two.invalid" }, wantStatus: http.StatusBadRequest, wantBody: "invalid_mcp_request\n"},
		{name: "invalid host userinfo", mutate: func(r *http.Request) { r.Host = "user@host.invalid" }, wantStatus: http.StatusBadRequest, wantBody: "invalid_mcp_request\n"},
		{name: "forwarded ignored", mutate: func(r *http.Request) {
			r.Header.Set("Forwarded", "host=private.invalid")
			r.Header.Set("X-Forwarded-Host", "private.invalid")
		}, wantStatus: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validRequest(t, "tools/list", requestBody("tools/list"))
			if test.mutate != nil {
				test.mutate(request)
			}
			response := perform(t, handler, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d, body = %q", response.Code, test.wantStatus, response.Body.String())
			}
			if test.wantBody != "" && response.Body.String() != test.wantBody {
				t.Fatalf("body = %q, want fixed category %q", response.Body.String(), test.wantBody)
			}
			if response.Header().Get("Allow") != test.wantAllow {
				t.Errorf("Allow = %q, want %q", response.Header().Get("Allow"), test.wantAllow)
			}
			assertSecurityHeaders(t, response.Header())
		})
	}
}

func assertSecurityHeaders(t *testing.T, header http.Header) {
	t.Helper()
	want := map[string]string{
		"Content-Type":            "application/json; charset=utf-8",
		"Cache-Control":           "no-store",
		"Pragma":                  "no-cache",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": "default-src 'none'",
		"X-Frame-Options":         "DENY",
	}
	for name, value := range want {
		if header.Get(name) != value {
			t.Errorf("%s = %q, want %q", name, header.Get(name), value)
		}
	}
	for name := range header {
		if strings.HasPrefix(strings.ToLower(name), "access-control-allow-") {
			t.Errorf("CORS response header exposed: %s", name)
		}
	}
}

func TestProtocolRevisionRoutingHeadersAndSessionRejection(t *testing.T) {
	handler := newContractHandler(t, config.Defaults())
	tests := []struct {
		name       string
		body       string
		mutate     func(*http.Request)
		wantStatus int
		wantCode   float64
	}{
		{name: "discover", body: requestBody("server/discover"), wantStatus: http.StatusOK},
		{name: "direct tools list", body: requestBody("tools/list"), wantStatus: http.StatusOK},
		{name: "direct tools call", body: requestBody("tools/call"), wantStatus: http.StatusOK},
		{name: "missing protocol header", body: requestBody("tools/list"), mutate: func(r *http.Request) { r.Header.Del("MCP-Protocol-Version") }, wantStatus: http.StatusBadRequest},
		{name: "legacy header", body: requestBody("tools/list"), mutate: func(r *http.Request) { r.Header.Set("MCP-Protocol-Version", "2025-06-18") }, wantStatus: http.StatusBadRequest},
		{name: "future header", body: requestBody("tools/list"), mutate: func(r *http.Request) { r.Header.Set("MCP-Protocol-Version", "2027-01-01") }, wantStatus: http.StatusBadRequest},
		{name: "missing method header", body: requestBody("tools/list"), mutate: func(r *http.Request) { r.Header.Del("Mcp-Method") }, wantStatus: http.StatusBadRequest},
		{name: "duplicate method header", body: requestBody("tools/list"), mutate: func(r *http.Request) { r.Header.Add("Mcp-Method", "tools/list") }, wantStatus: http.StatusBadRequest},
		{name: "method control", body: requestBody("tools/list"), mutate: func(r *http.Request) { r.Header["Mcp-Method"] = []string{"tools/list\x00"} }, wantStatus: http.StatusBadRequest},
		{name: "method oversized", body: requestBody("tools/list"), mutate: func(r *http.Request) {
			r.Header["Mcp-Method"] = []string{strings.Repeat("x", MaximumRoutingHeaderBytes+1)}
		}, wantStatus: http.StatusBadRequest},
		{name: "method mismatch", body: requestBody("tools/list"), mutate: func(r *http.Request) { r.Header.Set("Mcp-Method", "tools/call") }, wantStatus: http.StatusBadRequest, wantCode: -32020},
		{name: "unexpected name", body: requestBody("tools/list"), mutate: func(r *http.Request) { r.Header.Set("Mcp-Name", "system_capabilities") }, wantStatus: http.StatusBadRequest},
		{name: "missing name", body: requestBody("tools/call"), mutate: func(r *http.Request) { r.Header.Del("Mcp-Name") }, wantStatus: http.StatusBadRequest},
		{name: "duplicate name", body: requestBody("tools/call"), mutate: func(r *http.Request) { r.Header.Add("Mcp-Name", "system_capabilities") }, wantStatus: http.StatusBadRequest},
		{name: "name mismatch", body: requestBody("tools/call"), mutate: func(r *http.Request) { r.Header.Set("Mcp-Name", "other") }, wantStatus: http.StatusBadRequest, wantCode: -32020},
		{name: "session", body: requestBody("tools/list"), mutate: func(r *http.Request) { r.Header.Set("Mcp-Session-Id", "synthetic-session") }, wantStatus: http.StatusBadRequest},
		{name: "event id", body: requestBody("tools/list"), mutate: func(r *http.Request) { r.Header.Set("Last-Event-ID", "synthetic-event") }, wantStatus: http.StatusBadRequest},
		{name: "initialize", body: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"legacy","version":"1"}}}`, mutate: func(r *http.Request) { r.Header.Set("Mcp-Method", "initialize") }, wantStatus: http.StatusOK, wantCode: -32601},
		{name: "initialized", body: `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`, mutate: func(r *http.Request) { r.Header.Set("Mcp-Method", "notifications/initialized") }, wantStatus: http.StatusBadRequest},
		{name: "unknown method", body: requestBody("private/method"), wantStatus: http.StatusOK, wantCode: -32601},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			method := "tools/list"
			if strings.Contains(test.body, `"method":"tools/call"`) {
				method = "tools/call"
			} else if strings.Contains(test.body, `"method":"server/discover"`) {
				method = "server/discover"
			} else if strings.Contains(test.body, `"method":"private/method"`) {
				method = "private/method"
			}
			request := validRequest(t, method, test.body)
			if test.mutate != nil {
				test.mutate(request)
			}
			response := perform(t, handler, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d, body = %q", response.Code, test.wantStatus, response.Body.String())
			}
			if test.wantCode != 0 {
				var envelope struct {
					Error struct {
						Code float64 `json:"code"`
						Data any     `json:"data"`
					} `json:"error"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope.Error.Code != test.wantCode || envelope.Error.Data != nil {
					t.Fatalf("JSON-RPC error = %#v, decode = %v", envelope, err)
				}
			}
		})
	}
}

func TestEnvelopeStructureBoundsAndErrorCategories(t *testing.T) {
	handler := newContractHandler(t, config.Defaults())
	deep := strings.Repeat(`{"x":`, MaximumJSONDepth) + `0` + strings.Repeat("}", MaximumJSONDepth)
	nodes := `[` + strings.Repeat("0,", MaximumJSONNodes) + `0]`
	tests := []struct {
		name string
		body string
		code float64
	}{
		{name: "parse", body: `{`, code: -32700},
		{name: "invalid utf8", body: string([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}), code: -32700},
		{name: "trailing", body: requestBody("tools/list") + `{}`, code: -32700},
		{name: "batch", body: `[` + requestBody("tools/list") + `]`, code: -32600},
		{name: "duplicate method", body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call","params":{` + validMeta() + `}}`, code: -32600},
		{name: "case alias", body: `{"jsonrpc":"2.0","id":1,"Method":"tools/list","params":{` + validMeta() + `}}`, code: -32600},
		{name: "nul alias", body: `{"jsonrpc":"2.0","id":1,"meth\u0000od":"tools/list","params":{` + validMeta() + `}}`, code: -32600},
		{name: "missing meta", body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, code: -32602},
		{name: "unsupported client capability", body: strings.Replace(requestBody("tools/list"), `"clientCapabilities":{}`, `"clientCapabilities":{"sampling":{}}`, 1), code: -32602},
		{name: "deep", body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + validMeta() + `,"extra":` + deep + `}}`, code: -32600},
		{name: "nodes", body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + validMeta() + `,"extra":` + nodes + `}}`, code: -32600},
		{name: "extra arguments", body: strings.Replace(requestBody("tools/call"), `"arguments":{}`, `"arguments":{"private":"value"}`, 1), code: -32602},
		{name: "unknown tool", body: strings.Replace(requestBody("tools/call"), "system_capabilities", "private_tool", 1), code: -32601},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			method := "tools/list"
			if strings.Contains(test.body, `"method":"tools/call"`) {
				method = "tools/call"
			}
			request := validRequest(t, method, test.body)
			if strings.Contains(test.body, "private_tool") {
				request.Header.Set("Mcp-Name", "private_tool")
			}
			response := perform(t, handler, request)
			if response.Code != http.StatusOK {
				t.Fatalf("HTTP status = %d, body = %q", response.Code, response.Body.String())
			}
			var envelope struct {
				Error struct {
					Code float64 `json:"code"`
					Data any     `json:"data"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope.Error.Code != test.code || envelope.Error.Data != nil {
				t.Fatalf("error = %#v, decode = %v, body = %q", envelope, err, response.Body.String())
			}
			for _, forbidden := range []string{"private", "sampling", "meth\\u0000od", "unexpected end", "invalid character"} {
				if strings.Contains(response.Body.String(), forbidden) {
					t.Errorf("error reflected %q", forbidden)
				}
			}
		})
	}
}

func TestRequestBodyExactAndOneOverLimitsForDeclaredAndChunkedBodies(t *testing.T) {
	configuration := config.Defaults()
	configuration.Server.MaxRequestBytes = MaximumRequestBytes + 1
	handler := newContractHandler(t, configuration)
	base := requestBody("tools/list")
	for _, declared := range []bool{true, false} {
		for _, size := range []int{MaximumRequestBytes, MaximumRequestBytes + 1} {
			name := "chunked"
			if declared {
				name = "declared"
			}
			t.Run(name+"_"+string(rune(size-MaximumRequestBytes+'0')), func(t *testing.T) {
				body := base + strings.Repeat(" ", size-len(base))
				request := validRequest(t, "tools/list", body)
				if declared {
					request.ContentLength = int64(size)
				} else {
					request.ContentLength = -1
					request.TransferEncoding = []string{"chunked"}
				}
				response := perform(t, handler, request)
				if size == MaximumRequestBytes && response.Code != http.StatusOK {
					t.Fatalf("exact limit status = %d", response.Code)
				}
				if size == MaximumRequestBytes+1 && (response.Code != http.StatusRequestEntityTooLarge || response.Body.String() != "request_too_large\n") {
					t.Fatalf("one over response = %d %q", response.Code, response.Body.String())
				}
			})
		}
	}

	configuration.Server.MaxRequestBytes = 4096
	handler = newContractHandler(t, configuration)
	request := validRequest(t, "tools/list", base+strings.Repeat(" ", 4096-len(base)+1))
	response := perform(t, handler, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("configured lower bound status = %d", response.Code)
	}
}

func TestToolsListAndSystemCapabilitiesGolden(t *testing.T) {
	configuration := config.Defaults()
	configuration.Database.URLEnv = "SYNTHETIC_DATABASE_URL"
	configuration.Database.AuthTokenEnv = "SYNTHETIC_DATABASE_TOKEN"
	configuration.Gmail.OAuthClientIDEnv = "SYNTHETIC_GOOGLE_CLIENT_ID"
	configuration.Gmail.OAuthClientSecretEnv = "SYNTHETIC_GOOGLE_CLIENT_SECRET"
	configuration.Gmail.OAuthRedirectURLEnv = "SYNTHETIC_GOOGLE_REDIRECT_URL"
	configuration.Encryption.MasterKeyEnv = "SYNTHETIC_MASTER_KEY"
	handler := newContractHandler(t, configuration)

	list := perform(t, handler, validRequest(t, "tools/list", requestBody("tools/list")))
	if list.Code != http.StatusOK {
		t.Fatalf("tools/list status = %d, body = %q", list.Code, list.Body.String())
	}
	var listed struct {
		Result struct {
			Tools []struct {
				Name        string         `json:"name"`
				InputSchema map[string]any `json:"inputSchema"`
				Annotations map[string]any `json:"annotations"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Result.Tools) != 1 || listed.Result.Tools[0].Name != "system_capabilities" {
		t.Fatalf("tools = %#v", listed.Result.Tools)
	}
	wantSchema := map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}
	if !reflect.DeepEqual(listed.Result.Tools[0].InputSchema, wantSchema) {
		t.Errorf("input schema = %#v, want %#v", listed.Result.Tools[0].InputSchema, wantSchema)
	}
	wantAnnotations := map[string]any{"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false}
	if !reflect.DeepEqual(listed.Result.Tools[0].Annotations, wantAnnotations) {
		t.Errorf("annotations = %#v, want %#v", listed.Result.Tools[0].Annotations, wantAnnotations)
	}

	call := perform(t, handler, validRequest(t, "tools/call", requestBody("tools/call")))
	if call.Code != http.StatusOK {
		t.Fatalf("tools/call status = %d, body = %q", call.Code, call.Body.String())
	}
	var called struct {
		Result struct {
			StructuredContent json.RawMessage `json:"structuredContent"`
			Content           []any           `json:"content"`
			IsError           bool            `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(call.Body.Bytes(), &called); err != nil {
		t.Fatal(err)
	}
	if called.Result.IsError || len(called.Result.Content) != 0 || len(called.Result.StructuredContent) == 0 {
		t.Fatalf("tool result is not structured-only: %#v", called.Result)
	}
	golden, err := os.ReadFile("../../testdata/mcp-system-capabilities-default.json")
	if err != nil {
		t.Fatal(err)
	}
	var got, want any
	if err := json.Unmarshal(called.Result.StructuredContent, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(golden, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("structured output differs from reviewed golden\n got %s\nwant %s", called.Result.StructuredContent, golden)
	}
	if len(call.Body.Bytes()) > MaximumResponseBytes {
		t.Fatalf("response bytes = %d, want at most %d", len(call.Body.Bytes()), MaximumResponseBytes)
	}
	for _, name := range []string{
		configuration.Database.URLEnv,
		configuration.Database.AuthTokenEnv,
		configuration.Gmail.OAuthClientIDEnv,
		configuration.Gmail.OAuthClientSecretEnv,
		configuration.Gmail.OAuthRedirectURLEnv,
		configuration.Encryption.MasterKeyEnv,
	} {
		t.Setenv(name, "SYNTHETIC_VALUE_MUST_NOT_APPEAR")
	}
	afterEnvironment := perform(t, handler, validRequest(t, "tools/call", requestBody("tools/call")))
	var afterCalled struct {
		Result struct {
			StructuredContent json.RawMessage `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(afterEnvironment.Body.Bytes(), &afterCalled); err != nil || !bytes.Equal(afterCalled.Result.StructuredContent, called.Result.StructuredContent) {
		t.Fatal("capability output changed with secret presence or value")
	}
	for _, forbidden := range []string{"SYNTHETIC_VALUE", "present", "connected", "healthy", "migration_state"} {
		if strings.Contains(call.Body.String(), forbidden) {
			t.Errorf("capability response exposes runtime or secret state %q", forbidden)
		}
	}
}

func TestCapabilityOutputBuildMetadataMissingPrerequisitesAndFreshSnapshots(t *testing.T) {
	configuration := config.Defaults()
	development := newContractHandler(t, configuration)
	first := perform(t, development, validRequest(t, "tools/call", requestBody("tools/call"))).Body.Bytes()
	second := perform(t, development, validRequest(t, "tools/call", requestBody("tools/call"))).Body.Bytes()
	if !bytes.Equal(first, second) {
		t.Fatal("identical development inputs produced different bytes")
	}
	var payload map[string]any
	if err := json.Unmarshal(first, &payload); err != nil {
		t.Fatal(err)
	}
	structured := payload["result"].(map[string]any)["structuredContent"].(map[string]any)
	if structured["binary_version"] != "dev" || structured["binary_commit"] != nil || structured["protocol_version"] != protocolVersion || structured["output_version"] != float64(1) {
		t.Fatalf("development metadata = %#v", structured)
	}
	capabilities := structured["capabilities"].([]any)
	capabilities[0].(map[string]any)["name"] = "mutated"
	third := perform(t, development, validRequest(t, "tools/call", requestBody("tools/call"))).Body.Bytes()
	if !bytes.Equal(first, third) {
		t.Fatal("mutating a prior decoded snapshot affected a later call")
	}
	for _, raw := range capabilities {
		capability := raw.(map[string]any)
		missing := capability["missing_prerequisites"].([]any)
		if capability["implementation_status"] == "not_implemented" && !slices.Contains(missing, any("implementation_not_available")) {
			t.Errorf("missing implementation code: %#v", capability)
		}
		if capability["configuration_status"] == "disabled" && !slices.Contains(missing, any("disabled_by_configuration")) {
			t.Errorf("missing configuration code: %#v", capability)
		}
		for _, value := range missing {
			if value != "implementation_not_available" && value != "disabled_by_configuration" {
				t.Errorf("unsafe missing prerequisite code %q", value)
			}
		}
	}

	release, err := New(Options{Configuration: configuration, BinaryVersion: "v0.1.0", BinaryCommit: strings.Repeat("a", 40), BearerToken: []byte(canonicalToken()), AuditOutput: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	defer release.Close()
	releaseResponse := perform(t, release, validRequest(t, "tools/call", requestBody("tools/call")))
	if !strings.Contains(releaseResponse.Body.String(), `"binary_version":"v0.1.0"`) || !strings.Contains(releaseResponse.Body.String(), `"binary_commit":"`+strings.Repeat("a", 40)+`"`) {
		t.Fatalf("release metadata missing: %s", releaseResponse.Body.String())
	}
	if _, err := New(Options{Configuration: configuration, BinaryVersion: "v0.1.0", BinaryCommit: "bad", BearerToken: []byte(canonicalToken()), AuditOutput: io.Discard}); err == nil {
		t.Fatal("invalid release metadata accepted")
	}
}

func TestDiscoveryAdvertisesOnlyExactRevisionAndTools(t *testing.T) {
	handler := newContractHandler(t, config.Defaults())
	response := perform(t, handler, validRequest(t, "server/discover", requestBody("server/discover")))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
	var envelope struct {
		Result struct {
			SupportedVersions []string       `json:"supportedVersions"`
			Capabilities      map[string]any `json:"capabilities"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(envelope.Result.SupportedVersions, []string{protocolVersion}) || !reflect.DeepEqual(envelope.Result.Capabilities, map[string]any{"tools": map[string]any{"listChanged": false}}) {
		t.Fatalf("discovery = %#v", envelope.Result)
	}
	for _, forbidden := range []string{"prompts", "resources", "subscriptions", "logging", "roots", "sampling", "elicitation", "tasks", "experimental", "completion"} {
		if strings.Contains(response.Body.String(), `"`+forbidden+`"`) {
			t.Errorf("discovery advertises %q", forbidden)
		}
	}
}

func TestCompatibilityFlagsCannotBroadenWrapper(t *testing.T) {
	flags := []string{
		"allowsessionsinstateless=1",
		"disablecontenttypecheck=1",
		"enableoriginverification=0",
		"seterroroverwrite=1",
		"disablecompleteparamsvalidation=1",
	}
	for _, flag := range flags {
		t.Run(flag, func(t *testing.T) {
			t.Setenv("MCPGODEBUG", flag)
			handler := newContractHandler(t, config.Defaults())
			checks := []*http.Request{
				validRequest(t, "tools/list", requestBody("tools/list")),
				validRequest(t, "tools/list", requestBody("tools/list")),
				validRequest(t, "tools/list", requestBody("tools/list")),
				validRequest(t, "initialize", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`),
			}
			checks[0].Method = http.MethodDelete
			checks[0].Header.Set("Mcp-Session-Id", "synthetic-session")
			checks[1].Header.Set("Content-Type", "text/plain")
			checks[2].Header.Set("Origin", "https://private.invalid")
			for index, request := range checks {
				response := perform(t, handler, request)
				if response.Code == http.StatusOK && !strings.Contains(response.Body.String(), `"code":-32601`) {
					t.Errorf("compatibility check %d broadened wrapper: %d %q", index, response.Code, response.Body.String())
				}
				if response.Header().Get("Mcp-Session-Id") != "" || response.Header().Get("Content-Type") == "text/event-stream" {
					t.Errorf("compatibility check %d enabled sessions or SSE", index)
				}
			}
		})
	}
}

func TestConcurrencyDeadlineCancellationResponseCapAndClose(t *testing.T) {
	entered := make(chan struct{}, MaximumConcurrentRequests+1)
	release := make(chan struct{})
	var invocations atomic.Int64
	handler := newContractHandler(t, config.Defaults(), withDispatchHook(func(ctx context.Context) error {
		invocations.Add(1)
		entered <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}))

	var wait sync.WaitGroup
	responses := make(chan *httptest.ResponseRecorder, MaximumConcurrentRequests)
	for index := 0; index < MaximumConcurrentRequests; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			responses <- perform(t, handler, validRequest(t, "tools/call", requestBody("tools/call")))
		}()
	}
	for index := 0; index < MaximumConcurrentRequests; index++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("request did not enter dispatch")
		}
	}
	seventeenth := perform(t, handler, validRequest(t, "tools/call", requestBody("tools/call")))
	if seventeenth.Code != http.StatusTooManyRequests || seventeenth.Body.String() != "too_many_requests\n" || seventeenth.Header().Get("Retry-After") != "1" {
		t.Fatalf("seventeenth response = %d %q", seventeenth.Code, seventeenth.Body.String())
	}
	close(release)
	wait.Wait()
	close(responses)
	for response := range responses {
		if response.Code != http.StatusOK {
			t.Errorf("admitted response = %d %q", response.Code, response.Body.String())
		}
	}
	if invocations.Load() != MaximumConcurrentRequests {
		t.Fatalf("dispatch invocations = %d, want %d", invocations.Load(), MaximumConcurrentRequests)
	}

	deadline := newContractHandler(t, config.Defaults(), withApplicationTimeout(20*time.Millisecond), withDispatchHook(func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}))
	response := perform(t, deadline, validRequest(t, "tools/call", requestBody("tools/call")))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"code":-32603`) {
		t.Fatalf("deadline response = %d %q", response.Code, response.Body.String())
	}

	cancelled := make(chan struct{})
	cancellation := newContractHandler(t, config.Defaults(), withDispatchHook(func(ctx context.Context) error {
		<-ctx.Done()
		close(cancelled)
		return ctx.Err()
	}))
	ctx, cancel := context.WithCancel(context.Background())
	request := validRequest(t, "tools/call", requestBody("tools/call")).WithContext(ctx)
	done := make(chan struct{})
	go func() { perform(t, cancellation, request); close(done) }()
	cancel()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("client cancellation did not reach application")
	}
	<-done

	responseLimited := newContractHandler(t, config.Defaults(), withResponseLimit(256))
	limited := perform(t, responseLimited, validRequest(t, "tools/call", requestBody("tools/call")))
	if limited.Code != http.StatusInternalServerError || limited.Body.String() != "internal_error\n" || strings.Contains(limited.Body.String(), "capabilities") {
		t.Fatalf("response cap = %d %q", limited.Code, limited.Body.String())
	}

	owned := append([]byte(nil), canonicalToken()...)
	closer, err := New(Options{Configuration: config.Defaults(), BinaryVersion: "dev", BearerToken: owned, AuditOutput: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	clear(owned)
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, value := range closer.token {
		if value != 0 {
			t.Fatal("handler-owned decoded token was not cleared")
		}
	}
	afterClose := perform(t, closer, validRequest(t, "tools/list", requestBody("tools/list")))
	if afterClose.Code != http.StatusServiceUnavailable || afterClose.Body.String() != "service_unavailable\n" {
		t.Fatalf("closed handler response = %d %q", afterClose.Code, afterClose.Body.String())
	}
}

func TestAuditLogUsesOnlyFixedAllowlistAndRedactsRequestData(t *testing.T) {
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			configuration := config.Defaults()
			configuration.Logging.Format = format
			var audit bytes.Buffer
			handler, err := New(Options{Configuration: configuration, BinaryVersion: "dev", BearerToken: []byte(canonicalToken()), AuditOutput: &audit})
			if err != nil {
				t.Fatal(err)
			}
			defer handler.Close()
			request := validRequest(t, "tools/call", requestBody("tools/call"))
			request.Host = "sensitive-host.invalid"
			request.RemoteAddr = "192.0.2.99:1234"
			request.Header.Set("User-Agent", "sensitive-agent")
			request.Header.Set("X-Canary", "sensitive-header")
			perform(t, handler, request)
			logText := audit.String()
			for _, forbidden := range []string{canonicalToken(), "sensitive", "192.0.2.99", "system_capabilities", "synthetic-client", configuration.MCP.BearerTokenEnv, "Mcp-Method", "Authorization"} {
				if strings.Contains(logText, forbidden) {
					t.Errorf("audit disclosed %q: %s", forbidden, logText)
				}
			}
			fields := decodeAuditFields(t, format, logText)
			wantKeys := []string{"duration_ms", "event", "level", "method", "msg", "operation", "outcome", "status", "time"}
			gotKeys := make([]string, 0, len(fields))
			for key := range fields {
				gotKeys = append(gotKeys, key)
			}
			slices.Sort(gotKeys)
			if !reflect.DeepEqual(gotKeys, wantKeys) || fields["event"] != "mcp_request" || fields["operation"] != "mcp.system_capabilities" {
				t.Fatalf("audit fields = %#v", fields)
			}
		})
	}
}

func decodeAuditFields(t *testing.T, format, line string) map[string]any {
	t.Helper()
	if format == "json" {
		var fields map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &fields); err != nil {
			t.Fatal(err)
		}
		return fields
	}
	fields := map[string]any{}
	for _, word := range strings.Fields(line) {
		key, value, found := strings.Cut(word, "=")
		if found {
			fields[key] = strings.Trim(value, `"`)
		}
	}
	return fields
}

func TestNoApplicationAuthorityBeyondTypedCapabilityRegistry(t *testing.T) {
	handler := newContractHandler(t, config.Defaults())
	for _, method := range []string{
		"resources/list", "resources/read", "prompts/list", "prompts/get", "completion/complete",
		"logging/setLevel", "sampling/createMessage", "elicitation/create", "roots/list",
		"subscriptions/listen", "tasks/list", "gmail/request", "sql/query", "shell/exec", "url/fetch", "vikunja/write",
	} {
		request := validRequest(t, method, requestBody(method))
		response := perform(t, handler, request)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"code":-32601`) {
			t.Errorf("method %q response = %d %q", method, response.Code, response.Body.String())
		}
	}
}

func TestMCPPackageDependencyGraphHasNoApplicationAuthority(t *testing.T) {
	command := exec.Command("go", "list", "-mod=readonly", "-deps", "./internal/mcp")
	command.Dir = "../.."
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list MCP dependencies: %v: %s", err, output)
	}
	dependencies := strings.Fields(string(output))
	for _, forbidden := range []string{
		"database/sql",
		"github.com/mandloideep/inboxgate/internal/account",
		"github.com/mandloideep/inboxgate/internal/cryptobox",
		"github.com/mandloideep/inboxgate/internal/gate",
		"github.com/mandloideep/inboxgate/internal/gateeval",
		"github.com/mandloideep/inboxgate/internal/gmail",
		"github.com/mandloideep/inboxgate/internal/mail",
		"github.com/mandloideep/inboxgate/internal/storage",
		"github.com/mandloideep/inboxgate/internal/storage/turso",
	} {
		if slices.Contains(dependencies, forbidden) {
			t.Errorf("MCP dependency graph reaches forbidden authority %q", forbidden)
		}
	}
}

func FuzzParseBearerToken(f *testing.F) {
	f.Add(canonicalToken())
	f.Add("")
	f.Add(canonicalToken() + "=")
	f.Fuzz(func(t *testing.T, input string) {
		decoded, err := ParseBearerToken(input)
		if err == nil {
			if len(input) != 43 || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != input {
				t.Fatalf("accepted noncanonical token shape")
			}
		}
		clear(decoded)
	})
}

func FuzzParseAuthorization(f *testing.F) {
	f.Add("Bearer " + canonicalToken())
	f.Add("bearer " + canonicalToken())
	f.Add("")
	f.Fuzz(func(t *testing.T, value string) {
		decoded, err := parseAuthorization([]string{value})
		if err == nil && (value != "Bearer "+canonicalToken() || !bytes.Equal(decoded, syntheticTokenBytes)) {
			t.Fatal("authorization parser accepted a noncanonical value")
		}
		clear(decoded)
	})
}

func FuzzRoutingHeaders(f *testing.F) {
	f.Add("tools/list", "")
	f.Add("tools/call", "system_capabilities")
	f.Add("tools/call\x00", "system_capabilities")
	f.Fuzz(func(t *testing.T, method, name string) {
		if len(method)+len(name) > 1024 {
			t.Skip()
		}
		handler := newContractHandler(t, config.Defaults())
		request := validRequest(t, "tools/list", requestBody("tools/list"))
		request.Header["Mcp-Method"] = []string{method}
		if name != "" {
			request.Header["Mcp-Name"] = []string{name}
		}
		response := perform(t, handler, request)
		if method != "tools/list" || name != "" {
			if response.Code == http.StatusOK && !strings.Contains(response.Body.String(), `"code":-32020`) {
				t.Fatal("routing mismatch reached application success")
			}
		}
	})
}

func FuzzStructuralEnvelope(f *testing.F) {
	f.Add([]byte(requestBody("tools/list")))
	f.Add([]byte("{"))
	f.Add([]byte("[]"))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > MaximumRequestBytes+1 {
			t.Skip()
		}
		classification := classifyEnvelope(body)
		if classification.Code != 0 && classification.Code != -32700 && classification.Code != -32600 && classification.Code != -32602 && classification.Code != -32020 {
			t.Fatalf("unbounded error vocabulary: %#v", classification)
		}
		if strings.Contains(classification.Message, string(body)) && len(body) != 0 {
			t.Fatal("classification reflected input")
		}
	})
}

func FuzzCapabilityRendering(f *testing.F) {
	f.Add("SYNTHETIC_DATABASE_URL")
	f.Add("A")
	f.Fuzz(func(t *testing.T, name string) {
		if !validEnvironmentName(name) {
			t.Skip()
		}
		configuration := config.Defaults()
		configuration.Database.URLEnv = name
		first, err := renderCapabilities(configuration, "dev", "")
		if err != nil {
			t.Fatal(err)
		}
		second, err := renderCapabilities(configuration, "dev", "")
		if err != nil || !bytes.Equal(first, second) || len(first) > MaximumResponseBytes {
			t.Fatalf("render is unstable or unbounded")
		}
	})
}

func TestNoRetryOnApplicationFailure(t *testing.T) {
	var calls atomic.Int64
	handler := newContractHandler(t, config.Defaults(), withDispatchHook(func(context.Context) error {
		calls.Add(1)
		return errors.New("sensitive application error")
	}))
	response := perform(t, handler, validRequest(t, "tools/call", requestBody("tools/call")))
	if calls.Load() != 1 || response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"code":-32603`) || strings.Contains(response.Body.String(), "sensitive") {
		t.Fatalf("application failure calls = %d, response = %d %q", calls.Load(), response.Code, response.Body.String())
	}
}
