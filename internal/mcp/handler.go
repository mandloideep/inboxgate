// Package mcp exposes InboxGate's single authenticated MCP capability tool.
package mcp

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mandloideep/inboxgate/internal/buildmeta"
	"github.com/mandloideep/inboxgate/internal/config"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	ProtocolVersion           = "2026-07-28"
	MaximumRequestBytes       = 65_536
	MaximumRoutingHeaderBytes = 256
	MaximumJSONDepth          = 16
	MaximumJSONNodes          = 2_048
	MaximumResponseBytes      = 65_536
	MaximumConcurrentRequests = 16
	applicationTimeout        = 5 * time.Second
	systemCapabilitiesTool    = "system_capabilities"
)

var environmentNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

type Options struct {
	Configuration config.Config
	BinaryVersion string
	BinaryCommit  string
	BearerToken   []byte
	AuditOutput   io.Writer
}

type Option func(*Handler)

func withDispatchHook(hook func(context.Context) error) Option {
	return func(handler *Handler) { handler.dispatchHook = hook }
}

func withApplicationTimeout(timeout time.Duration) Option {
	return func(handler *Handler) { handler.applicationTimeout = timeout }
}

func withResponseLimit(limit int) Option {
	return func(handler *Handler) { handler.responseLimit = limit }
}

type Handler struct {
	configuration      config.Config
	binaryVersion      string
	binaryCommit       string
	token              []byte
	audit              *slog.Logger
	sdk                http.Handler
	rootContext        context.Context
	rootCancel         context.CancelFunc
	dispatchHook       func(context.Context) error
	applicationTimeout time.Duration
	responseLimit      int
	admission          chan struct{}

	mu       sync.Mutex
	active   sync.WaitGroup
	requests map[*activeRequest]struct{}
	closed   bool
}

type activeRequest struct {
	cancel context.CancelFunc
	body   io.Closer
}

func New(options Options, modifiers ...Option) (*Handler, error) {
	if options.BinaryVersion == "dev" {
		if options.BinaryCommit != "" {
			return nil, errors.New("invalid build metadata")
		}
	} else if err := buildmeta.ValidateRelease(options.BinaryVersion, options.BinaryCommit); err != nil {
		return nil, errors.New("invalid build metadata")
	}
	decoded, err := ParseBearerToken(string(options.BearerToken))
	if err != nil {
		return nil, errors.New("invalid bearer token")
	}
	rootContext, rootCancel := context.WithCancel(context.Background())
	handler := &Handler{
		configuration:      options.Configuration,
		binaryVersion:      options.BinaryVersion,
		binaryCommit:       options.BinaryCommit,
		token:              decoded,
		rootContext:        rootContext,
		rootCancel:         rootCancel,
		applicationTimeout: applicationTimeout,
		responseLimit:      MaximumResponseBytes,
		admission:          make(chan struct{}, MaximumConcurrentRequests),
		requests:           make(map[*activeRequest]struct{}),
	}
	for _, modifier := range modifiers {
		modifier(handler)
	}
	if handler.applicationTimeout <= 0 || handler.responseLimit <= 0 || handler.responseLimit > MaximumResponseBytes {
		handler.rootCancel()
		clear(handler.token)
		return nil, errors.New("invalid MCP handler options")
	}
	if options.AuditOutput == nil {
		options.AuditOutput = io.Discard
	}
	handler.audit, err = newAuditLogger(options.Configuration.Logging, options.AuditOutput)
	if err != nil {
		handler.rootCancel()
		clear(handler.token)
		return nil, err
	}
	handler.sdk = handler.newSDKHandler()
	return handler, nil
}

func ParseBearerToken(value string) ([]byte, error) {
	if len(value) != 43 {
		return nil, errors.New("invalid token")
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' || character == '_') {
			return nil, errors.New("invalid token")
		}
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, errors.New("invalid token")
	}
	return decoded, nil
}

func parseAuthorization(values []string) ([]byte, error) {
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || len(values[0]) != len("Bearer ")+43 {
		return nil, errors.New("invalid authorization")
	}
	return ParseBearerToken(values[0][len("Bearer "):])
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	started := time.Now()
	status := http.StatusInternalServerError
	operation := operationForHeaders(request.Header)
	defer func() {
		handler.logAudit(operation, methodClass(request.Method), status, outcomeForStatus(status), started)
	}()
	setSecurityHeaders(response.Header())

	if handler.isClosed() {
		status = http.StatusServiceUnavailable
		writeFixed(response, request.Method == http.MethodHead, status, "service_unavailable", "", "")
		return
	}
	if !handler.exactRoute(request) {
		status = http.StatusNotFound
		writeFixed(response, request.Method == http.MethodHead, status, "not_found", "", "")
		return
	}
	authorized, closed := handler.authenticate(request.Header.Values("Authorization"))
	if closed {
		status = http.StatusServiceUnavailable
		writeFixed(response, request.Method == http.MethodHead, status, "service_unavailable", "", "")
		return
	}
	if !authorized {
		status = http.StatusUnauthorized
		writeFixed(response, request.Method == http.MethodHead, status, "unauthorized", "", "Bearer")
		return
	}
	if request.Method != http.MethodPost {
		status = http.StatusMethodNotAllowed
		writeFixed(response, request.Method == http.MethodHead, status, "method_not_allowed", "POST", "")
		return
	}
	if forbiddenBrowserRequest(request.Header) {
		status = http.StatusForbidden
		writeFixed(response, false, status, "forbidden", "", "")
		return
	}
	if !validHost(request.Host) {
		status = http.StatusBadRequest
		writeFixed(response, false, status, "invalid_mcp_request", "", "")
		return
	}
	if !exactContentType(request.Header) {
		status = http.StatusUnsupportedMediaType
		writeFixed(response, false, status, "unsupported_media_type", "", "")
		return
	}
	if !acceptable(request.Header.Values("Accept")) {
		status = http.StatusNotAcceptable
		writeFixed(response, false, status, "not_acceptable", "", "")
		return
	}
	methodHeader, ok := requiredRoutingHeader(request.Header, "Mcp-Method")
	if !ok {
		status = http.StatusBadRequest
		writeFixed(response, false, status, "invalid_mcp_request", "", "")
		return
	}
	nameHeader, namePresent, nameValid := optionalRoutingHeader(request.Header, "Mcp-Name")
	if !nameValid {
		status = http.StatusBadRequest
		writeFixed(response, false, status, "invalid_mcp_request", "", "")
		return
	}
	protocolHeader, ok := requiredRoutingHeader(request.Header, "Mcp-Protocol-Version")
	if !ok || protocolHeader != ProtocolVersion || hasHeader(request.Header, "Mcp-Session-Id") || hasHeader(request.Header, "Last-Event-ID") {
		status = http.StatusBadRequest
		writeFixed(response, false, status, "invalid_mcp_request", "", "")
		return
	}
	requestContext, cancel := context.WithTimeout(request.Context(), handler.applicationTimeout)
	stop := context.AfterFunc(handler.rootContext, cancel)
	active := &activeRequest{cancel: cancel, body: request.Body}
	admitted, closed := handler.admit(active)
	if !admitted {
		stop()
		cancel()
		if closed {
			status = http.StatusServiceUnavailable
			writeFixed(response, false, status, "service_unavailable", "", "")
			return
		}
		status = http.StatusTooManyRequests
		response.Header().Set("Retry-After", "1")
		writeFixed(response, false, status, "too_many_requests", "", "")
		return
	}
	defer func() {
		stop()
		cancel()
		handler.release(active)
	}()

	maximum := int(handler.configuration.Server.MaxRequestBytes)
	if maximum > MaximumRequestBytes {
		maximum = MaximumRequestBytes
	}
	if request.ContentLength > int64(maximum) {
		status = http.StatusRequestEntityTooLarge
		writeFixed(response, false, status, "request_too_large", "", "")
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, int64(maximum)+1))
	if request.Body != nil {
		_ = request.Body.Close()
	}
	if err != nil || len(body) > maximum {
		status = http.StatusRequestEntityTooLarge
		writeFixed(response, false, status, "request_too_large", "", "")
		return
	}
	classification := classifyEnvelope(body)
	if classification.Method == "notifications/initialized" {
		status = http.StatusBadRequest
		writeFixed(response, false, status, "invalid_mcp_request", "", "")
		return
	}
	if classification.Code != -32700 {
		if classification.Method != "" {
			if methodHeader != classification.Method {
				status = http.StatusBadRequest
				writeJSONRPCError(response, status, -32020, classification.ID)
				return
			}
			if classification.Method == "tools/call" {
				if !namePresent {
					status = http.StatusBadRequest
					writeFixed(response, false, status, "invalid_mcp_request", "", "")
					return
				}
				if nameHeader != classification.Name {
					status = http.StatusBadRequest
					writeJSONRPCError(response, status, -32020, classification.ID)
					return
				}
			} else if namePresent {
				status = http.StatusBadRequest
				writeFixed(response, false, status, "invalid_mcp_request", "", "")
				return
			}
		}
	}
	if classification.Code != 0 && classification.Code != -32700 {
		status = http.StatusOK
		writeJSONRPCError(response, status, classification.Code, classification.ID)
		return
	}

	if classification.Method == "tools/call" && handler.dispatchHook != nil {
		if err := handler.dispatchHook(requestContext); err != nil {
			status = http.StatusOK
			writeJSONRPCError(response, status, -32603, classification.ID)
			return
		}
	}
	sdkRequest := request.Clone(requestContext)
	sdkRequest.Header = request.Header.Clone()
	sdkRequest.Header.Set("Accept", "application/json, text/event-stream")
	sdkRequest.Body = io.NopCloser(bytes.NewReader(body))
	sdkRequest.ContentLength = int64(len(body))
	buffer := newResponseBuffer(handler.responseLimit)
	handler.sdk.ServeHTTP(buffer, sdkRequest)
	if buffer.exceeded {
		status = http.StatusInternalServerError
		writeFixed(response, false, status, "internal_error", "", "")
		return
	}
	if classification.Code == -32700 {
		status = http.StatusOK
		writeJSONRPCError(response, status, -32700, nil)
		return
	}
	if code, found := sdkErrorCode(buffer.body.Bytes()); found {
		status = http.StatusOK
		writeJSONRPCError(response, status, normalizeSDKError(code), classification.ID)
		return
	}
	if buffer.status != 0 && buffer.status != http.StatusOK {
		status = http.StatusInternalServerError
		writeFixed(response, false, status, "internal_error", "", "")
		return
	}
	status = http.StatusOK
	if classification.Method == "server/discover" {
		writeDiscovery(response, status, classification.ID, handler.binaryVersion)
		return
	}
	writeBuffered(response, status, buffer.body.Bytes())
}

func (handler *Handler) Close() error {
	handler.mu.Lock()
	if handler.closed {
		handler.mu.Unlock()
		return nil
	}
	handler.closed = true
	clear(handler.token)
	requests := make([]*activeRequest, 0, len(handler.requests))
	for request := range handler.requests {
		requests = append(requests, request)
	}
	handler.mu.Unlock()
	handler.rootCancel()
	for _, request := range requests {
		request.cancel()
		if request.body != nil {
			_ = request.body.Close()
		}
	}
	handler.active.Wait()
	return nil
}

func (handler *Handler) isClosed() bool {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	return handler.closed
}

func (handler *Handler) authenticate(values []string) (bool, bool) {
	presented, err := parseAuthorization(values)
	if err != nil {
		return false, false
	}
	defer clear(presented)
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if handler.closed {
		return false, true
	}
	return subtle.ConstantTimeCompare(presented, handler.token) == 1, false
}

func (handler *Handler) admit(request *activeRequest) (bool, bool) {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if handler.closed {
		return false, true
	}
	select {
	case handler.admission <- struct{}{}:
		handler.active.Add(1)
		handler.requests[request] = struct{}{}
		return true, false
	default:
		return false, false
	}
}

func (handler *Handler) release(request *activeRequest) {
	handler.mu.Lock()
	delete(handler.requests, request)
	handler.mu.Unlock()
	<-handler.admission
	handler.active.Done()
}

func (handler *Handler) exactRoute(request *http.Request) bool {
	return request.URL != nil && request.URL.Path == handler.configuration.MCP.Path && request.URL.RawPath == "" && request.URL.RawQuery == "" && request.URL.Fragment == "" && request.URL.EscapedPath() == handler.configuration.MCP.Path
}

func (handler *Handler) newSDKHandler() http.Handler {
	server := mcpsdk.NewServer(&mcpsdk.Implementation{Name: "InboxGate", Version: handler.binaryVersion}, &mcpsdk.ServerOptions{
		Capabilities: &mcpsdk.ServerCapabilities{Tools: &mcpsdk.ToolCapabilities{}},
	})
	destructive := false
	openWorld := false
	server.AddTool(&mcpsdk.Tool{
		Name:        systemCapabilitiesTool,
		Description: "Return the current binary and configured capability registry.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false},
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: true, DestructiveHint: &destructive, IdempotentHint: true, OpenWorldHint: &openWorld},
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		_ = ctx
		data, err := renderCapabilities(handler.configuration, handler.binaryVersion, handler.binaryCommit)
		if err != nil {
			return nil, errors.New("application failure")
		}
		return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{}, StructuredContent: json.RawMessage(data)}, nil
	})
	return mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server { return server }, &mcpsdk.StreamableHTTPOptions{
		Stateless:                    true,
		JSONResponse:                 true,
		Logger:                       nil,
		EventStore:                   nil,
		MaxRequestBodyBytes:          int64(min(int(handler.configuration.Server.MaxRequestBytes), MaximumRequestBytes)),
		PropagateRequestCancellation: true,
	})
}

type renderedCapability struct {
	Name                      config.CapabilityName         `json:"name"`
	ImplementationStatus      config.ImplementationStatus   `json:"implementation_status"`
	ConfigurationStatus       config.ConfigurationStatus    `json:"configuration_status"`
	Enabled                   bool                          `json:"enabled"`
	MissingPrerequisites      []string                      `json:"missing_prerequisites"`
	RequiredSecretNames       []string                      `json:"required_secret_names"`
	RequiredDatabaseMigration *string                       `json:"required_database_migration"`
	SecurityClassification    config.SecurityClassification `json:"security_classification"`
}

type capabilityOutput struct {
	OutputVersion              uint64               `json:"output_version"`
	ProtocolVersion            string               `json:"protocol_version"`
	BinaryVersion              string               `json:"binary_version"`
	BinaryCommit               *string              `json:"binary_commit"`
	ConfigurationSchemaVersion uint64               `json:"configuration_schema_version"`
	Capabilities               []renderedCapability `json:"capabilities"`
}

func renderCapabilities(configuration config.Config, version, commit string) ([]byte, error) {
	if version == "dev" {
		if commit != "" {
			return nil, errors.New("invalid build metadata")
		}
	} else if err := buildmeta.ValidateRelease(version, commit); err != nil {
		return nil, errors.New("invalid build metadata")
	}
	registry := config.CapabilityRegistry(configuration)
	slices.SortFunc(registry, func(left, right config.Capability) int { return strings.Compare(string(left.Name), string(right.Name)) })
	output := capabilityOutput{OutputVersion: 1, ProtocolVersion: ProtocolVersion, BinaryVersion: version, ConfigurationSchemaVersion: configuration.Version, Capabilities: make([]renderedCapability, 0, len(registry))}
	if version != "dev" {
		output.BinaryCommit = &commit
	}
	for _, capability := range registry {
		missing := []string{}
		if capability.ImplementationStatus == config.ImplementationStatusNotImplemented {
			missing = append(missing, "implementation_not_available")
		}
		if capability.ConfigurationStatus == config.ConfigurationStatusDisabled {
			missing = append(missing, "disabled_by_configuration")
		}
		for _, name := range capability.RequiredSecretNames {
			if !validEnvironmentName(name) {
				return nil, errors.New("invalid capability environment name")
			}
		}
		output.Capabilities = append(output.Capabilities, renderedCapability{
			Name: capability.Name, ImplementationStatus: capability.ImplementationStatus, ConfigurationStatus: capability.ConfigurationStatus,
			Enabled: capability.Enabled, MissingPrerequisites: missing, RequiredSecretNames: append([]string{}, capability.RequiredSecretNames...),
			RequiredDatabaseMigration: capability.RequiredDatabaseMigration, SecurityClassification: capability.SecurityClassification,
		})
	}
	data, err := json.Marshal(output)
	if err != nil || len(data) > MaximumResponseBytes {
		return nil, errors.New("capability output exceeds limit")
	}
	return data, nil
}

func validEnvironmentName(value string) bool {
	return environmentNamePattern.MatchString(value)
}

func newAuditLogger(configuration config.Logging, output io.Writer) (*slog.Logger, error) {
	var level slog.Level
	switch configuration.Level {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return nil, errors.New("invalid logging level")
	}
	options := &slog.HandlerOptions{Level: level}
	if configuration.Format == "json" {
		return slog.New(slog.NewJSONHandler(output, options)), nil
	}
	if configuration.Format == "text" {
		return slog.New(slog.NewTextHandler(output, options)), nil
	}
	return nil, errors.New("invalid logging format")
}

func (handler *Handler) logAudit(operation, method string, status int, outcome string, started time.Time) {
	duration := time.Since(started).Milliseconds()
	if duration < 0 {
		duration = 0
	}
	if duration > 60_000 {
		duration = 60_000
	}
	handler.audit.Info("mcp_request", "event", "mcp_request", "operation", operation, "method", method, "status", status, "duration_ms", duration, "outcome", outcome)
}

func operationForHeaders(header http.Header) string {
	method, methodOK := singleValue(header, "Mcp-Method")
	name, nameOK := singleValue(header, "Mcp-Name")
	switch method {
	case "server/discover":
		if methodOK && !nameOK {
			return "mcp.discover"
		}
	case "tools/list":
		if methodOK && !nameOK {
			return "mcp.tools_list"
		}
	case "tools/call":
		if methodOK && nameOK && name == systemCapabilitiesTool {
			return "mcp.system_capabilities"
		}
	}
	return "mcp.other"
}

func methodClass(method string) string {
	if method == http.MethodPost {
		return "POST"
	}
	return "other"
}

func outcomeForStatus(status int) string {
	if status >= 200 && status < 300 {
		return "success"
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return "rejected"
	}
	return "failure"
}

func setSecurityHeaders(header http.Header) {
	header.Set("Content-Type", "application/json; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Content-Security-Policy", "default-src 'none'")
	header.Set("X-Frame-Options", "DENY")
}

func writeFixed(response http.ResponseWriter, head bool, status int, category, allow, authenticate string) {
	body := category + "\n"
	if allow != "" {
		response.Header().Set("Allow", allow)
	}
	if authenticate != "" {
		response.Header().Set("WWW-Authenticate", authenticate)
	}
	response.Header().Set("Content-Length", strconv.Itoa(len(body)))
	response.WriteHeader(status)
	if !head {
		_, _ = io.WriteString(response, body)
	}
}

func writeBuffered(response http.ResponseWriter, status int, body []byte) {
	response.Header().Set("Content-Length", strconv.Itoa(len(body)))
	response.WriteHeader(status)
	_, _ = response.Write(body)
}

func writeJSONRPCError(response http.ResponseWriter, status, code int, id any) {
	if code == -32700 {
		id = nil
	}
	payload := struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: id}
	payload.Error.Code = code
	payload.Error.Message = jsonRPCMessage(code)
	body, _ := json.Marshal(payload)
	writeBuffered(response, status, body)
}

func writeDiscovery(response http.ResponseWriter, status int, id any, version string) {
	payload := struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Result  struct {
			Meta struct {
				ServerInfo mcpsdk.Implementation `json:"io.modelcontextprotocol/serverInfo"`
			} `json:"_meta"`
			SupportedVersions []string `json:"supportedVersions"`
			Capabilities      struct {
				Tools struct {
					ListChanged bool `json:"listChanged"`
				} `json:"tools"`
			} `json:"capabilities"`
		} `json:"result"`
	}{JSONRPC: "2.0", ID: id}
	payload.Result.Meta.ServerInfo = mcpsdk.Implementation{Name: "InboxGate", Version: version}
	payload.Result.SupportedVersions = []string{ProtocolVersion}
	body, _ := json.Marshal(payload)
	writeBuffered(response, status, body)
}

func sdkErrorCode(body []byte) (int, bool) {
	var envelope struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Error == nil {
		return 0, false
	}
	return envelope.Error.Code, true
}

func normalizeSDKError(code int) int {
	switch code {
	case -32700, -32600, -32601, -32602, -32603, -32020:
		return code
	default:
		return -32603
	}
}

func exactContentType(header http.Header) bool {
	values := header.Values("Content-Type")
	return len(values) == 1 && values[0] == "application/json"
}

func acceptable(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if strings.TrimSpace(part) == "application/json" || strings.TrimSpace(part) == "*/*" {
				return true
			}
		}
	}
	return false
}

func forbiddenBrowserRequest(header http.Header) bool {
	if hasHeader(header, "Origin") {
		return true
	}
	for name := range header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "access-control-request-") || strings.HasPrefix(lower, "sec-fetch-") {
			return true
		}
	}
	return false
}

func validHost(host string) bool {
	if host == "" || len(host) > 263 || strings.ContainsAny(host, " ,@/?#\\") {
		return false
	}
	for index := 0; index < len(host); index++ {
		if host[index] < 0x21 || host[index] > 0x7e {
			return false
		}
	}
	hostname := host
	port := ""
	if strings.HasPrefix(host, "[") {
		closing := strings.IndexByte(host, ']')
		if closing < 0 || net.ParseIP(host[1:closing]) == nil || !strings.Contains(host[1:closing], ":") {
			return false
		}
		hostname = host[1:closing]
		suffix := host[closing+1:]
		if suffix != "" {
			if !strings.HasPrefix(suffix, ":") {
				return false
			}
			port = suffix[1:]
		}
	} else {
		if strings.ContainsAny(host, "[]") || strings.Count(host, ":") > 1 {
			return false
		}
		if before, after, found := strings.Cut(host, ":"); found {
			hostname, port = before, after
		}
		if !validHostname(hostname) {
			return false
		}
	}
	if hostname == "" || port == "" && strings.HasSuffix(host, ":") {
		return false
	}
	if port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65_535 || strconv.Itoa(value) != port {
			return false
		}
	}
	return true
}

func validHostname(hostname string) bool {
	if len(hostname) > 253 {
		return false
	}
	if parsed := net.ParseIP(hostname); parsed != nil {
		return strings.Contains(hostname, ".")
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || !asciiAlphaNumeric(label[0]) || !asciiAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for index := 1; index < len(label)-1; index++ {
			if !asciiAlphaNumeric(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func requiredRoutingHeader(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) != 1 || values[0] == "" || len(values[0]) > MaximumRoutingHeaderBytes {
		return "", false
	}
	for index := 0; index < len(values[0]); index++ {
		if values[0][index] < 0x21 || values[0][index] > 0x7e || values[0][index] == ',' {
			return "", false
		}
	}
	return values[0], true
}

func optionalRoutingHeader(header http.Header, name string) (string, bool, bool) {
	values := header.Values(name)
	if len(values) == 0 {
		return "", false, true
	}
	value, valid := requiredRoutingHeader(header, name)
	return value, true, valid
}

func singleValue(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) != 1 {
		return "", false
	}
	return values[0], true
}

func hasHeader(header http.Header, name string) bool {
	_, found := header[http.CanonicalHeaderKey(name)]
	return found
}

type responseBuffer struct {
	header   http.Header
	body     bytes.Buffer
	status   int
	limit    int
	exceeded bool
}

func newResponseBuffer(limit int) *responseBuffer {
	return &responseBuffer{header: make(http.Header), limit: limit}
}

func (buffer *responseBuffer) Header() http.Header {
	return buffer.header
}

func (buffer *responseBuffer) WriteHeader(status int) {
	if buffer.status == 0 {
		buffer.status = status
	}
}

func (buffer *responseBuffer) Write(data []byte) (int, error) {
	if buffer.status == 0 {
		buffer.status = http.StatusOK
	}
	remaining := buffer.limit - buffer.body.Len()
	if remaining < len(data) {
		buffer.exceeded = true
		if remaining > 0 {
			_, _ = buffer.body.Write(data[:remaining])
		}
		return len(data), nil
	}
	_, _ = buffer.body.Write(data)
	return len(data), nil
}
