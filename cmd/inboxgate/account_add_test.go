package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/cryptobox"
	"github.com/mandloideep/inboxgate/internal/gmail"
	"github.com/mandloideep/inboxgate/internal/storage"
)

const (
	cliAccessToken  = "cli-synthetic-access-token"
	cliRefreshToken = "cli-synthetic-refresh-token"
)

func TestAccountAddHelpAndUsage(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if exit := run([]string{"account", "add", "--help"}, &stdout, &stderr); exit != 0 {
		t.Fatalf("account add help exit = %d, stderr = %q", exit, stderr.String())
	}
	for _, required := range []string{"inboxgate [--config PATH] account add", "one authorization URL", "one-shot", "environment"} {
		if !strings.Contains(stdout.String(), required) {
			t.Fatalf("account add help missing %q: %q", required, stdout.String())
		}
	}
	for _, args := range [][]string{{"account"}, {"account", "unknown"}, {"account", "add", "extra"}, {"account", "add", "--secret=value"}} {
		stdout.Reset()
		stderr.Reset()
		if exit := run(args, &stdout, &stderr); exit != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "Usage:") {
			t.Fatalf("run(%q) exit = %d, stdout = %q, stderr = %q", args, exit, stdout.String(), stderr.String())
		}
	}
}

func TestAccountAddRejectsRemoteStorageBeforeListenerOrProvider(t *testing.T) {
	configuration := config.Defaults()
	configuration.Server.Listen = "127.0.0.1:0"
	keyring := "igk1:active=" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	for name, value := range map[string]string{
		configuration.Gmail.OAuthClientIDEnv:     "synthetic-client",
		configuration.Gmail.OAuthClientSecretEnv: "synthetic-secret",
		configuration.Gmail.OAuthRedirectURLEnv:  "https://example.test/oauth/google/callback",
		configuration.Encryption.MasterKeyEnv:    keyring,
		configuration.Database.URLEnv:            "https://database.example.test",
		configuration.Database.AuthTokenEnv:      "synthetic-database-token",
	} {
		t.Setenv(name, value)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if exit := runAccountAddCommand(configuration, &stdout, &stderr); exit != 1 || stdout.Len() != 0 || stderr.String() != "account enrollment unavailable: storage setup failed\n" {
		t.Fatalf("remote storage exit = %d, stdout = %q, stderr = %q", exit, stdout.String(), stderr.String())
	}
	for _, private := range []string{"example.test", "synthetic", keyring} {
		if strings.Contains(stdout.String()+stderr.String(), private) {
			t.Fatal("storage eligibility diagnostic disclosed private runtime data")
		}
	}
}

func TestAccountAddRejectsEveryCrossPurposeEnvironmentSelectorAliasBeforeLookup(t *testing.T) {
	const private = "SYNTHETIC_ALIASED_RUNTIME_VALUE"
	originalLookup := lookupAccountEnvironment
	lookups := 0
	lookupAccountEnvironment = func(string) (string, bool) {
		lookups++
		return private, true
	}
	t.Cleanup(func() { lookupAccountEnvironment = originalLookup })
	for first := 0; first < 6; first++ {
		for second := first + 1; second < 6; second++ {
			t.Run(fmt.Sprintf("%d_%d", first, second), func(t *testing.T) {
				configuration := config.Defaults()
				names := []*string{
					&configuration.Gmail.OAuthClientIDEnv,
					&configuration.Gmail.OAuthClientSecretEnv,
					&configuration.Gmail.OAuthRedirectURLEnv,
					&configuration.Encryption.MasterKeyEnv,
					&configuration.Database.URLEnv,
					&configuration.Database.AuthTokenEnv,
				}
				*names[second] = *names[first]
				t.Setenv(*names[first], private)
				var stdout bytes.Buffer
				var stderr bytes.Buffer
				exit := runAccountAddCommand(configuration, &stdout, &stderr)
				if exit != 1 || stdout.Len() != 0 || stderr.String() != "account enrollment unavailable: invalid runtime configuration\n" {
					t.Fatalf("alias exit = %d, stdout = %q, stderr = %q", exit, stdout.String(), stderr.String())
				}
				if strings.Contains(stdout.String()+stderr.String(), private) {
					t.Fatal("alias diagnostic disclosed selected environment value")
				}
			})
		}
	}
	if lookups != 0 {
		t.Fatalf("selector aliases caused %d environment lookups", lookups)
	}
}

func TestAccountAddLoadsConfigurationThenDispatchesWithoutSecretArguments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	original := accountAddCommand
	t.Cleanup(func() { accountAddCommand = original })
	called := 0
	accountAddCommand = func(configuration config.Config, stdout, stderr io.Writer) int {
		called++
		if configuration.Gmail.Scope != "gmail.readonly" {
			t.Fatalf("scope = %q", configuration.Gmail.Scope)
		}
		return 0
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if exit := run([]string{"--config", path, "account", "add"}, &stdout, &stderr); exit != 0 || called != 1 {
		t.Fatalf("account add exit = %d, called = %d, stdout = %q, stderr = %q", exit, called, stdout.String(), stderr.String())
	}
}

func TestOnlyAccountAddResolvesSelectedRuntimeEnvironmentValues(t *testing.T) {
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reservation.Close() })
	path := filepath.Join(t.TempDir(), "config.yaml")
	document := "version: 1\nserver:\n  listen: " + strconv.Quote(reservation.Addr().String()) + "\n"
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	originalLookup := lookupAccountEnvironment
	lookups := 0
	lookupAccountEnvironment = func(string) (string, bool) {
		lookups++
		return "SYNTHETIC_RUNTIME_VALUE", true
	}
	t.Cleanup(func() { lookupAccountEnvironment = originalLookup })
	commands := [][]string{
		{"--config", path, "config", "validate"},
		{"--config", path, "config", "effective"},
		{"--config", path, "capabilities"},
		{"--config", path, "doctor"},
		{"--config", path, "serve"},
	}
	for _, command := range commands {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		exit := run(command, &stdout, &stderr)
		if command[len(command)-1] == "serve" {
			if exit != 1 {
				t.Fatalf("serve exit = %d, stdout = %q, stderr = %q", exit, stdout.String(), stderr.String())
			}
		} else if exit != 0 {
			t.Fatalf("run(%q) exit = %d, stdout = %q, stderr = %q", command, exit, stdout.String(), stderr.String())
		}
		if lookups != 0 || strings.Contains(stdout.String()+stderr.String(), "SYNTHETIC_RUNTIME_VALUE") {
			t.Fatalf("run(%q) resolved or disclosed account enrollment environment values", command)
		}
	}
}

func TestRunAccountAddCompletesSyntheticProviderAndPinnedDriverFlow(t *testing.T) {
	storageServer := newAccountAddProtocolServer(t)
	var providerMu sync.Mutex
	providerRequests := make([]string, 0, 3)
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerMu.Lock()
		providerRequests = append(providerRequests, r.Method+" "+r.Host+r.URL.EscapedPath())
		providerMu.Unlock()
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil || r.PostForm.Get("code") != "cli-synthetic-code" || r.PostForm.Get("client_secret") != "cli-synthetic-client-secret" {
				t.Error("token exchange request was not exact")
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"access_token":%q,"refresh_token":%q,"token_type":"Bearer","expires_in":3600,"scope":"openid https://www.googleapis.com/auth/gmail.readonly"}`, cliAccessToken, cliRefreshToken)
		case "/v1/userinfo":
			if r.Header.Get("Authorization") != "Bearer "+cliAccessToken {
				t.Error("userinfo bearer token was not exact")
			}
			_, _ = io.WriteString(w, `{"sub":"cli-synthetic-subject"}`)
		case "/gmail/v1/users/me/profile":
			if r.Header.Get("Authorization") != "Bearer "+cliAccessToken {
				t.Error("profile bearer token was not exact")
			}
			_, _ = io.WriteString(w, `{"emailAddress":"cli-person@example.test","historyId":"12345"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(provider.Close)

	providerTransport := provider.Client().Transport.(*http.Transport).Clone()
	providerTransport.Proxy = nil
	providerTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // Synthetic loopback server certificate only.
	providerAddress := provider.Listener.Addr().String()
	providerTransport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		switch host {
		case "oauth2.googleapis.com", "openidconnect.googleapis.com", "gmail.googleapis.com":
			address = providerAddress
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	t.Cleanup(providerTransport.CloseIdleConnections)
	originalEnrollmentFactory := newAccountEnrollment
	newAccountEnrollment = func(clientID, clientSecret []byte, redirectURL string, handle storage.Handle, keyring *cryptobox.Keyring) (*gmail.Enrollment, error) {
		enrollment, err := gmail.New(clientID, clientSecret, redirectURL, handle, keyring)
		if err != nil {
			return nil, err
		}
		setSyntheticEnrollmentTransport(enrollment, func() *http.Transport { return providerTransport.Clone() })
		return enrollment, nil
	}
	t.Cleanup(func() { newAccountEnrollment = originalEnrollmentFactory })

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var listenerOnce sync.Once
	t.Cleanup(func() { listenerOnce.Do(func() { _ = listener.Close() }) })
	originalListen := accountAddListen
	accountAddListen = func(network, address string) (net.Listener, error) {
		if network != "tcp" || address != listener.Addr().String() {
			return nil, errors.New("unexpected callback listener request")
		}
		return listener, nil
	}
	t.Cleanup(func() { accountAddListen = originalListen })

	configurationPath := filepath.Join(t.TempDir(), "config.yaml")
	configurationDocument := "version: 1\nserver:\n  listen: " + strconv.Quote(listener.Addr().String()) + "\n"
	if err := os.WriteFile(configurationPath, []byte(configurationDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	keyring := "igk1:active=" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{51}, 32))
	for name, value := range map[string]string{
		"GOOGLE_OAUTH_CLIENT_ID":     "cli-synthetic-client-id",
		"GOOGLE_OAUTH_CLIENT_SECRET": "cli-synthetic-client-secret",
		"GOOGLE_OAUTH_REDIRECT_URL":  "http://" + listener.Addr().String() + "/oauth/google/callback",
		"INBOXGATE_MASTER_KEY":       keyring,
		"TURSO_DATABASE_URL":         storageServer.URL,
	} {
		t.Setenv(name, value)
	}
	_ = os.Unsetenv("TURSO_AUTH_TOKEN")
	output := newSignaledWriter()
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- run([]string{"--config", configurationPath, "account", "add"}, output, &stderr) }()
	authorizationLine := output.next(t)
	authorizationURL, err := url.Parse(strings.TrimSpace(authorizationLine))
	if err != nil || authorizationURL.Host != "accounts.google.com" {
		t.Fatalf("authorization URL = %q, error = %v", authorizationLine, err)
	}
	callback := "http://" + listener.Addr().String() + "/oauth/google/callback?code=cli-synthetic-code&state=" + url.QueryEscape(authorizationURL.Query().Get("state"))
	response, err := http.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("callback status = %d, authorization URL = %q", response.StatusCode, authorizationLine)
	}
	select {
	case exit := <-done:
		if exit != 0 {
			providerMu.Lock()
			gotProvider := append([]string(nil), providerRequests...)
			providerMu.Unlock()
			t.Fatalf("account add exit = %d, stderr = %q, provider requests = %#v, storage categories = %s", exit, stderr.String(), gotProvider, storageServer.categoryText())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("account add did not finish")
	}
	stdout := output.String()
	if !strings.HasSuffix(stdout, "account enrolled\n") || stderr.Len() != 0 {
		t.Fatalf("stdout = %q, stderr = %q", stdout, stderr.String())
	}
	providerMu.Lock()
	gotProvider := append([]string(nil), providerRequests...)
	providerMu.Unlock()
	wantProvider := []string{"POST oauth2.googleapis.com/token", "GET openidconnect.googleapis.com/v1/userinfo", "GET gmail.googleapis.com/gmail/v1/users/me/profile"}
	if fmt.Sprint(gotProvider) != fmt.Sprint(wantProvider) {
		t.Fatalf("provider requests = %#v, want %#v", gotProvider, wantProvider)
	}
	storageServer.assertComplete(t)
	for _, private := range []string{"cli-synthetic-client-secret", cliAccessToken, cliRefreshToken, keyring, "cli-synthetic-subject", "cli-person@example.test"} {
		if strings.Contains(stdout+stderr.String(), private) {
			t.Fatal("command output disclosed private provider data")
		}
	}
	for _, secret := range []string{"cli-synthetic-client-secret", cliAccessToken, cliRefreshToken, keyring, "cli-person@example.test"} {
		if strings.Contains(storageServer.requestText(), secret) {
			t.Fatal("storage wire disclosed a provider secret or profile address")
		}
	}
}

type signaledWriter struct {
	mu    sync.Mutex
	data  bytes.Buffer
	lines chan string
}

func newSignaledWriter() *signaledWriter { return &signaledWriter{lines: make(chan string, 4)} }

func (w *signaledWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	_, _ = w.data.Write(data)
	w.mu.Unlock()
	select {
	case w.lines <- string(append([]byte(nil), data...)):
	default:
	}
	return len(data), nil
}

func (w *signaledWriter) next(t *testing.T) string {
	t.Helper()
	select {
	case line := <-w.lines:
		return line
	case <-time.After(time.Second):
		t.Fatal("command did not write authorization URL")
		return ""
	}
}

func (w *signaledWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.data.String()
}

type accountAddProtocolServer struct {
	*httptest.Server
	mu         sync.Mutex
	accountID  string
	subject    string
	historyID  string
	keyID      string
	envelope   string
	requests   []string
	categories []string
}

type accountAddProtocolValue struct {
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

func newAccountAddProtocolServer(t *testing.T) *accountAddProtocolServer {
	t.Helper()
	server := &accountAddProtocolServer{}
	server.Server = httptest.NewServer(http.HandlerFunc(server.serveHTTP))
	t.Cleanup(server.Close)
	return server
}

func (s *accountAddProtocolServer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	s.mu.Lock()
	s.requests = append(s.requests, string(body))
	s.mu.Unlock()
	if r.URL.Path == "/v3/pipeline" {
		var request struct {
			Requests []struct {
				Type string `json:"type"`
			} `json:"requests"`
		}
		_ = json.Unmarshal(body, &request)
		results := make([]any, len(request.Requests))
		for index, item := range request.Requests {
			response := map[string]any{"type": item.Type}
			if item.Type == "get_autocommit" {
				response["is_autocommit"] = true
			}
			results[index] = map[string]any{"type": "ok", "response": response}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"baton": "cli-baton", "base_url": nil, "results": results})
		return
	}
	if r.URL.Path != "/v3/cursor" {
		http.NotFound(w, r)
		return
	}
	var request struct {
		Batch struct {
			Steps []struct {
				Stmt struct {
					SQL  string                    `json:"sql"`
					Args []accountAddProtocolValue `json:"args"`
				} `json:"stmt"`
			} `json:"steps"`
		} `json:"batch"`
	}
	if json.Unmarshal(body, &request) != nil || len(request.Batch.Steps) == 0 {
		http.Error(w, "invalid", http.StatusBadRequest)
		return
	}
	statement := request.Batch.Steps[0].Stmt
	args := make([]string, len(statement.Args))
	for index, argument := range statement.Args {
		if argument.Type != "null" {
			_ = json.Unmarshal(argument.Value, &args[index])
		}
	}
	rows, columns, affected, category := s.execute(statement.SQL, args)
	s.mu.Lock()
	s.categories = append(s.categories, category)
	s.mu.Unlock()
	encoder := json.NewEncoder(w)
	_ = encoder.Encode(map[string]any{"baton": "cli-baton", "base_url": nil})
	_ = encoder.Encode(map[string]any{"type": "step_begin", "step": 0, "cols": columns})
	for _, row := range rows {
		_ = encoder.Encode(map[string]any{"type": "row", "row": row})
	}
	_ = encoder.Encode(map[string]any{"type": "step_end", "step": 0, "affected_row_count": affected})
	_ = encoder.Encode(map[string]any{"type": "step_begin", "step": 1, "cols": []any{}})
	_ = encoder.Encode(map[string]any{"type": "step_end", "step": 1})
}

func (s *accountAddProtocolServer) execute(statement string, args []string) ([][]any, []any, int64, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case strings.HasPrefix(statement, "WITH input(account_id, provider, provider_subject)"):
		row := []any{cliInteger(1), cliInteger(0), cliNull(), cliNull(), cliNull(), cliInteger(0), cliNull(), cliNull(), cliNull()}
		if s.accountID != "" {
			row = []any{cliInteger(1), cliInteger(1), cliText(s.accountID), cliText("gmail"), cliText(s.subject), cliInteger(1), cliText(s.accountID), cliText("gmail"), cliText(s.subject)}
		}
		return [][]any{row}, cliColumns("sentinel", "id_count", "id_account_id", "id_provider", "id_subject", "subject_count", "subject_account_id", "subject_provider", "subject"), 0, "account_lookup"
	case strings.HasPrefix(statement, "INSERT INTO inboxgate_accounts"):
		s.accountID, s.subject = args[0], args[1]
		return nil, nil, 1, "account_insert"
	case strings.Contains(statement, "cursor_match AS"):
		row := []any{cliInteger(1), cliInteger(1), cliText(s.accountID), cliInteger(0), cliNull(), cliNull()}
		if s.historyID != "" {
			row[3], row[4], row[5] = cliInteger(1), cliText(s.accountID), cliText(s.historyID)
		}
		return [][]any{row}, cliColumns("sentinel", "account_count", "account_id", "cursor_count", "cursor_account_id", "history_id"), 0, "cursor_lookup"
	case strings.HasPrefix(statement, "INSERT INTO inboxgate_synchronization_cursors"):
		s.historyID = args[1]
		return nil, nil, 1, "cursor_insert"
	case strings.Contains(statement, "credential_match AS"):
		row := []any{cliInteger(1), cliInteger(1), cliText(s.accountID), cliInteger(0), cliNull(), cliNull(), cliNull()}
		if s.envelope != "" {
			row[3], row[4], row[5], row[6] = cliInteger(1), cliText(s.accountID), cliText(s.keyID), cliText(s.envelope)
		}
		return [][]any{row}, cliColumns("sentinel", "account_count", "account_id", "credential_count", "credential_account_id", "key_id", "envelope"), 0, "credential_lookup"
	case strings.HasPrefix(statement, "INSERT INTO inboxgate_provider_credentials"):
		s.keyID, s.envelope = args[1], args[2]
		return nil, nil, 1, "credential_insert"
	default:
		return nil, nil, 0, "unexpected"
	}
}

func (s *accountAddProtocolServer) assertComplete(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	want := []string{"account_lookup", "account_insert", "account_lookup", "cursor_lookup", "credential_lookup", "cursor_lookup", "cursor_insert", "cursor_lookup", "credential_lookup", "credential_insert", "credential_lookup", "account_lookup", "cursor_lookup", "credential_lookup"}
	if fmt.Sprint(s.categories) != fmt.Sprint(want) {
		t.Fatalf("storage SQL sequence = %#v, want %#v", s.categories, want)
	}
	if s.accountID == "" || s.subject != "cli-synthetic-subject" || s.historyID != "12345" || s.keyID != "active" || s.envelope == "" || strings.Contains(s.envelope, cliRefreshToken) {
		t.Fatal("durable synthetic account, cursor, or ciphertext state is incomplete")
	}
}

func (s *accountAddProtocolServer) requestText() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.requests, "\n")
}

func (s *accountAddProtocolServer) categoryText() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fmt.Sprint(s.categories)
}

func cliColumns(names ...string) []any {
	columns := make([]any, len(names))
	for index, name := range names {
		columns[index] = map[string]any{"name": name, "decltype": "TEXT"}
	}
	return columns
}

func cliInteger(value int64) map[string]any {
	return map[string]any{"type": "integer", "value": strconv.FormatInt(value, 10)}
}
func cliText(value string) map[string]any { return map[string]any{"type": "text", "value": value} }
func cliNull() map[string]any             { return map[string]any{"type": "null"} }

func setSyntheticEnrollmentTransport(enrollment *gmail.Enrollment, factory func() *http.Transport) {
	field := reflect.ValueOf(enrollment).Elem().FieldByName("transport")
	writable := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
	writable.Set(reflect.ValueOf(factory))
}
