package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
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
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"

	accountlife "github.com/mandloideep/inboxgate/internal/account"
	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/cryptobox"
	"github.com/mandloideep/inboxgate/internal/storage"
)

func TestAccountLifecycleHelpAndExactArgumentGrammar(t *testing.T) {
	for _, subcommand := range []string{"list", "pause", "resume", "revoke"} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if exit := run([]string{"account", subcommand, "--help"}, &stdout, &stderr); exit != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "account "+subcommand) {
			t.Fatalf("account %s help exit=%d stdout=%q stderr=%q", subcommand, exit, stdout.String(), stderr.String())
		}
	}
	invalid := [][]string{
		{"account", "list", "extra"},
		{"account", "pause"},
		{"account", "pause", "not-an-account"},
		{"account", "pause", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "extra"},
		{"account", "resume"},
		{"account", "revoke", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"account", "revoke", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--confirm=true"},
		{"account", "revoke", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--confirm", "extra"},
	}
	for _, args := range invalid {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if exit := run(args, &stdout, &stderr); exit != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "Usage:") {
			t.Fatalf("run(%q) exit=%d stdout=%q stderr=%q", args, exit, stdout.String(), stderr.String())
		}
	}
}

func TestAccountLifecycleDispatchLoadsConfigurationWithoutSecretArguments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	original := accountLifecycleCommand
	t.Cleanup(func() { accountLifecycleCommand = original })
	want := []struct {
		args      []string
		action    string
		accountID string
		confirmed bool
	}{
		{args: []string{"account", "list"}, action: "list"},
		{args: []string{"account", "pause", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, action: "pause", accountID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{args: []string{"account", "resume", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, action: "resume", accountID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		{args: []string{"account", "revoke", "cccccccccccccccccccccccccccccccc", "--confirm"}, action: "revoke", accountID: "cccccccccccccccccccccccccccccccc", confirmed: true},
	}
	for _, tt := range want {
		called := 0
		accountLifecycleCommand = func(configuration config.Config, action, accountID string, confirmed bool, stdout, stderr io.Writer) int {
			called++
			if action != tt.action || accountID != tt.accountID || confirmed != tt.confirmed || configuration.Database.Engine != "turso" {
				t.Fatalf("dispatch = %q %q %v", action, accountID, confirmed)
			}
			return 0
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		args := append([]string{"--config", path}, tt.args...)
		if exit := run(args, &stdout, &stderr); exit != 0 || called != 1 {
			t.Fatalf("run(%q) exit=%d called=%d stdout=%q stderr=%q", args, exit, called, stdout.String(), stderr.String())
		}
	}
}

func TestAccountListCanonicalJSONAndLifecycleCommandMessages(t *testing.T) {
	accountID, _ := storage.ParseAccountID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	version, _ := storage.ParseLifecycleVersion(2)
	fixture, err := renderAccountList([]storage.AccountSummary{{
		AccountID: accountID, Provider: storage.ProviderGmail, State: storage.AccountStateActive, StateVersion: version,
		RevocationStatus: storage.RevocationStatusNone, CursorPresent: true, CredentialPresent: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"output_version\": 1,\n  \"accounts\": [\n    {\n      \"account_id\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\n      \"provider\": \"gmail\",\n      \"state\": \"active\",\n      \"state_version\": 2,\n      \"reauthorization_reason\": null,\n      \"revocation_status\": \"none\",\n      \"cursor_present\": true,\n      \"credential_present\": true\n    }\n  ]\n}\n"
	if string(fixture) != want {
		t.Fatalf("canonical account list bytes = %q", fixture)
	}
	maximumVersion, _ := storage.ParseLifecycleVersion(int64(^uint64(0) >> 1))
	reason := storage.ReauthorizationReasonGmailUnauthorizedAfterRefresh
	maximum := make([]storage.AccountSummary, storage.MaximumAccountList)
	for index := range maximum {
		id, _ := storage.ParseAccountID(fmt.Sprintf("%032x", index+1))
		maximum[index] = storage.AccountSummary{AccountID: id, Provider: storage.ProviderGmail, State: storage.AccountStateReauthorizationRequired, StateVersion: maximumVersion, ReauthorizationReason: &reason, RevocationStatus: storage.RevocationStatusNone, CursorPresent: true, CredentialPresent: true}
	}
	maximumFixture, err := renderAccountList(maximum)
	if err != nil || len(maximumFixture) >= 64<<10 || maximumFixture[len(maximumFixture)-1] != '\n' {
		t.Fatalf("maximum canonical list bytes = %d, error = %v", len(maximumFixture), err)
	}
	if _, err := renderAccountList(append(maximum, maximum[0])); !errors.Is(err, storage.ErrResultTooLarge) {
		t.Fatalf("over-bound canonical list error = %v", err)
	}
	if accountPausedMessage != "account paused\n" || accountActiveMessage != "account active\n" || accountRevokedConfirmedMessage != "account revoked; provider revocation confirmed\n" || accountRevokedManualMessage != "account revoked locally; provider revocation requires owner action\n" {
		t.Fatal("operator messages differ from exact contract")
	}
}

func TestRunAccountLifecycleCommandsUsePinnedDriverAndFixedProviderAuthority(t *testing.T) {
	storageServer := newAccountAddProtocolServer(t)
	accountID := "abababababababababababababababab"
	providerToken := "synthetic-lifecycle-revocation-token"
	keyringText := "igk1:active=" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{73}, 32))
	ring, err := cryptobox.ParseKeyring([]byte(keyringText))
	if err != nil {
		t.Fatal(err)
	}
	envelopeText, err := ring.EncryptRefreshToken(accountID, []byte(providerToken))
	_ = ring.Close()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := storage.ParseCredentialEnvelope(envelopeText)
	if err != nil {
		t.Fatal(err)
	}
	storageServer.mu.Lock()
	storageServer.accountID = accountID
	storageServer.subject = "synthetic-lifecycle-subject"
	storageServer.historyID = "98765"
	storageServer.keyID = envelope.KeyID().String()
	storageServer.envelope = envelope.String()
	storageServer.state = "active"
	storageServer.version = 2
	storageServer.revocation = "none"
	storageServer.mu.Unlock()

	var providerRequests atomic.Int32
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		providerRequests.Add(1)
		if request.Method != http.MethodPost || request.Host != "oauth2.googleapis.com" || request.URL.Path != "/revoke" || request.URL.RawQuery != "" || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
			t.Error("revocation request escaped the fixed request shape")
		}
		body, readErr := io.ReadAll(request.Body)
		values, parseErr := url.ParseQuery(string(body))
		if readErr != nil || parseErr != nil || len(values) != 1 || len(values["token"]) != 1 || values.Get("token") != providerToken {
			t.Error("revocation request body was not exact")
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(provider.Close)
	providerTransport := provider.Client().Transport.(*http.Transport).Clone()
	providerTransport.Proxy = nil
	providerTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // Synthetic loopback certificate only.
	providerAddress := provider.Listener.Addr().String()
	providerTransport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr != nil || host != "oauth2.googleapis.com" {
			return nil, errors.New("unexpected provider authority")
		}
		return (&net.Dialer{}).DialContext(ctx, network, providerAddress)
	}
	t.Cleanup(providerTransport.CloseIdleConnections)
	originalManagerFactory := newAccountLifecycleManager
	newAccountLifecycleManager = func(handle storage.Handle, resolver func() (*cryptobox.Keyring, error)) *accountlife.Manager {
		manager := accountlife.NewWithKeyringResolver(handle, resolver)
		setSyntheticLifecycleTransport(manager, providerTransport)
		return manager
	}
	t.Cleanup(func() { newAccountLifecycleManager = originalManagerFactory })

	configurationPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configurationPath, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TURSO_DATABASE_URL", storageServer.URL)
	t.Setenv("INBOXGATE_MASTER_KEY", keyringText)
	_ = os.Unsetenv("TURSO_AUTH_TOKEN")
	originalLookup := lookupAccountEnvironment
	lookupValues := map[string]string{"TURSO_DATABASE_URL": storageServer.URL, "INBOXGATE_MASTER_KEY": keyringText}
	var lookupNames []string
	masterAfterClaim := false
	lookupAccountEnvironment = func(name string) (string, bool) {
		lookupNames = append(lookupNames, name)
		if name == "INBOXGATE_MASTER_KEY" {
			storageServer.mu.Lock()
			masterAfterClaim = storageServer.state == "revoked" && storageServer.revocation == "attempting" && storageServer.envelope != ""
			storageServer.mu.Unlock()
		}
		value, ok := lookupValues[name]
		return value, ok
	}
	t.Cleanup(func() { lookupAccountEnvironment = originalLookup })
	runCommand := func(arguments ...string) (int, string, string) {
		t.Helper()
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		args := append([]string{"--config", configurationPath, "account"}, arguments...)
		exit := run(args, &stdout, &stderr)
		return exit, stdout.String(), stderr.String()
	}

	exit, output, diagnostic := runCommand("list")
	if exit != 0 || diagnostic != "" || !strings.Contains(output, `"state": "active"`) || !strings.Contains(output, `"state_version": 2`) || !strings.Contains(output, `"credential_present": true`) {
		t.Fatalf("initial account list = exit %d, stdout %q, stderr %q", exit, output, diagnostic)
	}
	if got := strings.Join(lookupNames, ","); got != "TURSO_DATABASE_URL,TURSO_AUTH_TOKEN" {
		t.Fatalf("list environment lookups = %q", got)
	}
	lookupNames = nil
	if exit, output, diagnostic = runCommand("pause", accountID); exit != 0 || output != accountPausedMessage || diagnostic != "" {
		t.Fatalf("pause = exit %d, stdout %q, stderr %q", exit, output, diagnostic)
	}
	if got := strings.Join(lookupNames, ","); got != "TURSO_DATABASE_URL,TURSO_AUTH_TOKEN" {
		t.Fatalf("pause environment lookups = %q", got)
	}
	lookupNames = nil
	if exit, output, diagnostic = runCommand("resume", accountID); exit != 0 || output != accountActiveMessage || diagnostic != "" {
		t.Fatalf("resume = exit %d, stdout %q, stderr %q", exit, output, diagnostic)
	}
	if got := strings.Join(lookupNames, ","); got != "TURSO_DATABASE_URL,TURSO_AUTH_TOKEN" {
		t.Fatalf("resume environment lookups = %q", got)
	}
	lookupNames = nil
	if exit, output, diagnostic = runCommand("revoke", accountID, "--confirm"); exit != 0 || output != accountRevokedConfirmedMessage || diagnostic != "" {
		t.Fatalf("revoke = exit %d, stdout %q, stderr %q", exit, output, diagnostic)
	}
	if got := strings.Join(lookupNames, ","); got != "TURSO_DATABASE_URL,TURSO_AUTH_TOKEN,INBOXGATE_MASTER_KEY" || !masterAfterClaim {
		t.Fatalf("revoke environment lookups = %q, master after claim = %v", got, masterAfterClaim)
	}
	lookupNames = nil
	if exit, output, diagnostic = runCommand("list"); exit != 0 || diagnostic != "" || !strings.Contains(output, `"state": "revoked"`) || !strings.Contains(output, `"state_version": 7`) || !strings.Contains(output, `"revocation_status": "confirmed"`) || !strings.Contains(output, `"credential_present": false`) {
		t.Fatalf("final account list = exit %d, stdout %q, stderr %q", exit, output, diagnostic)
	}
	if providerRequests.Load() != 1 {
		t.Fatalf("provider requests = %d, want 1", providerRequests.Load())
	}
	storageServer.mu.Lock()
	finalState, finalVersion, finalRevocation, finalEnvelope := storageServer.state, storageServer.version, storageServer.revocation, storageServer.envelope
	storageServer.mu.Unlock()
	if finalState != "revoked" || finalVersion != 7 || finalRevocation != "confirmed" || finalEnvelope != "" {
		t.Fatal("durable lifecycle or credential deletion was incomplete")
	}
	combined := output + diagnostic + storageServer.requestText()
	for _, private := range []string{providerToken, keyringText, "synthetic-lifecycle-subject"} {
		if strings.Contains(combined, private) {
			t.Fatal("lifecycle command disclosed private provider material")
		}
	}
}

func TestRunAccountRevokeNeverResolvesMasterKeyWhenCredentialIsAbsent(t *testing.T) {
	storageServer := newAccountAddProtocolServer(t)
	accountID := "acacacacacacacacacacacacacacacac"
	storageServer.mu.Lock()
	storageServer.accountID = accountID
	storageServer.subject = "synthetic-missing-credential-subject"
	storageServer.historyID = "7"
	storageServer.state = "active"
	storageServer.version = 2
	storageServer.revocation = "none"
	storageServer.envelope = ""
	storageServer.keyID = ""
	storageServer.mu.Unlock()

	configurationPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configurationPath, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	originalLookup := lookupAccountEnvironment
	var names []string
	lookupAccountEnvironment = func(name string) (string, bool) {
		names = append(names, name)
		switch name {
		case "TURSO_DATABASE_URL":
			return storageServer.URL, true
		case "TURSO_AUTH_TOKEN":
			return "", false
		case "INBOXGATE_MASTER_KEY":
			t.Fatal("master key selector was resolved without a durable credential")
		}
		return "", false
	}
	t.Cleanup(func() { lookupAccountEnvironment = originalLookup })
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exit := run([]string{"--config", configurationPath, "account", "revoke", accountID, "--confirm"}, &stdout, &stderr)
	if exit != 1 || stdout.String() != accountRevokedManualMessage || stderr.Len() != 0 {
		t.Fatalf("missing-credential revoke = exit %d, stdout %q, stderr %q", exit, stdout.String(), stderr.String())
	}
	if got := strings.Join(names, ","); got != "TURSO_DATABASE_URL,TURSO_AUTH_TOKEN" {
		t.Fatalf("missing-credential environment lookups = %q", got)
	}
	storageServer.mu.Lock()
	state, revocation := storageServer.state, storageServer.revocation
	storageServer.mu.Unlock()
	if state != "revoked" || revocation != "manual_action_required" {
		t.Fatalf("missing-credential durable lifecycle = %s/%s", state, revocation)
	}
}

func setSyntheticLifecycleTransport(manager *accountlife.Manager, transport http.RoundTripper) {
	field := reflect.ValueOf(manager).Elem().FieldByName("transport")
	writable := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
	writable.Set(reflect.ValueOf(transport))
}
