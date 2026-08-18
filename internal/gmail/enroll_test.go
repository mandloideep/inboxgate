package gmail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/cryptobox"
	"github.com/mandloideep/inboxgate/internal/storage"
	storagefake "github.com/mandloideep/inboxgate/internal/storage/fake"
)

const (
	syntheticClientID     = "synthetic-client-id"
	syntheticClientSecret = "synthetic-client-secret"
	syntheticCode         = "synthetic-authorization-code"
	syntheticAccessToken  = "synthetic-access-token"
	syntheticRefreshToken = "synthetic-refresh-token"
	syntheticSubject      = "synthetic-subject"
	syntheticEmail        = "person@example.test"
	syntheticHistoryID    = "18446744073709551615"
)

func TestEnrollmentConfigurationAndCallbackAdjacentBounds(t *testing.T) {
	redirectPrefix := "https://"
	redirectSuffix := callbackPath
	maximumRedirect := redirectPrefix + strings.Repeat("r", 2048-len(redirectPrefix)-len(redirectSuffix)) + redirectSuffix
	base := enrollmentOptions{clientID: bytes.Repeat([]byte{'i'}, 512), clientSecret: bytes.Repeat([]byte{'s'}, 512), redirectURL: maximumRedirect, store: storagefake.New(), keyring: syntheticKeyring(t)}
	if _, err := newEnrollment(base, enrollmentDependencies{}); err != nil {
		t.Fatalf("maximum enrollment configuration error = %v", err)
	}
	for _, mutate := range []func(*enrollmentOptions){
		func(options *enrollmentOptions) { options.clientID = bytes.Repeat([]byte{'i'}, 513) },
		func(options *enrollmentOptions) { options.clientSecret = bytes.Repeat([]byte{'s'}, 513) },
		func(options *enrollmentOptions) { options.redirectURL = maximumRedirect + "x" },
		func(options *enrollmentOptions) { options.redirectURL = "http://example.test" + callbackPath },
	} {
		options := base
		mutate(&options)
		if _, err := newEnrollment(options, enrollmentDependencies{}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("out-of-bound configuration error = %v", err)
		}
	}

	for _, extra := range []int{0, 1} {
		enrollment := newTestEnrollment(t, enrollmentOptions{clientID: []byte(syntheticClientID), clientSecret: []byte(syntheticClientSecret), redirectURL: "http://127.0.0.1:8080" + callbackPath, store: storagefake.New(), keyring: syntheticKeyring(t)}, enrollmentDependencies{random: bytes.NewReader(append(bytes.Repeat([]byte{36 + byte(extra)}, 32), bytes.Repeat([]byte{38 + byte(extra)}, 32)...)), now: fixedNow})
		attempt, err := enrollment.beginAuthorization()
		if err != nil {
			t.Fatal(err)
		}
		prefix := callbackPath + "?code="
		suffix := "&state=" + attempt.state
		code := strings.Repeat("c", 4096-len(prefix)-len(suffix)+extra)
		response := httptest.NewRecorder()
		enrollment.callbackHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, prefix+code+suffix, nil))
		want := http.StatusOK
		if extra == 1 {
			want = http.StatusBadRequest
		}
		if response.Code != want {
			t.Fatalf("callback target extra %d status = %d, want %d", extra, response.Code, want)
		}
	}
}

func TestAuthorizationRequestIsExactAndRandomValuesAreIndependent(t *testing.T) {
	listener := listenLoopback(t)
	redirect := "http://" + listener.Addr().String() + callbackPath
	random := append(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)...)
	enrollment := newTestEnrollment(t, enrollmentOptions{clientID: []byte(syntheticClientID), clientSecret: []byte(syntheticClientSecret), redirectURL: redirect, store: storagefake.New(), keyring: syntheticKeyring(t)}, enrollmentDependencies{random: bytes.NewReader(random), now: fixedNow})
	attempt, err := enrollment.beginAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(attempt.url)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != productionAuthorizationEndpoint {
		t.Fatalf("authorization endpoint = %q", parsed.Scheme+"://"+parsed.Host+parsed.Path)
	}
	state := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	verifier := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	challengeBytes := sha256.Sum256([]byte(verifier))
	want := url.Values{
		"access_type":           {"offline"},
		"client_id":             {syntheticClientID},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challengeBytes[:])},
		"code_challenge_method": {"S256"},
		"prompt":                {"consent select_account"},
		"redirect_uri":          {redirect},
		"response_type":         {"code"},
		"scope":                 {requestedScope},
		"state":                 {state},
	}
	if parsed.Query().Encode() != want.Encode() || attempt.state != state || attempt.verifier != verifier || attempt.state == attempt.verifier {
		t.Fatalf("authorization query = %q, want %q", parsed.Query().Encode(), want.Encode())
	}
	if _, err := enrollment.beginAuthorization(); !errors.Is(err, ErrBusy) {
		t.Fatalf("second begin error = %v, want ErrBusy", err)
	}
}

func TestCallbackRejectsInvalidRequestsWithoutConsumingMatchingAttempt(t *testing.T) {
	now := fixedNow()
	enrollment := newTestEnrollment(t, enrollmentOptions{clientID: []byte(syntheticClientID), clientSecret: []byte(syntheticClientSecret), redirectURL: "http://127.0.0.1:8080" + callbackPath, store: storagefake.New(), keyring: syntheticKeyring(t)}, enrollmentDependencies{random: bytes.NewReader(append(bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32)...)), now: func() time.Time { return now }})
	attempt, err := enrollment.beginAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		method string
		target string
		body   string
	}{
		{name: "method", method: http.MethodPost, target: callbackPath + "?code=x&state=" + attempt.state},
		{name: "path", method: http.MethodGet, target: "/oauth/google/other?code=x&state=" + attempt.state},
		{name: "body", method: http.MethodGet, target: callbackPath + "?code=x&state=" + attempt.state, body: "x"},
		{name: "unknown", method: http.MethodGet, target: callbackPath + "?code=x&state=" + attempt.state + "&extra=x"},
		{name: "duplicate", method: http.MethodGet, target: callbackPath + "?code=x&code=y&state=" + attempt.state},
		{name: "mixed", method: http.MethodGet, target: callbackPath + "?code=x&error=denied&state=" + attempt.state},
		{name: "empty", method: http.MethodGet, target: callbackPath + "?code=&state=" + attempt.state},
		{name: "missing", method: http.MethodGet, target: callbackPath + "?code=x"},
		{name: "mismatch", method: http.MethodGet, target: callbackPath + "?code=x&state=" + strings.Repeat("A", 43)},
		{name: "oversized code", method: http.MethodGet, target: callbackPath + "?code=" + strings.Repeat("a", 4097) + "&state=" + attempt.state},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(tt.method, tt.target, strings.NewReader(tt.body))
			response := httptest.NewRecorder()
			enrollment.callbackHandler().ServeHTTP(response, request)
			if response.Code == http.StatusOK || response.Body.Len() > 256 {
				t.Fatalf("callback status = %d, body bytes = %d", response.Code, response.Body.Len())
			}
			assertCallbackHeaders(t, response.Header())
			for _, secret := range []string{attempt.state, syntheticCode, syntheticSubject, syntheticEmail} {
				if strings.Contains(response.Body.String(), secret) || headerContains(response.Header(), secret) {
					t.Fatal("callback response disclosed synthetic private data")
				}
			}
		})
	}
	valid := httptest.NewRequest(http.MethodGet, callbackPath+"?code="+syntheticCode+"&state="+attempt.state, nil)
	response := httptest.NewRecorder()
	enrollment.callbackHandler().ServeHTTP(response, valid)
	if response.Code != http.StatusOK {
		t.Fatalf("valid callback status = %d", response.Code)
	}
	result := <-attempt.result
	if result.code != syntheticCode || result.err != nil {
		t.Fatalf("callback result = %#v", result)
	}
	reused := httptest.NewRecorder()
	enrollment.callbackHandler().ServeHTTP(reused, valid)
	if reused.Code == http.StatusOK {
		t.Fatal("reused callback succeeded")
	}
}

func TestCallbackRejectsUnknownLengthBodyWithoutConsumingAttempt(t *testing.T) {
	enrollment := newTestEnrollment(t, enrollmentOptions{clientID: []byte(syntheticClientID), clientSecret: []byte(syntheticClientSecret), redirectURL: "http://127.0.0.1:8080" + callbackPath, store: storagefake.New(), keyring: syntheticKeyring(t)}, enrollmentDependencies{random: bytes.NewReader(append(bytes.Repeat([]byte{21}, 32), bytes.Repeat([]byte{22}, 32)...)), now: fixedNow})
	attempt, err := enrollment.beginAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	target := callbackPath + "?code=" + syntheticCode + "&state=" + attempt.state
	request := httptest.NewRequest(http.MethodGet, target, io.NopCloser(strings.NewReader("x")))
	request.ContentLength = -1
	response := httptest.NewRecorder()
	enrollment.callbackHandler().ServeHTTP(response, request)
	if response.Code == http.StatusOK || len(attempt.result) != 0 {
		t.Fatalf("unknown-length callback status = %d, queued results = %d", response.Code, len(attempt.result))
	}
	valid := httptest.NewRecorder()
	enrollment.callbackHandler().ServeHTTP(valid, httptest.NewRequest(http.MethodGet, target, nil))
	if valid.Code != http.StatusOK || len(attempt.result) != 1 {
		t.Fatalf("valid callback status = %d, queued results = %d", valid.Code, len(attempt.result))
	}
}

func TestEnrollmentAttemptExpiresWithoutCallbackOrProviderWork(t *testing.T) {
	listener := listenLoopback(t)
	expires := make(chan time.Time, 1)
	store := &observedStore{Handle: storagefake.New()}
	enrollment := newTestEnrollment(t, enrollmentOptions{clientID: []byte(syntheticClientID), clientSecret: []byte(syntheticClientSecret), redirectURL: "http://" + listener.Addr().String() + callbackPath, store: store, keyring: syntheticKeyring(t)}, enrollmentDependencies{random: bytes.NewReader(append(bytes.Repeat([]byte{23}, 32), bytes.Repeat([]byte{24}, 32)...)), now: fixedNow, after: func(duration time.Duration) <-chan time.Time {
		if duration != attemptLifetime {
			t.Fatalf("expiry duration = %v, want %v", duration, attemptLifetime)
		}
		return expires
	}})
	lines := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- enrollment.run(context.Background(), listener, channelWriter{lines: lines}) }()
	select {
	case <-lines:
	case <-time.After(time.Second):
		t.Fatal("authorization URL was not written")
	}
	expires <- fixedNow().Add(attemptLifetime)
	select {
	case err := <-done:
		if !errors.Is(err, ErrCallback) || err.Error() != ErrCallback.Error() {
			t.Fatalf("expiry error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("expired enrollment did not return")
	}
	enrollment.mu.Lock()
	pending := enrollment.pending
	enrollment.mu.Unlock()
	if pending != nil || store.calls != 0 {
		t.Fatalf("expiry left pending attempt or used storage: pending=%v calls=%d", pending != nil, store.calls)
	}
	connection, err := net.DialTimeout("tcp", listener.Addr().String(), 100*time.Millisecond)
	if err == nil {
		_ = connection.Close()
		t.Fatal("callback listener remained open after expiry")
	}
}

func TestConsumedCallbackWinsWhenAttemptTimerIsAlsoReady(t *testing.T) {
	listener := listenLoopback(t)
	expires := make(chan time.Time, 1)
	afterEntered := make(chan struct{})
	releaseAfter := make(chan struct{})
	enrollment := newTestEnrollment(t, enrollmentOptions{clientID: []byte(syntheticClientID), clientSecret: []byte(syntheticClientSecret), redirectURL: "http://" + listener.Addr().String() + callbackPath, store: storagefake.New(), keyring: syntheticKeyring(t)}, enrollmentDependencies{random: bytes.NewReader(append(bytes.Repeat([]byte{25}, 32), bytes.Repeat([]byte{26}, 32)...)), now: fixedNow, after: func(duration time.Duration) <-chan time.Time {
		if duration != attemptLifetime {
			t.Fatalf("expiry duration = %v", duration)
		}
		close(afterEntered)
		<-releaseAfter
		return expires
	}})
	lines := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- enrollment.run(context.Background(), listener, channelWriter{lines: lines}) }()
	authorizationLine := <-lines
	parsed, err := url.Parse(strings.TrimSpace(authorizationLine))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-afterEntered:
	case <-time.After(time.Second):
		t.Fatal("run did not reach synchronized timer boundary")
	}
	callback := "http://" + listener.Addr().String() + callbackPath + "?error=access_denied&state=" + url.QueryEscape(parsed.Query().Get("state"))
	response, err := http.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("callback status = %d", response.StatusCode)
	}
	expires <- fixedNow().Add(attemptLifetime)
	close(releaseAfter)
	select {
	case err := <-done:
		if !errors.Is(err, ErrDenied) || errors.Is(err, ErrCallback) {
			t.Fatalf("simultaneous callback and expiry error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("simultaneous callback and expiry did not finish")
	}
}

func TestMatchingDenialAndExpiryConsumeAttempt(t *testing.T) {
	for _, test := range []struct {
		name    string
		advance time.Duration
		query   func(string) string
	}{
		{name: "denial", query: func(state string) string { return "error=access_denied&state=" + state }},
		{name: "expired", advance: 10*time.Minute + time.Nanosecond, query: func(state string) string { return "code=x&state=" + state }},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := fixedNow()
			enrollment := newTestEnrollment(t, enrollmentOptions{clientID: []byte(syntheticClientID), clientSecret: []byte(syntheticClientSecret), redirectURL: "http://127.0.0.1:8080" + callbackPath, store: storagefake.New(), keyring: syntheticKeyring(t)}, enrollmentDependencies{random: bytes.NewReader(append(bytes.Repeat([]byte{5}, 32), bytes.Repeat([]byte{6}, 32)...)), now: func() time.Time { return now }})
			attempt, err := enrollment.beginAuthorization()
			if err != nil {
				t.Fatal(err)
			}
			now = now.Add(test.advance)
			response := httptest.NewRecorder()
			enrollment.callbackHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, callbackPath+"?"+test.query(attempt.state), nil))
			if response.Code == http.StatusOK && test.name == "expired" {
				t.Fatal("expired callback succeeded")
			}
			select {
			case result := <-attempt.result:
				if result.err == nil {
					t.Fatal("consuming callback has nil error")
				}
			case <-time.After(time.Second):
				t.Fatal("consuming callback did not queue result")
			}
		})
	}
}

func TestSyntheticEnrollmentUsesExactProviderWireAndPersistsEncryptedCredential(t *testing.T) {
	var mu sync.Mutex
	requests := make([]string, 0, 3)
	var tokenForm url.Values
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.EscapedPath())
		mu.Unlock()
		switch r.URL.Path {
		case "/token":
			if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Authorization") != "" {
				t.Error("token request used wrong content type or authorization header")
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			tokenForm = r.PostForm
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"access_token":%q,"refresh_token":%q,"token_type":"Bearer","expires_in":3600,"scope":%q}`, syntheticAccessToken, syntheticRefreshToken, requestedScope)
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer "+syntheticAccessToken || r.ContentLength > 0 {
				t.Error("userinfo request contract violated")
			}
			fmt.Fprintf(w, `{"sub":%q}`, syntheticSubject)
		case "/gmail/v1/users/me/profile":
			if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+syntheticAccessToken || r.ContentLength > 0 {
				t.Error("Gmail profile request contract violated")
			}
			fmt.Fprintf(w, `{"emailAddress":%q,"historyId":%q,"messagesTotal":1,"threadsTotal":1}`, syntheticEmail, syntheticHistoryID)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(provider.Close)
	listener := listenLoopback(t)
	redirect := "http://" + listener.Addr().String() + callbackPath
	store := storagefake.New()
	ring := syntheticKeyring(t)
	randomBytes := append(bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{8}, 32)...)
	randomBytes = append(randomBytes, bytes.Repeat([]byte{9}, 16)...)
	transportCalls := 0
	enrollment := newTestEnrollment(t, enrollmentOptions{clientID: []byte(syntheticClientID), clientSecret: []byte(syntheticClientSecret), redirectURL: redirect, store: store, keyring: ring}, enrollmentDependencies{endpoints: providerEndpoints{authorization: provider.URL + "/authorize", token: provider.URL + "/token", userInfo: provider.URL + "/userinfo", gmailProfile: provider.URL + "/gmail/v1/users/me/profile"}, random: bytes.NewReader(randomBytes), now: fixedNow, transport: func() *http.Transport {
		transportCalls++
		return productionHTTPTransport()
	}})
	lines := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- enrollment.run(context.Background(), listener, channelWriter{lines: lines}) }()
	authorizationURL := <-lines
	parsed, err := url.Parse(strings.TrimSpace(authorizationURL))
	if err != nil {
		t.Fatal(err)
	}
	callbackURL := redirect + "?code=" + syntheticCode + "&state=" + parsed.Query().Get("state")
	response, err := http.Get(callbackURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if err := <-done; err != nil {
		t.Fatalf("enrollment run error = %v", err)
	}
	if transportCalls != 1 {
		t.Fatalf("private transport factory calls = %d, want 1", transportCalls)
	}
	if got := requests; len(got) != 3 || got[0] != "POST /token" || got[1] != "GET /userinfo" || got[2] != "GET /gmail/v1/users/me/profile" {
		t.Fatalf("provider requests = %#v", got)
	}
	verifier := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
	wantTokenForm := url.Values{"client_id": {syntheticClientID}, "client_secret": {syntheticClientSecret}, "code": {syntheticCode}, "code_verifier": {verifier}, "grant_type": {"authorization_code"}, "redirect_uri": {redirect}}
	if tokenForm.Encode() != wantTokenForm.Encode() {
		t.Fatalf("token form = %q, want %q", tokenForm.Encode(), wantTokenForm.Encode())
	}
	accountText := hex.EncodeToString(bytes.Repeat([]byte{9}, 16))
	accountID, _ := storage.ParseAccountID(accountText)
	cursor, err := store.GetSynchronizationCursor(context.Background(), accountID)
	if err != nil || cursor.HistoryID.String() != syntheticHistoryID {
		t.Fatalf("durable cursor = %#v, error = %v", cursor, err)
	}
	credential, err := store.GetProviderCredential(context.Background(), accountID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(credential.Envelope.String(), syntheticRefreshToken) {
		t.Fatal("durable credential contains plaintext")
	}
	plaintext, err := ring.DecryptRefreshToken(accountText, credential.Envelope.String())
	if err != nil || string(plaintext) != syntheticRefreshToken {
		t.Fatalf("durable credential authentication failed: %v", err)
	}
	clear(plaintext)
}

func TestTokenExchangeResponseMatrixIsStrictBoundedAndNeverRetried(t *testing.T) {
	validJSON := func(scope, access, refresh string, expiry int) string {
		return fmt.Sprintf(`{"access_token":%q,"refresh_token":%q,"token_type":"Bearer","expires_in":%d,"scope":%q}`, access, refresh, expiry, scope)
	}
	maximumBody := validJSON(requestedScope, syntheticAccessToken, syntheticRefreshToken, 3600)
	maximumPrefix := strings.TrimSuffix(maximumBody, "}") + `,"padding":"`
	maximumSuffix := `"}`
	maximumBody = maximumPrefix + strings.Repeat("x", maximumProviderBodyBytes-len(maximumPrefix)-len(maximumSuffix)) + maximumSuffix
	if len(maximumBody) != maximumProviderBodyBytes {
		t.Fatalf("maximum token fixture bytes = %d", len(maximumBody))
	}
	tests := []struct {
		name        string
		contentType string
		body        string
		status      int
		wantSuccess bool
	}{
		{name: "json exact scope", contentType: "application/json", body: validJSON(requestedScope, syntheticAccessToken, syntheticRefreshToken, 3600), wantSuccess: true},
		{name: "json reordered scope", contentType: "application/json", body: validJSON("https://www.googleapis.com/auth/gmail.readonly openid", syntheticAccessToken, syntheticRefreshToken, 3600), wantSuccess: true},
		{name: "form exact scope", contentType: "application/x-www-form-urlencoded", body: url.Values{"access_token": {syntheticAccessToken}, "refresh_token": {syntheticRefreshToken}, "token_type": {"Bearer"}, "expires_in": {"3600"}, "scope": {requestedScope}}.Encode(), wantSuccess: true},
		{name: "maximum body", contentType: "application/json", body: maximumBody, wantSuccess: true},
		{name: "maximum tokens", contentType: "application/json", body: validJSON(requestedScope, strings.Repeat("a", 4096), strings.Repeat("r", 4096), 3600), wantSuccess: true},
		{name: "oversized body", contentType: "application/json", body: maximumBody + "x"},
		{name: "missing scope", contentType: "application/json", body: validJSON("", syntheticAccessToken, syntheticRefreshToken, 3600)},
		{name: "partial scope", contentType: "application/json", body: validJSON("openid", syntheticAccessToken, syntheticRefreshToken, 3600)},
		{name: "additional scope", contentType: "application/json", body: validJSON(requestedScope+" profile", syntheticAccessToken, syntheticRefreshToken, 3600)},
		{name: "duplicate scope value", contentType: "application/json", body: validJSON(requestedScope+" openid", syntheticAccessToken, syntheticRefreshToken, 3600)},
		{name: "wrong token type", contentType: "application/json", body: strings.Replace(validJSON(requestedScope, syntheticAccessToken, syntheticRefreshToken, 3600), `"Bearer"`, `"bearer"`, 1)},
		{name: "zero expiry", contentType: "application/json", body: validJSON(requestedScope, syntheticAccessToken, syntheticRefreshToken, 0)},
		{name: "excess expiry", contentType: "application/json", body: validJSON(requestedScope, syntheticAccessToken, syntheticRefreshToken, 86401)},
		{name: "missing access", contentType: "application/json", body: validJSON(requestedScope, "", syntheticRefreshToken, 3600)},
		{name: "oversized access", contentType: "application/json", body: validJSON(requestedScope, strings.Repeat("a", 4097), syntheticRefreshToken, 3600)},
		{name: "missing refresh", contentType: "application/json", body: validJSON(requestedScope, syntheticAccessToken, "", 3600)},
		{name: "oversized refresh", contentType: "application/json", body: validJSON(requestedScope, syntheticAccessToken, strings.Repeat("r", 4097), 3600)},
		{name: "malformed", contentType: "application/json", body: "{"},
		{name: "trailing", contentType: "application/json", body: validJSON(requestedScope, syntheticAccessToken, syntheticRefreshToken, 3600) + "{}"},
		{name: "unexpected encoding", contentType: "application/octet-stream", body: validJSON(requestedScope, syntheticAccessToken, syntheticRefreshToken, 3600)},
		{name: "status", contentType: "application/json", status: http.StatusBadGateway, body: "private token fault"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				switch r.URL.Path {
				case "/token":
					w.Header().Set("Content-Type", test.contentType)
					status := test.status
					if status == 0 {
						status = http.StatusOK
					}
					w.WriteHeader(status)
					_, _ = io.WriteString(w, test.body)
				case "/userinfo":
					fmt.Fprintf(w, `{"sub":%q}`, syntheticSubject)
				case "/profile":
					fmt.Fprintf(w, `{"emailAddress":%q,"historyId":"91"}`, syntheticEmail)
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(provider.Close)
			enrollment := newTestEnrollment(t, enrollmentOptions{clientID: []byte(syntheticClientID), clientSecret: []byte(syntheticClientSecret), redirectURL: "http://127.0.0.1:8080" + callbackPath, store: storagefake.New(), keyring: syntheticKeyring(t)}, enrollmentDependencies{endpoints: providerEndpoints{authorization: provider.URL + "/authorize", token: provider.URL + "/token", userInfo: provider.URL + "/userinfo", gmailProfile: provider.URL + "/profile"}, random: bytes.NewReader(bytes.Repeat([]byte{31}, 16)), now: fixedNow})
			err := enrollment.complete(context.Background(), syntheticCode, "synthetic-verifier")
			if test.wantSuccess {
				if err != nil || requests != 3 {
					t.Fatalf("token exchange error = %v, requests = %d", err, requests)
				}
				return
			}
			if !errors.Is(err, ErrProvider) || requests != 1 || strings.Contains(err.Error(), "private") {
				t.Fatalf("token exchange error = %v, requests = %d", err, requests)
			}
		})
	}
}

func TestTokenResponseRejectsEveryDuplicateFieldBeforeOAuthDecoding(t *testing.T) {
	for _, field := range []string{"access_token", "refresh_token", "token_type", "expires_in", "scope"} {
		for _, encoding := range []string{"json", "form"} {
			t.Run(encoding+"_"+field, func(t *testing.T) {
				var body string
				contentType := "application/json"
				if encoding == "json" {
					body = fmt.Sprintf(`{"%s":"one","%s":"two"}`, field, field)
				} else {
					contentType = "application/x-www-form-urlencoded"
					body = url.QueryEscape(field) + "=one&" + url.QueryEscape(field) + "=two"
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", contentType)
					_, _ = io.WriteString(w, body)
				}))
				t.Cleanup(server.Close)
				request, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader("code=x"))
				if err != nil {
					t.Fatal(err)
				}
				_, err = ownedHTTPClient(server.URL, productionHTTPTransport()).Do(request)
				if !errors.Is(err, ErrProvider) {
					t.Fatalf("duplicate %s response error = %v", field, err)
				}
			})
		}
	}
}

func TestTokenResponseRejectsFoldedSensitiveJSONNames(t *testing.T) {
	for _, name := range []string{"access_token", "refresh_token", "token_type", "expires_in", "scope"} {
		folded := strings.ToUpper(name)
		for _, body := range []string{
			fmt.Sprintf(`{"%s":"one"}`, folded),
			fmt.Sprintf(`{"%s":"one","%s":"two"}`, name, folded),
		} {
			if err := validateTokenResponse("application/json", []byte(body)); !errors.Is(err, ErrProvider) {
				t.Fatalf("folded sensitive field %q error = %v", name, err)
			}
		}
	}
}

func TestTokenResponseRejectsUnicodeFoldedSensitiveJSONNames(t *testing.T) {
	unicodeFolded := map[string]string{
		"access_token":  "acceſs_token",
		"refresh_token": "refreſh_token",
		"token_type":    "toKen_type",
		"expires_in":    "expireſ_in",
		"scope":         "ſcope",
	}
	for canonical, folded := range unicodeFolded {
		t.Run(canonical, func(t *testing.T) {
			var decoded map[string]json.RawMessage
			body := []byte(fmt.Sprintf(`{"%s":"one"}`, folded))
			if err := json.Unmarshal(body, &decoded); err != nil || !strings.EqualFold(canonical, folded) {
				t.Fatalf("Unicode fold fixture is invalid: decoded=%v error=%v", decoded, err)
			}
			if err := validateTokenResponse("application/json", body); !errors.Is(err, ErrProvider) {
				t.Fatalf("Unicode-folded field %q error = %v", folded, err)
			}
			duplicate := []byte(fmt.Sprintf(`{"%s":"one","%s":"two"}`, canonical, folded))
			if err := validateTokenResponse("application/json", duplicate); !errors.Is(err, ErrProvider) {
				t.Fatalf("canonical plus Unicode-folded field %q error = %v", folded, err)
			}
		})
	}
}

func TestTokenFormNamesRemainByteExactWithoutUnicodeFolding(t *testing.T) {
	body := []byte("access_token=one&acce%C5%BFs_token=two")
	if err := validateTokenResponse("application/x-www-form-urlencoded", body); err != nil {
		t.Fatalf("distinct form field names were Unicode-normalized: %v", err)
	}
}

func TestProductionHTTPClientIgnoresMutableDefaultTransport(t *testing.T) {
	original := http.DefaultTransport
	maliciousCalls := 0
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		maliciousCalls++
		return nil, errors.New("malicious ambient transport")
	})
	t.Cleanup(func() { http.DefaultTransport = original })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "{}")
	}))
	t.Cleanup(server.Close)
	transport := productionHTTPTransport()
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 || transport.DialContext == nil {
		t.Fatal("production transport does not have explicit verified TLS and dial policy")
	}
	response, err := ownedHTTPClient("", transport).Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if maliciousCalls != 0 {
		t.Fatalf("ambient default transport calls = %d", maliciousCalls)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestTokenRedirectNeverForwardsAuthorizationCodeOrClientCredential(t *testing.T) {
	destinationRequests := 0
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { destinationRequests++ }))
	t.Cleanup(destination.Close)
	requests := 0
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	t.Cleanup(provider.Close)
	enrollment := newTestEnrollment(t, enrollmentOptions{clientID: []byte(syntheticClientID), clientSecret: []byte(syntheticClientSecret), redirectURL: "http://127.0.0.1:8080" + callbackPath, store: storagefake.New(), keyring: syntheticKeyring(t)}, enrollmentDependencies{endpoints: providerEndpoints{authorization: provider.URL, token: provider.URL, userInfo: provider.URL, gmailProfile: provider.URL}, random: bytes.NewReader(bytes.Repeat([]byte{32}, 16)), now: fixedNow})
	err := enrollment.complete(context.Background(), syntheticCode, "synthetic-verifier")
	if !errors.Is(err, ErrProvider) || requests != 1 || destinationRequests != 0 {
		t.Fatalf("redirect error = %v, source requests = %d, destination requests = %d", err, requests, destinationRequests)
	}
}

func TestTokenHeaderAndBodyStallsCancelWithoutRetry(t *testing.T) {
	for _, stage := range []string{"header", "body"} {
		t.Run(stage, func(t *testing.T) {
			started := make(chan struct{})
			finished := make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			requests := 0
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				requests++
				close(started)
				if stage == "body" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"access_token":"`)
					if flusher, ok := w.(http.Flusher); ok {
						flusher.Flush()
					}
				}
				select {
				case <-r.Context().Done():
				case <-release:
				}
				close(finished)
			}))
			t.Cleanup(provider.Close)
			enrollment := newTestEnrollment(t, enrollmentOptions{clientID: []byte(syntheticClientID), clientSecret: []byte(syntheticClientSecret), redirectURL: "http://127.0.0.1:8080" + callbackPath, store: storagefake.New(), keyring: syntheticKeyring(t)}, enrollmentDependencies{endpoints: providerEndpoints{authorization: provider.URL, token: provider.URL, userInfo: provider.URL, gmailProfile: provider.URL}, random: bytes.NewReader(bytes.Repeat([]byte{33}, 16)), now: fixedNow})
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() { result <- enrollment.complete(ctx, syntheticCode, "synthetic-verifier") }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("token request did not reach named stall")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, ErrProvider) || !errors.Is(err, context.Canceled) || requests != 1 {
					t.Fatalf("token stall error = %v, requests = %d", err, requests)
				}
			case <-time.After(time.Second):
				t.Fatal("canceled token request did not return")
			}
			select {
			case <-finished:
			case <-time.After(time.Second):
				releaseOnce.Do(func() { close(release) })
				t.Fatal("token handler did not observe cancellation")
			}
		})
	}
}

func TestProviderResponsesFailClosedWithFixedDiagnostics(t *testing.T) {
	maximumProfilePrefix := `{"emailAddress":"a@b.test","historyId":"1","padding":"`
	maximumProfile := maximumProfilePrefix + strings.Repeat("x", maximumProviderBodyBytes-len(maximumProfilePrefix)-2) + `"}`
	tests := []struct {
		name        string
		body        string
		status      int
		redirect    bool
		userinfo    bool
		wantSuccess bool
	}{
		{name: "userinfo minimum", userinfo: true, body: `{"sub":"x"}`, wantSuccess: true},
		{name: "userinfo subject maximum", userinfo: true, body: `{"sub":"` + strings.Repeat("s", 255) + `"}`, wantSuccess: true},
		{name: "userinfo subject oversized", userinfo: true, body: `{"sub":"` + strings.Repeat("s", 256) + `"}`},
		{name: "userinfo missing", userinfo: true, body: `{}`},
		{name: "userinfo control", userinfo: true, body: `{"sub":"x\u0000y"}`},
		{name: "userinfo malformed", userinfo: true, body: `{`},
		{name: "userinfo trailing", userinfo: true, body: `{"sub":"x"}{}`},
		{name: "profile minimum", body: `{"emailAddress":"a@b.test","historyId":"1"}`, wantSuccess: true},
		{name: "profile email maximum", body: `{"emailAddress":"` + strings.Repeat("e", 320) + `","historyId":"1"}`, wantSuccess: true},
		{name: "profile email oversized", body: `{"emailAddress":"` + strings.Repeat("e", 321) + `","historyId":"1"}`},
		{name: "profile body maximum", body: maximumProfile, wantSuccess: true},
		{name: "profile zero history", body: `{"emailAddress":"a@b.test","historyId":"0"}`},
		{name: "profile overflow history", body: `{"emailAddress":"a@b.test","historyId":"18446744073709551616"}`},
		{name: "profile email control", body: `{"emailAddress":"a\u0000@b.test","historyId":"1"}`},
		{name: "provider status", status: http.StatusBadGateway, body: `private provider body`},
		{name: "redirect", redirect: true},
		{name: "oversized", body: strings.Repeat("x", maximumProviderBodyBytes+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var destination *httptest.Server
			if tt.redirect {
				destination = httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("redirect destination received bearer request") }))
				t.Cleanup(destination.Close)
			}
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.redirect {
					http.Redirect(w, r, destination.URL, http.StatusFound)
					return
				}
				status := tt.status
				if status == 0 {
					status = http.StatusOK
				}
				w.WriteHeader(status)
				_, _ = io.WriteString(w, tt.body)
			}))
			t.Cleanup(provider.Close)
			enrollment := &Enrollment{endpoints: providerEndpoints{userInfo: provider.URL, gmailProfile: provider.URL}}
			var err error
			if tt.userinfo {
				_, err = enrollment.fetchSubject(context.Background(), ownedHTTPClient("", productionHTTPTransport()), []byte(syntheticAccessToken))
			} else {
				_, err = enrollment.fetchProfile(context.Background(), ownedHTTPClient("", productionHTTPTransport()), []byte(syntheticAccessToken))
			}
			if tt.wantSuccess {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, ErrProvider) || len(err.Error()) > 96 {
				t.Fatalf("provider error = %v", err)
			}
			for _, marker := range []string{syntheticAccessToken, syntheticSubject, syntheticEmail, "private provider body"} {
				if strings.Contains(err.Error(), marker) {
					t.Fatal("provider error disclosed private data")
				}
			}
		})
	}
}

func TestProviderHeaderAndBodyStallsCancelAndReleaseHandlers(t *testing.T) {
	for _, stage := range []string{"header", "body"} {
		t.Run(stage, func(t *testing.T) {
			started := make(chan struct{})
			finished := make(chan struct{})
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(started)
				if stage == "body" {
					_, _ = io.WriteString(w, `{"sub":"`)
					if flusher, ok := w.(http.Flusher); ok {
						flusher.Flush()
					}
				}
				<-r.Context().Done()
				close(finished)
			}))
			t.Cleanup(provider.Close)
			enrollment := &Enrollment{endpoints: providerEndpoints{userInfo: provider.URL}}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			_, err := enrollment.fetchSubject(ctx, ownedHTTPClient("", productionHTTPTransport()), []byte(syntheticAccessToken))
			if !errors.Is(err, ErrProvider) || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("stalled %s error = %v", stage, err)
			}
			select {
			case <-started:
			default:
				t.Fatalf("stalled %s request did not reach handler", stage)
			}
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatalf("stalled %s handler was not released", stage)
			}
		})
	}
}

func TestCallbackCapacityOneAndConcurrentReplayAreBounded(t *testing.T) {
	enrollment := newTestEnrollment(t, enrollmentOptions{clientID: []byte(syntheticClientID), clientSecret: []byte(syntheticClientSecret), redirectURL: "http://127.0.0.1:8080" + callbackPath, store: storagefake.New(), keyring: syntheticKeyring(t)}, enrollmentDependencies{random: bytes.NewReader(append(bytes.Repeat([]byte{10}, 32), bytes.Repeat([]byte{11}, 32)...)), now: fixedNow})
	attempt, err := enrollment.beginAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	target := callbackPath + "?code=" + syntheticCode + "&state=" + attempt.state
	statuses := make(chan int, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			response := httptest.NewRecorder()
			enrollment.callbackHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
			statuses <- response.Code
		}()
	}
	wait.Wait()
	close(statuses)
	successes := 0
	for status := range statuses {
		if status == http.StatusOK {
			successes++
		}
	}
	if successes != 1 || len(attempt.result) != 1 {
		t.Fatalf("successful callbacks = %d, queued results = %d", successes, len(attempt.result))
	}
}

func TestCallbackFullResultChannelReturnsFixedConflictWithoutDisclosure(t *testing.T) {
	enrollment := newTestEnrollment(t, enrollmentOptions{clientID: []byte(syntheticClientID), clientSecret: []byte(syntheticClientSecret), redirectURL: "http://127.0.0.1:8080" + callbackPath, store: storagefake.New(), keyring: syntheticKeyring(t)}, enrollmentDependencies{random: bytes.NewReader(append(bytes.Repeat([]byte{34}, 32), bytes.Repeat([]byte{35}, 32)...)), now: fixedNow})
	attempt, err := enrollment.beginAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	attempt.result <- callbackResult{err: ErrCallback}
	response := httptest.NewRecorder()
	target := callbackPath + "?code=" + syntheticCode + "&state=" + attempt.state
	enrollment.callbackHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
	if response.Code != http.StatusConflict || response.Body.String() != "Authorization callback rejected.\n" || len(attempt.result) != 1 {
		t.Fatalf("full callback status = %d, body = %q, queued = %d", response.Code, response.Body.String(), len(attempt.result))
	}
	assertCallbackHeaders(t, response.Header())
	for _, private := range []string{attempt.state, syntheticCode, syntheticSubject, syntheticEmail} {
		if strings.Contains(response.Body.String(), private) || headerContains(response.Header(), private) {
			t.Fatal("full callback response disclosed private data")
		}
	}
}

func TestEnrollmentRestartStatesAreFailClosedAndIdempotent(t *testing.T) {
	accountID, _ := storage.ParseAccountID("09090909090909090909090909090909")
	subject, _ := storage.ParseProviderSubject(syntheticSubject)
	proposedHistory, _ := storage.ParseHistoryID(syntheticHistoryID)
	existingHistory, _ := storage.ParseHistoryID("41")
	for _, test := range []struct {
		name           string
		seedCursor     bool
		seedCredential bool
		wantRecovery   bool
	}{
		{name: "account only"},
		{name: "cursor only", seedCursor: true},
		{name: "complete", seedCursor: true, seedCredential: true},
		{name: "credential only", seedCredential: true, wantRecovery: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := storagefake.New()
			account, err := store.EnsureAccount(context.Background(), storage.AccountSeed{ID: accountID, ProviderSubject: subject})
			if err != nil {
				t.Fatal(err)
			}
			if test.seedCursor {
				if err := store.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: account.ID, Next: existingHistory}); err != nil {
					t.Fatal(err)
				}
			}
			ring := syntheticKeyring(t)
			envelopeText, err := ring.EncryptRefreshToken(account.ID.String(), []byte(syntheticRefreshToken))
			if err != nil {
				t.Fatal(err)
			}
			envelope, _ := storage.ParseCredentialEnvelope(envelopeText)
			if test.seedCredential {
				if err := store.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: account.ID, Next: envelope}); err != nil {
					t.Fatal(err)
				}
			}
			enrollment := &Enrollment{store: store, keyring: ring}
			err = enrollment.reconcile(context.Background(), account, proposedHistory, []byte(syntheticRefreshToken))
			if test.wantRecovery {
				if !errors.Is(err, ErrRecoveryRequired) {
					t.Fatalf("reconcile error = %v, want recovery", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			gotCursor, _ := store.GetSynchronizationCursor(context.Background(), account.ID)
			gotCredential, _ := store.GetProviderCredential(context.Background(), account.ID)
			wantHistory := proposedHistory
			if test.seedCursor {
				wantHistory = existingHistory
			}
			if gotCursor.HistoryID != wantHistory {
				t.Fatal("reconciliation replaced cursor")
			}
			plaintext, decryptErr := ring.DecryptRefreshToken(account.ID.String(), gotCredential.Envelope.String())
			if decryptErr != nil || string(plaintext) != syntheticRefreshToken {
				t.Fatalf("read-back credential failed: %v", decryptErr)
			}
			clear(plaintext)
		})
	}
}

func TestEnrollmentUncertainWritesUseOneFreshReadAndNeverReplay(t *testing.T) {
	for _, test := range []struct {
		name             string
		faultCursor      bool
		applyCursor      bool
		faultCredential  bool
		applyCredential  bool
		wantRecovery     bool
		wantCursorWrites int
		wantCredWrites   int
	}{
		{name: "cursor applied", faultCursor: true, applyCursor: true, wantCursorWrites: 1, wantCredWrites: 1},
		{name: "cursor absent", faultCursor: true, wantRecovery: true, wantCursorWrites: 1},
		{name: "credential applied", faultCredential: true, applyCredential: true, wantCursorWrites: 1, wantCredWrites: 1},
		{name: "credential absent", faultCredential: true, wantRecovery: true, wantCursorWrites: 1, wantCredWrites: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := storagefake.New()
			accountID, _ := storage.ParseAccountID("12121212121212121212121212121212")
			subject, _ := storage.ParseProviderSubject(syntheticSubject)
			account, err := base.EnsureAccount(context.Background(), storage.AccountSeed{ID: accountID, ProviderSubject: subject})
			if err != nil {
				t.Fatal(err)
			}
			history, _ := storage.ParseHistoryID("42")
			store := &uncertainStore{Handle: base, faultCursor: test.faultCursor, applyCursor: test.applyCursor, faultCredential: test.faultCredential, applyCredential: test.applyCredential}
			ring := syntheticKeyring(t)
			enrollment := &Enrollment{store: store, keyring: ring}
			err = enrollment.reconcile(context.Background(), account, history, []byte("uncertain-proposed-refresh-token"))
			if test.wantRecovery {
				if !errors.Is(err, ErrRecoveryRequired) {
					t.Fatalf("reconcile error = %v, want recovery", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if store.cursorWrites != test.wantCursorWrites || store.credentialWrites != test.wantCredWrites {
				t.Fatalf("writes = cursor %d credential %d, want %d and %d", store.cursorWrites, store.credentialWrites, test.wantCursorWrites, test.wantCredWrites)
			}
			if test.wantRecovery {
				fresh := &uncertainStore{Handle: base}
				if err := (&Enrollment{store: fresh, keyring: ring}).reconcile(context.Background(), account, history, []byte("uncertain-proposed-refresh-token")); err != nil {
					t.Fatalf("fresh reconciliation error = %v", err)
				}
				wantFreshCursorWrites := 0
				if test.faultCursor {
					wantFreshCursorWrites = 1
				}
				if fresh.cursorWrites != wantFreshCursorWrites || fresh.credentialWrites != 1 {
					t.Fatalf("fresh writes = cursor %d credential %d, want %d and 1", fresh.cursorWrites, fresh.credentialWrites, wantFreshCursorWrites)
				}
			}
		})
	}
}

func TestConcurrentSameSubjectEnrollmentConvergesOnCompleteCanonicalState(t *testing.T) {
	store := storagefake.New()
	subject, _ := storage.ParseProviderSubject(syntheticSubject)
	histories := []storage.HistoryID{mustHistory(t, "77"), mustHistory(t, "88")}
	tokens := [][]byte{[]byte("synthetic-refresh-token-one"), []byte("synthetic-refresh-token-two")}
	firstID, _ := storage.ParseAccountID("13131313131313131313131313131313")
	secondID, _ := storage.ParseAccountID("14141414141414141414141414141414")
	ring := syntheticKeyring(t)
	start := make(chan struct{})
	results := make(chan error, 2)
	accounts := make(chan storage.Account, 2)
	for index, candidate := range []storage.AccountID{firstID, secondID} {
		candidate := candidate
		index := index
		go func() {
			<-start
			account, err := store.EnsureAccount(context.Background(), storage.AccountSeed{ID: candidate, ProviderSubject: subject})
			if err == nil {
				err = (&Enrollment{store: store, keyring: ring}).reconcile(context.Background(), account, histories[index], tokens[index])
			}
			accounts <- account
			results <- err
		}()
	}
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("concurrent enrollment error = %v", err)
		}
	}
	first := <-accounts
	second := <-accounts
	if first != second {
		t.Fatalf("canonical accounts differ")
	}
	cursor, err := store.GetSynchronizationCursor(context.Background(), first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cursor.HistoryID != histories[0] && cursor.HistoryID != histories[1] {
		t.Fatalf("canonical cursor = %q", cursor.HistoryID)
	}
	credential, err := store.GetProviderCredential(context.Background(), first.ID)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := ring.DecryptRefreshToken(first.ID.String(), credential.Envelope.String())
	if err != nil || (string(plaintext) != string(tokens[0]) && string(plaintext) != string(tokens[1])) {
		t.Fatalf("canonical credential failed authentication: %v", err)
	}
	clear(plaintext)
}

func mustHistory(t *testing.T, value string) storage.HistoryID {
	t.Helper()
	history, err := storage.ParseHistoryID(value)
	if err != nil {
		t.Fatal(err)
	}
	return history
}

type observedStore struct {
	storage.Handle
	calls int
}

func (s *observedStore) EnsureAccount(ctx context.Context, seed storage.AccountSeed) (storage.Account, error) {
	s.calls++
	return s.Handle.EnsureAccount(ctx, seed)
}

func (s *observedStore) GetSynchronizationCursor(ctx context.Context, accountID storage.AccountID) (storage.SynchronizationCursor, error) {
	s.calls++
	return s.Handle.GetSynchronizationCursor(ctx, accountID)
}

func (s *observedStore) CommitSynchronization(ctx context.Context, commit storage.SynchronizationCommit) error {
	s.calls++
	return s.Handle.CommitSynchronization(ctx, commit)
}

func (s *observedStore) GetProviderCredential(ctx context.Context, accountID storage.AccountID) (storage.ProviderCredential, error) {
	s.calls++
	return s.Handle.GetProviderCredential(ctx, accountID)
}

func (s *observedStore) CommitProviderCredential(ctx context.Context, commit storage.ProviderCredentialCommit) error {
	s.calls++
	return s.Handle.CommitProviderCredential(ctx, commit)
}

type uncertainStore struct {
	storage.Handle
	mu               sync.Mutex
	faultCursor      bool
	applyCursor      bool
	faultCredential  bool
	applyCredential  bool
	cursorWrites     int
	credentialWrites int
}

func (s *uncertainStore) CommitSynchronization(ctx context.Context, commit storage.SynchronizationCommit) error {
	s.mu.Lock()
	s.cursorWrites++
	fault := s.faultCursor
	s.faultCursor = false
	apply := s.applyCursor
	s.mu.Unlock()
	if fault {
		if apply {
			_ = s.Handle.CommitSynchronization(ctx, commit)
		}
		return storage.ErrPersistenceUnknown
	}
	return s.Handle.CommitSynchronization(ctx, commit)
}

func (s *uncertainStore) CommitProviderCredential(ctx context.Context, commit storage.ProviderCredentialCommit) error {
	s.mu.Lock()
	s.credentialWrites++
	fault := s.faultCredential
	s.faultCredential = false
	apply := s.applyCredential
	s.mu.Unlock()
	if fault {
		if apply {
			_ = s.Handle.CommitProviderCredential(ctx, commit)
		}
		return storage.ErrPersistenceUnknown
	}
	return s.Handle.CommitProviderCredential(ctx, commit)
}

func newTestEnrollment(t *testing.T, options enrollmentOptions, dependencies enrollmentDependencies) *Enrollment {
	t.Helper()
	enrollment, err := newEnrollment(options, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	return enrollment
}

func syntheticKeyring(t *testing.T) *cryptobox.Keyring {
	t.Helper()
	encoded := "igk1:active=" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{42}, cryptobox.KeyBytes))
	ring, err := cryptobox.ParseKeyring([]byte(encoded))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ring.Close() })
	return ring
}

func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func fixedNow() time.Time { return time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC) }

func assertCallbackHeaders(t *testing.T, header http.Header) {
	t.Helper()
	for name, value := range map[string]string{"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'"} {
		if header.Get(name) != value {
			t.Fatalf("%s = %q, want %q", name, header.Get(name), value)
		}
	}
}

func headerContains(header http.Header, marker string) bool {
	for name, values := range header {
		if strings.Contains(name, marker) || strings.Contains(strings.Join(values, ""), marker) {
			return true
		}
	}
	return false
}

type channelWriter struct{ lines chan<- string }

func (w channelWriter) Write(data []byte) (int, error) {
	w.lines <- string(append([]byte(nil), data...))
	return len(data), nil
}

var _ io.Writer = channelWriter{}
