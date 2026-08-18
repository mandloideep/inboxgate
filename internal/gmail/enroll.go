// Package gmail implements the bounded one-shot Gmail enrollment flow.
package gmail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/oauth2"

	"github.com/mandloideep/inboxgate/internal/cryptobox"
	"github.com/mandloideep/inboxgate/internal/storage"
)

const (
	productionAuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
	productionTokenEndpoint         = "https://oauth2.googleapis.com/token"
	productionUserInfoEndpoint      = "https://openidconnect.googleapis.com/v1/userinfo"
	productionGmailProfileEndpoint  = "https://gmail.googleapis.com/gmail/v1/users/me/profile"
	callbackPath                    = "/oauth/google/callback"
	requestedScope                  = "openid https://www.googleapis.com/auth/gmail.readonly"
	maximumProviderBodyBytes        = 16_384
	maximumAuthorizationURLBytes    = 4_096
	maximumCodeBytes                = 4_096
	attemptLifetime                 = 10 * time.Minute
	providerDeadline                = 15 * time.Second
)

var (
	ErrBusy             = errors.New("gmail enrollment: authorization already pending")
	ErrCallback         = errors.New("gmail enrollment: callback rejected")
	ErrDenied           = errors.New("gmail enrollment: authorization denied")
	ErrProvider         = errors.New("gmail enrollment: provider request failed")
	ErrRecoveryRequired = errors.New("gmail enrollment: recovery required")
	ErrInvalidConfig    = errors.New("gmail enrollment: invalid runtime configuration")
	ErrOutput           = errors.New("gmail enrollment: output failed")
)

type enrollmentOptions struct {
	clientID     []byte
	clientSecret []byte
	redirectURL  string
	store        storage.Handle
	keyring      *cryptobox.Keyring
}

type providerEndpoints struct {
	authorization string
	token         string
	userInfo      string
	gmailProfile  string
}

type enrollmentDependencies struct {
	endpoints providerEndpoints
	random    io.Reader
	now       func() time.Time
	after     func(time.Duration) <-chan time.Time
	transport func() *http.Transport
}

type Enrollment struct {
	mu           sync.Mutex
	clientID     []byte
	clientSecret []byte
	redirectURL  string
	store        storage.Handle
	keyring      *cryptobox.Keyring
	endpoints    providerEndpoints
	random       io.Reader
	now          func() time.Time
	after        func(time.Duration) <-chan time.Time
	transport    func() *http.Transport
	pending      *authorizationAttempt
}

type authorizationAttempt struct {
	url      string
	state    string
	verifier string
	created  time.Time
	result   chan callbackResult
}

type callbackResult struct {
	code    string
	err     error
	handled <-chan struct{}
}

func New(clientID, clientSecret []byte, redirectURL string, store storage.Handle, keyring *cryptobox.Keyring) (*Enrollment, error) {
	return newEnrollment(enrollmentOptions{clientID: clientID, clientSecret: clientSecret, redirectURL: redirectURL, store: store, keyring: keyring}, enrollmentDependencies{})
}

func newEnrollment(options enrollmentOptions, dependencies enrollmentDependencies) (*Enrollment, error) {
	if len(options.clientID) < 1 || len(options.clientID) > 512 || len(options.clientSecret) < 1 || len(options.clientSecret) > 512 || options.store == nil || options.keyring == nil || !validVisible(options.clientID) || !validVisible(options.clientSecret) || !validRedirectURL(options.redirectURL) {
		return nil, ErrInvalidConfig
	}
	endpoints := dependencies.endpoints
	if endpoints == (providerEndpoints{}) {
		endpoints = providerEndpoints{authorization: productionAuthorizationEndpoint, token: productionTokenEndpoint, userInfo: productionUserInfoEndpoint, gmailProfile: productionGmailProfileEndpoint}
	}
	if dependencies.random == nil {
		dependencies.random = rand.Reader
	}
	if dependencies.now == nil {
		dependencies.now = time.Now
	}
	if dependencies.after == nil {
		dependencies.after = time.After
	}
	if dependencies.transport == nil {
		dependencies.transport = productionHTTPTransport
	}
	return &Enrollment{clientID: append([]byte(nil), options.clientID...), clientSecret: append([]byte(nil), options.clientSecret...), redirectURL: options.redirectURL, store: options.store, keyring: options.keyring, endpoints: endpoints, random: dependencies.random, now: dependencies.now, after: dependencies.after, transport: dependencies.transport}, nil
}

func (e *Enrollment) beginAuthorization() (*authorizationAttempt, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pending != nil {
		if e.now().Before(e.pending.created.Add(attemptLifetime)) {
			return nil, ErrBusy
		}
		select {
		case e.pending.result <- callbackResult{err: ErrCallback}:
		default:
		}
		e.pending = nil
	}
	stateBytes := make([]byte, 32)
	verifierBytes := make([]byte, 32)
	if _, err := io.ReadFull(e.random, stateBytes); err != nil {
		clear(stateBytes)
		clear(verifierBytes)
		return nil, ErrProvider
	}
	if _, err := io.ReadFull(e.random, verifierBytes); err != nil {
		clear(stateBytes)
		clear(verifierBytes)
		return nil, ErrProvider
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	clear(stateBytes)
	clear(verifierBytes)
	configuration := oauth2.Config{ClientID: string(e.clientID), RedirectURL: e.redirectURL, Scopes: strings.Fields(requestedScope), Endpoint: oauth2.Endpoint{AuthURL: e.endpoints.authorization, TokenURL: e.endpoints.token, AuthStyle: oauth2.AuthStyleInParams}}
	authorizationURL := configuration.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "consent select_account"), oauth2.S256ChallengeOption(verifier))
	if len(authorizationURL) > maximumAuthorizationURLBytes {
		return nil, ErrProvider
	}
	attempt := &authorizationAttempt{url: authorizationURL, state: state, verifier: verifier, created: e.now(), result: make(chan callbackResult, 1)}
	e.pending = attempt
	return attempt, nil
}

func (e *Enrollment) callbackHandler() http.Handler { return http.HandlerFunc(e.handleCallback) }

func (e *Enrollment) handleCallback(w http.ResponseWriter, r *http.Request) {
	setCallbackHeaders(w.Header())
	if r.Method != http.MethodGet || r.URL.EscapedPath() != callbackPath || len(r.RequestURI) > 4096 || !emptyCallbackBody(r) {
		writeCallback(w, http.StatusBadRequest, false)
		return
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !validCallbackKeys(values) {
		writeCallback(w, http.StatusBadRequest, false)
		return
	}
	state := values.Get("state")
	e.mu.Lock()
	attempt := e.pending
	if attempt == nil || len(state) != 43 || subtle.ConstantTimeCompare([]byte(state), []byte(attempt.state)) != 1 {
		e.mu.Unlock()
		writeCallback(w, http.StatusBadRequest, false)
		return
	}
	if !e.now().Before(attempt.created.Add(attemptLifetime)) {
		e.pending = nil
		e.mu.Unlock()
		attempt.result <- callbackResult{err: ErrCallback}
		writeCallback(w, http.StatusBadRequest, false)
		return
	}
	code := values.Get("code")
	denial := values.Get("error")
	if (code == "") == (denial == "") || (code != "" && (len(code) > maximumCodeBytes || !validVisible([]byte(code)))) || (denial != "" && (len(denial) > 128 || !validVisible([]byte(denial)))) {
		e.mu.Unlock()
		writeCallback(w, http.StatusBadRequest, false)
		return
	}
	e.pending = nil
	e.mu.Unlock()
	result := callbackResult{code: code}
	if denial != "" {
		result.err = ErrDenied
	}
	handled := make(chan struct{})
	result.handled = handled
	select {
	case attempt.result <- result:
		writeCallback(w, http.StatusOK, true)
		close(handled)
	default:
		writeCallback(w, http.StatusConflict, false)
	}
}

func emptyCallbackBody(request *http.Request) bool {
	if request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
		return false
	}
	if request.Body == nil || request.Body == http.NoBody || request.ContentLength == 0 {
		return true
	}
	var probe [1]byte
	n, err := request.Body.Read(probe[:])
	return n == 0 && errors.Is(err, io.EOF)
}

func validCallbackKeys(values url.Values) bool {
	if len(values) != 2 || len(values["state"]) != 1 || values.Get("state") == "" {
		return false
	}
	if code, ok := values["code"]; ok {
		return len(code) == 1 && code[0] != "" && values["error"] == nil
	}
	denial, ok := values["error"]
	return ok && len(denial) == 1 && denial[0] != "" && values["code"] == nil
}

func setCallbackHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	header.Set("Content-Type", "text/plain; charset=utf-8")
}

func writeCallback(w http.ResponseWriter, status int, success bool) {
	w.WriteHeader(status)
	if success {
		_, _ = io.WriteString(w, "Authorization received. Return to the operator terminal.\n")
	} else {
		_, _ = io.WriteString(w, "Authorization callback rejected.\n")
	}
}

func (e *Enrollment) Run(ctx context.Context, listener net.Listener, output io.Writer) error {
	return e.run(ctx, listener, output)
}

func (e *Enrollment) run(ctx context.Context, listener net.Listener, output io.Writer) error {
	attempt, err := e.beginAuthorization()
	if err != nil {
		return err
	}
	server := &http.Server{Handler: e.callbackHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 16 * 1024, ErrorLog: log.New(io.Discard, "", 0)}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	if written, writeErr := fmt.Fprintln(output, attempt.url); writeErr != nil || written != len(attempt.url)+1 {
		stopCallbackServer(server, served)
		return ErrOutput
	}
	var result callbackResult
	expires := e.after(attemptLifetime)
	select {
	case result = <-attempt.result:
	case <-expires:
		e.mu.Lock()
		expired := false
		if e.pending == attempt {
			e.pending = nil
			expired = true
		}
		e.mu.Unlock()
		if !expired {
			result = <-attempt.result
			break
		}
		attempt.url = ""
		attempt.state = ""
		attempt.verifier = ""
		stopCallbackServer(server, served)
		return ErrCallback
	case <-ctx.Done():
		stopCallbackServer(server, served)
		return errors.Join(ErrCallback, ctx.Err())
	}
	if result.handled != nil {
		select {
		case <-result.handled:
		case <-ctx.Done():
			_ = server.Close()
			return errors.Join(ErrCallback, ctx.Err())
		}
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
	_ = server.Shutdown(shutdownCtx)
	shutdownCancel()
	select {
	case <-served:
	case <-time.After(time.Second):
		return ErrCallback
	}
	if result.err != nil {
		return result.err
	}
	code := result.code
	verifier := attempt.verifier
	attempt.url = ""
	attempt.state = ""
	attempt.verifier = ""
	defer func() {
		code = ""
		verifier = ""
	}()
	return e.complete(ctx, code, verifier)
}

func stopCallbackServer(server *http.Server, served <-chan error) {
	_ = server.Close()
	select {
	case <-served:
	case <-time.After(time.Second):
	}
}

func (e *Enrollment) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	clear(e.clientID)
	clear(e.clientSecret)
	e.clientID = nil
	e.clientSecret = nil
	if e.pending != nil {
		e.pending.url = ""
		e.pending.state = ""
		e.pending.verifier = ""
		e.pending = nil
	}
}

func (e *Enrollment) complete(ctx context.Context, code, verifier string) error {
	requestCtx, cancel := context.WithTimeout(ctx, providerDeadline)
	defer cancel()
	client := ownedHTTPClient(e.endpoints.token, e.transport())
	configuration := oauth2.Config{ClientID: string(e.clientID), ClientSecret: string(e.clientSecret), RedirectURL: e.redirectURL, Scopes: strings.Fields(requestedScope), Endpoint: oauth2.Endpoint{AuthURL: e.endpoints.authorization, TokenURL: e.endpoints.token, AuthStyle: oauth2.AuthStyleInParams}}
	requestCtx = context.WithValue(requestCtx, oauth2.HTTPClient, client)
	token, err := configuration.Exchange(requestCtx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return fixedProviderError(requestCtx)
	}
	if token == nil || token.TokenType != "Bearer" || len(token.AccessToken) < 1 || len(token.AccessToken) > 4096 || len(token.RefreshToken) < 1 || len(token.RefreshToken) > 4096 || token.Expiry.IsZero() || !token.Expiry.After(e.now()) || token.Expiry.After(e.now().Add(24*time.Hour)) || !exactScope(fmt.Sprint(token.Extra("scope"))) {
		return ErrProvider
	}
	accessToken := []byte(token.AccessToken)
	refreshToken := []byte(token.RefreshToken)
	token.AccessToken = ""
	token.RefreshToken = ""
	defer clear(accessToken)
	defer clear(refreshToken)
	subjectText, err := e.fetchSubject(ctx, client, accessToken)
	if err != nil {
		return err
	}
	subject, err := storage.ParseProviderSubject(subjectText)
	if err != nil {
		return ErrProvider
	}
	accountBytes := make([]byte, 16)
	if _, err := io.ReadFull(e.random, accountBytes); err != nil {
		clear(accountBytes)
		return ErrProvider
	}
	accountID, _ := storage.ParseAccountID(hex.EncodeToString(accountBytes))
	clear(accountBytes)
	account, err := e.store.EnsureAccount(ctx, storage.AccountSeed{ID: accountID, ProviderSubject: subject})
	if err != nil {
		return fixedStorageError(err)
	}
	history, err := e.fetchProfile(ctx, client, accessToken)
	if err != nil {
		return err
	}
	return e.reconcile(ctx, account, history, refreshToken)
}

func (e *Enrollment) fetchSubject(ctx context.Context, client *http.Client, accessToken []byte) (string, error) {
	var response struct {
		Sub string `json:"sub"`
	}
	if err := providerGET(ctx, client, e.endpoints.userInfo, accessToken, &response); err != nil {
		return "", err
	}
	if _, err := storage.ParseProviderSubject(response.Sub); err != nil {
		return "", ErrProvider
	}
	return response.Sub, nil
}

func (e *Enrollment) fetchProfile(ctx context.Context, client *http.Client, accessToken []byte) (storage.HistoryID, error) {
	var response struct {
		EmailAddress string `json:"emailAddress"`
		HistoryID    string `json:"historyId"`
	}
	if err := providerGET(ctx, client, e.endpoints.gmailProfile, accessToken, &response); err != nil {
		return storage.HistoryID{}, err
	}
	if len(response.EmailAddress) < 1 || len(response.EmailAddress) > 320 || !utf8.ValidString(response.EmailAddress) || strings.IndexFunc(response.EmailAddress, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return storage.HistoryID{}, ErrProvider
	}
	history, err := storage.ParseHistoryID(response.HistoryID)
	if err != nil {
		return storage.HistoryID{}, ErrProvider
	}
	return history, nil
}

func providerGET(ctx context.Context, client *http.Client, endpoint string, accessToken []byte, target any) error {
	requestCtx, cancel := context.WithTimeout(ctx, providerDeadline)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ErrProvider
	}
	request.Header.Set("Authorization", "Bearer "+string(accessToken))
	response, err := client.Do(request)
	if err != nil {
		return fixedProviderError(requestCtx)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ErrProvider
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumProviderBodyBytes+1))
	if err != nil {
		clear(body)
		return fixedProviderError(requestCtx)
	}
	if len(body) > maximumProviderBodyBytes {
		clear(body)
		return ErrProvider
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		clear(body)
		return ErrProvider
	}
	clear(body)
	return nil
}

func (e *Enrollment) reconcile(ctx context.Context, account storage.Account, history storage.HistoryID, refreshToken []byte) error {
	cursor, cursorErr := e.store.GetSynchronizationCursor(ctx, account.ID)
	credential, credentialErr := e.store.GetProviderCredential(ctx, account.ID)
	hasCursor := cursorErr == nil
	hasCredential := credentialErr == nil
	if cursorErr != nil && !errors.Is(cursorErr, storage.ErrCursorNotFound) || credentialErr != nil && !errors.Is(credentialErr, storage.ErrCredentialNotFound) {
		return ErrRecoveryRequired
	}
	if hasCredential && !hasCursor {
		cursor, cursorErr = e.store.GetSynchronizationCursor(ctx, account.ID)
		if cursorErr != nil {
			return ErrRecoveryRequired
		}
		return e.verifyComplete(ctx, account, cursor, credential)
	}
	if hasCursor && hasCredential {
		return e.verifyComplete(ctx, account, cursor, credential)
	}
	if !hasCursor {
		if err := e.store.CommitSynchronization(ctx, storage.SynchronizationCommit{AccountID: account.ID, Next: history}); err != nil {
			cursor, cursorErr = e.store.GetSynchronizationCursor(ctx, account.ID)
			if cursorErr != nil {
				return ErrRecoveryRequired
			}
		} else {
			cursor = storage.SynchronizationCursor{AccountID: account.ID, HistoryID: history}
		}
	}
	envelopeText, err := e.keyring.EncryptRefreshToken(account.ID.String(), refreshToken)
	if err != nil {
		return ErrRecoveryRequired
	}
	envelope, err := storage.ParseCredentialEnvelope(envelopeText)
	if err != nil {
		return ErrRecoveryRequired
	}
	if err := e.store.CommitProviderCredential(ctx, storage.ProviderCredentialCommit{AccountID: account.ID, Next: envelope}); err != nil {
		credential, credentialErr = e.store.GetProviderCredential(ctx, account.ID)
		if credentialErr != nil {
			return ErrRecoveryRequired
		}
	} else {
		credential = storage.ProviderCredential{AccountID: account.ID, KeyID: envelope.KeyID(), Envelope: envelope}
	}
	return e.verifyComplete(ctx, account, cursor, credential)
}

func (e *Enrollment) verifyComplete(ctx context.Context, account storage.Account, _ storage.SynchronizationCursor, _ storage.ProviderCredential) error {
	canonical, err := e.store.EnsureAccount(ctx, storage.AccountSeed{ID: account.ID, ProviderSubject: account.ProviderSubject})
	if err != nil || canonical != account {
		return ErrRecoveryRequired
	}
	cursor, err := e.store.GetSynchronizationCursor(ctx, account.ID)
	if err != nil || cursor.AccountID != account.ID {
		return ErrRecoveryRequired
	}
	credential, err := e.store.GetProviderCredential(ctx, account.ID)
	if err != nil || credential.AccountID != account.ID {
		return ErrRecoveryRequired
	}
	plaintext, err := e.keyring.DecryptRefreshToken(account.ID.String(), credential.Envelope.String())
	if err != nil {
		return ErrRecoveryRequired
	}
	clear(plaintext)
	return nil
}

func productionHTTPTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

func ownedHTTPClient(tokenURL string, transport *http.Transport) *http.Client {
	return &http.Client{Transport: boundedTransport{base: transport, tokenURL: tokenURL}, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrProvider }}
}

type boundedTransport struct {
	base     http.RoundTripper
	tokenURL string
}

func (t boundedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maximumProviderBodyBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) > maximumProviderBodyBytes {
		clear(body)
		return nil, ErrProvider
	}
	if t.tokenURL != "" && request.URL.String() == t.tokenURL && response.StatusCode >= 200 && response.StatusCode < 300 {
		if err := validateTokenResponse(response.Header.Get("Content-Type"), body); err != nil {
			clear(body)
			return nil, ErrProvider
		}
	}
	response.Body = &clearingResponseBody{reader: bytes.NewReader(body), data: body}
	return response, nil
}

type clearingResponseBody struct {
	reader *bytes.Reader
	data   []byte
}

func (body *clearingResponseBody) Read(destination []byte) (int, error) {
	return body.reader.Read(destination)
}

func (body *clearingResponseBody) Close() error {
	clear(body.data)
	body.data = nil
	return nil
}

func validateTokenResponse(contentType string, body []byte) error {
	mediaType := strings.TrimSpace(strings.Split(contentType, ";")[0])
	switch mediaType {
	case "application/json", "text/json":
		decoder := json.NewDecoder(bytes.NewReader(body))
		start, err := decoder.Token()
		if err != nil || start != json.Delim('{') {
			return ErrProvider
		}
		seen := make(map[string]bool)
		sensitiveNames := []string{"access_token", "refresh_token", "token_type", "expires_in", "scope"}
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] || noncanonicalSensitiveJSONName(name, sensitiveNames) {
				return ErrProvider
			}
			seen[name] = true
			var value json.RawMessage
			if err := decoder.Decode(&value); err != nil {
				return ErrProvider
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') || decoder.Decode(&struct{}{}) != io.EOF {
			return ErrProvider
		}
		return nil
	case "application/x-www-form-urlencoded", "text/plain":
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return ErrProvider
		}
		for _, values := range values {
			if len(values) != 1 {
				return ErrProvider
			}
		}
		return nil
	default:
		return ErrProvider
	}
}

func noncanonicalSensitiveJSONName(name string, canonicalNames []string) bool {
	for _, canonical := range canonicalNames {
		if strings.EqualFold(name, canonical) {
			return name != canonical
		}
	}
	return false
}

func validRedirectURL(value string) bool {
	if len(value) < 1 || len(value) > 2048 {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.EscapedPath() != callbackPath || parsed.Path != callbackPath || parsed.Hostname() == "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	return parsed.Scheme == "http" && net.ParseIP(parsed.Hostname()) != nil && net.ParseIP(parsed.Hostname()).IsLoopback()
}

func validVisible(value []byte) bool {
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func exactScope(scope string) bool {
	fields := strings.Fields(scope)
	return len(fields) == 2 && ((fields[0] == "openid" && fields[1] == "https://www.googleapis.com/auth/gmail.readonly") || (fields[1] == "openid" && fields[0] == "https://www.googleapis.com/auth/gmail.readonly"))
}

func fixedProviderError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrProvider, err)
	}
	return ErrProvider
}

func fixedStorageError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(ErrRecoveryRequired, err)
	}
	return ErrRecoveryRequired
}
