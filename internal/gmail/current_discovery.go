package gmail

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/oauth2"

	"github.com/mandloideep/inboxgate/internal/cryptobox"
	maildomain "github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
)

const (
	productionGmailHistoryEndpoint = "https://gmail.googleapis.com/gmail/v1/users/me/history"
	productionGmailMessageEndpoint = "https://gmail.googleapis.com/gmail/v1/users/me/messages/"

	MaximumHistoryPageBodyBytes         = 1_048_576
	MaximumMessageMetadataBodyBytes     = 262_144
	MaximumProviderErrorBodyBytes       = 16_384
	MaximumPageTokenBytes               = 4_096
	MaximumMessageHeaderEntries         = 256
	MaximumSelectedHeaderBytes          = 65_536
	MaximumMessagePartDepth             = 32
	MaximumMessageParts                 = 1_000
	MaximumProviderAttempts             = 4
	MaximumProviderRequestAttempts      = 20_041
	MaximumCurrentDiscoveryPages        = storage.MaximumCurrentDiscoveryPages
	MaximumCurrentDiscoveryPageMessages = storage.MaximumCurrentDiscoveryPageMessages
	MaximumCurrentDiscoveryMessages     = storage.MaximumCurrentDiscoveryMessages
	MaximumRetryJitter                  = 250 * time.Millisecond
	MaximumRetryAfter                   = 30 * time.Second
	ProviderRequestDeadline             = 15 * time.Second

	currentDiscoveryCleanupDeadline = 15 * time.Second
	maximumAccessTokenBytes         = 4_096
	maximumOAuthExpirySeconds       = 86_400
	maximumMIMEFilenameBytes        = 4_096
	maximumAttachmentIDBytes        = 4_096
)

var (
	ErrCurrentDiscoveryInvalidRequest          = errors.New("gmail current discovery: invalid request")
	ErrCurrentDiscoveryInactiveAccount         = errors.New("gmail current discovery: inactive account")
	ErrCurrentDiscoveryRefreshFailed           = errors.New("gmail current discovery: access refresh failed")
	ErrCurrentDiscoveryReauthorizationRequired = errors.New("gmail current discovery: reauthorization required")
	ErrCurrentDiscoveryHistoryCursorStale      = errors.New("gmail current discovery: history cursor stale")
	ErrCurrentDiscoveryBoundedBacklog          = errors.New("gmail current discovery: bounded backlog")
	ErrCurrentDiscoveryRetryExhausted          = errors.New("gmail current discovery: retry exhausted")
	ErrCurrentDiscoveryInvalidProviderResponse = errors.New("gmail current discovery: invalid provider response")
	ErrCurrentDiscoveryConflict                = errors.New("gmail current discovery: discovery conflict")
	ErrCurrentDiscoveryRecoveryRequired        = errors.New("gmail current discovery: recovery required")
	errCurrentDiscoveryRedirect                = errors.New("gmail current discovery: redirect rejected")
)

var retryBaseDelays = [...]time.Duration{time.Second, 2 * time.Second, 4 * time.Second}

type CurrentDiscoveryResult struct {
	HistoryPagesRead       uint16
	UniqueMessageAdditions uint16
	MessagesCommitted      uint16
	VanishedMessages       uint16
	CursorAdvanced         bool
}

type currentDiscoveryOptions struct {
	clientID     []byte
	clientSecret []byte
	pageSize     int
	store        storage.Handle
	keyring      *cryptobox.Keyring
}

type currentDiscoveryEndpoints struct {
	token   string
	history string
	message string
}

type currentDiscoveryDependencies struct {
	endpoints      currentDiscoveryEndpoints
	transport      http.RoundTripper
	jitter         io.Reader
	sleep          func(context.Context, time.Duration) error
	cleanupTimeout time.Duration
}

type CurrentDiscovery struct {
	invokeMu       sync.Mutex
	clientID       []byte
	clientSecret   []byte
	pageSize       int
	store          storage.Handle
	keyring        *cryptobox.Keyring
	endpoints      currentDiscoveryEndpoints
	transport      http.RoundTripper
	jitter         io.Reader
	sleep          func(context.Context, time.Duration) error
	cleanupTimeout time.Duration
	closeOnce      sync.Once
}

type discoveryPreflight struct {
	lifecycle storage.AccountLifecycle
	cursor    storage.SynchronizationCursor
	refresh   []byte
}

type discoveredIdentity struct {
	messageID string
	threadID  string
}

type refreshClassification uint8

const (
	refreshUnclassified refreshClassification = iota
	refreshInvalidGrant
	refreshAdminPolicy
)

func NewCurrentDiscovery(clientID, clientSecret []byte, pageSize int, store storage.Handle, keyring *cryptobox.Keyring) (*CurrentDiscovery, error) {
	return newCurrentDiscovery(currentDiscoveryOptions{clientID: clientID, clientSecret: clientSecret, pageSize: pageSize, store: store, keyring: keyring}, currentDiscoveryDependencies{})
}

func newCurrentDiscovery(options currentDiscoveryOptions, dependencies currentDiscoveryDependencies) (*CurrentDiscovery, error) {
	if len(options.clientID) < 1 || len(options.clientID) > 512 || len(options.clientSecret) < 1 || len(options.clientSecret) > 512 || !validVisible(options.clientID) || !validVisible(options.clientSecret) || options.pageSize < 1 || options.pageSize > storage.MaximumCurrentDiscoveryPageMessages || options.store == nil || options.keyring == nil {
		return nil, ErrCurrentDiscoveryInvalidRequest
	}
	if dependencies.endpoints == (currentDiscoveryEndpoints{}) {
		dependencies.endpoints = currentDiscoveryEndpoints{token: productionTokenEndpoint, history: productionGmailHistoryEndpoint, message: productionGmailMessageEndpoint}
	}
	if !validCurrentDiscoveryEndpoints(dependencies.endpoints) {
		return nil, ErrCurrentDiscoveryInvalidRequest
	}
	if dependencies.transport == nil {
		dependencies.transport = currentDiscoveryTransport()
	}
	if dependencies.jitter == nil {
		dependencies.jitter = cryptorand.Reader
	}
	if dependencies.sleep == nil {
		dependencies.sleep = currentDiscoverySleep
	}
	if dependencies.cleanupTimeout <= 0 {
		dependencies.cleanupTimeout = currentDiscoveryCleanupDeadline
	}
	return &CurrentDiscovery{
		clientID: append([]byte(nil), options.clientID...), clientSecret: append([]byte(nil), options.clientSecret...),
		pageSize: options.pageSize, store: options.store, keyring: options.keyring, endpoints: dependencies.endpoints,
		transport: dependencies.transport, jitter: dependencies.jitter, sleep: dependencies.sleep, cleanupTimeout: dependencies.cleanupTimeout,
	}, nil
}

func (discovery *CurrentDiscovery) Close() {
	if discovery == nil {
		return
	}
	discovery.closeOnce.Do(func() {
		discovery.invokeMu.Lock()
		defer discovery.invokeMu.Unlock()
		clear(discovery.clientID)
		clear(discovery.clientSecret)
		discovery.clientID = nil
		discovery.clientSecret = nil
		if closer, ok := discovery.transport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	})
}

func (discovery *CurrentDiscovery) Discover(ctx context.Context, accountID storage.AccountID) (CurrentDiscoveryResult, error) {
	if discovery != nil {
		discovery.invokeMu.Lock()
		defer discovery.invokeMu.Unlock()
	}
	if discovery == nil || discovery.store == nil || discovery.keyring == nil || len(discovery.clientID) == 0 || len(discovery.clientSecret) == 0 || discovery.pageSize < 1 || discovery.pageSize > storage.MaximumCurrentDiscoveryPageMessages {
		return CurrentDiscoveryResult{}, ErrCurrentDiscoveryInvalidRequest
	}
	if ctx == nil {
		return CurrentDiscoveryResult{}, ErrCurrentDiscoveryInvalidRequest
	}
	if parsed, err := storage.ParseAccountID(accountID.String()); err != nil || parsed != accountID {
		return CurrentDiscoveryResult{}, ErrCurrentDiscoveryInvalidRequest
	}
	preflight, err := discovery.preflight(ctx, accountID)
	if err != nil {
		return CurrentDiscoveryResult{}, err
	}
	defer clear(preflight.refresh)
	accessToken, classification, err := discovery.refreshAccessToken(ctx, preflight.refresh)
	if err != nil {
		if classification == refreshInvalidGrant {
			return CurrentDiscoveryResult{}, discovery.markReauthorization(accountID, preflight.lifecycle, storage.ReauthorizationReasonRefreshInvalidGrant)
		}
		if classification == refreshAdminPolicy {
			return CurrentDiscoveryResult{}, discovery.markReauthorization(accountID, preflight.lifecycle, storage.ReauthorizationReasonRefreshAdminPolicyEnforced)
		}
		return CurrentDiscoveryResult{}, err
	}
	defer clear(accessToken)
	identities, nextCursor, pages, err := discovery.readHistory(ctx, accountID, preflight.lifecycle, preflight.cursor.HistoryID, accessToken)
	if err != nil {
		return CurrentDiscoveryResult{}, err
	}
	result := CurrentDiscoveryResult{HistoryPagesRead: uint16(pages), UniqueMessageAdditions: uint16(len(identities))}
	comparison := nextCursor.Compare(preflight.cursor.HistoryID)
	if comparison < 0 {
		return CurrentDiscoveryResult{}, ErrCurrentDiscoveryInvalidProviderResponse
	}
	if comparison == 0 {
		if len(identities) == 0 || discovery.alreadyDurable(ctx, accountID, identities) {
			return result, nil
		}
		return CurrentDiscoveryResult{}, ErrCurrentDiscoveryInvalidProviderResponse
	}
	messages := make([]maildomain.Message, 0, len(identities))
	for _, identity := range identities {
		message, vanished, fetchErr := discovery.readMessage(ctx, accountID, preflight.lifecycle, identity, accessToken)
		if fetchErr != nil {
			return CurrentDiscoveryResult{}, fetchErr
		}
		if vanished {
			result.VanishedMessages++
			continue
		}
		messages = append(messages, message)
	}
	commit := storage.CurrentDiscoveryCommit{AccountID: accountID, Expected: preflight.cursor.HistoryID, Next: nextCursor, Messages: messages}
	if _, err := storage.PrepareCurrentDiscoveryCommit(commit); err != nil {
		if errors.Is(err, storage.ErrCurrentDiscoveryConflict) {
			return CurrentDiscoveryResult{}, ErrCurrentDiscoveryConflict
		}
		return CurrentDiscoveryResult{}, ErrCurrentDiscoveryInvalidProviderResponse
	}
	if err := discovery.store.CommitCurrentDiscovery(ctx, commit); err != nil {
		return CurrentDiscoveryResult{}, fixedCurrentDiscoveryStorageError(err)
	}
	result.MessagesCommitted = uint16(len(messages))
	result.CursorAdvanced = true
	return result, nil
}

func (discovery *CurrentDiscovery) preflight(ctx context.Context, accountID storage.AccountID) (discoveryPreflight, error) {
	if err := discovery.store.ReconcileCurrentDiscovery(ctx, accountID); err != nil {
		if errors.Is(err, storage.ErrLifecycleConflict) {
			return discoveryPreflight{}, ErrCurrentDiscoveryInactiveAccount
		}
		return discoveryPreflight{}, fixedCurrentDiscoveryStorageError(err)
	}
	lifecycle, err := discovery.store.GetAccountLifecycle(ctx, accountID)
	if err != nil {
		return discoveryPreflight{}, fixedCurrentDiscoveryStorageError(err)
	}
	if inactiveLifecycle(lifecycle) {
		return discoveryPreflight{}, ErrCurrentDiscoveryInactiveAccount
	}
	if !validActiveLifecycle(lifecycle, accountID) || lifecycle.Version.Int64() == math.MaxInt64 {
		return discoveryPreflight{}, ErrCurrentDiscoveryRecoveryRequired
	}
	cursor, err := discovery.store.GetSynchronizationCursor(ctx, accountID)
	if err != nil || cursor.AccountID != accountID {
		return discoveryPreflight{}, fixedCurrentDiscoveryStorageError(err)
	}
	credential, err := discovery.store.GetProviderCredential(ctx, accountID)
	if err != nil || credential.AccountID != accountID || credential.KeyID != credential.Envelope.KeyID() {
		return discoveryPreflight{}, fixedCurrentDiscoveryStorageError(err)
	}
	refresh, err := discovery.keyring.DecryptRefreshToken(accountID.String(), credential.Envelope.String())
	if err != nil || len(refresh) < 1 || len(refresh) > storage.MaximumCredentialPlaintextBytes {
		clear(refresh)
		return discoveryPreflight{}, ErrCurrentDiscoveryRecoveryRequired
	}
	verified, err := discovery.store.GetAccountLifecycle(ctx, accountID)
	if err != nil {
		clear(refresh)
		return discoveryPreflight{}, fixedCurrentDiscoveryStorageError(err)
	}
	if inactiveLifecycle(verified) {
		clear(refresh)
		return discoveryPreflight{}, ErrCurrentDiscoveryInactiveAccount
	}
	if !sameLifecycle(lifecycle, verified) || !validActiveLifecycle(verified, accountID) {
		clear(refresh)
		return discoveryPreflight{}, ErrCurrentDiscoveryRecoveryRequired
	}
	return discoveryPreflight{lifecycle: lifecycle, cursor: cursor, refresh: refresh}, nil
}

func inactiveLifecycle(lifecycle storage.AccountLifecycle) bool {
	return lifecycle.State == storage.AccountStatePaused || lifecycle.State == storage.AccountStateReauthorizationRequired || lifecycle.State == storage.AccountStateRevoked
}

func validActiveLifecycle(lifecycle storage.AccountLifecycle, accountID storage.AccountID) bool {
	return lifecycle.AccountID == accountID && lifecycle.State == storage.AccountStateActive && lifecycle.Version.Int64() >= 1 && lifecycle.ReauthorizationReason == nil && lifecycle.RevocationStatus == storage.RevocationStatusNone
}

func sameLifecycle(left, right storage.AccountLifecycle) bool {
	if left.AccountID != right.AccountID || left.State != right.State || left.Version != right.Version || left.RevocationStatus != right.RevocationStatus {
		return false
	}
	if left.ReauthorizationReason == nil || right.ReauthorizationReason == nil {
		return left.ReauthorizationReason == nil && right.ReauthorizationReason == nil
	}
	return *left.ReauthorizationReason == *right.ReauthorizationReason
}

func (discovery *CurrentDiscovery) refreshAccessToken(ctx context.Context, refresh []byte) ([]byte, refreshClassification, error) {
	requestCtx, cancel := context.WithTimeout(ctx, ProviderRequestDeadline)
	defer cancel()
	validator := &refreshValidationTransport{
		base: discovery.transport, endpoint: discovery.endpoints.token,
		clientID: string(discovery.clientID), clientSecret: string(discovery.clientSecret), refresh: string(refresh),
	}
	client := &http.Client{Transport: validator, CheckRedirect: rejectCurrentDiscoveryRedirect}
	configuration := oauth2.Config{
		ClientID: string(discovery.clientID), ClientSecret: string(discovery.clientSecret),
		Endpoint: oauth2.Endpoint{TokenURL: discovery.endpoints.token, AuthStyle: oauth2.AuthStyleInParams},
	}
	expired := &oauth2.Token{RefreshToken: string(refresh), Expiry: time.Unix(1, 0)}
	requestCtx = context.WithValue(requestCtx, oauth2.HTTPClient, client)
	token, tokenErr := configuration.TokenSource(requestCtx, expired).Token()
	expired.RefreshToken = ""
	if tokenErr != nil {
		if requestCtx.Err() != nil {
			return nil, validator.classification, errors.Join(ErrCurrentDiscoveryRefreshFailed, requestCtx.Err())
		}
		return nil, validator.classification, ErrCurrentDiscoveryRefreshFailed
	}
	if token == nil || token.TokenType != "Bearer" || len(token.AccessToken) < 1 || len(token.AccessToken) > maximumAccessTokenBytes {
		if token != nil {
			token.AccessToken = ""
			token.RefreshToken = ""
		}
		return nil, validator.classification, ErrCurrentDiscoveryRefreshFailed
	}
	access := []byte(token.AccessToken)
	token.AccessToken = ""
	token.RefreshToken = ""
	return access, refreshUnclassified, nil
}

type refreshValidationTransport struct {
	base           http.RoundTripper
	endpoint       string
	clientID       string
	clientSecret   string
	refresh        string
	classification refreshClassification
}

func (transport *refreshValidationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.String() != transport.endpoint || request.Method != "POST" || request.URL.RawQuery != "" || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" || request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || request.Body == nil {
		return nil, ErrCurrentDiscoveryRefreshFailed
	}
	requestBody, err := io.ReadAll(io.LimitReader(request.Body, 16_385))
	if err != nil || len(requestBody) > 16_384 {
		clear(requestBody)
		return nil, ErrCurrentDiscoveryRefreshFailed
	}
	request.Body = &clearingResponseBody{reader: bytes.NewReader(requestBody), data: requestBody}
	values, err := url.ParseQuery(string(requestBody))
	want := url.Values{
		"client_id": {transport.clientID}, "client_secret": {transport.clientSecret},
		"grant_type": {"refresh_token"}, "refresh_token": {transport.refresh},
	}
	if err != nil || values.Encode() != want.Encode() {
		return nil, ErrCurrentDiscoveryRefreshFailed
	}
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, MaximumProviderErrorBodyBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) > MaximumProviderErrorBodyBytes {
		clear(body)
		return nil, ErrCurrentDiscoveryRefreshFailed
	}
	if !jsonContentType(response.Header.Get("Content-Type")) {
		clear(body)
		return nil, ErrCurrentDiscoveryRefreshFailed
	}
	if response.StatusCode == http.StatusOK {
		if validateRefreshSuccess(body) != nil {
			clear(body)
			return nil, ErrCurrentDiscoveryRefreshFailed
		}
	} else if response.StatusCode == http.StatusBadRequest {
		transport.classification = classifyRefreshError(body)
	} else if response.StatusCode >= 200 && response.StatusCode < 300 {
		clear(body)
		return nil, ErrCurrentDiscoveryRefreshFailed
	}
	response.Body = &clearingResponseBody{reader: bytes.NewReader(body), data: body}
	return response, nil
}

func (discovery *CurrentDiscovery) readHistory(ctx context.Context, accountID storage.AccountID, lifecycle storage.AccountLifecycle, cursor storage.HistoryID, access []byte) ([]discoveredIdentity, storage.HistoryID, int, error) {
	identities := make([]discoveredIdentity, 0)
	byMessage := make(map[string]string)
	seenTokens := make(map[string]struct{})
	pageToken := ""
	var previousRecord storage.HistoryID
	var previousPageHistory storage.HistoryID
	var finalCursor storage.HistoryID
	for page := 1; page <= storage.MaximumCurrentDiscoveryPages; page++ {
		target, err := discovery.historyURL(cursor.String(), pageToken)
		if err != nil {
			return nil, storage.HistoryID{}, page - 1, ErrCurrentDiscoveryInvalidRequest
		}
		status, body, err := discovery.gmailGET(ctx, target, access, MaximumHistoryPageBodyBytes)
		if err != nil {
			return nil, storage.HistoryID{}, page - 1, err
		}
		if status == http.StatusUnauthorized {
			clear(body)
			return nil, storage.HistoryID{}, page, discovery.markReauthorization(accountID, lifecycle, storage.ReauthorizationReasonGmailUnauthorizedAfterRefresh)
		}
		if status == http.StatusForbidden {
			reason, exact := exactGoogleErrorReason(body)
			clear(body)
			if exact && reason == "domainPolicy" {
				return nil, storage.HistoryID{}, page, discovery.markReauthorization(accountID, lifecycle, storage.ReauthorizationReasonGmailDomainPolicy)
			}
			return nil, storage.HistoryID{}, page, ErrCurrentDiscoveryInvalidProviderResponse
		}
		if status == http.StatusNotFound {
			clear(body)
			return nil, storage.HistoryID{}, page, ErrCurrentDiscoveryHistoryCursorStale
		}
		if status != http.StatusOK {
			clear(body)
			return nil, storage.HistoryID{}, page, ErrCurrentDiscoveryInvalidProviderResponse
		}
		decoded, err := decodeHistoryPage(body)
		clear(body)
		if err != nil {
			return nil, storage.HistoryID{}, page, ErrCurrentDiscoveryInvalidProviderResponse
		}
		for _, record := range decoded.records {
			if previousRecord.String() != "" && record.id.Compare(previousRecord) <= 0 {
				return nil, storage.HistoryID{}, page, ErrCurrentDiscoveryInvalidProviderResponse
			}
			previousRecord = record.id
			for _, identity := range record.identities {
				if thread, exists := byMessage[identity.messageID]; exists {
					if thread != identity.threadID {
						return nil, storage.HistoryID{}, page, ErrCurrentDiscoveryConflict
					}
					continue
				}
				if len(identities) == storage.MaximumCurrentDiscoveryMessages {
					return nil, storage.HistoryID{}, page, ErrCurrentDiscoveryBoundedBacklog
				}
				byMessage[identity.messageID] = identity.threadID
				identities = append(identities, identity)
			}
		}
		if decoded.historyID.Compare(cursor) < 0 || previousRecord.String() != "" && decoded.historyID.Compare(previousRecord) < 0 || previousPageHistory.String() != "" && decoded.historyID.Compare(previousPageHistory) < 0 {
			return nil, storage.HistoryID{}, page, ErrCurrentDiscoveryInvalidProviderResponse
		}
		previousPageHistory = decoded.historyID
		finalCursor = decoded.historyID
		if decoded.nextPageToken == "" {
			return identities, finalCursor, page, nil
		}
		if _, exists := seenTokens[decoded.nextPageToken]; exists {
			return nil, storage.HistoryID{}, page, ErrCurrentDiscoveryInvalidProviderResponse
		}
		seenTokens[decoded.nextPageToken] = struct{}{}
		pageToken = decoded.nextPageToken
		if page == storage.MaximumCurrentDiscoveryPages {
			return nil, storage.HistoryID{}, page, ErrCurrentDiscoveryBoundedBacklog
		}
	}
	return nil, storage.HistoryID{}, storage.MaximumCurrentDiscoveryPages, ErrCurrentDiscoveryBoundedBacklog
}

func (discovery *CurrentDiscovery) readMessage(ctx context.Context, accountID storage.AccountID, lifecycle storage.AccountLifecycle, identity discoveredIdentity, access []byte) (maildomain.Message, bool, error) {
	target, err := discovery.messageURL(identity.messageID)
	if err != nil {
		return maildomain.Message{}, false, ErrCurrentDiscoveryInvalidRequest
	}
	status, body, err := discovery.gmailGET(ctx, target, access, MaximumMessageMetadataBodyBytes)
	if err != nil {
		return maildomain.Message{}, false, err
	}
	if status == http.StatusUnauthorized {
		clear(body)
		return maildomain.Message{}, false, discovery.markReauthorization(accountID, lifecycle, storage.ReauthorizationReasonGmailUnauthorizedAfterRefresh)
	}
	if status == http.StatusForbidden {
		reason, exact := exactGoogleErrorReason(body)
		clear(body)
		if exact && reason == "domainPolicy" {
			return maildomain.Message{}, false, discovery.markReauthorization(accountID, lifecycle, storage.ReauthorizationReasonGmailDomainPolicy)
		}
		return maildomain.Message{}, false, ErrCurrentDiscoveryInvalidProviderResponse
	}
	if status == http.StatusNotFound {
		clear(body)
		return maildomain.Message{}, true, nil
	}
	if status != http.StatusOK {
		clear(body)
		return maildomain.Message{}, false, ErrCurrentDiscoveryInvalidProviderResponse
	}
	input, err := decodeMessageMetadata(body, identity)
	clear(body)
	if err != nil {
		return maildomain.Message{}, false, ErrCurrentDiscoveryInvalidProviderResponse
	}
	message, err := maildomain.Normalize(accountID.String(), input)
	if err != nil {
		return maildomain.Message{}, false, ErrCurrentDiscoveryInvalidProviderResponse
	}
	return message, false, nil
}

func (discovery *CurrentDiscovery) alreadyDurable(ctx context.Context, accountID storage.AccountID, identities []discoveredIdentity) bool {
	for _, identity := range identities {
		message, err := discovery.store.GetDiscoveredMessage(ctx, accountID, identity.messageID)
		if err != nil || message.GmailThreadID() != identity.threadID {
			return false
		}
	}
	return true
}

func (discovery *CurrentDiscovery) historyURL(cursor, pageToken string) (string, error) {
	parsed, err := url.Parse(discovery.endpoints.history)
	if err != nil {
		return "", err
	}
	query := url.Values{
		"startHistoryId": {cursor},
		"historyTypes":   {"messageAdded"},
		"maxResults":     {strconv.Itoa(discovery.pageSize)},
		"fields":         {"history(id,messagesAdded(message(id,threadId))),historyId,nextPageToken"},
	}
	if pageToken != "" {
		query.Set("pageToken", pageToken)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func (discovery *CurrentDiscovery) messageURL(messageID string) (string, error) {
	if storage.ValidateGmailMessageID(messageID) != nil {
		return "", storage.ErrInvalidValue
	}
	parsed, err := url.Parse(discovery.endpoints.message)
	if err != nil {
		return "", err
	}
	parsed.RawPath = strings.TrimSuffix(parsed.EscapedPath(), "/") + "/" + url.PathEscape(messageID)
	parsed.Path = strings.TrimSuffix(parsed.Path, "/") + "/" + messageID
	parsed.RawQuery = url.Values{"format": {"FULL"}, "fields": {messageMetadataFields}}.Encode()
	return parsed.String(), nil
}

func (discovery *CurrentDiscovery) gmailGET(ctx context.Context, target string, access []byte, successLimit int64) (int, []byte, error) {
	client := &http.Client{Transport: discovery.transport, CheckRedirect: rejectCurrentDiscoveryRedirect}
	for attempt := 0; attempt < MaximumProviderAttempts; attempt++ {
		requestCtx, cancel := context.WithTimeout(ctx, ProviderRequestDeadline)
		request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, target, nil)
		if err != nil {
			cancel()
			return 0, nil, ErrCurrentDiscoveryInvalidRequest
		}
		request.Close = true
		request.Header.Set("Authorization", "Bearer "+string(access))
		response, requestErr := client.Do(request)
		request.Header.Del("Authorization")
		if requestErr != nil {
			cancel()
			if errors.Is(requestErr, errCurrentDiscoveryRedirect) {
				return 0, nil, ErrCurrentDiscoveryInvalidProviderResponse
			}
			if ctx.Err() != nil {
				return 0, nil, errors.Join(ErrCurrentDiscoveryRetryExhausted, ctx.Err())
			}
			if attempt == MaximumProviderAttempts-1 {
				return 0, nil, ErrCurrentDiscoveryRetryExhausted
			}
			if err := discovery.waitForRetry(ctx, attempt, ""); err != nil {
				return 0, nil, err
			}
			continue
		}
		limit := int64(MaximumProviderErrorBodyBytes)
		if response.StatusCode == http.StatusOK {
			limit = successLimit
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
		closeErr := response.Body.Close()
		cancel()
		if int64(len(body)) > limit {
			clear(body)
			return 0, nil, ErrCurrentDiscoveryInvalidProviderResponse
		}
		if readErr != nil || closeErr != nil {
			clear(body)
			if ctx.Err() != nil {
				return 0, nil, errors.Join(ErrCurrentDiscoveryRetryExhausted, ctx.Err())
			}
			if attempt == MaximumProviderAttempts-1 {
				return 0, nil, ErrCurrentDiscoveryRetryExhausted
			}
			if err := discovery.waitForRetry(ctx, attempt, ""); err != nil {
				return 0, nil, err
			}
			continue
		}
		if response.StatusCode == http.StatusOK && !jsonContentType(response.Header.Get("Content-Type")) {
			clear(body)
			return 0, nil, ErrCurrentDiscoveryInvalidProviderResponse
		}
		retryable := retryableGmailResponse(response.StatusCode, body)
		if !retryable {
			return response.StatusCode, body, nil
		}
		if attempt == MaximumProviderAttempts-1 {
			clear(body)
			return 0, nil, ErrCurrentDiscoveryRetryExhausted
		}
		retryAfter := response.Header.Get("Retry-After")
		clear(body)
		if err := discovery.waitForRetry(ctx, attempt, retryAfter); err != nil {
			return 0, nil, err
		}
	}
	return 0, nil, ErrCurrentDiscoveryRetryExhausted
}

func retryableGmailResponse(status int, body []byte) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	case http.StatusForbidden:
		reason, exact := exactGoogleErrorReason(body)
		return exact && (reason == "rateLimitExceeded" || reason == "userRateLimitExceeded")
	default:
		return false
	}
}

func (discovery *CurrentDiscovery) waitForRetry(ctx context.Context, retryIndex int, retryAfterText string) error {
	maximum := big.NewInt(int64(MaximumRetryJitter/time.Millisecond) + 1)
	jitter, err := cryptorand.Int(discovery.jitter, maximum)
	if err != nil {
		return ErrCurrentDiscoveryRetryExhausted
	}
	delay := retryBaseDelays[retryIndex] + time.Duration(jitter.Int64())*time.Millisecond
	if retryAfter := parseRetryAfter(retryAfterText); retryAfter > delay {
		delay = retryAfter
	}
	if delay > MaximumRetryAfter {
		delay = MaximumRetryAfter
	}
	if err := discovery.sleep(ctx, delay); err != nil {
		if ctx.Err() != nil {
			return errors.Join(ErrCurrentDiscoveryRetryExhausted, ctx.Err())
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return errors.Join(ErrCurrentDiscoveryRetryExhausted, err)
		}
		return ErrCurrentDiscoveryRetryExhausted
	}
	return nil
}

func parseRetryAfter(text string) time.Duration {
	if text == "" || len(text) > 2 || text[0] == '0' {
		return 0
	}
	seconds, err := strconv.Atoi(text)
	if err != nil || seconds < 1 || seconds > int(MaximumRetryAfter/time.Second) || strconv.Itoa(seconds) != text {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

func (discovery *CurrentDiscovery) markReauthorization(accountID storage.AccountID, expected storage.AccountLifecycle, reason storage.ReauthorizationReason) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), discovery.cleanupTimeout)
	defer cancel()
	commit := storage.LifecycleCommit{
		AccountID: accountID, ExpectedState: storage.AccountStateActive, ExpectedVersion: expected.Version,
		ExpectedRevocationStatus: storage.RevocationStatusNone, NextState: storage.AccountStateReauthorizationRequired,
		ReauthorizationReason: &reason, RevocationStatus: storage.RevocationStatusNone,
	}
	if err := discovery.store.CommitAccountLifecycle(cleanupCtx, commit); err != nil {
		verified, verificationErr := discovery.store.GetAccountLifecycle(cleanupCtx, accountID)
		if verificationErr != nil || !storage.LifecycleMatchesCommit(verified, commit) {
			return ErrCurrentDiscoveryRecoveryRequired
		}
	}
	return ErrCurrentDiscoveryReauthorizationRequired
}

func fixedCurrentDiscoveryStorageError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(ErrCurrentDiscoveryRecoveryRequired, err)
	}
	if errors.Is(err, storage.ErrLifecycleConflict) {
		return ErrCurrentDiscoveryInactiveAccount
	}
	if errors.Is(err, storage.ErrCurrentDiscoveryConflict) || errors.Is(err, storage.ErrCursorConflict) {
		return ErrCurrentDiscoveryConflict
	}
	return ErrCurrentDiscoveryRecoveryRequired
}

func currentDiscoverySleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func currentDiscoveryTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		DisableKeepAlives:     true,
		MaxIdleConns:          32,
		IdleConnTimeout:       30 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

func rejectCurrentDiscoveryRedirect(*http.Request, []*http.Request) error {
	return errCurrentDiscoveryRedirect
}

func validCurrentDiscoveryEndpoints(endpoints currentDiscoveryEndpoints) bool {
	production := currentDiscoveryEndpoints{token: productionTokenEndpoint, history: productionGmailHistoryEndpoint, message: productionGmailMessageEndpoint}
	if endpoints == production {
		return true
	}
	for _, value := range []string{endpoints.token, endpoints.history, endpoints.message} {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Hostname() == "" {
			return false
		}
		address := net.ParseIP(parsed.Hostname())
		if address == nil || !address.IsLoopback() {
			return false
		}
	}
	return true
}

func jsonContentType(value string) bool {
	mediaType := strings.TrimSpace(strings.Split(value, ";")[0])
	return mediaType == "application/json"
}

func validBoundedText(value string, maximum int) bool {
	if len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	return strings.IndexFunc(value, unicode.IsControl) < 0
}
