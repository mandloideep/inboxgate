package gmail

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mandloideep/inboxgate/internal/cryptobox"
	maildomain "github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
)

var candidateContentFields = buildCandidateContentFields()

var (
	ErrCandidateContentInvalidRequest          = errors.New("gmail candidate content: invalid request")
	ErrCandidateContentIneligible              = errors.New("gmail candidate content: ineligible")
	ErrCandidateContentInactiveAccount         = errors.New("gmail candidate content: inactive account")
	ErrCandidateContentUnavailable             = errors.New("gmail candidate content: unavailable")
	ErrCandidateContentVanished                = errors.New("gmail candidate content: message vanished")
	ErrCandidateContentReauthorizationRequired = errors.New("gmail candidate content: reauthorization required")
	ErrCandidateContentConflict                = errors.New("gmail candidate content: conflict")
	ErrCandidateContentRecoveryRequired        = errors.New("gmail candidate content: recovery required")
)

type candidateContentOptions struct {
	clientID     []byte
	clientSecret []byte
	store        storage.Handle
	keyring      *cryptobox.Keyring
}

type candidateContentEndpoints struct {
	token   string
	message string
}

type candidateContentDependencies struct {
	endpoints      candidateContentEndpoints
	transport      http.RoundTripper
	jitter         io.Reader
	sleep          func(context.Context, time.Duration) error
	now            func() time.Time
	cleanupTimeout time.Duration
}

// CandidateContentExtractor performs one inert bounded content extraction.
type CandidateContentExtractor struct {
	invokeMu sync.Mutex
	store    storage.Handle
	auth     *CurrentDiscovery
	now      func() time.Time
	closed   bool
}

type candidateContentPreflight struct {
	lifecycle storage.AccountLifecycle
	message   maildomain.Message
	decision  storage.GateDecision
	refresh   []byte
}

func NewCandidateContentExtractor(clientID, clientSecret []byte, store storage.Handle, keyring *cryptobox.Keyring) (*CandidateContentExtractor, error) {
	return newCandidateContentExtractor(candidateContentOptions{clientID: clientID, clientSecret: clientSecret, store: store, keyring: keyring}, candidateContentDependencies{})
}

func newCandidateContentExtractor(options candidateContentOptions, dependencies candidateContentDependencies) (*CandidateContentExtractor, error) {
	if options.store == nil || options.keyring == nil {
		return nil, ErrCandidateContentInvalidRequest
	}
	if dependencies.endpoints == (candidateContentEndpoints{}) {
		dependencies.endpoints = candidateContentEndpoints{token: productionTokenEndpoint, message: productionGmailMessageEndpoint}
	}
	endpoints := currentDiscoveryEndpoints{token: dependencies.endpoints.token, history: dependencies.endpoints.message, message: dependencies.endpoints.message}
	if !validCurrentDiscoveryEndpoints(endpoints) {
		return nil, ErrCandidateContentInvalidRequest
	}
	auth, err := newCurrentDiscovery(currentDiscoveryOptions{clientID: options.clientID, clientSecret: options.clientSecret, pageSize: 1, store: options.store, keyring: options.keyring}, currentDiscoveryDependencies{
		endpoints: endpoints, transport: dependencies.transport, jitter: dependencies.jitter,
		sleep: dependencies.sleep, cleanupTimeout: dependencies.cleanupTimeout,
	})
	if err != nil {
		return nil, ErrCandidateContentInvalidRequest
	}
	if dependencies.now == nil {
		dependencies.now = time.Now
	}
	return &CandidateContentExtractor{store: options.store, auth: auth, now: dependencies.now}, nil
}

func (extractor *CandidateContentExtractor) Close() {
	if extractor == nil {
		return
	}
	extractor.invokeMu.Lock()
	defer extractor.invokeMu.Unlock()
	if extractor.closed {
		return
	}
	extractor.closed = true
	if extractor.auth != nil {
		extractor.auth.Close()
	}
}

func (extractor *CandidateContentExtractor) Extract(ctx context.Context, accountID storage.AccountID, gmailMessageID string, excerptLimit int) (maildomain.CandidateContent, error) {
	if extractor != nil {
		extractor.invokeMu.Lock()
		defer extractor.invokeMu.Unlock()
	}
	if extractor == nil || extractor.closed || extractor.store == nil || extractor.auth == nil || extractor.now == nil || ctx == nil || excerptLimit < maildomain.MinimumExcerptBytes || excerptLimit > maildomain.MaximumExcerptBytes {
		return maildomain.CandidateContent{}, ErrCandidateContentInvalidRequest
	}
	if parsed, err := storage.ParseAccountID(accountID.String()); err != nil || parsed != accountID || storage.ValidateGmailMessageID(gmailMessageID) != nil {
		return maildomain.CandidateContent{}, ErrCandidateContentInvalidRequest
	}
	preflight, err := extractor.preflight(ctx, accountID, gmailMessageID, excerptLimit)
	if err != nil {
		return maildomain.CandidateContent{}, err
	}
	if preflight.refresh == nil {
		state, stateErr := extractor.store.GetCandidateContent(ctx, accountID, gmailMessageID, excerptLimit)
		if stateErr == nil && state.Current {
			return state.Content, nil
		}
		return maildomain.CandidateContent{}, ErrCandidateContentRecoveryRequired
	}
	defer clear(preflight.refresh)
	access, classification, err := extractor.auth.refreshAccessToken(ctx, preflight.refresh)
	if err != nil {
		if classification == refreshInvalidGrant {
			return maildomain.CandidateContent{}, extractor.markReauthorization(accountID, preflight.lifecycle, storage.ReauthorizationReasonRefreshInvalidGrant)
		}
		if classification == refreshAdminPolicy {
			return maildomain.CandidateContent{}, extractor.markReauthorization(accountID, preflight.lifecycle, storage.ReauthorizationReasonRefreshAdminPolicyEnforced)
		}
		return maildomain.CandidateContent{}, fixedCandidateContentProviderError(err)
	}
	defer clear(access)
	if err := extractor.verifyPreflight(ctx, accountID, gmailMessageID, preflight); err != nil {
		return maildomain.CandidateContent{}, err
	}
	target, err := extractor.contentURL(gmailMessageID)
	if err != nil {
		return maildomain.CandidateContent{}, ErrCandidateContentInvalidRequest
	}
	status, body, err := extractor.auth.gmailGET(ctx, target, access, MaximumCandidateContentBodyBytes)
	if err != nil {
		return maildomain.CandidateContent{}, fixedCandidateContentProviderError(err)
	}
	defer clear(body)
	switch status {
	case http.StatusUnauthorized:
		return maildomain.CandidateContent{}, extractor.markReauthorization(accountID, preflight.lifecycle, storage.ReauthorizationReasonGmailUnauthorizedAfterRefresh)
	case http.StatusForbidden:
		reason, exact := exactGoogleErrorReason(body)
		if exact && reason == "domainPolicy" {
			return maildomain.CandidateContent{}, extractor.markReauthorization(accountID, preflight.lifecycle, storage.ReauthorizationReasonGmailDomainPolicy)
		}
		return maildomain.CandidateContent{}, ErrCandidateContentUnavailable
	case http.StatusNotFound:
		return maildomain.CandidateContent{}, ErrCandidateContentVanished
	case http.StatusOK:
	default:
		return maildomain.CandidateContent{}, ErrCandidateContentUnavailable
	}
	kind, excerpt, truncated, err := decodeCandidateContentResponse(body, preflight.message.GmailMessageID(), preflight.message.GmailThreadID(), excerptLimit)
	if err != nil {
		return maildomain.CandidateContent{}, ErrCandidateContentUnavailable
	}
	timestamp := extractor.now().UnixMilli()
	next, err := maildomain.NewCandidateContent(maildomain.CandidateContentInput{
		RecordID: preflight.message.RecordID(), SourceMetadataHash: preflight.message.MetadataHash(), GateVersion: preflight.decision.Version(),
		GateInputHash: preflight.decision.InputHash(), SourceKind: kind, Excerpt: excerpt, ExcerptLimit: excerptLimit,
		Truncated: truncated, FetchedAtUnixMS: timestamp,
	})
	if err != nil {
		return maildomain.CandidateContent{}, ErrCandidateContentUnavailable
	}
	commit := storage.CandidateContentCommit{Source: preflight.message, Gate: preflight.decision, LifecycleVersion: preflight.lifecycle.Version, Next: next}
	prior, priorErr := extractor.store.GetCandidateContent(ctx, accountID, gmailMessageID, excerptLimit)
	if priorErr == nil {
		if prior.Current && prior.Content.SemanticEqual(next) {
			return prior.Content, nil
		}
		revision := prior.Content.Revision()
		commit.Expected = &revision
	} else if !errors.Is(priorErr, storage.ErrCandidateContentNotFound) {
		return maildomain.CandidateContent{}, fixedCandidateContentStorageError(priorErr)
	}
	if err := extractor.store.CommitCandidateContent(ctx, commit); err != nil {
		return maildomain.CandidateContent{}, fixedCandidateContentCommitError(err)
	}
	durable, err := extractor.store.GetCandidateContent(ctx, accountID, gmailMessageID, excerptLimit)
	if err != nil || !durable.Current || !durable.Content.SemanticEqual(next) {
		return maildomain.CandidateContent{}, fixedCandidateContentStorageError(err)
	}
	return durable.Content, nil
}

func (extractor *CandidateContentExtractor) preflight(ctx context.Context, accountID storage.AccountID, gmailMessageID string, excerptLimit int) (candidateContentPreflight, error) {
	lifecycle, err := extractor.store.GetAccountLifecycle(ctx, accountID)
	if err != nil {
		return candidateContentPreflight{}, fixedCandidateContentStorageError(err)
	}
	if inactiveLifecycle(lifecycle) {
		return candidateContentPreflight{}, ErrCandidateContentInactiveAccount
	}
	if !validActiveLifecycle(lifecycle, accountID) || lifecycle.Version.Int64() == math.MaxInt64 {
		return candidateContentPreflight{}, ErrCandidateContentRecoveryRequired
	}
	message, err := extractor.store.GetDiscoveredMessage(ctx, accountID, gmailMessageID)
	if err != nil {
		return candidateContentPreflight{}, fixedCandidateContentStorageError(err)
	}
	decision, err := extractor.store.GetGateDecision(ctx, accountID, gmailMessageID)
	if err != nil {
		return candidateContentPreflight{}, fixedCandidateContentStorageError(err)
	}
	if !decision.Current || decision.Decision.SourceMetadataHash() != message.MetadataHash() || !storage.CandidateOutcome(decision.Decision.Outcome()) {
		return candidateContentPreflight{}, ErrCandidateContentIneligible
	}
	if state, contentErr := extractor.store.GetCandidateContent(ctx, accountID, gmailMessageID, excerptLimit); contentErr == nil && state.Current {
		return candidateContentPreflight{lifecycle: lifecycle, message: message, decision: decision.Decision}, nil
	} else if contentErr != nil && !errors.Is(contentErr, storage.ErrCandidateContentNotFound) {
		return candidateContentPreflight{}, fixedCandidateContentStorageError(contentErr)
	}
	credential, err := extractor.store.GetProviderCredential(ctx, accountID)
	if err != nil || credential.AccountID != accountID || credential.KeyID != credential.Envelope.KeyID() {
		return candidateContentPreflight{}, fixedCandidateContentStorageError(err)
	}
	refresh, err := extractor.auth.keyring.DecryptRefreshToken(accountID.String(), credential.Envelope.String())
	if err != nil || len(refresh) < 1 || len(refresh) > storage.MaximumCredentialPlaintextBytes {
		clear(refresh)
		return candidateContentPreflight{}, ErrCandidateContentRecoveryRequired
	}
	return candidateContentPreflight{lifecycle: lifecycle, message: message, decision: decision.Decision, refresh: refresh}, nil
}

func (extractor *CandidateContentExtractor) verifyPreflight(ctx context.Context, accountID storage.AccountID, gmailMessageID string, expected candidateContentPreflight) error {
	lifecycle, err := extractor.store.GetAccountLifecycle(ctx, accountID)
	if err != nil {
		return fixedCandidateContentStorageError(err)
	}
	if inactiveLifecycle(lifecycle) {
		return ErrCandidateContentInactiveAccount
	}
	message, messageErr := extractor.store.GetDiscoveredMessage(ctx, accountID, gmailMessageID)
	decision, decisionErr := extractor.store.GetGateDecision(ctx, accountID, gmailMessageID)
	if messageErr != nil || decisionErr != nil {
		return fixedCandidateContentStorageError(errors.Join(messageErr, decisionErr))
	}
	if !sameLifecycle(lifecycle, expected.lifecycle) || !message.Equal(expected.message) || !decision.Current || !decision.Decision.Equal(expected.decision) || !storage.CandidateOutcome(decision.Decision.Outcome()) {
		return ErrCandidateContentConflict
	}
	return nil
}

func (extractor *CandidateContentExtractor) contentURL(messageID string) (string, error) {
	if storage.ValidateGmailMessageID(messageID) != nil {
		return "", storage.ErrInvalidValue
	}
	parsed, err := url.Parse(extractor.auth.endpoints.message)
	if err != nil {
		return "", err
	}
	parsed.RawPath = strings.TrimSuffix(parsed.EscapedPath(), "/") + "/" + url.PathEscape(messageID)
	parsed.Path = strings.TrimSuffix(parsed.Path, "/") + "/" + messageID
	parsed.RawQuery = url.Values{"format": {"FULL"}, "fields": {candidateContentFields}}.Encode()
	return parsed.String(), nil
}

func (extractor *CandidateContentExtractor) markReauthorization(accountID storage.AccountID, lifecycle storage.AccountLifecycle, reason storage.ReauthorizationReason) error {
	err := extractor.auth.markReauthorization(accountID, lifecycle, reason)
	if errors.Is(err, ErrCurrentDiscoveryReauthorizationRequired) {
		return ErrCandidateContentReauthorizationRequired
	}
	return ErrCandidateContentRecoveryRequired
}

func fixedCandidateContentProviderError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(ErrCandidateContentUnavailable, err)
	}
	return ErrCandidateContentUnavailable
}

func fixedCandidateContentStorageError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(ErrCandidateContentRecoveryRequired, err)
	}
	switch {
	case errors.Is(err, storage.ErrLifecycleConflict):
		return ErrCandidateContentInactiveAccount
	case errors.Is(err, storage.ErrCandidateContentConflict), errors.Is(err, storage.ErrCandidateContentStaleSource):
		return ErrCandidateContentConflict
	case errors.Is(err, storage.ErrCandidateContentIneligible), errors.Is(err, storage.ErrGateDecisionNotFound):
		return ErrCandidateContentIneligible
	default:
		return ErrCandidateContentRecoveryRequired
	}
}

func fixedCandidateContentCommitError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(ErrCandidateContentRecoveryRequired, err)
	}
	switch {
	case errors.Is(err, storage.ErrLifecycleConflict):
		return ErrCandidateContentInactiveAccount
	case errors.Is(err, storage.ErrCandidateContentConflict), errors.Is(err, storage.ErrCandidateContentStaleSource), errors.Is(err, storage.ErrCandidateContentIneligible), errors.Is(err, storage.ErrGateDecisionNotFound):
		return ErrCandidateContentConflict
	default:
		return ErrCandidateContentRecoveryRequired
	}
}

func buildCandidateContentFields() string {
	part := "mimeType,headers(name,value),filename,body(size,data,attachmentId)"
	for depth := MaximumMessagePartDepth - 1; depth >= 1; depth-- {
		part = "mimeType,headers(name,value),filename,body(size,data,attachmentId),parts(" + part + ")"
	}
	return "id,threadId,payload(mimeType,headers(name,value),filename,body(size,data,attachmentId),parts(" + part + "))"
}

var _ = (*CandidateContentExtractor)(nil)
