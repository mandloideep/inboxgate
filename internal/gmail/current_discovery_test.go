package gmail

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/cryptobox"
	maildomain "github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
	storagefake "github.com/mandloideep/inboxgate/internal/storage/fake"
)

const (
	discoveryAccountText = "11111111111111111111111111111111"
	discoveryStartCursor = "100"
	discoveryNextCursor  = "104"
	discoveryRefreshText = "synthetic-refresh-material"
	discoveryAccessText  = "synthetic-access-material"
)

var discoveryLoopbackEndpoints = currentDiscoveryEndpoints{
	token:   "http://127.0.0.1/token",
	history: "http://127.0.0.1/gmail/v1/users/me/history",
	message: "http://127.0.0.1/gmail/v1/users/me/messages/",
}

func TestCurrentDiscoverySyntheticFlowIsExactAndAtomic(t *testing.T) {
	fixture := newDiscoveryFixture(t, 500)
	var requests []*http.Request
	fixture.transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, cloneRequest(t, request))
		switch request.URL.Path {
		case "/token":
			assertRefreshRequest(t, request)
			return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
		case "/gmail/v1/users/me/history":
			pageToken := request.URL.Query().Get("pageToken")
			assertHistoryRequest(t, request, discoveryStartCursor, pageToken, 500)
			if pageToken == "opaque-page" {
				return jsonResponse(http.StatusOK, `{"historyId":"102"}`), nil
			}
			return jsonResponse(http.StatusOK, `{"history":[{"id":"101","messagesAdded":[{"message":{"id":"message-b","threadId":"thread-b"}},{"message":{"id":"message-a","threadId":"thread-a"}},{"message":{"id":"message-a","threadId":"thread-a"}}]}],"historyId":"102","nextPageToken":"opaque-page"}`), nil
		case "/gmail/v1/users/me/messages/message-a":
			assertMessageRequest(t, request, "message-a")
			return jsonResponse(http.StatusOK, messageJSON("message-a", "thread-a", []headerFixture{
				{name: "from", value: "=?UTF-8?Q?Synthetic_Sender?= <sender@example.test>"},
				{name: "TO", value: "B <b@example.test>, a@example.test"},
				{name: "Cc", value: "broken address"},
				{name: "Delivered-To", value: "delivered@example.test"},
				{name: "Subject", value: "=?UTF-8?Q?Bounded_subject?="},
				{name: "Message-ID", value: "<synthetic-a@example.test>"},
				{name: "List-ID", value: "list.example.test"},
				{name: "List-Unsubscribe", value: "untrusted-presence"},
				{name: "Auto-Submitted", value: "no"},
				{name: "Precedence", value: "list"},
				{name: "X-Unselected", value: "discard-me"},
			}, []any{partFixture("note.txt", ""), partFixture("", "attachment-a"), partFixture("both.bin", "attachment-b")})), nil
		case "/gmail/v1/users/me/messages/message-b":
			assertMessageRequest(t, request, "message-b")
			return jsonResponse(http.StatusNotFound, `{}`), nil
		default:
			t.Fatalf("unexpected provider path %q", request.URL.Path)
			return nil, errors.New("unreachable synthetic transport")
		}
	})
	discovery := fixture.discovery(t)
	result, err := discovery.Discover(context.Background(), fixture.accountID)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	want := CurrentDiscoveryResult{HistoryPagesRead: 2, UniqueMessageAdditions: 2, MessagesCommitted: 1, VanishedMessages: 1, CursorAdvanced: true}
	if result != want {
		t.Fatalf("result = %#v, want %#v", result, want)
	}
	if fixture.store.commitCount != 1 || fixture.store.cursorOnlyWrites != 0 {
		t.Fatalf("aggregate commits = %d, cursor-only writes = %d", fixture.store.commitCount, fixture.store.cursorOnlyWrites)
	}
	if len(fixture.store.lastCommit.Messages) != 1 || fixture.store.lastCommit.Expected.String() != discoveryStartCursor || fixture.store.lastCommit.Next.String() != "102" {
		t.Fatalf("aggregate commit = %#v", fixture.store.lastCommit)
	}
	stored, err := fixture.store.GetDiscoveredMessage(context.Background(), fixture.accountID, "message-a")
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(stored.CanonicalJSON(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["sender_display"] != "Synthetic Sender" || metadata["sender_address"] != "sender@example.test" || metadata["subject"] != "Bounded subject" || metadata["attachment_count"] != float64(3) || metadata["list_unsubscribe"] != true {
		t.Fatalf("canonical metadata = %s", stored.CanonicalJSON())
	}
	if got := metadata["to"].([]any); len(got) != 2 || got[0] != "a@example.test" || got[1] != "b@example.test" {
		t.Fatalf("canonical recipients = %#v", got)
	}
	if got := metadata["cc"].([]any); len(got) != 0 {
		t.Fatalf("malformed optional recipients = %#v", got)
	}
	if strings.Contains(string(stored.CanonicalJSON()), "discard-me") || strings.Contains(string(stored.CanonicalJSON()), "note.txt") || strings.Contains(string(stored.CanonicalJSON()), "attachment-a") {
		t.Fatal("transient provider metadata was persisted")
	}
	cursor, err := fixture.store.GetSynchronizationCursor(context.Background(), fixture.accountID)
	if err != nil || cursor.HistoryID.String() != "102" {
		t.Fatalf("cursor = %#v, error = %v", cursor, err)
	}
	if len(requests) != 5 || fixture.store.actions[0] != "reconcile" {
		t.Fatalf("requests = %d, storage actions = %#v", len(requests), fixture.store.actions)
	}
	assertBoundedResultDoesNotDisclose(t, result)
}

func TestCurrentDiscoveryPreflightOrderAndFailuresPreventProviderContact(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*discoveryFixture)
		wantError error
	}{
		{name: "reconciliation", mutate: func(f *discoveryFixture) { f.store.failReconcile = storage.ErrCurrentDiscoveryRecoveryRequired }, wantError: ErrCurrentDiscoveryRecoveryRequired},
		{name: "paused", mutate: func(f *discoveryFixture) { f.store.lifecycleOverride = lifecycleWith(storage.AccountStatePaused, 2) }, wantError: ErrCurrentDiscoveryInactiveAccount},
		{name: "reauthorization", mutate: func(f *discoveryFixture) {
			f.store.lifecycleOverride = lifecycleWith(storage.AccountStateReauthorizationRequired, 2)
		}, wantError: ErrCurrentDiscoveryInactiveAccount},
		{name: "revoked", mutate: func(f *discoveryFixture) { f.store.lifecycleOverride = lifecycleWith(storage.AccountStateRevoked, 2) }, wantError: ErrCurrentDiscoveryInactiveAccount},
		{name: "version exhausted", mutate: func(f *discoveryFixture) {
			f.store.lifecycleOverride = lifecycleWith(storage.AccountStateActive, math.MaxInt64)
		}, wantError: ErrCurrentDiscoveryRecoveryRequired},
		{name: "cursor missing", mutate: func(f *discoveryFixture) { f.store.failCursor = storage.ErrCursorNotFound }, wantError: ErrCurrentDiscoveryRecoveryRequired},
		{name: "credential missing", mutate: func(f *discoveryFixture) { f.store.failCredential = storage.ErrCredentialNotFound }, wantError: ErrCurrentDiscoveryRecoveryRequired},
		{name: "ciphertext authentication", mutate: func(f *discoveryFixture) { f.store.credentialOverride = malformedCredential(t) }, wantError: ErrCurrentDiscoveryRecoveryRequired},
		{name: "lifecycle changed", mutate: func(f *discoveryFixture) {
			f.store.secondLifecycleOverride = lifecycleWith(storage.AccountStatePaused, 3)
		}, wantError: ErrCurrentDiscoveryInactiveAccount},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDiscoveryFixture(t, 100)
			test.mutate(fixture)
			providerCalls := 0
			fixture.transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				providerCalls++
				return nil, errors.New("provider contact is forbidden")
			})
			_, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
			if !errors.Is(err, test.wantError) || providerCalls != 0 {
				t.Fatalf("error = %v, provider calls = %d", err, providerCalls)
			}
			if len(fixture.store.actions) == 0 || fixture.store.actions[0] != "reconcile" || fixture.store.commitCount != 0 || fixture.store.cursorOnlyWrites != 0 {
				t.Fatalf("storage actions = %#v", fixture.store.actions)
			}
		})
	}
}

func TestCurrentDiscoveryConfigurationBoundsFailBeforeStorage(t *testing.T) {
	for _, pageSize := range []int{0, 501} {
		store := &discoveryStoreProbe{Handle: storagefake.New()}
		_, err := newCurrentDiscovery(currentDiscoveryOptions{clientID: []byte(syntheticClientID), clientSecret: []byte(syntheticClientSecret), pageSize: pageSize, store: store, keyring: syntheticKeyring(t)}, currentDiscoveryDependencies{})
		if !errors.Is(err, ErrCurrentDiscoveryInvalidRequest) || len(store.actions) != 0 {
			t.Fatalf("page size %d error = %v, actions = %#v", pageSize, err, store.actions)
		}
	}
	for _, pageSize := range []int{1, 500} {
		fixture := newDiscoveryFixture(t, pageSize)
		fixture.transport = successfulNoChangeTransport(t, pageSize)
		result, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
		if err != nil || result.HistoryPagesRead != 1 || result.CursorAdvanced || fixture.store.commitCount != 0 {
			t.Fatalf("page size %d result = %#v, error = %v", pageSize, result, err)
		}
	}
}

func TestCurrentDiscoveryRefreshContractAndClassifications(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		content    string
		body       string
		want       error
		wantReason storage.ReauthorizationReason
	}{
		{name: "malformed response", status: 200, content: "application/json", body: `{`, want: ErrCurrentDiscoveryRefreshFailed},
		{name: "duplicate field", status: 200, content: "application/json", body: `{"access_token":"a","access_token":"b","token_type":"Bearer","expires_in":3600}`, want: ErrCurrentDiscoveryRefreshFailed},
		{name: "noncanonical duration", status: 200, content: "application/json", body: `{"access_token":"a","token_type":"Bearer","expires_in":3.6e3}`, want: ErrCurrentDiscoveryRefreshFailed},
		{name: "excessive duration", status: 200, content: "application/json", body: `{"access_token":"a","token_type":"Bearer","expires_in":86401}`, want: ErrCurrentDiscoveryRefreshFailed},
		{name: "wrong token type", status: 200, content: "application/json", body: `{"access_token":"a","token_type":"bearer","expires_in":3600}`, want: ErrCurrentDiscoveryRefreshFailed},
		{name: "scope drift", status: 200, content: "application/json", body: `{"access_token":"a","token_type":"Bearer","expires_in":3600,"scope":"openid"}`, want: ErrCurrentDiscoveryRefreshFailed},
		{name: "refresh rotation", status: 200, content: "application/json", body: `{"access_token":"a","token_type":"Bearer","expires_in":3600,"refresh_token":"replacement"}`, want: ErrCurrentDiscoveryRefreshFailed},
		{name: "wrong content type", status: 200, content: "text/plain", body: refreshSuccessJSON(), want: ErrCurrentDiscoveryRefreshFailed},
		{name: "invalid grant", status: 400, content: "application/json", body: `{"error":"invalid_grant"}`, want: ErrCurrentDiscoveryReauthorizationRequired, wantReason: storage.ReauthorizationReasonRefreshInvalidGrant},
		{name: "admin policy", status: 400, content: "application/json", body: `{"error":"admin_policy_enforced"}`, want: ErrCurrentDiscoveryReauthorizationRequired, wantReason: storage.ReauthorizationReasonRefreshAdminPolicyEnforced},
		{name: "conflicting oauth error", status: 400, content: "application/json", body: `{"error":"invalid_grant","error_description":"synthetic"}`, want: ErrCurrentDiscoveryRefreshFailed},
		{name: "transient status", status: 503, content: "application/json", body: `{}`, want: ErrCurrentDiscoveryRefreshFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDiscoveryFixture(t, 100)
			calls := 0
			fixture.transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				assertRefreshRequest(t, request)
				response := jsonResponse(test.status, test.body)
				response.Header.Set("Content-Type", test.content)
				return response, nil
			})
			_, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
			if !errors.Is(err, test.want) || calls != 1 {
				t.Fatalf("error = %v, calls = %d", err, calls)
			}
			lifecycle, lifecycleErr := fixture.store.Handle.GetAccountLifecycle(context.Background(), fixture.accountID)
			if lifecycleErr != nil {
				t.Fatal(lifecycleErr)
			}
			if test.wantReason.String() == "" {
				if lifecycle.State != storage.AccountStateActive {
					t.Fatalf("unexpected lifecycle = %#v", lifecycle)
				}
			} else if lifecycle.State != storage.AccountStateReauthorizationRequired || lifecycle.ReauthorizationReason == nil || *lifecycle.ReauthorizationReason != test.wantReason {
				t.Fatalf("lifecycle = %#v", lifecycle)
			}
			assertCursorAndCredentialUnchanged(t, fixture)
		})
	}
}

func TestCurrentDiscoveryJSONNamesAndUnicodeAreByteExactAtEveryLevel(t *testing.T) {
	validHistory := `{"history":[{"id":"101","messagesAdded":[{"message":{"id":"message-1","threadId":"thread-1"}}]}],"historyId":"102"}`
	historyCases := []string{
		strings.Replace(validHistory, `"history"`, `"History"`, 1),
		strings.Replace(validHistory, `"id":"101"`, `"ID":"101"`, 1),
		strings.Replace(validHistory, `"messagesAdded"`, `"MessagesAdded"`, 1),
		strings.Replace(validHistory, `"message"`, `"Message"`, 1),
		strings.Replace(validHistory, `"id":"message-1"`, `"ID":"message-1"`, 1),
		strings.Replace(validHistory, `"threadId"`, `"ThreadId"`, 1),
		strings.Replace(validHistory, `"historyId"`, `"HistoryId"`, 1),
		strings.Replace(validHistory, `"historyId":"102"`, `"historyId":"102","HistoryId":"102"`, 1),
		`{"historyId":"102","nextPageToken":"\ud800"}`,
	}
	for index, body := range historyCases {
		if _, err := decodeHistoryPage([]byte(body)); !errors.Is(err, ErrCurrentDiscoveryInvalidProviderResponse) {
			t.Fatalf("history case %d error = %v", index, err)
		}
	}
	invalidHistoryUTF8 := append([]byte(`{"historyId":"102","nextPageToken":"`), 0xff)
	invalidHistoryUTF8 = append(invalidHistoryUTF8, []byte(`"}`)...)
	if _, err := decodeHistoryPage(invalidHistoryUTF8); !errors.Is(err, ErrCurrentDiscoveryInvalidProviderResponse) {
		t.Fatalf("invalid UTF-8 history error = %v", err)
	}

	validMessage := messageJSON("message-1", "thread-1", []headerFixture{{name: "Subject", value: "synthetic"}}, []any{partFixture("", "")})
	messageCases := []string{
		strings.Replace(validMessage, `"id":`, `"ID":`, 1),
		strings.Replace(validMessage, `"threadId":`, `"ThreadId":`, 1),
		strings.Replace(validMessage, `"labelIds":`, `"LabelIds":`, 1),
		strings.Replace(validMessage, `"internalDate":`, `"InternalDate":`, 1),
		strings.Replace(validMessage, `"sizeEstimate":`, `"SizeEstimate":`, 1),
		strings.Replace(validMessage, `"payload":`, `"Payload":`, 1),
		strings.Replace(validMessage, `"headers":`, `"Headers":`, 1),
		strings.Replace(validMessage, `"name":"Subject"`, `"Name":"Subject"`, 1),
		strings.Replace(validMessage, `"value":"synthetic"`, `"Value":"synthetic"`, 1),
		strings.Replace(validMessage, `"filename":`, `"Filename":`, 1),
		strings.Replace(validMessage, `"body":`, `"Body":`, 1),
		strings.Replace(validMessage, `"attachmentId":`, `"AttachmentId":`, 1),
		strings.Replace(validMessage, `"parts":`, `"Parts":`, 1),
		replaceNth(validMessage, `"filename":`, `"Filename":`, 2),
		replaceNth(validMessage, `"body":`, `"Body":`, 2),
		replaceNth(validMessage, `"attachmentId":`, `"AttachmentId":`, 2),
		replaceNth(validMessage, `"parts":`, `"Parts":`, 2),
		strings.Replace(validMessage, `"id":"message-1"`, `"id":"message-1","ID":"message-1"`, 1),
		strings.Replace(validMessage, `"value":"synthetic"`, `"value":"\ud800"`, 1),
		messageJSON("message-1", "thread-1", nil, []any{map[string]any{"PartId": nil}}),
	}
	for index, body := range messageCases {
		if _, err := decodeMessageMetadata([]byte(body), discoveredIdentity{messageID: "message-1", threadID: "thread-1"}); !errors.Is(err, ErrCurrentDiscoveryInvalidProviderResponse) {
			t.Fatalf("message case %d error = %v", index, err)
		}
	}
	messagePrefix, messageSuffix, found := strings.Cut(validMessage, "synthetic")
	if !found {
		t.Fatal("invalid UTF-8 fixture target is missing")
	}
	invalidMessageUTF8 := append([]byte(messagePrefix), 0xff)
	invalidMessageUTF8 = append(invalidMessageUTF8, []byte(messageSuffix)...)
	if _, err := decodeMessageMetadata(invalidMessageUTF8, discoveredIdentity{messageID: "message-1", threadID: "thread-1"}); !errors.Is(err, ErrCurrentDiscoveryInvalidProviderResponse) {
		t.Fatalf("invalid UTF-8 message error = %v", err)
	}

	errorCases := []string{
		strings.Replace(googleErrorJSON("domainPolicy"), `"error"`, `"Error"`, 1),
		strings.Replace(googleErrorJSON("domainPolicy"), `"code"`, `"Code"`, 1),
		strings.Replace(googleErrorJSON("domainPolicy"), `"message"`, `"Message"`, 1),
		strings.Replace(googleErrorJSON("domainPolicy"), `"status"`, `"Status"`, 1),
		strings.Replace(googleErrorJSON("domainPolicy"), `"errors"`, `"Errors"`, 1),
		replaceNth(googleErrorJSON("domainPolicy"), `"domain"`, `"Domain"`, 1),
		replaceNth(googleErrorJSON("domainPolicy"), `"message"`, `"Message"`, 2),
		strings.Replace(googleErrorJSON("domainPolicy"), `"reason"`, `"Reason"`, 1),
		strings.Replace(googleErrorJSON("domainPolicy"), `"reason":"domainPolicy"`, `"reason":"domainPolicy","Reason":"domainPolicy"`, 1),
		strings.Replace(googleErrorJSON("domainPolicy"), `"message":"synthetic"`, `"message":"\ud800"`, 1),
	}
	for index, body := range errorCases {
		if reason, exact := exactGoogleErrorReason([]byte(body)); exact || reason != "" {
			t.Fatalf("error case %d classified as %q", index, reason)
		}
	}

	refreshCases := []string{
		strings.Replace(refreshSuccessJSON(), `"access_token"`, `"Access_token"`, 1),
		strings.Replace(refreshSuccessJSON(), `"access_token":"`+discoveryAccessText+`"`, `"access_token":"`+discoveryAccessText+`","Access_token":"other"`, 1),
		strings.Replace(refreshSuccessJSON(), discoveryAccessText, `\ud800`, 1),
	}
	for index, body := range refreshCases {
		if err := validateRefreshSuccess([]byte(body)); err == nil {
			t.Fatalf("refresh case %d error = %v", index, err)
		}
	}
}

func TestCurrentDiscoveryRefreshRejectsOversizeRedirectAndCancellation(t *testing.T) {
	tests := []struct {
		name      string
		transport http.RoundTripper
		cancel    bool
	}{
		{name: "oversized", transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, strings.Repeat("x", MaximumProviderErrorBodyBytes+1)), nil
		})},
		{name: "redirect", transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			response := jsonResponse(http.StatusFound, `{}`)
			response.Header.Set("Location", "http://127.0.0.1/other")
			return response, nil
		})},
		{name: "cancellation", transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			<-request.Context().Done()
			return nil, request.Context().Err()
		}), cancel: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDiscoveryFixture(t, 100)
			fixture.transport = test.transport
			ctx := context.Background()
			if test.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				fixture.transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
					cancel()
					return test.transport.RoundTrip(request)
				})
			}
			_, err := fixture.discovery(t).Discover(ctx, fixture.accountID)
			if !errors.Is(err, ErrCurrentDiscoveryRefreshFailed) || test.cancel && !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestCurrentDiscoveryHistoryValidationAndCursorRules(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		status     int
		want       error
		wantCommit int
	}{
		{name: "absent history no change", body: `{"historyId":"100"}`, status: 200, wantCommit: 0},
		{name: "filtered advance", body: `{"historyId":"101"}`, status: 200, wantCommit: 1},
		{name: "stale cursor", body: `{}`, status: 404, want: ErrCurrentDiscoveryHistoryCursorStale},
		{name: "missing final cursor", body: `{}`, status: 200, want: ErrCurrentDiscoveryInvalidProviderResponse},
		{name: "regressed final cursor", body: `{"historyId":"99"}`, status: 200, want: ErrCurrentDiscoveryInvalidProviderResponse},
		{name: "same cursor with addition", body: `{"history":[{"id":"101","messagesAdded":[{"message":{"id":"m","threadId":"t"}}]}],"historyId":"100"}`, status: 200, want: ErrCurrentDiscoveryInvalidProviderResponse},
		{name: "duplicate json", body: `{"historyId":"101","historyId":"102"}`, status: 200, want: ErrCurrentDiscoveryInvalidProviderResponse},
		{name: "unknown projected field", body: `{"historyId":"101","unexpected":true}`, status: 200, want: ErrCurrentDiscoveryInvalidProviderResponse},
		{name: "null history", body: `{"history":null,"historyId":"101"}`, status: 200, want: ErrCurrentDiscoveryInvalidProviderResponse},
		{name: "noncanonical record id", body: `{"history":[{"id":"0101","messagesAdded":[]}],"historyId":"101"}`, status: 200, want: ErrCurrentDiscoveryInvalidProviderResponse},
		{name: "nonincreasing records", body: `{"history":[{"id":"102","messagesAdded":[]},{"id":"101","messagesAdded":[]}],"historyId":"103"}`, status: 200, want: ErrCurrentDiscoveryInvalidProviderResponse},
		{name: "conflicting identity", body: `{"history":[{"id":"101","messagesAdded":[{"message":{"id":"m","threadId":"t1"}},{"message":{"id":"m","threadId":"t2"}}]}],"historyId":"102"}`, status: 200, want: ErrCurrentDiscoveryConflict},
		{name: "too many records", body: historyWithRecords(501), status: 200, want: ErrCurrentDiscoveryInvalidProviderResponse},
		{name: "too many additions", body: historyWithAdditions(501), status: 200, want: ErrCurrentDiscoveryInvalidProviderResponse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDiscoveryFixture(t, 500)
			messageCalls := 0
			fixture.transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				switch request.URL.Path {
				case "/token":
					return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
				case "/gmail/v1/users/me/history":
					return jsonResponse(test.status, test.body), nil
				default:
					messageCalls++
					return nil, errors.New("message request was forbidden")
				}
			})
			result, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("result = %#v, error = %v", result, err)
			}
			if fixture.store.commitCount != test.wantCommit || messageCalls != 0 {
				t.Fatalf("commit count = %d, message calls = %d", fixture.store.commitCount, messageCalls)
			}
			if test.want != nil {
				assertCursorAndCredentialUnchanged(t, fixture)
			}
		})
	}
}

func TestCurrentDiscoveryPaginationBoundsAndTokenCycles(t *testing.T) {
	tests := []struct {
		name string
		next func(int) string
		want error
	}{
		{name: "ten complete pages", next: func(page int) string {
			if page < 10 {
				return fmt.Sprintf("page-%d", page+1)
			}
			return ""
		}},
		{name: "bounded backlog", next: func(page int) string { return fmt.Sprintf("page-%d", page+1) }, want: ErrCurrentDiscoveryBoundedBacklog},
		{name: "repeated token", next: func(int) string { return "same-token" }, want: ErrCurrentDiscoveryInvalidProviderResponse},
		{name: "control token", next: func(int) string { return "bad\ntoken" }, want: ErrCurrentDiscoveryInvalidProviderResponse},
		{name: "oversized token", next: func(int) string { return strings.Repeat("p", MaximumPageTokenBytes+1) }, want: ErrCurrentDiscoveryInvalidProviderResponse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDiscoveryFixture(t, 1)
			page := 0
			fixture.transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Path == "/token" {
					return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
				}
				if request.URL.Path != "/gmail/v1/users/me/history" {
					t.Fatal("metadata requested before a complete page chain")
				}
				page++
				next := test.next(page)
				body := fmt.Sprintf(`{"historyId":"%d"`, 100+page)
				if next != "" {
					encoded, _ := json.Marshal(next)
					body += `,"nextPageToken":` + string(encoded)
				}
				return jsonResponse(http.StatusOK, body+`}`), nil
			})
			_, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("pages = %d, error = %v", page, err)
			}
			if test.want == ErrCurrentDiscoveryBoundedBacklog && page != MaximumCurrentDiscoveryPages || fixture.store.commitCount != 0 && test.want != nil {
				t.Fatalf("pages = %d, commits = %d", page, fixture.store.commitCount)
			}
		})
	}
}

func TestCurrentDiscoveryMetadataProjectionAndMIMEBounds(t *testing.T) {
	if !strings.HasPrefix(messageMetadataFields, "id,threadId,labelIds,internalDate,sizeEstimate,payload(") {
		t.Fatalf("message fields = %q", messageMetadataFields)
	}
	for _, forbidden := range []string{"snippet", "raw", "historyId", "classification", "data", "size,"} {
		if strings.Contains(messageMetadataFields, forbidden) {
			t.Fatalf("message fields contain %q: %s", forbidden, messageMetadataFields)
		}
	}
	if strings.Count(messageMetadataFields, "parts(") != MaximumMessagePartDepth+1 || !strings.Contains(messageMetadataFields, "parts(partId)") {
		t.Fatalf("finite message fields depth = %d: %s", strings.Count(messageMetadataFields, "parts("), messageMetadataFields)
	}

	tests := []struct {
		name  string
		parts []any
		want  error
	}{
		{name: "zero parts", parts: nil},
		{name: "one part", parts: []any{partFixture("", "")}},
		{name: "one thousand parts", parts: repeatedParts(1000)},
		{name: "one thousand one parts", parts: repeatedParts(1001), want: ErrCurrentDiscoveryInvalidProviderResponse},
		{name: "depth thirty two", parts: []any{nestedPart(32)}, want: nil},
		{name: "depth thirty three", parts: []any{nestedPart(33)}, want: ErrCurrentDiscoveryInvalidProviderResponse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDiscoveryFixture(t, 100)
			fixture.transport = oneMessageTransport(t, messageJSON("message-1", "thread-1", nil, test.parts))
			_, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestCurrentDiscoveryAttachmentCountingRules(t *testing.T) {
	parts := []any{
		partFixture("filename-only", ""),
		partFixture("", "attachment-only"),
		partFixture("both", "attachment-both"),
		map[string]any{"filename": "inline", "body": map[string]any{}, "parts": []any{partFixture("nested", "")}},
	}
	fixture := newDiscoveryFixture(t, 100)
	fixture.transport = oneMessageTransport(t, messageJSONWithRoot("message-1", "thread-1", "root-does-not-count", "root-id-does-not-count", nil, parts))
	_, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
	if err != nil {
		t.Fatal(err)
	}
	message := fixture.store.lastCommit.Messages[0]
	var metadata map[string]any
	_ = json.Unmarshal(message.CanonicalJSON(), &metadata)
	if metadata["attachment_count"] != float64(5) {
		t.Fatalf("attachment count = %#v", metadata["attachment_count"])
	}
}

func TestCurrentDiscoveryHeaderNormalizationIsConservative(t *testing.T) {
	longSubject := strings.Repeat("s", 4097)
	controlSubject := "bad\nsubject"
	headers := []headerFixture{
		{name: "From", value: "one@example.test"},
		{name: "From", value: "two@example.test"},
		{name: "To", value: "Good <good@example.test>"},
		{name: "To", value: "malformed"},
		{name: "Cc", value: "=?UTF-8?Q?Person?= <cc@example.test>"},
		{name: "Delivered-To", value: "delivered@example.test"},
		{name: "Subject", value: longSubject},
		{name: "Message-ID", value: "<one@example.test>"},
		{name: "Message-ID", value: "<two@example.test>"},
		{name: "List-ID", value: controlSubject},
		{name: "Auto-Submitted", value: "auto-generated"},
		{name: "Precedence", value: "bulk"},
		{name: "List-Unsubscribe", value: controlSubject},
	}
	fixture := newDiscoveryFixture(t, 100)
	fixture.transport = oneMessageTransport(t, messageJSON("message-1", "thread-1", headers, nil))
	_, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	_ = json.Unmarshal(fixture.store.lastCommit.Messages[0].CanonicalJSON(), &metadata)
	if metadata["sender_address"] != "" || metadata["subject"] != "" || metadata["rfc_message_id"] != "" || metadata["list_id"] != "" || metadata["list_unsubscribe"] != true {
		t.Fatalf("singleton normalization = %#v", metadata)
	}
	if got := metadata["to"].([]any); len(got) != 1 || got[0] != "good@example.test" {
		t.Fatalf("to = %#v", got)
	}
	if got := metadata["cc"].([]any); len(got) != 1 || got[0] != "cc@example.test" {
		t.Fatalf("cc = %#v", got)
	}
}

func TestCurrentDiscoveryHeaderAndIdentityBounds(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "too many headers", body: messageJSON("message-1", "thread-1", repeatedHeaders(MaximumMessageHeaderEntries+1), nil)},
		{name: "selected header bytes", body: messageJSON("message-1", "thread-1", []headerFixture{{name: "Subject", value: strings.Repeat("s", MaximumSelectedHeaderBytes+1)}}, nil)},
		{name: "message mismatch", body: messageJSON("different", "thread-1", nil, nil)},
		{name: "thread mismatch", body: messageJSON("message-1", "different", nil, nil)},
		{name: "body data", body: strings.Replace(messageJSON("message-1", "thread-1", nil, nil), `"body":{"attachmentId":""}`, `"body":{"attachmentId":"","data":"forbidden"}`, 1)},
		{name: "snippet", body: strings.TrimSuffix(messageJSON("message-1", "thread-1", nil, nil), "}") + `,"snippet":"forbidden"}`},
		{name: "duplicate response key", body: `{"id":"message-1","id":"message-1","threadId":"thread-1","labelIds":[],"internalDate":"1","sizeEstimate":1,"payload":{"headers":[],"body":{},"parts":[]}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDiscoveryFixture(t, 100)
			fixture.transport = oneMessageTransport(t, test.body)
			_, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
			if !errors.Is(err, ErrCurrentDiscoveryInvalidProviderResponse) || fixture.store.commitCount != 0 {
				t.Fatalf("error = %v, commits = %d", err, fixture.store.commitCount)
			}
		})
	}
}

func TestCurrentDiscoveryRetryPolicyIsBoundedAndCancelable(t *testing.T) {
	fixture := newDiscoveryFixture(t, 100)
	attempts := 0
	fixture.transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/token" {
			return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
		}
		attempts++
		if attempts <= 3 {
			response := jsonResponse(http.StatusServiceUnavailable, `{}`)
			if attempts == 1 {
				response.Header.Set("Retry-After", "3")
			}
			return response, nil
		}
		return jsonResponse(http.StatusOK, `{"historyId":"100"}`), nil
	})
	_, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != MaximumProviderAttempts || !slices.Equal(fixture.waits, []time.Duration{3 * time.Second, 2 * time.Second, 4 * time.Second}) {
		t.Fatalf("attempts = %d, waits = %v", attempts, fixture.waits)
	}

	t.Run("transport failures", func(t *testing.T) {
		fixture := newDiscoveryFixture(t, 100)
		calls := 0
		fixture.transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Path == "/token" {
				return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
			}
			calls++
			if calls < MaximumProviderAttempts {
				return nil, errors.New("synthetic transport interruption")
			}
			return jsonResponse(http.StatusOK, `{"historyId":"100"}`), nil
		})
		_, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
		if err != nil || calls != MaximumProviderAttempts || !slices.Equal(fixture.waits, []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}) {
			t.Fatalf("error = %v, calls = %d, waits = %v", err, calls, fixture.waits)
		}
	})

	for _, endpoint := range []string{"history", "message"} {
		for _, failure := range []string{"body read", "body close"} {
			t.Run(endpoint+" "+failure+" retries", func(t *testing.T) {
				fixture := newDiscoveryFixture(t, 100)
				physicalRequests := 0
				fixture.transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
					if request.URL.Path == "/token" {
						return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
					}
					if endpoint == "message" && request.URL.Path == "/gmail/v1/users/me/history" {
						return jsonResponse(http.StatusOK, `{"history":[{"id":"101","messagesAdded":[{"message":{"id":"message-1","threadId":"thread-1"}}]}],"historyId":"102"}`), nil
					}
					physicalRequests++
					if fixture.store.commitCount != 0 {
						t.Fatalf("storage committed before provider completion on attempt %d", physicalRequests)
					}
					if physicalRequests < MaximumProviderAttempts {
						if failure == "body read" {
							return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: readFailureBody{}}, nil
						}
						body := `{"historyId":"101"}`
						if endpoint == "message" {
							body = messageJSON("message-1", "thread-1", nil, nil)
						}
						return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: &closeFailureBody{Reader: strings.NewReader(body)}}, nil
					}
					if endpoint == "message" {
						return jsonResponse(http.StatusOK, messageJSON("message-1", "thread-1", nil, nil)), nil
					}
					return jsonResponse(http.StatusOK, `{"historyId":"101"}`), nil
				})
				result, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
				if err != nil || !result.CursorAdvanced || physicalRequests != MaximumProviderAttempts || fixture.store.commitCount != 1 || !slices.Equal(fixture.waits, []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}) {
					t.Fatalf("result = %#v, error = %v, physical requests = %d, commits = %d, waits = %v", result, err, physicalRequests, fixture.store.commitCount, fixture.waits)
				}
			})
		}
	}

	t.Run("message round trip and status retry", func(t *testing.T) {
		fixture := newDiscoveryFixture(t, 100)
		messageRequests := 0
		fixture.transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
			switch request.URL.Path {
			case "/token":
				return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
			case "/gmail/v1/users/me/history":
				return jsonResponse(http.StatusOK, `{"history":[{"id":"101","messagesAdded":[{"message":{"id":"message-1","threadId":"thread-1"}}]}],"historyId":"102"}`), nil
			default:
				messageRequests++
				if messageRequests == 1 {
					return nil, errors.New("synthetic message transport interruption")
				}
				if messageRequests == 2 {
					return jsonResponse(http.StatusServiceUnavailable, `{}`), nil
				}
				return jsonResponse(http.StatusOK, messageJSON("message-1", "thread-1", nil, nil)), nil
			}
		})
		result, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
		if err != nil || !result.CursorAdvanced || messageRequests != 3 || fixture.store.commitCount != 1 || !slices.Equal(fixture.waits, []time.Duration{time.Second, 2 * time.Second}) {
			t.Fatalf("result = %#v, error = %v, requests = %d, commits = %d, waits = %v", result, err, messageRequests, fixture.store.commitCount, fixture.waits)
		}
	})

	for _, status := range []int{http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			fixture := newDiscoveryFixture(t, 100)
			calls := 0
			fixture.transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Path == "/token" {
					return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
				}
				calls++
				body := `{}`
				if status == http.StatusForbidden {
					body = googleErrorJSON("rateLimitExceeded")
				}
				return jsonResponse(status, body), nil
			})
			_, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
			if !errors.Is(err, ErrCurrentDiscoveryRetryExhausted) || calls != MaximumProviderAttempts {
				t.Fatalf("error = %v, calls = %d", err, calls)
			}
		})
	}

	t.Run("wait cancellation", func(t *testing.T) {
		fixture := newDiscoveryFixture(t, 100)
		ctx, cancel := context.WithCancel(context.Background())
		fixture.sleep = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
		fixture.transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Path == "/token" {
				return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
			}
			return jsonResponse(http.StatusTooManyRequests, `{}`), nil
		})
		_, err := fixture.discovery(t).Discover(ctx, fixture.accountID)
		if !errors.Is(err, ErrCurrentDiscoveryRetryExhausted) || !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestCurrentDiscoveryOwnedTransportAccountsForStaleConnectionRetry(t *testing.T) {
	listener := listenLoopback(t)
	physicalHistory := make(chan struct{}, 2)
	serverDone := make(chan struct{})
	go serveStaleDiscoveryConnection(t, listener, physicalHistory, serverDone)
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-serverDone:
		case <-time.After(time.Second):
			t.Fatal("synthetic stale-connection server did not stop")
		}
	})

	fixture := newDiscoveryFixture(t, 100)
	baseURL := "http://" + listener.Addr().String()
	discovery, err := newCurrentDiscovery(currentDiscoveryOptions{
		clientID: []byte(syntheticClientID), clientSecret: []byte(syntheticClientSecret), pageSize: 100,
		store: fixture.store, keyring: fixture.keyring,
	}, currentDiscoveryDependencies{
		endpoints: currentDiscoveryEndpoints{token: baseURL + "/token", history: baseURL + "/history", message: baseURL + "/messages/"},
		transport: currentDiscoveryTransport(), jitter: zeroReader{}, sleep: fixture.sleep,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(discovery.Close)
	result, err := discovery.Discover(context.Background(), fixture.accountID)
	if err != nil || result.HistoryPagesRead != 1 {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if len(physicalHistory) != 2 || !slices.Equal(fixture.waits, []time.Duration{time.Second}) {
		t.Fatalf("physical history requests = %d, explicit waits = %v", len(physicalHistory), fixture.waits)
	}
}

func TestCurrentDiscoveryHistoryAndMessageReadLifecycleIsBounded(t *testing.T) {
	for _, endpoint := range []string{"history", "message"} {
		for _, stage := range []string{"header deadline", "body deadline", "body read", "body close"} {
			t.Run(endpoint+" "+stage, func(t *testing.T) {
				fixture := newDiscoveryFixture(t, 100)
				fixture.transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
					switch request.URL.Path {
					case "/token":
						return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
					case "/gmail/v1/users/me/history":
						if endpoint == "message" {
							return jsonResponse(http.StatusOK, `{"history":[{"id":"101","messagesAdded":[{"message":{"id":"message-1","threadId":"thread-1"}}]}],"historyId":"102"}`), nil
						}
					case "/gmail/v1/users/me/messages/message-1":
						if endpoint != "message" {
							t.Fatal("unexpected message request")
						}
					default:
						t.Fatalf("unexpected path %q", request.URL.Path)
					}
					switch stage {
					case "header deadline":
						<-request.Context().Done()
						return nil, request.Context().Err()
					case "body deadline":
						return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: &contextReadBody{ctx: request.Context()}}, nil
					case "body read":
						return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: readFailureBody{}}, nil
					case "body close":
						body := `{"historyId":"100"}`
						if endpoint == "message" {
							body = messageJSON("message-1", "thread-1", nil, nil)
						}
						return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: &closeFailureBody{Reader: strings.NewReader(body)}}, nil
					}
					return nil, errors.New("unreachable")
				})
				ctx := context.Background()
				if strings.Contains(stage, "deadline") {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, 20*time.Millisecond)
					defer cancel()
				}
				_, err := fixture.discovery(t).Discover(ctx, fixture.accountID)
				if stage == "header deadline" || stage == "body deadline" {
					if !errors.Is(err, ErrCurrentDiscoveryRetryExhausted) || !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("error = %v", err)
					}
				} else if stage == "body read" || stage == "body close" {
					if !errors.Is(err, ErrCurrentDiscoveryRetryExhausted) {
						t.Fatalf("error = %v", err)
					}
				}
				if fixture.store.commitCount != 0 {
					t.Fatalf("commits = %d", fixture.store.commitCount)
				}
			})
		}
	}
}

func TestCurrentDiscoveryExactPublishedBounds(t *testing.T) {
	t.Run("history records", func(t *testing.T) {
		fixture := newDiscoveryFixture(t, 500)
		fixture.transport = historyResponseTransport(historyWithRecords(500), http.StatusOK)
		result, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
		if err != nil || !result.CursorAdvanced || fixture.store.commitCount != 1 {
			t.Fatalf("result = %#v, error = %v, commits = %d", result, err, fixture.store.commitCount)
		}
	})

	for _, test := range []struct {
		name    string
		limit   int
		over    bool
		message bool
		error   bool
	}{
		{name: "history exact", limit: MaximumHistoryPageBodyBytes},
		{name: "history over", limit: MaximumHistoryPageBodyBytes, over: true},
		{name: "message exact", limit: MaximumMessageMetadataBodyBytes, message: true},
		{name: "message over", limit: MaximumMessageMetadataBodyBytes, message: true, over: true},
		{name: "error exact", limit: MaximumProviderErrorBodyBytes, error: true},
		{name: "error over", limit: MaximumProviderErrorBodyBytes, error: true, over: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDiscoveryFixture(t, 100)
			target := test.limit
			if test.over {
				target++
			}
			if test.message {
				fixture.transport = oneMessageTransport(t, paddedJSON(messageJSON("message-1", "thread-1", nil, nil), target))
			} else {
				status := http.StatusOK
				body := paddedJSON(`{"historyId":"100"}`, target)
				if test.error {
					status = http.StatusNotFound
					body = paddedJSON(`{}`, target)
				}
				fixture.transport = historyResponseTransport(body, status)
			}
			_, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
			if test.over {
				if !errors.Is(err, ErrCurrentDiscoveryInvalidProviderResponse) {
					t.Fatalf("error = %v", err)
				}
			} else if test.error {
				if !errors.Is(err, ErrCurrentDiscoveryHistoryCursorStale) {
					t.Fatalf("error = %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}

	for _, test := range []struct {
		name    string
		headers []headerFixture
	}{
		{name: "256 headers", headers: repeatedHeaders(MaximumMessageHeaderEntries)},
		{name: "65536 selected bytes", headers: []headerFixture{{name: "Subject", value: strings.Repeat("s", MaximumSelectedHeaderBytes)}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDiscoveryFixture(t, 100)
			fixture.transport = oneMessageTransport(t, messageJSON("message-1", "thread-1", test.headers, nil))
			if _, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID); err != nil {
				t.Fatal(err)
			}
		})
	}

	t.Run("5000 plus page ten continuation", func(t *testing.T) {
		fixture := newDiscoveryFixture(t, 500)
		pages := 0
		messageCalls := 0
		fixture.transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Path == "/token" {
				return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
			}
			if request.URL.Path != "/gmail/v1/users/me/history" {
				messageCalls++
				return nil, errors.New("metadata must not be requested")
			}
			pages++
			return jsonResponse(http.StatusOK, historyPageWithMessages(pages, true)), nil
		})
		result, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
		if !errors.Is(err, ErrCurrentDiscoveryBoundedBacklog) || pages != 10 || messageCalls != 0 || result != (CurrentDiscoveryResult{}) {
			t.Fatalf("result = %#v, error = %v, pages = %d, messages = %d", result, err, pages, messageCalls)
		}
	})

	t.Run("aggregate encoded bytes end to end", func(t *testing.T) {
		for _, target := range []int{storage.MaximumCurrentDiscoveryEncodedBytes, storage.MaximumCurrentDiscoveryEncodedBytes + 1} {
			inputs := discoveryInputsAtEncodedBytes(t, discoveryAccountText, target)
			byMessage := make(map[string]discoveryAggregateInput, len(inputs))
			for _, input := range inputs {
				byMessage[input.messageID] = input
			}
			fixture := newDiscoveryFixture(t, 500)
			fixture.transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				switch request.URL.Path {
				case "/token":
					return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
				case "/gmail/v1/users/me/history":
					page := 0
					if token := request.URL.Query().Get("pageToken"); token != "" {
						page, _ = strconv.Atoi(strings.TrimPrefix(token, "aggregate-page-"))
					}
					return jsonResponse(http.StatusOK, aggregateHistoryPage(inputs, page)), nil
				default:
					messageID := strings.TrimPrefix(request.URL.Path, "/gmail/v1/users/me/messages/")
					input, ok := byMessage[messageID]
					if !ok {
						return nil, errors.New("unknown aggregate message")
					}
					headers := []headerFixture{}
					if input.subject != "" {
						headers = append(headers, headerFixture{name: "Subject", value: input.subject})
					}
					return jsonResponse(http.StatusOK, messageJSON(input.messageID, input.threadID, headers, nil)), nil
				}
			})
			result, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
			if target == storage.MaximumCurrentDiscoveryEncodedBytes {
				prepared, prepareErr := storage.PrepareCurrentDiscoveryCommit(fixture.store.lastCommit)
				if err != nil || prepareErr != nil || prepared.EncodedBytes() != uint64(target) || fixture.store.commitCount != 1 || fixture.store.cursorOnlyWrites != 0 || !result.CursorAdvanced || int(result.MessagesCommitted) != len(inputs) {
					t.Fatalf("target %d result = %#v, encoded = %d, error = %v, prepare error = %v, commits = %d, cursor-only = %d", target, result, prepared.EncodedBytes(), err, prepareErr, fixture.store.commitCount, fixture.store.cursorOnlyWrites)
				}
			} else {
				if !errors.Is(err, ErrCurrentDiscoveryInvalidProviderResponse) || result != (CurrentDiscoveryResult{}) || fixture.store.commitCount != 0 || fixture.store.cursorOnlyWrites != 0 {
					t.Fatalf("target %d result = %#v, error = %v, commits = %d, cursor-only = %d", target, result, err, fixture.store.commitCount, fixture.store.cursorOnlyWrites)
				}
				assertCursorAndCredentialUnchanged(t, fixture)
			}
		}
	})
}

func TestCurrentDiscoveryGmailAuthorizationClassificationsStopWork(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		reason storage.ReauthorizationReason
		want   error
	}{
		{name: "unauthorized", status: 401, body: `{}`, reason: storage.ReauthorizationReasonGmailUnauthorizedAfterRefresh, want: ErrCurrentDiscoveryReauthorizationRequired},
		{name: "domain policy", status: 403, body: googleErrorJSON("domainPolicy"), reason: storage.ReauthorizationReasonGmailDomainPolicy, want: ErrCurrentDiscoveryReauthorizationRequired},
		{name: "conflicting policy", status: 403, body: googleErrorReasonsJSON("domainPolicy", "rateLimitExceeded"), want: ErrCurrentDiscoveryInvalidProviderResponse},
		{name: "malformed policy", status: 403, body: `{"error":{"errors":[{"reason":"domainPolicy"}],"unknown":true}}`, want: ErrCurrentDiscoveryInvalidProviderResponse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDiscoveryFixture(t, 100)
			gmailCalls := 0
			fixture.transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Path == "/token" {
					return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
				}
				gmailCalls++
				return jsonResponse(test.status, test.body), nil
			})
			_, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
			if !errors.Is(err, test.want) || gmailCalls != 1 || fixture.store.commitCount != 0 {
				t.Fatalf("error = %v, calls = %d, commits = %d", err, gmailCalls, fixture.store.commitCount)
			}
			lifecycle, _ := fixture.store.Handle.GetAccountLifecycle(context.Background(), fixture.accountID)
			if test.reason.String() == "" {
				if lifecycle.State != storage.AccountStateActive {
					t.Fatalf("lifecycle = %#v", lifecycle)
				}
			} else if lifecycle.State != storage.AccountStateReauthorizationRequired || lifecycle.ReauthorizationReason == nil || *lifecycle.ReauthorizationReason != test.reason {
				t.Fatalf("lifecycle = %#v", lifecycle)
			}
		})
	}
}

func TestCurrentDiscoveryUncertainCommitIsNotReplayed(t *testing.T) {
	fixture := newDiscoveryFixture(t, 100)
	fixture.store.failCommit = storage.ErrPersistenceUnknown
	fixture.store.applyFailedCommit = true
	providerCalls := 0
	fixture.transport = countingTransport(oneMessageTransport(t, messageJSON("message-1", "thread-1", nil, nil)), &providerCalls)
	_, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
	if !errors.Is(err, ErrCurrentDiscoveryRecoveryRequired) || fixture.store.commitCount != 1 {
		t.Fatalf("error = %v, commits = %d", err, fixture.store.commitCount)
	}
	firstCalls := providerCalls
	fixture.store.failCommit = nil
	result, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
	if err != nil || providerCalls != firstCalls+2 || result.CursorAdvanced {
		t.Fatalf("restart result = %#v, error = %v, calls = %d", result, err, providerCalls)
	}
	if fixture.store.actions[0] != "reconcile" || fixture.store.cursorOnlyWrites != 0 {
		t.Fatalf("actions = %#v", fixture.store.actions)
	}
}

func TestCurrentDiscoveryRestartReconciliationIsAuthoritative(t *testing.T) {
	t.Run("sealed", func(t *testing.T) {
		fixture := newDiscoveryFixture(t, 100)
		message, err := maildomain.Normalize(fixture.accountID.String(), maildomain.MessageInput{
			GmailMessageID: "sealed-message", GmailThreadID: "sealed-thread", To: []string{}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{},
		})
		if err != nil {
			t.Fatal(err)
		}
		expected, _ := storage.ParseHistoryID(discoveryStartCursor)
		next, _ := storage.ParseHistoryID("102")
		fixture.store.reconcile = func(ctx context.Context, accountID storage.AccountID) error {
			return fixture.store.Handle.CommitCurrentDiscovery(ctx, storage.CurrentDiscoveryCommit{AccountID: accountID, Expected: expected, Next: next, Messages: []maildomain.Message{message}})
		}
		providerCalls := 0
		fixture.transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
			providerCalls++
			if request.URL.Path == "/token" {
				return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
			}
			assertHistoryRequest(t, request, "102", "", 100)
			return jsonResponse(http.StatusOK, `{"historyId":"102"}`), nil
		})
		result, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
		if err != nil || result.CursorAdvanced || providerCalls != 2 || fixture.store.commitCount != 0 {
			t.Fatalf("result = %#v, error = %v, calls = %d, commits = %d", result, err, providerCalls, fixture.store.commitCount)
		}
	})

	t.Run("open", func(t *testing.T) {
		fixture := newDiscoveryFixture(t, 100)
		fixture.store.reconcile = func(context.Context, storage.AccountID) error { return nil }
		fixture.transport = successfulNoChangeTransport(t, 100)
		result, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
		if err != nil || result.HistoryPagesRead != 1 || fixture.store.commitCount != 0 {
			t.Fatalf("result = %#v, error = %v, commits = %d", result, err, fixture.store.commitCount)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		fixture := newDiscoveryFixture(t, 100)
		fixture.store.reconcile = func(context.Context, storage.AccountID) error { return storage.ErrCurrentDiscoveryRecoveryRequired }
		providerCalls := 0
		fixture.transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			providerCalls++
			return nil, errors.New("provider contact forbidden")
		})
		_, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
		if !errors.Is(err, ErrCurrentDiscoveryRecoveryRequired) || providerCalls != 0 {
			t.Fatalf("error = %v, provider calls = %d", err, providerCalls)
		}
	})
}

func TestCurrentDiscoverySeparateInstancesResolveExactAndDifferentRaces(t *testing.T) {
	for _, different := range []bool{false, true} {
		name := "exact"
		if different {
			name = "different"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newDiscoveryFixture(t, 100)
			var arrived sync.WaitGroup
			arrived.Add(2)
			release := make(chan struct{})
			makeTransport := func(next, messageID, threadID string) http.RoundTripper {
				return roundTripFunc(func(request *http.Request) (*http.Response, error) {
					switch request.URL.Path {
					case "/token":
						return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
					case "/gmail/v1/users/me/history":
						return jsonResponse(http.StatusOK, fmt.Sprintf(`{"history":[{"id":"101","messagesAdded":[{"message":{"id":%q,"threadId":%q}}]}],"historyId":%q}`, messageID, threadID, next)), nil
					default:
						arrived.Done()
						<-release
						return jsonResponse(http.StatusOK, messageJSON(messageID, threadID, nil, nil)), nil
					}
				})
			}
			firstNext, secondNext := "102", "102"
			firstMessage, secondMessage := "message-1", "message-1"
			firstThread, secondThread := "thread-1", "thread-1"
			if different {
				secondNext, secondMessage, secondThread = "103", "message-2", "thread-2"
			}
			first := fixture.discoveryWithTransport(t, makeTransport(firstNext, firstMessage, firstThread))
			second := fixture.discoveryWithTransport(t, makeTransport(secondNext, secondMessage, secondThread))
			type outcome struct {
				result CurrentDiscoveryResult
				err    error
			}
			outcomes := make(chan outcome, 2)
			go func() {
				result, err := first.Discover(context.Background(), fixture.accountID)
				outcomes <- outcome{result: result, err: err}
			}()
			go func() {
				result, err := second.Discover(context.Background(), fixture.accountID)
				outcomes <- outcome{result: result, err: err}
			}()
			arrived.Wait()
			close(release)
			values := []outcome{<-outcomes, <-outcomes}
			if different {
				successes, conflicts := 0, 0
				for _, value := range values {
					if value.err == nil && value.result.CursorAdvanced {
						successes++
					} else if errors.Is(value.err, ErrCurrentDiscoveryConflict) {
						conflicts++
					} else {
						t.Fatalf("outcome = %#v, error = %v", value.result, value.err)
					}
				}
				if successes != 1 || conflicts != 1 {
					t.Fatalf("successes = %d, conflicts = %d", successes, conflicts)
				}
			} else {
				for _, value := range values {
					if value.err != nil || !value.result.CursorAdvanced {
						t.Fatalf("outcome = %#v, error = %v", value.result, value.err)
					}
				}
			}
		})
	}
}

func TestCurrentDiscoveryLifecycleRaceCannotAdvanceCursor(t *testing.T) {
	fixture := newDiscoveryFixture(t, 100)
	fixture.store.beforeDiscoveryCommit = func(ctx context.Context, accountID storage.AccountID) {
		lifecycle, err := fixture.store.Handle.GetAccountLifecycle(ctx, accountID)
		if err != nil {
			t.Fatal(err)
		}
		commit := storage.LifecycleCommit{
			AccountID: accountID, ExpectedState: lifecycle.State, ExpectedVersion: lifecycle.Version,
			ExpectedRevocationStatus: lifecycle.RevocationStatus, NextState: storage.AccountStatePaused,
			RevocationStatus: storage.RevocationStatusNone,
		}
		if err := fixture.store.Handle.CommitAccountLifecycle(ctx, commit); err != nil {
			t.Fatal(err)
		}
	}
	fixture.transport = oneMessageTransport(t, messageJSON("message-1", "thread-1", nil, nil))
	_, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
	if !errors.Is(err, ErrCurrentDiscoveryInactiveAccount) || fixture.store.commitCount != 1 {
		t.Fatalf("error = %v, commit calls = %d", err, fixture.store.commitCount)
	}
	cursor, cursorErr := fixture.store.Handle.GetSynchronizationCursor(context.Background(), fixture.accountID)
	if cursorErr != nil || cursor.HistoryID.String() != discoveryStartCursor {
		t.Fatalf("cursor = %#v, error = %v", cursor, cursorErr)
	}
	if _, messageErr := fixture.store.Handle.GetDiscoveredMessage(context.Background(), fixture.accountID, "message-1"); !errors.Is(messageErr, storage.ErrMessageNotFound) {
		t.Fatalf("message error = %v", messageErr)
	}
}

func TestCurrentDiscoveryAbsoluteRequestCap(t *testing.T) {
	if MaximumProviderAttempts != 4 || MaximumCurrentDiscoveryPages != 10 || MaximumCurrentDiscoveryPageMessages != 500 || MaximumCurrentDiscoveryMessages != 5000 || MaximumProviderRequestAttempts != 20041 {
		t.Fatal("compiled request bounds drifted")
	}
	fixture := newDiscoveryFixture(t, 500)
	fixture.sleep = func(context.Context, time.Duration) error { return nil }
	var mu sync.Mutex
	counts := map[string]int{}
	total := 0
	fixture.transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		total++
		key := request.URL.Path + "?" + request.URL.RawQuery
		counts[key]++
		attempt := counts[key]
		if request.URL.Path == "/token" {
			return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
		}
		if attempt < MaximumProviderAttempts {
			return jsonResponse(http.StatusServiceUnavailable, `{}`), nil
		}
		if request.URL.Path == "/gmail/v1/users/me/history" {
			page := 1
			if token := request.URL.Query().Get("pageToken"); token != "" {
				page, _ = strconv.Atoi(strings.TrimPrefix(token, "page-"))
			}
			return jsonResponse(http.StatusOK, historyPageWithMessages(page, page < 10)), nil
		}
		return jsonResponse(http.StatusNotFound, `{}`), nil
	})
	result, err := fixture.discovery(t).Discover(context.Background(), fixture.accountID)
	if err != nil {
		t.Fatal(err)
	}
	if total != MaximumProviderRequestAttempts || result.HistoryPagesRead != 10 || result.UniqueMessageAdditions != 5000 || result.VanishedMessages != 5000 || result.MessagesCommitted != 0 || !result.CursorAdvanced {
		t.Fatalf("total = %d, result = %#v", total, result)
	}
}

func TestCurrentDiscoveryReachableRequestInventoryIsReadOnly(t *testing.T) {
	source, err := os.ReadFile("current_discovery.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, forbidden := range []string{"/send", "/modify", "/trash", "/untrash", "/attachments/", "messages.list", "format=RAW", "http.MethodDelete", "http.MethodPatch", "http.MethodPut"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("reachable Gmail inventory contains %q", forbidden)
		}
	}
	if strings.Count(text, "http.MethodPost") != 0 {
		t.Fatal("current discovery must delegate its only POST to the bounded OAuth token source")
	}
	if !strings.Contains(text, "http.MethodGet") || !strings.Contains(text, "CommitCurrentDiscovery") || strings.Contains(text, "CommitSynchronization") {
		t.Fatal("read-only request or atomic storage inventory drifted")
	}
}

type discoveryFixture struct {
	accountID storage.AccountID
	store     *discoveryStoreProbe
	keyring   *cryptobox.Keyring
	pageSize  int
	transport http.RoundTripper
	sleep     func(context.Context, time.Duration) error
	waits     []time.Duration
}

func newDiscoveryFixture(t *testing.T, pageSize int) *discoveryFixture {
	t.Helper()
	base := storagefake.New()
	accountID, _ := storage.ParseAccountID(discoveryAccountText)
	subject, _ := storage.ParseProviderSubject("synthetic-discovery-subject")
	if _, err := base.EnsureAccount(context.Background(), storage.AccountSeed{ID: accountID, ProviderSubject: subject}); err != nil {
		t.Fatal(err)
	}
	start, _ := storage.ParseHistoryID(discoveryStartCursor)
	if err := base.CommitSynchronization(context.Background(), storage.SynchronizationCommit{AccountID: accountID, Next: start}); err != nil {
		t.Fatal(err)
	}
	ring := syntheticKeyring(t)
	envelopeText, err := ring.EncryptRefreshToken(accountID.String(), []byte(discoveryRefreshText))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := storage.ParseCredentialEnvelope(envelopeText)
	if err != nil {
		t.Fatal(err)
	}
	if err := base.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: accountID, Next: envelope}); err != nil {
		t.Fatal(err)
	}
	lifecycle, _ := base.GetAccountLifecycle(context.Background(), accountID)
	if err := base.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: accountID, ExpectedState: lifecycle.State, ExpectedVersion: lifecycle.Version, ExpectedRevocationStatus: lifecycle.RevocationStatus, NextState: storage.AccountStateActive, RevocationStatus: storage.RevocationStatusNone}); err != nil {
		t.Fatal(err)
	}
	probe := &discoveryStoreProbe{Handle: base}
	fixture := &discoveryFixture{accountID: accountID, store: probe, keyring: ring, pageSize: pageSize}
	fixture.sleep = func(_ context.Context, duration time.Duration) error {
		fixture.waits = append(fixture.waits, duration)
		return nil
	}
	return fixture
}

func (fixture *discoveryFixture) discovery(t *testing.T) *CurrentDiscovery {
	t.Helper()
	transport := fixture.transport
	if transport == nil {
		transport = successfulNoChangeTransport(t, fixture.pageSize)
	}
	return fixture.discoveryWithTransport(t, transport)
}

func (fixture *discoveryFixture) discoveryWithTransport(t *testing.T, transport http.RoundTripper) *CurrentDiscovery {
	t.Helper()
	discovery, err := newCurrentDiscovery(currentDiscoveryOptions{
		clientID: []byte(syntheticClientID), clientSecret: []byte(syntheticClientSecret), pageSize: fixture.pageSize,
		store: fixture.store, keyring: fixture.keyring,
	}, currentDiscoveryDependencies{
		endpoints: discoveryLoopbackEndpoints,
		transport: transport,
		jitter:    zeroReader{},
		sleep:     fixture.sleep,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(discovery.Close)
	return discovery
}

type zeroReader struct{}

func (zeroReader) Read(destination []byte) (int, error) {
	clear(destination)
	return len(destination), nil
}

type discoveryStoreProbe struct {
	storage.Handle
	mu                      sync.Mutex
	actions                 []string
	commitCount             int
	cursorOnlyWrites        int
	lastCommit              storage.CurrentDiscoveryCommit
	failReconcile           error
	failCursor              error
	failCredential          error
	failCommit              error
	applyFailedCommit       bool
	reconcile               func(context.Context, storage.AccountID) error
	beforeDiscoveryCommit   func(context.Context, storage.AccountID)
	lifecycleOverride       *storage.AccountLifecycle
	secondLifecycleOverride *storage.AccountLifecycle
	credentialOverride      *storage.ProviderCredential
	lifecycleReads          int
}

func (store *discoveryStoreProbe) action(name string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.actions = append(store.actions, name)
}

func (store *discoveryStoreProbe) ReconcileCurrentDiscovery(ctx context.Context, accountID storage.AccountID) error {
	store.action("reconcile")
	if store.reconcile != nil {
		return store.reconcile(ctx, accountID)
	}
	if store.failReconcile != nil {
		return store.failReconcile
	}
	return store.Handle.ReconcileCurrentDiscovery(ctx, accountID)
}

func (store *discoveryStoreProbe) GetAccountLifecycle(ctx context.Context, accountID storage.AccountID) (storage.AccountLifecycle, error) {
	store.action("lifecycle")
	store.mu.Lock()
	store.lifecycleReads++
	read := store.lifecycleReads
	second := store.secondLifecycleOverride
	override := store.lifecycleOverride
	store.mu.Unlock()
	if read == 2 && second != nil {
		value := *second
		value.AccountID = accountID
		return value, nil
	}
	if override != nil {
		value := *override
		value.AccountID = accountID
		return value, nil
	}
	return store.Handle.GetAccountLifecycle(ctx, accountID)
}

func (store *discoveryStoreProbe) GetSynchronizationCursor(ctx context.Context, accountID storage.AccountID) (storage.SynchronizationCursor, error) {
	store.action("cursor")
	if store.failCursor != nil {
		return storage.SynchronizationCursor{}, store.failCursor
	}
	return store.Handle.GetSynchronizationCursor(ctx, accountID)
}

func (store *discoveryStoreProbe) GetProviderCredential(ctx context.Context, accountID storage.AccountID) (storage.ProviderCredential, error) {
	store.action("credential")
	if store.failCredential != nil {
		return storage.ProviderCredential{}, store.failCredential
	}
	if store.credentialOverride != nil {
		return *store.credentialOverride, nil
	}
	return store.Handle.GetProviderCredential(ctx, accountID)
}

func (store *discoveryStoreProbe) CommitSynchronization(ctx context.Context, commit storage.SynchronizationCommit) error {
	store.cursorOnlyWrites++
	return store.Handle.CommitSynchronization(ctx, commit)
}

func (store *discoveryStoreProbe) CommitAccountLifecycle(ctx context.Context, commit storage.LifecycleCommit) error {
	store.action("lifecycle_commit")
	return store.Handle.CommitAccountLifecycle(ctx, commit)
}

func (store *discoveryStoreProbe) CommitCurrentDiscovery(ctx context.Context, commit storage.CurrentDiscoveryCommit) error {
	store.action("discovery_commit")
	store.mu.Lock()
	store.commitCount++
	store.lastCommit = commit
	before := store.beforeDiscoveryCommit
	fail := store.failCommit
	apply := store.applyFailedCommit
	store.mu.Unlock()
	if before != nil {
		before(ctx, commit.AccountID)
	}
	if fail != nil {
		if apply {
			_ = store.Handle.CommitCurrentDiscovery(ctx, commit)
		}
		return fail
	}
	return store.Handle.CommitCurrentDiscovery(ctx, commit)
}

func lifecycleWith(state storage.AccountState, versionValue int64) *storage.AccountLifecycle {
	version, _ := storage.ParseLifecycleVersion(versionValue)
	value := &storage.AccountLifecycle{State: state, Version: version, RevocationStatus: storage.RevocationStatusNone}
	if state == storage.AccountStateReauthorizationRequired {
		reason := storage.ReauthorizationReasonRefreshInvalidGrant
		value.ReauthorizationReason = &reason
	}
	if state == storage.AccountStateRevoked {
		value.RevocationStatus = storage.RevocationStatusConfirmed
	}
	return value
}

func malformedCredential(t *testing.T) *storage.ProviderCredential {
	t.Helper()
	otherAccount := "22222222222222222222222222222222"
	ring := syntheticKeyring(t)
	envelopeText, err := ring.EncryptRefreshToken(otherAccount, []byte(discoveryRefreshText))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := storage.ParseCredentialEnvelope(envelopeText)
	if err != nil {
		t.Fatal(err)
	}
	accountID, _ := storage.ParseAccountID(discoveryAccountText)
	return &storage.ProviderCredential{AccountID: accountID, KeyID: envelope.KeyID(), Envelope: envelope}
}

func successfulNoChangeTransport(t *testing.T, pageSize int) http.RoundTripper {
	t.Helper()
	return roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/token":
			assertRefreshRequest(t, request)
			return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
		case "/gmail/v1/users/me/history":
			assertHistoryRequest(t, request, discoveryStartCursor, "", pageSize)
			return jsonResponse(http.StatusOK, `{"historyId":"100"}`), nil
		default:
			t.Fatalf("unexpected path %q", request.URL.Path)
			return nil, errors.New("unreachable")
		}
	})
}

func oneMessageTransport(t *testing.T, messageBody string) http.RoundTripper {
	t.Helper()
	return roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/token":
			return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
		case "/gmail/v1/users/me/history":
			return jsonResponse(http.StatusOK, `{"history":[{"id":"101","messagesAdded":[{"message":{"id":"message-1","threadId":"thread-1"}}]}],"historyId":"102"}`), nil
		case "/gmail/v1/users/me/messages/message-1":
			assertMessageRequest(t, request, "message-1")
			return jsonResponse(http.StatusOK, messageBody), nil
		default:
			t.Fatalf("unexpected path %q", request.URL.Path)
			return nil, errors.New("unreachable")
		}
	})
}

func countingTransport(base http.RoundTripper, calls *int) http.RoundTripper {
	return roundTripFunc(func(request *http.Request) (*http.Response, error) {
		*calls++
		return base.RoundTrip(request)
	})
}

func assertRefreshRequest(t *testing.T, request *http.Request) {
	t.Helper()
	if request.Method != http.MethodPost || request.URL.String() != discoveryLoopbackEndpoints.token || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" || request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatalf("refresh request = %s %s, headers = %#v", request.Method, request.URL, request.Header)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	values, err := url.ParseQuery(string(body))
	if err != nil {
		t.Fatal(err)
	}
	want := url.Values{"client_id": {syntheticClientID}, "client_secret": {syntheticClientSecret}, "grant_type": {"refresh_token"}, "refresh_token": {discoveryRefreshText}}
	if values.Encode() != want.Encode() || request.URL.RawQuery != "" {
		t.Fatalf("refresh form = %#v, query = %q", values, request.URL.RawQuery)
	}
}

func assertHistoryRequest(t *testing.T, request *http.Request, cursor, pageToken string, pageSize int) {
	t.Helper()
	if request.Method != http.MethodGet || request.URL.Path != "/gmail/v1/users/me/history" || request.Body != nil && request.Body != http.NoBody || request.Header.Get("Authorization") != "Bearer "+discoveryAccessText {
		t.Fatalf("history request = %s %s, headers = %#v", request.Method, request.URL, request.Header)
	}
	want := url.Values{
		"startHistoryId": {cursor}, "historyTypes": {"messageAdded"}, "maxResults": {strconv.Itoa(pageSize)},
		"fields": {"history(id,messagesAdded(message(id,threadId))),historyId,nextPageToken"},
	}
	if pageToken != "" {
		want.Set("pageToken", pageToken)
	}
	if request.URL.Query().Encode() != want.Encode() {
		t.Fatalf("history query = %q, want %q", request.URL.Query().Encode(), want.Encode())
	}
}

func assertMessageRequest(t *testing.T, request *http.Request, id string) {
	t.Helper()
	if request.Method != http.MethodGet || request.URL.Path != "/gmail/v1/users/me/messages/"+url.PathEscape(id) || request.Body != nil && request.Body != http.NoBody || request.Header.Get("Authorization") != "Bearer "+discoveryAccessText {
		t.Fatalf("message request = %s %s, headers = %#v", request.Method, request.URL, request.Header)
	}
	want := url.Values{"format": {"FULL"}, "fields": {messageMetadataFields}}
	if request.URL.Query().Encode() != want.Encode() || request.URL.Query().Has("metadataHeaders") {
		t.Fatalf("message query = %q, want %q", request.URL.Query().Encode(), want.Encode())
	}
}

func cloneRequest(t *testing.T, request *http.Request) *http.Request {
	t.Helper()
	clone := request.Clone(context.Background())
	if request.Body != nil {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		clone.Body = io.NopCloser(bytes.NewReader(body))
	}
	return clone
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Status: strconv.Itoa(status), Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func refreshSuccessJSON() string {
	return `{"access_token":"` + discoveryAccessText + `","token_type":"Bearer","expires_in":3600,"scope":"https://www.googleapis.com/auth/gmail.readonly openid"}`
}

type headerFixture struct {
	name  string
	value string
}

func messageJSON(id, thread string, headers []headerFixture, parts []any) string {
	return messageJSONWithRoot(id, thread, "", "", headers, parts)
}

func messageJSONWithRoot(id, thread, rootFilename, rootAttachment string, headers []headerFixture, parts []any) string {
	headerValues := make([]any, 0, len(headers))
	for _, header := range headers {
		headerValues = append(headerValues, map[string]any{"name": header.name, "value": header.value})
	}
	payload := map[string]any{"headers": headerValues, "filename": rootFilename, "body": map[string]any{"attachmentId": rootAttachment}, "parts": parts}
	value := map[string]any{"id": id, "threadId": thread, "labelIds": []string{"INBOX", "CATEGORY_PERSONAL"}, "internalDate": "1735689600000", "sizeEstimate": 4096, "payload": payload}
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func partFixture(filename, attachmentID string) map[string]any {
	return map[string]any{"filename": filename, "body": map[string]any{"attachmentId": attachmentID}, "parts": []any{}}
}

func repeatedParts(count int) []any {
	result := make([]any, count)
	for index := range result {
		result[index] = partFixture("", "")
	}
	return result
}

func nestedPart(depth int) map[string]any {
	part := partFixture("", "")
	for index := 1; index < depth; index++ {
		part = map[string]any{"filename": "", "body": map[string]any{"attachmentId": ""}, "parts": []any{part}}
	}
	return part
}

func repeatedHeaders(count int) []headerFixture {
	result := make([]headerFixture, count)
	for index := range result {
		result[index] = headerFixture{name: "X-Unselected", value: "x"}
	}
	return result
}

func historyWithRecords(count int) string {
	records := make([]string, count)
	for index := range records {
		records[index] = fmt.Sprintf(`{"id":"%d","messagesAdded":[]}`, index+101)
	}
	return `{"history":[` + strings.Join(records, ",") + `],"historyId":"1000"}`
}

func historyWithAdditions(count int) string {
	additions := make([]string, count)
	for index := range additions {
		additions[index] = fmt.Sprintf(`{"message":{"id":"m-%d","threadId":"t-%d"}}`, index, index)
	}
	return `{"history":[{"id":"101","messagesAdded":[` + strings.Join(additions, ",") + `]}],"historyId":"102"}`
}

func historyPageWithMessages(page int, hasNext bool) string {
	additions := make([]string, 500)
	for index := range additions {
		number := (page-1)*500 + index
		additions[index] = fmt.Sprintf(`{"message":{"id":"message-%d","threadId":"thread-%d"}}`, number, number)
	}
	body := fmt.Sprintf(`{"history":[{"id":"%d","messagesAdded":[%s]}],"historyId":"%d"`, 100+page, strings.Join(additions, ","), 100+page)
	if hasNext {
		body += fmt.Sprintf(`,"nextPageToken":"page-%d"`, page+1)
	}
	return body + `}`
}

func googleErrorJSON(reason string) string { return googleErrorReasonsJSON(reason) }

func googleErrorReasonsJSON(reasons ...string) string {
	items := make([]string, len(reasons))
	for index, reason := range reasons {
		items[index] = fmt.Sprintf(`{"domain":"global","message":"synthetic","reason":%q}`, reason)
	}
	return `{"error":{"code":403,"message":"synthetic","status":"PERMISSION_DENIED","errors":[` + strings.Join(items, ",") + `]}}`
}

func assertCursorAndCredentialUnchanged(t *testing.T, fixture *discoveryFixture) {
	t.Helper()
	cursor, err := fixture.store.Handle.GetSynchronizationCursor(context.Background(), fixture.accountID)
	if err != nil || cursor.HistoryID.String() != discoveryStartCursor {
		t.Fatalf("cursor = %#v, error = %v", cursor, err)
	}
	credential, err := fixture.store.Handle.GetProviderCredential(context.Background(), fixture.accountID)
	if err != nil || credential.AccountID != fixture.accountID {
		t.Fatalf("credential = %#v, error = %v", credential, err)
	}
	plaintext, err := fixture.keyring.DecryptRefreshToken(fixture.accountID.String(), credential.Envelope.String())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	if string(plaintext) != discoveryRefreshText {
		t.Fatal("durable credential changed")
	}
}

func assertBoundedResultDoesNotDisclose(t *testing.T, result CurrentDiscoveryResult) {
	t.Helper()
	encoded := fmt.Sprintf("%#v", result)
	for _, sensitive := range []string{discoveryAccountText, discoveryStartCursor, discoveryNextCursor, discoveryRefreshText, discoveryAccessText, "message-a", "thread-a", "sender@example.test"} {
		if strings.Contains(encoded, sensitive) {
			t.Fatalf("result disclosed synthetic private value %q", sensitive)
		}
	}
}

type contextReadBody struct {
	ctx context.Context
}

func (body *contextReadBody) Read([]byte) (int, error) {
	<-body.ctx.Done()
	return 0, body.ctx.Err()
}

func (*contextReadBody) Close() error { return nil }

type readFailureBody struct{}

func (readFailureBody) Read([]byte) (int, error) { return 0, errors.New("synthetic body read failure") }
func (readFailureBody) Close() error             { return nil }

type closeFailureBody struct {
	io.Reader
}

func (*closeFailureBody) Close() error { return errors.New("synthetic body close failure") }

func paddedJSON(body string, size int) string {
	if len(body) > size {
		panic("JSON fixture exceeds requested size")
	}
	return body + strings.Repeat(" ", size-len(body))
}

func replaceNth(text, old, replacement string, occurrence int) string {
	start := 0
	for index := 1; index <= occurrence; index++ {
		offset := strings.Index(text[start:], old)
		if offset < 0 {
			return text
		}
		start += offset
		if index == occurrence {
			return text[:start] + replacement + text[start+len(old):]
		}
		start += len(old)
	}
	return text
}

func historyResponseTransport(body string, status int) http.RoundTripper {
	return roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/token" {
			return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
		}
		if request.URL.Path == "/gmail/v1/users/me/history" {
			return jsonResponse(status, body), nil
		}
		return nil, errors.New("unexpected synthetic request")
	})
}

func serveStaleDiscoveryConnection(t *testing.T, listener net.Listener, physicalHistory chan<- struct{}, done chan<- struct{}) {
	t.Helper()
	defer close(done)
	historyRequests := 0
	for historyRequests < 2 {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		reader := bufio.NewReader(connection)
		for {
			request, err := http.ReadRequest(reader)
			if err != nil {
				_ = connection.Close()
				break
			}
			_, _ = io.Copy(io.Discard, request.Body)
			_ = request.Body.Close()
			if request.URL.Path == "/token" {
				body := refreshSuccessJSON()
				_, _ = fmt.Fprintf(connection, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
				continue
			}
			if request.URL.Path != "/history" {
				t.Errorf("unexpected physical path %q", request.URL.Path)
				_ = connection.Close()
				return
			}
			historyRequests++
			physicalHistory <- struct{}{}
			if historyRequests == 1 {
				_ = connection.Close()
				break
			}
			body := `{"historyId":"100"}`
			_, _ = fmt.Fprintf(connection, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			_ = connection.Close()
			return
		}
	}
}

type discoveryAggregateInput struct {
	messageID string
	threadID  string
	subject   string
}

func discoveryInputsAtEncodedBytes(t *testing.T, accountText string, target int) []discoveryAggregateInput {
	t.Helper()
	inputs := make([]discoveryAggregateInput, 0, storage.MaximumCurrentDiscoveryMessages)
	deltas := make([]int, 0, storage.MaximumCurrentDiscoveryMessages)
	baseTotal := 0
	deltaTotal := 0
	maximumTotal := 0
	for index := 0; index < storage.MaximumCurrentDiscoveryMessages && maximumTotal < target; index++ {
		input := discoveryAggregateInput{messageID: fmt.Sprintf("boundary-%04d", index), threadID: fmt.Sprintf("thread-%04d", index)}
		message, err := normalizeDiscoveryAggregateInput(accountText, input)
		if err != nil {
			t.Fatal(err)
		}
		maximumInput := input
		maximumInput.subject = strings.Repeat("s", 4096)
		maximum, err := normalizeDiscoveryAggregateInput(accountText, maximumInput)
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, input)
		delta := discoveryEncodedMessageSize(maximum) - discoveryEncodedMessageSize(message)
		deltas = append(deltas, delta)
		baseTotal += discoveryEncodedMessageSize(message)
		deltaTotal += delta
		maximumTotal = baseTotal + deltaTotal
	}
	if baseTotal > target || maximumTotal < target {
		t.Fatalf("cannot construct aggregate target %d: base=%d max=%d messages=%d", target, baseTotal, maximumTotal, len(inputs))
	}
	remaining := target - baseTotal
	for index := range inputs {
		addition := min(remaining, deltas[index])
		if addition == 0 {
			continue
		}
		inputs[index].subject = strings.Repeat("s", addition)
		remaining -= addition
	}
	if remaining != 0 {
		t.Fatalf("aggregate target has %d unallocated bytes", remaining)
	}
	return inputs
}

func normalizeDiscoveryAggregateInput(accountText string, input discoveryAggregateInput) (maildomain.Message, error) {
	return maildomain.Normalize(accountText, maildomain.MessageInput{
		GmailMessageID: input.messageID, GmailThreadID: input.threadID, InternalDateMS: 1735689600000,
		Subject: input.subject, To: []string{}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{"INBOX", "CATEGORY_PERSONAL"}, SizeEstimate: 4096,
	})
}

func aggregateHistoryPage(inputs []discoveryAggregateInput, page int) string {
	start := page * storage.MaximumCurrentDiscoveryPageMessages
	end := min(start+storage.MaximumCurrentDiscoveryPageMessages, len(inputs))
	additions := make([]string, 0, end-start)
	for _, input := range inputs[start:end] {
		additions = append(additions, fmt.Sprintf(`{"message":{"id":%q,"threadId":%q}}`, input.messageID, input.threadID))
	}
	historyID := 101 + page
	body := fmt.Sprintf(`{"history":[{"id":%q,"messagesAdded":[%s]}],"historyId":%q`, strconv.Itoa(historyID), strings.Join(additions, ","), strconv.Itoa(historyID))
	if end < len(inputs) {
		body += fmt.Sprintf(`,"nextPageToken":%q`, fmt.Sprintf("aggregate-page-%d", page+1))
	}
	return body + `}`
}

func discoveryEncodedMessageSize(message maildomain.Message) int {
	return 4 + len(message.RecordID()) + 4 + len(message.GmailMessageID()) + 4 + len(message.GmailThreadID()) + 4 + 4 + len(message.CanonicalJSON()) + 4 + len(message.MetadataHash())
}
