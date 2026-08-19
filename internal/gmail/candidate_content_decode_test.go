package gmail

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/gate"
	maildomain "github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
)

func encodedBody(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

func candidateDocument(messageID, threadID, payload string) []byte {
	return []byte(fmt.Sprintf(`{"id":%q,"threadId":%q,"payload":%s}`, messageID, threadID, payload))
}

func textPart(mime, charset string, body []byte) string {
	return fmt.Sprintf(`{"mimeType":%q,"headers":[{"name":"Content-Type","value":%q}],"filename":"","body":{"size":%d,"data":%q}}`, mime, mime+"; charset="+charset, len(body), encodedBody(body))
}

func TestDecodeCandidateContentPrefersPlainAndCanonicalizes(t *testing.T) {
	payload := fmt.Sprintf(`{"mimeType":"multipart/alternative","headers":[{"name":"Content-Type","value":"multipart/alternative"}],"filename":"","body":{"size":0},"parts":[%s,%s]}`,
		textPart("text/html", "utf-8", []byte(`<p>html only</p>`)),
		textPart("text/plain", "utf-8", []byte("  plain\r\n\r\n\r\nline\x00\u202E  ")),
	)
	kind, excerpt, truncated, err := decodeCandidateContentResponse(candidateDocument("synthetic-message", "synthetic-thread", payload), "synthetic-message", "synthetic-thread", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if kind != maildomain.CandidateSourceTextPlain || excerpt != "plain\n\nline�" || truncated {
		t.Fatalf("kind=%s excerpt=%q truncated=%t", kind.String(), excerpt, truncated)
	}
}

func TestDecodeCandidateIgnoresInertMIMEParameters(t *testing.T) {
	plain := `{"mimeType":"text/plain","headers":[{"name":"Content-Type","value":"text/plain; charset=utf-8; format=flowed"}],"filename":"","body":{"size":7,"data":"dmlzaWJsZQ"}}`
	PDF := `{"mimeType":"application/pdf","headers":[{"name":"Content-Type","value":"application/pdf; name=synthetic.pdf"}],"filename":"","body":{"size":4,"data":"cGRmIQ"}}`
	payload := fmt.Sprintf(`{"mimeType":"multipart/mixed","headers":[{"name":"Content-Type","value":"multipart/mixed; boundary=synthetic"}],"filename":"","body":{"size":0},"parts":[%s,%s]}`, PDF, plain)
	kind, excerpt, _, err := decodeCandidateContentResponse(candidateDocument("m", "t", payload), "m", "t", 1024)
	if err != nil || kind != maildomain.CandidateSourceTextPlain || excerpt != "visible" {
		t.Fatalf("kind=%s excerpt=%q err=%v", kind, excerpt, err)
	}
}

func TestDecodeCandidateExcludesAttachmentSubtrees(t *testing.T) {
	attachedChild := textPart("text/html", "utf-8", []byte(`<p>attached secret</p>`))
	attached := fmt.Sprintf(`{"mimeType":"multipart/mixed","headers":[{"name":"Content-Type","value":"multipart/mixed; name=attached.eml"}],"filename":"attached.eml","body":{"size":0,"attachmentId":"attachment"},"parts":[%s]}`, attachedChild)
	visible := textPart("text/html", "utf-8", []byte(`<p>visible</p>`))
	payload := fmt.Sprintf(`{"mimeType":"multipart/mixed","headers":[],"filename":"","body":{"size":0},"parts":[%s,%s]}`, attached, visible)
	_, excerpt, _, err := decodeCandidateContentResponse(candidateDocument("m", "t", payload), "m", "t", 1024)
	if err != nil || excerpt != "visible" {
		t.Fatalf("excerpt=%q err=%v", excerpt, err)
	}
}

func TestDecodeCandidateHTMLDiscardsActiveHiddenAndLinks(t *testing.T) {
	html := `<html><head><title>secret</title></head><body><p>Hello <a href="https://private.invalid/path">world</a></p><script>steal()</script><style>.x{}</style><div hidden>hidden one</div><div aria-hidden="true">hidden two</div><div style="DISPLAY : none">hidden three</div><form>hidden four</form><p>Done</p></body></html>`
	payload := textPart("text/html", "utf-8", []byte(html))
	kind, excerpt, truncated, err := decodeCandidateContentResponse(candidateDocument("m", "t", payload), "m", "t", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if kind != maildomain.CandidateSourceTextHTML || excerpt != "Hello world\nDone" || truncated {
		t.Fatalf("kind=%s excerpt=%q truncated=%t", kind.String(), excerpt, truncated)
	}
	for _, forbidden := range []string{"https", "secret", "steal", "hidden", "<", ">"} {
		if strings.Contains(excerpt, forbidden) {
			t.Fatalf("excerpt retained %q: %q", forbidden, excerpt)
		}
	}
}

func TestDecodeCandidateHTMLFailsClosedOnEncodedVisibility(t *testing.T) {
	for _, html := range []string{
		`<div aria-hidden="tr&#117;e">hidden</div>`,
		`<div style="display:n&#x6f;ne">hidden</div>`,
	} {
		payload := textPart("text/html", "utf-8", []byte(html))
		if _, _, _, err := decodeCandidateContentResponse(candidateDocument("m", "t", payload), "m", "t", 1024); err == nil {
			t.Fatalf("encoded visibility accepted: %q", html)
		}
	}
}

func TestDecodeCandidateHTMLRejectsNonvoidSelfClosingAndAmbiguousHiddenCSS(t *testing.T) {
	for _, tag := range []string{"div", "script", "style", "template", "noscript", "svg", "math", "head", "form", "object", "iframe", "canvas"} {
		html := "<" + tag + "/>visible"
		if _, err := candidateHTMLToText(html); err == nil {
			t.Fatalf("nonvoid self-closing tag accepted: %q", html)
		}
	}
	for _, html := range []string{
		`<div style="display:none!important">hidden</div><p>visible</p>`,
		`<div style="visibility:hidden ! important">hidden</div><p>visible</p>`,
		`<div style="opacity:0!important">hidden</div><p>visible</p>`,
		`<div style="opacity:0.0">hidden</div><p>visible</p>`,
		`<div style="visibility:collapse">hidden</div><p>visible</p>`,
	} {
		text, err := candidateHTMLToText(html)
		if err != nil || strings.TrimSpace(text) != "visible" {
			t.Fatalf("hidden CSS retained for %q: text=%q err=%v", html, text, err)
		}
	}
	for _, html := range []string{
		`<div style="display:n/**/one">hidden</div>`,
		`<div style="visibility:hidden!synthetic">hidden</div>`,
		`<div style="opacity:calc(0)">hidden</div>`,
		`<div style="display:var(--synthetic)">hidden</div>`,
	} {
		if _, err := candidateHTMLToText(html); err == nil {
			t.Fatalf("ambiguous hidden CSS accepted: %q", html)
		}
	}
	if text, err := candidateHTMLToText(`before<br/>after<img src="synthetic"/>done`); err != nil || text != "before\nafterdone" {
		t.Fatalf("void tags rejected: text=%q err=%v", text, err)
	}
}

func TestCandidateHTMLDiscardHiddenAndVoidVocabularies(t *testing.T) {
	for _, tag := range []string{"script", "style", "template", "noscript", "svg", "math", "head", "form", "object", "iframe", "canvas"} {
		html := "<p>before</p><" + tag + ">secret</" + tag + "><p>after</p>"
		text, err := candidateHTMLToText(html)
		if err != nil || strings.TrimSpace(text) != "before\nafter" {
			t.Fatalf("discard tag %q: text=%q err=%v", tag, text, err)
		}
	}
	for _, attribute := range []string{`hidden`, `aria-hidden="true"`, `style="display:none!important"`, `style="visibility:collapse"`, `style="opacity:0%"`} {
		html := "<p>before</p><div " + attribute + ">secret</div><p>after</p>"
		text, err := candidateHTMLToText(html)
		if err != nil || strings.TrimSpace(text) != "before\nafter" {
			t.Fatalf("hidden attribute %q: text=%q err=%v", attribute, text, err)
		}
	}
	voids := "<area/><base/><br/><col/><embed/><hr/><img/><input/><link/><meta/><param/><source/><track/><wbr/>"
	if text, err := candidateHTMLToText("before" + voids + "after"); err != nil || text != "before\nafter" {
		t.Fatalf("void vocabulary: text=%q err=%v", text, err)
	}
}

func TestDecodeCandidateCharsetsAndUTF8Truncation(t *testing.T) {
	tests := []struct {
		charset string
		body    []byte
		want    string
	}{
		{"us-ascii", []byte("ASCII"), "ASCII"},
		{"iso-8859-1", []byte{0x63, 0x61, 0x66, 0xe9}, "café"},
		{"windows-1252", []byte{0x80, '1', '0'}, "€10"},
	}
	for _, tt := range tests {
		t.Run(tt.charset, func(t *testing.T) {
			_, got, _, err := decodeCandidateContentResponse(candidateDocument("m", "t", textPart("text/plain", tt.charset, tt.body)), "m", "t", 1024)
			if err != nil || got != tt.want {
				t.Fatalf("got=%q err=%v", got, err)
			}
		})
	}
	long := strings.Repeat("a", 1023) + "€more"
	_, got, truncated, err := decodeCandidateContentResponse(candidateDocument("m", "t", textPart("text/plain", "utf-8", []byte(long))), "m", "t", 1024)
	if err != nil || !truncated || len(got) != 1023 || !strings.HasSuffix(got, "a") {
		t.Fatalf("bytes=%d truncated=%t err=%v", len(got), truncated, err)
	}
}

func TestDecodeCandidateRejectsAttachmentsMalformedAndBounds(t *testing.T) {
	attachment := `{"mimeType":"text/plain","headers":[{"name":"Content-Type","value":"text/plain; charset=utf-8"}],"filename":"note.txt","body":{"size":4,"data":"dGVzdA","attachmentId":"att"}}`
	tests := []struct {
		name string
		body []byte
	}{
		{"attachment only", candidateDocument("m", "t", attachment)},
		{"noncanonical base64", candidateDocument("m", "t", strings.Replace(textPart("text/plain", "utf-8", []byte("test")), "dGVzdA", "dGVzdA==", 1))},
		{"size mismatch", candidateDocument("m", "t", strings.Replace(textPart("text/plain", "utf-8", []byte("test")), `"size":4`, `"size":3`, 1))},
		{"unknown charset", candidateDocument("m", "t", textPart("text/plain", "utf-16", []byte("test")))},
		{"malformed html", candidateDocument("m", "t", textPart("text/html", "utf-8", []byte(`<p><b>broken</p>`)))},
		{"wrong identity", candidateDocument("other", "t", textPart("text/plain", "utf-8", []byte("test")))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, _, err := decodeCandidateContentResponse(tt.body, "m", "t", 1024); err == nil {
				t.Fatal("invalid provider content accepted")
			}
		})
	}

	part := textPart("text/plain", "utf-8", []byte("ok"))
	for depth := 1; depth < MaximumMessagePartDepth; depth++ {
		part = fmt.Sprintf(`{"mimeType":"multipart/mixed","headers":[{"name":"Content-Type","value":"multipart/mixed"}],"filename":"","body":{"size":0},"parts":[%s]}`, part)
	}
	if _, excerpt, _, err := decodeCandidateContentResponse(candidateDocument("m", "t", part), "m", "t", 1024); err != nil || excerpt != "ok" {
		t.Fatalf("exact MIME depth rejected: excerpt=%q err=%v", excerpt, err)
	}
	part = fmt.Sprintf(`{"mimeType":"multipart/mixed","headers":[{"name":"Content-Type","value":"multipart/mixed"}],"filename":"","body":{"size":0},"parts":[%s]}`, part)
	if _, _, _, err := decodeCandidateContentResponse(candidateDocument("m", "t", part), "m", "t", 1024); err == nil {
		t.Fatal("one-over MIME depth accepted")
	}
}

func TestDecodeCandidateResponseAndMIMECountBoundaries(t *testing.T) {
	valid := candidateDocument("m", "t", textPart("text/plain", "utf-8", []byte("ok")))
	exact := append(append([]byte(nil), valid...), bytes.Repeat([]byte(" "), MaximumCandidateContentBodyBytes-len(valid))...)
	if _, excerpt, _, err := decodeCandidateContentResponse(exact, "m", "t", 1024); err != nil || excerpt != "ok" {
		t.Fatalf("exact response bound rejected: excerpt=%q err=%v", excerpt, err)
	}
	oneOver := append(append([]byte(nil), exact...), ' ')
	if _, _, _, err := decodeCandidateContentResponse(oneOver, "m", "t", 1024); err == nil {
		t.Fatal("one-over response bound accepted")
	}
	for _, limit := range []int{maildomain.MinimumExcerptBytes - 1, maildomain.MaximumExcerptBytes + 1} {
		if _, _, _, err := decodeCandidateContentResponse(valid, "m", "t", limit); err == nil {
			t.Fatalf("invalid excerpt limit accepted: %d", limit)
		}
	}

	emptyPart := `{"mimeType":"application/octet-stream","headers":[],"filename":"","body":{"size":0}}`
	parts := make([]string, MaximumMessageParts-1)
	parts[0] = textPart("text/plain", "utf-8", []byte("ok"))
	for index := 1; index < len(parts); index++ {
		parts[index] = emptyPart
	}
	payload := fmt.Sprintf(`{"mimeType":"multipart/mixed","headers":[{"name":"Content-Type","value":"multipart/mixed"}],"filename":"","body":{"size":0},"parts":[%s]}`, strings.Join(parts, ","))
	if _, excerpt, _, err := decodeCandidateContentResponse(candidateDocument("m", "t", payload), "m", "t", 1024); err != nil || excerpt != "ok" {
		t.Fatalf("exact MIME node bound rejected: excerpt=%q err=%v", excerpt, err)
	}
	payload = strings.Replace(payload, `]}`, ","+emptyPart+`]}`, 1)
	if _, _, _, err := decodeCandidateContentResponse(candidateDocument("m", "t", payload), "m", "t", 1024); err == nil {
		t.Fatal("one-over MIME node bound accepted")
	}
}

func TestDecodeCandidateDecodedAndHTMLBoundaries(t *testing.T) {
	exactDecoded := bytes.Repeat([]byte("x"), maildomain.MaximumDecodedContentBytes)
	if _, excerpt, truncated, err := decodeCandidateContentResponse(candidateDocument("m", "t", textPart("text/plain", "utf-8", exactDecoded)), "m", "t", 1024); err != nil || len(excerpt) != 1024 || !truncated {
		t.Fatalf("exact decoded bound rejected: bytes=%d truncated=%t err=%v", len(excerpt), truncated, err)
	}
	oneOverDecoded := append(append([]byte(nil), exactDecoded...), 'x')
	if _, _, _, err := decodeCandidateContentResponse(candidateDocument("m", "t", textPart("text/plain", "utf-8", oneOverDecoded)), "m", "t", 1024); err == nil {
		t.Fatal("one-over decoded bound accepted")
	}
	exactExpansion := bytes.Repeat([]byte{0xe9}, maildomain.MaximumDecodedContentBytes/2)
	if _, excerpt, truncated, err := decodeCandidateContentResponse(candidateDocument("m", "t", textPart("text/plain", "iso-8859-1", exactExpansion)), "m", "t", 1024); err != nil || len(excerpt) != 1024 || !truncated {
		t.Fatalf("exact charset expansion bound rejected: bytes=%d truncated=%t err=%v", len(excerpt), truncated, err)
	}
	oneOverExpansion := append(append([]byte(nil), exactExpansion...), 0xe9)
	if _, _, _, err := decodeCandidateContentResponse(candidateDocument("m", "t", textPart("text/plain", "iso-8859-1", oneOverExpansion)), "m", "t", 1024); err == nil {
		t.Fatal("one-over charset expansion bound accepted")
	}

	exactTokens := strings.Repeat("<br>", maximumHTMLTokens) + "ok"
	if _, excerpt, _, err := decodeCandidateContentResponse(candidateDocument("m", "t", textPart("text/html", "utf-8", []byte(exactTokens))), "m", "t", 1024); err != nil || excerpt != "ok" {
		t.Fatalf("exact HTML token bound rejected: excerpt=%q err=%v", excerpt, err)
	}
	oneOverTokens := "<br>" + exactTokens
	if _, _, _, err := decodeCandidateContentResponse(candidateDocument("m", "t", textPart("text/html", "utf-8", []byte(oneOverTokens))), "m", "t", 1024); err == nil {
		t.Fatal("one-over HTML token bound accepted")
	}

	exactDepth := strings.Repeat("<div>", MaximumMessagePartDepth) + "ok" + strings.Repeat("</div>", MaximumMessagePartDepth)
	if _, excerpt, _, err := decodeCandidateContentResponse(candidateDocument("m", "t", textPart("text/html", "utf-8", []byte(exactDepth))), "m", "t", 1024); err != nil || excerpt != "ok" {
		t.Fatalf("exact HTML depth rejected: excerpt=%q err=%v", excerpt, err)
	}
	oneOverDepth := "<div>" + exactDepth + "</div>"
	if _, _, _, err := decodeCandidateContentResponse(candidateDocument("m", "t", textPart("text/html", "utf-8", []byte(oneOverDepth))), "m", "t", 1024); err == nil {
		t.Fatal("one-over HTML depth accepted")
	}
}

func seedCandidateMessage(t *testing.T, fixture *discoveryFixture, candidate bool) (maildomain.Message, storage.GateDecision) {
	t.Helper()
	to := []string{}
	if candidate {
		to = []string{"owner@example.test"}
	}
	message, err := maildomain.Normalize(fixture.accountID.String(), maildomain.MessageInput{GmailMessageID: "content-message", GmailThreadID: "content-thread", To: to, CC: []string{}, DeliveredTo: []string{}, Labels: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	next, _ := storage.ParseHistoryID("101")
	if err := fixture.store.Handle.CommitCurrentDiscovery(context.Background(), storage.CurrentDiscoveryCommit{AccountID: fixture.accountID, Expected: mustHistoryID(t, discoveryStartCursor), Next: next, Messages: []maildomain.Message{message}}); err != nil {
		t.Fatal(err)
	}
	classification, err := gate.Classify(message, config.Defaults().Gate)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := storage.NewGateDecision(classification, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Handle.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: message, Next: decision}); err != nil {
		t.Fatal(err)
	}
	return message, decision
}

func mustHistoryID(t *testing.T, value string) storage.HistoryID {
	t.Helper()
	id, err := storage.ParseHistoryID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestCandidateContentExtractorSyntheticFlowAndExactRequest(t *testing.T) {
	fixture := newDiscoveryFixture(t, 1)
	message, decision := seedCandidateMessage(t, fixture, true)
	requests := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		switch request.URL.Path {
		case "/token":
			assertRefreshRequest(t, request)
			return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
		case "/gmail/v1/users/me/messages/content-message":
			if request.Method != http.MethodGet || request.Body != nil && request.Body != http.NoBody || request.Header.Get("Authorization") != "Bearer "+discoveryAccessText || request.URL.Query().Get("format") != "FULL" || request.URL.Query().Get("fields") != candidateContentFields {
				t.Fatalf("content request = %s %s headers=%#v", request.Method, request.URL, request.Header)
			}
			return jsonResponse(http.StatusOK, string(candidateDocument(message.GmailMessageID(), message.GmailThreadID(), textPart("text/plain", "utf-8", []byte(strings.Repeat("x", 1100)))))), nil
		default:
			t.Fatalf("unexpected path %q", request.URL.Path)
			return nil, fmt.Errorf("unexpected synthetic request")
		}
	})
	extractor, err := newCandidateContentExtractor(candidateContentOptions{clientID: []byte(syntheticClientID), clientSecret: []byte(syntheticClientSecret), store: fixture.store, keyring: fixture.keyring}, candidateContentDependencies{endpoints: candidateContentEndpoints{token: discoveryLoopbackEndpoints.token, message: discoveryLoopbackEndpoints.message}, transport: transport, jitter: zeroReader{}, sleep: func(context.Context, time.Duration) error { return nil }, now: func() time.Time { return time.UnixMilli(1700000000123) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(extractor.Close)
	content, err := extractor.Extract(context.Background(), fixture.accountID, message.GmailMessageID(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || content.GateInputHash() != decision.InputHash() || content.ExcerptBytes() != 1024 || !content.Truncated() || content.ContentTrust() != maildomain.ContentTrustUntrustedEmail {
		t.Fatalf("requests=%d content=%#v", requests, content)
	}
	state, err := fixture.store.GetCandidateContent(context.Background(), fixture.accountID, message.GmailMessageID(), 1024)
	if err != nil || !state.Current || !state.Content.Equal(content) {
		t.Fatalf("state=%#v err=%v", state, err)
	}
}

func TestCandidateContentExtractorIneligibleStopsBeforeProvider(t *testing.T) {
	fixture := newDiscoveryFixture(t, 1)
	message, _ := seedCandidateMessage(t, fixture, false)
	calls := 0
	extractor, err := newCandidateContentExtractor(candidateContentOptions{clientID: []byte(syntheticClientID), clientSecret: []byte(syntheticClientSecret), store: fixture.store, keyring: fixture.keyring}, candidateContentDependencies{endpoints: candidateContentEndpoints{token: discoveryLoopbackEndpoints.token, message: discoveryLoopbackEndpoints.message}, transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, fmt.Errorf("provider contact forbidden")
	}), now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(extractor.Close)
	if _, err := extractor.Extract(context.Background(), fixture.accountID, message.GmailMessageID(), 1024); err != ErrCandidateContentIneligible || calls != 0 {
		t.Fatalf("error=%v provider_calls=%d", err, calls)
	}
}

func TestCandidateContentExtractorRechecksAuthorityBeforeContentRequest(t *testing.T) {
	fixture := newDiscoveryFixture(t, 1)
	message, _ := seedCandidateMessage(t, fixture, true)
	fixture.store.secondLifecycleOverride = lifecycleWith(storage.AccountStatePaused, 3)
	calls := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Path != "/token" {
			t.Fatalf("content request crossed changed authority: %s", request.URL.Path)
		}
		return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
	})
	extractor, err := newCandidateContentExtractor(candidateContentOptions{clientID: []byte(syntheticClientID), clientSecret: []byte(syntheticClientSecret), store: fixture.store, keyring: fixture.keyring}, candidateContentDependencies{endpoints: candidateContentEndpoints{token: discoveryLoopbackEndpoints.token, message: discoveryLoopbackEndpoints.message}, transport: transport, jitter: zeroReader{}, sleep: fixture.sleep, now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(extractor.Close)
	if _, err := extractor.Extract(context.Background(), fixture.accountID, message.GmailMessageID(), 1024); !errors.Is(err, ErrCandidateContentInactiveAccount) || calls != 1 {
		t.Fatalf("error=%v provider_calls=%d", err, calls)
	}
}

func TestCandidateContentExtractorProviderClassificationsAndRetryBound(t *testing.T) {
	tests := []struct {
		name             string
		status           int
		body             string
		want             error
		wantContentCalls int
		wantReauthorize  bool
	}{
		{name: "vanished", status: http.StatusNotFound, body: `{}`, want: ErrCandidateContentVanished, wantContentCalls: 1},
		{name: "unauthorized", status: http.StatusUnauthorized, body: `{}`, want: ErrCandidateContentReauthorizationRequired, wantContentCalls: 1, wantReauthorize: true},
		{name: "domain policy", status: http.StatusForbidden, body: googleErrorJSON("domainPolicy"), want: ErrCandidateContentReauthorizationRequired, wantContentCalls: 1, wantReauthorize: true},
		{name: "other forbidden", status: http.StatusForbidden, body: googleErrorJSON("insufficientPermissions"), want: ErrCandidateContentUnavailable, wantContentCalls: 1},
		{name: "retry exhausted", status: http.StatusTooManyRequests, body: googleErrorJSON("rateLimitExceeded"), want: ErrCandidateContentUnavailable, wantContentCalls: MaximumProviderAttempts},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDiscoveryFixture(t, 1)
			message, _ := seedCandidateMessage(t, fixture, true)
			contentCalls := 0
			transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Path == "/token" {
					return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
				}
				contentCalls++
				return jsonResponse(test.status, test.body), nil
			})
			extractor, err := newCandidateContentExtractor(candidateContentOptions{clientID: []byte(syntheticClientID), clientSecret: []byte(syntheticClientSecret), store: fixture.store, keyring: fixture.keyring}, candidateContentDependencies{endpoints: candidateContentEndpoints{token: discoveryLoopbackEndpoints.token, message: discoveryLoopbackEndpoints.message}, transport: transport, jitter: zeroReader{}, sleep: fixture.sleep, now: time.Now})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(extractor.Close)
			if _, err := extractor.Extract(context.Background(), fixture.accountID, message.GmailMessageID(), 1024); !errors.Is(err, test.want) || contentCalls != test.wantContentCalls {
				t.Fatalf("error=%v content_calls=%d", err, contentCalls)
			}
			lifecycle, err := fixture.store.Handle.GetAccountLifecycle(context.Background(), fixture.accountID)
			if err != nil {
				t.Fatal(err)
			}
			if test.wantReauthorize && lifecycle.State != storage.AccountStateReauthorizationRequired {
				t.Fatalf("lifecycle=%#v", lifecycle)
			}
			if !test.wantReauthorize && lifecycle.State != storage.AccountStateActive {
				t.Fatalf("lifecycle=%#v", lifecycle)
			}
		})
	}
}

func TestCandidateContentExtractorRejectsPostRefreshSourceChanges(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *discoveryFixture, maildomain.Message, storage.GateDecision)
	}{
		{name: "message metadata", mutate: func(t *testing.T, fixture *discoveryFixture, message maildomain.Message, _ storage.GateDecision) {
			fixture.store.candidateMessageRead = 2
			fixture.store.candidateMessageValue = changedCandidateMessage(t, fixture.accountID, message)
		}},
		{name: "gate observation", mutate: func(t *testing.T, fixture *discoveryFixture, _ maildomain.Message, decision storage.GateDecision) {
			changed, err := storage.DecodeGateDecision(int64(decision.Version()), decision.SourceMetadataHash(), decision.InputHash(), decision.Outcome().String(), decision.ReasonJSON(), decision.EvaluatedAtUnixMS()+1)
			if err != nil {
				t.Fatal(err)
			}
			fixture.store.candidateGateRead = 2
			fixture.store.candidateGateValue = storage.GateDecisionState{Decision: changed, Current: true}
		}},
		{name: "gate input", mutate: func(t *testing.T, fixture *discoveryFixture, message maildomain.Message, _ storage.GateDecision) {
			policy := config.Defaults().Gate
			policy.MailingListIsBulkSignal = !policy.MailingListIsBulkSignal
			fixture.store.candidateGateRead = 2
			fixture.store.candidateGateValue = storage.GateDecisionState{Decision: candidateDecision(t, message, policy, 2000), Current: true}
		}},
		{name: "gate outcome", mutate: func(t *testing.T, fixture *discoveryFixture, message maildomain.Message, _ storage.GateDecision) {
			policy := config.Defaults().Gate
			policy.DirectRecipientIsCandidate = false
			fixture.store.candidateGateRead = 2
			fixture.store.candidateGateValue = storage.GateDecisionState{Decision: candidateDecision(t, message, policy, 2000), Current: true}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDiscoveryFixture(t, 1)
			message, decision := seedCandidateMessage(t, fixture, true)
			test.mutate(t, fixture, message, decision)
			calls := 0
			extractor := candidateExtractorForTest(t, fixture, roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.URL.Path != "/token" {
					t.Fatalf("content request crossed changed source: %s", request.URL.Path)
				}
				return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
			}), fixture.sleep)
			if _, err := extractor.Extract(context.Background(), fixture.accountID, message.GmailMessageID(), 1024); !errors.Is(err, ErrCandidateContentConflict) || calls != 1 || fixture.store.candidateCommitCount != 0 {
				t.Fatalf("error=%v provider_calls=%d writes=%d", err, calls, fixture.store.candidateCommitCount)
			}
		})
	}
}

func TestCandidateContentExtractorRejectsPostGETAuthorityChanges(t *testing.T) {
	tests := []struct {
		name string
		want error
		hook func(*testing.T, *discoveryFixture, maildomain.Message, storage.GateDecision)
	}{
		{name: "lifecycle", want: ErrCandidateContentInactiveAccount, hook: func(t *testing.T, fixture *discoveryFixture, _ maildomain.Message, _ storage.GateDecision) {
			lifecycle, err := fixture.store.Handle.GetAccountLifecycle(context.Background(), fixture.accountID)
			if err != nil {
				t.Fatal(err)
			}
			if err := fixture.store.Handle.CommitAccountLifecycle(context.Background(), storage.LifecycleCommit{AccountID: fixture.accountID, ExpectedState: lifecycle.State, ExpectedVersion: lifecycle.Version, ExpectedRevocationStatus: lifecycle.RevocationStatus, NextState: storage.AccountStatePaused, RevocationStatus: storage.RevocationStatusNone}); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "message metadata", want: ErrCandidateContentConflict, hook: func(t *testing.T, fixture *discoveryFixture, message maildomain.Message, _ storage.GateDecision) {
			next, _ := storage.ParseHistoryID("102")
			if err := fixture.store.Handle.CommitCurrentDiscovery(context.Background(), storage.CurrentDiscoveryCommit{AccountID: fixture.accountID, Expected: mustHistoryID(t, "101"), Next: next, Messages: []maildomain.Message{changedCandidateMessage(t, fixture.accountID, message)}}); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "gate", want: ErrCandidateContentConflict, hook: func(t *testing.T, fixture *discoveryFixture, message maildomain.Message, decision storage.GateDecision) {
			policy := config.Defaults().Gate
			policy.MailingListIsBulkSignal = !policy.MailingListIsBulkSignal
			next := candidateDecision(t, message, policy, 2000)
			revision := decision.Revision()
			if err := fixture.store.Handle.CommitGateDecision(context.Background(), storage.GateDecisionCommit{Source: message, Expected: &revision, Next: next}); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDiscoveryFixture(t, 1)
			message, decision := seedCandidateMessage(t, fixture, true)
			fixture.store.beforeCandidateCommit = func(context.Context, storage.CandidateContentCommit) {
				test.hook(t, fixture, message, decision)
			}
			calls := 0
			extractor := candidateExtractorForTest(t, fixture, roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.URL.Path == "/token" {
					return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
				}
				return jsonResponse(http.StatusOK, string(candidateDocument(message.GmailMessageID(), message.GmailThreadID(), textPart("text/plain", "utf-8", []byte("visible"))))), nil
			}), fixture.sleep)
			if _, err := extractor.Extract(context.Background(), fixture.accountID, message.GmailMessageID(), 1024); !errors.Is(err, test.want) || calls != 2 || fixture.store.candidateCommitCount != 1 {
				t.Fatalf("error=%v provider_calls=%d writes=%d", err, calls, fixture.store.candidateCommitCount)
			}
		})
	}
}

func TestCandidateContentExtractorRefreshClassifications(t *testing.T) {
	for _, test := range []struct {
		name   string
		error  string
		reason storage.ReauthorizationReason
	}{
		{name: "invalid grant", error: "invalid_grant", reason: storage.ReauthorizationReasonRefreshInvalidGrant},
		{name: "admin policy", error: "admin_policy_enforced", reason: storage.ReauthorizationReasonRefreshAdminPolicyEnforced},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDiscoveryFixture(t, 1)
			message, _ := seedCandidateMessage(t, fixture, true)
			calls := 0
			extractor := candidateExtractorForTest(t, fixture, roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return jsonResponse(http.StatusBadRequest, `{"error":"`+test.error+`"}`), nil
			}), fixture.sleep)
			if _, err := extractor.Extract(context.Background(), fixture.accountID, message.GmailMessageID(), 1024); !errors.Is(err, ErrCandidateContentReauthorizationRequired) || calls != 1 || fixture.store.candidateCommitCount != 0 {
				t.Fatalf("error=%v provider_calls=%d writes=%d", err, calls, fixture.store.candidateCommitCount)
			}
			lifecycle, err := fixture.store.Handle.GetAccountLifecycle(context.Background(), fixture.accountID)
			if err != nil || lifecycle.ReauthorizationReason == nil || *lifecycle.ReauthorizationReason != test.reason {
				t.Fatalf("lifecycle=%#v err=%v", lifecycle, err)
			}
		})
	}
}

func TestCandidateContentExtractorCancellationAndDiagnosticSuppression(t *testing.T) {
	t.Run("preflight cancellation", func(t *testing.T) {
		fixture := newDiscoveryFixture(t, 1)
		message, _ := seedCandidateMessage(t, fixture, true)
		calls := 0
		extractor := candidateExtractorForTest(t, fixture, roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return nil, errors.New("provider contact forbidden")
		}), fixture.sleep)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := extractor.Extract(ctx, fixture.accountID, message.GmailMessageID(), 1024); !errors.Is(err, context.Canceled) || calls != 0 || fixture.store.candidateCommitCount != 0 {
			t.Fatalf("error=%v provider_calls=%d writes=%d", err, calls, fixture.store.candidateCommitCount)
		}
	})
	t.Run("provider deadline", func(t *testing.T) {
		fixture := newDiscoveryFixture(t, 1)
		message, _ := seedCandidateMessage(t, fixture, true)
		calls := 0
		extractor := candidateExtractorForTest(t, fixture, roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			if request.URL.Path == "/token" {
				return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
			}
			return nil, context.DeadlineExceeded
		}), func(context.Context, time.Duration) error { return context.DeadlineExceeded })
		if _, err := extractor.Extract(context.Background(), fixture.accountID, message.GmailMessageID(), 1024); !errors.Is(err, context.DeadlineExceeded) || calls != 2 || fixture.store.candidateCommitCount != 0 {
			t.Fatalf("error=%v provider_calls=%d writes=%d", err, calls, fixture.store.candidateCommitCount)
		}
	})
	t.Run("retry sleep cancellation", func(t *testing.T) {
		fixture := newDiscoveryFixture(t, 1)
		message, _ := seedCandidateMessage(t, fixture, true)
		calls, sleeps := 0, 0
		ctx, cancel := context.WithCancel(context.Background())
		extractor := candidateExtractorForTest(t, fixture, roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			if request.URL.Path == "/token" {
				return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
			}
			return jsonResponse(http.StatusTooManyRequests, googleErrorJSON("rateLimitExceeded")), nil
		}), func(context.Context, time.Duration) error {
			sleeps++
			cancel()
			return ctx.Err()
		})
		if _, err := extractor.Extract(ctx, fixture.accountID, message.GmailMessageID(), 1024); !errors.Is(err, context.Canceled) || calls != 2 || sleeps != 1 || fixture.store.candidateCommitCount != 0 {
			t.Fatalf("error=%v provider_calls=%d sleeps=%d writes=%d", err, calls, sleeps, fixture.store.candidateCommitCount)
		}
	})
	t.Run("raw provider diagnostic", func(t *testing.T) {
		fixture := newDiscoveryFixture(t, 1)
		message, _ := seedCandidateMessage(t, fixture, true)
		extractor := candidateExtractorForTest(t, fixture, roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Path == "/token" {
				return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
			}
			return nil, errors.New("synthetic-private-provider-diagnostic")
		}), func(context.Context, time.Duration) error { return nil })
		_, err := extractor.Extract(context.Background(), fixture.accountID, message.GmailMessageID(), 1024)
		if !errors.Is(err, ErrCandidateContentUnavailable) || strings.Contains(err.Error(), "synthetic-private") {
			t.Fatalf("diagnostic crossed boundary: %v", err)
		}
	})
	t.Run("raw storage diagnostic", func(t *testing.T) {
		fixture := newDiscoveryFixture(t, 1)
		message, _ := seedCandidateMessage(t, fixture, true)
		fixture.store.failCandidateCommit = errors.New("synthetic-private-storage-diagnostic")
		extractor := candidateExtractorForTest(t, fixture, roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Path == "/token" {
				return jsonResponse(http.StatusOK, refreshSuccessJSON()), nil
			}
			return jsonResponse(http.StatusOK, string(candidateDocument(message.GmailMessageID(), message.GmailThreadID(), textPart("text/plain", "utf-8", []byte("visible"))))), nil
		}), fixture.sleep)
		_, err := extractor.Extract(context.Background(), fixture.accountID, message.GmailMessageID(), 1024)
		if !errors.Is(err, ErrCandidateContentRecoveryRequired) || strings.Contains(err.Error(), "synthetic-private") || fixture.store.candidateCommitCount != 1 {
			t.Fatalf("diagnostic crossed boundary: %v writes=%d", err, fixture.store.candidateCommitCount)
		}
	})
}

func candidateExtractorForTest(t *testing.T, fixture *discoveryFixture, transport http.RoundTripper, sleep func(context.Context, time.Duration) error) *CandidateContentExtractor {
	t.Helper()
	extractor, err := newCandidateContentExtractor(candidateContentOptions{clientID: []byte(syntheticClientID), clientSecret: []byte(syntheticClientSecret), store: fixture.store, keyring: fixture.keyring}, candidateContentDependencies{endpoints: candidateContentEndpoints{token: discoveryLoopbackEndpoints.token, message: discoveryLoopbackEndpoints.message}, transport: transport, jitter: zeroReader{}, sleep: sleep, now: func() time.Time { return time.UnixMilli(1700000000123) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(extractor.Close)
	return extractor
}

func changedCandidateMessage(t *testing.T, accountID storage.AccountID, message maildomain.Message) maildomain.Message {
	t.Helper()
	changed, err := maildomain.Normalize(accountID.String(), maildomain.MessageInput{GmailMessageID: message.GmailMessageID(), GmailThreadID: message.GmailThreadID(), Subject: "changed metadata", To: []string{"owner@example.test"}, CC: []string{}, DeliveredTo: []string{}, Labels: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

func candidateDecision(t *testing.T, message maildomain.Message, policy config.Gate, timestamp int64) storage.GateDecision {
	t.Helper()
	classification, err := gate.Classify(message, policy)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := storage.NewGateDecision(classification, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	return decision
}
