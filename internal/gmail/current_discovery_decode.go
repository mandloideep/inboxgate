package gmail

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	stdmail "net/mail"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	maildomain "github.com/mandloideep/inboxgate/internal/mail"
	"github.com/mandloideep/inboxgate/internal/storage"
)

var messageMetadataFields = buildMessageMetadataFields()

type decodedHistoryPage struct {
	records       []decodedHistoryRecord
	historyID     storage.HistoryID
	nextPageToken string
}

type decodedHistoryRecord struct {
	id         storage.HistoryID
	identities []discoveredIdentity
}

type historyPageJSON struct {
	History       json.RawMessage `json:"history"`
	HistoryID     *string         `json:"historyId"`
	NextPageToken json.RawMessage `json:"nextPageToken"`
}

type historyRecordJSON struct {
	ID            *string         `json:"id"`
	MessagesAdded json.RawMessage `json:"messagesAdded"`
}

type historyAdditionJSON struct {
	Message *historyMessageJSON `json:"message"`
}

type historyMessageJSON struct {
	ID       *string `json:"id"`
	ThreadID *string `json:"threadId"`
}

type messageJSONDocument struct {
	ID           *string             `json:"id"`
	ThreadID     *string             `json:"threadId"`
	LabelIDs     *[]string           `json:"labelIds"`
	InternalDate *string             `json:"internalDate"`
	SizeEstimate *uint32             `json:"sizeEstimate"`
	Payload      *messagePayloadJSON `json:"payload"`
}

type messagePayloadJSON struct {
	Headers  *[]messageHeaderJSON `json:"headers"`
	Filename *string              `json:"filename"`
	Body     *messagePartBodyJSON `json:"body"`
	Parts    json.RawMessage      `json:"parts"`
}

type messageHeaderJSON struct {
	Name  *string `json:"name"`
	Value *string `json:"value"`
}

type messagePartJSON struct {
	PartID   *string              `json:"partId"`
	Filename *string              `json:"filename"`
	Body     *messagePartBodyJSON `json:"body"`
	Parts    json.RawMessage      `json:"parts"`
}

type messagePartBodyJSON struct {
	AttachmentID *string `json:"attachmentId"`
}

type googleErrorEnvelope struct {
	Error *googleErrorObject `json:"error"`
}

type googleErrorObject struct {
	Code    *int               `json:"code"`
	Message *string            `json:"message"`
	Status  *string            `json:"status"`
	Errors  *[]googleErrorItem `json:"errors"`
}

type googleErrorItem struct {
	Domain       *string `json:"domain"`
	Message      *string `json:"message"`
	Reason       *string `json:"reason"`
	Location     *string `json:"location"`
	LocationType *string `json:"locationType"`
}

func buildMessageMetadataFields() string {
	part := "filename,body(attachmentId),parts(partId)"
	for depth := MaximumMessagePartDepth - 1; depth >= 1; depth-- {
		part = "filename,body(attachmentId),parts(" + part + ")"
	}
	return "id,threadId,labelIds,internalDate,sizeEstimate,payload(headers(name,value),filename,body(attachmentId),parts(" + part + "))"
}

func validateRefreshSuccess(body []byte) error {
	fields, err := decodeStrictRawObject(body)
	if err != nil {
		return err
	}
	for name := range fields {
		switch name {
		case "access_token", "token_type", "expires_in", "scope":
		default:
			return ErrCurrentDiscoveryRefreshFailed
		}
	}
	var accessToken, tokenType string
	if raw := fields["access_token"]; raw == nil || json.Unmarshal(raw, &accessToken) != nil || len(accessToken) < 1 || len(accessToken) > maximumAccessTokenBytes {
		return ErrCurrentDiscoveryRefreshFailed
	}
	if raw := fields["token_type"]; raw == nil || json.Unmarshal(raw, &tokenType) != nil || tokenType != "Bearer" {
		return ErrCurrentDiscoveryRefreshFailed
	}
	expiryRaw := fields["expires_in"]
	if !canonicalPositiveDecimal(expiryRaw) {
		return ErrCurrentDiscoveryRefreshFailed
	}
	expiry, err := strconv.ParseUint(string(expiryRaw), 10, 32)
	if err != nil || expiry > maximumOAuthExpirySeconds {
		return ErrCurrentDiscoveryRefreshFailed
	}
	if raw, present := fields["scope"]; present {
		var scope string
		if json.Unmarshal(raw, &scope) != nil || !exactScope(scope) {
			return ErrCurrentDiscoveryRefreshFailed
		}
	}
	return nil
}

func classifyRefreshError(body []byte) refreshClassification {
	fields, err := decodeStrictRawObject(body)
	if err != nil || len(fields) != 1 {
		return refreshUnclassified
	}
	var code string
	if json.Unmarshal(fields["error"], &code) != nil {
		return refreshUnclassified
	}
	switch code {
	case "invalid_grant":
		return refreshInvalidGrant
	case "admin_policy_enforced":
		return refreshAdminPolicy
	default:
		return refreshUnclassified
	}
}

func decodeHistoryPage(body []byte) (decodedHistoryPage, error) {
	document, err := decodeExactObject(body, "history", "historyId", "nextPageToken")
	if err != nil {
		return decodedHistoryPage{}, ErrCurrentDiscoveryInvalidProviderResponse
	}
	historyIDText, err := requiredJSONString(document, "historyId")
	if err != nil {
		return decodedHistoryPage{}, ErrCurrentDiscoveryInvalidProviderResponse
	}
	historyID, err := storage.ParseHistoryID(historyIDText)
	if err != nil {
		return decodedHistoryPage{}, ErrCurrentDiscoveryInvalidProviderResponse
	}
	result := decodedHistoryPage{historyID: historyID}
	if raw, present := document["nextPageToken"]; present {
		pageToken, err := decodeJSONString(raw)
		if err != nil || !validOpaquePageToken(pageToken) {
			return decodedHistoryPage{}, ErrCurrentDiscoveryInvalidProviderResponse
		}
		result.nextPageToken = pageToken
	}
	historyRaw, present := document["history"]
	if !present {
		return result, nil
	}
	records, err := decodeJSONArray(historyRaw)
	if err != nil || len(records) > storage.MaximumCurrentDiscoveryPageMessages {
		return decodedHistoryPage{}, ErrCurrentDiscoveryInvalidProviderResponse
	}
	result.records = make([]decodedHistoryRecord, 0, len(records))
	additionCount := 0
	for _, recordRaw := range records {
		record, err := decodeExactObject(recordRaw, "id", "messagesAdded")
		if err != nil {
			return decodedHistoryPage{}, ErrCurrentDiscoveryInvalidProviderResponse
		}
		recordIDText, err := requiredJSONString(record, "id")
		if err != nil {
			return decodedHistoryPage{}, ErrCurrentDiscoveryInvalidProviderResponse
		}
		recordID, err := storage.ParseHistoryID(recordIDText)
		if err != nil {
			return decodedHistoryPage{}, ErrCurrentDiscoveryInvalidProviderResponse
		}
		decodedRecord := decodedHistoryRecord{id: recordID}
		if additionsRaw, present := record["messagesAdded"]; present {
			additions, err := decodeJSONArray(additionsRaw)
			if err != nil {
				return decodedHistoryPage{}, ErrCurrentDiscoveryInvalidProviderResponse
			}
			additionCount += len(additions)
			if additionCount > storage.MaximumCurrentDiscoveryPageMessages {
				return decodedHistoryPage{}, ErrCurrentDiscoveryInvalidProviderResponse
			}
			decodedRecord.identities = make([]discoveredIdentity, 0, len(additions))
			for _, additionRaw := range additions {
				addition, err := decodeExactObject(additionRaw, "message")
				if err != nil {
					return decodedHistoryPage{}, ErrCurrentDiscoveryInvalidProviderResponse
				}
				messageRaw, present := addition["message"]
				if !present {
					return decodedHistoryPage{}, ErrCurrentDiscoveryInvalidProviderResponse
				}
				message, err := decodeExactObject(messageRaw, "id", "threadId")
				if err != nil {
					return decodedHistoryPage{}, ErrCurrentDiscoveryInvalidProviderResponse
				}
				messageID, messageErr := requiredJSONString(message, "id")
				threadID, threadErr := requiredJSONString(message, "threadId")
				if messageErr != nil || threadErr != nil || storage.ValidateGmailMessageID(messageID) != nil || storage.ValidateGmailMessageID(threadID) != nil {
					return decodedHistoryPage{}, ErrCurrentDiscoveryInvalidProviderResponse
				}
				decodedRecord.identities = append(decodedRecord.identities, discoveredIdentity{messageID: messageID, threadID: threadID})
			}
		}
		result.records = append(result.records, decodedRecord)
	}
	return result, nil
}

func decodeMessageMetadata(body []byte, identity discoveredIdentity) (maildomain.MessageInput, error) {
	document, err := decodeExactObject(body, "id", "threadId", "labelIds", "internalDate", "sizeEstimate", "payload")
	if err != nil {
		return maildomain.MessageInput{}, ErrCurrentDiscoveryInvalidProviderResponse
	}
	messageID, messageErr := requiredJSONString(document, "id")
	threadID, threadErr := requiredJSONString(document, "threadId")
	internalDateText, dateErr := requiredJSONString(document, "internalDate")
	if messageErr != nil || threadErr != nil || dateErr != nil || messageID != identity.messageID || threadID != identity.threadID {
		return maildomain.MessageInput{}, ErrCurrentDiscoveryInvalidProviderResponse
	}
	internalDate, err := strconv.ParseInt(internalDateText, 10, 64)
	if err != nil || internalDate < 0 || strconv.FormatInt(internalDate, 10) != internalDateText {
		return maildomain.MessageInput{}, ErrCurrentDiscoveryInvalidProviderResponse
	}
	labelsRaw, labelsPresent := document["labelIds"]
	sizeRaw, sizePresent := document["sizeEstimate"]
	payloadRaw, payloadPresent := document["payload"]
	if !labelsPresent || !sizePresent || !payloadPresent || isJSONNull(labelsRaw) || isJSONNull(sizeRaw) || isJSONNull(payloadRaw) {
		return maildomain.MessageInput{}, ErrCurrentDiscoveryInvalidProviderResponse
	}
	var labels []string
	var sizeEstimate uint32
	if decodeStrict(labelsRaw, &labels) != nil || labels == nil || decodeStrict(sizeRaw, &sizeEstimate) != nil {
		return maildomain.MessageInput{}, ErrCurrentDiscoveryInvalidProviderResponse
	}
	payload, err := decodeExactObject(payloadRaw, "headers", "filename", "body", "parts")
	if err != nil {
		return maildomain.MessageInput{}, ErrCurrentDiscoveryInvalidProviderResponse
	}
	headersRaw, present := payload["headers"]
	if !present {
		return maildomain.MessageInput{}, ErrCurrentDiscoveryInvalidProviderResponse
	}
	headers, err := decodeMessageHeaders(headersRaw)
	if err != nil {
		return maildomain.MessageInput{}, ErrCurrentDiscoveryInvalidProviderResponse
	}
	selected, err := selectHeaders(headers)
	if err != nil {
		return maildomain.MessageInput{}, err
	}
	if filename, present, err := optionalJSONString(payload, "filename"); err != nil || present && !validMIMEFilename(filename) {
		return maildomain.MessageInput{}, ErrCurrentDiscoveryInvalidProviderResponse
	}
	if bodyRaw, present := payload["body"]; present && !isJSONNull(bodyRaw) {
		attachmentID, err := decodePartBody(bodyRaw)
		if err != nil || !validAttachmentID(attachmentID) {
			return maildomain.MessageInput{}, ErrCurrentDiscoveryInvalidProviderResponse
		}
	}
	parts, attachments, err := decodeMessageParts(payload["parts"])
	if err != nil || parts > MaximumMessageParts || attachments > MaximumMessageParts {
		return maildomain.MessageInput{}, ErrCurrentDiscoveryInvalidProviderResponse
	}
	input := maildomain.MessageInput{
		GmailMessageID: identity.messageID, GmailThreadID: identity.threadID, InternalDateMS: internalDate,
		Labels: append([]string(nil), labels...), SizeEstimate: sizeEstimate,
		AttachmentCount: uint16(attachments),
	}
	applySelectedHeaders(&input, selected)
	return input, nil
}

func decodeMessageParts(raw json.RawMessage) (int, int, error) {
	if len(raw) == 0 {
		return 0, 0, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return 0, 0, nil
	}
	var parts []json.RawMessage
	if err := decodeStrict(raw, &parts); err != nil {
		return 0, 0, err
	}
	count := 0
	attachments := 0
	for _, part := range parts {
		if err := walkMessagePart(part, 1, &count, &attachments); err != nil {
			return 0, 0, err
		}
	}
	return count, attachments, nil
}

func walkMessagePart(raw json.RawMessage, depth int, count, attachments *int) error {
	if depth > MaximumMessagePartDepth {
		return ErrCurrentDiscoveryInvalidProviderResponse
	}
	*count++
	if *count > MaximumMessageParts {
		return ErrCurrentDiscoveryInvalidProviderResponse
	}
	part, err := decodeExactObject(raw, "partId", "filename", "body", "parts")
	if err != nil {
		return ErrCurrentDiscoveryInvalidProviderResponse
	}
	if partID, present := part["partId"]; present && !isJSONNull(partID) {
		return ErrCurrentDiscoveryInvalidProviderResponse
	}
	filename := ""
	if value, present, err := optionalJSONString(part, "filename"); err != nil || present && !validMIMEFilename(value) {
		return ErrCurrentDiscoveryInvalidProviderResponse
	} else if present {
		filename = value
	}
	attachmentID := ""
	if bodyRaw, present := part["body"]; present && !isJSONNull(bodyRaw) {
		attachmentID, err = decodePartBody(bodyRaw)
		if err != nil || !validAttachmentID(attachmentID) {
			return ErrCurrentDiscoveryInvalidProviderResponse
		}
	}
	if filename != "" || attachmentID != "" {
		*attachments++
	}
	partsRaw, present := part["parts"]
	if !present {
		return nil
	}
	if isJSONNull(partsRaw) {
		return ErrCurrentDiscoveryInvalidProviderResponse
	}
	children, err := decodeJSONArray(partsRaw)
	if err != nil {
		return err
	}
	if depth == MaximumMessagePartDepth && len(children) != 0 {
		return ErrCurrentDiscoveryInvalidProviderResponse
	}
	for _, child := range children {
		if err := walkMessagePart(child, depth+1, count, attachments); err != nil {
			return err
		}
	}
	return nil
}

func decodeMessageHeaders(raw json.RawMessage) ([]messageHeaderJSON, error) {
	values, err := decodeJSONArray(raw)
	if err != nil {
		return nil, err
	}
	headers := make([]messageHeaderJSON, 0, len(values))
	for _, value := range values {
		object, err := decodeExactObject(value, "name", "value")
		if err != nil {
			return nil, err
		}
		name, nameErr := requiredJSONString(object, "name")
		headerValue, valueErr := requiredJSONString(object, "value")
		if nameErr != nil || valueErr != nil {
			return nil, ErrCurrentDiscoveryInvalidProviderResponse
		}
		headers = append(headers, messageHeaderJSON{Name: &name, Value: &headerValue})
	}
	return headers, nil
}

func decodePartBody(raw json.RawMessage) (string, error) {
	object, err := decodeExactObject(raw, "attachmentId")
	if err != nil {
		return "", err
	}
	value, present, err := optionalJSONString(object, "attachmentId")
	if err != nil {
		return "", err
	}
	if !present {
		return "", nil
	}
	return value, nil
}

type selectedHeaders map[string][]string

var selectedHeaderNames = map[string]string{
	"message-id":       "message-id",
	"from":             "from",
	"to":               "to",
	"cc":               "cc",
	"delivered-to":     "delivered-to",
	"subject":          "subject",
	"list-id":          "list-id",
	"list-unsubscribe": "list-unsubscribe",
	"auto-submitted":   "auto-submitted",
	"precedence":       "precedence",
}

func selectHeaders(headers []messageHeaderJSON) (selectedHeaders, error) {
	if len(headers) > MaximumMessageHeaderEntries {
		return nil, ErrCurrentDiscoveryInvalidProviderResponse
	}
	selected := make(selectedHeaders)
	bytesSelected := 0
	for _, header := range headers {
		if header.Name == nil || header.Value == nil {
			return nil, ErrCurrentDiscoveryInvalidProviderResponse
		}
		name, ok := selectedHeaderNames[strings.ToLower(*header.Name)]
		if !ok {
			continue
		}
		bytesSelected += len(*header.Value)
		if bytesSelected > MaximumSelectedHeaderBytes {
			return nil, ErrCurrentDiscoveryInvalidProviderResponse
		}
		selected[name] = append(selected[name], *header.Value)
	}
	return selected, nil
}

func applySelectedHeaders(input *maildomain.MessageInput, headers selectedHeaders) {
	input.RFCMessageID = optionalSingleton(headers["message-id"], 998)
	input.Subject = optionalSingleton(headers["subject"], 4096)
	input.ListID = optionalSingleton(headers["list-id"], 512)
	input.AutoSubmitted = optionalSingleton(headers["auto-submitted"], 128)
	input.Precedence = optionalSingleton(headers["precedence"], 128)
	input.ListUnsubscribe = len(headers["list-unsubscribe"]) != 0
	input.SenderDisplay, input.SenderAddress = optionalSender(headers["from"])
	input.To = optionalAddresses(headers["to"])
	input.CC = optionalAddresses(headers["cc"])
	input.DeliveredTo = optionalAddresses(headers["delivered-to"])
}

func optionalSingleton(values []string, maximum int) string {
	if len(values) != 1 {
		return ""
	}
	decoded, err := new(mime.WordDecoder).DecodeHeader(values[0])
	if err != nil || !validBoundedText(decoded, maximum) {
		return ""
	}
	return decoded
}

func optionalSender(values []string) (string, string) {
	if len(values) != 1 {
		return "", ""
	}
	parser := stdmail.AddressParser{WordDecoder: new(mime.WordDecoder)}
	addresses, err := parser.ParseList(values[0])
	if err != nil || len(addresses) != 1 || !validBoundedText(addresses[0].Name, 512) || !validBoundedText(addresses[0].Address, 512) {
		return "", ""
	}
	return addresses[0].Name, addresses[0].Address
}

func optionalAddresses(values []string) []string {
	result := make([]string, 0)
	parser := stdmail.AddressParser{WordDecoder: new(mime.WordDecoder)}
	for _, value := range values {
		addresses, err := parser.ParseList(value)
		if err != nil {
			continue
		}
		for _, address := range addresses {
			if validBoundedText(address.Address, 512) {
				result = append(result, address.Address)
			}
		}
	}
	return result
}

func validMIMEFilename(value string) bool {
	return validBoundedText(value, maximumMIMEFilenameBytes)
}

func validAttachmentID(value string) bool {
	if len(value) > maximumAttachmentIDBytes {
		return false
	}
	for index := range value {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validOpaquePageToken(value string) bool {
	if len(value) < 1 || len(value) > MaximumPageTokenBytes || !utf8.ValidString(value) {
		return false
	}
	return strings.IndexFunc(value, unicode.IsControl) < 0
}

func exactGoogleErrorReason(body []byte) (string, bool) {
	envelope, err := decodeExactObject(body, "error")
	if err != nil {
		return "", false
	}
	errorRaw, present := envelope["error"]
	if !present {
		return "", false
	}
	errorObject, err := decodeExactObject(errorRaw, "code", "message", "status", "errors")
	if err != nil {
		return "", false
	}
	for _, name := range []string{"message", "status"} {
		if _, _, err := optionalJSONString(errorObject, name); err != nil {
			return "", false
		}
	}
	if raw, present := errorObject["code"]; present && !isJSONNull(raw) {
		var code int
		if decodeStrict(raw, &code) != nil {
			return "", false
		}
	}
	errorsRaw, present := errorObject["errors"]
	if !present {
		return "", false
	}
	items, err := decodeJSONArray(errorsRaw)
	if err != nil || len(items) == 0 {
		return "", false
	}
	reason := ""
	for _, raw := range items {
		item, err := decodeExactObject(raw, "domain", "message", "reason", "location", "locationType")
		if err != nil {
			return "", false
		}
		for _, name := range []string{"domain", "message", "location", "locationType"} {
			if _, _, err := optionalJSONString(item, name); err != nil {
				return "", false
			}
		}
		itemReason, err := requiredJSONString(item, "reason")
		if err != nil || itemReason == "" {
			return "", false
		}
		if reason == "" {
			reason = itemReason
		} else if reason != itemReason {
			return "", false
		}
	}
	return reason, true
}

func decodeStrictRawObject(body []byte) (map[string]json.RawMessage, error) {
	if err := validateDuplicateFreeJSON(body); err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if err := decodeStrict(body, &object); err != nil || object == nil {
		return nil, ErrCurrentDiscoveryInvalidProviderResponse
	}
	return object, nil
}

func decodeExactObject(body []byte, allowedNames ...string) (map[string]json.RawMessage, error) {
	if err := validateDuplicateFreeJSON(body); err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if err := decodeStrict(body, &object); err != nil || object == nil {
		return nil, ErrCurrentDiscoveryInvalidProviderResponse
	}
	allowed := make(map[string]struct{}, len(allowedNames))
	for _, name := range allowedNames {
		allowed[name] = struct{}{}
	}
	for name := range object {
		if _, ok := allowed[name]; !ok {
			return nil, ErrCurrentDiscoveryInvalidProviderResponse
		}
	}
	return object, nil
}

func decodeJSONArray(raw json.RawMessage) ([]json.RawMessage, error) {
	if isJSONNull(raw) {
		return nil, ErrCurrentDiscoveryInvalidProviderResponse
	}
	var values []json.RawMessage
	if err := decodeStrict(raw, &values); err != nil || values == nil {
		return nil, ErrCurrentDiscoveryInvalidProviderResponse
	}
	return values, nil
}

func requiredJSONString(object map[string]json.RawMessage, name string) (string, error) {
	raw, present := object[name]
	if !present {
		return "", ErrCurrentDiscoveryInvalidProviderResponse
	}
	return decodeJSONString(raw)
}

func optionalJSONString(object map[string]json.RawMessage, name string) (string, bool, error) {
	raw, present := object[name]
	if !present || isJSONNull(raw) {
		return "", false, nil
	}
	value, err := decodeJSONString(raw)
	return value, true, err
}

func decodeJSONString(raw json.RawMessage) (string, error) {
	if isJSONNull(raw) {
		return "", ErrCurrentDiscoveryInvalidProviderResponse
	}
	var value string
	if err := decodeStrict(raw, &value); err != nil {
		return "", ErrCurrentDiscoveryInvalidProviderResponse
	}
	return value, nil
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func decodeStrict(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return ErrCurrentDiscoveryInvalidProviderResponse
	}
	return nil
}

func validateDuplicateFreeJSON(body []byte) error {
	if !validJSONUnicode(body) {
		return ErrCurrentDiscoveryInvalidProviderResponse
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder, 0); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return ErrCurrentDiscoveryInvalidProviderResponse
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, depth int) error {
	if depth > (4*MaximumMessagePartDepth)+16 {
		return ErrCurrentDiscoveryInvalidProviderResponse
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return ErrCurrentDiscoveryInvalidProviderResponse
			}
			if _, exists := seen[key]; exists {
				return ErrCurrentDiscoveryInvalidProviderResponse
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return ErrCurrentDiscoveryInvalidProviderResponse
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return ErrCurrentDiscoveryInvalidProviderResponse
		}
	default:
		return ErrCurrentDiscoveryInvalidProviderResponse
	}
	return nil
}

func canonicalPositiveDecimal(raw json.RawMessage) bool {
	if len(raw) == 0 || raw[0] < '1' || raw[0] > '9' {
		return false
	}
	for _, character := range raw[1:] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validJSONUnicode(body []byte) bool {
	if !utf8.Valid(body) {
		return false
	}
	inString := false
	for index := 0; index < len(body); index++ {
		switch body[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || index+1 >= len(body) {
				continue
			}
			index++
			if body[index] != 'u' {
				continue
			}
			value, ok := decodeJSONHexQuad(body, index+1)
			if !ok {
				return false
			}
			index += 4
			if value >= 0xdc00 && value <= 0xdfff {
				return false
			}
			if value < 0xd800 || value > 0xdbff {
				continue
			}
			if index+6 >= len(body) || body[index+1] != '\\' || body[index+2] != 'u' {
				return false
			}
			low, ok := decodeJSONHexQuad(body, index+3)
			if !ok || low < 0xdc00 || low > 0xdfff {
				return false
			}
			index += 6
		}
	}
	return true
}

func decodeJSONHexQuad(body []byte, start int) (uint16, bool) {
	if start < 0 || start+4 > len(body) {
		return 0, false
	}
	var value uint16
	for _, character := range body[start : start+4] {
		value <<= 4
		switch {
		case character >= '0' && character <= '9':
			value += uint16(character - '0')
		case character >= 'a' && character <= 'f':
			value += uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			value += uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}
