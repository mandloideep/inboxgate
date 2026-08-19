package gmail

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"mime"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	maildomain "github.com/mandloideep/inboxgate/internal/mail"
)

const (
	MaximumCandidateContentBodyBytes = 1_048_576
	maximumHTMLTokenBytes            = 65_536
	maximumHTMLTokens                = 10_000
)

var errCandidateContentDecode = errors.New("gmail candidate content: unavailable")

type selectedCandidatePart struct {
	kind    maildomain.CandidateSourceKind
	charset string
	data    string
	size    int
}

type candidatePartSelection struct {
	plain *selectedCandidatePart
	html  *selectedCandidatePart
	nodes int
}

func decodeCandidateContentResponse(body []byte, messageID, threadID string, excerptLimit int) (maildomain.CandidateSourceKind, string, bool, error) {
	if excerptLimit < maildomain.MinimumExcerptBytes || excerptLimit > maildomain.MaximumExcerptBytes || len(body) == 0 || len(body) > MaximumCandidateContentBodyBytes {
		return "", "", false, errCandidateContentDecode
	}
	document, err := decodeExactObject(body, "id", "threadId", "payload")
	if err != nil {
		return "", "", false, errCandidateContentDecode
	}
	providerMessageID, messageErr := requiredJSONString(document, "id")
	providerThreadID, threadErr := requiredJSONString(document, "threadId")
	payload, present := document["payload"]
	if messageErr != nil || threadErr != nil || providerMessageID != messageID || providerThreadID != threadID || !present || isJSONNull(payload) {
		return "", "", false, errCandidateContentDecode
	}
	selection := candidatePartSelection{}
	if err := walkCandidatePart(payload, 1, &selection); err != nil {
		return "", "", false, errCandidateContentDecode
	}
	selected := selection.plain
	if selected == nil {
		selected = selection.html
	}
	if selected == nil {
		return "", "", false, errCandidateContentDecode
	}
	raw, err := decodeCandidatePartData(*selected)
	if err != nil {
		return "", "", false, errCandidateContentDecode
	}
	defer clear(raw)
	decoded, err := decodeCandidateCharset(raw, selected.charset)
	if err != nil || len(decoded) > maildomain.MaximumDecodedContentBytes {
		return "", "", false, errCandidateContentDecode
	}
	if selected.kind == maildomain.CandidateSourceTextHTML {
		decoded, err = candidateHTMLToText(decoded)
		if err != nil {
			return "", "", false, errCandidateContentDecode
		}
	}
	excerpt, truncated := canonicalizeCandidateText(decoded, excerptLimit)
	if excerpt == "" {
		return "", "", false, errCandidateContentDecode
	}
	return selected.kind, excerpt, truncated, nil
}

func walkCandidatePart(raw json.RawMessage, depth int, selection *candidatePartSelection) error {
	if depth > MaximumMessagePartDepth {
		return errCandidateContentDecode
	}
	selection.nodes++
	if selection.nodes > MaximumMessageParts {
		return errCandidateContentDecode
	}
	part, err := decodeExactObject(raw, "mimeType", "headers", "filename", "body", "parts")
	if err != nil {
		return errCandidateContentDecode
	}
	mimeType, err := requiredJSONString(part, "mimeType")
	if err != nil || len(mimeType) == 0 || len(mimeType) > 255 || strings.IndexFunc(mimeType, unicode.IsControl) >= 0 {
		return errCandidateContentDecode
	}
	charset, err := candidatePartCharset(part["headers"], mimeType)
	if err != nil {
		return errCandidateContentDecode
	}
	filename, present, err := optionalJSONString(part, "filename")
	if err != nil || present && !validMIMEFilename(filename) {
		return errCandidateContentDecode
	}
	size, data, attachmentID, err := candidatePartBody(part["body"])
	if err != nil {
		return errCandidateContentDecode
	}
	eligible := filename == "" && attachmentID == "" && data != "" && (strings.EqualFold(mimeType, "text/plain") || strings.EqualFold(mimeType, "text/html"))
	if eligible {
		kind := maildomain.CandidateSourceTextPlain
		if strings.EqualFold(mimeType, "text/html") {
			kind = maildomain.CandidateSourceTextHTML
		}
		candidate := &selectedCandidatePart{kind: kind, charset: charset, data: data, size: size}
		if kind == maildomain.CandidateSourceTextPlain && selection.plain == nil {
			selection.plain = candidate
		}
		if kind == maildomain.CandidateSourceTextHTML && selection.html == nil {
			selection.html = candidate
		}
	}
	partsRaw, hasParts := part["parts"]
	if !hasParts {
		return nil
	}
	if isJSONNull(partsRaw) {
		return errCandidateContentDecode
	}
	children, err := decodeJSONArray(partsRaw)
	if err != nil {
		return errCandidateContentDecode
	}
	if depth == MaximumMessagePartDepth && len(children) != 0 {
		return errCandidateContentDecode
	}
	for _, child := range children {
		if err := walkCandidatePart(child, depth+1, selection); err != nil {
			return err
		}
	}
	return nil
}

func candidatePartCharset(raw json.RawMessage, fieldMIMEType string) (string, error) {
	charset := "us-ascii"
	if len(raw) == 0 || isJSONNull(raw) {
		return charset, nil
	}
	headers, err := decodeJSONArray(raw)
	if err != nil || len(headers) > MaximumMessageHeaderEntries {
		return "", errCandidateContentDecode
	}
	found := false
	selectedBytes := 0
	for _, rawHeader := range headers {
		header, err := decodeExactObject(rawHeader, "name", "value")
		if err != nil {
			return "", errCandidateContentDecode
		}
		name, nameErr := requiredJSONString(header, "name")
		value, valueErr := requiredJSONString(header, "value")
		if nameErr != nil || valueErr != nil || len(name) > 256 || len(value) > maximumMIMEFilenameBytes || strings.IndexFunc(name+value, unicode.IsControl) >= 0 {
			return "", errCandidateContentDecode
		}
		if !strings.EqualFold(name, "Content-Type") {
			continue
		}
		selectedBytes += len(name) + len(value)
		if found || selectedBytes > MaximumSelectedHeaderBytes {
			return "", errCandidateContentDecode
		}
		found = true
		mediaType, parameters, err := mime.ParseMediaType(value)
		if err != nil || !strings.EqualFold(mediaType, fieldMIMEType) {
			return "", errCandidateContentDecode
		}
		for key := range parameters {
			if !strings.EqualFold(key, "charset") && !strings.EqualFold(key, "boundary") {
				return "", errCandidateContentDecode
			}
		}
		if value, ok := parameters["charset"]; ok {
			charset = strings.ToLower(strings.TrimSpace(value))
		}
	}
	if !validCandidateCharset(charset) {
		return "", errCandidateContentDecode
	}
	return charset, nil
}

func candidatePartBody(raw json.RawMessage) (int, string, string, error) {
	if len(raw) == 0 || isJSONNull(raw) {
		return 0, "", "", nil
	}
	body, err := decodeExactObject(raw, "size", "data", "attachmentId")
	if err != nil {
		return 0, "", "", errCandidateContentDecode
	}
	rawSize, present := body["size"]
	if !present {
		return 0, "", "", errCandidateContentDecode
	}
	textSize := string(bytes.TrimSpace(rawSize))
	size64, err := strconv.ParseInt(textSize, 10, 64)
	if err != nil || size64 < 0 || size64 > maildomain.MaximumDecodedContentBytes || strconv.FormatInt(size64, 10) != textSize {
		return 0, "", "", errCandidateContentDecode
	}
	data, _, dataErr := optionalJSONString(body, "data")
	attachmentID, _, attachmentErr := optionalJSONString(body, "attachmentId")
	if dataErr != nil || attachmentErr != nil || len(attachmentID) > maximumAttachmentIDBytes || strings.IndexFunc(attachmentID, unicode.IsControl) >= 0 || len(data) > base64.RawURLEncoding.EncodedLen(maildomain.MaximumDecodedContentBytes) {
		return 0, "", "", errCandidateContentDecode
	}
	return int(size64), data, attachmentID, nil
}

func decodeCandidatePartData(part selectedCandidatePart) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(part.data)
	if err != nil || len(decoded) != part.size || len(decoded) > maildomain.MaximumDecodedContentBytes || base64.RawURLEncoding.EncodeToString(decoded) != part.data {
		clear(decoded)
		return nil, errCandidateContentDecode
	}
	return decoded, nil
}

func validCandidateCharset(value string) bool {
	switch value {
	case "utf-8", "utf8", "us-ascii", "ascii", "iso-8859-1", "windows-1252", "cp1252":
		return true
	default:
		return false
	}
}

func decodeCandidateCharset(raw []byte, charset string) (string, error) {
	switch charset {
	case "utf-8", "utf8":
		if !utf8.Valid(raw) {
			return "", errCandidateContentDecode
		}
		return string(raw), nil
	case "us-ascii", "ascii":
		for _, value := range raw {
			if value > 0x7f {
				return "", errCandidateContentDecode
			}
		}
		return string(raw), nil
	case "iso-8859-1":
		runes := make([]rune, len(raw))
		for index, value := range raw {
			runes[index] = rune(value)
		}
		return string(runes), nil
	case "windows-1252", "cp1252":
		runes := make([]rune, 0, len(raw))
		for _, value := range raw {
			decoded, ok := decodeWindows1252(value)
			if !ok {
				return "", errCandidateContentDecode
			}
			runes = append(runes, decoded)
		}
		return string(runes), nil
	default:
		return "", errCandidateContentDecode
	}
}

func decodeWindows1252(value byte) (rune, bool) {
	if value < 0x80 || value >= 0xa0 {
		return rune(value), true
	}
	table := map[byte]rune{
		0x80: '€', 0x82: '‚', 0x83: 'ƒ', 0x84: '„', 0x85: '…', 0x86: '†', 0x87: '‡',
		0x88: 'ˆ', 0x89: '‰', 0x8a: 'Š', 0x8b: '‹', 0x8c: 'Œ', 0x8e: 'Ž', 0x91: '‘',
		0x92: '’', 0x93: '“', 0x94: '”', 0x95: '•', 0x96: '–', 0x97: '\u2014', 0x98: '˜',
		0x99: '™', 0x9a: 'š', 0x9b: '›', 0x9c: 'œ', 0x9e: 'ž', 0x9f: 'Ÿ',
	}
	decoded, ok := table[value]
	return decoded, ok
}

type candidateHTMLFrame struct {
	name    string
	discard bool
}

func candidateHTMLToText(input string) (string, error) {
	if !utf8.ValidString(input) || len(input) > maildomain.MaximumDecodedContentBytes {
		return "", errCandidateContentDecode
	}
	var output strings.Builder
	lastBreak := false
	writeBreak := func() {
		if output.Len() != 0 && !lastBreak {
			output.WriteByte('\n')
			lastBreak = true
		}
	}
	stack := make([]candidateHTMLFrame, 0, MaximumMessagePartDepth)
	tokens := 0
	for index := 0; index < len(input); {
		if input[index] != '<' {
			next := strings.IndexByte(input[index:], '<')
			if next < 0 {
				next = len(input) - index
			}
			text, err := decodeCandidateEntities(input[index : index+next])
			if err != nil {
				return "", err
			}
			if !candidateHTMLDiscarded(stack) {
				output.WriteString(text)
				if text != "" {
					lastBreak = strings.HasSuffix(text, "\n")
				}
			}
			index += next
			continue
		}
		tokens++
		if tokens > maximumHTMLTokens {
			return "", errCandidateContentDecode
		}
		if strings.HasPrefix(input[index:], "<!--") {
			end := strings.Index(input[index+4:], "-->")
			if end < 0 || end > maximumHTMLTokenBytes || strings.Contains(input[index+4:index+4+end], "--") {
				return "", errCandidateContentDecode
			}
			index += 4 + end + 3
			continue
		}
		end, err := candidateTagEnd(input, index+1)
		if err != nil || end-index > maximumHTMLTokenBytes {
			return "", errCandidateContentDecode
		}
		token := input[index+1 : end]
		closing, selfClosing, name, attributes, err := parseCandidateTag(token)
		if err != nil {
			return "", errCandidateContentDecode
		}
		if closing {
			if len(stack) == 0 || stack[len(stack)-1].name != name {
				return "", errCandidateContentDecode
			}
			frame := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if !frame.discard && candidateBlockTag(name) {
				writeBreak()
			}
		} else {
			inherited := candidateHTMLDiscarded(stack)
			discard := inherited || candidateDiscardTag(name) || candidateHidden(attributes)
			if !discard && candidateBlockTag(name) {
				writeBreak()
			}
			if !candidateVoidTag(name) && !selfClosing {
				if len(stack) == MaximumMessagePartDepth {
					return "", errCandidateContentDecode
				}
				stack = append(stack, candidateHTMLFrame{name: name, discard: discard})
			}
		}
		index = end + 1
	}
	if len(stack) != 0 {
		return "", errCandidateContentDecode
	}
	return output.String(), nil
}

func candidateTagEnd(input string, start int) (int, error) {
	quote := byte(0)
	for index := start; index < len(input); index++ {
		value := input[index]
		if quote != 0 {
			if value == quote {
				quote = 0
			}
			continue
		}
		if value == '\'' || value == '"' {
			quote = value
			continue
		}
		if value == '<' {
			return 0, errCandidateContentDecode
		}
		if value == '>' {
			return index, nil
		}
	}
	return 0, errCandidateContentDecode
}

func parseCandidateTag(token string) (bool, bool, string, map[string]string, error) {
	token = strings.TrimSpace(token)
	if token == "" || token[0] == '!' || token[0] == '?' {
		return false, false, "", nil, errCandidateContentDecode
	}
	closing := token[0] == '/'
	if closing {
		token = strings.TrimSpace(token[1:])
	}
	selfClosing := strings.HasSuffix(token, "/")
	if selfClosing {
		token = strings.TrimSpace(strings.TrimSuffix(token, "/"))
	}
	nameEnd := 0
	for nameEnd < len(token) && candidateNameByte(token[nameEnd]) {
		nameEnd++
	}
	if nameEnd == 0 {
		return false, false, "", nil, errCandidateContentDecode
	}
	name := strings.ToLower(token[:nameEnd])
	remainder := token[nameEnd:]
	if closing {
		if strings.TrimSpace(remainder) != "" || selfClosing {
			return false, false, "", nil, errCandidateContentDecode
		}
		return true, false, name, map[string]string{}, nil
	}
	attributes, err := parseCandidateAttributes(remainder)
	return false, selfClosing, name, attributes, err
}

func parseCandidateAttributes(input string) (map[string]string, error) {
	attributes := make(map[string]string)
	for index := 0; index < len(input); {
		for index < len(input) && candidateSpace(input[index]) {
			index++
		}
		if index == len(input) {
			return attributes, nil
		}
		start := index
		for index < len(input) && candidateAttributeByte(input[index]) {
			index++
		}
		if start == index {
			return nil, errCandidateContentDecode
		}
		name := strings.ToLower(input[start:index])
		if _, exists := attributes[name]; exists {
			return nil, errCandidateContentDecode
		}
		for index < len(input) && candidateSpace(input[index]) {
			index++
		}
		value := ""
		if index < len(input) && input[index] == '=' {
			index++
			for index < len(input) && candidateSpace(input[index]) {
				index++
			}
			if index == len(input) {
				return nil, errCandidateContentDecode
			}
			if input[index] == '\'' || input[index] == '"' {
				quote := input[index]
				index++
				start = index
				for index < len(input) && input[index] != quote {
					index++
				}
				if index == len(input) {
					return nil, errCandidateContentDecode
				}
				value = input[start:index]
				index++
			} else {
				start = index
				for index < len(input) && !candidateSpace(input[index]) {
					if strings.ContainsRune("<>\"'=`", rune(input[index])) {
						return nil, errCandidateContentDecode
					}
					index++
				}
				value = input[start:index]
			}
		}
		attributes[name] = value
	}
	return attributes, nil
}

func decodeCandidateEntities(input string) (string, error) {
	var output strings.Builder
	for index := 0; index < len(input); {
		if input[index] != '&' {
			next := strings.IndexByte(input[index:], '&')
			if next < 0 {
				next = len(input) - index
			}
			output.WriteString(input[index : index+next])
			index += next
			continue
		}
		end := strings.IndexByte(input[index:], ';')
		if end < 2 || end > 16 {
			return "", errCandidateContentDecode
		}
		entity := input[index+1 : index+end]
		var decoded rune
		switch entity {
		case "amp":
			decoded = '&'
		case "lt":
			decoded = '<'
		case "gt":
			decoded = '>'
		case "quot":
			decoded = '"'
		case "apos":
			decoded = '\''
		case "nbsp":
			decoded = ' '
		default:
			base := 10
			number := entity
			if strings.HasPrefix(number, "#x") || strings.HasPrefix(number, "#X") {
				base, number = 16, number[2:]
			} else if strings.HasPrefix(number, "#") {
				number = number[1:]
			} else {
				return "", errCandidateContentDecode
			}
			value, err := strconv.ParseUint(number, base, 32)
			if err != nil || value == 0 || value > utf8.MaxRune || value >= 0xd800 && value <= 0xdfff {
				return "", errCandidateContentDecode
			}
			decoded = rune(value)
		}
		output.WriteRune(decoded)
		index += end + 1
	}
	return output.String(), nil
}

func candidateHTMLDiscarded(stack []candidateHTMLFrame) bool {
	return len(stack) != 0 && stack[len(stack)-1].discard
}

func candidateHidden(attributes map[string]string) bool {
	if _, exists := attributes["hidden"]; exists {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(attributes["aria-hidden"]), "true") {
		return true
	}
	for _, declaration := range strings.Split(attributes["style"], ";") {
		key, value, found := strings.Cut(declaration, ":")
		if !found {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.ToLower(strings.Join(strings.Fields(value), ""))
		if key == "display" && value == "none" || key == "visibility" && value == "hidden" || key == "opacity" && value == "0" {
			return true
		}
	}
	return false
}

func candidateDiscardTag(name string) bool {
	switch name {
	case "script", "style", "template", "noscript", "svg", "math", "head", "form", "object", "embed", "iframe", "canvas":
		return true
	default:
		return false
	}
}

func candidateBlockTag(name string) bool {
	switch name {
	case "address", "article", "aside", "blockquote", "br", "dd", "div", "dl", "dt", "fieldset", "figcaption", "figure", "footer", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "nav", "ol", "p", "pre", "section", "table", "tbody", "td", "tfoot", "th", "thead", "tr", "ul":
		return true
	default:
		return false
	}
}

func candidateVoidTag(name string) bool {
	switch name {
	case "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr":
		return true
	default:
		return false
	}
}

func candidateNameByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '-' || value == ':'
}

func candidateAttributeByte(value byte) bool {
	return candidateNameByte(value) || value == '_'
}

func candidateSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n' || value == '\f'
}

func canonicalizeCandidateText(input string, limit int) (string, bool) {
	input = strings.ReplaceAll(strings.ReplaceAll(input, "\r\n", "\n"), "\r", "\n")
	var cleaned strings.Builder
	for _, value := range input {
		switch {
		case unsafeInvisibleCandidateRune(value):
			continue
		case value == '\n' || value == '\t' || !unicode.IsControl(value):
			cleaned.WriteRune(value)
		default:
			cleaned.WriteRune(utf8.RuneError)
		}
	}
	lines := strings.Split(cleaned.String(), "\n")
	for index := range lines {
		lines[index] = strings.TrimRight(lines[index], " \t")
	}
	canonical := strings.TrimSpace(strings.Join(lines, "\n"))
	for strings.Contains(canonical, "\n\n\n") {
		canonical = strings.ReplaceAll(canonical, "\n\n\n", "\n\n")
	}
	if len(canonical) <= limit {
		return canonical, false
	}
	boundary := limit
	for boundary > 0 && !utf8.RuneStart(canonical[boundary]) {
		boundary--
	}
	return canonical[:boundary], true
}

func unsafeInvisibleCandidateRune(value rune) bool {
	if value == 0x00ad || value == 0x061c || value == 0x200b || value == 0x200c || value == 0x200d || value == 0x200e || value == 0x200f || value == 0x2060 || value == 0xfeff {
		return true
	}
	return value >= 0x202a && value <= 0x202e || value >= 0x2066 && value <= 0x2069 || value >= 0xfe00 && value <= 0xfe0f || value >= 0xe0100 && value <= 0xe01ef
}
