package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

type Problem struct {
	Path   string
	Line   int
	Column int
	Reason string
}

func (p Problem) Error() string {
	if p.Line > 0 {
		return fmt.Sprintf("%s (line %d, column %d): %s", p.Path, p.Line, p.Column, p.Reason)
	}
	return p.Path + ": " + p.Reason
}

type ValidationError struct {
	Problems []Problem
}

func (e *ValidationError) Error() string {
	parts := make([]string, len(e.Problems))
	for i, problem := range e.Problems {
		parts[i] = problem.Error()
	}
	return strings.Join(parts, "\n")
}

type schemaNode struct {
	fields map[string]*schemaNode
	item   *schemaNode
}

var scalar = &schemaNode{}

var schema = mapping(map[string]*schemaNode{
	"version": scalar,
	"capabilities": mapping(map[string]*schemaNode{
		"gmail.read": scalar, "gmail.current_sync": scalar, "gmail.backfill": scalar,
		"mail.review_read": scalar, "mail.review_write": scalar,
	}),
	"server": mapping(map[string]*schemaNode{
		"listen": scalar, "read_header_timeout": scalar, "read_timeout": scalar, "write_timeout": scalar,
		"idle_timeout": scalar, "max_request_bytes": scalar,
	}),
	"database": mapping(map[string]*schemaNode{
		"engine": scalar, "url_env": scalar, "auth_token_env": scalar, "max_open_connections": scalar,
		"max_idle_connections": scalar, "connection_max_lifetime": scalar,
	}),
	"gmail": mapping(map[string]*schemaNode{
		"oauth_client_id_env": scalar, "oauth_client_secret_env": scalar, "oauth_redirect_url_env": scalar,
		"scope": scalar, "poll_interval": scalar, "poll_jitter": scalar, "page_size": scalar,
		"max_accounts_in_flight": scalar, "body_excerpt_bytes": scalar, "thread_max_messages": scalar,
	}),
	"backfill": mapping(map[string]*schemaNode{
		"enabled": scalar, "default_lookback_days": scalar, "maximum_lookback_days": scalar, "page_size": scalar,
		"current_mail_has_priority": scalar,
		"run_window":                mapping(map[string]*schemaNode{"timezone": scalar, "start": scalar, "end": scalar}),
	}),
	"gate": mapping(map[string]*schemaNode{
		"version": scalar, "excluded_labels": sequence(scalar), "suppress_gmail_categories": sequence(scalar),
		"direct_recipient_is_candidate": scalar, "mailing_list_is_bulk_signal": scalar,
		"sender_allow_domains": sequence(scalar), "sender_block_domains": sequence(scalar),
		"subject_candidate_terms": sequence(scalar), "subject_urgent_terms": sequence(scalar),
	}),
	"review": mapping(map[string]*schemaNode{
		"default_page_size": scalar, "maximum_page_size": scalar, "automatic_task_creation": scalar,
	}),
	"retention": mapping(map[string]*schemaNode{"metadata_days": scalar, "excerpt_days": scalar, "audit_days": scalar}),
	"mcp": mapping(map[string]*schemaNode{
		"enabled": scalar, "path": scalar, "bearer_token_env": scalar, "enable_review_writes": scalar, "enable_operator_tools": scalar,
	}),
	"encryption": mapping(map[string]*schemaNode{"master_key_env": scalar}),
	"logging":    mapping(map[string]*schemaNode{"level": scalar, "format": scalar}),
})

func mapping(fields map[string]*schemaNode) *schemaNode { return &schemaNode{fields: fields} }
func sequence(item *schemaNode) *schemaNode             { return &schemaNode{item: item} }

func Parse(data []byte) (Config, error) {
	config, _, err := parseValidated(data)
	return config, err
}

func parseValidated(data []byte) (Config, *yaml.Node, error) {
	if len(data) > MaxFileBytes {
		return Config{}, nil, validationError(Problem{Path: "$", Reason: fmt.Sprintf("configuration exceeds the %d-byte limit", MaxFileBytes)})
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return Config{}, nil, validationError(Problem{Path: "$", Reason: "configuration document is empty"})
	}
	if !utf8.Valid(data) {
		return Config{}, nil, validationError(Problem{Path: "$", Reason: "configuration must be valid UTF-8"})
	}
	if problem := invalidCharacter(data); problem != nil {
		return Config{}, nil, validationError(*problem)
	}
	if line, found := directiveLine(data); found {
		return Config{}, nil, validationError(Problem{Path: "$", Line: line, Column: 1, Reason: "YAML directives are not supported"})
	}
	if line, found := documentEndLine(data); found {
		return Config{}, nil, validationError(Problem{Path: "$", Line: line, Column: 1, Reason: "YAML document-end markers are not supported"})
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return Config{}, nil, validationError(safeYAMLError(err))
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return Config{}, nil, validationError(safeYAMLError(err))
		}
		line, column := 0, 0
		if len(extra.Content) > 0 {
			line, column = extra.Content[0].Line, extra.Content[0].Column
		}
		return Config{}, nil, validationError(Problem{Path: "$", Line: line, Column: column, Reason: "multiple YAML documents are not supported"})
	}
	if len(document.Content) != 1 || document.Content[0].Kind == yaml.ScalarNode && document.Content[0].Tag == "!!null" {
		return Config{}, nil, validationError(Problem{Path: "$", Reason: "configuration document must not be null"})
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return Config{}, nil, validationError(Problem{Path: "$", Line: root.Line, Column: root.Column, Reason: "document root must be a mapping"})
	}

	var problems []Problem
	nodes := 0
	walkStructure(root, schema, "$", 1, &nodes, &problems)
	if len(problems) != 0 {
		return Config{}, nil, validationError(problems...)
	}

	config := Defaults()
	decodeConfig(root, &config, &problems)
	validateConfig(config, &problems)
	if len(problems) != 0 {
		return Config{}, nil, validationError(problems...)
	}
	return config, root, nil
}

func validationError(problems ...Problem) error {
	sort.SliceStable(problems, func(i, j int) bool {
		if problems[i].Path != problems[j].Path {
			return problems[i].Path < problems[j].Path
		}
		if problems[i].Line != problems[j].Line {
			return problems[i].Line < problems[j].Line
		}
		if problems[i].Column != problems[j].Column {
			return problems[i].Column < problems[j].Column
		}
		return problems[i].Reason < problems[j].Reason
	})
	return &ValidationError{Problems: problems}
}

func invalidCharacter(data []byte) *Problem {
	line, column := 1, 1
	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		if r == 0 || r < 0x20 && r != '\t' && r != '\n' && r != '\r' || r >= 0x7f && r <= 0x84 || r >= 0x86 && r <= 0x9f {
			return &Problem{Path: "$", Line: line, Column: column, Reason: "configuration contains a disallowed control character"}
		}
		data = data[size:]
		if r == '\n' {
			line, column = line+1, 1
		} else {
			column++
		}
	}
	return nil
}

func directiveLine(data []byte) (int, bool) {
	for index, line := range bytes.Split(data, []byte("\n")) {
		for bytes.HasPrefix(line, []byte{0xef, 0xbb, 0xbf}) {
			line = line[3:]
		}
		if len(line) > 0 && line[0] == '%' {
			return index + 1, true
		}
	}
	return 0, false
}

func documentEndLine(data []byte) (int, bool) {
	for index, line := range bytes.Split(data, []byte("\n")) {
		if !bytes.HasPrefix(line, []byte("...")) {
			continue
		}
		rest := line[3:]
		if len(rest) == 0 {
			return index + 1, true
		}
		if rest[0] == ' ' || rest[0] == '\t' || rest[0] == '\r' {
			trimmed := strings.TrimSpace(string(rest))
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				return index + 1, true
			}
		}
	}
	return 0, false
}

func containsUnicodeControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

var yamlLocation = regexp.MustCompile(`line ([0-9]+):`)

func safeYAMLError(err error) Problem {
	problem := Problem{Path: "$", Reason: "malformed YAML"}
	match := yamlLocation.FindStringSubmatch(err.Error())
	if len(match) == 2 {
		problem.Line, _ = strconv.Atoi(match[1])
		problem.Column = 1
	}
	return problem
}

func walkStructure(node *yaml.Node, expected *schemaNode, fieldPath string, depth int, nodes *int, problems *[]Problem) {
	*nodes++
	if *nodes > MaxNodes {
		if *nodes == MaxNodes+1 {
			addProblem(problems, node, fieldPath, "configuration exceeds the 4096-node limit")
		}
		return
	}
	if node.Anchor != "" || node.Alias != nil {
		addProblem(problems, node, fieldPath, "YAML anchors and aliases are not supported")
	}
	if node.Kind == yaml.AliasNode {
		addProblem(problems, node, fieldPath, "YAML aliases are not supported")
		return
	}
	if !isCoreTag(node.Tag) {
		addProblem(problems, node, fieldPath, "custom YAML tags are not supported")
	}
	if node.Kind == yaml.ScalarNode && node.Tag == "!!null" {
		addProblem(problems, node, fieldPath, "null values are not supported")
		return
	}
	if node.Kind == yaml.ScalarNode && containsUnicodeControl(node.Value) {
		addProblem(problems, node, fieldPath, "scalar contains a disallowed control character")
	}
	if node.Kind == yaml.MappingNode || node.Kind == yaml.SequenceNode {
		if depth > MaxDepth {
			addProblem(problems, node, fieldPath, "configuration exceeds the nesting depth limit of 8")
			return
		}
	}

	switch {
	case expected.fields != nil:
		if node.Kind != yaml.MappingNode {
			addProblem(problems, node, fieldPath, "must be a mapping")
			return
		}
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index+1 < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			*nodes++
			if key.Kind == yaml.ScalarNode && containsUnicodeControl(key.Value) {
				addProblem(problems, key, fieldPath, "mapping key contains a disallowed control character")
			}
			if key.Tag == "!!merge" || key.Value == "<<" {
				addProblem(problems, key, fieldPath, "YAML merge keys are not supported")
				walkUnknown(value, fieldPath, depth+1, nodes, problems)
				continue
			}
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				addProblem(problems, key, fieldPath, "mapping keys must be strings")
				continue
			}
			if key.Anchor != "" || key.Alias != nil || !isCoreTag(key.Tag) {
				addProblem(problems, key, fieldPath, "mapping keys cannot use YAML features")
			}
			if _, duplicate := seen[key.Value]; duplicate {
				addProblem(problems, key, fieldPath, "duplicate key")
			}
			seen[key.Value] = struct{}{}
			child, known := expected.fields[key.Value]
			if !known {
				addProblem(problems, key, fieldPath, "unknown key")
				walkUnknown(value, fieldPath, depth+1, nodes, problems)
				continue
			}
			childPath := key.Value
			if fieldPath != "$" {
				childPath = fieldPath + "." + key.Value
			}
			walkStructure(value, child, childPath, depth+1, nodes, problems)
		}
	case expected.item != nil:
		if node.Kind != yaml.SequenceNode {
			addProblem(problems, node, fieldPath, "must be a sequence")
			return
		}
		for index, item := range node.Content {
			walkStructure(item, expected.item, fmt.Sprintf("%s[%d]", fieldPath, index), depth+1, nodes, problems)
		}
	default:
		if node.Kind != yaml.ScalarNode {
			addProblem(problems, node, fieldPath, "must be a scalar")
			walkComplexChildren(node, fieldPath, depth, nodes, problems)
		}
	}
}

func walkComplexChildren(node *yaml.Node, fieldPath string, depth int, nodes *int, problems *[]Problem) {
	switch node.Kind {
	case yaml.MappingNode:
		for index := 0; index+1 < len(node.Content); index += 2 {
			*nodes++
			walkStructure(node.Content[index+1], scalar, fieldPath, depth+1, nodes, problems)
		}
	case yaml.SequenceNode:
		for _, item := range node.Content {
			walkStructure(item, scalar, fieldPath, depth+1, nodes, problems)
		}
	}
}

func walkUnknown(node *yaml.Node, fieldPath string, depth int, nodes *int, problems *[]Problem) {
	walkStructure(node, scalar, fieldPath, depth, nodes, problems)
}

func isCoreTag(tag string) bool {
	switch tag {
	case "", "!!map", "!!seq", "!!str", "!!bool", "!!int", "!!float", "!!null", "!!timestamp", "!!merge", "!!binary":
		return true
	default:
		return false
	}
}

func addProblem(problems *[]Problem, node *yaml.Node, fieldPath, reason string) {
	*problems = append(*problems, Problem{Path: fieldPath, Line: node.Line, Column: node.Column, Reason: reason})
}

func mappingValues(node *yaml.Node) map[string]*yaml.Node {
	result := make(map[string]*yaml.Node, len(node.Content)/2)
	for index := 0; index+1 < len(node.Content); index += 2 {
		result[node.Content[index].Value] = node.Content[index+1]
	}
	return result
}

func decodeConfig(root *yaml.Node, config *Config, problems *[]Problem) {
	values := mappingValues(root)
	if node, found := values["version"]; found {
		config.Version = readUint(node, "version", problems)
	} else {
		*problems = append(*problems, Problem{Path: "version", Reason: "is required"})
	}
	if node := values["capabilities"]; node != nil {
		decodeCapabilities(node, &config.Capabilities, problems)
	}
	if node := values["server"]; node != nil {
		decodeServer(node, &config.Server, problems)
	}
	if node := values["database"]; node != nil {
		decodeDatabase(node, &config.Database, problems)
	}
	if node := values["gmail"]; node != nil {
		decodeGmail(node, &config.Gmail, problems)
	}
	if node := values["backfill"]; node != nil {
		decodeBackfill(node, &config.Backfill, problems)
	}
	if node := values["gate"]; node != nil {
		decodeGate(node, &config.Gate, problems)
	}
	if node := values["review"]; node != nil {
		decodeReview(node, &config.Review, problems)
	}
	if node := values["retention"]; node != nil {
		decodeRetention(node, &config.Retention, problems)
	}
	if node := values["mcp"]; node != nil {
		decodeMCP(node, &config.MCP, problems)
	}
	if node := values["encryption"]; node != nil {
		decodeEncryption(node, &config.Encryption, problems)
	}
	if node := values["logging"]; node != nil {
		decodeLogging(node, &config.Logging, problems)
	}
}

func readUint(node *yaml.Node, fieldPath string, problems *[]Problem) uint64 {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!int" || node.Style != 0 || !regexp.MustCompile(`^(0|[1-9][0-9]*)$`).MatchString(node.Value) {
		addProblem(problems, node, fieldPath, "must be an unquoted canonical unsigned decimal integer")
		return 0
	}
	value, err := strconv.ParseUint(node.Value, 10, 64)
	if err != nil {
		addProblem(problems, node, fieldPath, "integer is outside the supported range")
		return 0
	}
	return value
}

func readBool(node *yaml.Node, fieldPath string, problems *[]Problem) bool {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!bool" || node.Style != 0 || node.Value != "true" && node.Value != "false" {
		addProblem(problems, node, fieldPath, "must be an unquoted lowercase boolean")
		return false
	}
	return node.Value == "true"
}

func readString(node *yaml.Node, fieldPath string, problems *[]Problem) string {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		addProblem(problems, node, fieldPath, "must be a string")
		return ""
	}
	return node.Value
}

func readDuration(node *yaml.Node, fieldPath string, problems *[]Problem) time.Duration {
	value := readString(node, fieldPath, problems)
	duration, err := time.ParseDuration(value)
	if err != nil {
		addProblem(problems, node, fieldPath, "must be a valid Go duration")
		return 0
	}
	return duration
}

func readStrings(node *yaml.Node, fieldPath string, problems *[]Problem) []string {
	values := make([]string, 0, len(node.Content))
	for index, item := range node.Content {
		values = append(values, readString(item, fmt.Sprintf("%s[%d]", fieldPath, index), problems))
	}
	return values
}
