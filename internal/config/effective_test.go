package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestEffectiveMinimalExpandsDefaultsWithCompleteProvenance(t *testing.T) {
	effective, err := ParseEffective([]byte("version: 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(effective.Configuration, Defaults()) {
		t.Errorf("minimal effective configuration differs from Defaults():\n got %#v\nwant %#v", effective.Configuration, Defaults())
	}
	data, err := effective.JSON("flag")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(data, []byte("}\n")) || bytes.HasSuffix(data, []byte("}\n\n")) {
		t.Fatalf("effective JSON must have exactly one final newline: %q", data[len(data)-4:])
	}
	var envelope map[string]any
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("unmarshal effective JSON: %v", err)
	}
	if envelope["output_version"] != float64(1) || envelope["path_source"] != "flag" {
		t.Errorf("envelope metadata = %#v", envelope)
	}
	configuration := envelope["configuration"].(map[string]any)
	sources := envelope["sources"].(map[string]any)
	assertSourceParity(t, configuration, sources, "configuration")
	assertEverySource(t, sources, "version", sourceCompiledDefault)
	if sources["version"] != sourceFile {
		t.Errorf("version source = %v, want file", sources["version"])
	}
	for _, field := range []string{"sender_allow_domains", "sender_block_domains", "subject_candidate_terms", "subject_urgent_terms"} {
		if value := configuration["gate"].(map[string]any)[field]; value == nil || len(value.([]any)) != 0 {
			t.Errorf("gate.%s = %#v, want []", field, value)
		}
	}
}

func TestEffectiveExampleMarksEveryLeafAsFile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	effective, err := ParseEffective(data)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := effective.JSON("environment")
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatal(err)
	}
	assertEverySource(t, envelope["sources"], "", sourceFile)
}

func TestEffectiveProvenanceUsesPresenceNotValueComparison(t *testing.T) {
	document := []byte(`version: 1
server: {}
backfill:
  enabled: true
gate:
  excluded_labels: [SPAM, TRASH]
  sender_allow_domains: []
review:
  automatic_task_creation: false
retention:
  metadata_days: 0
logging:
  level: info
`)
	effective, err := ParseEffective(document)
	if err != nil {
		t.Fatal(err)
	}
	sources := effective.Sources
	if sources.Server.Listen != sourceCompiledDefault || sources.Server.ReadTimeout != sourceCompiledDefault {
		t.Errorf("empty server mapping sources = %#v", sources.Server)
	}
	for field, got := range map[string]string{
		"backfill.enabled":               sources.Backfill.Enabled,
		"gate.excluded_labels":           sources.Gate.ExcludedLabels,
		"gate.sender_allow_domains":      sources.Gate.SenderAllowDomains,
		"review.automatic_task_creation": sources.Review.AutomaticTaskCreation,
		"retention.metadata_days":        sources.Retention.MetadataDays,
		"logging.level":                  sources.Logging.Level,
	} {
		if got != sourceFile {
			t.Errorf("%s source = %q, want file", field, got)
		}
	}
	if sources.Logging.Format != sourceCompiledDefault {
		t.Errorf("omitted logging.format source = %q", sources.Logging.Format)
	}
}

func TestEffectivePreservesValuesAndNormalizesDurations(t *testing.T) {
	document := []byte(`version: 1
server:
  read_timeout: 0.5m
gmail:
  poll_interval: 300s
gate:
  excluded_labels: [TRASH, SPAM]
  sender_allow_domains: [second.example, first.example]
  subject_candidate_terms: ["<tag>&value", "line separator", "paragraph separator"]
`)
	effective, err := ParseEffective(document)
	if err != nil {
		t.Fatal(err)
	}
	data, err := effective.JSON("flag")
	if err != nil {
		t.Fatal(err)
	}
	output := string(data)
	for _, expected := range []string{
		`"read_timeout": "30s"`,
		`"poll_interval": "5m0s"`,
		"\"excluded_labels\": [\n        \"TRASH\",\n        \"SPAM\"",
		"\"sender_allow_domains\": [\n        \"second.example\",\n        \"first.example\"",
		`"\u003ctag\u003e\u0026value"`,
		`"line\u2028separator"`,
		`"paragraph\u2029separator"`,
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("effective output does not contain %q:\n%s", expected, output)
		}
	}
}

func TestEffectiveOutputOrderingAndDeterminism(t *testing.T) {
	first, err := ParseEffective([]byte("version: 1\nlogging: {format: json}\n"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := ParseEffective([]byte("---\n# comment\nlogging:\n  format: 'json'\nversion: 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := first.JSON("default")
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := second.JSON("default")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Errorf("equivalent documents differ:\nfirst:\n%s\nsecond:\n%s", firstJSON, secondJSON)
	}
	if !strings.Contains(string(firstJSON), `"path_source": "default"`) {
		t.Errorf("default path source is not rendered literally: %s", firstJSON)
	}
	output := string(firstJSON)
	assertOrdered(t, output, []string{`"output_version"`, `"path_source"`, `"configuration"`, `"sources"`})
	sourcesIndex := strings.Index(output, `  "sources": {`)
	if sourcesIndex < 0 {
		t.Fatal("effective output has no sources object")
	}
	configurationKeys := []string{
		`"version"`, `"server"`, `"listen"`, `"read_header_timeout"`, `"read_timeout"`, `"write_timeout"`, `"idle_timeout"`, `"max_request_bytes"`,
		`"database"`, `"engine"`, `"url_env"`, `"auth_token_env"`, `"max_open_connections"`, `"max_idle_connections"`, `"connection_max_lifetime"`,
		`"gmail"`, `"oauth_client_id_env"`, `"oauth_client_secret_env"`, `"oauth_redirect_url_env"`, `"scope"`, `"poll_interval"`, `"poll_jitter"`, `"page_size"`, `"max_accounts_in_flight"`, `"body_excerpt_bytes"`, `"thread_max_messages"`,
		`"backfill"`, `"enabled"`, `"default_lookback_days"`, `"maximum_lookback_days"`, `"page_size"`, `"current_mail_has_priority"`, `"run_window"`, `"timezone"`, `"start"`, `"end"`,
		`"gate"`, `"version"`, `"excluded_labels"`, `"suppress_gmail_categories"`, `"direct_recipient_is_candidate"`, `"mailing_list_is_bulk_signal"`, `"sender_allow_domains"`, `"sender_block_domains"`, `"subject_candidate_terms"`, `"subject_urgent_terms"`,
		`"review"`, `"default_page_size"`, `"maximum_page_size"`, `"automatic_task_creation"`,
		`"retention"`, `"metadata_days"`, `"excerpt_days"`, `"audit_days"`,
		`"mcp"`, `"enabled"`, `"path"`, `"bearer_token_env"`, `"enable_review_writes"`, `"enable_operator_tools"`,
		`"encryption"`, `"master_key_env"`,
		`"logging"`, `"level"`, `"format"`,
	}
	assertOrdered(t, output[:sourcesIndex], configurationKeys)
	assertOrdered(t, output[sourcesIndex:], configurationKeys)
}

func TestEffectiveProvenanceOneLeafAtATime(t *testing.T) {
	tests := []struct {
		path string
		yaml string
	}{
		{path: "version"},
		{path: "server.listen", yaml: "server: {listen: 'localhost:8080'}\n"},
		{path: "server.read_header_timeout", yaml: "server: {read_header_timeout: 5s}\n"},
		{path: "server.read_timeout", yaml: "server: {read_timeout: 30s}\n"},
		{path: "server.write_timeout", yaml: "server: {write_timeout: 30s}\n"},
		{path: "server.idle_timeout", yaml: "server: {idle_timeout: 60s}\n"},
		{path: "server.max_request_bytes", yaml: "server: {max_request_bytes: 1048576}\n"},
		{path: "database.engine", yaml: "database: {engine: turso}\n"},
		{path: "database.url_env", yaml: "database: {url_env: DATABASE_URL_NAME}\n"},
		{path: "database.auth_token_env", yaml: "database: {auth_token_env: DATABASE_TOKEN_NAME}\n"},
		{path: "database.max_open_connections", yaml: "database: {max_open_connections: 8}\n"},
		{path: "database.max_idle_connections", yaml: "database: {max_idle_connections: 2}\n"},
		{path: "database.connection_max_lifetime", yaml: "database: {connection_max_lifetime: 30m}\n"},
		{path: "gmail.oauth_client_id_env", yaml: "gmail: {oauth_client_id_env: CLIENT_ID_NAME}\n"},
		{path: "gmail.oauth_client_secret_env", yaml: "gmail: {oauth_client_secret_env: CLIENT_SECRET_NAME}\n"},
		{path: "gmail.oauth_redirect_url_env", yaml: "gmail: {oauth_redirect_url_env: REDIRECT_URL_NAME}\n"},
		{path: "gmail.scope", yaml: "gmail: {scope: gmail.readonly}\n"},
		{path: "gmail.poll_interval", yaml: "gmail: {poll_interval: 5m}\n"},
		{path: "gmail.poll_jitter", yaml: "gmail: {poll_jitter: 30s}\n"},
		{path: "gmail.page_size", yaml: "gmail: {page_size: 100}\n"},
		{path: "gmail.max_accounts_in_flight", yaml: "gmail: {max_accounts_in_flight: 2}\n"},
		{path: "gmail.body_excerpt_bytes", yaml: "gmail: {body_excerpt_bytes: 32768}\n"},
		{path: "gmail.thread_max_messages", yaml: "gmail: {thread_max_messages: 50}\n"},
		{path: "backfill.enabled", yaml: "backfill: {enabled: false}\n"},
		{path: "backfill.default_lookback_days", yaml: "backfill: {default_lookback_days: 365}\n"},
		{path: "backfill.maximum_lookback_days", yaml: "backfill: {maximum_lookback_days: 3650}\n"},
		{path: "backfill.page_size", yaml: "backfill: {page_size: 100}\n"},
		{path: "backfill.current_mail_has_priority", yaml: "backfill: {current_mail_has_priority: false}\n"},
		{path: "backfill.run_window.timezone", yaml: "backfill: {run_window: {timezone: UTC}}\n"},
		{path: "backfill.run_window.start", yaml: "backfill: {run_window: {start: '21:00'}}\n"},
		{path: "backfill.run_window.end", yaml: "backfill: {run_window: {end: '07:00'}}\n"},
		{path: "gate.version", yaml: "gate: {version: 1}\n"},
		{path: "gate.excluded_labels", yaml: "gate: {excluded_labels: [TRASH, SPAM]}\n"},
		{path: "gate.suppress_gmail_categories", yaml: "gate: {suppress_gmail_categories: [CATEGORY_SOCIAL]}\n"},
		{path: "gate.direct_recipient_is_candidate", yaml: "gate: {direct_recipient_is_candidate: false}\n"},
		{path: "gate.mailing_list_is_bulk_signal", yaml: "gate: {mailing_list_is_bulk_signal: false}\n"},
		{path: "gate.sender_allow_domains", yaml: "gate: {sender_allow_domains: [allow.example]}\n"},
		{path: "gate.sender_block_domains", yaml: "gate: {sender_block_domains: [block.example]}\n"},
		{path: "gate.subject_candidate_terms", yaml: "gate: {subject_candidate_terms: [candidate]}\n"},
		{path: "gate.subject_urgent_terms", yaml: "gate: {subject_urgent_terms: [urgent]}\n"},
		{path: "review.default_page_size", yaml: "review: {default_page_size: 25}\n"},
		{path: "review.maximum_page_size", yaml: "review: {maximum_page_size: 100}\n"},
		{path: "review.automatic_task_creation", yaml: "review: {automatic_task_creation: false}\n"},
		{path: "retention.metadata_days", yaml: "retention: {metadata_days: 0}\n"},
		{path: "retention.excerpt_days", yaml: "retention: {excerpt_days: 365}\n"},
		{path: "retention.audit_days", yaml: "retention: {audit_days: 730}\n"},
		{path: "mcp.enabled", yaml: "mcp: {enabled: false}\n"},
		{path: "mcp.path", yaml: "mcp: {path: /operator-mcp}\n"},
		{path: "mcp.bearer_token_env", yaml: "mcp: {bearer_token_env: MCP_TOKEN_NAME}\n"},
		{path: "mcp.enable_review_writes", yaml: "mcp: {enable_review_writes: false}\n"},
		{path: "mcp.enable_operator_tools", yaml: "mcp: {enable_operator_tools: false}\n"},
		{path: "encryption.master_key_env", yaml: "encryption: {master_key_env: MASTER_KEY_NAME}\n"},
		{path: "logging.level", yaml: "logging: {level: warn}\n"},
		{path: "logging.format", yaml: "logging: {format: text}\n"},
	}

	seen := make(map[string]bool, len(tests))
	for _, test := range tests {
		if seen[test.path] {
			t.Fatalf("duplicate one-leaf provenance case %q", test.path)
		}
		seen[test.path] = true
	}

	for _, test := range tests {
		t.Run(strings.ReplaceAll(test.path, ".", "_"), func(t *testing.T) {
			effective, err := ParseEffective([]byte("version: 1\n" + test.yaml))
			if err != nil {
				t.Fatalf("ParseEffective() error = %v", err)
			}
			encoded, err := json.Marshal(effective.Sources)
			if err != nil {
				t.Fatal(err)
			}
			var sources map[string]any
			if err := json.Unmarshal(encoded, &sources); err != nil {
				t.Fatal(err)
			}
			flattened := make(map[string]string)
			flattenSourceLeaves(t, sources, "", flattened)
			if len(flattened) != len(tests) {
				t.Fatalf("source leaf count = %d, want exhaustive case count %d", len(flattened), len(tests))
			}
			for path := range seen {
				want := sourceCompiledDefault
				if path == "version" || path == test.path {
					want = sourceFile
				}
				if got := flattened[path]; got != want {
					t.Errorf("source %s = %q, want %q while targeting %s", path, got, want, test.path)
				}
			}
		})
	}
}

func flattenSourceLeaves(t *testing.T, value map[string]any, prefix string, output map[string]string) {
	t.Helper()
	for key, child := range value {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		switch typed := child.(type) {
		case map[string]any:
			flattenSourceLeaves(t, typed, path, output)
		case string:
			output[path] = typed
		default:
			t.Fatalf("source %s has unexpected type %T", path, child)
		}
	}
}

func TestEffectiveNeverReadsNamedSecretValues(t *testing.T) {
	const sentinel = "SYNTHETIC_SENTINEL_MUST_NEVER_APPEAR"
	document := []byte(`version: 1
database: {url_env: DB_URL_NAME, auth_token_env: DB_TOKEN_NAME}
gmail: {oauth_client_id_env: CLIENT_ID_NAME, oauth_client_secret_env: CLIENT_SECRET_NAME, oauth_redirect_url_env: REDIRECT_NAME}
mcp: {bearer_token_env: MCP_TOKEN_NAME}
encryption: {master_key_env: MASTER_KEY_NAME}
`)
	for _, name := range []string{"DB_URL_NAME", "DB_TOKEN_NAME", "CLIENT_ID_NAME", "CLIENT_SECRET_NAME", "REDIRECT_NAME", "MCP_TOKEN_NAME", "MASTER_KEY_NAME"} {
		t.Setenv(name, sentinel+name)
	}
	effective, err := ParseEffective(document)
	if err != nil {
		t.Fatal(err)
	}
	data, err := effective.JSON("flag")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), sentinel) {
		t.Fatalf("effective output contains named secret value: %s", data)
	}
	for _, name := range []string{"DB_URL_NAME", "DB_TOKEN_NAME", "CLIENT_ID_NAME", "CLIENT_SECRET_NAME", "REDIRECT_NAME", "MCP_TOKEN_NAME", "MASTER_KEY_NAME"} {
		if !strings.Contains(string(data), `"`+name+`"`) {
			t.Errorf("effective output omits environment name %q", name)
		}
	}
}

func TestParseEffectivePreservesValidationBehavior(t *testing.T) {
	valid := []byte("version: 1\n")
	plain, plainErr := Parse(valid)
	effective, effectiveErr := ParseEffective(valid)
	if plainErr != nil || effectiveErr != nil || !reflect.DeepEqual(plain, effective.Configuration) {
		t.Fatalf("valid parity: Parse = %#v, %v; ParseEffective = %#v, %v", plain, plainErr, effective.Configuration, effectiveErr)
	}
	invalid := []byte("version: 1\nlogging: {level: private-value}\n")
	_, plainErr = Parse(invalid)
	_, effectiveErr = ParseEffective(invalid)
	if plainErr == nil || effectiveErr == nil || plainErr.Error() != effectiveErr.Error() {
		t.Fatalf("invalid diagnostic parity: Parse = %v, ParseEffective = %v", plainErr, effectiveErr)
	}
}

func assertSourceParity(t *testing.T, configuration, sources map[string]any, path string) {
	t.Helper()
	if len(configuration) != len(sources) {
		t.Errorf("%s key count differs: configuration=%d sources=%d", path, len(configuration), len(sources))
	}
	for key, configurationValue := range configuration {
		sourceValue, ok := sources[key]
		if !ok {
			t.Errorf("%s.%s has no source", path, key)
			continue
		}
		if child, ok := configurationValue.(map[string]any); ok {
			sourceChild, ok := sourceValue.(map[string]any)
			if !ok {
				t.Errorf("%s.%s source = %T, want object", path, key, sourceValue)
				continue
			}
			assertSourceParity(t, child, sourceChild, path+"."+key)
			continue
		}
		if sourceValue != sourceFile && sourceValue != sourceCompiledDefault {
			t.Errorf("%s.%s source = %#v", path, key, sourceValue)
		}
	}
	for key := range sources {
		if _, ok := configuration[key]; !ok {
			t.Errorf("%s has extra source %s", path, key)
		}
	}
}

func assertEverySource(t *testing.T, value any, exceptPath, want string) {
	t.Helper()
	var walk func(any, string)
	walk = func(current any, path string) {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				childPath := key
				if path != "" {
					childPath = path + "." + key
				}
				walk(child, childPath)
			}
		case string:
			if path != exceptPath && typed != want {
				t.Errorf("%s source = %q, want %q", path, typed, want)
			}
		default:
			t.Errorf("%s source = %T, want string or object", path, current)
		}
	}
	walk(value, "")
}

func assertOrdered(t *testing.T, value string, keys []string) {
	t.Helper()
	position := -1
	for _, key := range keys {
		next := strings.Index(value[position+1:], key)
		if next < 0 {
			t.Errorf("ordered output is missing %s", key)
			return
		}
		position += next + 1
	}
}
