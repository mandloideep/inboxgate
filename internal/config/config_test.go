package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestParseMinimalAppliesEveryDefault(t *testing.T) {
	got, err := Parse([]byte("version: 1\n"))
	if err != nil {
		t.Fatalf("Parse(minimal) error = %v", err)
	}
	if want := Defaults(); !reflect.DeepEqual(got, want) {
		t.Errorf("Parse(minimal) = %#v, want defaults %#v", got, want)
	}
}

func TestExampleIsCompleteAndMatchesDefaults(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse(config.example.yaml) error = %v", err)
	}
	if want := Defaults(); !reflect.DeepEqual(got, want) {
		t.Errorf("example = %#v, want defaults %#v", got, want)
	}
	for _, forbidden := range []string{"actual-secret", "access-token", "refresh-token"} {
		if strings.Contains(string(data), forbidden) {
			t.Errorf("example contains forbidden secret marker %q", forbidden)
		}
	}
}

func TestParseRejectsStrictYAMLFeatures(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{name: "empty", yaml: " \n", want: "document is empty"},
		{name: "missing version", yaml: "{}\n", want: "version: is required"},
		{name: "null document", yaml: "null\n", want: "must not be null"},
		{name: "sequence root", yaml: "- version: 1\n", want: "root must be a mapping"},
		{name: "multiple documents", yaml: "version: 1\n---\n", want: "multiple YAML documents"},
		{name: "document end", yaml: "version: 1\n...\n", want: "document-end markers"},
		{name: "directive", yaml: "%YAML 1.2\n---\nversion: 1\n", want: "directives are not supported"},
		{name: "anchor", yaml: "version: &value 1\n", want: "anchors and aliases"},
		{name: "alias", yaml: "version: &value 1\ngate:\n  version: *value\n", want: "anchors and aliases"},
		{name: "merge", yaml: "version: 1\ngate:\n  <<: {version: 1}\n", want: "merge keys"},
		{name: "custom tag", yaml: "version: !unsafe 1\n", want: "custom YAML tags"},
		{name: "null value", yaml: "version: 1\nlogging: null\n", want: "null values"},
		{name: "non-string key", yaml: "version: 1\n1: value\n", want: "mapping keys must be strings"},
		{name: "unknown root key", yaml: "version: 1\nunknown: true\n", want: "unknown key"},
		{name: "unknown capability", yaml: "version: 1\ncapabilities: {arbitrary.name: false}\n", want: "unknown key"},
		{name: "unknown nested key", yaml: "version: 1\nserver:\n  typo: 1\n", want: "unknown key"},
		{name: "duplicate unknown key", yaml: "version: 1\nunknown: true\nunknown: false\n", want: "duplicate key"},
		{name: "duplicate root", yaml: "version: 1\nversion: 1\n", want: "duplicate key"},
		{name: "duplicate nested", yaml: "version: 1\nlogging:\n  level: info\n  level: warn\n", want: "duplicate key"},
		{name: "quoted integer", yaml: "version: \"1\"\n", want: "unquoted canonical"},
		{name: "signed integer", yaml: "version: +1\n", want: "unquoted canonical"},
		{name: "leading zero integer", yaml: "version: 01\n", want: "unquoted canonical"},
		{name: "hex integer", yaml: "version: 0x1\n", want: "unquoted canonical"},
		{name: "float integer", yaml: "version: 1.0\n", want: "unquoted canonical"},
		{name: "infinite integer", yaml: "version: .inf\n", want: "unquoted canonical"},
		{name: "nan integer", yaml: "version: .nan\n", want: "unquoted canonical"},
		{name: "uppercase boolean", yaml: "version: 1\nbackfill:\n  enabled: TRUE\n", want: "unquoted lowercase boolean"},
		{name: "quoted boolean", yaml: "version: 1\nbackfill:\n  enabled: \"true\"\n", want: "unquoted lowercase boolean"},
		{name: "non-scalar integer", yaml: "version: [1]\n", want: "must be a scalar"},
		{name: "control", yaml: "version: 1\x00\n", want: "disallowed control character"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse([]byte(test.yaml))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Parse() error = %v, want text %q", err, test.want)
			}
		})
	}
	t.Run("invalid UTF-8", func(t *testing.T) {
		_, err := Parse([]byte{'v', 'e', 'r', 's', 'i', 'o', 'n', ':', ' ', 0xff})
		if err == nil || !strings.Contains(err.Error(), "valid UTF-8") {
			t.Fatalf("Parse(invalid UTF-8) error = %v", err)
		}
	})
}

func TestParseRejectsDecodedScalarControlsWithoutLeakingValues(t *testing.T) {
	tests := []string{`\0`, `\n`, `\t`, `\x7f`, `\u0080`}
	for _, escaped := range tests {
		t.Run(strings.ReplaceAll(escaped, "\\", "escape-"), func(t *testing.T) {
			document := "version: 1\nencryption:\n  master_key_env: \"PRIVATE" + escaped + "VALUE\"\n"
			_, err := Parse([]byte(document))
			if err == nil || !strings.Contains(err.Error(), "disallowed control character") {
				t.Fatalf("Parse(decoded control) error = %v", err)
			}
			for _, leaked := range []string{"PRIVATE", "VALUE"} {
				if strings.Contains(err.Error(), leaked) {
					t.Errorf("diagnostic leaked scalar content %q: %v", leaked, err)
				}
			}
		})
	}

	_, err := Parse([]byte("version: 1\n\"log\\tging\": {}\n"))
	if err == nil || !strings.Contains(err.Error(), "disallowed control character") {
		t.Fatalf("Parse(control in key) error = %v", err)
	}
}

func TestDocumentEndMarkerDetectionRespectsScalarIndentation(t *testing.T) {
	for _, marker := range []string{"...", "...   ", "... # end", "...\r"} {
		document := "version: 1\n" + marker + "\n"
		if _, err := Parse([]byte(document)); err == nil || !strings.Contains(err.Error(), "document-end markers") {
			t.Errorf("Parse(%q) error = %v, want document-end rejection", marker, err)
		}
	}

	for _, indicator := range []string{"|-", ">-"} {
		document := "version: 1\ngate:\n  subject_candidate_terms:\n    - " + indicator + "\n      ...\n"
		if _, err := Parse([]byte(document)); err != nil {
			t.Errorf("Parse(indented %s scalar) error = %v", indicator, err)
		}
	}
}

func TestDirectiveDetectionHandlesLeadingUTF8BOM(t *testing.T) {
	bom := "\uFEFF"
	tests := []struct {
		document string
		line     int
	}{
		{document: bom + "%YAML 1.1\n---\nversion: 1\n", line: 1},
		{document: bom + "%TAG !yaml! tag:yaml.org,2002:\n---\nversion: !yaml!int 1\n", line: 1},
		{document: bom + bom + "%YAML 1.1\n---\nversion: 1\n", line: 1},
		{document: "# preceding comment\n" + bom + "%TAG !yaml! tag:yaml.org,2002:\n---\nversion: !yaml!int 1\n", line: 2},
	}
	for _, test := range tests {
		_, err := Parse([]byte(test.document))
		if err == nil {
			t.Error("Parse(BOM directive) succeeded")
			continue
		}
		want := fmt.Sprintf("$ (line %d, column 1): YAML directives are not supported", test.line)
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(BOM directive) error = %v", err)
		}
		for _, leaked := range []string{"YAML 1.1", "tag:yaml.org,2002", "!yaml!int"} {
			if strings.Contains(err.Error(), leaked) {
				t.Errorf("directive diagnostic leaked input %q: %v", leaked, err)
			}
		}
	}

	ordinary := []string{
		bom + "version: 1\n",
	}
	for _, document := range ordinary {
		config, err := Parse([]byte(document))
		if err != nil {
			t.Fatalf("Parse(BOM schema v1) error = %v", err)
		}
		if config.Version != 1 {
			t.Errorf("Parse(BOM schema v1) version = %d, want 1", config.Version)
		}
	}
}

func TestServerListenRejectsMalformedHosts(t *testing.T) {
	invalid := []string{
		" example.com:443",
		"example.com :443",
		"example.com:443 ",
		"example\\name:443",
		"bad..name:443",
		"-bad.example:443",
		"[example.com]:443",
		"256.256.256.256:443",
	}
	for _, listen := range invalid {
		document := "version: 1\nserver:\n  listen: \"" + strings.ReplaceAll(listen, "\\", "\\\\") + "\"\n"
		if _, err := Parse([]byte(document)); err == nil || !strings.Contains(err.Error(), "server.listen") {
			t.Errorf("Parse(malformed listen) error = %v", err)
		}
	}

	valid := []string{"localhost:1", "mail.example.test:443", "mail.example.test.:443", "192.0.2.1:65535", "[2001:db8::1]:443", "[::ffff:192.0.2.1]:443"}
	for _, listen := range valid {
		document := "version: 1\nserver:\n  listen: \"" + listen + "\"\n"
		if _, err := Parse([]byte(document)); err != nil {
			t.Errorf("Parse(valid listen %q) error = %v", listen, err)
		}
	}
}

func TestMCPPathUsesSafeUnescapedHTTPGrammar(t *testing.T) {
	invalid := []string{"/has space", "/has\\backslash", "/has[bracket]", "/has`tick", "/line\\nfeed"}
	for _, value := range invalid {
		document := "version: 1\nmcp:\n  path: \"" + strings.ReplaceAll(value, "\\", "\\\\") + "\"\n"
		if _, err := Parse([]byte(document)); err == nil || !strings.Contains(err.Error(), "mcp.path") {
			t.Errorf("Parse(unsafe MCP path %q) error = %v", value, err)
		}
	}

	valid := []string{"/mcp", "/v1/mail-items_~", "/a!$&'()*+,;=:@/b"}
	for _, value := range valid {
		document := "version: 1\nmcp:\n  path: \"" + value + "\"\n"
		if _, err := Parse([]byte(document)); err != nil {
			t.Errorf("Parse(valid MCP path %q) error = %v", value, err)
		}
	}
}

func TestSubjectTermsUseUnicodeCaseFolding(t *testing.T) {
	document := "version: 1\ngate:\n  subject_candidate_terms: [Σ, ς]\n"
	if _, err := Parse([]byte(document)); err == nil || !strings.Contains(err.Error(), "gate.subject_candidate_terms") {
		t.Fatalf("Parse(Unicode case-fold duplicate) error = %v", err)
	}
}

func TestParseEnforcesComplexityLimits(t *testing.T) {
	atDepthLimit := "version: 1\ngate:\n  excluded_labels:\n    - " + strings.Repeat("[", 5) + "x" + strings.Repeat("]", 5) + "\n"
	if _, err := Parse([]byte(atDepthLimit)); err == nil || strings.Contains(err.Error(), "nesting depth") || !strings.Contains(err.Error(), "must be a scalar") {
		t.Fatalf("depth-8 Parse() error = %v, want only schema-shape error", err)
	}
	overDepthLimit := "version: 1\ngate:\n  excluded_labels:\n    - " + strings.Repeat("[", 6) + "x" + strings.Repeat("]", 6) + "\n"
	if _, err := Parse([]byte(overDepthLimit)); err == nil || !strings.Contains(err.Error(), "nesting depth") {
		t.Fatalf("depth-9 Parse() error = %v, want depth error", err)
	}

	atNodeLimit := "version: 1\ngate:\n  excluded_labels:\n" + strings.Repeat("    - X\n", 4_089)
	if _, err := Parse([]byte(atNodeLimit)); err == nil || strings.Contains(err.Error(), "4096-node") || !strings.Contains(err.Error(), "gate.excluded_labels") {
		t.Fatalf("4096-node Parse() error = %v, want only list-cardinality error", err)
	}
	overNodeLimit := "version: 1\ngate:\n  excluded_labels:\n" + strings.Repeat("    - X\n", 4_090)
	if _, err := Parse([]byte(overNodeLimit)); err == nil || !strings.Contains(err.Error(), "4096-node") {
		t.Fatalf("4097-node Parse() error = %v, want node error", err)
	}
}

func TestMalformedYAMLDiagnosticIsLocatedAndValueSafe(t *testing.T) {
	rejected := "DO_NOT_REPORT_THIS_VALUE"
	document := "version: 1\nlogging: [" + rejected + "\n"
	_, err := Parse([]byte(document))
	if err == nil || !strings.Contains(err.Error(), "malformed YAML") || !strings.Contains(err.Error(), "line ") || !strings.Contains(err.Error(), "column ") {
		t.Fatalf("Parse(malformed YAML) error = %v", err)
	}
	if strings.Contains(err.Error(), rejected) {
		t.Errorf("malformed YAML diagnostic leaked source content: %v", err)
	}
}

func TestParseValidatesEverySchemaBoundary(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{name: "version", yaml: "version: 2\n", want: "version"},
		{name: "listen host", yaml: "version: 1\nserver: {listen: ':8080'}\n", want: "server.listen"},
		{name: "listen port", yaml: "version: 1\nserver: {listen: 'localhost:0'}\n", want: "server.listen"},
		{name: "listen length", yaml: "version: 1\nserver: {listen: '" + strings.Repeat("a", 261) + ":80'}\n", want: "server.listen"},
		{name: "read header minimum", yaml: "version: 1\nserver: {read_header_timeout: 999ms}\n", want: "server.read_header_timeout"},
		{name: "read maximum", yaml: "version: 1\nserver: {read_timeout: 301s}\n", want: "server.read_timeout"},
		{name: "write maximum", yaml: "version: 1\nserver: {write_timeout: 301s}\n", want: "server.write_timeout"},
		{name: "idle maximum", yaml: "version: 1\nserver: {idle_timeout: 601s}\n", want: "server.idle_timeout"},
		{name: "read header relation", yaml: "version: 1\nserver: {read_header_timeout: 10s, read_timeout: 5s}\n", want: "server.read_header_timeout"},
		{name: "request bytes", yaml: "version: 1\nserver: {max_request_bytes: 1023}\n", want: "server.max_request_bytes"},
		{name: "engine", yaml: "version: 1\ndatabase: {engine: sqlite}\n", want: "database.engine"},
		{name: "env name", yaml: "version: 1\ndatabase: {url_env: lower}\n", want: "database.url_env"},
		{name: "env name length", yaml: "version: 1\ndatabase: {url_env: " + strings.Repeat("A", 129) + "}\n", want: "database.url_env"},
		{name: "open connections", yaml: "version: 1\ndatabase: {max_open_connections: 0}\n", want: "database.max_open_connections"},
		{name: "idle connections", yaml: "version: 1\ndatabase: {max_open_connections: 2, max_idle_connections: 3}\n", want: "database.max_idle_connections"},
		{name: "connection lifetime", yaml: "version: 1\ndatabase: {connection_max_lifetime: 59s}\n", want: "database.connection_max_lifetime"},
		{name: "invalid duration", yaml: "version: 1\ndatabase: {connection_max_lifetime: forever}\n", want: "database.connection_max_lifetime"},
		{name: "scope", yaml: "version: 1\ngmail: {scope: gmail.modify}\n", want: "gmail.scope"},
		{name: "poll interval", yaml: "version: 1\ngmail: {poll_interval: 59s}\n", want: "gmail.poll_interval"},
		{name: "poll jitter max", yaml: "version: 1\ngmail: {poll_jitter: 301s}\n", want: "gmail.poll_jitter"},
		{name: "poll jitter relation", yaml: "version: 1\ngmail: {poll_interval: 2m, poll_jitter: 61s}\n", want: "gmail.poll_jitter"},
		{name: "gmail page", yaml: "version: 1\ngmail: {page_size: 501}\n", want: "gmail.page_size"},
		{name: "gmail concurrency", yaml: "version: 1\ngmail: {max_accounts_in_flight: 17}\n", want: "gmail.max_accounts_in_flight"},
		{name: "excerpt", yaml: "version: 1\ngmail: {body_excerpt_bytes: 1023}\n", want: "gmail.body_excerpt_bytes"},
		{name: "thread", yaml: "version: 1\ngmail: {thread_max_messages: 101}\n", want: "gmail.thread_max_messages"},
		{name: "lookback", yaml: "version: 1\nbackfill: {default_lookback_days: 0}\n", want: "backfill.default_lookback_days"},
		{name: "lookback relation", yaml: "version: 1\nbackfill: {default_lookback_days: 10, maximum_lookback_days: 5}\n", want: "backfill.default_lookback_days"},
		{name: "backfill page", yaml: "version: 1\nbackfill: {page_size: 0}\n", want: "backfill.page_size"},
		{name: "timezone local", yaml: "version: 1\nbackfill: {run_window: {timezone: Local}}\n", want: "backfill.run_window.timezone"},
		{name: "timezone unsafe", yaml: "version: 1\nbackfill: {run_window: {timezone: ../zone}}\n", want: "backfill.run_window.timezone"},
		{name: "disabled still validates", yaml: "version: 1\nbackfill: {enabled: false, run_window: {timezone: ../zone}}\n", want: "backfill.run_window.timezone"},
		{name: "window format", yaml: "version: 1\nbackfill: {run_window: {start: '9:00'}}\n", want: "backfill.run_window.start"},
		{name: "window equal", yaml: "version: 1\nbackfill: {run_window: {start: '09:00', end: '09:00'}}\n", want: "backfill.run_window"},
		{name: "gate version", yaml: "version: 1\ngate: {version: 2}\n", want: "gate.version"},
		{name: "label", yaml: "version: 1\ngate: {excluded_labels: ['not valid']}\n", want: "gate.excluded_labels"},
		{name: "category", yaml: "version: 1\ngate: {suppress_gmail_categories: [CATEGORY_UNKNOWN]}\n", want: "gate.suppress_gmail_categories"},
		{name: "domain uppercase", yaml: "version: 1\ngate: {sender_allow_domains: [Example.com]}\n", want: "gate.sender_allow_domains"},
		{name: "domain wildcard", yaml: "version: 1\ngate: {sender_allow_domains: ['*.example.com']}\n", want: "gate.sender_allow_domains"},
		{name: "domain IP", yaml: "version: 1\ngate: {sender_allow_domains: [192.0.2.1]}\n", want: "gate.sender_allow_domains"},
		{name: "domain length", yaml: "version: 1\ngate: {sender_allow_domains: [" + strings.Repeat("a", 254) + "]}\n", want: "gate.sender_allow_domains"},
		{name: "domain overlap", yaml: "version: 1\ngate: {sender_allow_domains: [example.com], sender_block_domains: [example.com]}\n", want: "gate.sender_block_domains"},
		{name: "subject duplicate", yaml: "version: 1\ngate: {subject_candidate_terms: [Hello, hello]}\n", want: "gate.subject_candidate_terms"},
		{name: "subject whitespace", yaml: "version: 1\ngate: {subject_candidate_terms: [' padded ']}\n", want: "gate.subject_candidate_terms"},
		{name: "subject length", yaml: "version: 1\ngate: {subject_candidate_terms: [" + strings.Repeat("a", 129) + "]}\n", want: "gate.subject_candidate_terms"},
		{name: "review page", yaml: "version: 1\nreview: {default_page_size: 0}\n", want: "review.default_page_size"},
		{name: "review relation", yaml: "version: 1\nreview: {default_page_size: 10, maximum_page_size: 5}\n", want: "review.default_page_size"},
		{name: "metadata", yaml: "version: 1\nretention: {metadata_days: 36501}\n", want: "retention.metadata_days"},
		{name: "metadata relation", yaml: "version: 1\nretention: {metadata_days: 10, excerpt_days: 11}\n", want: "retention.metadata_days"},
		{name: "excerpt days", yaml: "version: 1\nretention: {excerpt_days: 0}\n", want: "retention.excerpt_days"},
		{name: "audit days", yaml: "version: 1\nretention: {audit_days: 3651}\n", want: "retention.audit_days"},
		{name: "mcp root", yaml: "version: 1\nmcp: {path: /}\n", want: "mcp.path"},
		{name: "mcp dirty", yaml: "version: 1\nmcp: {path: /a/../b}\n", want: "mcp.path"},
		{name: "mcp percent", yaml: "version: 1\nmcp: {path: /a%20b}\n", want: "mcp.path"},
		{name: "mcp length", yaml: "version: 1\nmcp: {path: /" + strings.Repeat("a", 128) + "}\n", want: "mcp.path"},
		{name: "logging level", yaml: "version: 1\nlogging: {level: trace}\n", want: "logging.level"},
		{name: "logging format", yaml: "version: 1\nlogging: {format: yaml}\n", want: "logging.format"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse([]byte(test.yaml))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Parse() error = %v, want field %q", err, test.want)
			}
		})
	}
}

func TestParseEnforcesListCardinalityAndUniqueness(t *testing.T) {
	labels := make([]string, 33)
	for index := range labels {
		labels[index] = "L" + strconv.Itoa(index)
	}
	domains := make([]string, 257)
	for index := range domains {
		domains[index] = "d" + strconv.Itoa(index) + ".example"
	}
	subjects := make([]string, 257)
	for index := range subjects {
		subjects[index] = "term " + strconv.Itoa(index)
	}
	tests := []struct {
		field string
		body  string
	}{
		{field: "gate.excluded_labels", body: "excluded_labels: [" + strings.Join(labels, ",") + "]"},
		{field: "gate.excluded_labels", body: "excluded_labels: [SPAM, SPAM]"},
		{field: "gate.suppress_gmail_categories", body: "suppress_gmail_categories: [CATEGORY_FORUMS, CATEGORY_PERSONAL, CATEGORY_PROMOTIONS, CATEGORY_SOCIAL, CATEGORY_UPDATES, CATEGORY_FORUMS]"},
		{field: "gate.sender_allow_domains", body: "sender_allow_domains: [" + strings.Join(domains, ",") + "]"},
		{field: "gate.subject_candidate_terms", body: "subject_candidate_terms: [" + strings.Join(subjects, ",") + "]"},
	}
	for _, test := range tests {
		_, err := Parse([]byte("version: 1\ngate:\n  " + test.body + "\n"))
		if err == nil || !strings.Contains(err.Error(), test.field) {
			t.Errorf("Parse(%s) error = %v", test.field, err)
		}
	}
}

func TestParseAcceptsBoundaryAndPresenceCases(t *testing.T) {
	valid := []string{
		"version: 1\ngate: {excluded_labels: [], suppress_gmail_categories: [], sender_allow_domains: [], sender_block_domains: [], subject_candidate_terms: [], subject_urgent_terms: []}\n",
		"version: 1\ngmail: {poll_interval: 1m, poll_jitter: 0s, page_size: 1, max_accounts_in_flight: 16, body_excerpt_bytes: 65536, thread_max_messages: 100}\n",
		"version: 1\nbackfill: {enabled: false, default_lookback_days: 1, maximum_lookback_days: 1, page_size: 500, run_window: {timezone: UTC, start: '06:00', end: '22:00'}}\n",
		"version: 1\nretention: {metadata_days: 0, excerpt_days: 1, audit_days: 3650}\n",
		"---\nversion: 1\n",
	}
	for index, document := range valid {
		if _, err := Parse([]byte(document)); err != nil {
			t.Errorf("valid case %d error = %v", index, err)
		}
	}
}

func TestParseAcceptsExactUpperBoundaries(t *testing.T) {
	domain := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	document := "version: 1\n" +
		"server: {listen: '" + domain + ":65535', read_header_timeout: 30s, read_timeout: 5m, write_timeout: 5m, idle_timeout: 10m, max_request_bytes: 1048576}\n" +
		"database: {url_env: " + strings.Repeat("A", 128) + ", max_open_connections: 64, max_idle_connections: 64, connection_max_lifetime: 24h}\n" +
		"gmail: {poll_interval: 1h, poll_jitter: 5m, page_size: 500, max_accounts_in_flight: 16, body_excerpt_bytes: 65536, thread_max_messages: 100}\n" +
		"backfill: {default_lookback_days: 3650, maximum_lookback_days: 3650, page_size: 500}\n" +
		"gate: {sender_allow_domains: [" + domain + "], subject_candidate_terms: [" + strings.Repeat("s", 128) + "]}\n" +
		"review: {default_page_size: 100, maximum_page_size: 100}\n" +
		"retention: {metadata_days: 36500, excerpt_days: 3650, audit_days: 3650}\n" +
		"mcp: {path: /" + strings.Repeat("m", 127) + "}\n"
	if _, err := Parse([]byte(document)); err != nil {
		t.Fatalf("Parse(exact upper boundaries) error = %v", err)
	}
}

func TestParseAcceptsExactLowerBoundaries(t *testing.T) {
	document := "version: 1\n" +
		"server: {listen: 'localhost:1', read_header_timeout: 1s, read_timeout: 1s, write_timeout: 1s, idle_timeout: 1s, max_request_bytes: 1024}\n" +
		"database: {max_open_connections: 1, max_idle_connections: 0, connection_max_lifetime: 1m}\n" +
		"gmail: {poll_interval: 1m, poll_jitter: 0s, page_size: 1, max_accounts_in_flight: 1, body_excerpt_bytes: 1024, thread_max_messages: 1}\n" +
		"backfill: {default_lookback_days: 1, maximum_lookback_days: 1, page_size: 1}\n" +
		"review: {default_page_size: 1, maximum_page_size: 1}\n" +
		"retention: {metadata_days: 1, excerpt_days: 1, audit_days: 1}\n" +
		"mcp: {path: /a}\n"
	if _, err := Parse([]byte(document)); err != nil {
		t.Fatalf("Parse(exact lower boundaries) error = %v", err)
	}
}

func TestParseAcceptsExactMaximumListCardinalities(t *testing.T) {
	labels := numberedValues("LABEL_", 32, "")
	categories := []string{"CATEGORY_FORUMS", "CATEGORY_PERSONAL", "CATEGORY_PROMOTIONS", "CATEGORY_SOCIAL", "CATEGORY_UPDATES"}
	allowDomains := numberedValues("allow", 256, ".example")
	blockDomains := numberedValues("block", 256, ".example")
	candidateTerms := numberedValues("candidate-", 256, "")
	urgentTerms := numberedValues("urgent-", 256, "")
	document := "version: 1\ngate:\n" +
		"  excluded_labels: [" + strings.Join(labels, ",") + "]\n" +
		"  suppress_gmail_categories: [" + strings.Join(categories, ",") + "]\n" +
		"  sender_allow_domains: [" + strings.Join(allowDomains, ",") + "]\n" +
		"  sender_block_domains: [" + strings.Join(blockDomains, ",") + "]\n" +
		"  subject_candidate_terms: [" + strings.Join(candidateTerms, ",") + "]\n" +
		"  subject_urgent_terms: [" + strings.Join(urgentTerms, ",") + "]\n"
	if _, err := Parse([]byte(document)); err != nil {
		t.Fatalf("Parse(exact maximum lists) error = %v", err)
	}
}

func numberedValues(prefix string, count int, suffix string) []string {
	values := make([]string, count)
	for index := range values {
		values[index] = prefix + strconv.Itoa(index) + suffix
	}
	return values
}

func TestNamedSecretEnvironmentValuesDoNotAffectParsing(t *testing.T) {
	document := []byte("version: 1\nencryption: {master_key_env: SYNTHETIC_MASTER_KEY}\n")
	t.Setenv("SYNTHETIC_MASTER_KEY", "first-private-value")
	first, err := Parse(document)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SYNTHETIC_MASTER_KEY", "different-private-value")
	second, err := Parse(document)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) || first.Encryption.MasterKeyEnv != "SYNTHETIC_MASTER_KEY" {
		t.Errorf("named secret environment value affected parsing: first=%#v second=%#v", first.Encryption, second.Encryption)
	}
}

func TestDiagnosticsDoNotRevealRejectedValues(t *testing.T) {
	secret := "actual-secret-value"
	_, err := Parse([]byte("version: 1\nencryption:\n  master_key_env: " + secret + "\n"))
	if err == nil {
		t.Fatal("Parse() succeeded")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("diagnostic reveals rejected value: %q", err)
	}
	var validation *ValidationError
	if !errors.As(err, &validation) || len(validation.Problems) == 0 {
		t.Fatalf("error = %T %v, want ValidationError", err, err)
	}
}

func TestLoadEnforcesRegularFileAndSizeBoundary(t *testing.T) {
	directory := t.TempDir()
	valid := filepath.Join(directory, "valid.yaml")
	data := append([]byte("version: 1\n#"), make([]byte, MaxFileBytes-len("version: 1\n#"))...)
	for index := len("version: 1\n#"); index < len(data); index++ {
		data[index] = 'x'
	}
	if err := os.WriteFile(valid, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(valid); err != nil {
		t.Fatalf("Load(maximum file) error = %v", err)
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(workingDirectory, valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(relative); err != nil {
		t.Fatalf("Load(relative path) error = %v", err)
	}

	tooLarge := filepath.Join(directory, "large.yaml")
	if err := os.WriteFile(tooLarge, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(tooLarge); err == nil || !strings.Contains(err.Error(), "65536-byte") {
		t.Fatalf("Load(too large) error = %v", err)
	}
	if _, err := Load(directory); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("Load(directory) error = %v", err)
	}

	symlink := filepath.Join(directory, "linked.yaml")
	if err := os.Symlink(valid, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(symlink); err != nil {
		t.Fatalf("Load(symlink) error = %v", err)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
