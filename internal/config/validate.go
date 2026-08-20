package config

import (
	"net"
	pathpkg "path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	environmentName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
	labelName       = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	windowTime      = regexp.MustCompile(`^(?:[01][0-9]|2[0-3]):[0-5][0-9]$`)
	domainLabel     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	hostLabel       = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	numericPort     = regexp.MustCompile(`^[0-9]+$`)
)

func validateConfig(config Config, problems *[]Problem) {
	equalUint("version", config.Version, 1, problems)
	validateCapabilityDefinitions(config, capabilityDefinitions, problems)
	validateServer(config.Server, problems)
	validateDatabase(config.Database, problems)
	validateGmail(config.Gmail, problems)
	validateBackfill(config.Backfill, problems)
	validateGate(config.Gate, problems)
	validateReview(config.Review, problems)
	validateRetention(config.Retention, problems)
	validateMCP(config.MCP, problems)
	validateEnvironmentName("encryption.master_key_env", config.Encryption.MasterKeyEnv, problems)
	oneOf("logging.level", config.Logging.Level, []string{"debug", "info", "warn", "error"}, problems)
	oneOf("logging.format", config.Logging.Format, []string{"json", "text"}, problems)
}

func validateServer(server Server, problems *[]Problem) {
	if !validListenAddress(server.Listen) {
		problem(problems, "server.listen", "must be a valid hostname, IPv4, or bracketed IPv6 address and numeric port with at most 263 bytes")
	}
	durationRange("server.read_header_timeout", server.ReadHeaderTimeout, time.Second, 30*time.Second, problems)
	durationRange("server.read_timeout", server.ReadTimeout, time.Second, 5*time.Minute, problems)
	durationRange("server.write_timeout", server.WriteTimeout, time.Second, 5*time.Minute, problems)
	durationRange("server.idle_timeout", server.IdleTimeout, time.Second, 10*time.Minute, problems)
	if server.ReadHeaderTimeout > server.ReadTimeout {
		problem(problems, "server.read_header_timeout", "must not exceed server.read_timeout")
	}
	uintRange("server.max_request_bytes", server.MaxRequestBytes, 1_024, 1_048_576, problems)
}

func validListenAddress(value string) bool {
	if value == "" || len(value) > 263 || !isASCII(value) || strings.ContainsAny(value, "/?#@\\") || strings.Contains(value, "://") {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" || !numericPort.MatchString(port) {
		return false
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort < 1 || parsedPort > 65_535 {
		return false
	}
	if strings.HasPrefix(value, "[") {
		ip := net.ParseIP(host)
		return ip != nil && strings.Contains(host, ":") && !strings.Contains(host, "%")
	}
	if strings.ContainsAny(host, "[]:") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.To4() != nil
	}
	if onlyDigitsAndDots(host) {
		return false
	}
	hostname := strings.TrimSuffix(host, ".")
	if hostname == "" || len(hostname) > 253 || strings.HasPrefix(hostname, ".") {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if !hostLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func onlyDigitsAndDots(value string) bool {
	for _, character := range value {
		if character != '.' && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func validateDatabase(database Database, problems *[]Problem) {
	oneOf("database.engine", database.Engine, []string{"turso"}, problems)
	validateEnvironmentName("database.url_env", database.URLEnv, problems)
	validateEnvironmentName("database.auth_token_env", database.AuthTokenEnv, problems)
	uintRange("database.max_open_connections", database.MaxOpenConnections, 1, 64, problems)
	uintRange("database.max_idle_connections", database.MaxIdleConnections, 0, 64, problems)
	if database.MaxIdleConnections > database.MaxOpenConnections {
		problem(problems, "database.max_idle_connections", "must not exceed database.max_open_connections")
	}
	durationRange("database.connection_max_lifetime", database.ConnectionMaxLifetime, time.Minute, 24*time.Hour, problems)
}

func validateGmail(gmail Gmail, problems *[]Problem) {
	validateEnvironmentName("gmail.oauth_client_id_env", gmail.OAuthClientIDEnv, problems)
	validateEnvironmentName("gmail.oauth_client_secret_env", gmail.OAuthClientSecretEnv, problems)
	validateEnvironmentName("gmail.oauth_redirect_url_env", gmail.OAuthRedirectURLEnv, problems)
	oneOf("gmail.scope", gmail.Scope, []string{"gmail.readonly"}, problems)
	durationRange("gmail.poll_interval", gmail.PollInterval, time.Minute, time.Hour, problems)
	durationRange("gmail.poll_jitter", gmail.PollJitter, 0, 5*time.Minute, problems)
	if gmail.PollJitter > gmail.PollInterval/2 {
		problem(problems, "gmail.poll_jitter", "must not exceed half of gmail.poll_interval")
	}
	uintRange("gmail.page_size", gmail.PageSize, 1, 500, problems)
	uintRange("gmail.max_accounts_in_flight", gmail.MaxAccountsInFlight, 1, 16, problems)
	uintRange("gmail.body_excerpt_bytes", gmail.BodyExcerptBytes, 1_024, 65_536, problems)
	uintRange("gmail.thread_max_messages", gmail.ThreadMaxMessages, 1, 100, problems)
}

func validateBackfill(backfill Backfill, problems *[]Problem) {
	uintRange("backfill.default_lookback_days", backfill.DefaultLookbackDays, 1, 3_650, problems)
	uintRange("backfill.maximum_lookback_days", backfill.MaximumLookbackDays, 1, 3_650, problems)
	if backfill.DefaultLookbackDays > backfill.MaximumLookbackDays {
		problem(problems, "backfill.default_lookback_days", "must not exceed backfill.maximum_lookback_days")
	}
	uintRange("backfill.page_size", backfill.PageSize, 1, 500, problems)
	validateTimezone(backfill.RunWindow.Timezone, problems)
	if !windowTime.MatchString(backfill.RunWindow.Start) {
		problem(problems, "backfill.run_window.start", "must use zero-padded HH:MM")
	}
	if !windowTime.MatchString(backfill.RunWindow.End) {
		problem(problems, "backfill.run_window.end", "must use zero-padded HH:MM")
	}
	if backfill.RunWindow.Start == backfill.RunWindow.End {
		problem(problems, "backfill.run_window", "start and end must differ")
	}
}

func validateTimezone(value string, problems *[]Problem) {
	if value == "" || len(value) > 64 || value == "Local" || !isASCII(value) || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") {
		problem(problems, "backfill.run_window.timezone", "must be UTC or a safe IANA timezone name")
		return
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			problem(problems, "backfill.run_window.timezone", "must be UTC or a safe IANA timezone name")
			return
		}
	}
	if _, err := time.LoadLocation(value); err != nil {
		problem(problems, "backfill.run_window.timezone", "must be UTC or a loadable IANA timezone name")
	}
}

func validateGate(gate Gate, problems *[]Problem) {
	equalUint("gate.version", gate.Version, 1, problems)
	validateUniqueList("gate.excluded_labels", gate.ExcludedLabels, 32, false, func(value string) bool { return labelName.MatchString(value) }, "must contain unique supported label identifiers", problems)
	categories := map[string]struct{}{"CATEGORY_FORUMS": {}, "CATEGORY_PERSONAL": {}, "CATEGORY_PROMOTIONS": {}, "CATEGORY_SOCIAL": {}, "CATEGORY_UPDATES": {}}
	validateUniqueList("gate.suppress_gmail_categories", gate.SuppressGmailCategories, 5, false, func(value string) bool { _, ok := categories[value]; return ok }, "must contain unique supported Gmail categories", problems)
	validateDomains("gate.sender_allow_domains", gate.SenderAllowDomains, problems)
	validateDomains("gate.sender_block_domains", gate.SenderBlockDomains, problems)
	allowed := make(map[string]struct{}, len(gate.SenderAllowDomains))
	for _, domain := range gate.SenderAllowDomains {
		allowed[domain] = struct{}{}
	}
	for _, domain := range gate.SenderBlockDomains {
		if _, overlap := allowed[domain]; overlap {
			problem(problems, "gate.sender_block_domains", "must not overlap gate.sender_allow_domains")
			break
		}
	}
	validateSubjects("gate.subject_candidate_terms", gate.SubjectCandidateTerms, problems)
	validateSubjects("gate.subject_urgent_terms", gate.SubjectUrgentTerms, problems)
}

func validateDomains(fieldPath string, values []string, problems *[]Problem) {
	validateUniqueList(fieldPath, values, 256, false, validDomain, "must contain unique lowercase ASCII DNS domains", problems)
}

func validDomain(value string) bool {
	if value == "" || len(value) > 253 || !isASCII(value) || value != strings.ToLower(value) || net.ParseIP(value) != nil || strings.ContainsAny(value, ":/*_@") || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !domainLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func validateSubjects(fieldPath string, values []string, problems *[]Problem) {
	validateUniqueList(fieldPath, values, 256, true, func(value string) bool {
		if value == "" || value != strings.TrimSpace(value) || len(value) > 128 || !utf8.ValidString(value) {
			return false
		}
		for _, r := range value {
			if unicode.IsControl(r) {
				return false
			}
		}
		return true
	}, "must contain unique trimmed literal terms of 1 to 128 UTF-8 bytes without controls", problems)
}

func validateReview(review Review, problems *[]Problem) {
	uintRange("review.default_page_size", review.DefaultPageSize, 1, 100, problems)
	uintRange("review.maximum_page_size", review.MaximumPageSize, 1, 100, problems)
	if review.DefaultPageSize > review.MaximumPageSize {
		problem(problems, "review.default_page_size", "must not exceed review.maximum_page_size")
	}
}

func validateRetention(retention Retention, problems *[]Problem) {
	if retention.MetadataDays > 36_500 {
		problem(problems, "retention.metadata_days", "must be 0 or between 1 and 36500")
	}
	uintRange("retention.excerpt_days", retention.ExcerptDays, 1, 3_650, problems)
	uintRange("retention.audit_days", retention.AuditDays, 1, 3_650, problems)
	if retention.MetadataDays != 0 && retention.MetadataDays < retention.ExcerptDays {
		problem(problems, "retention.metadata_days", "must be 0 or not shorter than retention.excerpt_days")
	}
}

func validateMCP(mcp MCP, problems *[]Problem) {
	value := mcp.Path
	if len(value) < 2 || len(value) > 128 || value == "/" || !strings.HasPrefix(value, "/") || strings.Contains(value, "//") || pathpkg.Clean(value) != value || !safeHTTPPath(value) {
		problem(problems, "mcp.path", "must be a clean absolute ASCII HTTP path of 2 to 128 bytes")
	}
	if value == "/health/live" || value == "/health/ready" {
		problem(problems, "mcp.path", "must not overlap a reserved health path")
	}
	validateEnvironmentName("mcp.bearer_token_env", mcp.BearerTokenEnv, problems)
}

func safeHTTPPath(value string) bool {
	for index := 1; index < len(value); index++ {
		character := value[index]
		if character == '/' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			continue
		}
		switch character {
		case '-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '@':
			continue
		default:
			return false
		}
	}
	return true
}

func validateEnvironmentName(fieldPath, value string, problems *[]Problem) {
	if !environmentName.MatchString(value) {
		problem(problems, fieldPath, "must be an uppercase environment-variable name of at most 128 bytes")
	}
}

func validateUniqueList(fieldPath string, values []string, maximum int, fold bool, valid func(string) bool, reason string, problems *[]Problem) {
	if len(values) > maximum {
		problem(problems, fieldPath, reason)
	}
	seen := make(map[string]struct{}, len(values))
	var folded []string
	for _, value := range values {
		if !valid(value) {
			problem(problems, fieldPath, reason)
			return
		}
		if fold {
			for _, prior := range folded {
				if strings.EqualFold(prior, value) {
					problem(problems, fieldPath, reason)
					return
				}
			}
			folded = append(folded, value)
		} else {
			if _, duplicate := seen[value]; duplicate {
				problem(problems, fieldPath, reason)
				return
			}
			seen[value] = struct{}{}
		}
	}
}

func isASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] > 0x7f {
			return false
		}
	}
	return true
}

func durationRange(fieldPath string, value, minimum, maximum time.Duration, problems *[]Problem) {
	if value < minimum || value > maximum {
		problem(problems, fieldPath, "duration is outside the supported range")
	}
}

func uintRange(fieldPath string, value, minimum, maximum uint64, problems *[]Problem) {
	if value < minimum || value > maximum {
		problem(problems, fieldPath, "integer is outside the supported range")
	}
}

func equalUint(fieldPath string, value, expected uint64, problems *[]Problem) {
	if value != expected {
		problem(problems, fieldPath, "unsupported schema version")
	}
}

func oneOf(fieldPath, value string, choices []string, problems *[]Problem) {
	for _, choice := range choices {
		if value == choice {
			return
		}
	}
	problem(problems, fieldPath, "is not a supported value")
}

func problem(problems *[]Problem, fieldPath, reason string) {
	*problems = append(*problems, Problem{Path: fieldPath, Reason: reason})
}
