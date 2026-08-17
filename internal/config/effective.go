package config

import (
	"encoding/json"
	"fmt"

	"go.yaml.in/yaml/v3"
)

const (
	sourceFile            = "file"
	sourceCompiledDefault = "compiled_default"
)

type Effective struct {
	Configuration Config
	Sources       Sources
}

type effectiveEnvelope struct {
	OutputVersion uint64       `json:"output_version"`
	PathSource    string       `json:"path_source"`
	Configuration outputConfig `json:"configuration"`
	Sources       Sources      `json:"sources"`
}

type outputConfig struct {
	Version      uint64             `json:"version"`
	Capabilities outputCapabilities `json:"capabilities"`
	Server       outputServer       `json:"server"`
	Database     outputDatabase     `json:"database"`
	Gmail        outputGmail        `json:"gmail"`
	Backfill     outputBackfill     `json:"backfill"`
	Gate         outputGate         `json:"gate"`
	Review       outputReview       `json:"review"`
	Retention    outputRetention    `json:"retention"`
	MCP          outputMCP          `json:"mcp"`
	Encryption   outputEncryption   `json:"encryption"`
	Logging      outputLogging      `json:"logging"`
}

type outputCapabilities struct {
	GmailRead        bool `json:"gmail.read"`
	GmailCurrentSync bool `json:"gmail.current_sync"`
	GmailBackfill    bool `json:"gmail.backfill"`
	MailReviewRead   bool `json:"mail.review_read"`
	MailReviewWrite  bool `json:"mail.review_write"`
}

type outputServer struct {
	Listen            string `json:"listen"`
	ReadHeaderTimeout string `json:"read_header_timeout"`
	ReadTimeout       string `json:"read_timeout"`
	WriteTimeout      string `json:"write_timeout"`
	IdleTimeout       string `json:"idle_timeout"`
	MaxRequestBytes   uint64 `json:"max_request_bytes"`
}

type outputDatabase struct {
	Engine                string `json:"engine"`
	URLEnv                string `json:"url_env"`
	AuthTokenEnv          string `json:"auth_token_env"`
	MaxOpenConnections    uint64 `json:"max_open_connections"`
	MaxIdleConnections    uint64 `json:"max_idle_connections"`
	ConnectionMaxLifetime string `json:"connection_max_lifetime"`
}

type outputGmail struct {
	OAuthClientIDEnv     string `json:"oauth_client_id_env"`
	OAuthClientSecretEnv string `json:"oauth_client_secret_env"`
	OAuthRedirectURLEnv  string `json:"oauth_redirect_url_env"`
	Scope                string `json:"scope"`
	PollInterval         string `json:"poll_interval"`
	PollJitter           string `json:"poll_jitter"`
	PageSize             uint64 `json:"page_size"`
	MaxAccountsInFlight  uint64 `json:"max_accounts_in_flight"`
	BodyExcerptBytes     uint64 `json:"body_excerpt_bytes"`
	ThreadMaxMessages    uint64 `json:"thread_max_messages"`
}

type outputBackfill struct {
	Enabled                bool            `json:"enabled"`
	DefaultLookbackDays    uint64          `json:"default_lookback_days"`
	MaximumLookbackDays    uint64          `json:"maximum_lookback_days"`
	PageSize               uint64          `json:"page_size"`
	CurrentMailHasPriority bool            `json:"current_mail_has_priority"`
	RunWindow              outputRunWindow `json:"run_window"`
}

type outputRunWindow struct {
	Timezone string `json:"timezone"`
	Start    string `json:"start"`
	End      string `json:"end"`
}

type outputGate struct {
	Version                    uint64   `json:"version"`
	ExcludedLabels             []string `json:"excluded_labels"`
	SuppressGmailCategories    []string `json:"suppress_gmail_categories"`
	DirectRecipientIsCandidate bool     `json:"direct_recipient_is_candidate"`
	MailingListIsBulkSignal    bool     `json:"mailing_list_is_bulk_signal"`
	SenderAllowDomains         []string `json:"sender_allow_domains"`
	SenderBlockDomains         []string `json:"sender_block_domains"`
	SubjectCandidateTerms      []string `json:"subject_candidate_terms"`
	SubjectUrgentTerms         []string `json:"subject_urgent_terms"`
}

type outputReview struct {
	DefaultPageSize       uint64 `json:"default_page_size"`
	MaximumPageSize       uint64 `json:"maximum_page_size"`
	AutomaticTaskCreation bool   `json:"automatic_task_creation"`
}

type outputRetention struct {
	MetadataDays uint64 `json:"metadata_days"`
	ExcerptDays  uint64 `json:"excerpt_days"`
	AuditDays    uint64 `json:"audit_days"`
}

type outputMCP struct {
	Enabled             bool   `json:"enabled"`
	Path                string `json:"path"`
	BearerTokenEnv      string `json:"bearer_token_env"`
	EnableReviewWrites  bool   `json:"enable_review_writes"`
	EnableOperatorTools bool   `json:"enable_operator_tools"`
}

type outputEncryption struct {
	MasterKeyEnv string `json:"master_key_env"`
}

type outputLogging struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

type Sources struct {
	Version      string                   `json:"version"`
	Capabilities sourceCapabilitiesOutput `json:"capabilities"`
	Server       sourceServerOutput       `json:"server"`
	Database     sourceDatabaseOutput     `json:"database"`
	Gmail        sourceGmailOutput        `json:"gmail"`
	Backfill     sourceBackfillOutput     `json:"backfill"`
	Gate         sourceGateOutput         `json:"gate"`
	Review       sourceReviewOutput       `json:"review"`
	Retention    sourceRetentionOutput    `json:"retention"`
	MCP          sourceMCPOutput          `json:"mcp"`
	Encryption   sourceEncryptionOutput   `json:"encryption"`
	Logging      sourceLoggingOutput      `json:"logging"`
}

type sourceCapabilitiesOutput struct {
	GmailRead        string `json:"gmail.read"`
	GmailCurrentSync string `json:"gmail.current_sync"`
	GmailBackfill    string `json:"gmail.backfill"`
	MailReviewRead   string `json:"mail.review_read"`
	MailReviewWrite  string `json:"mail.review_write"`
}

type sourceServerOutput struct {
	Listen            string `json:"listen"`
	ReadHeaderTimeout string `json:"read_header_timeout"`
	ReadTimeout       string `json:"read_timeout"`
	WriteTimeout      string `json:"write_timeout"`
	IdleTimeout       string `json:"idle_timeout"`
	MaxRequestBytes   string `json:"max_request_bytes"`
}

type sourceDatabaseOutput struct {
	Engine                string `json:"engine"`
	URLEnv                string `json:"url_env"`
	AuthTokenEnv          string `json:"auth_token_env"`
	MaxOpenConnections    string `json:"max_open_connections"`
	MaxIdleConnections    string `json:"max_idle_connections"`
	ConnectionMaxLifetime string `json:"connection_max_lifetime"`
}

type sourceGmailOutput struct {
	OAuthClientIDEnv     string `json:"oauth_client_id_env"`
	OAuthClientSecretEnv string `json:"oauth_client_secret_env"`
	OAuthRedirectURLEnv  string `json:"oauth_redirect_url_env"`
	Scope                string `json:"scope"`
	PollInterval         string `json:"poll_interval"`
	PollJitter           string `json:"poll_jitter"`
	PageSize             string `json:"page_size"`
	MaxAccountsInFlight  string `json:"max_accounts_in_flight"`
	BodyExcerptBytes     string `json:"body_excerpt_bytes"`
	ThreadMaxMessages    string `json:"thread_max_messages"`
}

type sourceBackfillOutput struct {
	Enabled                string                `json:"enabled"`
	DefaultLookbackDays    string                `json:"default_lookback_days"`
	MaximumLookbackDays    string                `json:"maximum_lookback_days"`
	PageSize               string                `json:"page_size"`
	CurrentMailHasPriority string                `json:"current_mail_has_priority"`
	RunWindow              sourceRunWindowOutput `json:"run_window"`
}

type sourceRunWindowOutput struct {
	Timezone string `json:"timezone"`
	Start    string `json:"start"`
	End      string `json:"end"`
}

type sourceGateOutput struct {
	Version                    string `json:"version"`
	ExcludedLabels             string `json:"excluded_labels"`
	SuppressGmailCategories    string `json:"suppress_gmail_categories"`
	DirectRecipientIsCandidate string `json:"direct_recipient_is_candidate"`
	MailingListIsBulkSignal    string `json:"mailing_list_is_bulk_signal"`
	SenderAllowDomains         string `json:"sender_allow_domains"`
	SenderBlockDomains         string `json:"sender_block_domains"`
	SubjectCandidateTerms      string `json:"subject_candidate_terms"`
	SubjectUrgentTerms         string `json:"subject_urgent_terms"`
}

type sourceReviewOutput struct {
	DefaultPageSize       string `json:"default_page_size"`
	MaximumPageSize       string `json:"maximum_page_size"`
	AutomaticTaskCreation string `json:"automatic_task_creation"`
}

type sourceRetentionOutput struct {
	MetadataDays string `json:"metadata_days"`
	ExcerptDays  string `json:"excerpt_days"`
	AuditDays    string `json:"audit_days"`
}

type sourceMCPOutput struct {
	Enabled             string `json:"enabled"`
	Path                string `json:"path"`
	BearerTokenEnv      string `json:"bearer_token_env"`
	EnableReviewWrites  string `json:"enable_review_writes"`
	EnableOperatorTools string `json:"enable_operator_tools"`
}

type sourceEncryptionOutput struct {
	MasterKeyEnv string `json:"master_key_env"`
}

type sourceLoggingOutput struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

func ParseEffective(data []byte) (Effective, error) {
	configuration, root, err := parseValidated(data)
	if err != nil {
		return Effective{}, err
	}
	return Effective{Configuration: configuration, Sources: collectSources(root)}, nil
}

func (effective Effective) JSON(pathSource string) ([]byte, error) {
	if pathSource != "flag" && pathSource != "environment" && pathSource != "default" {
		return nil, fmt.Errorf("invalid path source")
	}
	payload := effectiveEnvelope{
		OutputVersion: 2,
		PathSource:    pathSource,
		Configuration: outputConfiguration(effective.Configuration),
		Sources:       effective.Sources,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal effective configuration: %w", err)
	}
	return append(data, '\n'), nil
}

func collectSources(root *yaml.Node) Sources {
	rootValues := mappingValues(root)
	capabilities := childValues(rootValues, "capabilities")
	server := childValues(rootValues, "server")
	database := childValues(rootValues, "database")
	gmail := childValues(rootValues, "gmail")
	backfill := childValues(rootValues, "backfill")
	runWindow := childValues(backfill, "run_window")
	gate := childValues(rootValues, "gate")
	review := childValues(rootValues, "review")
	retention := childValues(rootValues, "retention")
	mcp := childValues(rootValues, "mcp")
	encryption := childValues(rootValues, "encryption")
	logging := childValues(rootValues, "logging")
	return Sources{
		Version: presentSource(rootValues, "version"),
		Capabilities: sourceCapabilitiesOutput{
			GmailRead: presentSource(capabilities, "gmail.read"), GmailCurrentSync: presentSource(capabilities, "gmail.current_sync"),
			GmailBackfill: presentSource(capabilities, "gmail.backfill"), MailReviewRead: presentSource(capabilities, "mail.review_read"),
			MailReviewWrite: presentSource(capabilities, "mail.review_write"),
		},
		Server: sourceServerOutput{
			Listen: presentSource(server, "listen"), ReadHeaderTimeout: presentSource(server, "read_header_timeout"),
			ReadTimeout: presentSource(server, "read_timeout"), WriteTimeout: presentSource(server, "write_timeout"),
			IdleTimeout: presentSource(server, "idle_timeout"), MaxRequestBytes: presentSource(server, "max_request_bytes"),
		},
		Database: sourceDatabaseOutput{
			Engine: presentSource(database, "engine"), URLEnv: presentSource(database, "url_env"),
			AuthTokenEnv: presentSource(database, "auth_token_env"), MaxOpenConnections: presentSource(database, "max_open_connections"),
			MaxIdleConnections: presentSource(database, "max_idle_connections"), ConnectionMaxLifetime: presentSource(database, "connection_max_lifetime"),
		},
		Gmail: sourceGmailOutput{
			OAuthClientIDEnv: presentSource(gmail, "oauth_client_id_env"), OAuthClientSecretEnv: presentSource(gmail, "oauth_client_secret_env"),
			OAuthRedirectURLEnv: presentSource(gmail, "oauth_redirect_url_env"), Scope: presentSource(gmail, "scope"),
			PollInterval: presentSource(gmail, "poll_interval"), PollJitter: presentSource(gmail, "poll_jitter"),
			PageSize: presentSource(gmail, "page_size"), MaxAccountsInFlight: presentSource(gmail, "max_accounts_in_flight"),
			BodyExcerptBytes: presentSource(gmail, "body_excerpt_bytes"), ThreadMaxMessages: presentSource(gmail, "thread_max_messages"),
		},
		Backfill: sourceBackfillOutput{
			Enabled: presentSource(backfill, "enabled"), DefaultLookbackDays: presentSource(backfill, "default_lookback_days"),
			MaximumLookbackDays: presentSource(backfill, "maximum_lookback_days"), PageSize: presentSource(backfill, "page_size"),
			CurrentMailHasPriority: presentSource(backfill, "current_mail_has_priority"),
			RunWindow:              sourceRunWindowOutput{Timezone: presentSource(runWindow, "timezone"), Start: presentSource(runWindow, "start"), End: presentSource(runWindow, "end")},
		},
		Gate: sourceGateOutput{
			Version: presentSource(gate, "version"), ExcludedLabels: presentSource(gate, "excluded_labels"),
			SuppressGmailCategories: presentSource(gate, "suppress_gmail_categories"), DirectRecipientIsCandidate: presentSource(gate, "direct_recipient_is_candidate"),
			MailingListIsBulkSignal: presentSource(gate, "mailing_list_is_bulk_signal"), SenderAllowDomains: presentSource(gate, "sender_allow_domains"),
			SenderBlockDomains: presentSource(gate, "sender_block_domains"), SubjectCandidateTerms: presentSource(gate, "subject_candidate_terms"),
			SubjectUrgentTerms: presentSource(gate, "subject_urgent_terms"),
		},
		Review: sourceReviewOutput{
			DefaultPageSize: presentSource(review, "default_page_size"), MaximumPageSize: presentSource(review, "maximum_page_size"),
			AutomaticTaskCreation: presentSource(review, "automatic_task_creation"),
		},
		Retention: sourceRetentionOutput{
			MetadataDays: presentSource(retention, "metadata_days"), ExcerptDays: presentSource(retention, "excerpt_days"),
			AuditDays: presentSource(retention, "audit_days"),
		},
		MCP: sourceMCPOutput{
			Enabled: presentSource(mcp, "enabled"), Path: presentSource(mcp, "path"), BearerTokenEnv: presentSource(mcp, "bearer_token_env"),
			EnableReviewWrites: presentSource(mcp, "enable_review_writes"), EnableOperatorTools: presentSource(mcp, "enable_operator_tools"),
		},
		Encryption: sourceEncryptionOutput{MasterKeyEnv: presentSource(encryption, "master_key_env")},
		Logging:    sourceLoggingOutput{Level: presentSource(logging, "level"), Format: presentSource(logging, "format")},
	}
}

func childValues(values map[string]*yaml.Node, key string) map[string]*yaml.Node {
	node := values[key]
	if node == nil {
		return nil
	}
	return mappingValues(node)
}

func presentSource(values map[string]*yaml.Node, key string) string {
	if values[key] != nil {
		return sourceFile
	}
	return sourceCompiledDefault
}

func outputConfiguration(value Config) outputConfig {
	return outputConfig{
		Version: value.Version,
		Capabilities: outputCapabilities{
			GmailRead: value.Capabilities.GmailRead, GmailCurrentSync: value.Capabilities.GmailCurrentSync,
			GmailBackfill: value.Capabilities.GmailBackfill, MailReviewRead: value.Capabilities.MailReviewRead,
			MailReviewWrite: value.Capabilities.MailReviewWrite,
		},
		Server: outputServer{
			Listen: value.Server.Listen, ReadHeaderTimeout: value.Server.ReadHeaderTimeout.String(), ReadTimeout: value.Server.ReadTimeout.String(),
			WriteTimeout: value.Server.WriteTimeout.String(), IdleTimeout: value.Server.IdleTimeout.String(), MaxRequestBytes: value.Server.MaxRequestBytes,
		},
		Database: outputDatabase{
			Engine: value.Database.Engine, URLEnv: value.Database.URLEnv, AuthTokenEnv: value.Database.AuthTokenEnv,
			MaxOpenConnections: value.Database.MaxOpenConnections, MaxIdleConnections: value.Database.MaxIdleConnections,
			ConnectionMaxLifetime: value.Database.ConnectionMaxLifetime.String(),
		},
		Gmail: outputGmail{
			OAuthClientIDEnv: value.Gmail.OAuthClientIDEnv, OAuthClientSecretEnv: value.Gmail.OAuthClientSecretEnv,
			OAuthRedirectURLEnv: value.Gmail.OAuthRedirectURLEnv, Scope: value.Gmail.Scope,
			PollInterval: value.Gmail.PollInterval.String(), PollJitter: value.Gmail.PollJitter.String(), PageSize: value.Gmail.PageSize,
			MaxAccountsInFlight: value.Gmail.MaxAccountsInFlight, BodyExcerptBytes: value.Gmail.BodyExcerptBytes, ThreadMaxMessages: value.Gmail.ThreadMaxMessages,
		},
		Backfill: outputBackfill{
			Enabled: value.Backfill.Enabled, DefaultLookbackDays: value.Backfill.DefaultLookbackDays,
			MaximumLookbackDays: value.Backfill.MaximumLookbackDays, PageSize: value.Backfill.PageSize,
			CurrentMailHasPriority: value.Backfill.CurrentMailHasPriority,
			RunWindow:              outputRunWindow{Timezone: value.Backfill.RunWindow.Timezone, Start: value.Backfill.RunWindow.Start, End: value.Backfill.RunWindow.End},
		},
		Gate: outputGate{
			Version: value.Gate.Version, ExcludedLabels: nonNilStrings(value.Gate.ExcludedLabels), SuppressGmailCategories: nonNilStrings(value.Gate.SuppressGmailCategories),
			DirectRecipientIsCandidate: value.Gate.DirectRecipientIsCandidate, MailingListIsBulkSignal: value.Gate.MailingListIsBulkSignal,
			SenderAllowDomains: nonNilStrings(value.Gate.SenderAllowDomains), SenderBlockDomains: nonNilStrings(value.Gate.SenderBlockDomains),
			SubjectCandidateTerms: nonNilStrings(value.Gate.SubjectCandidateTerms), SubjectUrgentTerms: nonNilStrings(value.Gate.SubjectUrgentTerms),
		},
		Review:    outputReview{DefaultPageSize: value.Review.DefaultPageSize, MaximumPageSize: value.Review.MaximumPageSize, AutomaticTaskCreation: value.Review.AutomaticTaskCreation},
		Retention: outputRetention{MetadataDays: value.Retention.MetadataDays, ExcerptDays: value.Retention.ExcerptDays, AuditDays: value.Retention.AuditDays},
		MCP: outputMCP{
			Enabled: value.MCP.Enabled, Path: value.MCP.Path, BearerTokenEnv: value.MCP.BearerTokenEnv,
			EnableReviewWrites: value.MCP.EnableReviewWrites, EnableOperatorTools: value.MCP.EnableOperatorTools,
		},
		Encryption: outputEncryption{MasterKeyEnv: value.Encryption.MasterKeyEnv},
		Logging:    outputLogging{Level: value.Logging.Level, Format: value.Logging.Format},
	}
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
