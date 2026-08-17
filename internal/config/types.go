// Package config parses and validates InboxGate configuration schema v1.
package config

import "time"

const (
	MaxFileBytes = 65_536
	MaxNodes     = 4_096
	MaxDepth     = 8
)

type Config struct {
	Version    uint64
	Server     Server
	Database   Database
	Gmail      Gmail
	Backfill   Backfill
	Gate       Gate
	Review     Review
	Retention  Retention
	MCP        MCP
	Encryption Encryption
	Logging    Logging
}

type Server struct {
	Listen            string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxRequestBytes   uint64
}

type Database struct {
	Engine                string
	URLEnv                string
	AuthTokenEnv          string
	MaxOpenConnections    uint64
	MaxIdleConnections    uint64
	ConnectionMaxLifetime time.Duration
}

type Gmail struct {
	OAuthClientIDEnv     string
	OAuthClientSecretEnv string
	OAuthRedirectURLEnv  string
	Scope                string
	PollInterval         time.Duration
	PollJitter           time.Duration
	PageSize             uint64
	MaxAccountsInFlight  uint64
	BodyExcerptBytes     uint64
	ThreadMaxMessages    uint64
}

type Backfill struct {
	Enabled                bool
	DefaultLookbackDays    uint64
	MaximumLookbackDays    uint64
	PageSize               uint64
	CurrentMailHasPriority bool
	RunWindow              RunWindow
}

type RunWindow struct {
	Timezone string
	Start    string
	End      string
}

type Gate struct {
	Version                    uint64
	ExcludedLabels             []string
	SuppressGmailCategories    []string
	DirectRecipientIsCandidate bool
	MailingListIsBulkSignal    bool
	SenderAllowDomains         []string
	SenderBlockDomains         []string
	SubjectCandidateTerms      []string
	SubjectUrgentTerms         []string
}

type Review struct {
	DefaultPageSize       uint64
	MaximumPageSize       uint64
	AutomaticTaskCreation bool
}

type Retention struct {
	MetadataDays uint64
	ExcerptDays  uint64
	AuditDays    uint64
}

type MCP struct {
	Enabled             bool
	Path                string
	BearerTokenEnv      string
	EnableReviewWrites  bool
	EnableOperatorTools bool
}

type Encryption struct {
	MasterKeyEnv string
}

type Logging struct {
	Level  string
	Format string
}

func Defaults() Config {
	return Config{
		Version:    1,
		Server:     Server{Listen: "0.0.0.0:8080", ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxRequestBytes: 1_048_576},
		Database:   Database{Engine: "turso", URLEnv: "TURSO_DATABASE_URL", AuthTokenEnv: "TURSO_AUTH_TOKEN", MaxOpenConnections: 8, MaxIdleConnections: 2, ConnectionMaxLifetime: 30 * time.Minute},
		Gmail:      Gmail{OAuthClientIDEnv: "GOOGLE_OAUTH_CLIENT_ID", OAuthClientSecretEnv: "GOOGLE_OAUTH_CLIENT_SECRET", OAuthRedirectURLEnv: "GOOGLE_OAUTH_REDIRECT_URL", Scope: "gmail.readonly", PollInterval: 5 * time.Minute, PollJitter: 30 * time.Second, PageSize: 100, MaxAccountsInFlight: 2, BodyExcerptBytes: 32_768, ThreadMaxMessages: 50},
		Backfill:   Backfill{Enabled: true, DefaultLookbackDays: 365, MaximumLookbackDays: 3_650, PageSize: 100, CurrentMailHasPriority: true, RunWindow: RunWindow{Timezone: "America/Chicago", Start: "22:00", End: "06:00"}},
		Gate:       Gate{Version: 1, ExcludedLabels: []string{"SPAM", "TRASH"}, SuppressGmailCategories: []string{"CATEGORY_PROMOTIONS", "CATEGORY_SOCIAL"}, DirectRecipientIsCandidate: true, MailingListIsBulkSignal: true, SenderAllowDomains: []string{}, SenderBlockDomains: []string{}, SubjectCandidateTerms: []string{}, SubjectUrgentTerms: []string{}},
		Review:     Review{DefaultPageSize: 25, MaximumPageSize: 100, AutomaticTaskCreation: false},
		Retention:  Retention{MetadataDays: 0, ExcerptDays: 365, AuditDays: 730},
		MCP:        MCP{Enabled: true, Path: "/mcp", BearerTokenEnv: "INBOXGATE_MCP_TOKEN", EnableReviewWrites: true, EnableOperatorTools: false},
		Encryption: Encryption{MasterKeyEnv: "INBOXGATE_MASTER_KEY"},
		Logging:    Logging{Level: "info", Format: "json"},
	}
}
