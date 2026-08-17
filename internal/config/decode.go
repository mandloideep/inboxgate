package config

import "go.yaml.in/yaml/v3"

func decodeCapabilities(node *yaml.Node, target *Capabilities, problems *[]Problem) {
	values := mappingValues(node)
	if child := values["gmail.read"]; child != nil {
		target.GmailRead = readBool(child, "capabilities.gmail.read", problems)
	}
	if child := values["gmail.current_sync"]; child != nil {
		target.GmailCurrentSync = readBool(child, "capabilities.gmail.current_sync", problems)
	}
	if child := values["gmail.backfill"]; child != nil {
		target.GmailBackfill = readBool(child, "capabilities.gmail.backfill", problems)
	}
	if child := values["mail.review_read"]; child != nil {
		target.MailReviewRead = readBool(child, "capabilities.mail.review_read", problems)
	}
	if child := values["mail.review_write"]; child != nil {
		target.MailReviewWrite = readBool(child, "capabilities.mail.review_write", problems)
	}
}

func decodeServer(node *yaml.Node, target *Server, problems *[]Problem) {
	v := mappingValues(node)
	if n := v["listen"]; n != nil {
		target.Listen = readString(n, "server.listen", problems)
	}
	if n := v["read_header_timeout"]; n != nil {
		target.ReadHeaderTimeout = readDuration(n, "server.read_header_timeout", problems)
	}
	if n := v["read_timeout"]; n != nil {
		target.ReadTimeout = readDuration(n, "server.read_timeout", problems)
	}
	if n := v["write_timeout"]; n != nil {
		target.WriteTimeout = readDuration(n, "server.write_timeout", problems)
	}
	if n := v["idle_timeout"]; n != nil {
		target.IdleTimeout = readDuration(n, "server.idle_timeout", problems)
	}
	if n := v["max_request_bytes"]; n != nil {
		target.MaxRequestBytes = readUint(n, "server.max_request_bytes", problems)
	}
}

func decodeDatabase(node *yaml.Node, target *Database, problems *[]Problem) {
	v := mappingValues(node)
	if n := v["engine"]; n != nil {
		target.Engine = readString(n, "database.engine", problems)
	}
	if n := v["url_env"]; n != nil {
		target.URLEnv = readString(n, "database.url_env", problems)
	}
	if n := v["auth_token_env"]; n != nil {
		target.AuthTokenEnv = readString(n, "database.auth_token_env", problems)
	}
	if n := v["max_open_connections"]; n != nil {
		target.MaxOpenConnections = readUint(n, "database.max_open_connections", problems)
	}
	if n := v["max_idle_connections"]; n != nil {
		target.MaxIdleConnections = readUint(n, "database.max_idle_connections", problems)
	}
	if n := v["connection_max_lifetime"]; n != nil {
		target.ConnectionMaxLifetime = readDuration(n, "database.connection_max_lifetime", problems)
	}
}

func decodeGmail(node *yaml.Node, target *Gmail, problems *[]Problem) {
	v := mappingValues(node)
	if n := v["oauth_client_id_env"]; n != nil {
		target.OAuthClientIDEnv = readString(n, "gmail.oauth_client_id_env", problems)
	}
	if n := v["oauth_client_secret_env"]; n != nil {
		target.OAuthClientSecretEnv = readString(n, "gmail.oauth_client_secret_env", problems)
	}
	if n := v["oauth_redirect_url_env"]; n != nil {
		target.OAuthRedirectURLEnv = readString(n, "gmail.oauth_redirect_url_env", problems)
	}
	if n := v["scope"]; n != nil {
		target.Scope = readString(n, "gmail.scope", problems)
	}
	if n := v["poll_interval"]; n != nil {
		target.PollInterval = readDuration(n, "gmail.poll_interval", problems)
	}
	if n := v["poll_jitter"]; n != nil {
		target.PollJitter = readDuration(n, "gmail.poll_jitter", problems)
	}
	if n := v["page_size"]; n != nil {
		target.PageSize = readUint(n, "gmail.page_size", problems)
	}
	if n := v["max_accounts_in_flight"]; n != nil {
		target.MaxAccountsInFlight = readUint(n, "gmail.max_accounts_in_flight", problems)
	}
	if n := v["body_excerpt_bytes"]; n != nil {
		target.BodyExcerptBytes = readUint(n, "gmail.body_excerpt_bytes", problems)
	}
	if n := v["thread_max_messages"]; n != nil {
		target.ThreadMaxMessages = readUint(n, "gmail.thread_max_messages", problems)
	}
}

func decodeBackfill(node *yaml.Node, target *Backfill, problems *[]Problem) {
	v := mappingValues(node)
	if n := v["enabled"]; n != nil {
		target.Enabled = readBool(n, "backfill.enabled", problems)
	}
	if n := v["default_lookback_days"]; n != nil {
		target.DefaultLookbackDays = readUint(n, "backfill.default_lookback_days", problems)
	}
	if n := v["maximum_lookback_days"]; n != nil {
		target.MaximumLookbackDays = readUint(n, "backfill.maximum_lookback_days", problems)
	}
	if n := v["page_size"]; n != nil {
		target.PageSize = readUint(n, "backfill.page_size", problems)
	}
	if n := v["current_mail_has_priority"]; n != nil {
		target.CurrentMailHasPriority = readBool(n, "backfill.current_mail_has_priority", problems)
	}
	if n := v["run_window"]; n != nil {
		w := mappingValues(n)
		if field := w["timezone"]; field != nil {
			target.RunWindow.Timezone = readString(field, "backfill.run_window.timezone", problems)
		}
		if field := w["start"]; field != nil {
			target.RunWindow.Start = readString(field, "backfill.run_window.start", problems)
		}
		if field := w["end"]; field != nil {
			target.RunWindow.End = readString(field, "backfill.run_window.end", problems)
		}
	}
}

func decodeGate(node *yaml.Node, target *Gate, problems *[]Problem) {
	v := mappingValues(node)
	if n := v["version"]; n != nil {
		target.Version = readUint(n, "gate.version", problems)
	}
	if n := v["excluded_labels"]; n != nil {
		target.ExcludedLabels = readStrings(n, "gate.excluded_labels", problems)
	}
	if n := v["suppress_gmail_categories"]; n != nil {
		target.SuppressGmailCategories = readStrings(n, "gate.suppress_gmail_categories", problems)
	}
	if n := v["direct_recipient_is_candidate"]; n != nil {
		target.DirectRecipientIsCandidate = readBool(n, "gate.direct_recipient_is_candidate", problems)
	}
	if n := v["mailing_list_is_bulk_signal"]; n != nil {
		target.MailingListIsBulkSignal = readBool(n, "gate.mailing_list_is_bulk_signal", problems)
	}
	if n := v["sender_allow_domains"]; n != nil {
		target.SenderAllowDomains = readStrings(n, "gate.sender_allow_domains", problems)
	}
	if n := v["sender_block_domains"]; n != nil {
		target.SenderBlockDomains = readStrings(n, "gate.sender_block_domains", problems)
	}
	if n := v["subject_candidate_terms"]; n != nil {
		target.SubjectCandidateTerms = readStrings(n, "gate.subject_candidate_terms", problems)
	}
	if n := v["subject_urgent_terms"]; n != nil {
		target.SubjectUrgentTerms = readStrings(n, "gate.subject_urgent_terms", problems)
	}
}

func decodeReview(node *yaml.Node, target *Review, problems *[]Problem) {
	v := mappingValues(node)
	if n := v["default_page_size"]; n != nil {
		target.DefaultPageSize = readUint(n, "review.default_page_size", problems)
	}
	if n := v["maximum_page_size"]; n != nil {
		target.MaximumPageSize = readUint(n, "review.maximum_page_size", problems)
	}
	if n := v["automatic_task_creation"]; n != nil {
		target.AutomaticTaskCreation = readBool(n, "review.automatic_task_creation", problems)
	}
}

func decodeRetention(node *yaml.Node, target *Retention, problems *[]Problem) {
	v := mappingValues(node)
	if n := v["metadata_days"]; n != nil {
		target.MetadataDays = readUint(n, "retention.metadata_days", problems)
	}
	if n := v["excerpt_days"]; n != nil {
		target.ExcerptDays = readUint(n, "retention.excerpt_days", problems)
	}
	if n := v["audit_days"]; n != nil {
		target.AuditDays = readUint(n, "retention.audit_days", problems)
	}
}

func decodeMCP(node *yaml.Node, target *MCP, problems *[]Problem) {
	v := mappingValues(node)
	if n := v["enabled"]; n != nil {
		target.Enabled = readBool(n, "mcp.enabled", problems)
	}
	if n := v["path"]; n != nil {
		target.Path = readString(n, "mcp.path", problems)
	}
	if n := v["bearer_token_env"]; n != nil {
		target.BearerTokenEnv = readString(n, "mcp.bearer_token_env", problems)
	}
	if n := v["enable_review_writes"]; n != nil {
		target.EnableReviewWrites = readBool(n, "mcp.enable_review_writes", problems)
	}
	if n := v["enable_operator_tools"]; n != nil {
		target.EnableOperatorTools = readBool(n, "mcp.enable_operator_tools", problems)
	}
}

func decodeEncryption(node *yaml.Node, target *Encryption, problems *[]Problem) {
	if n := mappingValues(node)["master_key_env"]; n != nil {
		target.MasterKeyEnv = readString(n, "encryption.master_key_env", problems)
	}
}

func decodeLogging(node *yaml.Node, target *Logging, problems *[]Problem) {
	v := mappingValues(node)
	if n := v["level"]; n != nil {
		target.Level = readString(n, "logging.level", problems)
	}
	if n := v["format"]; n != nil {
		target.Format = readString(n, "logging.format", problems)
	}
}
