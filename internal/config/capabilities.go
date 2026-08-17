package config

import (
	"encoding/json"
	"fmt"
	"sort"
)

type CapabilityName string

const (
	CapabilityGmailBackfill      CapabilityName = "gmail.backfill"
	CapabilityGmailCurrentSync   CapabilityName = "gmail.current_sync"
	CapabilityGmailModify        CapabilityName = "gmail.modify"
	CapabilityGmailRead          CapabilityName = "gmail.read"
	CapabilityMailReviewRead     CapabilityName = "mail.review_read"
	CapabilityMailReviewWrite    CapabilityName = "mail.review_write"
	CapabilitySystemCapabilities CapabilityName = "system.capabilities"
	CapabilityVikunjaWrite       CapabilityName = "vikunja.write"
	CapabilityZohoRead           CapabilityName = "zoho.read"
)

type ImplementationStatus string

const (
	ImplementationStatusImplemented    ImplementationStatus = "implemented"
	ImplementationStatusNotImplemented ImplementationStatus = "not_implemented"
)

type ConfigurationStatus string

const (
	ConfigurationStatusEnabled         ConfigurationStatus = "enabled"
	ConfigurationStatusDisabled        ConfigurationStatus = "disabled"
	ConfigurationStatusNotConfigurable ConfigurationStatus = "not_configurable"
)

type SecurityClassification string

const (
	SecurityOperationalMetadata SecurityClassification = "operational_metadata"
	SecuritySensitiveRead       SecurityClassification = "sensitive_read"
	SecuritySensitiveWrite      SecurityClassification = "sensitive_write"
	SecurityProhibited          SecurityClassification = "prohibited"
)

type Capability struct {
	Name                      CapabilityName         `json:"name"`
	ImplementationStatus      ImplementationStatus   `json:"implementation_status"`
	ConfigurationStatus       ConfigurationStatus    `json:"configuration_status"`
	Enabled                   bool                   `json:"enabled"`
	RequiredSecretNames       []string               `json:"required_secret_names"`
	RequiredDatabaseMigration *string                `json:"required_database_migration"`
	SecurityClassification    SecurityClassification `json:"security_classification"`
}

type capabilityConfigBinding uint8

const (
	capabilityConfigNone capabilityConfigBinding = iota
	capabilityConfigGmailBackfill
	capabilityConfigGmailCurrentSync
	capabilityConfigGmailRead
	capabilityConfigMailReviewRead
	capabilityConfigMailReviewWrite
)

type capabilityPrerequisites uint8

const (
	capabilityPrerequisitesNone capabilityPrerequisites = iota
	capabilityPrerequisitesGmail
	capabilityPrerequisitesDatabase
)

type capabilityDefinition struct {
	Name                   CapabilityName
	ConfigBinding          capabilityConfigBinding
	ImplementationStatus   ImplementationStatus
	Prerequisites          capabilityPrerequisites
	SecurityClassification SecurityClassification
}

var capabilityDefinitions = []capabilityDefinition{
	{Name: CapabilityGmailBackfill, ConfigBinding: capabilityConfigGmailBackfill, ImplementationStatus: ImplementationStatusNotImplemented, Prerequisites: capabilityPrerequisitesGmail, SecurityClassification: SecuritySensitiveRead},
	{Name: CapabilityGmailCurrentSync, ConfigBinding: capabilityConfigGmailCurrentSync, ImplementationStatus: ImplementationStatusNotImplemented, Prerequisites: capabilityPrerequisitesGmail, SecurityClassification: SecuritySensitiveRead},
	{Name: CapabilityGmailModify, ConfigBinding: capabilityConfigNone, ImplementationStatus: ImplementationStatusNotImplemented, Prerequisites: capabilityPrerequisitesNone, SecurityClassification: SecurityProhibited},
	{Name: CapabilityGmailRead, ConfigBinding: capabilityConfigGmailRead, ImplementationStatus: ImplementationStatusNotImplemented, Prerequisites: capabilityPrerequisitesGmail, SecurityClassification: SecuritySensitiveRead},
	{Name: CapabilityMailReviewRead, ConfigBinding: capabilityConfigMailReviewRead, ImplementationStatus: ImplementationStatusNotImplemented, Prerequisites: capabilityPrerequisitesDatabase, SecurityClassification: SecuritySensitiveRead},
	{Name: CapabilityMailReviewWrite, ConfigBinding: capabilityConfigMailReviewWrite, ImplementationStatus: ImplementationStatusNotImplemented, Prerequisites: capabilityPrerequisitesDatabase, SecurityClassification: SecuritySensitiveWrite},
	{Name: CapabilitySystemCapabilities, ConfigBinding: capabilityConfigNone, ImplementationStatus: ImplementationStatusImplemented, Prerequisites: capabilityPrerequisitesNone, SecurityClassification: SecurityOperationalMetadata},
	{Name: CapabilityVikunjaWrite, ConfigBinding: capabilityConfigNone, ImplementationStatus: ImplementationStatusNotImplemented, Prerequisites: capabilityPrerequisitesNone, SecurityClassification: SecuritySensitiveWrite},
	{Name: CapabilityZohoRead, ConfigBinding: capabilityConfigNone, ImplementationStatus: ImplementationStatusNotImplemented, Prerequisites: capabilityPrerequisitesNone, SecurityClassification: SecuritySensitiveRead},
}

type capabilityEnvelope struct {
	OutputVersion              uint64       `json:"output_version"`
	ConfigurationSchemaVersion uint64       `json:"configuration_schema_version"`
	Capabilities               []Capability `json:"capabilities"`
}

func CapabilityRegistry(configuration Config) []Capability {
	return capabilityRegistryFromDefinitions(configuration, capabilityDefinitions)
}

func capabilityRegistryFromDefinitions(configuration Config, definitions []capabilityDefinition) []Capability {
	registry := make([]Capability, 0, len(definitions))
	for _, definition := range definitions {
		configurationStatus := configurationStatus(configuration, definition.ConfigBinding)
		enabled := definition.ImplementationStatus == ImplementationStatusImplemented && (configurationStatus == ConfigurationStatusEnabled || configurationStatus == ConfigurationStatusNotConfigurable)
		registry = append(registry, Capability{
			Name: definition.Name, ImplementationStatus: definition.ImplementationStatus, ConfigurationStatus: configurationStatus, Enabled: enabled,
			RequiredSecretNames: requiredSecretNames(configuration, definition.Prerequisites), RequiredDatabaseMigration: nil,
			SecurityClassification: definition.SecurityClassification,
		})
	}
	return registry
}

func configurationStatus(configuration Config, binding capabilityConfigBinding) ConfigurationStatus {
	if binding == capabilityConfigNone {
		return ConfigurationStatusNotConfigurable
	}
	enabled := capabilityConfigured(configuration.Capabilities, binding)
	if enabled {
		return ConfigurationStatusEnabled
	}
	return ConfigurationStatusDisabled
}

func capabilityConfigured(configuration Capabilities, binding capabilityConfigBinding) bool {
	switch binding {
	case capabilityConfigGmailBackfill:
		return configuration.GmailBackfill
	case capabilityConfigGmailCurrentSync:
		return configuration.GmailCurrentSync
	case capabilityConfigGmailRead:
		return configuration.GmailRead
	case capabilityConfigMailReviewRead:
		return configuration.MailReviewRead
	case capabilityConfigMailReviewWrite:
		return configuration.MailReviewWrite
	default:
		return false
	}
}

func requiredSecretNames(configuration Config, prerequisites capabilityPrerequisites) []string {
	switch prerequisites {
	case capabilityPrerequisitesGmail:
		return sortedSecretNames(
			configuration.Database.AuthTokenEnv,
			configuration.Database.URLEnv,
			configuration.Encryption.MasterKeyEnv,
			configuration.Gmail.OAuthClientIDEnv,
			configuration.Gmail.OAuthClientSecretEnv,
			configuration.Gmail.OAuthRedirectURLEnv,
		)
	case capabilityPrerequisitesDatabase:
		return sortedSecretNames(configuration.Database.AuthTokenEnv, configuration.Database.URLEnv)
	default:
		return []string{}
	}
}

func validateCapabilityDefinitions(configuration Config, definitions []capabilityDefinition, problems *[]Problem) {
	for _, definition := range definitions {
		if definition.ConfigBinding != capabilityConfigNone && capabilityConfigured(configuration.Capabilities, definition.ConfigBinding) && definition.ImplementationStatus != ImplementationStatusImplemented {
			problem(problems, "capabilities."+string(definition.Name), "cannot enable a capability not implemented by this binary")
		}
	}
}

func sortedSecretNames(values ...string) []string {
	result := append([]string{}, values...)
	sort.Strings(result)
	return result
}

func CapabilitiesJSON(configuration Config) ([]byte, error) {
	payload := capabilityEnvelope{OutputVersion: 1, ConfigurationSchemaVersion: configuration.Version, Capabilities: CapabilityRegistry(configuration)}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal capabilities: %w", err)
	}
	return append(data, '\n'), nil
}
