// Package accountstatusview defines the authority-free account status result model.
package accountstatusview

import "github.com/mandloideep/inboxgate/internal/config"

const OutputVersion uint64 = 1

type CursorStatus string

const (
	CursorStatusInitialized   CursorStatus = "initialized"
	CursorStatusUninitialized CursorStatus = "uninitialized"
)

type Availability string

const AvailabilityNotAvailable Availability = "not_available"

type Persistence string

const PersistenceNotPersisted Persistence = "not_persisted"

type CapabilityStatus struct {
	ImplementationStatus config.ImplementationStatus
	ConfigurationStatus  config.ConfigurationStatus
	Enabled              bool
}

type Account struct {
	AccountID             string
	Provider              string
	State                 string
	StateVersion          int64
	ReauthorizationReason *string
	RevocationStatus      string
	CursorStatus          CursorStatus

	CurrentExecutionStatus Availability
	CurrentStaleStatus     Persistence
	LastSuccessAt          *string
	LastErrorCategory      *string

	BackfillExecutionStatus  Availability
	BackfillCheckpointStatus Persistence
	BackfillProgress         *uint64
}

type Snapshot struct {
	Accounts    []Account
	CurrentSync CapabilityStatus
	Backfill    CapabilityStatus
}
