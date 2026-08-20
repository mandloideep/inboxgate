// Package reviewinspectview defines authority-free candidate inspection inputs and outputs.
package reviewinspectview

import "slices"

const (
	OutputVersion1             = 1
	MaximumCursorBytes         = 414
	MaximumInternalDateUnixMS  = int64(253402300799999)
	ContentTrustUntrustedEmail = "untrusted_email"
	UrgencyAll                 = "all"
	UrgencyStandard            = "standard"
	UrgencyUrgent              = "urgent"
)

type ListRequest struct {
	AccountIDs            []string `json:"account_ids,omitempty"`
	Urgency               string   `json:"urgency,omitempty"`
	InternalDateMinUnixMS *int64   `json:"internal_date_min_unix_ms,omitempty"`
	InternalDateMaxUnixMS *int64   `json:"internal_date_max_unix_ms,omitempty"`
	PageSize              uint64   `json:"page_size,omitempty"`
	Cursor                string   `json:"cursor,omitempty"`
}

type Candidate struct {
	AccountID              string `json:"account_id"`
	GmailThreadID          string `json:"gmail_thread_id"`
	GmailMessageID         string `json:"gmail_message_id"`
	InternalDateUnixMS     int64  `json:"internal_date_unix_ms"`
	Urgency                string `json:"urgency"`
	Outcome                string `json:"outcome"`
	SenderDisplayPreview   string `json:"sender_display_preview"`
	SenderDisplayTruncated bool   `json:"sender_display_truncated"`
	SenderAddress          string `json:"sender_address"`
	SubjectPreview         string `json:"subject_preview"`
	SubjectTruncated       bool   `json:"subject_truncated"`
	HasAttachments         bool   `json:"has_attachments"`
	ContentTrust           string `json:"content_trust"`
	Excerpt                string `json:"-"`
	ContentHash            string `json:"-"`
	SourceKind             string `json:"-"`
	FetchedAtUnixMS        int64  `json:"-"`
}

type CandidatePage struct {
	OutputVersion int         `json:"output_version"`
	Candidates    []Candidate `json:"candidates"`
	NextCursor    *string     `json:"next_cursor"`
}

func (page CandidatePage) Clone() CandidatePage {
	copyPage := page
	copyPage.Candidates = slices.Clone(page.Candidates)
	if page.NextCursor != nil {
		value := *page.NextCursor
		copyPage.NextCursor = &value
	}
	return copyPage
}

type GateReasonRequest struct {
	AccountID      string `json:"account_id"`
	GmailMessageID string `json:"gmail_message_id"`
	GmailThreadID  string `json:"-"`
}

type GateReason struct {
	OutputVersion     int      `json:"output_version"`
	AccountID         string   `json:"account_id"`
	GmailThreadID     string   `json:"gmail_thread_id"`
	GmailMessageID    string   `json:"gmail_message_id"`
	GateVersion       uint32   `json:"gate_version"`
	Outcome           string   `json:"outcome"`
	ReasonCodes       []string `json:"reason_codes"`
	EvaluatedAtUnixMS int64    `json:"evaluated_at_unix_ms"`
	SourceCurrent     bool     `json:"source_current"`
	PolicyCurrent     bool     `json:"policy_current"`
}

func (reason GateReason) Clone() GateReason {
	copyReason := reason
	copyReason.ReasonCodes = slices.Clone(reason.ReasonCodes)
	return copyReason
}
