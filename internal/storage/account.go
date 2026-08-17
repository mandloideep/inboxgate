package storage

import (
	"errors"
	"strconv"
	"strings"
)

const ProviderGmail = "gmail"

var (
	ErrInvalidValue          = errors.New("storage: invalid value")
	ErrAccountConflict       = errors.New("storage: account conflict")
	ErrAccountNotFound       = errors.New("storage: account not found")
	ErrCursorNotFound        = errors.New("storage: synchronization cursor not found")
	ErrCursorConflict        = errors.New("storage: synchronization cursor conflict")
	ErrCursorRegression      = errors.New("storage: synchronization cursor regression")
	ErrPersistenceAcquire    = errors.New("storage: persistence connection failed")
	ErrPersistenceInspect    = errors.New("storage: persistence inspection failed")
	ErrPersistenceUnknown    = errors.New("storage: persistence outcome unknown")
	ErrPersistenceNotAllowed = errors.New("storage: persistence not allowed")
)

// AccountID is a validated opaque 128-bit identifier encoded as lowercase hex.
type AccountID struct {
	value string
}

func ParseAccountID(value string) (AccountID, error) {
	if len(value) != 32 || strings.IndexFunc(value, func(r rune) bool {
		return !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f')
	}) >= 0 {
		return AccountID{}, ErrInvalidValue
	}
	return AccountID{value: value}, nil
}

func (id AccountID) String() string { return id.value }

func (id AccountID) valid() bool {
	_, err := ParseAccountID(id.value)
	return err == nil
}

// ProviderSubject is a validated opaque Gmail profile subject.
type ProviderSubject struct {
	value string
}

func ParseProviderSubject(value string) (ProviderSubject, error) {
	if len(value) == 0 || len(value) > 255 || strings.IndexFunc(value, func(r rune) bool {
		return r < 0x21 || r > 0x7e
	}) >= 0 {
		return ProviderSubject{}, ErrInvalidValue
	}
	return ProviderSubject{value: value}, nil
}

func (subject ProviderSubject) String() string { return subject.value }

func (subject ProviderSubject) valid() bool {
	_, err := ParseProviderSubject(subject.value)
	return err == nil
}

// HistoryID is a canonical positive uint64 encoded as decimal text.
type HistoryID struct {
	text  string
	value uint64
}

func ParseHistoryID(text string) (HistoryID, error) {
	if len(text) == 0 || len(text) > 20 || text[0] == '0' || strings.IndexFunc(text, func(r rune) bool {
		return r < '0' || r > '9'
	}) >= 0 {
		return HistoryID{}, ErrInvalidValue
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil || value == 0 || strconv.FormatUint(value, 10) != text {
		return HistoryID{}, ErrInvalidValue
	}
	return HistoryID{text: text, value: value}, nil
}

func (id HistoryID) String() string { return id.text }

func (id HistoryID) valid() bool {
	parsed, err := ParseHistoryID(id.text)
	return err == nil && parsed.value == id.value
}

func (id HistoryID) Compare(other HistoryID) int {
	switch {
	case id.value < other.value:
		return -1
	case id.value > other.value:
		return 1
	default:
		return 0
	}
}

type AccountSeed struct {
	ID              AccountID
	ProviderSubject ProviderSubject
}

type Account struct {
	ID              AccountID
	ProviderSubject ProviderSubject
}

type SynchronizationCursor struct {
	AccountID AccountID
	HistoryID HistoryID
}

type SynchronizationCommit struct {
	AccountID AccountID
	Expected  *HistoryID
	Next      HistoryID
}

func ValidateAccountSeed(seed AccountSeed) error {
	if !seed.ID.valid() || !seed.ProviderSubject.valid() {
		return ErrInvalidValue
	}
	return nil
}

func ValidateSynchronizationCommit(commit SynchronizationCommit) error {
	if !commit.AccountID.valid() || !commit.Next.valid() || (commit.Expected != nil && !commit.Expected.valid()) {
		return ErrInvalidValue
	}
	return nil
}
