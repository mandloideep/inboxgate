package storage

import (
	"bytes"
	"encoding/base64"
)

const (
	MaximumCredentialPlaintextBytes = 4096
	MinimumCredentialEnvelopeBytes  = 55
	MaximumCredentialEnvelopeBytes  = 5556
)

var credentialMagic = [4]byte{'I', 'G', 'C', 0}

type CredentialKeyID struct {
	value string
}

func ParseCredentialKeyID(value string) (CredentialKeyID, error) {
	if !validCredentialKeyID([]byte(value)) {
		return CredentialKeyID{}, ErrInvalidValue
	}
	return CredentialKeyID{value: value}, nil
}

func (id CredentialKeyID) String() string { return id.value }

func (id CredentialKeyID) valid() bool {
	parsed, err := ParseCredentialKeyID(id.value)
	return err == nil && parsed == id
}

type CredentialEnvelope struct {
	text  string
	keyID CredentialKeyID
}

func ParseCredentialEnvelope(text string) (CredentialEnvelope, error) {
	if len(text) < MinimumCredentialEnvelopeBytes || len(text) > MaximumCredentialEnvelopeBytes || len(text) < 5 || text[:5] != "igc1." {
		return CredentialEnvelope{}, ErrInvalidValue
	}
	encoded := text[5:]
	if !validCredentialBase64URL(encoded) {
		return CredentialEnvelope{}, ErrInvalidValue
	}
	binary, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(binary) < 7+1+12+17 {
		clear(binary)
		return CredentialEnvelope{}, ErrInvalidValue
	}
	defer clear(binary)
	if !bytes.Equal(binary[:4], credentialMagic[:]) || binary[4] != 1 || binary[5] != 1 {
		return CredentialEnvelope{}, ErrInvalidValue
	}
	keyLength := int(binary[6])
	headerLength := 7 + keyLength
	if keyLength < 1 || keyLength > 32 || headerLength+12+17 > len(binary) || len(binary)-(headerLength+12) > MaximumCredentialPlaintextBytes+16 {
		return CredentialEnvelope{}, ErrInvalidValue
	}
	keyID, err := ParseCredentialKeyID(string(binary[7:headerLength]))
	if err != nil {
		return CredentialEnvelope{}, ErrInvalidValue
	}
	return CredentialEnvelope{text: text, keyID: keyID}, nil
}

func (envelope CredentialEnvelope) String() string { return envelope.text }

func (envelope CredentialEnvelope) KeyID() CredentialKeyID { return envelope.keyID }

func (envelope CredentialEnvelope) valid() bool {
	parsed, err := ParseCredentialEnvelope(envelope.text)
	return err == nil && parsed == envelope
}

type ProviderCredential struct {
	AccountID AccountID
	KeyID     CredentialKeyID
	Envelope  CredentialEnvelope
}

type ProviderCredentialCommit struct {
	AccountID AccountID
	Expected  *CredentialEnvelope
	Next      CredentialEnvelope
}

func ValidateProviderCredentialCommit(commit ProviderCredentialCommit) error {
	if !commit.AccountID.valid() || !commit.Next.valid() || (commit.Expected != nil && !commit.Expected.valid()) {
		return ErrInvalidValue
	}
	return nil
}

func validCredentialKeyID(value []byte) bool {
	if len(value) < 1 || len(value) > 32 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func validCredentialBase64URL(value string) bool {
	if value == "" {
		return false
	}
	for index := range value {
		character := value[index]
		if (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}
