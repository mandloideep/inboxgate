// Package cryptobox provides the fixed InboxGate Gmail refresh-token
// encryption format without resolving secrets or activating runtime behavior.
package cryptobox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"slices"
	"sync"
)

const (
	KeyBytes                   = 32
	NonceBytes                 = 12
	AuthenticationTagBytes     = 16
	MinimumPlaintextBytes      = 1
	MaximumPlaintextBytes      = 4096
	MaximumKeyringBytes        = 620
	MinimumEnvelopeTextBytes   = 55
	MaximumEnvelopeTextBytes   = 5556
	maximumKeyringEntries      = 8
	maximumKeyIDBytes          = 32
	keyringPrefix              = "igk1:"
	envelopePrefix             = "igc1."
	envelopeFixedHeaderBytes   = 7
	envelopeFormatVersion      = 1
	envelopeAlgorithmAES256GCM = 1
)

var (
	ErrInvalidKeyring   = errors.New("cryptobox: invalid keyring")
	ErrClosedKeyring    = errors.New("cryptobox: closed keyring")
	ErrInvalidBinding   = errors.New("cryptobox: invalid binding")
	ErrInvalidPlaintext = errors.New("cryptobox: invalid plaintext")
	ErrInvalidEnvelope  = errors.New("cryptobox: invalid envelope")
	ErrUnknownKey       = errors.New("cryptobox: unknown key")
	ErrAuthentication   = errors.New("cryptobox: authentication failed")
	ErrRandomSource     = errors.New("cryptobox: random source failed")
)

var envelopeMagic = [4]byte{'I', 'G', 'C', 0}

type Keyring struct {
	mu       sync.RWMutex
	activeID string
	order    []string
	keys     map[string]*[KeyBytes]byte
	random   io.Reader
	closed   bool
}

func ParseKeyring(encoded []byte) (*Keyring, error) {
	if len(encoded) < len(keyringPrefix)+1 || len(encoded) > MaximumKeyringBytes || !bytes.HasPrefix(encoded, []byte(keyringPrefix)) {
		return nil, ErrInvalidKeyring
	}
	entries := bytes.Split(encoded[len(keyringPrefix):], []byte{','})
	if len(entries) < 1 || len(entries) > maximumKeyringEntries {
		return nil, ErrInvalidKeyring
	}
	ring := &Keyring{keys: make(map[string]*[KeyBytes]byte, len(entries)), random: rand.Reader}
	previousDecryptID := ""
	for index, entry := range entries {
		separator := bytes.IndexByte(entry, '=')
		if separator < 1 || separator != bytes.LastIndexByte(entry, '=') {
			ring.destroy()
			return nil, ErrInvalidKeyring
		}
		idBytes := entry[:separator]
		keyText := entry[separator+1:]
		if !validKeyID(idBytes) || len(keyText) != 43 {
			ring.destroy()
			return nil, ErrInvalidKeyring
		}
		id := string(idBytes)
		if _, duplicate := ring.keys[id]; duplicate || (index > 1 && id <= previousDecryptID) {
			ring.destroy()
			return nil, ErrInvalidKeyring
		}
		decoded := make([]byte, KeyBytes)
		decodedBytes, err := base64.RawURLEncoding.Strict().Decode(decoded, keyText)
		if err != nil || decodedBytes != KeyBytes {
			clear(decoded)
			ring.destroy()
			return nil, ErrInvalidKeyring
		}
		owned := new([KeyBytes]byte)
		copy(owned[:], decoded)
		clear(decoded)
		duplicateKey := false
		for _, existing := range ring.keys {
			if subtle.ConstantTimeCompare(existing[:], owned[:]) == 1 {
				duplicateKey = true
				break
			}
		}
		if duplicateKey {
			clear(owned[:])
			ring.destroy()
			return nil, ErrInvalidKeyring
		}
		ring.keys[id] = owned
		ring.order = append(ring.order, id)
		if index == 0 {
			ring.activeID = id
		} else {
			previousDecryptID = id
		}
	}
	canonical, err := ring.encodeLocked()
	if err != nil || !bytes.Equal(canonical, encoded) {
		clear(canonical)
		ring.destroy()
		return nil, ErrInvalidKeyring
	}
	clear(canonical)
	return ring, nil
}

func (k *Keyring) Encode() ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.encodeLocked()
}

func (k *Keyring) encodeLocked() ([]byte, error) {
	if k.closed {
		return nil, ErrClosedKeyring
	}
	result := make([]byte, 0, MaximumKeyringBytes)
	result = append(result, keyringPrefix...)
	for index, id := range k.order {
		if index > 0 {
			result = append(result, ',')
		}
		result = append(result, id...)
		result = append(result, '=')
		result = base64.RawURLEncoding.AppendEncode(result, k.keys[id][:])
	}
	return result, nil
}

func (k *Keyring) EncryptRefreshToken(accountID string, plaintext []byte) (string, error) {
	if !validAccountID(accountID) {
		return "", ErrInvalidBinding
	}
	if len(plaintext) < MinimumPlaintextBytes || len(plaintext) > MaximumPlaintextBytes {
		return "", ErrInvalidPlaintext
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return "", ErrClosedKeyring
	}
	key := k.keys[k.activeID]
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", ErrInvalidKeyring
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || aead.NonceSize() != NonceBytes || aead.Overhead() != AuthenticationTagBytes {
		return "", ErrInvalidKeyring
	}
	header := envelopeHeader(k.activeID)
	nonce := make([]byte, NonceBytes)
	if _, err := io.ReadFull(k.random, nonce); err != nil {
		clear(nonce)
		return "", ErrRandomSource
	}
	aad := associatedData(header, accountID)
	sealed := aead.Seal(nil, nonce, plaintext, aad)
	binary := make([]byte, 0, len(header)+len(nonce)+len(sealed))
	binary = append(binary, header...)
	binary = append(binary, nonce...)
	binary = append(binary, sealed...)
	encoded := envelopePrefix + base64.RawURLEncoding.EncodeToString(binary)
	clear(aad)
	clear(nonce)
	clear(sealed)
	clear(binary)
	return encoded, nil
}

func (k *Keyring) DecryptRefreshToken(accountID, envelope string) ([]byte, error) {
	if !validAccountID(accountID) {
		return nil, ErrInvalidBinding
	}
	parsed, err := parseEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	defer clear(parsed.binary)
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.closed {
		return nil, ErrClosedKeyring
	}
	key, ok := k.keys[parsed.keyID]
	if !ok {
		return nil, ErrUnknownKey
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, ErrInvalidKeyring
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidKeyring
	}
	aad := associatedData(parsed.header, accountID)
	plaintext, err := aead.Open(nil, parsed.nonce, parsed.sealed, aad)
	clear(aad)
	if err != nil {
		return nil, ErrAuthentication
	}
	if len(plaintext) < MinimumPlaintextBytes || len(plaintext) > MaximumPlaintextBytes {
		clear(plaintext)
		return nil, ErrInvalidEnvelope
	}
	return plaintext, nil
}

func (k *Keyring) RotateRefreshToken(accountID, envelope string) (string, bool, error) {
	parsed, err := parseEnvelope(envelope)
	if err != nil {
		return "", false, err
	}
	keyID := parsed.keyID
	clear(parsed.binary)
	plaintext, err := k.DecryptRefreshToken(accountID, envelope)
	if err != nil {
		return "", false, err
	}
	defer clear(plaintext)
	k.mu.RLock()
	if k.closed {
		k.mu.RUnlock()
		return "", false, ErrClosedKeyring
	}
	active := k.activeID
	k.mu.RUnlock()
	if keyID == active {
		return envelope, false, nil
	}
	rotated, err := k.EncryptRefreshToken(accountID, plaintext)
	if err != nil {
		return "", false, err
	}
	return rotated, true, nil
}

func (k *Keyring) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return ErrClosedKeyring
	}
	k.destroy()
	k.closed = true
	return nil
}

func (k *Keyring) destroy() {
	for _, key := range k.keys {
		clear(key[:])
	}
}

type parsedEnvelope struct {
	binary []byte
	header []byte
	keyID  string
	nonce  []byte
	sealed []byte
}

func parseEnvelope(text string) (parsedEnvelope, error) {
	if len(text) < MinimumEnvelopeTextBytes || len(text) > MaximumEnvelopeTextBytes || len(text) < len(envelopePrefix) || text[:len(envelopePrefix)] != envelopePrefix {
		return parsedEnvelope{}, ErrInvalidEnvelope
	}
	encoded := text[len(envelopePrefix):]
	if !validBase64URLText(encoded) {
		return parsedEnvelope{}, ErrInvalidEnvelope
	}
	binary, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(binary) < envelopeFixedHeaderBytes+1+NonceBytes+MinimumPlaintextBytes+AuthenticationTagBytes {
		clear(binary)
		return parsedEnvelope{}, ErrInvalidEnvelope
	}
	if !bytes.Equal(binary[:4], envelopeMagic[:]) || binary[4] != envelopeFormatVersion || binary[5] != envelopeAlgorithmAES256GCM {
		clear(binary)
		return parsedEnvelope{}, ErrInvalidEnvelope
	}
	keyIDLength := int(binary[6])
	headerLength := envelopeFixedHeaderBytes + keyIDLength
	if keyIDLength < 1 || keyIDLength > maximumKeyIDBytes || headerLength+NonceBytes+MinimumPlaintextBytes+AuthenticationTagBytes > len(binary) || !validKeyID(binary[7:headerLength]) {
		clear(binary)
		return parsedEnvelope{}, ErrInvalidEnvelope
	}
	sealed := binary[headerLength+NonceBytes:]
	if len(sealed) < MinimumPlaintextBytes+AuthenticationTagBytes || len(sealed) > MaximumPlaintextBytes+AuthenticationTagBytes {
		clear(binary)
		return parsedEnvelope{}, ErrInvalidEnvelope
	}
	return parsedEnvelope{
		binary: binary,
		header: binary[:headerLength],
		keyID:  string(binary[7:headerLength]),
		nonce:  binary[headerLength : headerLength+NonceBytes],
		sealed: sealed,
	}, nil
}

func envelopeHeader(keyID string) []byte {
	header := make([]byte, 0, envelopeFixedHeaderBytes+len(keyID))
	header = append(header, envelopeMagic[:]...)
	header = append(header, envelopeFormatVersion, envelopeAlgorithmAES256GCM, byte(len(keyID)))
	header = append(header, keyID...)
	return header
}

func associatedData(header []byte, accountID string) []byte {
	aad := slices.Clone(header)
	aad = append(aad, 0)
	aad = append(aad, "gmail"...)
	aad = append(aad, 0)
	aad = append(aad, "oauth_refresh_token"...)
	aad = append(aad, 0)
	aad = append(aad, accountID...)
	return aad
}

func validKeyID(value []byte) bool {
	if len(value) < 1 || len(value) > maximumKeyIDBytes || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func validAccountID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for index := range value {
		if (value[index] < '0' || value[index] > '9') && (value[index] < 'a' || value[index] > 'f') {
			return false
		}
	}
	return true
}

func validBase64URLText(value string) bool {
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
