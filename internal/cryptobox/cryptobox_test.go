package cryptobox

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
)

const testAccountA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testAccountB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestKeyringCanonicalGrammarAndBounds(t *testing.T) {
	canonical := canonicalKeyring("active", 1, "old-a", 2, "old_z", 3)
	ring, err := ParseKeyring([]byte(canonical))
	if err != nil {
		t.Fatalf("ParseKeyring() error = %v", err)
	}
	t.Cleanup(func() { _ = ring.Close() })
	encoded, err := ring.Encode()
	if err != nil || string(encoded) != canonical {
		t.Fatalf("Encode() did not reproduce canonical input")
	}
	if ring.activeID != "active" || len(ring.keys) != 3 {
		t.Fatal("parsed keyring does not preserve active key and entries")
	}

	eight := "igk1:active=" + encodedKey(1)
	for index := 0; index < 7; index++ {
		eight += ",old-" + string(rune('a'+index)) + "=" + encodedKey(byte(index+2))
	}
	if len(eight) > MaximumKeyringBytes {
		t.Fatal("eight-entry canonical fixture exceeds published bound")
	}
	eightRing, err := ParseKeyring([]byte(eight))
	if err != nil {
		t.Fatalf("ParseKeyring(eight entries) error = %v", err)
	}
	_ = eightRing.Close()

	exactMaximum := "igk1:" + "a" + strings.Repeat("a", 31) + "=" + encodedKey(1)
	for index := 0; index < 7; index++ {
		identifier := string(rune('b'+index)) + strings.Repeat(string(rune('b'+index)), 31)
		exactMaximum += "," + identifier + "=" + encodedKey(byte(index+2))
	}
	if len(exactMaximum) != MaximumKeyringBytes {
		t.Fatalf("maximum keyring fixture bytes = %d, want %d", len(exactMaximum), MaximumKeyringBytes)
	}
	maximumRing, err := ParseKeyring([]byte(exactMaximum))
	if err != nil {
		t.Fatalf("ParseKeyring(maximum bytes) error = %v", err)
	}
	_ = maximumRing.Close()
}

func TestKeyringRejectsEveryNoncanonicalForm(t *testing.T) {
	one := encodedKey(1)
	two := encodedKey(2)
	tests := []string{
		"", "igk2:a=" + one, "igk1:", "igk1:A=" + one, "igk1:a.=" + one,
		"igk1:a=" + one + "=", "igk1:a=+" + one[1:],
		"igk1:a=" + one + " ", "igk1:a=" + one + "\n", "igk1:a=" + one + ",",
		"igk1:a=" + one + ",a=" + two,
		"igk1:a=" + one + ",b=" + one,
		"igk1:a=" + one + ",z=" + two + ",b=" + encodedKey(3),
		"igk1:a=" + one[:42],
		"igk1:a=" + one + ",=bad",
		strings.Repeat("x", MaximumKeyringBytes+1),
	}
	tooMany := "igk1:active=" + one
	for index := 0; index < 8; index++ {
		tooMany += ",old-" + string(rune('a'+index)) + "=" + encodedKey(byte(index+2))
	}
	tests = append(tests, tooMany)
	for index, input := range tests {
		if _, err := ParseKeyring([]byte(input)); !errors.Is(err, ErrInvalidKeyring) {
			t.Fatalf("noncanonical keyring case %d error = %v, want ErrInvalidKeyring", index, err)
		}
	}
}

func TestDeterministicKnownAnswerEnvelopeAndRoundTrip(t *testing.T) {
	ring := mustRing(t, canonicalKeyring("active", 1))
	ring.random = bytes.NewReader([]byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab})
	plaintext := []byte{0x00, 0x01, 0xfe, 0xff, 0x41}
	envelope, err := ring.EncryptRefreshToken(testAccountA, plaintext)
	if err != nil {
		t.Fatalf("EncryptRefreshToken() error = %v", err)
	}
	const expected = "igc1.SUdDAAEBBmFjdGl2ZaChoqOkpaanqKmqq7nQw5m8RCLCR7myE37QOcGcqgJDqQ"
	if envelope != expected {
		t.Fatalf("known-answer envelope mismatch: got %q", envelope)
	}
	decoded, err := ring.DecryptRefreshToken(testAccountA, envelope)
	if err != nil || !bytes.Equal(decoded, plaintext) {
		t.Fatalf("DecryptRefreshToken() did not recover exact bytes: %v", err)
	}
	clear(decoded)
}

func TestPlaintextAndEnvelopeBoundsAndRandomFailure(t *testing.T) {
	ring := mustRing(t, canonicalKeyring("active", 1))
	for _, size := range []int{MinimumPlaintextBytes, MaximumPlaintextBytes} {
		ring.random = bytes.NewReader(bytes.Repeat([]byte{byte(size)}, NonceBytes))
		envelope, err := ring.EncryptRefreshToken(testAccountA, bytes.Repeat([]byte{0x7f}, size))
		if err != nil {
			t.Fatalf("EncryptRefreshToken(%d bytes) error = %v", size, err)
		}
		if len(envelope) < MinimumEnvelopeTextBytes || len(envelope) > MaximumEnvelopeTextBytes {
			t.Fatalf("envelope length = %d, outside published bounds", len(envelope))
		}
	}
	for _, size := range []int{0, MaximumPlaintextBytes + 1} {
		source := &countingReader{}
		ring.random = source
		if _, err := ring.EncryptRefreshToken(testAccountA, make([]byte, size)); !errors.Is(err, ErrInvalidPlaintext) {
			t.Fatalf("EncryptRefreshToken(%d bytes) error = %v, want ErrInvalidPlaintext", size, err)
		}
		if source.calls != 0 {
			t.Fatal("invalid plaintext acquired a nonce")
		}
	}
	for _, source := range []io.Reader{&failingReader{}, bytes.NewReader(make([]byte, NonceBytes-1))} {
		ring.random = source
		if _, err := ring.EncryptRefreshToken(testAccountA, []byte{1}); !errors.Is(err, ErrRandomSource) {
			t.Fatalf("random failure error = %v, want ErrRandomSource", err)
		}
	}
}

func TestEnvelopeTextAcceptsExactBoundsAndRejectsAdjacentLengths(t *testing.T) {
	minimumRing := mustRing(t, canonicalKeyring("a", 1))
	minimumRing.random = bytes.NewReader(bytes.Repeat([]byte{0x31}, NonceBytes))
	minimum, err := minimumRing.EncryptRefreshToken(testAccountA, []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if len(minimum) != MinimumEnvelopeTextBytes {
		t.Fatalf("minimum envelope bytes = %d, want %d", len(minimum), MinimumEnvelopeTextBytes)
	}
	if _, err := minimumRing.DecryptRefreshToken(testAccountA, minimum); err != nil {
		t.Fatalf("minimum envelope decryption error = %v", err)
	}
	if _, err := minimumRing.DecryptRefreshToken(testAccountA, minimum[:len(minimum)-1]); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("below-minimum envelope error = %v, want ErrInvalidEnvelope", err)
	}

	maximumID := "a" + strings.Repeat("z", maximumKeyIDBytes-1)
	maximumRing := mustRing(t, canonicalKeyring(maximumID, 2))
	maximumRing.random = bytes.NewReader(bytes.Repeat([]byte{0x32}, NonceBytes))
	maximum, err := maximumRing.EncryptRefreshToken(testAccountA, bytes.Repeat([]byte{2}, MaximumPlaintextBytes))
	if err != nil {
		t.Fatal(err)
	}
	if len(maximum) != MaximumEnvelopeTextBytes {
		t.Fatalf("maximum envelope bytes = %d, want %d", len(maximum), MaximumEnvelopeTextBytes)
	}
	if _, err := maximumRing.DecryptRefreshToken(testAccountA, maximum); err != nil {
		t.Fatalf("maximum envelope decryption error = %v", err)
	}
	if _, err := maximumRing.DecryptRefreshToken(testAccountA, maximum+"A"); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("above-maximum envelope error = %v, want ErrInvalidEnvelope", err)
	}
}

func TestInvalidBindingDoesNotAcquireNonceAndEveryEncryptionUsesFreshNonce(t *testing.T) {
	ring := mustRing(t, canonicalKeyring("active", 1))
	counted := &countingReader{}
	ring.random = counted
	if _, err := ring.EncryptRefreshToken("invalid-account", []byte{1}); !errors.Is(err, ErrInvalidBinding) {
		t.Fatalf("EncryptRefreshToken(invalid binding) error = %v, want ErrInvalidBinding", err)
	}
	if counted.calls != 0 {
		t.Fatal("invalid binding acquired a nonce")
	}

	ring.random = bytes.NewReader(append(bytes.Repeat([]byte{0x11}, NonceBytes), bytes.Repeat([]byte{0x22}, NonceBytes)...))
	first, err := ring.EncryptRefreshToken(testAccountA, []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	second, err := ring.EncryptRefreshToken(testAccountA, []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("successive encryptions reused an envelope")
	}
	firstBinary := decodeEnvelopeText(t, first)
	secondBinary := decodeEnvelopeText(t, second)
	headerLength := envelopeFixedHeaderBytes + len("active")
	if bytes.Equal(firstBinary[headerLength:headerLength+NonceBytes], secondBinary[headerLength:headerLength+NonceBytes]) {
		t.Fatal("successive encryptions reused a nonce")
	}
}

func TestEnvelopeTamperingBindingAndUnknownKeysFailClosed(t *testing.T) {
	ring := mustRing(t, canonicalKeyring("active", 1))
	ring.random = bytes.NewReader(bytes.Repeat([]byte{0x42}, NonceBytes))
	envelope, err := ring.EncryptRefreshToken(testAccountA, []byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.DecryptRefreshToken(testAccountB, envelope); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong-account error = %v, want ErrAuthentication", err)
	}
	binary := decodeEnvelopeText(t, envelope)
	for _, index := range []int{0, 4, 5, 7, len(binary) - AuthenticationTagBytes, len(binary) - 1} {
		tampered := append([]byte(nil), binary...)
		tampered[index] ^= 1
		_, err := ring.DecryptRefreshToken(testAccountA, encodeEnvelopeBinary(tampered))
		if !errors.Is(err, ErrInvalidEnvelope) && !errors.Is(err, ErrAuthentication) && !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("tamper index %d error = %v", index, err)
		}
	}
	for _, invalid := range []string{"", "igc2.x", "igc1.=", strings.Repeat("x", MaximumEnvelopeTextBytes+1)} {
		if _, err := ring.DecryptRefreshToken(testAccountA, invalid); !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("invalid envelope error = %v, want ErrInvalidEnvelope", err)
		}
	}
	other := mustRing(t, canonicalKeyring("other", 9))
	if _, err := other.DecryptRefreshToken(testAccountA, envelope); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("missing-key error = %v, want ErrUnknownKey", err)
	}
}

func TestEveryBinaryEnvelopeByteIsAuthenticatedOrStructurallyRejected(t *testing.T) {
	ring := mustRing(t, canonicalKeyring("active", 1))
	ring.random = bytes.NewReader(bytes.Repeat([]byte{0x51}, NonceBytes))
	envelope, err := ring.EncryptRefreshToken(testAccountA, []byte{1, 2, 3, 4, 5})
	if err != nil {
		t.Fatal(err)
	}
	binary := decodeEnvelopeText(t, envelope)
	headerLength := envelopeFixedHeaderBytes + len("active")
	for index := range binary {
		tampered := append([]byte(nil), binary...)
		tampered[index] ^= 1
		_, err := ring.DecryptRefreshToken(testAccountA, encodeEnvelopeBinary(tampered))
		if index >= headerLength {
			if !errors.Is(err, ErrAuthentication) {
				t.Fatalf("tamper byte %d error = %v, want ErrAuthentication", index, err)
			}
			continue
		}
		if !errors.Is(err, ErrInvalidEnvelope) && !errors.Is(err, ErrUnknownKey) && !errors.Is(err, ErrAuthentication) {
			t.Fatalf("header tamper byte %d error = %v, want fail-closed category", index, err)
		}
	}

	for _, keyIDLength := range []byte{0, maximumKeyIDBytes + 1} {
		tampered := append([]byte(nil), binary...)
		tampered[6] = keyIDLength
		if _, err := ring.DecryptRefreshToken(testAccountA, encodeEnvelopeBinary(tampered)); !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("key-id length %d error = %v, want ErrInvalidEnvelope", keyIDLength, err)
		}
	}
}

func TestRotationRestartRollbackRecoveryAndClose(t *testing.T) {
	old := mustRing(t, canonicalKeyring("old", 1))
	old.random = bytes.NewReader(bytes.Repeat([]byte{0x11}, NonceBytes))
	original, err := old.EncryptRefreshToken(testAccountA, []byte{9, 8, 7})
	if err != nil {
		t.Fatal(err)
	}
	unchanged, changed, err := old.RotateRefreshToken(testAccountA, original)
	if err != nil || changed || unchanged != original {
		t.Fatalf("active rotation = (%t, %v), want byte-idempotent", changed, err)
	}

	rotatedRing := mustRing(t, canonicalKeyring("new", 2, "old", 1))
	rotatedRing.random = bytes.NewReader(bytes.Repeat([]byte{0x22}, NonceBytes))
	rotated, changed, err := rotatedRing.RotateRefreshToken(testAccountA, original)
	if err != nil || !changed || rotated == original {
		t.Fatalf("old-key rotation = (%t, %v), want changed", changed, err)
	}
	restarted := mustRing(t, canonicalKeyring("new", 2, "old", 1))
	plaintext, err := restarted.DecryptRefreshToken(testAccountA, rotated)
	if err != nil || !bytes.Equal(plaintext, []byte{9, 8, 7}) {
		t.Fatalf("restart decrypt error = %v", err)
	}
	clear(plaintext)
	rollback := mustRing(t, canonicalKeyring("old", 1, "new", 2))
	if _, err := rollback.DecryptRefreshToken(testAccountA, rotated); err != nil {
		t.Fatalf("rollback decrypt error = %v", err)
	}
	missing := mustRing(t, canonicalKeyring("new", 2))
	if _, err := missing.DecryptRefreshToken(testAccountA, original); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("restored old envelope error = %v, want ErrUnknownKey", err)
	}
	recovered := mustRing(t, canonicalKeyring("new", 2, "old", 1))
	if _, err := recovered.DecryptRefreshToken(testAccountA, original); err != nil {
		t.Fatalf("recovered old envelope error = %v", err)
	}

	if err := recovered.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	for _, key := range recovered.keys {
		if *key != [KeyBytes]byte{} {
			t.Fatal("owned key array was not overwritten")
		}
	}
	if _, err := recovered.DecryptRefreshToken(testAccountA, original); !errors.Is(err, ErrClosedKeyring) {
		t.Fatalf("closed decrypt error = %v, want ErrClosedKeyring", err)
	}
	if _, err := recovered.Encode(); !errors.Is(err, ErrClosedKeyring) {
		t.Fatalf("closed encode error = %v, want ErrClosedKeyring", err)
	}
}

func canonicalKeyring(active string, pairs ...any) string {
	result := "igk1:" + active + "=" + encodedKey(keySeed(pairs[0]))
	for index := 1; index < len(pairs); index += 2 {
		result += "," + pairs[index].(string) + "=" + encodedKey(keySeed(pairs[index+1]))
	}
	return result
}

func keySeed(value any) byte {
	switch seed := value.(type) {
	case byte:
		return seed
	case int:
		return byte(seed)
	default:
		panic("unsupported synthetic key seed")
	}
}

func encodedKey(seed byte) string {
	key := make([]byte, KeyBytes)
	for index := range key {
		key[index] = seed + byte(index)
	}
	return base64.RawURLEncoding.EncodeToString(key)
}

func mustRing(t *testing.T, encoded string) *Keyring {
	t.Helper()
	ring, err := ParseKeyring([]byte(encoded))
	if err != nil {
		t.Fatalf("ParseKeyring() error = %v", err)
	}
	t.Cleanup(func() { _ = ring.Close() })
	return ring
}

func decodeEnvelopeText(t *testing.T, envelope string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(envelope, "igc1."))
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func encodeEnvelopeBinary(binary []byte) string {
	return "igc1." + base64.RawURLEncoding.EncodeToString(binary)
}

type countingReader struct{ calls int }

func (r *countingReader) Read([]byte) (int, error) {
	r.calls++
	return 0, errors.New("synthetic random failure")
}

type failingReader struct{}

func (*failingReader) Read([]byte) (int, error) {
	return 0, errors.New("synthetic random failure")
}
