package storage_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/mandloideep/inboxgate/internal/storage"
	storagefake "github.com/mandloideep/inboxgate/internal/storage/fake"
)

func TestProviderCredentialValueContract(t *testing.T) {
	for _, id := range []string{"a", "active-key_1", "z2345678901234567890123456789012"} {
		parsed, err := storage.ParseCredentialKeyID(id)
		if err != nil || parsed.String() != id {
			t.Fatalf("ParseCredentialKeyID() rejected canonical value: %v", err)
		}
	}
	for _, id := range []string{"", "A", "1a", "a.", "a\x00b", "a b", "a23456789012345678901234567890123"} {
		if _, err := storage.ParseCredentialKeyID(id); !errors.Is(err, storage.ErrInvalidValue) {
			t.Fatalf("ParseCredentialKeyID() error = %v, want ErrInvalidValue", err)
		}
	}

	for _, boundary := range []struct {
		keyID      string
		size       int
		textLength int
	}{
		{keyID: "a", size: 1, textLength: storage.MinimumCredentialEnvelopeBytes},
		{keyID: "a" + strings.Repeat("z", 31), size: storage.MaximumCredentialPlaintextBytes, textLength: storage.MaximumCredentialEnvelopeBytes},
	} {
		envelope := structuralEnvelope(boundary.keyID, boundary.size, byte(boundary.size))
		parsed, err := storage.ParseCredentialEnvelope(envelope)
		if err != nil || parsed.String() != envelope || parsed.KeyID().String() != boundary.keyID {
			t.Fatalf("ParseCredentialEnvelope(%d) rejected canonical structure: %v", boundary.size, err)
		}
		if len(envelope) != boundary.textLength {
			t.Fatalf("credential envelope text bytes = %d, want %d", len(envelope), boundary.textLength)
		}
	}
	minimum := structuralEnvelope("a", 1, 1)
	maximum := structuralEnvelope("a"+strings.Repeat("z", 31), storage.MaximumCredentialPlaintextBytes, 1)
	for _, envelope := range []string{"", "igc2.x", "igc1.=", minimum[:len(minimum)-1], maximum + "A", structuralEnvelope("active", storage.MaximumCredentialPlaintextBytes+1, 1)} {
		if _, err := storage.ParseCredentialEnvelope(envelope); !errors.Is(err, storage.ErrInvalidValue) {
			t.Fatalf("ParseCredentialEnvelope() error = %v, want ErrInvalidValue", err)
		}
	}
}

func TestFakeProviderCredentialCompareAndSwapContract(t *testing.T) {
	handle := storagefake.New()
	account := accountSeed(t, "66666666666666666666666666666666", "credential-subject")
	if _, err := handle.EnsureAccount(context.Background(), account); err != nil {
		t.Fatal(err)
	}
	if _, err := handle.GetProviderCredential(context.Background(), account.ID); !errors.Is(err, storage.ErrCredentialNotFound) {
		t.Fatalf("GetProviderCredential() error = %v, want ErrCredentialNotFound", err)
	}
	first := credentialEnvelope(t, structuralEnvelope("old", 32, 1))
	second := credentialEnvelope(t, structuralEnvelope("active", 32, 2))
	other := credentialEnvelope(t, structuralEnvelope("active", 32, 3))
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: account.ID, Next: first}); err != nil {
		t.Fatalf("initial CommitProviderCredential() error = %v", err)
	}
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: account.ID, Next: first}); err != nil {
		t.Fatalf("idempotent CommitProviderCredential() error = %v", err)
	}
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: account.ID, Next: second}); !errors.Is(err, storage.ErrCredentialConflict) {
		t.Fatalf("blind replacement error = %v, want ErrCredentialConflict", err)
	}
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: account.ID, Expected: &first, Next: second}); err != nil {
		t.Fatalf("rotation CommitProviderCredential() error = %v", err)
	}
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: account.ID, Expected: &first, Next: other}); !errors.Is(err, storage.ErrCredentialConflict) {
		t.Fatalf("stale replacement error = %v, want ErrCredentialConflict", err)
	}
	stored, err := handle.GetProviderCredential(context.Background(), account.ID)
	if err != nil || stored.AccountID != account.ID || stored.Envelope != second || stored.KeyID != second.KeyID() {
		t.Fatalf("GetProviderCredential() = (%#v, %v), want exact second envelope", stored, err)
	}
}

func TestFakeProviderCredentialConcurrentInitializationHasOneWinner(t *testing.T) {
	handle := storagefake.New()
	account := accountSeed(t, "77777777777777777777777777777777", "credential-concurrent")
	if _, err := handle.EnsureAccount(context.Background(), account); err != nil {
		t.Fatal(err)
	}
	next := []storage.CredentialEnvelope{
		credentialEnvelope(t, structuralEnvelope("active", 32, 4)),
		credentialEnvelope(t, structuralEnvelope("active", 32, 5)),
	}
	start := make(chan struct{})
	ready := sync.WaitGroup{}
	ready.Add(2)
	results := make(chan error, 2)
	for _, envelope := range next {
		go func(envelope storage.CredentialEnvelope) {
			ready.Done()
			<-start
			results <- handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: account.ID, Next: envelope})
		}(envelope)
	}
	ready.Wait()
	close(start)
	successes := 0
	conflicts := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		} else if errors.Is(err, storage.ErrCredentialConflict) {
			conflicts++
		} else {
			t.Fatalf("concurrent commit error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent results = %d successes, %d conflicts", successes, conflicts)
	}
}

func structuralEnvelope(keyID string, plaintextBytes int, fill byte) string {
	binary := []byte{'I', 'G', 'C', 0, 1, 1, byte(len(keyID))}
	binary = append(binary, keyID...)
	binary = append(binary, make([]byte, 12)...)
	binary = append(binary, make([]byte, plaintextBytes+16)...)
	for index := 7 + len(keyID); index < len(binary); index++ {
		binary[index] = fill
	}
	return "igc1." + base64.RawURLEncoding.EncodeToString(binary)
}

func credentialEnvelope(t *testing.T, text string) storage.CredentialEnvelope {
	t.Helper()
	envelope, err := storage.ParseCredentialEnvelope(text)
	if err != nil {
		t.Fatalf("ParseCredentialEnvelope() error = %v", err)
	}
	return envelope
}
