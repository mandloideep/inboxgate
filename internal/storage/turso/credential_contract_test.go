package turso

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/cryptobox"
	"github.com/mandloideep/inboxgate/internal/storage"
	storagefake "github.com/mandloideep/inboxgate/internal/storage/fake"
)

type syntheticCredential struct {
	keyID    string
	envelope string
}

const expectedCredentialCommitSQL = "INSERT INTO inboxgate_provider_credentials (account_id, key_id, envelope) SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM inboxgate_accounts WHERE account_id = ?) AND EXISTS (SELECT 1 FROM inboxgate_account_lifecycle WHERE account_id = ? AND state <> 'revoked') AND (? IS NULL OR EXISTS (SELECT 1 FROM inboxgate_provider_credentials WHERE account_id = ? AND envelope = ?)) ON CONFLICT(account_id) DO UPDATE SET key_id = excluded.key_id, envelope = excluded.envelope WHERE ? IS NOT NULL AND inboxgate_provider_credentials.envelope = ?"

func TestProviderCredentialReplacementSQLKeepsMatchingSourceRow(t *testing.T) {
	if credentialCommitSQL != expectedCredentialCommitSQL {
		t.Fatal("credential replacement SQL does not preserve a matching non-null expected source row")
	}
	for _, required := range []string{
		"EXISTS (SELECT 1 FROM inboxgate_accounts WHERE account_id = ?)",
		"EXISTS (SELECT 1 FROM inboxgate_account_lifecycle WHERE account_id = ? AND state <> 'revoked')",
		"(? IS NULL OR EXISTS (SELECT 1 FROM inboxgate_provider_credentials WHERE account_id = ? AND envelope = ?))",
		"WHERE ? IS NOT NULL AND inboxgate_provider_credentials.envelope = ?",
	} {
		if !strings.Contains(credentialCommitSQL, required) {
			t.Fatal("credential replacement SQL lost a required atomic guard")
		}
	}
}

func TestProviderCredentialUsesExactParameterizedWireAndSeparateVisibility(t *testing.T) {
	server := newMigrationProtocolServer(t)
	server.seedAccount(accountIDA, subjectA)
	handle := openPersistenceContractHandle(t, server.URL)
	next := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 48, 1))
	commit := storage.ProviderCredentialCommit{AccountID: persistenceAccountID(t, accountIDA), Next: next}
	if err := handle.CommitProviderCredential(context.Background(), commit); err != nil {
		t.Fatalf("CommitProviderCredential() error = %v", err)
	}
	stored, err := handle.GetProviderCredential(context.Background(), commit.AccountID)
	if err != nil || stored.Envelope != next || stored.KeyID != next.KeyID() {
		t.Fatalf("GetProviderCredential() = (%#v, %v), want exact ciphertext", stored, err)
	}
	records := server.persistenceRecords()
	if got := countPersistenceSQL(records, credentialCommitSQL); got != 1 {
		t.Fatalf("credential mutation attempts = %d, want 1", got)
	}
	var mutation migrationRequest
	for _, record := range records {
		if record.sql == credentialCommitSQL {
			mutation = record
		}
	}
	assertProtocolStatement(t, mutation, credentialCommitSQL, []protocolValue{
		textProtocolValue(accountIDA), textProtocolValue("active"), textProtocolValue(next.String()), textProtocolValue(accountIDA), textProtocolValue(accountIDA), nullProtocolValue(), textProtocolValue(accountIDA), nullProtocolValue(), nullProtocolValue(), nullProtocolValue(),
	})
	for index, record := range records {
		if record.sql == credentialCommitSQL && index+1 < len(records) && records[index+1].sql == credentialLookupSQL {
			if record.baton == nil || records[index+1].baton != nil {
				t.Fatalf("mutation and verification batons = (%v, %v), want separate streams", record.baton, records[index+1].baton)
			}
		}
	}
}

func TestProviderCredentialReplacementUsesExactExpectedArguments(t *testing.T) {
	server := newMigrationProtocolServer(t)
	server.seedAccount(accountIDA, subjectA)
	handle := openPersistenceContractHandle(t, server.URL)
	accountID := persistenceAccountID(t, accountIDA)
	oldEnvelope := mustCredentialEnvelope(t, structuralCredentialEnvelope("old", 32, 20))
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: accountID, Next: oldEnvelope}); err != nil {
		t.Fatal(err)
	}
	next := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 32, 21))
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: accountID, Expected: &oldEnvelope, Next: next}); err != nil {
		t.Fatalf("replacement CommitProviderCredential() error = %v", err)
	}
	var replacement migrationRequest
	for _, record := range server.persistenceRecords() {
		if record.sql == credentialCommitSQL {
			replacement = record
		}
	}
	assertProtocolStatement(t, replacement, expectedCredentialCommitSQL, []protocolValue{
		textProtocolValue(accountIDA), textProtocolValue("active"), textProtocolValue(next.String()), textProtocolValue(accountIDA), textProtocolValue(accountIDA), textProtocolValue(oldEnvelope.String()), textProtocolValue(accountIDA), textProtocolValue(oldEnvelope.String()), textProtocolValue(oldEnvelope.String()), textProtocolValue(oldEnvelope.String()),
	})
}

func TestProviderCredentialStorageRequestContainsCiphertextOnly(t *testing.T) {
	encodedKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x2a}, cryptobox.KeyBytes))
	ring, err := cryptobox.ParseKeyring([]byte("igk1:active=" + encodedKey))
	if err != nil {
		t.Fatalf("ParseKeyring() error = %v", err)
	}
	t.Cleanup(func() { _ = ring.Close() })
	accountID := persistenceAccountID(t, accountIDA)
	envelopeText, err := ring.EncryptRefreshToken(accountID.String(), []byte("synthetic-plaintext-must-not-cross-storage"))
	if err != nil {
		t.Fatalf("EncryptRefreshToken() error = %v", err)
	}
	envelope := mustCredentialEnvelope(t, envelopeText)
	server := newMigrationProtocolServer(t)
	server.seedAccount(accountIDA, subjectA)
	handle := openPersistenceContractHandle(t, server.URL)
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: accountID, Next: envelope}); err != nil {
		t.Fatalf("CommitProviderCredential() error = %v", err)
	}
	for _, record := range server.persistenceRecords() {
		if strings.Contains(record.sql, "synthetic-plaintext-must-not-cross-storage") {
			t.Fatal("credential plaintext appeared in SQL")
		}
		for _, argument := range record.args {
			if bytes.Contains(argument.Value, []byte("synthetic-plaintext-must-not-cross-storage")) {
				t.Fatal("credential plaintext appeared in a storage request")
			}
		}
	}
}

func TestProviderCredentialCommitRejectsRevokedLifecycleBeforeMutation(t *testing.T) {
	server := newMigrationProtocolServer(t)
	server.seedAccount(accountIDA, subjectA)
	server.seedLifecycle(accountIDA, "revoked", 2, nil, "pending")
	handle := openPersistenceContractHandle(t, server.URL)
	next := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 32, 72))
	err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: persistenceAccountID(t, accountIDA), Next: next})
	if !errors.Is(err, storage.ErrLifecycleConflict) {
		t.Fatalf("revoked credential commit error = %v", err)
	}
	if got := countPersistenceSQL(server.persistenceRecords(), credentialCommitSQL); got != 0 {
		t.Fatalf("revoked credential mutations = %d, want 0", got)
	}
}

func TestProviderCredentialEncryptPersistRestartRotateRollbackAndRecover(t *testing.T) {
	server := newMigrationProtocolServer(t)
	server.seedAccount(accountIDA, subjectA)
	accountID := persistenceAccountID(t, accountIDA)
	plaintext := []byte{0, 1, 2, 3, 0xfe, 0xff}
	oldKeyringText := syntheticKeyringText("old", 1)
	oldRing, err := cryptobox.ParseKeyring([]byte(oldKeyringText))
	if err != nil {
		t.Fatal(err)
	}
	originalText, err := oldRing.EncryptRefreshToken(accountID.String(), plaintext)
	if err != nil {
		t.Fatal(err)
	}
	original := mustCredentialEnvelope(t, originalText)
	handle := openPersistenceContractHandle(t, server.URL)
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: accountID, Next: original}); err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	if err := oldRing.Close(); err != nil {
		t.Fatal(err)
	}

	restartedOld, err := cryptobox.ParseKeyring([]byte(oldKeyringText))
	if err != nil {
		t.Fatal(err)
	}
	handle = openPersistenceContractHandle(t, server.URL)
	stored, err := handle.GetProviderCredential(context.Background(), accountID)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := restartedOld.DecryptRefreshToken(accountID.String(), stored.Envelope.String())
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("restart decryption failed: %v", err)
	}
	clear(decrypted)
	_ = restartedOld.Close()
	_ = handle.Close()

	rotatingText := syntheticKeyringText("new", 2, syntheticDecryptKey{id: "old", seed: 1})
	rotatingRing, err := cryptobox.ParseKeyring([]byte(rotatingText))
	if err != nil {
		t.Fatal(err)
	}
	rotatedText, changed, err := rotatingRing.RotateRefreshToken(accountID.String(), original.String())
	if err != nil || !changed {
		t.Fatalf("RotateRefreshToken() = (%t, %v), want changed", changed, err)
	}
	rotated := mustCredentialEnvelope(t, rotatedText)
	handle = openPersistenceContractHandle(t, server.URL)
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: accountID, Expected: &original, Next: rotated}); err != nil {
		t.Fatalf("rotation persistence error = %v", err)
	}
	_ = rotatingRing.Close()
	_ = handle.Close()

	restartedNew, err := cryptobox.ParseKeyring([]byte(rotatingText))
	if err != nil {
		t.Fatal(err)
	}
	handle = openPersistenceContractHandle(t, server.URL)
	stored, err = handle.GetProviderCredential(context.Background(), accountID)
	if err != nil || stored.Envelope != rotated {
		t.Fatalf("rotated restart load error = %v", err)
	}
	decrypted, err = restartedNew.DecryptRefreshToken(accountID.String(), stored.Envelope.String())
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("rotated restart decryption failed: %v", err)
	}
	clear(decrypted)
	if restored, err := restartedNew.DecryptRefreshToken(accountID.String(), original.String()); err != nil || !bytes.Equal(restored, plaintext) {
		t.Fatalf("restored old envelope decryption failed: %v", err)
	} else {
		clear(restored)
	}
	missingOld, err := cryptobox.ParseKeyring([]byte(syntheticKeyringText("new", 2)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missingOld.DecryptRefreshToken(accountID.String(), original.String()); !errors.Is(err, cryptobox.ErrUnknownKey) {
		t.Fatalf("missing old key error = %v, want ErrUnknownKey", err)
	}
	_ = missingOld.Close()
	recovered, err := cryptobox.ParseKeyring([]byte(rotatingText))
	if err != nil {
		t.Fatal(err)
	}
	if recoveredPlaintext, err := recovered.DecryptRefreshToken(accountID.String(), original.String()); err != nil || !bytes.Equal(recoveredPlaintext, plaintext) {
		t.Fatalf("recovered keyring decryption failed: %v", err)
	} else {
		clear(recoveredPlaintext)
	}
	_ = recovered.Close()

	rollbackText := syntheticKeyringText("old", 1, syntheticDecryptKey{id: "new", seed: 2})
	rollbackRing, err := cryptobox.ParseKeyring([]byte(rollbackText))
	if err != nil {
		t.Fatal(err)
	}
	rolledBackText, changed, err := rollbackRing.RotateRefreshToken(accountID.String(), rotated.String())
	if err != nil || !changed {
		t.Fatalf("rollback rotation = (%t, %v), want changed", changed, err)
	}
	rolledBack := mustCredentialEnvelope(t, rolledBackText)
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: accountID, Expected: &rotated, Next: rolledBack}); err != nil {
		t.Fatalf("rollback persistence error = %v", err)
	}
	_ = rollbackRing.Close()
	_ = restartedNew.Close()
	_ = handle.Close()

	finalRing, err := cryptobox.ParseKeyring([]byte(oldKeyringText))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = finalRing.Close() })
	handle = openPersistenceContractHandle(t, server.URL)
	finalStored, err := handle.GetProviderCredential(context.Background(), accountID)
	if err != nil || finalStored.Envelope != rolledBack {
		t.Fatalf("rollback restart load error = %v", err)
	}
	finalPlaintext, err := finalRing.DecryptRefreshToken(accountID.String(), finalStored.Envelope.String())
	if err != nil || !bytes.Equal(finalPlaintext, plaintext) {
		t.Fatalf("rollback restart decryption failed: %v", err)
	}
	clear(finalPlaintext)
}

func TestProviderCredentialUncertainWritesProveVisibilityDiscardSessionAndNeverReplay(t *testing.T) {
	server := newMigrationProtocolServer(t)
	tests := []struct {
		name        string
		mode        string
		wantSuccess bool
		wantDiscard bool
		wantClose   bool
	}{
		{name: "drop before durability", mode: "drop-before", wantDiscard: true},
		{name: "clean eof before durability", mode: "clean-eof", wantDiscard: true, wantClose: true},
		{name: "step begin eof before durability", mode: "step-begin-before", wantDiscard: true, wantClose: true},
		{name: "success without apply", mode: "success-without-apply", wantDiscard: true, wantClose: true},
		{name: "drop after durability", mode: "drop-after", wantSuccess: true, wantDiscard: true},
		{name: "malformed after durability", mode: "malformed-after", wantSuccess: true, wantDiscard: true},
		{name: "step begin eof after durability", mode: "step-begin-after", wantSuccess: true, wantDiscard: true, wantClose: true},
		{name: "zero affected after durability", mode: "apply-zero-affected", wantSuccess: true, wantDiscard: true, wantClose: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server.resetCredentialScenario()
			server.seedAccount(accountIDA, subjectA)
			server.armPersistenceResponse(credentialCommitSQL, tt.mode)
			handle := openPersistenceContractHandle(t, server.URL)
			next := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 32, 2))
			err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: persistenceAccountID(t, accountIDA), Next: next})
			if tt.wantSuccess {
				if err != nil {
					t.Fatalf("CommitProviderCredential() error = %v, want separately proved success", err)
				}
			} else if !errors.Is(err, storage.ErrPersistenceUnknown) {
				t.Fatalf("CommitProviderCredential() error = %v, want ErrPersistenceUnknown", err)
			}
			if err != nil {
				for _, raw := range []string{"raw", "synthetic-token", accountIDA, next.String()} {
					if strings.Contains(err.Error(), raw) || len(err.Error()) > 128 {
						t.Fatal("credential mutation returned an unbounded or raw diagnostic")
					}
				}
			}
			if got := countPersistenceSQL(server.persistenceRecords(), credentialCommitSQL); got != 1 {
				t.Fatalf("same-invocation mutation attempts = %d, want 1", got)
			}
			if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: persistenceAccountID(t, accountIDA), Next: next}); err != nil {
				t.Fatalf("fresh CommitProviderCredential() error = %v", err)
			}
			wantAttempts := 2
			if tt.wantSuccess {
				wantAttempts = 1
			}
			if got := countPersistenceSQL(server.persistenceRecords(), credentialCommitSQL); got != wantAttempts {
				t.Fatalf("credential attempts across invocations = %d, want %d", got, wantAttempts)
			}
			if tt.wantDiscard {
				baton := firstMutationBaton(t, server.persistenceRecords(), credentialCommitSQL)
				wantClose := 0
				if tt.wantClose {
					wantClose = 1
				}
				if got := server.cursorSessionCloseCount(baton); got != wantClose {
					t.Fatalf("unproven credential session close requests = %d, want %d", got, wantClose)
				}
				if !server.cursorSessionWasNotReusedAfterMutation(baton, credentialCommitSQL) {
					t.Fatal("unproven credential session was reused")
				}
			}
		})
	}
}

func TestProviderCredentialReplacementUncertaintyNeverReplaysAndReconcilesFresh(t *testing.T) {
	server := newMigrationProtocolServer(t)
	tests := []struct {
		name        string
		mode        string
		wantSuccess bool
		wantDiscard bool
		wantClose   bool
	}{
		{name: "drop before durability", mode: "drop-before", wantDiscard: true},
		{name: "clean eof before durability", mode: "clean-eof", wantDiscard: true, wantClose: true},
		{name: "step begin eof before durability", mode: "step-begin-before", wantDiscard: true, wantClose: true},
		{name: "success without apply", mode: "success-without-apply", wantDiscard: true, wantClose: true},
		{name: "drop after durability", mode: "drop-after", wantSuccess: true, wantDiscard: true},
		{name: "malformed after durability", mode: "malformed-after", wantSuccess: true, wantDiscard: true},
		{name: "step begin eof after durability", mode: "step-begin-after", wantSuccess: true, wantDiscard: true, wantClose: true},
		{name: "zero affected after durability", mode: "apply-zero-affected", wantSuccess: true, wantDiscard: true, wantClose: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server.resetCredentialScenario()
			server.seedAccount(accountIDA, subjectA)
			accountID := persistenceAccountID(t, accountIDA)
			oldEnvelope := mustCredentialEnvelope(t, structuralCredentialEnvelope("old", 32, 22))
			server.seedCredential(accountIDA, oldEnvelope.KeyID().String(), oldEnvelope.String())
			next := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 32, 23))
			server.armPersistenceResponse(credentialCommitSQL, tt.mode)
			handle := openPersistenceContractHandle(t, server.URL)
			err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: accountID, Expected: &oldEnvelope, Next: next})
			if tt.wantSuccess {
				if err != nil {
					t.Fatalf("replacement error = %v, want separately proved success", err)
				}
			} else if !errors.Is(err, storage.ErrPersistenceUnknown) {
				t.Fatalf("replacement error = %v, want ErrPersistenceUnknown", err)
			}
			if err != nil {
				for _, raw := range []string{"raw", "synthetic-token", accountIDA, oldEnvelope.String(), next.String()} {
					if strings.Contains(err.Error(), raw) || len(err.Error()) > 128 {
						t.Fatal("credential replacement returned an unbounded or raw diagnostic")
					}
				}
			}
			if got := countPersistenceSQL(server.persistenceRecords(), credentialCommitSQL); got != 1 {
				t.Fatalf("same-invocation replacement attempts = %d, want 1", got)
			}
			if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: accountID, Expected: &oldEnvelope, Next: next}); err != nil {
				t.Fatalf("fresh replacement error = %v", err)
			}
			wantAttempts := 2
			if tt.wantSuccess {
				wantAttempts = 1
			}
			if got := countPersistenceSQL(server.persistenceRecords(), credentialCommitSQL); got != wantAttempts {
				t.Fatalf("replacement attempts across invocations = %d, want %d", got, wantAttempts)
			}
			if tt.wantDiscard {
				baton := firstMutationBaton(t, server.persistenceRecords(), credentialCommitSQL)
				wantClose := 0
				if tt.wantClose {
					wantClose = 1
				}
				if got := server.cursorSessionCloseCount(baton); got != wantClose {
					t.Fatalf("unproven replacement session close requests = %d, want %d", got, wantClose)
				}
				if !server.cursorSessionWasNotReusedAfterMutation(baton, credentialCommitSQL) {
					t.Fatal("unproven replacement session was reused")
				}
			}
		})
	}
}

func TestProviderCredentialLookupRejectsMalformedMismatchedAndOversizedResponses(t *testing.T) {
	server := newMigrationProtocolServer(t)
	valid := structuralCredentialEnvelope("active", 32, 3)
	validRow := credentialRow(accountIDA, "active", valid)
	tests := []struct {
		name    string
		rows    [][]any
		mode    string
		columns int
	}{
		{name: "missing sentinel", mode: "success-without-apply"},
		{name: "clean eof", mode: "clean-eof"},
		{name: "dropped cursor", mode: "drop-before"},
		{name: "incomplete cursor", mode: "step-begin-before"},
		{name: "malformed body", mode: "malformed-after"},
		{name: "missing column", rows: [][]any{validRow[:6]}, columns: 6},
		{name: "extra column", rows: [][]any{append(append([]any{}, validRow...), nullValue())}, columns: 8},
		{name: "duplicate rows", rows: [][]any{credentialRow(accountIDA, "active", valid), credentialRow(accountIDA, "active", valid)}},
		{name: "wrong sentinel type", rows: [][]any{{textValue("1"), integerValue(1), textValue(accountIDA), integerValue(1), textValue(accountIDA), textValue("active"), textValue(valid)}}},
		{name: "wrong sentinel value", rows: [][]any{{integerValue(0), integerValue(1), textValue(accountIDA), integerValue(1), textValue(accountIDA), textValue("active"), textValue(valid)}}},
		{name: "wrong account count type", rows: [][]any{{integerValue(1), textValue("1"), textValue(accountIDA), integerValue(1), textValue(accountIDA), textValue("active"), textValue(valid)}}},
		{name: "negative account count", rows: [][]any{{integerValue(1), integerValue(-1), nullValue(), integerValue(0), nullValue(), nullValue(), nullValue()}}},
		{name: "excess account count", rows: [][]any{{integerValue(1), integerValue(2), textValue(accountIDA), integerValue(0), nullValue(), nullValue(), nullValue()}}},
		{name: "account count without value", rows: [][]any{{integerValue(1), integerValue(1), nullValue(), integerValue(0), nullValue(), nullValue(), nullValue()}}},
		{name: "absent account with value", rows: [][]any{{integerValue(1), integerValue(0), textValue(accountIDA), integerValue(0), nullValue(), nullValue(), nullValue()}}},
		{name: "wrong credential count type", rows: [][]any{{integerValue(1), integerValue(1), textValue(accountIDA), textValue("1"), textValue(accountIDA), textValue("active"), textValue(valid)}}},
		{name: "negative credential count", rows: [][]any{{integerValue(1), integerValue(1), textValue(accountIDA), integerValue(-1), nullValue(), nullValue(), nullValue()}}},
		{name: "excess credential count", rows: [][]any{{integerValue(1), integerValue(1), textValue(accountIDA), integerValue(2), textValue(accountIDA), textValue("active"), textValue(valid)}}},
		{name: "absent credential with values", rows: [][]any{{integerValue(1), integerValue(1), textValue(accountIDA), integerValue(0), textValue(accountIDA), textValue("active"), textValue(valid)}}},
		{name: "credential missing key", rows: [][]any{{integerValue(1), integerValue(1), textValue(accountIDA), integerValue(1), textValue(accountIDA), nullValue(), textValue(valid)}}},
		{name: "credential account wrong type", rows: [][]any{{integerValue(1), integerValue(1), textValue(accountIDA), integerValue(1), integerValue(1), textValue("active"), textValue(valid)}}},
		{name: "credential key wrong type", rows: [][]any{{integerValue(1), integerValue(1), textValue(accountIDA), integerValue(1), textValue(accountIDA), integerValue(1), textValue(valid)}}},
		{name: "credential envelope wrong type", rows: [][]any{{integerValue(1), integerValue(1), textValue(accountIDA), integerValue(1), textValue(accountIDA), textValue("active"), integerValue(1)}}},
		{name: "credential without account", rows: [][]any{{integerValue(1), integerValue(0), nullValue(), integerValue(1), textValue(accountIDA), textValue("active"), textValue(valid)}}},
		{name: "mismatched account value", rows: [][]any{credentialRow(accountIDB, "active", valid)}},
		{name: "key mismatch", rows: [][]any{credentialRow(accountIDA, "other", valid)}},
		{name: "invalid envelope", rows: [][]any{credentialRow(accountIDA, "active", "igc1.=")}},
		{name: "nul account", rows: [][]any{credentialRow(accountIDA+"\x00", "active", valid)}},
		{name: "nul key", rows: [][]any{credentialRow(accountIDA, "active\x00", valid)}},
		{name: "nul envelope", rows: [][]any{credentialRow(accountIDA, "active", valid+"\x00")}},
		{name: "oversized value", rows: [][]any{credentialRow(accountIDA, "active", strings.Repeat("A", storage.MaximumCredentialEnvelopeBytes+1))}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server.resetCredentialScenario()
			server.seedAccount(accountIDA, subjectA)
			if tt.mode != "" {
				server.armPersistenceResponse(credentialLookupSQL, tt.mode)
			} else {
				server.overridePersistenceRows(credentialLookupSQL, tt.rows)
			}
			if tt.columns != 0 {
				columns := make([]any, tt.columns)
				for index := range columns {
					columns[index] = map[string]any{"name": "synthetic_column", "decltype": "TEXT"}
				}
				server.overridePersistenceColumns(credentialLookupSQL, columns)
			}
			handle := openPersistenceContractHandle(t, server.URL)
			_, err := handle.GetProviderCredential(context.Background(), persistenceAccountID(t, accountIDA))
			if !errors.Is(err, storage.ErrPersistenceInspect) {
				t.Fatalf("GetProviderCredential() error = %v, want ErrPersistenceInspect", err)
			}
			if got := countPersistenceSQL(server.persistenceRecords(), credentialCommitSQL); got != 0 {
				t.Fatalf("credential mutations = %d, want 0", got)
			}
			for _, raw := range []string{"raw", "private marker", valid, accountIDA + "\x00"} {
				if strings.Contains(err.Error(), raw) {
					t.Fatal("credential inspection error reflected a remote value")
				}
			}
		})
	}
}

func TestProviderCredentialServerDiagnosticIsSanitized(t *testing.T) {
	server := newMigrationProtocolServer(t)
	server.seedAccount(accountIDA, subjectA)
	server.failNextSQL(credentialLookupSQL)
	handle := openPersistenceContractHandle(t, server.URL)
	_, err := handle.GetProviderCredential(context.Background(), persistenceAccountID(t, accountIDA))
	if !errors.Is(err, storage.ErrPersistenceInspect) {
		t.Fatalf("GetProviderCredential() error = %v, want ErrPersistenceInspect", err)
	}
	for _, raw := range []string{"raw", "synthetic-token", "SELECT", "private marker", accountIDA} {
		if strings.Contains(err.Error(), raw) {
			t.Fatal("credential inspection error reflected a remote diagnostic")
		}
	}
}

func TestProviderCredentialMutationServerDiagnosticIsUnknownSanitizedAndNotReplayed(t *testing.T) {
	server := newMigrationProtocolServer(t)
	server.seedAccount(accountIDA, subjectA)
	server.failNextSQL(credentialCommitSQL)
	handle := openPersistenceContractHandle(t, server.URL)
	next := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 32, 25))
	err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: persistenceAccountID(t, accountIDA), Next: next})
	if !errors.Is(err, storage.ErrPersistenceUnknown) {
		t.Fatalf("CommitProviderCredential() error = %v, want ErrPersistenceUnknown", err)
	}
	if got := countPersistenceSQL(server.persistenceRecords(), credentialCommitSQL); got != 1 {
		t.Fatalf("credential mutation attempts = %d, want 1", got)
	}
	for _, raw := range []string{"raw", "synthetic-token", "SELECT", "private marker", accountIDA, next.String()} {
		if strings.Contains(err.Error(), raw) || len(err.Error()) > 128 {
			t.Fatal("credential mutation error reflected a remote diagnostic")
		}
	}
}

func TestProviderCredentialCancellationAfterMutationStartsIsBoundedAndNeverReplayed(t *testing.T) {
	server := newMigrationProtocolServer(t)
	server.seedAccount(accountIDA, subjectA)
	started, release := server.stallPersistence(credentialCommitSQL)
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	handle := openPersistenceContractHandle(t, server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	next := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 32, 7))
	accountID := persistenceAccountID(t, accountIDA)
	result := make(chan error, 1)
	go func() {
		result <- handle.CommitProviderCredential(ctx, storage.ProviderCredentialCommit{AccountID: accountID, Next: next})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("CommitProviderCredential() did not reach the named mutation stage")
	}
	canceledAt := time.Now()
	cancel()
	var err error
	select {
	case err = <-result:
	case <-time.After(time.Second):
		t.Fatal("CommitProviderCredential() did not return after cancellation")
	}
	if elapsed := time.Since(canceledAt); elapsed >= 500*time.Millisecond {
		t.Fatalf("CommitProviderCredential() cancellation elapsed = %v, want bounded return", elapsed)
	}
	if !errors.Is(err, storage.ErrPersistenceUnknown) || !errors.Is(err, context.Canceled) {
		t.Fatalf("CommitProviderCredential() error = %v, want unknown outcome with cancellation", err)
	}
	if got := countPersistenceSQL(server.persistenceRecords(), credentialCommitSQL); got != 1 {
		t.Fatalf("same-invocation credential attempts = %d, want 1", got)
	}
	releaseOnce.Do(func() { close(release) })
}

func TestProviderCredentialProtocolBaseURLCanChangeAuthority(t *testing.T) {
	var destinationRequests atomic.Int32
	var mutationRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destinationRequests.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("credential-free persistence request sent an Authorization header")
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			t.Errorf("read changed-authority request: %v", err)
		}
		if strings.Contains(string(body), credentialCommitSQL) {
			mutationRequests.Add(1)
		}
		http.Error(w, "raw changed-authority credential marker", http.StatusBadGateway)
	}))
	t.Cleanup(destination.Close)

	server := newMigrationProtocolServer(t)
	server.seedAccount(accountIDA, subjectA)
	server.redirectNextCursorBaseURL(destination.URL)
	handle := openPersistenceContractHandle(t, server.URL)
	next := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 32, 8))
	err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: persistenceAccountID(t, accountIDA), Next: next})
	if !errors.Is(err, storage.ErrPersistenceInspect) {
		t.Fatalf("CommitProviderCredential() error = %v, want ErrPersistenceInspect", err)
	}
	if destinationRequests.Load() == 0 || mutationRequests.Load() != 0 {
		t.Fatalf("changed-authority requests = %d and mutations = %d, want preflight failure before mutation", destinationRequests.Load(), mutationRequests.Load())
	}
	for _, raw := range []string{"changed-authority", accountIDA, next.String()} {
		if strings.Contains(err.Error(), raw) {
			t.Fatalf("sanitized error %q contains raw marker", err)
		}
	}
}

func TestProviderCredentialDriverFollowsCredentialFreeRedirect(t *testing.T) {
	var redirectedRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedRequests.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("credential-free redirected request sent an Authorization header")
		}
		http.Error(w, "raw redirect credential marker", http.StatusBadGateway)
	}))
	t.Cleanup(destination.Close)
	initial := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(initial.Close)

	handle := openPersistenceContractHandle(t, initial.URL)
	_, err := handle.GetProviderCredential(context.Background(), persistenceAccountID(t, accountIDA))
	if !errors.Is(err, storage.ErrPersistenceInspect) {
		t.Fatalf("GetProviderCredential() error = %v, want ErrPersistenceInspect", err)
	}
	if redirectedRequests.Load() != 1 {
		t.Fatalf("redirected persistence requests = %d, want 1 without replay", redirectedRequests.Load())
	}
	if strings.Contains(err.Error(), "redirect credential") || strings.Contains(err.Error(), accountIDA) {
		t.Fatalf("sanitized error %q contains raw marker", err)
	}
}

func TestProviderCredentialRejectsDriverBufferedOversizedSuccessfulValue(t *testing.T) {
	server := newMigrationProtocolServer(t)
	server.seedAccount(accountIDA, subjectA)
	server.overridePersistenceRows(credentialLookupSQL, [][]any{credentialRow(accountIDA, "active", strings.Repeat("A", 1<<20))})
	handle := openPersistenceContractHandle(t, server.URL)
	_, err := handle.GetProviderCredential(context.Background(), persistenceAccountID(t, accountIDA))
	if !errors.Is(err, storage.ErrPersistenceInspect) || len(err.Error()) > 128 {
		t.Fatalf("GetProviderCredential() error = %v, want bounded inspect category", err)
	}
	if got := countPersistenceSQL(server.persistenceRecords(), credentialCommitSQL); got != 0 {
		t.Fatalf("credential mutation attempts = %d, want 0", got)
	}
}

func TestProviderCredentialRejectsRemoteOrCredentialedHandlesBeforeConnection(t *testing.T) {
	database := &migrationFakeDatabase{}
	adapter, err := newAdapter(Options{PersistenceTimeout: time.Second}, func(string, string) databaseHandle { return database })
	if err != nil {
		t.Fatalf("newAdapter() error = %v", err)
	}
	accountID := persistenceAccountID(t, accountIDA)
	next := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 32, 9))
	for _, endpoint := range []storage.Endpoint{
		{URL: "https://database.example", Token: "synthetic-token"},
		{URL: "https://database.example"},
	} {
		handle, openErr := adapter.Open(context.Background(), endpoint)
		if openErr != nil {
			t.Fatalf("Open() error = %v", openErr)
		}
		if _, operationErr := handle.GetProviderCredential(context.Background(), accountID); !errors.Is(operationErr, storage.ErrPersistenceNotAllowed) {
			t.Fatalf("GetProviderCredential() error = %v, want ErrPersistenceNotAllowed", operationErr)
		}
		if operationErr := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: accountID, Next: next}); !errors.Is(operationErr, storage.ErrPersistenceNotAllowed) {
			t.Fatalf("CommitProviderCredential() error = %v, want ErrPersistenceNotAllowed", operationErr)
		}
	}
	if calls := database.connCalls.Load(); calls != 0 {
		t.Fatalf("credential connection attempts = %d, want 0", calls)
	}
}

func TestProviderCredentialConnectionFailureIsSanitized(t *testing.T) {
	const raw = "raw private credential diagnostic"
	database := &migrationFakeDatabase{conn: func(context.Context) (*sql.Conn, error) {
		return nil, errors.New(raw)
	}}
	adapter, err := newAdapter(Options{PersistenceTimeout: time.Second}, func(string, string) databaseHandle { return database })
	if err != nil {
		t.Fatalf("newAdapter() error = %v", err)
	}
	handle, err := adapter.Open(context.Background(), storage.Endpoint{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	_, err = handle.GetProviderCredential(context.Background(), persistenceAccountID(t, accountIDA))
	if !errors.Is(err, storage.ErrPersistenceAcquire) || strings.Contains(err.Error(), raw) {
		t.Fatalf("GetProviderCredential() error = %v, want sanitized acquire category", err)
	}
}

func TestCredentialBehaviorContractAcrossFakeAndExactDriver(t *testing.T) {
	t.Run("fake", func(t *testing.T) { runCredentialBehaviorContract(t, storagefake.New()) })
	t.Run("exact driver", func(t *testing.T) {
		server := newMigrationProtocolServer(t)
		runCredentialBehaviorContract(t, openPersistenceContractHandle(t, server.URL))
	})
}

func runCredentialBehaviorContract(t *testing.T, handle storage.Handle) {
	t.Helper()
	account := persistenceSeed(t, accountIDA, subjectA)
	missingID := persistenceAccountID(t, accountIDB)
	first := mustCredentialEnvelope(t, structuralCredentialEnvelope("old", 32, 4))
	if _, err := handle.GetProviderCredential(context.Background(), missingID); !errors.Is(err, storage.ErrAccountNotFound) {
		t.Fatalf("missing-account lookup error = %v, want ErrAccountNotFound", err)
	}
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: missingID, Next: first}); !errors.Is(err, storage.ErrAccountNotFound) {
		t.Fatalf("missing-account commit error = %v, want ErrAccountNotFound", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := handle.GetProviderCredential(canceled, missingID); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled lookup error = %v, want context cancellation", err)
	}
	if err := handle.CommitProviderCredential(canceled, storage.ProviderCredentialCommit{AccountID: missingID, Next: first}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled commit error = %v, want context cancellation", err)
	}
	if _, err := handle.GetProviderCredential(context.Background(), storage.AccountID{}); !errors.Is(err, storage.ErrInvalidValue) {
		t.Fatalf("invalid lookup error = %v, want ErrInvalidValue", err)
	}
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{}); !errors.Is(err, storage.ErrInvalidValue) {
		t.Fatalf("invalid commit error = %v, want ErrInvalidValue", err)
	}
	if _, err := handle.EnsureAccount(context.Background(), account); err != nil {
		t.Fatal(err)
	}
	if _, err := handle.GetProviderCredential(context.Background(), account.ID); !errors.Is(err, storage.ErrCredentialNotFound) {
		t.Fatalf("absent credential error = %v", err)
	}
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: account.ID, Next: first}); err != nil {
		t.Fatal(err)
	}
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: account.ID, Next: first}); err != nil {
		t.Fatalf("idempotent initialization error = %v", err)
	}
	second := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 32, 5))
	third := mustCredentialEnvelope(t, structuralCredentialEnvelope("active", 32, 6))
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: account.ID, Next: second}); !errors.Is(err, storage.ErrCredentialConflict) {
		t.Fatalf("blind replacement error = %v, want ErrCredentialConflict", err)
	}
	stale := mustCredentialEnvelope(t, structuralCredentialEnvelope("old", 32, 24))
	if err := handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: account.ID, Expected: &stale, Next: second}); !errors.Is(err, storage.ErrCredentialConflict) {
		t.Fatalf("stale replacement error = %v, want ErrCredentialConflict", err)
	}
	stored, err := handle.GetProviderCredential(context.Background(), account.ID)
	if err != nil || stored.AccountID != account.ID || stored.KeyID != first.KeyID() || stored.Envelope != first {
		t.Fatalf("exact retrieval = (%#v, %v), want first ciphertext", stored, err)
	}
	start := make(chan struct{})
	ready := sync.WaitGroup{}
	ready.Add(2)
	results := make(chan error, 2)
	for _, next := range []storage.CredentialEnvelope{second, third} {
		go func(next storage.CredentialEnvelope) {
			ready.Done()
			<-start
			results <- handle.CommitProviderCredential(context.Background(), storage.ProviderCredentialCommit{AccountID: account.ID, Expected: &first, Next: next})
		}(next)
	}
	ready.Wait()
	close(start)
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		} else if !errors.Is(err, storage.ErrCredentialConflict) && !errors.Is(err, storage.ErrPersistenceUnknown) {
			t.Fatalf("concurrent credential error = %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent credential successes = %d, want 1", successes)
	}
}

func structuralCredentialEnvelope(keyID string, plaintextBytes int, fill byte) string {
	binary := []byte{'I', 'G', 'C', 0, 1, 1, byte(len(keyID))}
	binary = append(binary, keyID...)
	binary = append(binary, make([]byte, 12+plaintextBytes+16)...)
	for index := 7 + len(keyID); index < len(binary); index++ {
		binary[index] = fill
	}
	return "igc1." + base64.RawURLEncoding.EncodeToString(binary)
}

type syntheticDecryptKey struct {
	id   string
	seed byte
}

func syntheticKeyringText(active string, seed byte, decrypt ...syntheticDecryptKey) string {
	key := bytes.Repeat([]byte{seed}, cryptobox.KeyBytes)
	result := "igk1:" + active + "=" + base64.RawURLEncoding.EncodeToString(key)
	clear(key)
	for _, entry := range decrypt {
		key = bytes.Repeat([]byte{entry.seed}, cryptobox.KeyBytes)
		result += "," + entry.id + "=" + base64.RawURLEncoding.EncodeToString(key)
		clear(key)
	}
	return result
}

func mustCredentialEnvelope(t *testing.T, text string) storage.CredentialEnvelope {
	t.Helper()
	envelope, err := storage.ParseCredentialEnvelope(text)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func credentialRow(accountID, keyID, envelope string) []any {
	return []any{integerValue(1), integerValue(1), textValue(accountID), integerValue(1), textValue(accountID), textValue(keyID), textValue(envelope)}
}
