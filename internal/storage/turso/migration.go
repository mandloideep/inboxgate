package turso

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strconv"
	"strings"

	"github.com/mandloideep/inboxgate/internal/storage"
	"github.com/mandloideep/inboxgate/migrations"
)

const (
	ledgerTable        = "inboxgate_schema_migrations"
	beginImmediateSQL  = "BEGIN IMMEDIATE"
	commitSQL          = "COMMIT"
	rollbackSQL        = "ROLLBACK"
	ledgerExistsSQL    = "SELECT 1 FROM sqlite_schema WHERE type = ? AND name = ? LIMIT 1"
	ledgerRowsSQL      = "SELECT number, checksum FROM inboxgate_schema_migrations ORDER BY number LIMIT ?"
	userVersionSQL     = "PRAGMA user_version"
	sequenceInsertSQL  = "INSERT INTO inboxgate_schema_migrations (number, checksum) VALUES ("
	guardTable         = "inboxgate_migration_guard"
	terminalSavepoint  = "inboxgate_migration_terminal"
	terminalGuardTable = "inboxgate_migration_terminal_guard"
)

var (
	ErrMigrationNotAllowed     = errors.New("turso storage: migration not allowed")
	ErrMigrationCatalog        = errors.New("turso storage: migration catalog invalid")
	ErrMigrationAcquire        = errors.New("turso storage: migration connection failed")
	ErrMigrationInspect        = errors.New("turso storage: migration inspection failed")
	ErrMigrationDrift          = errors.New("turso storage: migration drift")
	ErrMigrationUnknownOutcome = errors.New("turso storage: migration outcome unknown")
)

// Migrate reconciles the embedded append-only catalog and verifies each
// purported commit through a separate physical connection.
//
// This operation is limited to credential-free literal-loopback endpoints.
func (h *handle) Migrate(ctx context.Context) (storage.MigrationResult, error) {
	catalog, err := migrations.Catalog()
	if err != nil {
		return storage.MigrationResult{}, ErrMigrationCatalog
	}
	return h.migrateCatalog(ctx, catalog)
}

func (h *handle) migrateCatalog(ctx context.Context, catalog []migrations.Migration) (storage.MigrationResult, error) {
	if !h.migrationAllowed {
		return storage.MigrationResult{}, ErrMigrationNotAllowed
	}
	if err := ctx.Err(); err != nil {
		return storage.MigrationResult{}, safeMigrationError(ErrMigrationAcquire, ctx)
	}

	migrationCtx, cancel := context.WithTimeout(ctx, h.migrationTimeout)
	defer cancel()
	inspectionConnection, err := h.database.Conn(migrationCtx)
	if err != nil {
		return storage.MigrationResult{}, safeMigrationError(ErrMigrationAcquire, migrationCtx)
	}
	initial, err := inspectLedger(migrationCtx, inspectionConnection, catalog)
	_ = inspectionConnection.Close()
	if err != nil {
		return storage.MigrationResult{}, err
	}
	result := storage.MigrationResult{Current: uint16(initial.current)}
	if initial.current == len(catalog) && initial.userVersion == int64(initial.current) {
		return result, nil
	}
	if initial.current == len(catalog) {
		connection, err := h.database.Conn(migrationCtx)
		if err != nil {
			return storage.MigrationResult{}, safeMigrationError(ErrMigrationAcquire, migrationCtx)
		}
		verified, err := h.proveTerminalState(migrationCtx, connection, catalog, uint16(initial.current))
		if err != nil {
			h.attemptRollback(connection)
			discardMigrationConnection(connection)
			return storage.MigrationResult{}, safeMigrationError(ErrMigrationUnknownOutcome, migrationCtx)
		}
		_ = connection.Close()
		return storage.MigrationResult{Current: uint16(verified.current)}, nil
	}

	current := initial.current
	for iteration := 0; iteration <= len(catalog); iteration++ {
		connection, err := h.database.Conn(migrationCtx)
		if err != nil {
			return storage.MigrationResult{}, safeMigrationError(ErrMigrationAcquire, migrationCtx)
		}
		migration := catalog[current]
		sequence, err := migrationSequence(catalog, current)
		if err != nil {
			_ = connection.Close()
			return storage.MigrationResult{}, ErrMigrationCatalog
		}
		if _, err := connection.ExecContext(migrationCtx, sequence); err != nil {
			h.attemptRollback(connection)
			discardMigrationConnection(connection)
			return storage.MigrationResult{}, safeMigrationError(ErrMigrationUnknownOutcome, migrationCtx)
		}
		result.Applied++
		result.Current = migration.Number

		verified, err := h.proveTerminalState(migrationCtx, connection, catalog, migration.Number)
		if err != nil {
			h.attemptRollback(connection)
			discardMigrationConnection(connection)
			return storage.MigrationResult{}, safeMigrationError(ErrMigrationUnknownOutcome, migrationCtx)
		}
		_ = connection.Close()
		result.Current = uint16(verified.current)
		if verified.current == len(catalog) {
			return result, nil
		}
		current = verified.current
	}
	return storage.MigrationResult{}, ErrMigrationDrift
}

const (
	maximumMigrationGuardBytes    = migrations.MaximumCount*192 + 512
	maximumMigrationSequenceBytes = migrations.MaximumFileBytes + maximumMigrationGuardBytes + 256
	maximumTerminalSequenceBytes  = maximumMigrationGuardBytes + 768
)

func migrationSequence(catalog []migrations.Migration, index int) (string, error) {
	if index < 0 || index >= len(catalog) || len(catalog) > migrations.MaximumCount {
		return "", ErrMigrationCatalog
	}
	migration := catalog[index]
	if migration.Number < 1 || migration.Number > migrations.MaximumCount ||
		int(migration.Number) != index+1 ||
		len(migration.Checksum) != sha256HexLength || !isLowerHex(migration.Checksum) ||
		len(migration.SQL) == 0 || len(migration.SQL) > migrations.MaximumFileBytes ||
		!strings.HasSuffix(strings.TrimSpace(migration.SQL), ";") {
		return "", ErrMigrationCatalog
	}
	guard, err := migrationPrefixGuard(catalog[:index])
	if err != nil {
		return "", ErrMigrationCatalog
	}

	var sequence strings.Builder
	sequence.Grow(len(migration.SQL) + len(guard) + 192)
	sequence.WriteString(beginImmediateSQL)
	sequence.WriteString(";\n")
	sequence.WriteString(migration.SQL)
	if !strings.HasSuffix(migration.SQL, "\n") {
		sequence.WriteByte('\n')
	}
	sequence.WriteString("CREATE TEMP TABLE ")
	sequence.WriteString(guardTable)
	sequence.WriteString(" (valid INTEGER NOT NULL CHECK (valid = 1));\n")
	sequence.WriteString("INSERT INTO ")
	sequence.WriteString(guardTable)
	sequence.WriteString(" (valid) SELECT CASE WHEN ")
	sequence.WriteString(guard)
	sequence.WriteString(" THEN 1 ELSE 0 END;\n")
	sequence.WriteString("DROP TABLE temp.")
	sequence.WriteString(guardTable)
	sequence.WriteString(";\n")
	sequence.WriteString(sequenceInsertSQL)
	sequence.WriteString(strconv.FormatUint(uint64(migration.Number), 10))
	sequence.WriteString(", '")
	sequence.WriteString(migration.Checksum)
	sequence.WriteString("');\n")
	sequence.WriteString(commitSQL)
	sequence.WriteByte(';')
	if sequence.Len() > maximumMigrationSequenceBytes {
		return "", ErrMigrationCatalog
	}
	return sequence.String(), nil
}

func migrationPrefixGuard(prefix []migrations.Migration) (string, error) {
	if len(prefix) > migrations.MaximumCount {
		return "", ErrMigrationCatalog
	}
	var guard strings.Builder
	guard.Grow(128 + len(prefix)*112)
	guard.WriteString("(SELECT COUNT(*) FROM ")
	guard.WriteString(ledgerTable)
	guard.WriteString(") = ")
	guard.WriteString(strconv.Itoa(len(prefix)))
	if len(prefix) > 0 {
		guard.WriteString(" AND NOT EXISTS (SELECT 1 FROM ")
		guard.WriteString(ledgerTable)
		guard.WriteString(" WHERE number IS NULL OR checksum IS NULL)")
		for index, applied := range prefix {
			if applied.Number < 1 || int(applied.Number) != index+1 ||
				len(applied.Checksum) != sha256HexLength || !isLowerHex(applied.Checksum) {
				return "", ErrMigrationCatalog
			}
			guard.WriteString(" AND (SELECT COUNT(*) FROM ")
			guard.WriteString(ledgerTable)
			guard.WriteString(" WHERE number = ")
			guard.WriteString(strconv.FormatUint(uint64(applied.Number), 10))
			guard.WriteString(" AND checksum = '")
			guard.WriteString(applied.Checksum)
			guard.WriteString("') = 1")
		}
	}
	if guard.Len() > maximumMigrationGuardBytes {
		return "", ErrMigrationCatalog
	}
	return guard.String(), nil
}

func terminalSequence(prefix []migrations.Migration) (string, error) {
	if len(prefix) == 0 || len(prefix) > migrations.MaximumCount {
		return "", ErrMigrationCatalog
	}
	guard, err := migrationPrefixGuard(prefix)
	if err != nil {
		return "", ErrMigrationCatalog
	}
	number := prefix[len(prefix)-1].Number
	if int(number) != len(prefix) {
		return "", ErrMigrationCatalog
	}
	var sequence strings.Builder
	sequence.Grow(len(guard) + 512)
	sequence.WriteString("SAVEPOINT ")
	sequence.WriteString(terminalSavepoint)
	sequence.WriteString(";\nUPDATE ")
	sequence.WriteString(ledgerTable)
	sequence.WriteString(" SET checksum = checksum WHERE number = ")
	sequence.WriteString(strconv.FormatUint(uint64(number), 10))
	sequence.WriteString(";\nCREATE TEMP TABLE ")
	sequence.WriteString(terminalGuardTable)
	sequence.WriteString(" (valid INTEGER NOT NULL CHECK (valid = 1));\nINSERT INTO ")
	sequence.WriteString(terminalGuardTable)
	sequence.WriteString(" (valid) SELECT CASE WHEN ")
	sequence.WriteString(guard)
	sequence.WriteString(" AND (SELECT COUNT(*) FROM pragma_user_version) = 1 AND (SELECT user_version FROM pragma_user_version) BETWEEN 0 AND ")
	sequence.WriteString(strconv.FormatUint(uint64(number), 10))
	sequence.WriteString(" THEN 1 ELSE 0 END;\nDROP TABLE temp.")
	sequence.WriteString(terminalGuardTable)
	sequence.WriteString(";\nPRAGMA user_version = ")
	sequence.WriteString(strconv.FormatUint(uint64(number), 10))
	sequence.WriteString(";\nRELEASE SAVEPOINT ")
	sequence.WriteString(terminalSavepoint)
	sequence.WriteByte(';')
	if sequence.Len() > maximumTerminalSequenceBytes {
		return "", ErrMigrationCatalog
	}
	return sequence.String(), nil
}

func (h *handle) proveTerminalState(
	ctx context.Context,
	connection *sql.Conn,
	catalog []migrations.Migration,
	number uint16,
) (ledgerState, error) {
	if number == 0 || int(number) > len(catalog) {
		return ledgerState{}, ErrMigrationCatalog
	}
	probe, err := terminalSequence(catalog[:number])
	if err != nil {
		return ledgerState{}, ErrMigrationCatalog
	}
	if _, err := connection.ExecContext(ctx, probe); err != nil {
		return ledgerState{}, ErrMigrationUnknownOutcome
	}
	verificationConnection, err := h.database.Conn(ctx)
	if err != nil {
		return ledgerState{}, ErrMigrationUnknownOutcome
	}
	verified, err := inspectLedger(ctx, verificationConnection, catalog)
	_ = verificationConnection.Close()
	if err != nil || verified.current < int(number) || verified.userVersion != int64(number) {
		return ledgerState{}, ErrMigrationUnknownOutcome
	}
	return verified, nil
}

type ledgerState struct {
	current     int
	userVersion int64
}

func inspectLedger(ctx context.Context, connection *sql.Conn, catalog []migrations.Migration) (ledgerState, error) {
	existsRows, err := connection.QueryContext(ctx, ledgerExistsSQL, "table", ledgerTable)
	if err != nil {
		return ledgerState{}, safeMigrationError(ErrMigrationInspect, ctx)
	}
	exists := false
	count := 0
	for existsRows.Next() {
		count++
		if count > 1 {
			_ = existsRows.Close()
			return ledgerState{}, ErrMigrationDrift
		}
		var marker int64
		if err := existsRows.Scan(&marker); err != nil || marker != 1 {
			_ = existsRows.Close()
			return ledgerState{}, ErrMigrationDrift
		}
		exists = true
	}
	if err := existsRows.Err(); err != nil {
		_ = existsRows.Close()
		return ledgerState{}, safeMigrationError(ErrMigrationInspect, ctx)
	}
	if err := existsRows.Close(); err != nil {
		return ledgerState{}, safeMigrationError(ErrMigrationInspect, ctx)
	}
	current := 0
	if exists {
		rows, err := connection.QueryContext(ctx, ledgerRowsSQL, int64(migrations.MaximumCount+1))
		if err != nil {
			return ledgerState{}, safeMigrationError(ErrMigrationInspect, ctx)
		}
		for rows.Next() {
			current++
			if current > migrations.MaximumCount || current > len(catalog) {
				_ = rows.Close()
				return ledgerState{}, ErrMigrationDrift
			}
			var number int64
			var checksum string
			if err := rows.Scan(&number, &checksum); err != nil {
				_ = rows.Close()
				return ledgerState{}, ErrMigrationDrift
			}
			if number != int64(current) || number < 1 || number > migrations.MaximumCount ||
				len(checksum) != sha256HexLength || !isLowerHex(checksum) || checksum != catalog[current-1].Checksum {
				_ = rows.Close()
				return ledgerState{}, ErrMigrationDrift
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return ledgerState{}, safeMigrationError(ErrMigrationInspect, ctx)
		}
		if err := rows.Close(); err != nil {
			return ledgerState{}, safeMigrationError(ErrMigrationInspect, ctx)
		}
		if current == 0 {
			return ledgerState{}, ErrMigrationDrift
		}
	}
	userVersion, err := inspectUserVersion(ctx, connection)
	if err != nil {
		return ledgerState{}, err
	}
	if userVersion < 0 || userVersion > int64(current) {
		return ledgerState{}, ErrMigrationDrift
	}
	return ledgerState{current: current, userVersion: userVersion}, nil
}

func inspectUserVersion(ctx context.Context, connection *sql.Conn) (int64, error) {
	rows, err := connection.QueryContext(ctx, userVersionSQL)
	if err != nil {
		return 0, safeMigrationError(ErrMigrationInspect, ctx)
	}
	count := 0
	var userVersion int64
	for rows.Next() {
		count++
		if count > 1 || rows.Scan(&userVersion) != nil {
			_ = rows.Close()
			return 0, ErrMigrationDrift
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, safeMigrationError(ErrMigrationInspect, ctx)
	}
	if err := rows.Close(); err != nil {
		return 0, safeMigrationError(ErrMigrationInspect, ctx)
	}
	if count != 1 {
		return 0, ErrMigrationDrift
	}
	return userVersion, nil
}

const sha256HexLength = 64

func isLowerHex(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool {
		return !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f')
	}) == -1
}

func (h *handle) attemptRollback(connection *sql.Conn) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), h.cleanupTimeout)
	defer cancel()
	_, _ = connection.ExecContext(cleanupCtx, rollbackSQL)
}

func discardMigrationConnection(connection *sql.Conn) {
	_ = connection.Raw(func(any) error { return driver.ErrBadConn })
	_ = connection.Close()
}

func safeMigrationError(category error, ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(category, err)
	}
	return category
}
