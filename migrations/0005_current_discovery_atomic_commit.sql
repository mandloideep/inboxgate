CREATE TABLE inboxgate_messages (
    record_id TEXT COLLATE BINARY PRIMARY KEY CHECK (
        length(CAST(record_id AS BLOB)) = 64
        AND instr(CAST(record_id AS BLOB), x'00') = 0
        AND record_id NOT GLOB '*[^0-9a-f]*'
    ),
    account_id TEXT NOT NULL CHECK (
        length(CAST(account_id AS BLOB)) = 32
        AND instr(CAST(account_id AS BLOB), x'00') = 0
        AND account_id NOT GLOB '*[^0-9a-f]*'
    ),
    gmail_message_id TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(gmail_message_id AS BLOB)) BETWEEN 1 AND 255
        AND instr(CAST(gmail_message_id AS BLOB), x'00') = 0
        AND gmail_message_id NOT GLOB '*[^!-~]*'
    ),
    gmail_thread_id TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(gmail_thread_id AS BLOB)) BETWEEN 1 AND 255
        AND instr(CAST(gmail_thread_id AS BLOB), x'00') = 0
        AND gmail_thread_id NOT GLOB '*[^!-~]*'
    ),
    metadata_version INTEGER NOT NULL CHECK (typeof(metadata_version) = 'integer' AND metadata_version = 1),
    metadata_json TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(metadata_json AS BLOB)) BETWEEN 1 AND 65536
        AND instr(CAST(metadata_json AS BLOB), x'00') = 0
    ),
    metadata_hash TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(metadata_hash AS BLOB)) = 64
        AND instr(CAST(metadata_hash AS BLOB), x'00') = 0
        AND metadata_hash NOT GLOB '*[^0-9a-f]*'
    ),
    UNIQUE (account_id, gmail_message_id),
    FOREIGN KEY (account_id) REFERENCES inboxgate_accounts (account_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE inboxgate_current_sync_attempts (
    account_id TEXT PRIMARY KEY CHECK (
        length(CAST(account_id AS BLOB)) = 32
        AND instr(CAST(account_id AS BLOB), x'00') = 0
        AND account_id NOT GLOB '*[^0-9a-f]*'
    ),
    attempt_id TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(attempt_id AS BLOB)) = 64
        AND instr(CAST(attempt_id AS BLOB), x'00') = 0
        AND attempt_id NOT GLOB '*[^0-9a-f]*'
    ),
    expected_history_id TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(expected_history_id AS BLOB)) BETWEEN 1 AND 20
        AND instr(CAST(expected_history_id AS BLOB), x'00') = 0
        AND expected_history_id NOT GLOB '*[^0-9]*'
        AND substr(expected_history_id, 1, 1) BETWEEN '1' AND '9'
        AND (length(CAST(expected_history_id AS BLOB)) < 20 OR expected_history_id <= '18446744073709551615')
    ),
    next_history_id TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(next_history_id AS BLOB)) BETWEEN 1 AND 20
        AND instr(CAST(next_history_id AS BLOB), x'00') = 0
        AND next_history_id NOT GLOB '*[^0-9]*'
        AND substr(next_history_id, 1, 1) BETWEEN '1' AND '9'
        AND (length(CAST(next_history_id AS BLOB)) < 20 OR next_history_id <= '18446744073709551615')
        AND (length(next_history_id) > length(expected_history_id) OR (length(next_history_id) = length(expected_history_id) AND next_history_id > expected_history_id))
    ),
    message_count INTEGER NOT NULL CHECK (typeof(message_count) = 'integer' AND message_count BETWEEN 0 AND 5000),
    encoded_bytes INTEGER NOT NULL CHECK (typeof(encoded_bytes) = 'integer' AND encoded_bytes BETWEEN 0 AND 16777216),
    manifest_hash TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(manifest_hash AS BLOB)) = 64
        AND instr(CAST(manifest_hash AS BLOB), x'00') = 0
        AND manifest_hash NOT GLOB '*[^0-9a-f]*'
    ),
    manifest_witness TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(manifest_witness AS BLOB)) = 78 + (2 * encoded_bytes)
        AND length(CAST(manifest_witness AS BLOB)) BETWEEN 78 AND 33554510
        AND instr(CAST(manifest_witness AS BLOB), x'00') = 0
        AND manifest_witness NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT COLLATE BINARY NOT NULL CHECK (state IN ('open', 'sealed')),
    UNIQUE (account_id),
    UNIQUE (account_id, attempt_id),
    FOREIGN KEY (account_id) REFERENCES inboxgate_accounts (account_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE inboxgate_current_sync_staging (
    account_id TEXT NOT NULL,
    attempt_id TEXT COLLATE BINARY NOT NULL,
    ordinal INTEGER NOT NULL CHECK (typeof(ordinal) = 'integer' AND ordinal BETWEEN 0 AND 4999),
    record_id TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(record_id AS BLOB)) = 64
        AND instr(CAST(record_id AS BLOB), x'00') = 0
        AND record_id NOT GLOB '*[^0-9a-f]*'
    ),
    gmail_message_id TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(gmail_message_id AS BLOB)) BETWEEN 1 AND 255
        AND instr(CAST(gmail_message_id AS BLOB), x'00') = 0
        AND gmail_message_id NOT GLOB '*[^!-~]*'
    ),
    gmail_thread_id TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(gmail_thread_id AS BLOB)) BETWEEN 1 AND 255
        AND instr(CAST(gmail_thread_id AS BLOB), x'00') = 0
        AND gmail_thread_id NOT GLOB '*[^!-~]*'
    ),
    metadata_version INTEGER NOT NULL CHECK (typeof(metadata_version) = 'integer' AND metadata_version = 1),
    metadata_json TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(metadata_json AS BLOB)) BETWEEN 1 AND 65536
        AND instr(CAST(metadata_json AS BLOB), x'00') = 0
    ),
    metadata_hash TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(metadata_hash AS BLOB)) = 64
        AND instr(CAST(metadata_hash AS BLOB), x'00') = 0
        AND metadata_hash NOT GLOB '*[^0-9a-f]*'
    ),
    encoded_bytes INTEGER NOT NULL CHECK (typeof(encoded_bytes) = 'integer' AND encoded_bytes BETWEEN 1 AND 16777216),
    row_witness TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(row_witness AS BLOB)) = 2 * encoded_bytes
        AND length(CAST(row_witness AS BLOB)) BETWEEN 2 AND 33554432
        AND instr(CAST(row_witness AS BLOB), x'00') = 0
        AND row_witness NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (account_id, attempt_id, ordinal),
    UNIQUE (account_id, attempt_id, gmail_message_id),
    UNIQUE (account_id, attempt_id, record_id),
    FOREIGN KEY (account_id, attempt_id) REFERENCES inboxgate_current_sync_attempts (account_id, attempt_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TRIGGER inboxgate_current_sync_attempt_insert_open
BEFORE INSERT ON inboxgate_current_sync_attempts
WHEN NEW.state <> 'open'
BEGIN
    SELECT RAISE(ABORT, 'current discovery attempt must start open');
END;

CREATE TRIGGER inboxgate_current_sync_attempt_seal
BEFORE UPDATE ON inboxgate_current_sync_attempts
BEGIN
    SELECT CASE WHEN NOT (
        OLD.account_id = NEW.account_id
        AND OLD.attempt_id = NEW.attempt_id
        AND OLD.expected_history_id = NEW.expected_history_id
        AND OLD.next_history_id = NEW.next_history_id
        AND OLD.message_count = NEW.message_count
        AND OLD.encoded_bytes = NEW.encoded_bytes
        AND OLD.manifest_hash = NEW.manifest_hash
        AND OLD.manifest_witness = NEW.manifest_witness
        AND OLD.state = 'open'
        AND NEW.state = 'sealed'
        AND (SELECT COUNT(*) FROM inboxgate_current_sync_staging AS staging WHERE staging.account_id = OLD.account_id AND staging.attempt_id = OLD.attempt_id) = OLD.message_count
        AND COALESCE((SELECT SUM(staging.encoded_bytes) FROM inboxgate_current_sync_staging AS staging WHERE staging.account_id = OLD.account_id AND staging.attempt_id = OLD.attempt_id), 0) = OLD.encoded_bytes
        AND (OLD.message_count = 0 OR COALESCE((SELECT MIN(staging.ordinal) FROM inboxgate_current_sync_staging AS staging WHERE staging.account_id = OLD.account_id AND staging.attempt_id = OLD.attempt_id), -1) = 0)
        AND (OLD.message_count = 0 OR COALESCE((SELECT MAX(staging.ordinal) FROM inboxgate_current_sync_staging AS staging WHERE staging.account_id = OLD.account_id AND staging.attempt_id = OLD.attempt_id), -1) = OLD.message_count - 1)
        AND NOT EXISTS (
            SELECT 1
            FROM inboxgate_current_sync_staging AS staging
            WHERE staging.account_id = OLD.account_id
              AND staging.attempt_id = OLD.attempt_id
              AND staging.row_witness <> (
                  printf('%08x', length(CAST(staging.record_id AS BLOB))) || lower(hex(CAST(staging.record_id AS BLOB)))
                  || printf('%08x', length(CAST(staging.gmail_message_id AS BLOB))) || lower(hex(CAST(staging.gmail_message_id AS BLOB)))
                  || printf('%08x', length(CAST(staging.gmail_thread_id AS BLOB))) || lower(hex(CAST(staging.gmail_thread_id AS BLOB)))
                  || printf('%08x', staging.metadata_version)
                  || printf('%08x', length(CAST(staging.metadata_json AS BLOB))) || lower(hex(CAST(staging.metadata_json AS BLOB)))
                  || printf('%08x', length(CAST(staging.metadata_hash AS BLOB))) || lower(hex(CAST(staging.metadata_hash AS BLOB)))
              )
        )
        AND OLD.manifest_witness = '696e626f78676174652f63757272656e742d73796e632d6d616e69666573742f763100' || printf('%08x', OLD.message_count) || COALESCE((
            SELECT group_concat(ordered.row_witness, '')
            FROM (
                SELECT staging.row_witness
                FROM inboxgate_current_sync_staging AS staging
                WHERE staging.account_id = OLD.account_id
                  AND staging.attempt_id = OLD.attempt_id
                ORDER BY staging.ordinal
            ) AS ordered
        ), '')
    ) THEN RAISE(ABORT, 'current discovery seal guard') END;
END;

CREATE TRIGGER inboxgate_current_sync_staging_immutable
BEFORE UPDATE ON inboxgate_current_sync_staging
BEGIN
    SELECT RAISE(ABORT, 'current discovery staging immutable');
END;

CREATE VIEW inboxgate_current_sync_finalize (account_id, attempt_id, manifest_hash) AS
SELECT NULL, NULL, NULL WHERE 0;

CREATE TRIGGER inboxgate_current_sync_finalize_insert
INSTEAD OF INSERT ON inboxgate_current_sync_finalize
BEGIN
    SELECT CASE WHEN (
        SELECT COUNT(*) FROM inboxgate_current_sync_attempts AS attempts
        WHERE attempts.account_id = NEW.account_id
          AND attempts.attempt_id = NEW.attempt_id
          AND attempts.manifest_hash = NEW.manifest_hash
          AND attempts.state = 'sealed'
    ) <> 1 THEN RAISE(ABORT, 'current discovery guard') END;

    SELECT CASE WHEN (
        SELECT COUNT(*) FROM inboxgate_account_lifecycle AS lifecycle
        WHERE lifecycle.account_id = NEW.account_id
          AND lifecycle.state = 'active'
    ) <> 1 THEN RAISE(ABORT, 'current discovery lifecycle') END;

    SELECT CASE WHEN (
        SELECT COUNT(*)
        FROM inboxgate_synchronization_cursors AS cursors
        JOIN inboxgate_current_sync_attempts AS attempts ON attempts.account_id = cursors.account_id
        WHERE attempts.account_id = NEW.account_id
          AND attempts.attempt_id = NEW.attempt_id
          AND cursors.history_id = attempts.expected_history_id
    ) <> 1 THEN RAISE(ABORT, 'current discovery cursor') END;

    SELECT CASE WHEN EXISTS (
        SELECT 1
        FROM inboxgate_current_sync_attempts AS attempts
        WHERE attempts.account_id = NEW.account_id
          AND attempts.attempt_id = NEW.attempt_id
          AND (
              (SELECT COUNT(*) FROM inboxgate_current_sync_staging AS staging WHERE staging.account_id = attempts.account_id AND staging.attempt_id = attempts.attempt_id) <> attempts.message_count
              OR COALESCE((SELECT SUM(staging.encoded_bytes) FROM inboxgate_current_sync_staging AS staging WHERE staging.account_id = attempts.account_id AND staging.attempt_id = attempts.attempt_id), 0) <> attempts.encoded_bytes
              OR (attempts.message_count = 0 AND EXISTS (SELECT 1 FROM inboxgate_current_sync_staging AS staging WHERE staging.account_id = attempts.account_id AND staging.attempt_id = attempts.attempt_id))
              OR (attempts.message_count > 0 AND COALESCE((SELECT MIN(staging.ordinal) FROM inboxgate_current_sync_staging AS staging WHERE staging.account_id = attempts.account_id AND staging.attempt_id = attempts.attempt_id), -1) <> 0)
              OR (attempts.message_count > 0 AND COALESCE((SELECT MAX(staging.ordinal) FROM inboxgate_current_sync_staging AS staging WHERE staging.account_id = attempts.account_id AND staging.attempt_id = attempts.attempt_id), -1) <> attempts.message_count - 1)
              OR attempts.manifest_witness <> '696e626f78676174652f63757272656e742d73796e632d6d616e69666573742f763100' || printf('%08x', attempts.message_count) || COALESCE((
                  SELECT group_concat(ordered.row_witness, '')
                  FROM (
                      SELECT staging.row_witness
                      FROM inboxgate_current_sync_staging AS staging
                      WHERE staging.account_id = attempts.account_id
                        AND staging.attempt_id = attempts.attempt_id
                      ORDER BY staging.ordinal
                  ) AS ordered
              ), '')
          )
    ) THEN RAISE(ABORT, 'current discovery manifest') END;

    SELECT CASE WHEN EXISTS (
        SELECT 1
        FROM inboxgate_current_sync_staging AS staging
        WHERE staging.account_id = NEW.account_id
          AND staging.attempt_id = NEW.attempt_id
          AND staging.row_witness <> (
              printf('%08x', length(CAST(staging.record_id AS BLOB))) || lower(hex(CAST(staging.record_id AS BLOB)))
              || printf('%08x', length(CAST(staging.gmail_message_id AS BLOB))) || lower(hex(CAST(staging.gmail_message_id AS BLOB)))
              || printf('%08x', length(CAST(staging.gmail_thread_id AS BLOB))) || lower(hex(CAST(staging.gmail_thread_id AS BLOB)))
              || printf('%08x', staging.metadata_version)
              || printf('%08x', length(CAST(staging.metadata_json AS BLOB))) || lower(hex(CAST(staging.metadata_json AS BLOB)))
              || printf('%08x', length(CAST(staging.metadata_hash AS BLOB))) || lower(hex(CAST(staging.metadata_hash AS BLOB)))
          )
    ) THEN RAISE(ABORT, 'current discovery integrity') END;

    SELECT CASE WHEN EXISTS (
        SELECT 1
        FROM inboxgate_current_sync_staging AS staging
        JOIN inboxgate_messages AS messages ON messages.record_id = staging.record_id
        WHERE staging.account_id = NEW.account_id
          AND staging.attempt_id = NEW.attempt_id
          AND (messages.account_id <> staging.account_id OR messages.gmail_message_id <> staging.gmail_message_id)
    ) THEN RAISE(ABORT, 'current discovery identity collision') END;

    SELECT CASE WHEN EXISTS (
        SELECT 1
        FROM inboxgate_current_sync_staging AS staging
        JOIN inboxgate_messages AS messages ON messages.account_id = staging.account_id AND messages.gmail_message_id = staging.gmail_message_id
        WHERE staging.account_id = NEW.account_id
          AND staging.attempt_id = NEW.attempt_id
          AND messages.record_id <> staging.record_id
    ) THEN RAISE(ABORT, 'current discovery malformed identity') END;

    SELECT CASE WHEN EXISTS (
        SELECT 1
        FROM inboxgate_current_sync_staging AS staging
        JOIN inboxgate_messages AS messages ON messages.account_id = staging.account_id AND messages.gmail_message_id = staging.gmail_message_id
        WHERE staging.account_id = NEW.account_id
          AND staging.attempt_id = NEW.attempt_id
          AND messages.gmail_thread_id <> staging.gmail_thread_id
    ) THEN RAISE(ABORT, 'current discovery thread drift') END;

    INSERT INTO inboxgate_messages (record_id, account_id, gmail_message_id, gmail_thread_id, metadata_version, metadata_json, metadata_hash)
    SELECT staging.record_id, staging.account_id, staging.gmail_message_id, staging.gmail_thread_id, staging.metadata_version, staging.metadata_json, staging.metadata_hash
    FROM inboxgate_current_sync_staging AS staging
    WHERE staging.account_id = NEW.account_id
      AND staging.attempt_id = NEW.attempt_id
    ON CONFLICT (account_id, gmail_message_id) DO UPDATE SET
        metadata_version = excluded.metadata_version,
        metadata_json = excluded.metadata_json,
        metadata_hash = excluded.metadata_hash
    WHERE inboxgate_messages.record_id = excluded.record_id
      AND inboxgate_messages.gmail_thread_id = excluded.gmail_thread_id;

    UPDATE inboxgate_synchronization_cursors
    SET history_id = (
        SELECT attempts.next_history_id
        FROM inboxgate_current_sync_attempts AS attempts
        WHERE attempts.account_id = NEW.account_id
          AND attempts.attempt_id = NEW.attempt_id
    )
    WHERE account_id = NEW.account_id
      AND history_id = (
          SELECT attempts.expected_history_id
          FROM inboxgate_current_sync_attempts AS attempts
          WHERE attempts.account_id = NEW.account_id
            AND attempts.attempt_id = NEW.attempt_id
      );

    SELECT CASE WHEN changes() <> 1 THEN RAISE(ABORT, 'current discovery cursor update') END;

    DELETE FROM inboxgate_current_sync_staging
    WHERE account_id = NEW.account_id
      AND attempt_id = NEW.attempt_id;

    DELETE FROM inboxgate_current_sync_attempts
    WHERE account_id = NEW.account_id
      AND attempt_id = NEW.attempt_id;
END;

CREATE VIEW inboxgate_current_sync_abort (account_id, attempt_id) AS
SELECT NULL, NULL WHERE 0;

CREATE TRIGGER inboxgate_current_sync_abort_insert
INSTEAD OF INSERT ON inboxgate_current_sync_abort
BEGIN
    SELECT CASE WHEN (
        SELECT COUNT(*)
        FROM inboxgate_current_sync_attempts AS attempts
        JOIN inboxgate_synchronization_cursors AS cursors ON cursors.account_id = attempts.account_id
        WHERE attempts.account_id = NEW.account_id
          AND attempts.attempt_id = NEW.attempt_id
          AND attempts.state = 'open'
          AND cursors.history_id = attempts.expected_history_id
          AND EXISTS (
              SELECT 1
              FROM inboxgate_account_lifecycle AS lifecycle
              WHERE lifecycle.account_id = attempts.account_id
                AND lifecycle.state = 'active'
          )
    ) <> 1 THEN RAISE(ABORT, 'current discovery abort guard') END;

    DELETE FROM inboxgate_current_sync_staging
    WHERE account_id = NEW.account_id
      AND attempt_id = NEW.attempt_id;

    DELETE FROM inboxgate_current_sync_attempts
    WHERE account_id = NEW.account_id
      AND attempt_id = NEW.attempt_id
      AND state = 'open';
END;

CREATE TRIGGER inboxgate_account_lifecycle_current_sync_cleanup
AFTER UPDATE OF state ON inboxgate_account_lifecycle
WHEN NEW.state = 'revoked'
BEGIN
    DELETE FROM inboxgate_current_sync_staging
    WHERE account_id = NEW.account_id;

    DELETE FROM inboxgate_current_sync_attempts
    WHERE account_id = NEW.account_id;
END;
