CREATE TABLE inboxgate_gate_decisions (
    record_id TEXT COLLATE BINARY PRIMARY KEY CHECK (
        length(CAST(record_id AS BLOB)) = 64
        AND instr(CAST(record_id AS BLOB), x'00') = 0
        AND record_id NOT GLOB '*[^0-9a-f]*'
    ),
    gate_version INTEGER NOT NULL CHECK (gate_version BETWEEN 1 AND 4294967295),
    source_metadata_hash TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(source_metadata_hash AS BLOB)) = 64
        AND instr(CAST(source_metadata_hash AS BLOB), x'00') = 0
        AND source_metadata_hash NOT GLOB '*[^0-9a-f]*'
    ),
    input_hash TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(input_hash AS BLOB)) = 64
        AND instr(CAST(input_hash AS BLOB), x'00') = 0
        AND input_hash NOT GLOB '*[^0-9a-f]*'
    ),
    outcome TEXT COLLATE BINARY NOT NULL CHECK (
        outcome IN ('ignore', 'metadata_only', 'review_candidate', 'urgent_review_candidate')
    ),
    reason_codes TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(reason_codes AS BLOB)) BETWEEN 2 AND 512
        AND instr(CAST(reason_codes AS BLOB), x'00') = 0
    ),
    evaluated_at_unix_ms INTEGER NOT NULL CHECK (
        evaluated_at_unix_ms BETWEEN 0 AND 253402300799999
    ),
    FOREIGN KEY (record_id) REFERENCES inboxgate_messages (record_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;
