CREATE TABLE inboxgate_candidate_content (
    record_id TEXT COLLATE BINARY PRIMARY KEY CHECK (
        length(CAST(record_id AS BLOB)) = 64
        AND instr(CAST(record_id AS BLOB), x'00') = 0
        AND record_id NOT GLOB '*[^0-9a-f]*'
    ),
    extractor_version INTEGER NOT NULL CHECK (
        typeof(extractor_version) = 'integer'
        AND extractor_version = 1
    ),
    source_metadata_hash TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(source_metadata_hash AS BLOB)) = 64
        AND instr(CAST(source_metadata_hash AS BLOB), x'00') = 0
        AND source_metadata_hash NOT GLOB '*[^0-9a-f]*'
    ),
    gate_version INTEGER NOT NULL CHECK (
        typeof(gate_version) = 'integer'
        AND gate_version BETWEEN 1 AND 4294967295
    ),
    gate_input_hash TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(gate_input_hash AS BLOB)) = 64
        AND instr(CAST(gate_input_hash AS BLOB), x'00') = 0
        AND gate_input_hash NOT GLOB '*[^0-9a-f]*'
    ),
    source_kind TEXT COLLATE BINARY NOT NULL CHECK (
        source_kind IN ('text_plain', 'text_html')
    ),
    excerpt TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(excerpt AS BLOB)) BETWEEN 1 AND 65536
        AND instr(CAST(excerpt AS BLOB), x'00') = 0
    ),
    excerpt_bytes INTEGER NOT NULL CHECK (
        typeof(excerpt_bytes) = 'integer'
        AND excerpt_bytes BETWEEN 1 AND 65536
        AND excerpt_bytes = length(CAST(excerpt AS BLOB))
    ),
    excerpt_limit INTEGER NOT NULL CHECK (
        typeof(excerpt_limit) = 'integer'
        AND excerpt_limit BETWEEN 1024 AND 65536
        AND excerpt_bytes <= excerpt_limit
    ),
    truncated INTEGER NOT NULL CHECK (
        typeof(truncated) = 'integer'
        AND truncated IN (0, 1)
    ),
    content_hash TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(content_hash AS BLOB)) = 64
        AND instr(CAST(content_hash AS BLOB), x'00') = 0
        AND content_hash NOT GLOB '*[^0-9a-f]*'
    ),
    fetched_at_unix_ms INTEGER NOT NULL CHECK (
        typeof(fetched_at_unix_ms) = 'integer'
        AND fetched_at_unix_ms BETWEEN 0 AND 253402300799999
    ),
    FOREIGN KEY (record_id) REFERENCES inboxgate_messages (record_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;
