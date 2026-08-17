CREATE TABLE inboxgate_schema_migrations (
    number INTEGER PRIMARY KEY CHECK (number BETWEEN 1 AND 256),
    checksum TEXT NOT NULL CHECK (length(checksum) = 64 AND checksum NOT GLOB '*[^0-9a-f]*')
) STRICT, WITHOUT ROWID;
