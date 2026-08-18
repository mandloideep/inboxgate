CREATE TABLE inboxgate_provider_credentials (
    account_id TEXT PRIMARY KEY CHECK (length(CAST(account_id AS BLOB)) = 32 AND instr(CAST(account_id AS BLOB), x'00') = 0 AND account_id NOT GLOB '*[^0-9a-f]*'),
    key_id TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(key_id AS BLOB)) BETWEEN 1 AND 32
        AND instr(CAST(key_id AS BLOB), x'00') = 0
        AND substr(key_id, 1, 1) GLOB '[a-z]'
        AND key_id NOT GLOB '*[^a-z0-9_-]*'
    ),
    envelope TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(envelope AS BLOB)) BETWEEN 55 AND 5556
        AND instr(CAST(envelope AS BLOB), x'00') = 0
        AND substr(envelope, 1, 5) = 'igc1.'
        AND substr(envelope, 6) NOT GLOB '*[^A-Za-z0-9_-]*'
    ),
    FOREIGN KEY (account_id) REFERENCES inboxgate_accounts (account_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;
