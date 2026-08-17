CREATE TABLE inboxgate_accounts (
    account_id TEXT PRIMARY KEY CHECK (length(CAST(account_id AS BLOB)) = 32 AND instr(CAST(account_id AS BLOB), x'00') = 0 AND account_id NOT GLOB '*[^0-9a-f]*'),
    provider TEXT NOT NULL CHECK (provider = 'gmail'),
    provider_subject TEXT COLLATE BINARY NOT NULL CHECK (length(CAST(provider_subject AS BLOB)) BETWEEN 1 AND 255 AND instr(CAST(provider_subject AS BLOB), x'00') = 0 AND provider_subject NOT GLOB '*[^!-~]*'),
    UNIQUE (provider, provider_subject)
) STRICT, WITHOUT ROWID;

CREATE TABLE inboxgate_synchronization_cursors (
    account_id TEXT PRIMARY KEY,
    history_id TEXT COLLATE BINARY NOT NULL CHECK (
        length(CAST(history_id AS BLOB)) BETWEEN 1 AND 20
        AND instr(CAST(history_id AS BLOB), x'00') = 0
        AND history_id NOT GLOB '*[^0-9]*'
        AND substr(history_id, 1, 1) BETWEEN '1' AND '9'
        AND (length(CAST(history_id AS BLOB)) < 20 OR history_id <= '18446744073709551615')
    ),
    FOREIGN KEY (account_id) REFERENCES inboxgate_accounts (account_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;
