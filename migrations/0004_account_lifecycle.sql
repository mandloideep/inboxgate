CREATE TABLE inboxgate_account_lifecycle (
    account_id TEXT PRIMARY KEY CHECK (length(CAST(account_id AS BLOB)) = 32 AND instr(CAST(account_id AS BLOB), x'00') = 0 AND account_id NOT GLOB '*[^0-9a-f]*'),
    state TEXT COLLATE BINARY NOT NULL CHECK (state IN ('pending', 'active', 'paused', 'reauthorization_required', 'revoked')),
    state_version INTEGER NOT NULL CHECK (typeof(state_version) = 'integer' AND state_version BETWEEN 1 AND 9223372036854775807),
    reauthorization_reason TEXT COLLATE BINARY CHECK (
        (state = 'reauthorization_required' AND (
            reauthorization_reason = 'refresh_invalid_grant'
            OR reauthorization_reason = 'refresh_admin_policy_enforced'
            OR reauthorization_reason = 'gmail_unauthorized_after_refresh'
            OR reauthorization_reason = 'gmail_domain_policy'
        ))
        OR (state <> 'reauthorization_required' AND reauthorization_reason IS NULL)
    ),
    revocation_status TEXT COLLATE BINARY NOT NULL CHECK (
        (state = 'revoked' AND revocation_status IN ('pending', 'attempting', 'confirmed', 'manual_action_required'))
        OR (state <> 'revoked' AND revocation_status = 'none')
    ),
    FOREIGN KEY (account_id) REFERENCES inboxgate_accounts (account_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

INSERT INTO inboxgate_account_lifecycle (account_id, state, state_version, reauthorization_reason, revocation_status)
SELECT
    account_id,
    CASE
        WHEN EXISTS (SELECT 1 FROM inboxgate_synchronization_cursors AS cursors WHERE cursors.account_id = inboxgate_accounts.account_id)
         AND EXISTS (SELECT 1 FROM inboxgate_provider_credentials AS credentials WHERE credentials.account_id = inboxgate_accounts.account_id)
        THEN 'active'
        ELSE 'pending'
    END,
    1,
    NULL,
    'none'
FROM inboxgate_accounts;

CREATE TRIGGER inboxgate_accounts_lifecycle_after_insert
AFTER INSERT ON inboxgate_accounts
BEGIN
    INSERT INTO inboxgate_account_lifecycle (account_id, state, state_version, reauthorization_reason, revocation_status)
    VALUES (NEW.account_id, 'pending', 1, NULL, 'none');
END;
