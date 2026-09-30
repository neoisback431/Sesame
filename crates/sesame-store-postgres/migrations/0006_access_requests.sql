-- SPDX-License-Identifier: Apache-2.0
-- Demandes d'accès depuis « Mes applications » (ADR 0029). Aucun secret : les identifiants
-- fournis par l'utilisateur vont dans app_secrets, le compte reste `pending` jusqu'à validation.

ALTER TABLE app_accounts DROP CONSTRAINT app_accounts_status_check;
ALTER TABLE app_accounts ADD CONSTRAINT app_accounts_status_check
    CHECK (status IN ('active', 'failed', 'disabled', 'pending'));

CREATE TABLE access_requests (
    app_id      text        NOT NULL,
    user_key    text        NOT NULL,
    kind        text        NOT NULL CHECK (kind IN ('credentials', 'no_account')),
    status      text        NOT NULL DEFAULT 'open'
                            CHECK (status IN ('open', 'approved', 'rejected', 'fulfilled')),
    note        text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    resolved_by text,
    PRIMARY KEY (app_id, user_key)
);
CREATE INDEX access_requests_open ON access_requests (created_at) WHERE status = 'open';
