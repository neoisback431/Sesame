-- SPDX-License-Identifier: Apache-2.0
-- Magasin de sessions et registre des comptes. Aucun secret en clair.

CREATE TABLE portal_sessions (
    id_hash      text        PRIMARY KEY,  -- SHA-256 du jeton du cookie, jamais le jeton
    issuer       text        NOT NULL,
    subject      text        NOT NULL,
    user_key     text        NOT NULL,
    display_name text,
    groups       text[]      NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL
);
CREATE INDEX portal_sessions_expires_at ON portal_sessions (expires_at);

CREATE TABLE app_sessions (
    portal_session text        NOT NULL REFERENCES portal_sessions (id_hash) ON DELETE CASCADE,
    app_id         text        NOT NULL,
    cookies        bytea       NOT NULL,   -- jar de cookies chiffré (AES-256-GCM)
    created_at     timestamptz NOT NULL,
    last_used_at   timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    PRIMARY KEY (portal_session, app_id)
);
CREATE INDEX app_sessions_expires_at ON app_sessions (expires_at);

CREATE TABLE app_accounts (
    app_id        text        NOT NULL,
    user_key      text        NOT NULL,
    status        text        NOT NULL CHECK (status IN ('active', 'failed', 'disabled')),
    status_reason text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz,
    PRIMARY KEY (app_id, user_key)
);
CREATE INDEX app_accounts_user_key ON app_accounts (user_key);
