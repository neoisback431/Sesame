-- SPDX-License-Identifier: Apache-2.0
-- Notifications par mail à l'administration (ADR 0030). Aucun secret.
--
-- `notifications` est une boîte d'envoi (outbox) : le portail et le proxy y déposent un
-- événement, le worker de l'administration l'envoie en SMTP puis le marque. Un SMTP en
-- panne ne bloque donc jamais une connexion ni un rejeu.
CREATE TABLE notifications (
    id         BIGSERIAL   PRIMARY KEY,
    event      TEXT        NOT NULL
               CHECK (event IN ('access_requested', 'account_failed', 'upstream_unreachable', 'admin_sensitive')),
    app_id     TEXT,
    user_key   TEXT,
    -- Code court (jamais un contenu de réponse ni un secret).
    reason     TEXT,
    -- Administrateur à l'origine de l'action (événements `admin_sensitive` seulement).
    actor      TEXT,
    status     TEXT        NOT NULL DEFAULT 'pending'
               CHECK (status IN ('pending', 'sent', 'failed', 'skipped')),
    attempts   INTEGER     NOT NULL DEFAULT 0,
    last_error TEXT,
    -- Prochaine tentative d'envoi (reprise avec attente croissante, ou bail pris par un worker).
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at    TIMESTAMPTZ
);
CREATE INDEX notifications_pending ON notifications (next_attempt_at) WHERE status = 'pending';
CREATE INDEX notifications_dedupe ON notifications (event, app_id, user_key, created_at);

-- Réglages, modifiables dans la console d'administration : une seule ligne. Le mot de passe
-- SMTP n'est jamais en base (variable d'environnement de l'admin).
CREATE TABLE notification_settings (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    enabled       BOOLEAN     NOT NULL DEFAULT false,
    smtp_host     TEXT        NOT NULL DEFAULT '',
    smtp_port     INTEGER     NOT NULL DEFAULT 587,
    smtp_security TEXT        NOT NULL DEFAULT 'starttls' CHECK (smtp_security IN ('starttls', 'tls', 'none')),
    smtp_user     TEXT        NOT NULL DEFAULT '',
    from_address  TEXT        NOT NULL DEFAULT '',
    recipients    TEXT[]      NOT NULL DEFAULT '{}',
    events        TEXT[]      NOT NULL DEFAULT '{access_requested,account_failed}',
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by    TEXT
);
INSERT INTO notification_settings (id) VALUES (1);
