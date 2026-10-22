-- SPDX-License-Identifier: Apache-2.0
-- Plusieurs comptes par couple (appli, utilisateur) (ADR 0034). Un compte est désigné par
-- (app_id, user_key, account_id) ; les comptes existants deviennent le compte `default`, compte
-- par défaut du couple. Aucun secret : le libellé est un nom choisi par l'administrateur.

ALTER TABLE app_accounts
    ADD COLUMN account_id text    NOT NULL DEFAULT 'default',
    ADD COLUMN label      text,
    ADD COLUMN is_default boolean NOT NULL DEFAULT false;
UPDATE app_accounts SET is_default = true;
ALTER TABLE app_accounts ADD CONSTRAINT app_accounts_account_id_check
    CHECK (account_id ~ '^[a-z0-9][a-z0-9-]{0,31}$');

-- La clé étrangère des diagnostics vise la clé primaire : on la recrée après coup.
ALTER TABLE replay_diagnostics DROP CONSTRAINT replay_diagnostics_app_id_user_key_fkey;
ALTER TABLE app_accounts DROP CONSTRAINT app_accounts_pkey;
ALTER TABLE app_accounts ADD PRIMARY KEY (app_id, user_key, account_id);
-- Un seul compte par défaut par couple.
CREATE UNIQUE INDEX app_accounts_one_default ON app_accounts (app_id, user_key) WHERE is_default;

ALTER TABLE replay_diagnostics ADD COLUMN account_id text NOT NULL DEFAULT 'default';
ALTER TABLE replay_diagnostics DROP CONSTRAINT replay_diagnostics_pkey;
ALTER TABLE replay_diagnostics ADD PRIMARY KEY (app_id, user_key, account_id);
ALTER TABLE replay_diagnostics ADD FOREIGN KEY (app_id, user_key, account_id)
    REFERENCES app_accounts (app_id, user_key, account_id) ON DELETE CASCADE;

-- Coffre PostgreSQL : un jeu de champs par compte. Le compte `default` garde la donnée
-- authentifiée du chiffrement d'avant (app|user|clé) : aucun rechiffrement.
ALTER TABLE app_secrets ADD COLUMN account_id text NOT NULL DEFAULT 'default';
ALTER TABLE app_secrets DROP CONSTRAINT app_secrets_pkey;
ALTER TABLE app_secrets ADD PRIMARY KEY (app_id, user_key, account_id, key);

-- Compte avec lequel la session applicative a été ouverte : une session ouverte avec un autre
-- compte que le compte choisi est abandonnée par le proxy.
ALTER TABLE app_sessions ADD COLUMN account_id text NOT NULL DEFAULT 'default';

-- Compte choisi par l'utilisateur depuis « Mes applications », pour toutes ses sessions portail.
-- Absent : compte par défaut. Supprimé avec le compte choisi.
CREATE TABLE app_account_selections (
    app_id      text        NOT NULL,
    user_key    text        NOT NULL,
    account_id  text        NOT NULL,
    selected_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (app_id, user_key),
    FOREIGN KEY (app_id, user_key, account_id)
        REFERENCES app_accounts (app_id, user_key, account_id) ON DELETE CASCADE
);
