-- SPDX-License-Identifier: Apache-2.0
-- Descripteurs d'applis créés dans l'UI d'administration, et leur historique.
-- Aucun secret : un descripteur ne référence les identifiants que par nom de clé.

CREATE TABLE app_descriptors (
    app_id     text        PRIMARY KEY,
    revision   integer     NOT NULL,
    document   jsonb       NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text
);

-- Historique en ajout seul ; son identifiant sert de version au rechargement à chaud.
CREATE TABLE app_descriptor_history (
    id         bigserial   PRIMARY KEY,
    app_id     text        NOT NULL,
    revision   integer     NOT NULL,
    action     text        NOT NULL CHECK (action IN ('created', 'updated', 'deleted')),
    document   jsonb,
    changed_at timestamptz NOT NULL DEFAULT now(),
    changed_by text
);
CREATE INDEX app_descriptor_history_app ON app_descriptor_history (app_id, id);
