-- SPDX-License-Identifier: Apache-2.0
-- Enrôlement préalable par e-mail, rattaché à l'identité SSO à la première connexion (ADR 0036).
-- Aucun secret : `enrolments` est écrit par l'administration, `user_aliases` par le portail.

-- Utilisateur enrôlé à la main : `user_key` est la clé sous laquelle comptes et secrets sont
-- rangés (l'e-mail en minuscules) ; `match_value` est la valeur que doit porter l'identité
-- (claim configurable, l'e-mail par défaut) pour réclamer l'enrôlement, une seule fois.
CREATE TABLE enrolments (
    user_key        text        PRIMARY KEY,
    match_value     text        NOT NULL,
    created_by      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    claimed_issuer  text,
    claimed_subject text,
    claimed_at      timestamptz,
    CHECK ((claimed_at IS NULL) = (claimed_subject IS NULL))
);
-- Une même valeur ne peut pas être attendue par deux enrôlements en attente.
CREATE UNIQUE INDEX enrolments_pending_match ON enrolments (lower(match_value)) WHERE claimed_at IS NULL;

-- Identité du fournisseur (issuer, subject) -> clé sous laquelle ses comptes sont rangés.
CREATE TABLE user_aliases (
    issuer    text        NOT NULL,
    subject   text        NOT NULL,
    user_key  text        NOT NULL,
    linked_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (issuer, subject)
);
CREATE INDEX user_aliases_user_key ON user_aliases (user_key);
