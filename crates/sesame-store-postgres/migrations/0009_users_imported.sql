-- SPDX-License-Identifier: Apache-2.0
-- Utilisateurs importés par l'administration avant leur première connexion (ADR 0032) :
-- last_login_at devient facultatif (NULL = jamais connecté). Le portail l'écrit explicitement.

ALTER TABLE users
    ALTER COLUMN last_login_at DROP NOT NULL,
    ALTER COLUMN last_login_at DROP DEFAULT;
