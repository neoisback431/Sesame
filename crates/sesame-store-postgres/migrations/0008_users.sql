-- SPDX-License-Identifier: Apache-2.0
-- Annuaire des utilisateurs connus (ADR 0031) : nom et e-mail déclarés par le fournisseur
-- d'identité, écrits par le portail à chaque connexion, lus par l'administration pour afficher
-- « Nom Prénom » à la place de la clé utilisateur. Aucun secret, aucune autorisation.

CREATE TABLE users (
    user_key      text        PRIMARY KEY,
    display_name  text,
    email         text,
    last_login_at timestamptz NOT NULL DEFAULT now()
);
