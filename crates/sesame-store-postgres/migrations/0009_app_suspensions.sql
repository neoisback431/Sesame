-- SPDX-License-Identifier: Apache-2.0
-- Connexion automatique suspendue (ADR 0033) : après « Déconnecter » sur une tuile de
-- « Mes applications », Sesame ne rejoue plus le login de cet utilisateur sur cette appli, dans
-- aucune de ses sessions portail (autre fenêtre, navigation privée), jusqu'au prochain clic sur
-- la tuile. Aucun secret : une ligne par couple (appli, utilisateur).

CREATE TABLE app_suspensions (
    app_id       text        NOT NULL,
    user_key     text        NOT NULL,
    suspended_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (app_id, user_key)
);
CREATE INDEX app_suspensions_user_key ON app_suspensions (user_key);
