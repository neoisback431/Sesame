-- SPDX-License-Identifier: Apache-2.0
-- Une appli par nom d'hôte : deux descripteurs en base ne peuvent pas partager
-- spec.public.host (les collisions avec les fichiers Git sont contrôlées à l'écriture
-- par l'administration et, à défaut, écartées au chargement par le portail et le proxy).
CREATE UNIQUE INDEX app_descriptors_public_host
    ON app_descriptors ((document #>> '{spec,public,host}'));
