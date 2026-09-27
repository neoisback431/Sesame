# SPDX-License-Identifier: Apache-2.0
"""Module d'embarquement Sesame.

- ``verify`` : rejoue le login selon un descripteur **sans JavaScript**, comme
  le moteur de proxy, avec un compte de test, pour valider le descripteur avant
  sa mise en service ;
- ``health`` : test de santé périodique sans identifiants, qui compare l'empreinte
  du formulaire de login (HTML brut) à celle du descripteur validé ;
- ``fingerprint`` : calcule l'empreinte actuelle, à reporter dans le descripteur.

Le mot de passe du compte de test n'est jamais écrit : ni dans un fichier, ni
dans la sortie, ni dans les logs. La capture automatique d'un login réel
(Playwright) n'est pas encore disponible ; un descripteur se rédige à partir de
``descriptors/TEMPLATE.yaml.example`` puis se valide avec ``verify``.
"""
