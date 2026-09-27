# SPDX-License-Identifier: Apache-2.0
"""Module d'embarquement Sesame.

- ``capture`` : pilote une connexion réelle (Playwright) avec un compte de test,
  observe le formulaire, les jetons CSRF, le cookie de session, la redirection et
  les signes d'expiration, puis propose un descripteur à relire ;
- ``verify`` : rejoue le login selon un descripteur **sans JavaScript**, comme
  le moteur de proxy, pour valider le descripteur avant sa mise en service ;
- ``health`` : test de santé périodique sans identifiants, qui compare l'empreinte
  du formulaire de login (HTML brut) à celle du descripteur validé.

Le mot de passe du compte de test n'est jamais écrit : ni dans le descripteur,
ni dans le rapport, ni dans les logs.
"""
