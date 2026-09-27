# 0020. Mode « remise » (handoff) : exception aux principes 1 et 3

**Statut** : acceptée (2026-09-28), implémentée. Révisée le même jour : modèle transparent, sans chemin dédié.

## Contexte

Le mode nominal (proxy) garde la session applicative côté serveur : le navigateur ne voit
jamais ni identifiant, ni cookie, ni jeton de l'appli. Certaines applis ne fonctionnent pas
ainsi :

- SPA qui gardent leur session dans le stockage du navigateur (`localStorage`) et
  l'envoient elles-mêmes en en-tête `Authorization` (cas YAST : `refreshToken` stocké,
  aucune vérification côté serveur au chargement) ;
- applis dont le JavaScript lit ses propres cookies, ou qui utilisent des WebSockets.

Pour elles, le proxy ne peut pas rendre la connexion transparente.

## Décision

Mode facultatif, **par appli**, **désactivé par défaut** : `spec.session.mode: proxy |
handoff` (défaut `proxy`).

**Totalement transparent, sans chemin ni hôte dédié** (révision du 2026-09-28, à la
demande de l'exploitant : la première proposition exposait `/__sesame/handoff` et joignait
l'appli directement). La tuile mène à l'URL normale de l'appli (`public.start_path`), sur
l'hôte public routé vers Sesame comme en mode proxy.

À la **première arrivée** (le navigateur ne présente pas encore le marqueur de remise),
Sesame :

1. vérifie la session portail, le compte actif et l'habilitation (inchangé) ;
2. lit le credential dans le coffre et rejoue le login côté serveur (inchangé, audité) ;
3. **remet** au navigateur l'élément de session déclaré dans le descripteur **et un
   marqueur** (`__sesame_handoff`, `HttpOnly`, TTL = `session.max_ttl`), puis le redirige
   vers l'URL demandée.

Aux **requêtes suivantes** (marqueur présent), Sesame **relaie l'appli de façon
transparente** : le navigateur porte lui-même la session ; ses cookies (le cookie du
portail et le marqueur retirés) et son en-tête `Authorization` sont relayés, les `Set-Cookie` de l'appli
lui reviennent, et Sesame n'injecte ni ne rejoue rien. À l'expiration du marqueur, la
prochaine arrivée redéclenche une remise (nouveau rejeu).

Élément remis, déclaré dans `spec.session.handoff` :

- `set_cookies` : cookies capturés au rejeu, posés sur le domaine de l'appli en `Set-Cookie` ;
- `local_storage` : valeurs lues dans la réponse JSON au login (champ pointé) écrites sous
  une clé du stockage local, par une page de remise qui redirige ensuite vers l'URL demandée.

Le mot de passe applicatif ne quitte **jamais** le serveur (principe 1 maintenu pour
lui). Seul l'élément de session est remis.

## Conséquences (contreparties assumées)

- **Exception au principe 3** et, pour les jetons, à la règle « jamais de jeton vers le
  navigateur » : l'élément remis est visible et copiable par l'utilisateur.
- Déconnexion du portail : le relais exige toujours la session portail, l'accès via
  Sesame est donc coupé aussitôt ; mais la session remise reste valable **côté appli**
  jusqu'à son expiration (Sesame ne la conserve pas et ne l'y ferme pas), ce qui compte
  si l'appli est joignable sans passer par Sesame.
- Désactivation d'un compte **non immédiate** : le compte n'est vérifié qu'à la remise ;
  le relais continue jusqu'à l'expiration du marqueur.
- Reconnexion automatique : à l'expiration du marqueur, et quand une navigation relayée
  correspond aux règles `spec.expiry` (audit `app_session_expired`, puis nouvelle remise).
  Une requête d'API expirée en cours de page n'est pas reprise : l'appli la gère.
- Audit limité à la connexion (lecture du coffre, rejeu, remise) : les requêtes relayées
  ensuite ne sont pas auditées appel par appel.
- Sesame reste dans le flux (relais transparent) : le prix de la transparence sur un seul
  hôte. Les mises à niveau WebSocket ne sont pas gérées par le relais actuel.
- Réservé aux applis où le proxy est impossible **et** où l'exploitant accepte ce risque ;
  en contexte PCI-DSS, à justifier appli par appli (hors périmètre des données de carte).
- L'admin affiche le mode de chaque appli ; le mode se choisit dans le formulaire guidé.
  Le recorder reste en mode proxy par défaut et signale une session par jeton comme
  bloquante ; il ne rédige un descripteur handoff que si on le lui demande (case
  « Mode handoff » de l'admin, `sesame-onboard record --handoff`).
