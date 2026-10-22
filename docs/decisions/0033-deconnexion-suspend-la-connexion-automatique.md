# 0033. « Déconnecter » suspend la connexion automatique à l'appli

**Statut** : acceptée (2026-10-12), implémentée. Remplace en partie [ADR 0022](0022-tuiles-nouvel-onglet-deconnexion-par-appli.md) (comportement du bouton « Déconnecter »).

## Contexte

Retour d'usage : Sesame « force la session » dans l'appli, même dans une fenêtre de navigation
privée, ce qui empêche de **changer de compte** dans l'appli (se connecter à la main avec un
autre compte que celui de l'utilisateur Sesame). Le bouton « Déconnecter » des tuiles (ADR 0022)
n'y changeait rien :

- il supprimait la seule session applicative stockée de la **session portail courante** ; une
  autre fenêtre ou une navigation privée (autre session portail) restait connectée d'office, et
  le prochain accès rejouait aussitôt le login, effaçant l'effet du bouton ;
- en mode **handoff** (ADR 0020), la session est portée par le navigateur (cookie remis sur
  l'hôte de l'appli, stockage local) : le portail, sur un autre hôte, n'y touchait pas, donc le
  bouton ne faisait rien du tout.

## Décision

« Déconnecter » **suspend la connexion automatique** de l'utilisateur à cette appli, jusqu'à ce
qu'il clique de nouveau sur la tuile.

- **État** : table `app_suspensions (app_id, user_key)` (migration `0009`), portée par
  `SessionStore` (`suspend_app`, `resume_app`, `is_app_suspended`, `suspended_apps`). La
  suspension vise l'**utilisateur**, pas une session portail : elle couvre toutes ses fenêtres,
  navigation privée comprise. `suspend_app` détruit aussi les sessions applicatives de toutes ses
  sessions portail pour cette appli. Aucun secret n'y est stocké.
- **Portail** : `POST /apps/<id>/disconnect` audite (`app_logout`, `manual_from_portal`), suspend,
  puis redirige (303) le navigateur vers l'hôte de l'appli, chemin réservé
  `/.sesame/disconnect`. `GET /apps/<id>/open` (la tuile pointe désormais ici) lève la
  suspension (audit `app_resumed`) puis redirige vers l'appli (`spec.public.start_path`). Une
  tuile suspendue reste cliquable (« Déconnecté : cliquez pour vous reconnecter ») et n'a plus de
  bouton « Déconnecter » (`TileState::Suspended`).
- **Proxy, suspendu** : ni rejeu ni lecture du coffre (donc aucun événement `secret_read` /
  `login_replay`). La requête est relayée telle quelle, en mode « navigateur porteur » comme le
  handoff : cookies et `Authorization` du navigateur transmis (hors cookies de Sesame), `Set-Cookie`
  de l'appli renvoyés au navigateur. L'utilisateur voit la page de login de l'appli et peut s'y
  connecter avec n'importe quel compte. Le contrôle se fait là où le proxy aurait rejoué (pas de
  session applicative en mode proxy ; pas de marqueur ou cookie remis effacé en mode handoff), sans
  requête supplémentaire en régime normal. Un compte **désactivé** par un administrateur (ou
  `pending`, ou absent) reste refusé : la suspension n'ouvre pas un accès que l'administrateur a
  retiré. L'habilitation `spec.access` reste appliquée.
- **Chemin réservé `/.sesame/disconnect`** (hôte de l'appli, session portail exigée) : efface les
  cookies de l'hôte (sauf celui du portail, jamais touché), `localStorage` et `sessionStorage`,
  puis renvoie au portail. N'agit **que si la suspension est active** : un lien piégé ne peut
  déconnecter personne qui ne l'a pas demandé depuis le portail (POST avec cookie `SameSite=Lax`).
  Hors suspension, simple redirection vers le portail. Le chemin n'est pas transmis à l'appli.
- **Reprise** : uniquement par clic sur la tuile (pas d'expiration automatique). Un favori ou un
  lien profond pendant la suspension montre la page de login de l'appli.

## Conséquences

- Principes 1 et 3 : pendant la suspension, l'appli est utilisée avec les identifiants et la session
  **que l'utilisateur saisit lui-même** ; le mot de passe du coffre n'est ni lu ni remis. Les
  cookies de l'appli atteignent le navigateur dans ce seul cas (comme le handoff, ADR 0020), c'est
  l'objet de la fonction.
- Changement de comportement : « Déconnecter » ne se voit plus annulé par un rejeu transparent ; le
  prochain clic sur la tuile reconnecte. Une appli suspendue n'est pas reconnectée par un accès
  direct (favori) : il faut repasser par la tuile.
- Un utilisateur qui oublie de recliquer sur la tuile garde la suspension ; elle ne concerne que
  lui et cette appli, et se lève d'un clic.
- Contrat `SessionStore` étendu (mémoire, PostgreSQL) et couvert par le test de contrat ; tests du
  proxy dans `crates/sesame-proxy/tests/suspension.rs` (pas de rejeu ni de lecture du coffre,
  cookies du navigateur relayés mais jamais celui du portail, suspension par utilisateur et par
  appli, compte désactivé refusé, nettoyage du navigateur).
