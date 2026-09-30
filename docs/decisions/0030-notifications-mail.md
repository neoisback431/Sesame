# 0030. Notifications par mail aux administrateurs

**Statut** : acceptée (2026-09-30), implémentée.

## Contexte

Les administrateurs ne voient une demande d'accès (ADR 0029), un compte passé en échec ou
une appli hors service que s'ils ouvrent la console. L'exploitant veut être prévenu par
mail, avec un SMTP et des événements **configurables dans la console d'administration**.

Les événements naissent dans le portail et le proxy (Rust), alors que la console est en
Python : il faut un point de rencontre qui ne mette pas un SMTP dans le chemin d'une
connexion.

## Décision

- **Boîte d'envoi en base** (`notifications`, migration `0007`) : le portail et le proxy
  y déposent un événement (`Notifier::notify`, PostgreSQL) ; **un worker de l'administration**
  l'expédie en SMTP puis le marque. Un SMTP en panne ne bloque ni une connexion, ni un
  rejeu, ni une demande : l'envoi est repris avec une attente croissante (1, 2, 4… minutes),
  abandonné après 6 tentatives, puis purgé après 30 jours. Un bail de 5 minutes évite le
  double envoi si l'admin tourne en plusieurs répliques.
- **Événements** : `access_requested` (portail et proxy), `account_failed` (proxy, compte
  bloqué jusqu'à correction), `upstream_unreachable` (proxy, appli hors service, sans
  changement d'état), `admin_sensitive` (admin : compte supprimé ou désactivé, application
  supprimée, désactivation en masse). Chacun est activable séparément.
- **Regroupement** : le dépôt ignore un événement identique (même type, même appli, même
  utilisateur) déjà déposé depuis 10 minutes, pour qu'une appli en panne ne produise pas un
  mail par requête.
- **Réglages dans la console** (`/settings/notifications`, `notification_settings`, une
  seule ligne) : activation, serveur, port, sécurité (STARTTLS, TLS implicite, aucune),
  identifiant, expéditeur, destinataires, événements notifiés. Bouton « mail de test »,
  historique des 30 derniers envois avec leur état et un code d'erreur court. Modifications
  et tests audités (`notification_settings_updated`, `notification_test`).
- **Le mot de passe SMTP reste dans l'environnement de l'admin** (`SESAME_SMTP_PASSWORD`),
  jamais en base ni affiché : l'admin ne relit aucun secret depuis la base (ADR 0021). Il
  n'est envoyé que sur une connexion chiffrée ; sans chiffrement, l'envoi est refusé.
- **Contenu des mails** : événement, appli, utilisateur, motif court, date, lien vers la
  console. **Aucun identifiant applicatif, aucun contenu de réponse d'appli.** Les valeurs
  insérées dans les en-têtes sont réduites à une ligne sans caractère de contrôle (pas
  d'injection d'en-tête) ; les adresses sont validées.
- Envoi par la bibliothèque standard (`smtplib`), certificats vérifiés (CA de
  `SESAME_CA_FILE` si fournie) : aucune dépendance nouvelle.

## Conséquences

- Le portail et le proxy gagnent un droit d'écriture sur `notifications` ; ils ne lisent
  jamais les réglages (le filtrage par événement se fait à l'envoi : un événement désactivé
  est marqué `skipped`).
- Notifications désactivées ou non configurées : les événements sont marqués `skipped`,
  pas conservés en attente indéfiniment.
- Les destinataires sont des données personnelles stockées en base et lisibles par les
  administrateurs seulement ; elles n'apparaissent pas dans l'audit (seulement leur nombre).
- Le serveur SMTP est choisi par un administrateur : même modèle de confiance que le
  recorder (ADR 0016), sans liste d'autorisation de destinations.
- Non couvert : le mail n'est pas un canal fiable de livraison (SMTP sans accusé de
  réception) ; le journal d'audit reste la source de vérité.
