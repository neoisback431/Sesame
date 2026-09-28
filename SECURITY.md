# Politique de sécurité

Sesame manipule des identifiants applicatifs et des sessions : nous traitons tout signalement de
vulnérabilité en priorité.

## Signaler une vulnérabilité

**N'ouvrez pas d'issue publique, de discussion ni de pull request** pour une vulnérabilité.

Utilisez le **signalement privé de GitHub** : onglet **Security** du dépôt, puis
**Report a vulnerability** (Security Advisories). Seuls les mainteneurs y ont accès.

Indiquez, dans la mesure du possible :

- la version (tag ou commit) et le composant concerné (portail, proxy, administration,
  recorder) ;
- le protocole d'identité (OIDC / SAML) et le coffre utilisés ;
- les étapes de reproduction et l'impact estimé ;
- une preuve de concept, **sans secret réel ni donnée d'une organisation**.

## Ce qui se passe ensuite

| Étape | Délai visé |
|---|---|
| Accusé de réception | 3 jours ouvrés |
| Première évaluation (gravité, périmètre) | 10 jours ouvrés |
| Correctif ou mesure de contournement | selon la gravité, au plus vite pour une faille critique |

Nous vous tenons informé, publions un avis de sécurité (GitHub Security Advisory, CVE si
pertinent) avec la version corrigée, et vous créditons si vous le souhaitez. Merci de ne rien
divulguer avant la publication du correctif.

## Versions maintenues

| Version | Correctifs de sécurité |
|---|---|
| 0.1.x | ✅ |

Tant que le projet est en 0.x, seule la dernière version mineure reçoit des correctifs.

## Périmètre

Dans le périmètre, par exemple : fuite d'un identifiant, d'un cookie ou d'un jeton vers le
navigateur, les logs ou une erreur ; contournement de l'authentification (OIDC, SAML) ou des
habilitations ; lecture du coffre par un autre composant que le proxy ; falsification de
l'audit ; injection dans l'administration.

Comportements **documentés et assumés** (voir [docs/decisions/](docs/decisions/)), qui ne sont
pas des vulnérabilités en soi mais dont les abus concrets nous intéressent :

- mode « remise » (handoff), qui remet un élément de session au navigateur (ADR 0020) ;
- vérification TLS vers les applis amont désactivée par défaut (ADR 0023) ;
- absence d'allowlist anti-SSRF dans le recorder, service interne réservé aux administrateurs
  (ADR 0016).

Les secrets présents dans le dépôt (`docker-compose*.yml`, `dev/`) sont des **valeurs de dev
publiques et explicites** : ce n'est pas une fuite.

## Bonnes pratiques de déploiement

- Générez vos propres clés (`openssl rand -base64 32`) : ne réutilisez jamais les valeurs de dev.
- N'exposez jamais le service `sesame-recorder` hors du réseau interne.
- Activez `spec.upstream.tls.verify: true` pour toute appli sur un segment réseau non maîtrisé.
- En production, utilisez des rôles PostgreSQL distincts pour le proxy (lecture du coffre) et
  l'administration (écriture seule), voir l'ADR 0021.
- Collectez le journal d'audit (`"log_type":"audit"`) dans votre SIEM.
