# 0032. Adresse publique annoncée à l'appli (`X-Forwarded-*`)

**Statut** : acceptée (2026-10-20), implémentée.

## Contexte

Le proxy joint l'appli sur son adresse interne (`spec.upstream.base_url`). L'appli se croit
donc servie à cette adresse et génère des URLs internes, que Sesame corrige après coup
(`rewrite.rs` : `Location` et corps de certains types de contenu). Cette réécriture ne
couvre pas les URLs construites par le JavaScript, les valeurs encodées ni les types non
listés, et certaines applis (n8n notamment) vérifient `Origin` / hôte et se comportent mal
si elles ne connaissent pas leur adresse publique.

Remplacer `Host` par l'hôte public (`spec.upstream.host_header`) n'est pas général : une
appli ou un frontal qui contrôle l'hôte (liste d'hôtes autorisés, hôte virtuel) répond 400.

Le Nginx du kit Compose pose déjà `X-Forwarded-Host` et `-Proto`, que le proxy relaie ; mais
l'ALB du kit AWS ne pose pas `X-Forwarded-Host`, et un client pourrait forger ces
en-têtes. L'appli ne recevait donc pas de façon fiable son adresse publique.

## Décision

**Pour toutes les applis**, le proxy pose sur chaque requête relayée **et** sur le rejeu du
login :

- `X-Forwarded-Host` : hôte public avec son port éventuel (`spec.public.host`) ;
- `X-Forwarded-Proto` : schéma public (celui de `SESAME_PORTAL_URL`) ;
- `X-Forwarded-Port` : port public (explicite, sinon 443 / 80 selon le schéma).

Les valeurs viennent du **descripteur**, jamais de la requête : tout `X-Forwarded-Host`,
`-Proto`, `-Port` et `Forwarded` (RFC 7239) fourni par le navigateur ou par un frontal est
**retiré et remplacé**. `X-Forwarded-For` (adresse du client posée par le frontal) est
conservé. `Host` reste inchangé (adresse interne, ou `host_header` si renseigné).

La réécriture a posteriori reste en place, comme filet.

## Conséquences

- Les applis qui savent lire ces en-têtes (n8n avec `N8N_PROXY_HOPS=1`, Django, Spring,
  ASP.NET, Express avec `trust proxy`, Rails, Flask avec ProxyFix) génèrent d'elles-mêmes
  des URLs publiques ; celles qui les ignorent ne changent pas de comportement. Chacune
  reste à configurer côté appli pour **faire confiance** à ces en-têtes.
- Changement de comportement pour **toutes** les applis (choix de l'exploitant, plutôt
  qu'une option par appli) : une appli qui réagissait mal à la présence de ces en-têtes
  devrait être traitée au cas par cas (aucun cas connu).
- Le rejeu reçoit les mêmes en-têtes : cookies `Secure` et contrôles d'origine se
  comportent comme en navigation.
- Un frontal en amont n'a plus à poser ces en-têtes pour l'appli ; ceux qu'il pose sont
  remplacés par les valeurs du descripteur (identiques en fonctionnement normal).
- Pas de nouvelle variable d'environnement ni de changement du schéma du descripteur.
