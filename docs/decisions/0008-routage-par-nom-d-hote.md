# 0008. Une appli par nom d'hôte

**Statut** : acceptée (2026-09-27)

## Contexte

Exposer les applis sous des préfixes de chemin (`/app1/…`) casse souvent les applis anciennes : liens absolus, cookies `Path=/`, JavaScript.

## Décision

Chaque appli a son propre nom d'hôte (`spec.public.host`), sous-domaine du portail. Le proxy route d'après l'en-tête `Host`.

## Conséquences

- Pas de réécriture de chemins. Seules les URLs absolues internes sont réécrites.
- Il faut un certificat couvrant les sous-domaines (wildcard ou SAN) et un DNS par appli.
- Le cookie du portail est posé sur le domaine parent, donc les sous-domaines le reçoivent. Le proxy le retire avant de relayer la requête à l'appli, et capture tous les `Set-Cookie` des applis pour qu'aucune ne puisse poser ou écraser de cookie sur le domaine parent (cookie tossing).
