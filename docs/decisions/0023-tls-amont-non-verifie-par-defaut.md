# 0023. `spec.upstream.tls.verify` à `false` par défaut

**Statut** : acceptée (2026-09-28), implémentée.

## Contexte

Le proxy (Rust, `reqwest`) vérifiait par défaut le certificat TLS de chaque appli
amont. Sur une appli réelle dont le certificat est signé par une PKI interne (CA privée
d'entreprise, cas courant pour des applis internes jamais exposées publiquement), le
rejeu échouait systématiquement dès le premier essai, sans qu'aucun compte ne soit en
cause : `invalid peer certificate: UnknownIssuer`. Diagnostiqué grâce à
`describe_upstream_error` (journalisation de la cause TLS/DNS/connexion, voir commit du
même jour). L'exploitant a demandé que la vérification devienne facultative, désactivée
par défaut.

## Décision

`spec.upstream.tls.verify` vaut désormais **`false` par défaut** (`Tls::default()`,
`crates/sesame-core/src/descriptor.rs`, schéma JSON). Une appli continue de fonctionner
sans rien déclarer. Pour vérifier réellement le certificat d'une appli, l'ajouter
explicitement dans son descripteur :

```yaml
spec:
  upstream:
    tls:
      verify: true
      ca_file: /etc/sesame/pki-interne.crt   # si la CA n'est pas dans le magasin système
```

`tls.ca_file` reste sans effet si `verify` est `false`.

## Conséquences (contrepartie assumée)

- **Aucune vérification TLS par défaut vers les applis amont** : un attaquant en
  position de réseau entre le proxy et l'appli (réseau interne compromis, DNS détourné)
  pourrait usurper l'appli sans que Sesame ne le détecte, et intercepter la requête de
  login qui porte l'identifiant et le mot de passe applicatifs. En environnement
  PCI-DSS (déploiement de référence), ce risque est à évaluer appli par appli :
  activer `tls.verify: true` (avec `ca_file` si la CA n'est pas publique) pour toute
  appli sur un segment réseau moins maîtrisé, notamment si elle transporte des données
  de paiement.
- Cohérent avec les autres défauts déjà assouplis à la demande de l'exploitant dans ce
  projet (`SESAME_RECORDER_INSECURE`, ADR sans numéro dédié ; coffre PostgreSQL sans
  Vault, ADR 0021) : la sécurité par défaut cède le pas à la facilité de mise en route
  sur des PKI internes, le durcissement restant possible et documenté, pas retiré.
- N'affecte que le trafic **proxy → appli amont** (rejeu et relais). Le trafic
  **navigateur → Sesame** (Nginx) n'est pas concerné : son certificat est géré
  séparément (`deploy/nginx/`), sans changement.
- Testé : `descriptor::tests::tls_verification_is_opt_in` (le défaut, sans `tls` déclaré,
  vaut bien `verify: false`).
