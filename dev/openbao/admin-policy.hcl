# Policy de l'UI d'administration : écriture et suppression des identifiants,
# SANS lecture. Un administrateur peut définir un mot de passe, jamais le relire.
path "secret/data/sesame/apps/*" {
  capabilities = ["create", "update"]
}
path "secret/metadata/sesame/apps/*" {
  capabilities = ["delete"]
}
