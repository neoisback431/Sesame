# Policy du moteur de proxy : lecture seule des identifiants applicatifs.
path "secret/data/sesame/apps/*" {
  capabilities = ["read"]
}
