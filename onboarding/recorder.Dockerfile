# SPDX-License-Identifier: Apache-2.0
# Image du recorder (sesame-onboard record) : navigateur headless fourni par l'image
# Playwright officielle, dont la version doit rester celle de la bibliothèque installée.
# Contexte de build : racine du dépôt (le schéma des descripteurs est intégré à l'image).
FROM mcr.microsoft.com/playwright/python:v1.63.0-noble
WORKDIR /app
COPY onboarding/pyproject.toml ./
COPY onboarding/src ./src
COPY schemas/app-descriptor.schema.json /etc/sesame/app-descriptor.schema.json
ENV SESAME_RECORDER_SCHEMA=/etc/sesame/app-descriptor.schema.json
RUN pip install --no-cache-dir --break-system-packages ".[capture]" "playwright==1.63.0"
USER pwuser
EXPOSE 8090
# Service HTTP interne appelé par l'admin. Pour une analyse ponctuelle en ligne de
# commande (make record), l'entrypoint est remplacé par « sesame-onboard … record ».
ENTRYPOINT ["sesame-recorder"]
