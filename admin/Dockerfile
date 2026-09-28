# SPDX-License-Identifier: Apache-2.0
# Contexte de build : racine du dépôt (le schéma des descripteurs est intégré à l'image).
FROM python:3.12-slim
WORKDIR /app
COPY admin/pyproject.toml ./
COPY admin/src ./src
COPY schemas/app-descriptor.schema.json /etc/sesame/app-descriptor.schema.json
ENV SESAME_SCHEMA_FILE=/etc/sesame/app-descriptor.schema.json
RUN pip install --no-cache-dir . && useradd --system --uid 10001 app
USER app
EXPOSE 8000
CMD ["python", "-m", "sesame_admin"]
