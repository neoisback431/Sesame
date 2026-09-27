# SPDX-License-Identifier: Apache-2.0
# Image du recorder (sesame-onboard record) : navigateur headless fourni par l'image
# Playwright officielle, dont la version doit rester celle de la bibliothèque installée.
FROM mcr.microsoft.com/playwright/python:v1.63.0-noble
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --break-system-packages ".[capture]" "playwright==1.63.0"
USER pwuser
ENTRYPOINT ["sesame-onboard", "--schema", "/etc/sesame/app-descriptor.schema.json", "record"]
