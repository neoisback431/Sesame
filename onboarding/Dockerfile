# SPDX-License-Identifier: Apache-2.0
# Image du test de santé et de la vérification (sans navigateur).
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --system --uid 10001 app
USER app
ENTRYPOINT ["sesame-onboard", "--schema", "/etc/sesame/app-descriptor.schema.json"]
CMD ["health", "/etc/sesame/descriptors"]
