# SPDX-License-Identifier: Apache-2.0
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY fake_app ./fake_app
RUN pip install --no-cache-dir . && useradd --system --uid 10001 app
USER app
EXPOSE 8000
# Un seul worker : sessions et jetons CSRF sont gardés en mémoire.
CMD ["gunicorn", "--workers", "1", "--bind", "0.0.0.0:8000", "fake_app.app:create_app()"]
