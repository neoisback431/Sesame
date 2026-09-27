# SPDX-License-Identifier: Apache-2.0
# Point d'entrée unique pour les développeurs et la CI (les fichiers CI restent minces).

CERTS := deploy/nginx/certs
PY_PROJECTS := dev/fake-app admin onboarding

.PHONY: help dev-certs up down logs health record test test-full test-rust test-python test-python-full test-postgres e2e lint lint-rust lint-python validate-descriptors images deny deny-python

help:
	@echo "dev-certs             certificat TLS de dev pour *.sesame.localhost"
	@echo "up / down / logs      environnement Docker Compose de dev"
	@echo "health                test de santé des formulaires de login (après make up)"
	@echo "record URL=… [ARGS=…] analyse une page de login et propose un descripteur (après make up)"
	@echo "test                  tests rapides (défaut) : Rust + Python, sans navigateur"
	@echo "test-full             tests complets : test + navigateur (recorder) + PostgreSQL (si Docker)"
	@echo "test-postgres         tests de contrat sur une base PostgreSQL jetable (Docker)"
	@echo "e2e                   tests bout en bout Playwright (après make up)"
	@echo "lint                  fmt, clippy, ruff, validation des descripteurs"
	@echo "deny                  licences des dépendances (Rust et Python)"
	@echo "images                construit les images Docker"

$(CERTS)/sesame.crt:
	mkdir -p $(CERTS)
	openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=Sesame dev CA" \
	  -keyout $(CERTS)/ca.key -out $(CERTS)/ca.crt \
	  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
	openssl req -newkey rsa:2048 -nodes -subj "/CN=sesame.localhost" \
	  -keyout $(CERTS)/sesame.key -out $(CERTS)/sesame.csr
	printf "subjectAltName=DNS:sesame.localhost,DNS:*.sesame.localhost\nextendedKeyUsage=serverAuth\n" > $(CERTS)/ext.cnf
	openssl x509 -req -in $(CERTS)/sesame.csr -CA $(CERTS)/ca.crt -CAkey $(CERTS)/ca.key \
	  -CAcreateserial -days 825 -extfile $(CERTS)/ext.cnf -out $(CERTS)/sesame.crt
	rm -f $(CERTS)/sesame.csr $(CERTS)/ext.cnf
	chmod 644 $(CERTS)/sesame.key

dev-certs: $(CERTS)/sesame.crt

up: dev-certs
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f

health:
	docker compose run --rm --build health

# Ex. : make record URL=http://fake-app:8000/login ARGS="--id fake-app --probe-failure"
record:
	@test -n "$(URL)" || (echo "usage : make record URL=<page de login> [ARGS=…]" && exit 2)
	docker compose run --rm --build --no-deps \
	  --entrypoint sesame-onboard recorder \
	  --schema /etc/sesame/app-descriptor.schema.json record "$(URL)" $(ARGS)

# Deux niveaux : `test` (rapide, à lancer après chaque modification) et `test-full`
# (complet : ajoute les tests qui lancent un Chromium headless et le contrat PostgreSQL).
test: test-rust test-python

test-full: test-rust test-python-full
	@if docker info >/dev/null 2>&1; then $(MAKE) --no-print-directory test-postgres; \
	  else echo "!! test-postgres IGNORÉ : Docker indisponible"; fi

test-rust:
	cargo test --workspace --locked

test-python:
	@for p in $(PY_PROJECTS); do echo "== $$p"; (cd $$p && uv run --group dev pytest -q -m "not browser") || exit 1; done

test-python-full:
	@for p in $(PY_PROJECTS); do echo "== $$p"; (cd $$p && uv run --group dev pytest -q) || exit 1; done

# Tests de contrat du magasin PostgreSQL sur une base jetable.
test-postgres:
	docker run -d --rm --name sesame-pgtest -e POSTGRES_PASSWORD=test -p 127.0.0.1:55432:5432 postgres:17-alpine >/dev/null
	@until docker exec sesame-pgtest pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
	export SESAME_TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:55432/postgres; \
	  cargo test -p sesame-store-postgres --locked \
	  && (cd admin && uv run --group dev pytest -q tests/test_store_contract.py); \
	  status=$$?; docker stop sesame-pgtest >/dev/null; exit $$status

# Parcours complets dans un vrai navigateur, sur l'environnement lancé par make up.
e2e:
	cd tests/e2e && uv run --group dev playwright install chromium && uv run --group dev pytest -q

lint: lint-rust lint-python validate-descriptors

lint-rust:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets --locked -- -D warnings

lint-python:
	uvx ruff check .
	uvx ruff format --check .

validate-descriptors:
	uv run -q scripts/validate_descriptors.py

deny: deny-python
	cargo deny check licenses

deny-python:
	@for p in $(PY_PROJECTS); do echo "== $$p"; \
	  (cd $$p && uv run -q --with pip-licenses python $(CURDIR)/scripts/check_python_licenses.py) || exit 1; done

images:
	docker compose build
