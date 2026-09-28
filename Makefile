# SPDX-License-Identifier: Apache-2.0
# Point d'entrée unique pour les développeurs et la CI (les fichiers CI restent minces).

CERTS := deploy/nginx/certs
PY_PROJECTS := dev/fake-app admin onboarding
# Dépôt de référence ; une autre organisation qui publie ses propres images passe
# REGISTRY=ghcr.io/<son-organisation>/sesame à `make release-images`.
REGISTRY ?= ghcr.io/neoisback431/sesame

.PHONY: help dev-certs up up-demo down logs health record test test-full test-rust test-python test-python-full test-postgres e2e lint lint-rust lint-python validate-descriptors check-dev-keys images release-images release-kit deny deny-python

help:
	@echo "dev-certs             certificat TLS de dev pour *.sesame.localhost"
	@echo "up / down / logs      environnement Docker Compose de dev (sans l'appli factice)"
	@echo "up-demo               comme up, avec en plus l'appli factice de démo (profil demo)"
	@echo "health                test de santé des formulaires de login (après make up-demo)"
	@echo "record URL=… [ARGS=…] analyse une page de login et propose un descripteur (après make up)"
	@echo "test                  tests rapides (défaut) : Rust + Python, sans navigateur"
	@echo "test-full             tests complets : test + navigateur (recorder) + PostgreSQL (si Docker)"
	@echo "test-postgres         tests de contrat sur une base PostgreSQL jetable (Docker)"
	@echo "e2e                   tests bout en bout Playwright (après make up-demo)"
	@echo "lint                  fmt, clippy, ruff, validation des descripteurs"
	@echo "deny                  licences des dépendances (Rust et Python)"
	@echo "images                construit les images Docker (dev)"
	@echo "release-images VERSION=vX.Y.Z [REGISTRY=…]  construit et publie les 4 images de release"
	@echo "release-kit VERSION=vX.Y.Z   archive du kit de déploiement (deploy/release/)"

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

# Ajoute l'appli factice (profil « demo », facultative) : login OIDC de bout en bout à
# essayer, e2e, test de santé. Sans elle, `make up` suffit pour le cœur de Sesame.
# Les comptes de démo (alice, carol, admin…) vivent dans le Keycloak de dev, facultatif
# et commenté par défaut dans docker-compose.yml.
up-demo: dev-certs
	@docker compose config --services | grep -qx keycloak || { \
	  echo "make up-demo exige le Keycloak de dev : décommentez le service keycloak et la"; \
	  echo "ligne 'keycloak:' du depends_on du portail dans docker-compose.yml."; exit 2; }
	docker compose --profile demo up -d --build

down:
	docker compose --profile demo down

logs:
	docker compose logs -f

health:
	docker compose --profile demo run --rm --build health

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

lint: lint-rust lint-python validate-descriptors check-dev-keys

lint-rust:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets --locked -- -D warnings

lint-python:
	uvx ruff check .
	uvx ruff format --check .

validate-descriptors:
	uv run -q scripts/validate_descriptors.py

# Une clé de chiffrement de dev mal générée (mauvaise longueur) ne casse rien au
# chargement de Compose, seulement au démarrage du service qui la lit (502 via Nginx).
check-dev-keys:
	uv run -q scripts/check_dev_keys.py

deny: deny-python
	cargo deny check licenses

deny-python:
	@for p in $(PY_PROJECTS); do echo "== $$p"; \
	  (cd $$p && uv run -q --with pip-licenses python $(CURDIR)/scripts/check_python_licenses.py) || exit 1; done

images:
	docker compose build

# 4 images publiées, une par service déployable (portail, proxy, admin, recorder) : pas
# d'image combinée, pour garder la frontière de sécurité portail/proxy (seul le proxy lit
# le coffre) et l'isolation du recorder (aucune allowlist anti-SSRF, ADR 0016). Portail et
# proxy partagent le même Dockerfile (étages runtime-portal / runtime-proxy) mais restent
# deux images et deux conteneurs distincts.
release-images:
	@test -n "$(VERSION)" || (echo "usage : make release-images VERSION=vX.Y.Z [REGISTRY=…]" && exit 2)
	docker build -f deploy/docker/rust.Dockerfile --build-arg BIN=sesame-portal --target runtime-portal \
	  -t $(REGISTRY)-portal:$(VERSION) -t $(REGISTRY)-portal:latest .
	docker build -f deploy/docker/rust.Dockerfile --build-arg BIN=sesame-proxy --target runtime-proxy \
	  -t $(REGISTRY)-proxy:$(VERSION) -t $(REGISTRY)-proxy:latest .
	docker build -f admin/Dockerfile . -t $(REGISTRY)-admin:$(VERSION) -t $(REGISTRY)-admin:latest
	docker build -f onboarding/recorder.Dockerfile . \
	  -t $(REGISTRY)-recorder:$(VERSION) -t $(REGISTRY)-recorder:latest
	@for name in portal proxy admin recorder; do \
	  docker push $(REGISTRY)-$$name:$(VERSION) && docker push $(REGISTRY)-$$name:latest; \
	done

# Archive du kit de déploiement (deploy/release/), jointe à la Release GitHub : version et
# registre des images figés dans .env.example, sans .env ni certificat local.
release-kit:
	@test -n "$(VERSION)" || (echo "usage : make release-kit VERSION=vX.Y.Z [REGISTRY=…]" && exit 2)
	rm -rf dist/sesame && mkdir -p dist/sesame/certs
	cp deploy/release/docker-compose.yml deploy/release/generate-keys.sh dist/sesame/
	cp -r deploy/release/nginx dist/sesame/
	cp deploy/release/certs/README dist/sesame/certs/
	sed -e 's|^SESAME_VERSION=.*|SESAME_VERSION=$(VERSION)|' \
	    -e 's|^# SESAME_REGISTRY=.*|SESAME_REGISTRY=$(patsubst %/sesame,%,$(REGISTRY))|' \
	    deploy/release/.env.example > dist/sesame/.env.example
	tar -czf dist/sesame-deploy-$(VERSION).tar.gz -C dist sesame
	@echo "dist/sesame-deploy-$(VERSION).tar.gz"
