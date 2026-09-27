# SPDX-License-Identifier: Apache-2.0
# Point d'entrée unique pour les développeurs et la CI (les fichiers CI restent minces).

CERTS := deploy/nginx/certs
# onboarding et admin rejoindront la liste avec leurs premiers tests.
PY_PROJECTS := dev/fake-app

.PHONY: help dev-certs up down logs test test-rust test-python lint lint-rust lint-python validate-descriptors images deny

help:
	@echo "dev-certs             certificat TLS de dev pour *.sesame.localhost"
	@echo "up / down / logs      environnement Docker Compose de dev"
	@echo "test                  tests Rust et Python"
	@echo "lint                  fmt, clippy, ruff, validation des descripteurs"
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

test: test-rust test-python

test-rust:
	cargo test --workspace --locked

test-python:
	@for p in $(PY_PROJECTS); do echo "== $$p"; (cd $$p && uv run --group dev pytest -q) || exit 1; done

lint: lint-rust lint-python validate-descriptors

lint-rust:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets --locked -- -D warnings

lint-python:
	uvx ruff check .
	uvx ruff format --check .

validate-descriptors:
	uv run -q scripts/validate_descriptors.py

deny:
	cargo deny check licenses

images:
	docker compose build
