# SPDX-License-Identifier: Apache-2.0
# Image des services Rust. Usage : --build-arg BIN=sesame-portal | sesame-proxy
# --target runtime-portal | runtime-proxy (voir docker-compose.yml)
FROM rust:1-slim-bookworm AS build
ARG BIN
WORKDIR /src
# libxmlsec1-dev/libxml2-dev/pkg-config/clang : nécessaires à `samael` (feature `xmlsec`,
# vérification de signature SAML, ADR 0024) côté portail seulement, mais présents ici pour
# les deux binaires (image de build commune, coût de compilation négligeable).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxmlsec1-dev libxml2-dev pkg-config clang \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY crates ./crates
COPY descriptors ./descriptors
# Caches partagés entre les images portail et proxy, construites en parallèle
# par Compose : sharing=locked sérialise l'accès (sinon deux cargo décompressent
# le même paquet en même temps et échouent sur « File exists »).
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked -p "$BIN" && cp "target/release/$BIN" /app

# sesame-proxy : aucune dépendance SAML/xmlsec, image minimale distroless.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime-proxy
COPY --from=build /app /app
USER nonroot
ENTRYPOINT ["/app"]

# sesame-portal : `samael` (feature `xmlsec`) lie dynamiquement libxmlsec1/libxml2/libssl,
# absentes de distroless/cc ; base Debian minimale à la place, pour ce binaire seulement.
FROM debian:bookworm-slim AS runtime-portal
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxmlsec1-openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 65532 nonroot
COPY --from=build /app /app
USER nonroot
ENTRYPOINT ["/app"]
