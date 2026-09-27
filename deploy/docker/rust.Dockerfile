# SPDX-License-Identifier: Apache-2.0
# Image des services Rust. Usage : --build-arg BIN=sesame-portal | sesame-proxy
FROM rust:1-slim-bookworm AS build
ARG BIN
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY crates ./crates
COPY descriptors ./descriptors
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p "$BIN" && cp "target/release/$BIN" /app

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /app /app
USER nonroot
ENTRYPOINT ["/app"]
