# SPDX-License-Identifier: Apache-2.0
"""Point d'entrée : ``python -m sesame_admin``."""

from __future__ import annotations

import json
import logging
import ssl
import sys

import httpx
import uvicorn

from .audit import StdoutAuditSink
from .auth import OidcAuthenticator
from .config import Settings
from .descriptors import DescriptorValidator, load_dir
from .openbao import OpenBaoSecretWriter
from .service import AdminService
from .store_postgres import PgPool, PostgresAccountStore, PostgresDescriptorStore
from .web import create_app


class JsonFormatter(logging.Formatter):
    """Logs JSON ; seuls des champs explicitement choisis sont ajoutés (jamais de saisie)."""

    FIELDS = ("correlation_id", "app_id", "target_user", "reason")

    def format(self, record: logging.LogRecord) -> str:
        out = {"level": record.levelname, "message": record.getMessage(), "target": record.name}
        out.update({k: getattr(record, k) for k in self.FIELDS if hasattr(record, k)})
        return json.dumps(out, ensure_ascii=False)


def main() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)

    s = Settings.from_env()
    apps = load_dir(s.descriptors_dir, s.schema_file)
    verify: ssl.SSLContext | bool = True
    if s.ca_file:
        verify = ssl.create_default_context()
        verify.load_verify_locations(cafile=str(s.ca_file))
    secrets = OpenBaoSecretWriter(
        s.openbao, httpx.AsyncClient(timeout=10, verify=verify, follow_redirects=False)
    )
    audit = StdoutAuditSink()
    db = PgPool(s.database_url)
    service = AdminService(
        apps,
        secrets,
        PostgresAccountStore(db),
        audit,
        PostgresDescriptorStore(db),
        DescriptorValidator(s.schema_file),
    )
    app = create_app(
        service,
        OidcAuthenticator(s.oidc, str(s.ca_file) if s.ca_file else None),
        audit,
        public_url=s.public_url,
        session_key=s.session_key,
        admin_group=s.admin_group,
        issuer=s.oidc.issuer,
        user_key_claim=s.oidc.user_key_claim,
        groups_claim=s.oidc.groups_claim,
        session_ttl_secs=s.session_ttl_secs,
        secure_cookies=s.public_url.startswith("https://"),
    )
    logging.getLogger(__name__).info("administration démarrée (%d applis en fichiers)", len(apps))
    uvicorn.run(
        app,
        host=s.listen_host,
        port=s.listen_port,
        proxy_headers=True,
        forwarded_allow_ips="*",
        log_config=None,
    )


if __name__ == "__main__":
    main()
