# SPDX-License-Identifier: Apache-2.0
from pathlib import Path

import pytest
from sesame_admin.audit import MemoryAuditSink
from sesame_admin.descriptors import DescriptorValidator, load_dir
from sesame_admin.identity import AdminUser
from sesame_admin.memory import (
    MemoryAccessRequestStore,
    MemoryAccountStore,
    MemoryDescriptorStore,
    MemoryNotificationStore,
    MemorySecretWriter,
)
from sesame_admin.service import AdminService

ROOT = Path(__file__).resolve().parents[2]
DESCRIPTORS = ROOT / "descriptors"
SCHEMA = ROOT / "schemas" / "app-descriptor.schema.json"

ADMIN = AdminUser("https://idp.test", "sub-admin", "admin", "Admin", ("sesame-admins",))


@pytest.fixture
def apps():
    return load_dir(DESCRIPTORS, SCHEMA)


def make_service(apps, audit=None, mailer=None) -> AdminService:
    return AdminService(
        apps,
        MemorySecretWriter(),
        MemoryAccountStore(),
        audit or MemoryAuditSink(),
        MemoryDescriptorStore(),
        DescriptorValidator(SCHEMA),
        MemoryAccessRequestStore(),
        MemoryNotificationStore(),
        mailer,
    )


def descriptor_yaml(app_id: str = "crm", host: str = "crm.sesame.test", **replace: str) -> str:
    """Descripteur valide dérivé de l'appli factice (identifiant et hôte changés)."""
    text = (DESCRIPTORS / "fake-app.yaml").read_text(encoding="utf-8")
    text = text.replace("id: fake-app", f"id: {app_id}").replace(
        "host: fake-app.sesame.localhost:8443", f"host: {host}"
    )
    for old, new in replace.items():
        text = text.replace(old, new)
    return text


@pytest.fixture
def service(apps):
    return make_service(apps)
