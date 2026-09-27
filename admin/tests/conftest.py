# SPDX-License-Identifier: Apache-2.0
from pathlib import Path

import pytest
from sesame_admin.audit import MemoryAuditSink
from sesame_admin.descriptors import load_dir
from sesame_admin.identity import AdminUser
from sesame_admin.memory import MemoryAccountStore, MemorySecretWriter
from sesame_admin.service import AdminService

ROOT = Path(__file__).resolve().parents[2]
DESCRIPTORS = ROOT / "descriptors"
SCHEMA = ROOT / "schemas" / "app-descriptor.schema.json"

ADMIN = AdminUser("https://idp.test", "sub-admin", "admin", "Admin", ("sesame-admins",))


@pytest.fixture
def apps():
    return load_dir(DESCRIPTORS, SCHEMA)


@pytest.fixture
def service(apps):
    return AdminService(apps, MemorySecretWriter(), MemoryAccountStore(), MemoryAuditSink())
