# SPDX-License-Identifier: Apache-2.0
"""Applis en base : validation (miroir de AppDescriptor::validate), fusion, opérations auditées."""

import re

import pytest
import yaml
from sesame_admin.descriptors import (
    DescriptorError,
    DescriptorValidator,
    app_from_doc,
    draft,
    merge,
    parse_yaml,
)
from sesame_admin.ports import NotFound, StoredDescriptor
from sesame_admin.service import InvalidDescriptor, InvalidInput

from .conftest import ADMIN, DESCRIPTORS, SCHEMA, descriptor_yaml

SECRET = "Sup3r-Secret-Value"
V = DescriptorValidator(SCHEMA)


def doc(**replace: str) -> dict:
    return yaml.safe_load(descriptor_yaml(**replace))


def test_reference_descriptor_is_valid():
    assert V.check(yaml.safe_load((DESCRIPTORS / "fake-app.yaml").read_text())) == []


@pytest.mark.parametrize(
    ("replace", "expected"),
    [
        ({"password: { from_secret: password }": "password: { from_secret: pin }"}, "clé inconnue « pin »"),
        ({'location_not_matches: "^/login"': 'location_not_matches: "^(/login"'}, "regex"),
        ({'location_not_matches: "^/login"': 'location_not_matches: "^(?!/login)"'}, "voisinage"),
        ({'paths: ["^/logout$"]': 'paths: ["(a)\\\\1"]'}, "références arrière"),
        ({"- source: hidden_input": "- source: regex"}, "pattern"),
        ({"- source: hidden_input": "- source: endpoint"}, "url"),
        ({'form_selector: "form#login-form"': "use_form: false"}, "action"),
        ({"- source: hidden_input": "- source: endpoint\n        url: api/csrf"}, "url"),
        ({"        name: csrf_token": "        name: csrf_token\n        url: /api/csrf"}, "url"),
        (
            {"- source: hidden_input": '- source: endpoint\n        url: /api/csrf\n        pattern: "(a"'},
            "regex",
        ),
        ({"max_ttl: 8h": "max_ttl: 99999999999999999999h"}, "durée invalide"),
        ({"cookies: [FAKEAPPSESSID]": "cookies: []"}, "cookies"),
        ({"max_attempts: 1": "max_attempts: 9"}, "max_attempts"),
        ({"  owner: sesame-dev": "  owner: sesame-dev\n  secret: x"}, "Additional properties"),
    ],
)
def test_checks_mirror_the_proxy(replace, expected):
    errors = V.check(doc(**replace))
    assert errors and any(expected in e for e in errors), errors


def test_endpoint_token_is_valid():
    text = (
        (DESCRIPTORS / "fake-app.yaml")
        .read_text()
        .replace("- source: hidden_input", "- source: endpoint\n        url: /api/csrf-token")
    )
    assert V.check(yaml.safe_load(text)) == []


def test_reserved_identifier():
    assert any("réservé" in e for e in V.check(doc(app_id="new")))


def test_parse_yaml_rejects_aliases_syntax_and_size():
    with pytest.raises(DescriptorError, match="alias"):
        parse_yaml("a: &x [1]\nb: *x\n")
    with pytest.raises(DescriptorError, match="ligne 2"):
        parse_yaml("a: 1\n b: [\n")
    with pytest.raises(DescriptorError, match="objet"):
        parse_yaml("- 1\n")
    with pytest.raises(DescriptorError, match="volumineux"):
        parse_yaml("a: " + "x" * 70_000)


def test_yaml_follows_schema_order_and_round_trips():
    d = doc()
    shuffled = {"spec": dict(reversed(list(d["spec"].items()))), "metadata": d["metadata"], **d}
    text = V.to_yaml(shuffled)
    assert text.startswith("apiVersion: sesame/v1\nkind: AppDescriptor\nmetadata:\n  id: crm\n")
    assert text.index("upstream:") < text.index("login:") < text.index("health:")
    assert yaml.safe_load(text) == d


def test_guided_draft_is_valid_and_its_rules_match_the_login_page():
    d = draft(
        {
            "id": "crm",
            "name": "CRM",
            "public_host": "CRM.sesame.test",
            "base_url": "http://crm.interne:8080/",
            "groups": "ventes, support",
            "form_url": "/auth/login.php",
            "session_cookie": "PHPSESSID",
            "csrf_field": "_token",
            "failure_text": "Mot de passe incorrect",
        }
    )
    assert V.check(d) == []
    assert d["spec"]["public"]["host"] == "crm.sesame.test"
    assert d["spec"]["access"] == {"groups": ["ventes", "support"]}
    expiry = d["spec"]["expiry"]["any_of"][0]["location_matches"]
    assert re.search(expiry, "http://crm.interne:8080/auth/login.php?next=/")
    assert re.search(expiry, "/auth/login.php")
    assert not re.search(expiry, "/auth/loginXphp")
    success = d["spec"]["login"]["success"]["any_of"][0]["location_not_matches"]
    assert re.search(success, "/auth/login.php") and not re.search(success, "/accueil")


def stored(app_id: str, document: dict) -> StoredDescriptor:
    return StoredDescriptor(app_id, 1, document, None, "admin")


def test_merge_follows_the_rust_rules(apps):
    catalog = merge(
        apps,
        [
            stored("crm", doc()),
            stored("fake-app", doc(app_id="fake-app", host="x.test")),  # id pris par un fichier
            stored("dup", doc(app_id="dup", host="fake-app.sesame.localhost:8443")),
            stored("mismatch", doc(app_id="autre", host="m.test")),
            stored("broken", doc(app_id="broken", host="b.test", **{"max_attempts: 1": "max_attempts: 0"})),
        ],
        V,
    )
    assert list(catalog.apps) == ["fake-app", "crm"]
    assert catalog.apps["crm"].origin == "db" and catalog.apps["crm"].editable
    assert not catalog.apps["fake-app"].editable
    assert {r.stored.app_id: r.reason for r in catalog.rejected}.keys() == {
        "fake-app",
        "dup",
        "mismatch",
        "broken",
    }


def actions(service):
    return [(e.action, e.outcome, e.reason) for e in service.audit.events]


async def test_create_update_delete_lifecycle(service):
    app_id, revision = await service.create_descriptor(ADMIN, descriptor_yaml(), "c1")
    assert (app_id, revision) == ("crm", 1)
    app = await service.app("crm")
    assert app.origin == "db" and app.public_host == "crm.sesame.test" and app.revision == 1

    text = descriptor_yaml(**{"name: Appli factice": "name: CRM", "revision: 1": "revision: 42"})
    assert await service.update_descriptor(ADMIN, "crm", text, 1, "c2") == 2
    app = await service.app("crm")
    assert (app.name, app.revision, app.updated_by) == ("CRM", 2, ADMIN.actor)
    assert (await service.stored("crm")).document["metadata"]["revision"] == 2

    await service.delete_descriptor(ADMIN, "crm", 2, "c3")
    with pytest.raises(NotFound):
        await service.app("crm")
    history = await service.descriptors.history("crm")
    assert [(h.action, h.revision) for h in history] == [("deleted", 2), ("updated", 2), ("created", 1)]
    assert actions(service) == [
        ("descriptor_created", "success", "revision:1"),
        ("descriptor_updated", "success", "revision:2"),
        ("descriptor_deleted", "success", "revision:2"),
    ]
    assert all(e.actor == ADMIN.actor and e.app_id == "crm" for e in service.audit.events)


async def test_created_app_accepts_accounts(service):
    await service.create_descriptor(ADMIN, descriptor_yaml(), "c")
    await service.provision(ADMIN, "crm", "carol", {"username": "u", "password": SECRET}, "c")
    assert (await service.accounts.get_account("crm", "carol")).status == "active"
    assert SECRET not in repr(service.audit.events)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (descriptor_yaml(app_id="fake-app", host="x.test"), "fichier Git"),
        (descriptor_yaml(host="fake-app.sesame.localhost:8443"), "déjà utilisé par"),
        ("kind: [", "syntaxe"),
        (descriptor_yaml(**{"keys: [username, password]": "keys: [username]"}), "clé inconnue"),
    ],
)
async def test_create_refuses_invalid_or_colliding_descriptors(service, text, expected):
    with pytest.raises(InvalidDescriptor) as e:
        await service.create_descriptor(ADMIN, text, "c")
    assert any(expected in err for err in e.value.errors), e.value.errors
    assert actions(service) == [("descriptor_created", "failure", "invalid_descriptor")]
    assert await service.descriptors.list_descriptors() == []


async def test_create_refuses_an_existing_identifier(service):
    await service.create_descriptor(ADMIN, descriptor_yaml(), "c")
    with pytest.raises(InvalidDescriptor, match="invalide"):
        await service.create_descriptor(ADMIN, descriptor_yaml(host="autre.test"), "c")


async def test_update_rules(service):
    await service.create_descriptor(ADMIN, descriptor_yaml(), "c")
    await service.create_descriptor(ADMIN, descriptor_yaml("erp", "erp.test"), "c")
    service.audit.events.clear()
    with pytest.raises(InvalidDescriptor, match="invalide") as e:  # révision périmée
        await service.update_descriptor(ADMIN, "crm", descriptor_yaml(), 0, "c")
    assert "entre-temps" in e.value.errors[0]
    with pytest.raises(InvalidDescriptor) as e:
        await service.update_descriptor(ADMIN, "crm", descriptor_yaml("autre"), 1, "c")
    assert "ne peut pas changer" in e.value.errors[0]
    with pytest.raises(InvalidDescriptor) as e:
        await service.update_descriptor(ADMIN, "crm", descriptor_yaml(host="erp.test"), 1, "c")
    assert "déjà utilisé par" in e.value.errors[0]
    with pytest.raises(InvalidDescriptor, match="invalide"):
        await service.update_descriptor(ADMIN, "fake-app", descriptor_yaml("fake-app"), 1, "c")
    with pytest.raises(NotFound):
        await service.update_descriptor(ADMIN, "absente", descriptor_yaml("absente", "z.test"), 1, "c")
    assert actions(service) == [
        ("descriptor_updated", "failure", "conflict"),
        ("descriptor_updated", "failure", "invalid_descriptor"),
        ("descriptor_updated", "failure", "invalid_descriptor"),
        ("descriptor_updated", "failure", "invalid_descriptor"),
        ("descriptor_updated", "failure", "not_found"),
    ]
    assert (await service.app("crm")).revision == 1


async def test_delete_is_refused_while_accounts_remain(service):
    await service.create_descriptor(ADMIN, descriptor_yaml(), "c")
    await service.provision(ADMIN, "crm", "carol", {"username": "u", "password": "p"}, "c")
    with pytest.raises(InvalidInput, match="comptes"):
        await service.delete_descriptor(ADMIN, "crm", 1, "c")
    with pytest.raises(InvalidInput, match="Git"):
        await service.delete_descriptor(ADMIN, "fake-app", 1, "c")
    await service.delete(ADMIN, "crm", "carol", "c")
    with pytest.raises(InvalidInput, match="entre-temps"):
        await service.delete_descriptor(ADMIN, "crm", 7, "c")
    await service.delete_descriptor(ADMIN, "crm", 1, "c")
    reasons = [e.reason for e in service.audit.events if e.action == "descriptor_deleted"]
    assert reasons == ["accounts_remaining", "read_only", "conflict", "revision:1"]


def test_guided_draft_without_habilitation_omits_access():
    # Sans groupe ni utilisateur : access absent → le compte actif suffit.
    d = draft(
        {
            "id": "wiki",
            "name": "Wiki",
            "public_host": "wiki.sesame.test",
            "base_url": "http://wiki.interne:8080",
            "session_cookie": "SID",
        }
    )
    assert V.check(d) == []
    assert "access" not in d["spec"]
    app = app_from_doc(d, "ui")
    assert app.access_open and app.allows("nimporte", ())


def test_descriptor_without_access_is_valid_and_open():
    doc = parse_yaml(descriptor_yaml("wiki2", "wiki2.sesame.test"))
    doc["spec"].pop("access", None)
    assert V.check(doc) == []
    assert app_from_doc(doc, "ui").allows("bob", ())
