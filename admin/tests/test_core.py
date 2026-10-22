# SPDX-License-Identifier: Apache-2.0
import pytest
from sesame_admin.descriptors import DescriptorError, load_dir
from sesame_admin.identity import ClaimsError, identity_from_claims, valid_user_key
from sesame_admin.ports import NotFound, Unavailable
from sesame_admin.service import InvalidInput

from .conftest import ADMIN, SCHEMA

SECRET = "Sup3r-Secret-Value"


def test_descriptors_are_loaded_read_only(apps):
    app = apps["fake-app"]
    assert app.credential_keys == ("username", "password")
    assert (app.groups, app.access_open) == (("fake-app-users",), False)
    assert "apiVersion: sesame/v1" in app.source


def test_invalid_descriptor_is_rejected(tmp_path):
    (tmp_path / "bad.yaml").write_text("apiVersion: sesame/v1\nkind: AppDescriptor\n")
    with pytest.raises(DescriptorError):
        load_dir(tmp_path, SCHEMA)


def test_user_keys():
    assert valid_user_key("alice") and valid_user_key("a.martin@example.org")
    for bad in ("", ".", "..", "a/b", "a b", "é", "x" * 257):
        assert not valid_user_key(bad), bad


def test_identity_from_claims():
    u = identity_from_claims(
        {"iss": "https://idp", "sub": "s1", "preferred_username": "admin", "groups": ["sesame-admins", 1]},
        "https://idp",
        "preferred_username",
        "groups",
    )
    assert u.groups == ("sesame-admins",) and u.actor == "https://idp|s1"
    assert identity_from_claims({"sub": "s1"}, "i", "sub", "groups").groups == ()
    with pytest.raises(ClaimsError):
        identity_from_claims({"sub": "s1", "preferred_username": "../x"}, "i", "preferred_username", "groups")


async def test_provision_writes_secret_then_activates_account(service):
    await service.provision(ADMIN, "fake-app", " carol ", {"username": "cdupont", "password": SECRET}, "c1")
    assert service.secrets.entries[("fake-app", "carol")] == {"username": "cdupont", "password": SECRET}
    account = await service.accounts.get_account("fake-app", "carol")
    assert account and account.status == "active"
    events = service.audit.events
    assert [(e.action, e.outcome) for e in events] == [
        ("credential_written", "success"),
        ("account_status_changed", "success"),
    ]
    assert all(
        e.actor == ADMIN.actor and e.target_user == "carol" and e.correlation_id == "c1" for e in events
    )
    assert SECRET not in repr(events)


async def test_provision_reactivates_failed_account(service):
    await service.accounts.upsert_active("fake-app", "alice")
    await service.accounts.set_status("fake-app", "alice", "failed", "login_rejected")
    await service.provision(ADMIN, "fake-app", "alice", {"username": "u", "password": "p"}, "c")
    account = await service.accounts.get_account("fake-app", "alice")
    assert account.status == "active" and account.status_reason is None


@pytest.mark.parametrize(
    ("user", "fields"),
    [
        ("../x", {"username": "u", "password": "p"}),
        ("carol", {"username": "u"}),
        ("carol", {"username": "u", "password": "p", "extra": "e"}),
        ("carol", {"username": "u", "password": ""}),
    ],
)
async def test_provision_rejects_invalid_input(service, user, fields):
    with pytest.raises(InvalidInput):
        await service.provision(ADMIN, "fake-app", user, fields, "c")
    assert service.secrets.entries == {} and service.audit.events == []


async def test_provision_unknown_app(service):
    with pytest.raises(NotFound):
        await service.provision(ADMIN, "inconnue", "carol", {}, "c")


async def test_provision_audits_secret_store_failure(service):
    async def down(*_):
        raise Unavailable("coffre injoignable")

    service.secrets.write_credential = down
    with pytest.raises(Unavailable):
        await service.provision(ADMIN, "fake-app", "carol", {"username": "u", "password": SECRET}, "c")
    assert [(e.action, e.outcome, e.reason) for e in service.audit.events] == [
        ("credential_written", "failure", "secret_store_unavailable")
    ]
    assert await service.accounts.get_account("fake-app", "carol") is None


async def test_disable_enable_delete(service):
    await service.provision(ADMIN, "fake-app", "carol", {"username": "u", "password": "p"}, "c")
    await service.set_status(ADMIN, "fake-app", "carol", "disabled", "c")
    assert (await service.accounts.get_account("fake-app", "carol")).status == "disabled"
    await service.set_status(ADMIN, "fake-app", "carol", "active", "c")
    assert (await service.accounts.get_account("fake-app", "carol")).status == "active"
    with pytest.raises(InvalidInput):
        await service.set_status(ADMIN, "fake-app", "carol", "failed", "c")
    with pytest.raises(NotFound):
        await service.set_status(ADMIN, "fake-app", "personne", "disabled", "c")
    await service.delete(ADMIN, "fake-app", "carol", "c")
    assert ("fake-app", "carol") not in service.secrets.entries
    assert await service.accounts.get_account("fake-app", "carol") is None
    assert service.audit.events[-2].action == "credential_deleted"


async def test_stdout_audit_format_matches_rust_services(capsys):
    from sesame_admin.audit import AuditEvent, StdoutAuditSink

    await StdoutAuditSink().record(AuditEvent.of("credential_written", "success", ADMIN, app_id="fake-app"))
    line = capsys.readouterr().out.strip()
    assert line.startswith('{"log_type":"audit",') and '"action":"credential_written"' in line


async def test_disable_all_covers_every_app_and_revokes_sessions(service):
    for app in ("fake-app", "retired-app"):  # retired-app : descripteur retiré
        await service.accounts.upsert_active(app, "carol")
        service.accounts.app_sessions[(app, "carol")] = 1
    await service.accounts.upsert_active("fake-app", "dave")
    service.accounts.app_sessions[("fake-app", "dave")] = 1

    assert await service.disable_all(ADMIN, "carol", "c") == 2
    assert {a.status for a in await service.accounts.list_user_accounts("carol")} == {"disabled"}
    assert ("fake-app", "carol") not in service.accounts.app_sessions
    assert ("retired-app", "carol") not in service.accounts.app_sessions
    assert service.accounts.app_sessions == {("fake-app", "dave"): 1}
    assert [e.reason for e in service.audit.events] == ["disabled:admin_bulk"] * 2
    assert await service.disable_all(ADMIN, "carol", "c") == 0


async def test_disable_and_delete_revoke_open_sessions(service):
    await service.provision(ADMIN, "fake-app", "carol", {"username": "u", "password": "p"}, "c")
    service.accounts.app_sessions[("fake-app", "carol")] = 2
    await service.set_status(ADMIN, "fake-app", "carol", "disabled", "c")
    assert ("fake-app", "carol") not in service.accounts.app_sessions
    service.accounts.app_sessions[("fake-app", "carol")] = 1
    await service.delete(ADMIN, "fake-app", "carol", "c")
    assert ("fake-app", "carol") not in service.accounts.app_sessions


# --- Comptes multiples (ADR 0034) ----------------------------------------------------------


async def test_labelled_accounts_live_beside_the_default_account(service):
    creds = {"username": "cdupont", "password": SECRET}
    assert await service.provision(ADMIN, "fake-app", "carol", creds, "c1") == "default"
    admin_creds = {"username": "cdupont-adm", "password": SECRET + "-adm"}
    assert (
        await service.provision(ADMIN, "fake-app", "carol", admin_creds, "c2", " Admin prod ") == "admin-prod"
    )

    assert service.secrets.entries[("fake-app", "carol", "admin-prod")] == admin_creds
    assert service.secrets.entries[("fake-app", "carol")] == creds
    default = await service.accounts.get_account("fake-app", "carol")
    extra = await service.accounts.get_account("fake-app", "carol", "admin-prod")
    assert default.is_default and not extra.is_default and extra.label == "Admin prod"
    written = [e for e in service.audit.events if e.action == "credential_written"]
    assert [e.account_id for e in written] == ["default", "admin-prod"]
    assert SECRET not in repr(service.audit.events)

    # Même libellé : identifiants remplacés, pas de nouveau compte.
    await service.provision(ADMIN, "fake-app", "carol", creds, "c3", "admin prod")
    assert len(await service.accounts.list_accounts("fake-app")) == 2
    for bad in ("!!!", "x" * 65):
        with pytest.raises(InvalidInput):
            await service.provision(ADMIN, "fake-app", "carol", creds, "c4", bad)


async def test_account_operations_target_one_account(service):
    creds = {"username": "u", "password": SECRET}
    await service.provision(ADMIN, "fake-app", "carol", creds, "c1")
    await service.provision(ADMIN, "fake-app", "carol", creds, "c2", "Admin")
    service.accounts.app_sessions[("fake-app", "carol")] = 1
    service.accounts.app_sessions[("fake-app", "carol", "admin")] = 1

    # Désactiver un compte ne révoque que ses sessions.
    await service.set_status(ADMIN, "fake-app", "carol", "disabled", "c3", "admin")
    assert (await service.accounts.get_account("fake-app", "carol", "admin")).status == "disabled"
    assert (await service.accounts.get_account("fake-app", "carol")).status == "active"
    assert service.accounts.app_sessions == {("fake-app", "carol"): 1}
    assert service.audit.events[-1].account_id == "admin"

    # Le compte par défaut ne se supprime pas tant qu'il en reste d'autres.
    with pytest.raises(InvalidInput):
        await service.delete(ADMIN, "fake-app", "carol", "c4")
    await service.set_default(ADMIN, "fake-app", "carol", "admin", "c5")
    assert service.audit.events[-1].action == "account_default_changed"
    await service.delete(ADMIN, "fake-app", "carol", "c6")  # « default » n'est plus le compte par défaut
    assert ("fake-app", "carol") not in service.secrets.entries
    assert await service.accounts.get_account("fake-app", "carol") is None
    assert (await service.accounts.get_account("fake-app", "carol", "admin")).is_default
    with pytest.raises(NotFound):
        await service.set_default(ADMIN, "fake-app", "carol", "inconnu", "c7")
    with pytest.raises(InvalidInput):
        await service.set_status(ADMIN, "fake-app", "carol", "active", "c8", "../x")

    # Tout désactiver couvre tous les comptes.
    await service.set_status(ADMIN, "fake-app", "carol", "active", "c9", "admin")
    await service.provision(ADMIN, "fake-app", "carol", creds, "c10", "Support")
    assert await service.disable_all(ADMIN, "carol", "c11") == 2
    assert {a.status for a in await service.accounts.list_user_accounts("carol")} == {"disabled"}
