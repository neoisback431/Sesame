# SPDX-License-Identifier: Apache-2.0
import json

import httpx
import pytest
from sesame_admin.openbao import OpenBaoConfig, OpenBaoSecretWriter
from sesame_admin.ports import Unavailable

CFG = OpenBaoConfig("http://bao:8200", "secret", "sesame/apps", "role", "approle-secret-id")


def writer(handler):
    return OpenBaoSecretWriter(CFG, httpx.AsyncClient(transport=httpx.MockTransport(handler)))


async def test_writes_and_deletes_with_relogin_on_revoked_token():
    calls = []
    logins = 0

    def handler(req: httpx.Request) -> httpx.Response:
        nonlocal logins
        if req.url.path == "/v1/auth/approle/login":
            logins += 1
            return httpx.Response(
                200, json={"auth": {"client_token": f"tok-{logins}", "lease_duration": 3600}}
            )
        if req.headers.get("x-vault-token") != "tok-2":
            return httpx.Response(403, json={"errors": ["permission denied"]})
        calls.append((req.method, req.url.path, req.content))
        return httpx.Response(204)

    w = writer(handler)
    await w.write_credential("fake-app", "carol", {"username": "u", "password": "p"})
    await w.delete_credential("fake-app", "carol")
    assert calls[0][:2] == ("POST", "/v1/secret/data/sesame/apps/fake-app/users/carol")
    assert json.loads(calls[0][2]) == {"data": {"username": "u", "password": "p"}}
    assert calls[1][:2] == ("DELETE", "/v1/secret/metadata/sesame/apps/fake-app/users/carol")
    assert logins == 2


async def test_errors_never_contain_secrets():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/login"):
            return httpx.Response(200, json={"auth": {"client_token": "t", "lease_duration": 60}})
        return httpx.Response(500, text="boom p4ssw0rd")

    with pytest.raises(Unavailable) as err:
        await writer(handler).write_credential("fake-app", "carol", {"username": "u", "password": "p4ssw0rd"})
    assert "p4ssw0rd" not in str(err.value)
    assert "approle-secret-id" not in repr(writer(handler))


async def test_rejects_path_traversal():
    w = writer(lambda r: httpx.Response(200, json={"auth": {"client_token": "t", "lease_duration": 60}}))
    for app, user in [("fake-app", "../x"), ("../x", "carol"), ("a/b", "carol")]:
        with pytest.raises(ValueError):
            await w.write_credential(app, user, {"k": "v"})


async def test_unreachable_store():
    def handler(req):
        raise httpx.ConnectError("refused")

    with pytest.raises(Unavailable):
        await writer(handler).write_credential("fake-app", "carol", {"k": "v"})
