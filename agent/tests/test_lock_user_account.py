"""Run button -> revoke_identity -> `net user <name> /active:no` (Windows only in real life)."""

import subprocess
import types

import pytest

from response import real_response_engine as rre


def _event(user_id):
    return types.SimpleNamespace(metadata={"payload": {"user_id": user_id}})


@pytest.fixture
def fake_net(monkeypatch):
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        if cmd[-1] == "/active:no":
            return types.SimpleNamespace(returncode=0, stdout="The command completed successfully.", stderr="")
        return types.SimpleNamespace(returncode=0, stdout="User name    x\nAccount active               No\n", stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setenv("COMPUTERNAME", "Anonmoyous")
    monkeypatch.setenv("USERNAME", "lalit")
    return calls


@pytest.mark.asyncio
async def test_local_pc_prefix_is_stripped(fake_net):
    eng = rre.RealResponseEngine.__new__(rre.RealResponseEngine)
    msg = await eng._lock_user_account(_event("Anonmoyous\\aibootest2"))
    assert fake_net[0] == ["net", "user", "aibootest2", "/active:no"]
    assert fake_net[1] == ["net", "user", "aibootest2"]
    assert "aibootest2" in msg and "verified" in msg


@pytest.mark.asyncio
async def test_plain_and_dot_names(fake_net):
    eng = rre.RealResponseEngine.__new__(rre.RealResponseEngine)
    await eng._lock_user_account(_event(".\\bob"))
    await eng._lock_user_account(_event("carol"))
    assert fake_net[0][2] == "bob" and fake_net[2][2] == "carol"


@pytest.mark.asyncio
async def test_domain_account_refused_clearly(fake_net):
    eng = rre.RealResponseEngine.__new__(rre.RealResponseEngine)
    with pytest.raises(RuntimeError, match="domain controller"):
        await eng._lock_user_account(_event("CORP\\alice"))
    assert fake_net == []


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["lalit", "Anonmoyous\\LALIT", "SYSTEM"])
async def test_never_locks_yourself_or_system(fake_net, name):
    eng = rre.RealResponseEngine.__new__(rre.RealResponseEngine)
    with pytest.raises(RuntimeError, match="Refusing"):
        await eng._lock_user_account(_event(name))
    assert fake_net == []
