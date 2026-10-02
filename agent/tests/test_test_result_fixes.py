"""
Fixes from the 2 Oct 2026 client test (screenshots of Alerts / reports):
  1. old offline-queue items are never re-sent (they came back as ~30 new
     "identity mismatch" alerts on every fresh install)
  2. the old correlation engine is off by default
  3. AiBoO does not report its own PowerShell helper (posture check) as
     "Malicious process detected: powershell.exe"
"""
import json
import os
import sqlite3
import time
from types import SimpleNamespace

import pytest

from core.event_bus import EventBus


# --------------------------------------------------------------- 1. queue
@pytest.fixture
def queue(tmp_path, monkeypatch):
    import core.alert_queue as aq
    monkeypatch.setattr(aq, "DB_PATH", str(tmp_path / "alerts_queue.db"))
    monkeypatch.setattr(aq.OfflineQueueManager, "_instance", None)
    monkeypatch.delenv("AIBOO_QUEUE_MAX_AGE_HOURS", raising=False)
    return aq


def _seed(path, rows):
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE IF NOT EXISTS pending_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL, payload TEXT, attempts INTEGER DEFAULT 0)""")
    for ts, attempts, name in rows:
        conn.execute("INSERT INTO pending_alerts (timestamp, payload, attempts) VALUES (?, ?, ?)",
                     (ts, json.dumps({"endpoint": "findings", "payload": {"summary": name}}), attempts))
    conn.commit()
    conn.close()


def _names(path):
    conn = sqlite3.connect(path)
    out = sorted(json.loads(p)["payload"]["summary"] for (p,) in conn.execute("SELECT payload FROM pending_alerts"))
    conn.close()
    return out


def test_old_and_dead_items_are_dropped_at_start(queue):
    now = time.time()
    _seed(queue.DB_PATH, [
        (now - 20 * 86400, 0, "september"),     # 20 days old -> drop
        (now - 25 * 3600, 3, "yesterday"),      # > 24 h -> drop
        (now - 60, 5, "failed-5-times"),        # dead -> drop
        (now - 60, 2, "recent"),                # keep
    ])
    queue.OfflineQueueManager(remote_url="http://x", api_key="k")
    assert _names(queue.DB_PATH) == ["recent"]


def test_stale_items_are_not_fetched_for_sending(queue):
    qm = queue.OfflineQueueManager(remote_url="http://x", api_key="k")
    now = time.time()
    _seed(queue.DB_PATH, [(now - 3 * 86400, 0, "old"), (now - 5, 0, "new")])
    rows = qm._get_pending_alerts()
    assert [json.loads(p)["payload"]["summary"] for _, p in rows] == ["new"]


def test_max_age_can_be_changed(queue, monkeypatch):
    monkeypatch.setenv("AIBOO_QUEUE_MAX_AGE_HOURS", "72")
    now = time.time()
    _seed(queue.DB_PATH, [(now - 48 * 3600, 0, "two-days"), (now - 100 * 3600, 0, "four-days")])
    queue.OfflineQueueManager(remote_url="http://x", api_key="k")
    assert _names(queue.DB_PATH) == ["two-days"]


@pytest.mark.asyncio
async def test_new_items_still_queue_normally(queue):
    qm = queue.OfflineQueueManager(remote_url="http://x", api_key="k")
    await qm.add_to_endpoint("findings", {"summary": "fresh"})
    assert _names(queue.DB_PATH) == ["fresh"]
    assert len(qm._get_pending_alerts()) == 1


def test_queue_file_is_not_in_git():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    with open(os.path.join(root, ".gitignore"), encoding="utf-8") as fh:
        assert "alerts_queue.db" in fh.read()


# ------------------------------------------------- 2. old correlation off
def test_old_correlation_engine_off_by_default():
    import core.orchestrator as orch
    src = open(orch.__file__, encoding="utf-8").read()
    assert "_cfg_bool(self.config, 'legacy_correlation', False)" in src
    assert "if self._legacy_correlation:\n            self.correlation.start()" in src


# ------------------------------------------- 3. own PowerShell not flagged
def _proc(name, cmdline, ppid, pid=5555):
    return SimpleNamespace(info={"pid": pid, "ppid": ppid, "name": name, "cmdline": cmdline,
                                 "memory_info": SimpleNamespace(rss=50 * 1024 * 1024)})


POSTURE_CMD = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
               "-EncodedCommand", "J" * 400]


class TestOwnHelpers:
    @pytest.fixture
    def agent(self):
        from agents.cyber_threat_agent import CyberThreatAgent
        return CyberThreatAgent(EventBus())

    def test_child_of_agent_is_ours(self, agent):
        assert agent._started_by_aiboo(_proc("powershell.exe", POSTURE_CMD, ppid=os.getpid()))

    def test_other_parent_is_not_ours(self, agent):
        assert not agent._started_by_aiboo(_proc("powershell.exe", POSTURE_CMD, ppid=1))

    def test_missing_ppid_is_not_ours(self, agent):
        p = SimpleNamespace(info={"pid": 1, "name": "powershell.exe", "cmdline": POSTURE_CMD})
        assert not agent._started_by_aiboo(p)

    @pytest.mark.asyncio
    async def test_scan_skips_own_posture_check_but_flags_others(self, agent, monkeypatch):
        import agents.cyber_threat_agent as cta
        own = _proc("powershell.exe", POSTURE_CMD, ppid=os.getpid(), pid=1001)
        foreign = _proc("powershell.exe", POSTURE_CMD, ppid=1, pid=1002)
        monkeypatch.setattr(cta.psutil, "process_iter", lambda attrs=None: iter([own, foreign]))
        threats = await agent._scan_memory_for_threats()
        assert [t.pid for t in threats] == [1002]
        assert threats[0].threat_type == "ENCODED_POWERSHELL"
