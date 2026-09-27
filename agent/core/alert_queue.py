"""
agent/core/alert_queue.py — Offline SQLite queue for AiBoO alerts.
Ensures zero alert loss during network outages.
Supports multiple backend endpoints (/findings, /heartbeat, /pseudo-lock, etc.)
"""
import sqlite3
import json
import time
import os
import threading
import logging
import asyncio
from typing import Optional, Dict, Any

import httpx

log = logging.getLogger("AlertQueue")

# Path to the SQLite database file (saved in the agent's root directory)
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alerts_queue.db")


class OfflineQueueManager:
    """
    Singleton manager for the offline alert queue.
    - Saves alerts to SQLite immediately.
    - Runs a background retry thread to forward them to the backend.
    - Supports multiple endpoints (findings, heartbeat, pseudo-lock, etc.)
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, remote_url: Optional[str] = None, api_key: Optional[str] = None):
        if self._initialized:
            return

        self.remote_url = remote_url
        self.api_key = api_key
        self._db_lock = threading.Lock()
        self._running = False
        self._retry_thread = None

        # Ensure the database and table exist
        self._init_db()
        self._initialized = True
        log.info("OfflineQueueManager initialized (DB: %s)", DB_PATH)

    @classmethod
    def get_instance(cls):
        """Get the singleton instance."""
        if cls._instance is None:
            raise RuntimeError("OfflineQueueManager not initialized. Call with remote_url/api_key first.")
        return cls._instance

    def _init_db(self):
        """Create the SQLite table if it doesn't exist."""
        with self._db_lock:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            # Create table without any comments or extra characters
            c.execute('''
                CREATE TABLE IF NOT EXISTS pending_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    payload TEXT,
                    attempts INTEGER DEFAULT 0
                )
            ''')
            # Create index separately (no comments inside the string)
            c.execute('CREATE INDEX IF NOT EXISTS idx_attempts ON pending_alerts (attempts, timestamp)')
            conn.commit()
            conn.close()

    # --- Public Async Methods ---

    async def add(self, payload: dict) -> int:
        """
        Legacy add method – queues a finding to the default 'findings' endpoint.
        For backward compatibility with LocalActionExecutor.
        """
        return await self.add_to_endpoint("findings", payload)

    async def add_to_endpoint(self, endpoint: str, payload: Dict[str, Any]) -> int:
        """
        Add an alert to the queue for a specific backend endpoint.
        endpoint: 'findings', 'heartbeat', 'pseudo-lock', 'correlated', 'gate-decision'
        payload: the actual data to send.
        Returns the ID of the inserted row.
        """
        wrapped = {
            "endpoint": endpoint,
            "payload": payload,
        }
        return await asyncio.to_thread(self._add_sync, wrapped)

    def _add_sync(self, wrapped_payload: dict) -> int:
        """Synchronous DB insert (runs in a thread pool)."""
        with self._db_lock:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(
                "INSERT INTO pending_alerts (timestamp, payload) VALUES (?, ?)",
                (time.time(), json.dumps(wrapped_payload))
            )
            alert_id = c.lastrowid
            conn.commit()
            conn.close()
            log.debug("Alert queued locally ID=%d (endpoint: %s)",
                      alert_id, wrapped_payload.get("endpoint", "unknown"))
            return alert_id

    # --- Retry Worker (runs in a background thread) ---

    def start_retry(self, remote_url: str, api_key: str):
        """Start the background thread that retries sending queued alerts."""
        self.remote_url = remote_url
        self.api_key = api_key

        if self._running:
            log.warning("Retry worker already running.")
            return

        self._running = True
        self._retry_thread = threading.Thread(target=self._retry_worker, daemon=True)
        self._retry_thread.start()
        log.info("Offline retry worker started (target URL: %s)", remote_url)

    def stop_retry(self):
        """Stop the retry worker gracefully."""
        self._running = False
        if self._retry_thread and self._retry_thread.is_alive():
            self._retry_thread.join(timeout=3)
        log.info("Offline retry worker stopped")

    def _retry_worker(self):
        """
        Main loop for the retry thread. Runs every 30 seconds.
        Fetches pending alerts (max 5 attempts), sends them to the appropriate endpoint,
        deletes on success, increments attempts on failure.
        """
        while self._running:
            try:
                pending = self._get_pending_alerts()
                if pending:
                    log.info("Retry worker: %d pending alert(s) to send", len(pending))
                    for alert_id, payload_str in pending:
                        if not self._running:
                            break
                        try:
                            wrapped = json.loads(payload_str)
                            endpoint = wrapped.get("endpoint", "findings")
                            inner_payload = wrapped.get("payload", {})

                            url = f"{self.remote_url}/api/agent/{endpoint}"
                            headers = {
                                "Content-Type": "application/json",
                                "X-API-Key": self.api_key,
                            }

                            response = httpx.post(
                                url,
                                headers=headers,
                                json=inner_payload,
                                timeout=10.0
                            )

                            if response.status_code in (200, 201):
                                self._delete_alert(alert_id)
                                log.info("Retry worker sent queued alert ID=%d to %s", alert_id, endpoint)
                            else:
                                self._increment_attempt(alert_id)
                                log.warning(
                                    "Retry failed for alert ID=%d (status %d) to %s",
                                    alert_id, response.status_code, endpoint
                                )
                        except httpx.RequestError as e:
                            log.error("Retry worker network error for alert %d: %s", alert_id, e)
                            self._increment_attempt(alert_id)
                        except Exception as e:
                            log.error("Retry worker unexpected error for alert %d: %s", alert_id, e)
                            self._increment_attempt(alert_id)

                # Wait 30 seconds before next check
                for _ in range(30):
                    if not self._running:
                        break
                    time.sleep(1)

            except Exception as e:
                log.error("Retry worker loop crashed: %s", e)
                time.sleep(60)

    # --- Internal DB helpers (synchronous, thread-safe) ---

    def _get_pending_alerts(self):
        """Fetch all alerts with less than 5 attempts, ordered by oldest first."""
        with self._db_lock:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(
                "SELECT id, payload FROM pending_alerts WHERE attempts < 5 ORDER BY timestamp"
            )
            rows = c.fetchall()
            conn.close()
            return rows

    def _delete_alert(self, alert_id: int):
        """Remove an alert from the queue after successful sending."""
        with self._db_lock:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("DELETE FROM pending_alerts WHERE id = ?", (alert_id,))
            conn.commit()
            conn.close()
            log.debug("Deleted queued alert ID=%d", alert_id)

    def _increment_attempt(self, alert_id: int):
        """Increment the attempts counter for a failed send."""
        with self._db_lock:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(
                "UPDATE pending_alerts SET attempts = attempts + 1 WHERE id = ?",
                (alert_id,)
            )
            conn.commit()
            conn.close()