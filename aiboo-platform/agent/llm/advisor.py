"""
llm/advisor.py — Shared LLM helper for AiBoO AI agents.

- call_llm(): Anthropic messages API with rate limiting + retries.
  Returns None when no API key / on failure, so callers can fall back
  to local heuristics (the platform never depends on the LLM).
- InsightStore: bounded store of narrative reports & threat hypotheses,
  served to the dashboard via GET /llm/insights.
- heuristic_advice(): offline, rule-based isolation advice used when the
  LLM is unavailable.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from core.config import config

log = logging.getLogger("LLM.Advisor")

_RETRY_MAX = 3
_RETRY_DELAY = 1.5
_RATE_LIMIT_PER_SEC = 4
_last_call_time = 0.0

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"


def llm_available() -> bool:
    return bool(config.llm_api_key or os.getenv("ANTHROPIC_API_KEY", ""))


async def call_llm(system: str, user: str, max_tokens: int = 400) -> Optional[str]:
    """Call the Anthropic messages API. Returns text or None (caller falls back)."""
    key = config.llm_api_key or os.getenv("ANTHROPIC_API_KEY", "")
    if not key:
        return None
    global _last_call_time
    payload = {
        "model": config.llm_model,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    }
    async with httpx.AsyncClient(timeout=httpx.Timeout(config.request_timeout)) as client:
        for attempt in range(_RETRY_MAX):
            try:
                elapsed = time.monotonic() - _last_call_time
                if elapsed < 1.0 / _RATE_LIMIT_PER_SEC:
                    await asyncio.sleep(1.0 / _RATE_LIMIT_PER_SEC - elapsed)
                _last_call_time = time.monotonic()

                resp = await client.post(
                    ANTHROPIC_URL,
                    headers={
                        "x-api-key": key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json=payload,
                )
                if resp.status_code == 429:
                    await asyncio.sleep(_RETRY_DELAY * (2 ** attempt))
                    continue
                resp.raise_for_status()
                return resp.json()["content"][0]["text"].strip()
            except httpx.HTTPStatusError as e:
                log.error("LLM HTTP error (attempt %d): %s", attempt + 1, e)
            except httpx.TimeoutException:
                log.error("LLM timeout (attempt %d)", attempt + 1)
            except Exception as e:
                log.error("LLM call failed: %s", e)
                break
            if attempt < _RETRY_MAX - 1:
                await asyncio.sleep(_RETRY_DELAY * (2 ** attempt))
    return None


# ── Insight store (narratives + hypotheses) ──────────────────────────────────

class InsightStore:
    """Bounded, thread-safe-enough store for AI-generated insights."""
    MAX = 50

    def __init__(self) -> None:
        self.reports: deque[dict[str, Any]] = deque(maxlen=self.MAX)
        self.hypotheses: deque[dict[str, Any]] = deque(maxlen=self.MAX)

    def add_report(self, alert_id: str, narrative: str, source: str = "llm") -> None:
        self.reports.appendleft({
            "id": alert_id,
            "narrative": narrative,
            "source": source,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def add_hypothesis(self, event_id: str, hypothesis: str, entity: str,
                       source: str = "llm") -> None:
        self.hypotheses.appendleft({
            "id": event_id,
            "entity": entity,
            "hypothesis": hypothesis,
            "source": source,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def snapshot(self) -> dict[str, list[dict[str, Any]]]:
        return {"reports": list(self.reports), "hypotheses": list(self.hypotheses)}


insights = InsightStore()


# ── Offline heuristic advice ─────────────────────────────────────────────────

_ADVICE_MAP: dict[str, tuple[list[str], str]] = {
    "network_intrusion": (
        ["isolate_asset", "pseudo_lock", "escalate_soc"],
        "Host shows active intrusion signals. Isolate the endpoint from the network, "
        "pseudo-lock the targeted service to a decoy, and preserve logs before escalation.",
    ),
    "identity_mismatch": (
        ["force_logout", "step_up_auth", "escalate_soc"],
        "Identity cannot be verified with confidence. Force logout of all sessions, "
        "require step-up authentication, and monitor for lateral movement.",
    ),
    "physical_intrusion": (
        ["lock_zone", "notify_security"],
        "Unauthorized physical access detected. Lock the affected zone immediately "
        "and dispatch security to verify on-site.",
    ),
    "insider_threat": (
        ["revoke_identity", "notify_hr", "escalate_soc"],
        "Behavior matches insider-threat pattern. Revoke elevated access, notify HR/legal, "
        "and begin evidence collection on file-transfer activity.",
    ),
    "memory_threat": (
        ["terminate_process", "quarantine_file", "isolate_asset"],
        "Malicious code is active in memory. Terminate the process, quarantine related "
        "files, and isolate the host before further encryption/exfiltration.",
    ),
    "anomalous_behavior": (
        ["challenge_mfa", "step_up_auth"],
        "Behavior deviates from the user baseline. Issue an MFA challenge and apply "
        "step-up authentication on sensitive resources.",
    ),
    "insider_threat_converged": (
        ["revoke_identity", "notify_hr", "notify_legal"],
        "Multi-day converged insider pattern confirmed. Revoke access, involve HR and "
        "legal, and retain audit evidence.",
    ),
    "ransomware_prelude": (
        ["isolate_asset", "terminate_process", "escalate_soc"],
        "Pre-encryption sequence detected. Isolate the host NOW, kill suspicious "
        "processes, and verify backups before the payload detonates.",
    ),
    "ghost_login": (
        ["force_logout", "revoke_session", "step_up_auth"],
        "Login from an impossible location while the user is badged on-site. "
        "Terminate sessions and require re-authentication.",
    ),
    "tailgating": (
        ["lock_zone", "notify_security"],
        "Tailgating observed at a restricted boundary. Lock the zone and review "
        "camera footage for identification.",
    ),
    "zero_trust_violation": (
        ["block_access", "step_up_auth"],
        "Zero Trust policy violation. Block the access attempt and require "
        "device posture re-validation.",
    ),
}

_DEFAULT_ADVICE = (
    ["isolate_asset", "notify_security", "escalate_soc"],
    "Unverified high-severity threat. Contain the affected asset, notify the "
    "security team, and escalate for manual review.",
)


def heuristic_advice(threat_type: str, metadata: dict[str, Any],
                     summary: str) -> tuple[list[str], str]:
    """Offline fallback: (recommended actions, advice text)."""
    actions, text = _ADVICE_MAP.get(threat_type, _DEFAULT_ADVICE)
    # Context-aware extra line
    target = metadata.get("src_ip") or metadata.get("endpoint") or metadata.get("user_id")
    extra = f" Primary target: {target}." if target else ""
    sev = ""
    if float(metadata.get("anomaly_score", 0) or 0) >= 2.5:
        sev = " Statistical anomaly score is high — treat as confirmed."
    return actions, text + extra + sev
