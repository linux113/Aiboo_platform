"""
llm/narrative_agent.py — LLM Narrative Agent (optional)

Subscribes to CorrelatedAlert and generates a plain-English
incident report using the Anthropic API.

Enable by setting ANTHROPIC_API_KEY in your .env file.
"""
from __future__ import annotations
import asyncio
import logging
import os
import time

import httpx

from core.event_bus import EventBus
from core.events import CorrelatedAlert
from core.config import config

log = logging.getLogger("LLM.NarrativeAgent")

_RETRY_MAX = 3
_RETRY_DELAY = 2.0
_RATE_LIMIT_PER_SEC = 4
_last_call_time: float = 0.0


class NarrativeAgent:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._key = config.llm_api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self._model = config.llm_model
        self._ready = bool(self._key)
        self._client: httpx.AsyncClient | None = None

    def start(self) -> None:
        if not self._ready:
            log.warning("ANTHROPIC_API_KEY not set — NarrativeAgent disabled.")
            return
        self.bus.subscribe(CorrelatedAlert, self._on_alert)
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(config.request_timeout))
        log.info("NarrativeAgent active — will generate incident reports.")

    async def stop(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _on_alert(self, alert: CorrelatedAlert) -> None:
        asyncio.create_task(self._generate(alert))

    async def _generate(self, alert: CorrelatedAlert) -> None:
        if not self._ready or not self._client:
            return
        try:
            payload = {
                "model": self._model,
                "max_tokens": 500,
                "system": (
                    "You are AiBoO's security narrative engine. "
                    "Write a concise, plain-English incident report "
                    "for a SOC analyst. Include: what happened, "
                    "which systems are affected, what actions were taken, "
                    "and the recommended next step."
                ),
                "messages": [{
                    "role": "user",
                    "content": (
                        f"Alert: {alert.description}\n"
                        f"Severity: {alert.severity.value}\n"
                        f"Confidence: {alert.confidence:.0%}\n"
                        f"Findings: {[f.summary for f in alert.findings]}\n"
                        f"Actions taken: {[a.value for a in alert.actions]}"
                    ),
                }],
            }
            for attempt in range(_RETRY_MAX):
                try:
                    global _last_call_time
                    elapsed = time.monotonic() - _last_call_time
                    if elapsed < 1.0 / _RATE_LIMIT_PER_SEC:
                        await asyncio.sleep(1.0 / _RATE_LIMIT_PER_SEC - elapsed)
                    _last_call_time = time.monotonic()

                    resp = await self._client.post(
                        "https://api.anthropic.com/v1/messages",
                        headers={
                            "x-api-key": self._key,
                            "anthropic-version": "2023-06-01",
                            "content-type": "application/json",
                        },
                        json=payload,
                    )
                    if resp.status_code == 429:
                        wait = _RETRY_DELAY * (2 ** attempt)
                        log.warning("Rate limited, retrying in %ss", wait)
                        await asyncio.sleep(wait)
                        continue
                    resp.raise_for_status()
                    data = resp.json()
                    narrative = data["content"][0]["text"]
                    log.info("Narrative for alert %s:\n%s", alert.alert_id, narrative)
                    return
                except httpx.HTTPStatusError as e:
                    log.error("HTTP error generating narrative (attempt %d): %s", attempt + 1, e)
                    if attempt < _RETRY_MAX - 1:
                        await asyncio.sleep(_RETRY_DELAY * (2 ** attempt))
                except httpx.TimeoutException:
                    log.error("Timeout generating narrative (attempt %d)", attempt + 1)
                    if attempt < _RETRY_MAX - 1:
                        await asyncio.sleep(_RETRY_DELAY * (2 ** attempt))
        except Exception as e:
            log.error("Narrative generation failed: %s", e)
