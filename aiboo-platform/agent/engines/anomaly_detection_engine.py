from __future__ import annotations

import asyncio
import logging
import statistics
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any

from core.event_bus import EventBus
from core.events import (
    AgentFinding, ThreatEvent, Severity, ThreatType, ResponseAction,
)

log = logging.getLogger("AnomalyDetectionEngine")

DEFAULT_WINDOW_MINUTES = 60
DEFAULT_ZSCORE_THRESHOLD = 2.5
DEFAULT_BASELINE_MIN_SAMPLES = 5


class MetricBaseline:
    def __init__(self, name: str, window_minutes: int = DEFAULT_WINDOW_MINUTES):
        self.name = name
        self.window_minutes = window_minutes
        self.values: list[dict] = []

    def add_value(self, value: float, timestamp: datetime | None = None) -> None:
        self.values.append({
            "value": value,
            "timestamp": timestamp or datetime.now(timezone.utc),
        })
        self._evict_stale()

    def _evict_stale(self) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=self.window_minutes)
        self.values = [v for v in self.values if v["timestamp"] > cutoff]

    def get_statistics(self) -> dict:
        self._evict_stale()
        if len(self.values) < 2:
            return {"mean": 0, "stdev": 0, "count": len(self.values)}

        vals = [v["value"] for v in self.values]
        try:
            mean = statistics.mean(vals)
            stdev = statistics.stdev(vals) if len(vals) > 1 else 0
        except statistics.StatisticsError:
            mean = 0
            stdev = 0

        return {
            "mean": mean,
            "stdev": stdev,
            "count": len(vals),
            "min": min(vals),
            "max": max(vals),
            "p50": statistics.median(vals),
        }

    def calculate_zscore(self, value: float) -> float:
        stats = self.get_statistics()
        if stats["stdev"] == 0 or stats["count"] < DEFAULT_BASELINE_MIN_SAMPLES:
            return 0.0
        return abs(value - stats["mean"]) / stats["stdev"] if stats["stdev"] > 0 else 0.0


class AnomalyDetectionEngine:
    def __init__(
        self,
        bus: EventBus,
        zscore_threshold: float = DEFAULT_ZSCORE_THRESHOLD,
    ) -> None:
        self.bus = bus
        self.zscore_threshold = zscore_threshold
        self._running = False
        self._baselines: dict[str, MetricBaseline] = {}
        self._anomaly_history: list[dict] = []
        self._entity_event_counts: dict[str, dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )

    def start(self) -> None:
        self.bus.subscribe(AgentFinding, self._ingest_finding)
        self.bus.subscribe(ThreatEvent, self._ingest_event)
        log.info(
            "Anomaly detection engine active — z-score threshold=%.1f, "
            "baseline window=%d min",
            self.zscore_threshold, DEFAULT_WINDOW_MINUTES,
        )

    def stop(self) -> None:
        self._running = False
        log.info("Anomaly detection engine stopped")

    def _get_baseline(self, metric_name: str) -> MetricBaseline:
        if metric_name not in self._baselines:
            self._baselines[metric_name] = MetricBaseline(metric_name)
        return self._baselines[metric_name]

    def _track_entity_rate(self, entity: str, event_type: str) -> int:
        self._entity_event_counts[entity][event_type] += 1
        key = f"entity_rate:{entity}:{event_type}"
        baseline = self._get_baseline(key)
        baseline.add_value(float(self._entity_event_counts[entity][event_type]))
        return self._entity_event_counts[entity][event_type]

    async def _ingest_finding(self, finding: AgentFinding) -> None:
        if finding.confidence < 0.2:
            return

        entity = (
            finding.metadata.get("user_id")
            or finding.metadata.get("src_ip")
            or finding.metadata.get("device_id")
        )
        if entity:
            count = self._track_entity_rate(entity, finding.threat_type.value)
            key = f"finding:{finding.threat_type.value}"
            baseline = self._get_baseline(key)
            baseline.add_value(float(finding.confidence))

        if finding.metadata:
            for meta_key in ("risk_score", "threat_score", "confidence"):
                if meta_key in finding.metadata:
                    try:
                        val = float(finding.metadata[meta_key])
                        key = f"meta:{meta_key}"
                        baseline = self._get_baseline(key)
                        baseline.add_value(val)
                    except (ValueError, TypeError):
                        pass

    async def _ingest_event(self, event: ThreatEvent) -> None:
        for metric_key in ("packet_rate", "data_volume_gb", "unusual_data_volume_gb"):
            if metric_key in event.payload:
                try:
                    val = float(event.payload[metric_key])
                    key = f"event:{metric_key}"
                    baseline = self._get_baseline(key)
                    baseline.add_value(val)
                    zscore = baseline.calculate_zscore(val)
                    if zscore > self.zscore_threshold:
                        await self._report_anomaly(
                            metric_name=metric_key,
                            current_value=val,
                            zscore=zscore,
                            stats=baseline.get_statistics(),
                            event=event,
                        )
                except (ValueError, TypeError):
                    pass

    async def _report_anomaly(
        self,
        metric_name: str,
        current_value: float,
        zscore: float,
        stats: dict,
        event: ThreatEvent,
    ) -> None:
        severity = (
            Severity.CRITICAL if zscore > self.zscore_threshold * 2
            else Severity.HIGH if zscore > self.zscore_threshold * 1.5
            else Severity.MEDIUM
        )

        anomaly_record = {
            "metric": metric_name,
            "current_value": current_value,
            "zscore": round(zscore, 2),
            "mean": round(stats["mean"], 2),
            "stdev": round(stats["stdev"], 2),
            "severity": severity.value,
            "event_id": event.event_id,
            "source": event.source,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._anomaly_history.append(anomaly_record)

        log.warning(
            "ANOMALY [%s] value=%.2f zscore=%.2f (mean=%.2f, stdev=%.2f) — %s",
            metric_name, current_value, zscore,
            stats["mean"], stats["stdev"], severity.value,
        )

        anomaly_finding = AgentFinding(
            agent_name=self.__class__.__name__,
            event_id=event.event_id,
            threat_type=ThreatType.ANOMALOUS_BEHAVIOR,
            severity=severity,
            confidence=round(min(abs(zscore) / 10, 1.0), 2),
            summary=(
                f"Statistical anomaly detected: {metric_name} = {current_value:.2f} "
                f"(z-score: {zscore:.1f}, mean: {stats['mean']:.2f})"
            ),
            actions=[
                ResponseAction.LOG,
                ResponseAction.ALERT_DASHBOARD,
                ResponseAction.NOTIFY_SECURITY,
            ],
            metadata=anomaly_record,
        )
        await self.bus.publish(anomaly_finding)

        if len(self._anomaly_history) > 10000:
            self._anomaly_history = self._anomaly_history[-5000:]

    def get_anomalies(
        self,
        severity: Severity | None = None,
        limit: int = 100,
    ) -> list[dict]:
        result = self._anomaly_history
        if severity:
            result = [a for a in result if a.get("severity") == severity.value]
        return result[-limit:]

    def get_baseline_summary(self) -> dict:
        summary = {}
        for name, baseline in self._baselines.items():
            if baseline.values:
                summary[name] = baseline.get_statistics()
        return summary

    def get_entity_rates(self, entity: str | None = None) -> dict:
        if entity:
            return dict(self._entity_event_counts.get(entity, {}))
        return {
            e: dict(counts)
            for e, counts in self._entity_event_counts.items()
        }
