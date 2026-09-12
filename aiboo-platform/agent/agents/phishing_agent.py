from __future__ import annotations

import asyncio
import re
from typing import Optional
from urllib.parse import urlparse

from core.base_agent import BaseAgent
from core.event_bus import EventBus
from core.events import (
    AgentFinding, ResponseAction, Severity,
    ThreatEvent, ThreatType,
)

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
    ".club", ".work", ".download", ".review", ".stream",
    ".bid", ".trade", ".date", ".win", ".men",
}

LOOKALIKE_DOMAINS = {
    "g00gle": "google", "go0gle": "google", "goog1e": "google",
    "googIe": "google", "faceb00k": "facebook", "faceb0ok": "facebook",
    "fac3book": "facebook", "paypa1": "paypal", "paypaI": "paypal",
    "paypаl": "paypal", "micr0soft": "microsoft", "micros0ft": "microsoft",
    "app1e": "apple", "appIe": "apple", "arnazon": "amazon",
    "ama zon": "amazon", "1inkedin": "linkedin", "Iinkedin": "linkedin",
}

PHISHING_KEYWORDS = [
    "verify", "confirm", "urgent", "suspended", "limited",
    "unusual activity", "unauthorized", "login attempt",
    "click here", "reset password", "account alert",
    "security alert", "update your", "payment failed",
    "invoice attached", "action required", "immediate attention",
]

SPOOFED_SENDER_PATTERNS = [
    r"no[-]?reply", r"noreply", r"admin@", r"support@",
    r"security@", r"service@", r"team@", r"help@",
    r"notification", r"alert@", r"mailer@",
]

SUSPICIOUS_URL_PATTERNS = [
    r"bit\.ly/", r"tinyurl\.com/", r"tiny\.cc/", r"ow\.ly/",
    r"is\.gd/", r"buff\.ly/", r"shorturl\.at/", r"tr\.im/",
    r"url\.ie/", r"rb\.gy/", r"tiny\.link/",
]

PHISHING_EMAIL_PATTERNS = {
    "generic_greeting": r"\b(dear\s+(user|customer|member|sir|madam))\b",
    "threat_language": r"\b(immediately|within\s+24\s+hours|or\s+else|failure\s+to)\b",
    "urgency_phrase": r"\b(expire(s|d)?\s+(today|soon)|last\s+warning|final\s+notice)\b",
    "spelling_errors": r"\b(recieve|seperate|occured|priviledge|definately)\b",
    "exclamation_chain": r"!{2,}",
}

PHISHING_EMAIL_PATTERNS_CASE_SENSITIVE = {
    "excessive_caps": r"[A-Z\s]{20,}",
}


class PhishingDetectionAgent(BaseAgent):
    def __init__(self, bus: EventBus) -> None:
        super().__init__("PhishingDetectionAgent", bus)
        self._reported_domains: dict[str, int] = {}

    def can_handle(self, event: ThreatEvent) -> bool:
        return event.threat_type in (
            ThreatType.NETWORK_INTRUSION,
            ThreatType.ANOMALOUS_BEHAVIOR,
            ThreatType.INSIDER_THREAT,
        )

    def _analyze_url(self, url: str) -> dict:
        result = {"suspicious": False, "risk_score": 0.0, "indicators": []}
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            full_url = url.lower()

            for shortener in SUSPICIOUS_URL_PATTERNS:
                if re.search(shortener, full_url):
                    result["suspicious"] = True
                    result["risk_score"] += 0.3
                    result["indicators"].append(f"URL shortener detected: {shortener}")

            if parsed.scheme and parsed.scheme != "https":
                result["suspicious"] = True
                result["risk_score"] += 0.2
                result["indicators"].append("Non-HTTPS URL")

            if parsed.hostname:
                hostname = parsed.hostname.lower()
                parts = hostname.split(".")
                if len(parts) >= 2:
                    tld = "." + parts[-1]
                    if tld in SUSPICIOUS_TLDS:
                        result["suspicious"] = True
                        result["risk_score"] += 0.3
                        result["indicators"].append(f"Suspicious TLD: {tld}")

                for lookalike, original in LOOKALIKE_DOMAINS.items():
                    if lookalike in domain:
                        result["suspicious"] = True
                        result["risk_score"] += 0.4
                        result["indicators"].append(f"Lookalike domain: {domain} (mimics {original})")

                at_count = hostname.count("@")
                if at_count > 0:
                    result["suspicious"] = True
                    result["risk_score"] += 0.2
                    result["indicators"].append("URL contains @ symbol (deceptive)")

                dash_count = hostname.count("-")
                if dash_count > 2:
                    result["suspicious"] = True
                    result["risk_score"] += 0.1
                    result["indicators"].append(f"Excessive hyphens in domain: {dash_count}")

            if parsed.path and len(parsed.path) > 50:
                result["suspicious"] = True
                result["risk_score"] += 0.1
                result["indicators"].append("Unusually long URL path")

            ip_pattern = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed.hostname or "")
            if ip_pattern:
                result["suspicious"] = True
                result["risk_score"] += 0.3
                result["indicators"].append("IP address used instead of domain name")

        except Exception:
            pass

        result["risk_score"] = min(result["risk_score"], 1.0)
        return result

    def _analyze_email_content(self, subject: str, body: str, sender: str) -> dict:
        result = {"suspicious": False, "risk_score": 0.0, "indicators": []}
        text = f"{subject} {body}"

        for keyword in PHISHING_KEYWORDS:
            if keyword in text.lower():
                result["suspicious"] = True
                result["risk_score"] += 0.15
                result["indicators"].append(f"Phishing keyword: '{keyword}'")

        for pattern_name, pattern in PHISHING_EMAIL_PATTERNS.items():
            if re.search(pattern, text, re.IGNORECASE):
                result["suspicious"] = True
                result["risk_score"] += 0.1
                result["indicators"].append(f"Phishing pattern: {pattern_name}")

        for pattern_name, pattern in PHISHING_EMAIL_PATTERNS_CASE_SENSITIVE.items():
            if re.search(pattern, text):
                result["suspicious"] = True
                result["risk_score"] += 0.1
                result["indicators"].append(f"Phishing pattern: {pattern_name}")

        sender_lower = (sender or "").lower()
        for spoof_pattern in SPOOFED_SENDER_PATTERNS:
            if re.search(spoof_pattern, sender_lower):
                result["suspicious"] = True
                result["risk_score"] += 0.2
                result["indicators"].append(f"Spoofed sender pattern: {spoof_pattern}")

        result["risk_score"] = min(result["risk_score"], 1.0)
        return result

    def _check_known_phishing_domain(self, domain: str) -> dict:
        result = {"known_threat": False, "risk_score": 0.0}
        if domain in self._reported_domains:
            self._reported_domains[domain] += 1
            if self._reported_domains[domain] >= 3:
                result["known_threat"] = True
                result["risk_score"] = 0.8
        else:
            self._reported_domains[domain] = 1
        return result

    async def analyse(self, event: ThreatEvent) -> AgentFinding | None:
        await asyncio.sleep(0.05)

        p = event.payload
        actions: list[ResponseAction] = [ResponseAction.LOG, ResponseAction.ALERT_DASHBOARD]
        confidence = 0.0
        severity = event.severity
        indicators = []

        urls = p.get("urls", []) or [p.get("url", "")]
        subject = p.get("subject", p.get("email_subject", ""))
        body = p.get("body", p.get("message", p.get("email_body", "")))
        sender = p.get("sender", p.get("from", p.get("source", "")))
        user_id = p.get("user_id", p.get("recipient", "unknown"))

        url_results = []
        for url in urls:
            if url:
                url_result = self._analyze_url(url)
                if url_result["suspicious"]:
                    url_results.append(url_result)
                    indicators.extend(url_result["indicators"])
                    confidence += url_result["risk_score"] * 0.4

                    parsed = urlparse(url)
                    if parsed.hostname:
                        known = self._check_known_phishing_domain(parsed.hostname)
                        if known["known_threat"]:
                            confidence += known["risk_score"] * 0.5
                            indicators.append(f"Known phishing domain: {parsed.hostname}")

        email_result = self._analyze_email_content(subject, body, sender)
        if email_result["suspicious"]:
            indicators.extend(email_result["indicators"])
            confidence += email_result["risk_score"] * 0.3

        confidence = min(confidence, 1.0)

        if confidence == 0.0:
            return None

        if confidence >= 0.7:
            severity = Severity.CRITICAL
            actions.extend([
                ResponseAction.BLOCK_ACCESS,
                ResponseAction.REVOKE_IDENTITY,
                ResponseAction.ESCALATE_SOC,
                ResponseAction.NOTIFY_SECURITY,
            ])
        elif confidence >= 0.4:
            severity = Severity.HIGH
            actions.extend([
                ResponseAction.REVOKE_IDENTITY,
                ResponseAction.NOTIFY_SECURITY,
            ])
        else:
            severity = Severity.MEDIUM
            actions.append(ResponseAction.NOTIFY_SECURITY)

        summary = (
            f"Phishing attempt detected for {user_id}. "
            f"Confidence: {confidence:.0%}. "
            f"Indicators: {'; '.join(indicators[:5])}"
        )

        return AgentFinding(
            agent_name=self.name,
            event_id=event.event_id,
            threat_type=ThreatType.NETWORK_INTRUSION,
            severity=severity,
            confidence=round(confidence, 2),
            summary=summary,
            actions=list(dict.fromkeys(actions)),
            metadata={
                "user_id": user_id,
                "phishing_indicators": indicators,
                "url_results": url_results,
                "email_analysis": email_result,
                "subject": subject,
            },
        )
