"""
gates/device_posture.py - Device trust for TriGate Gate 1.

Reads the security health ("posture") of THIS Windows PC with one read-only
PowerShell call and keeps the result in memory:

  * antivirus real-time protection on?   (Windows Security Center - also
                                          sees McAfee, Norton, ... not only
                                          Microsoft Defender)
  * antivirus definitions up to date?
  * Windows Firewall on for every profile (Domain / Private / Public)?
  * days since the last Windows update
  * system drive encrypted (BitLocker)?  (unknown on Windows Home - no penalty)
  * User Account Control (UAC) on?

The check runs in a background thread at start-up and then every
`device_check_minutes` (default 15), so scoring an event never waits for
PowerShell. Nothing is changed on the PC.

config.ini (both optional):
    device_trust         = true     # false = leave device health out of Gate 1
    device_check_minutes = 15
"""

from __future__ import annotations

import base64
import json
import logging
import subprocess
import sys
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Optional

log = logging.getLogger("TriGate.Device")

# Points (Gate 1 Trust). Negative = less trust.
P_AV_OFF = -15
P_AV_OLD = -5
P_FIREWALL_OFF = -10
P_UPDATES_VERY_OLD = -10        # last update > 60 days ago
P_UPDATES_OLD = -5              # last update 31-60 days ago
P_NOT_ENCRYPTED = -5
P_UAC_OFF = -5
P_HEALTHY = +5                  # every known check passed (at least 2 known)
DEVICE_PENALTY_CAP = -30        # one weak PC must not make every event "untrusted"

UPDATES_OLD_DAYS = 30
UPDATES_VERY_OLD_DAYS = 60
DEFENDER_SIGNATURE_MAX_DAYS = 7

_PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$r = @{}
try {
  $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
  $r.av = @($av | ForEach-Object { @{ name = [string]$_.displayName; state = [int]$_.productState } })
} catch {}
try {
  $mp = Get-MpComputerStatus -ErrorAction Stop
  $r.defender = @{ rtp = [bool]$mp.RealTimeProtectionEnabled; on = [bool]$mp.AntivirusEnabled;
                   sigAge = [int]$mp.AntivirusSignatureAge }
} catch {}
try {
  $r.fw = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
            @{ name = [string]$_.Name; on = ([string]$_.Enabled -eq 'True') } })
} catch {}
try {
  $h = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
  if ($h) { $r.lastUpdateDays = [int](((Get-Date) - $h.InstalledOn).TotalDays) }
} catch {}
if ($r.lastUpdateDays -eq $null) {
  try {
    $d = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastInstallationSuccessDate
    if ($d -and $d.Year -gt 2000) { $r.lastUpdateDays = [int](((Get-Date) - $d).TotalDays) }
  } catch {}
}
try {
  $b = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
  $r.bitlocker = [string]$b.ProtectionStatus
} catch {}
try {
  $r.uac = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop).EnableLUA
} catch {}
# ---- extra facts for the compliance report (do not change device trust) ----
try {
  $ap = auditpol /get /subcategory:'{0CCE9215-69AE-11D9-BED3-505054503030}' /r | Where-Object { $_ -ne '' } | ConvertFrom-Csv
  $row = $ap | Select-Object -First 1
  if ($row) { $r.auditLogon = [string]($row.PSObject.Properties | Select-Object -Index 4).Value }
} catch {}
try {
  foreach ($l in (net accounts)) {
    if ($l -match '^Lockout threshold:\s*(.+)$') { $r.lockout = $matches[1].Trim() }
    if ($l -match '^Minimum password length:\s*(\d+)') { $r.minPwLen = [int]$matches[1] }
  }
} catch {}
try { $g = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like '*-501' } | Select-Object -First 1
      if ($g) { $r.guest = [bool]$g.Enabled } } catch {}
try { $r.smb1 = [bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch {}
try { $r.rdpDeny = [int](Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop).fDenyTSConnections } catch {}
$r | ConvertTo-Json -Depth 4 -Compress
"""


@dataclass
class DevicePosture:
    """Security health of this PC. None = could not be checked (no points)."""
    checked_at: str = ""
    antivirus_names: list = field(default_factory=list)
    av_enabled: Optional[bool] = None
    av_up_to_date: Optional[bool] = None
    firewall_off_profiles: Optional[list] = None      # [] = all on
    last_update_days: Optional[int] = None
    disk_encrypted: Optional[bool] = None
    uac_enabled: Optional[bool] = None
    # compliance-only facts (not used for device trust points)
    audit_logon_failure: Optional[bool] = None
    audit_logon_success: Optional[bool] = None
    lockout_threshold: Optional[int] = None          # 0 = never locks
    min_password_length: Optional[int] = None
    guest_enabled: Optional[bool] = None
    smb1_enabled: Optional[bool] = None
    rdp_enabled: Optional[bool] = None
    error: str = ""

    def known_checks(self) -> int:
        return sum(v is not None for v in (self.av_enabled, self.firewall_off_profiles,
                                           self.last_update_days, self.disk_encrypted,
                                           self.uac_enabled))

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------
# Parsing (pure - unit tested on Linux)
# --------------------------------------------------------------------------
def _av_from_security_center(products: list) -> tuple[Optional[bool], Optional[bool], list]:
    """Windows Security Center productState: bit 0x1000 = real-time on,
    bit 0x10 = definitions out of date."""
    names, enabled, up_to_date = [], [], []
    for p in products or []:
        try:
            state = int(p.get("state"))
        except (TypeError, ValueError, AttributeError):
            continue
        name = str(p.get("name") or "antivirus")
        on = bool(state & 0x1000)
        names.append(name)
        enabled.append(on)
        if on:
            up_to_date.append(not bool(state & 0x10))
    if not names:
        return None, None, []
    any_on = any(enabled)
    return any_on, (all(up_to_date) if any_on else None), [n for n, on in zip(names, enabled) if on] or names


def parse_posture(raw: dict) -> DevicePosture:
    """Turn the PowerShell JSON into a DevicePosture."""
    p = DevicePosture(checked_at=datetime.now().strftime("%Y-%m-%d %H:%M"))
    raw = raw or {}

    av_list = raw.get("av")
    if isinstance(av_list, dict):                 # PowerShell 5 collapses 1-item arrays
        av_list = [av_list]
    on, fresh, names = _av_from_security_center(av_list or [])
    if on is None and isinstance(raw.get("defender"), dict):
        d = raw["defender"]
        on = bool(d.get("rtp")) and bool(d.get("on"))
        names = ["Microsoft Defender"]
        try:
            fresh = int(d.get("sigAge", 0)) <= DEFENDER_SIGNATURE_MAX_DAYS if on else None
        except (TypeError, ValueError):
            fresh = None
    p.av_enabled, p.av_up_to_date, p.antivirus_names = on, fresh, names

    fw = raw.get("fw")
    if isinstance(fw, dict):
        fw = [fw]
    if isinstance(fw, list) and fw:
        p.firewall_off_profiles = [str(x.get("name") or "?") for x in fw if not x.get("on")]

    try:
        if raw.get("lastUpdateDays") is not None:
            p.last_update_days = max(0, int(raw["lastUpdateDays"]))
    except (TypeError, ValueError):
        pass

    bl = str(raw.get("bitlocker") or "").strip().lower()
    if bl in ("on", "1"):
        p.disk_encrypted = True
    elif bl in ("off", "0"):
        p.disk_encrypted = False

    if raw.get("uac") is not None:
        try:
            p.uac_enabled = int(raw["uac"]) != 0
        except (TypeError, ValueError):
            pass

    audit = str(raw.get("auditLogon") or "").strip().lower()
    if audit:
        if "no auditing" in audit:
            p.audit_logon_failure = p.audit_logon_success = False
        elif "success" in audit or "failure" in audit:
            p.audit_logon_failure = "failure" in audit
            p.audit_logon_success = "success" in audit
    lock = str(raw.get("lockout") or "").strip().lower()
    if lock:
        if lock.isdigit():
            p.lockout_threshold = int(lock)
        elif lock in ("never", "nie", "jamais", "nunca"):
            p.lockout_threshold = 0
    for key, attr in (("minPwLen", "min_password_length"),):
        try:
            if raw.get(key) is not None:
                setattr(p, attr, int(raw[key]))
        except (TypeError, ValueError):
            pass
    for key, attr in (("guest", "guest_enabled"), ("smb1", "smb1_enabled")):
        if isinstance(raw.get(key), bool):
            setattr(p, attr, raw[key])
    if raw.get("rdpDeny") is not None:
        try:
            p.rdp_enabled = int(raw["rdpDeny"]) == 0
        except (TypeError, ValueError):
            pass
    return p


def posture_factors(p: Optional[DevicePosture]) -> list[tuple[int, str]]:
    """Gate 1 reasons for this PC's health: [(points, text), ...]."""
    if p is None or p.known_checks() == 0:
        return []
    bad: list[tuple[int, str]] = []
    if p.av_enabled is False:
        bad.append((P_AV_OFF, "Device: no antivirus real-time protection is on"))
    elif p.av_enabled and p.av_up_to_date is False:
        bad.append((P_AV_OLD, "Device: antivirus definitions are out of date"))
    if p.firewall_off_profiles:
        bad.append((P_FIREWALL_OFF, f"Device: Windows Firewall is OFF ({', '.join(p.firewall_off_profiles)})"))
    if p.last_update_days is not None:
        if p.last_update_days > UPDATES_VERY_OLD_DAYS:
            bad.append((P_UPDATES_VERY_OLD, f"Device: last Windows update was {p.last_update_days} days ago"))
        elif p.last_update_days > UPDATES_OLD_DAYS:
            bad.append((P_UPDATES_OLD, f"Device: last Windows update was {p.last_update_days} days ago"))
    if p.disk_encrypted is False:
        bad.append((P_NOT_ENCRYPTED, "Device: system drive is not encrypted (BitLocker off)"))
    if p.uac_enabled is False:
        bad.append((P_UAC_OFF, "Device: User Account Control (UAC) is turned off"))

    if bad:
        total = sum(x[0] for x in bad)
        if total < DEVICE_PENALTY_CAP:              # keep the reasons, cap the total
            scale = DEVICE_PENALTY_CAP / total
            bad = [(int(round(pts * scale)), txt) for pts, txt in bad]
            diff = DEVICE_PENALTY_CAP - sum(x[0] for x in bad)
            bad[0] = (bad[0][0] + diff, bad[0][1])
        return bad
    if p.known_checks() >= 2:
        ok = []
        if p.av_enabled:
            ok.append("antivirus on")
        if p.firewall_off_profiles == []:
            ok.append("firewall on")
        if p.last_update_days is not None:
            ok.append(f"updated {p.last_update_days} days ago")
        if p.disk_encrypted:
            ok.append("disk encrypted")
        return [(P_HEALTHY, "Device: this PC is healthy (" + ", ".join(ok or ["all checks passed"]) + ")")]
    return []


def summary(p: Optional[DevicePosture]) -> str:
    if p is None:
        return "not checked"
    if p.error and p.known_checks() == 0:
        return f"not available ({p.error})"
    parts = []
    if p.av_enabled is not None:
        av = ", ".join(p.antivirus_names) or "antivirus"
        parts.append(f"{av} {'ON' if p.av_enabled else 'OFF'}"
                     + (" (definitions old)" if p.av_up_to_date is False else ""))
    if p.firewall_off_profiles is not None:
        parts.append("firewall ON" if not p.firewall_off_profiles
                     else f"firewall OFF ({', '.join(p.firewall_off_profiles)})")
    if p.last_update_days is not None:
        parts.append(f"last update {p.last_update_days} d ago")
    if p.disk_encrypted is not None:
        parts.append(f"BitLocker {'ON' if p.disk_encrypted else 'OFF'}")
    if p.uac_enabled is not None:
        parts.append(f"UAC {'ON' if p.uac_enabled else 'OFF'}")
    return ", ".join(parts) or "no checks available"


# --------------------------------------------------------------------------
# Collection (Windows only)
# --------------------------------------------------------------------------
def collect_windows_posture(timeout: int = 90) -> Optional[DevicePosture]:
    """Run the read-only PowerShell check. None on non-Windows."""
    if not sys.platform.startswith("win"):
        return None
    try:
        encoded = base64.b64encode(_PS_SCRIPT.encode("utf-16-le")).decode("ascii")
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-EncodedCommand", encoded],
            capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        out = (res.stdout or "").strip()
        if not out:
            return DevicePosture(checked_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
                                 error=(res.stderr or "no output").strip()[:200])
        return parse_posture(json.loads(out[out.find("{"):]))
    except Exception as exc:                        # never break the agent
        return DevicePosture(checked_at=datetime.now().strftime("%Y-%m-%d %H:%M"), error=str(exc)[:200])


class PostureMonitor:
    """Keeps the latest DevicePosture fresh in a background thread."""

    def __init__(self, enabled: bool = True, minutes: float = 15, collector=collect_windows_posture):
        self.enabled = enabled
        self.minutes = max(1.0, float(minutes or 15))
        self._collector = collector
        self._posture: Optional[DevicePosture] = None
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._last_summary = ""
        self._listeners: list = []

    def add_listener(self, fn) -> None:
        """fn(posture) is called (in the posture thread) after every check -
        used to send the compliance report to the dashboard."""
        self._listeners.append(fn)

    def get(self) -> Optional[DevicePosture]:
        if not self.enabled:
            return None
        with self._lock:
            return self._posture

    def set(self, posture: Optional[DevicePosture]) -> None:
        with self._lock:
            self._posture = posture

    def refresh(self) -> Optional[DevicePosture]:
        p = self._collector()
        if p is not None:
            self.set(p)
            text = summary(p)
            if text != self._last_summary:           # log only when something changed
                self._last_summary = text
                if any(pts < 0 for pts, _ in posture_factors(p)):
                    log.warning("Device health (Gate 1): %s", text)
                else:
                    log.info("Device health (Gate 1): %s", text)
            for fn in list(self._listeners):
                try:
                    fn(p)
                except Exception as exc:              # a listener must never stop the checks
                    log.debug("posture listener failed: %s", exc)
        return p

    def start(self) -> None:
        if not self.enabled or self._thread is not None or not sys.platform.startswith("win"):
            return

        def loop():
            # small delay: let the agent finish starting (and set its log level)
            if self._stop.wait(5):
                return
            while not self._stop.is_set():
                self.refresh()
                self._stop.wait(self.minutes * 60)

        self._thread = threading.Thread(target=loop, name="TriGateDevicePosture", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()


_monitor = PostureMonitor(enabled=True)


def get_posture_monitor() -> PostureMonitor:
    return _monitor


def configure_device_trust(enabled: Any = True, minutes: Any = 15, start: bool = True) -> PostureMonitor:
    global _monitor
    _monitor.stop()
    on = str(enabled).strip().lower() not in ("false", "0", "no", "off")
    try:
        mins = float(minutes) if minutes not in (None, "") else 15
    except (TypeError, ValueError):
        mins = 15
    _monitor = PostureMonitor(enabled=on, minutes=mins)
    if start:
        _monitor.start()
    return _monitor


def set_posture_monitor(m: PostureMonitor) -> None:
    global _monitor
    _monitor = m
