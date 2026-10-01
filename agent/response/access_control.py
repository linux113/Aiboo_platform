"""
response/access_control.py - DYNAMIC access control on this Windows PC.

Before, the Zero Trust "access control" actions only wrote a log line
(force_logout, revoke_session, step_up_auth, ...). These are now real:

  restrict_identity  Disable a local account for N minutes (default 30) AND
                     log off its open sessions. It is re-enabled
                     AUTOMATICALLY when the time is up - even after an agent
                     restart (state saved in access_control_state.json).
                     An account that was already disabled is left alone (we
                     never re-enable something we did not disable).
  lift_restriction   Re-enable it now (dashboard button).
  force_logout /     Log off every session of that user (WTS API - works on
  revoke_session     Windows Home too, where logoff.exe / quser.exe are missing).
  step_up_auth /     Lock the screen, so the person at the PC must type the
  challenge_mfa      password again (Windows has no MFA prompt of its own).
  throttle_segment   Limit the upload speed from this PC to an IP or range
                     (Windows QoS policy, New-NetQosPolicy in the ActiveStore
                     = disappears on reboot) for N minutes, then removed
                     automatically.
  remove_throttle    Remove it now.

Safety rules (never broken):
  * never the account the agent runs as, never SYSTEM / service accounts
  * never log off the agent's own session
  * never throttle "everything" (/0../7) or the dashboard backend's IP
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import Any, Callable, Optional

log = logging.getLogger("AccessControl")

DEFAULT_RESTRICT_MINUTES = 30
MAX_MINUTES = 24 * 60
DEFAULT_THROTTLE_KBPS = 256
MIN_THROTTLE_KBPS = 64
_NAME_SAFE = re.compile(r"[^A-Za-z0-9-]")


def _is_windows() -> bool:
    return sys.platform.startswith("win")


def _minutes(value: Any, default: int) -> int:
    try:
        m = int(float(value))
    except (TypeError, ValueError):
        m = default
    return max(1, min(MAX_MINUTES, m))


def _me() -> set:
    names = set()
    for getter in (lambda: os.environ.get("USERNAME", ""), lambda: __import__("getpass").getuser()):
        try:
            v = getter()
        except Exception:
            v = ""
        if v:
            names.add(v.split("\\")[-1].lower())
    return names


# ---------------------------------------------------------------- Windows API
def wts_sessions() -> list[tuple[int, str]]:
    """[(session_id, user_name)] for sessions that have a user (WTS API)."""
    import ctypes
    from ctypes import wintypes

    class WTS_SESSION_INFOW(ctypes.Structure):
        _fields_ = [("SessionId", wintypes.DWORD), ("pWinStationName", wintypes.LPWSTR),
                    ("State", ctypes.c_int)]

    wts = ctypes.WinDLL("wtsapi32")
    info = ctypes.POINTER(WTS_SESSION_INFOW)()
    count = wintypes.DWORD()
    if not wts.WTSEnumerateSessionsW(None, 0, 1, ctypes.byref(info), ctypes.byref(count)):
        raise OSError(ctypes.get_last_error() or "WTSEnumerateSessions failed")
    out = []
    try:
        for i in range(count.value):
            sid = info[i].SessionId
            buf = wintypes.LPWSTR()
            size = wintypes.DWORD()
            if wts.WTSQuerySessionInformationW(None, sid, 5, ctypes.byref(buf), ctypes.byref(size)):  # 5 = WTSUserName
                name = buf.value or ""
                wts.WTSFreeMemory(buf)
                if name:
                    out.append((int(sid), name))
    finally:
        wts.WTSFreeMemory(info)
    return out


def wts_logoff(session_id: int) -> bool:
    import ctypes
    return bool(ctypes.WinDLL("wtsapi32").WTSLogoffSession(None, int(session_id), False))


def account_enabled(name: str) -> Optional[bool]:
    """True/False from NetUserGetInfo (language-independent); None = unknown."""
    if not _is_windows():
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class USER_INFO_1(ctypes.Structure):
            _fields_ = [("name", wintypes.LPWSTR), ("password", wintypes.LPWSTR),
                        ("password_age", wintypes.DWORD), ("priv", wintypes.DWORD),
                        ("home_dir", wintypes.LPWSTR), ("comment", wintypes.LPWSTR),
                        ("flags", wintypes.DWORD), ("script_path", wintypes.LPWSTR)]

        net = ctypes.WinDLL("netapi32")
        buf = ctypes.POINTER(USER_INFO_1)()
        rc = net.NetUserGetInfo(None, name, 1, ctypes.byref(buf))
        if rc != 0:
            return None
        flags = buf.contents.flags
        net.NetApiBufferFree(buf)
        return not bool(flags & 0x2)          # UF_ACCOUNTDISABLE
    except Exception:
        return None


def _run(cmd: list, timeout: int = 20) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _powershell(script: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return _run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-Command", script], timeout=timeout)


# --------------------------------------------------------------------- class
class WindowsAccessControl:
    def __init__(self, state_path: Optional[str] = None, *,
                 run: Callable = _run, powershell: Callable = _powershell,
                 sessions: Callable = wts_sessions, logoff: Callable = wts_logoff,
                 enabled_check: Callable = account_enabled, lock: Optional[Callable] = None,
                 protected_ips: Optional[list] = None, clock=time.time):
        self.state_path = state_path
        self._run, self._ps = run, powershell
        self._sessions, self._logoff, self._enabled = sessions, logoff, enabled_check
        self._lock_fn = lock
        self.protected_ips = [str(x) for x in (protected_ips or []) if x]
        self._clock = clock
        self._mutex = threading.RLock()
        self.state: dict = {"restrictions": {}, "throttles": {}}
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._load()

    # -------------------------------------------------------------- state io
    def _load(self) -> None:
        if not self.state_path or not os.path.exists(self.state_path):
            return
        try:
            with open(self.state_path, "r", encoding="utf-8") as fh:
                raw = json.load(fh) or {}
            self.state["restrictions"] = dict(raw.get("restrictions") or {})
            self.state["throttles"] = dict(raw.get("throttles") or {})
        except (OSError, ValueError) as exc:
            log.warning("access control state unreadable (%s) - starting empty", exc)

    def _save(self) -> None:
        if not self.state_path:
            return
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.state_path)), exist_ok=True)
            with open(self.state_path + ".tmp", "w", encoding="utf-8") as fh:
                json.dump(self.state, fh, indent=1)
            os.replace(self.state_path + ".tmp", self.state_path)
        except OSError as exc:
            log.warning("access control state not saved: %s", exc)

    @staticmethod
    def _until_text(epoch: float) -> str:
        return datetime.fromtimestamp(epoch).strftime("%H:%M")

    # ------------------------------------------------------------- accounts
    @staticmethod
    def _check_user(user: str) -> str:
        from response.real_response_engine import (
            _refuse_if_self_or_system, _to_local_account_name, _validate_user_id)
        user = str(user or "").strip()
        if not user or not _validate_user_id(user):
            raise RuntimeError(f"Invalid user name: {user!r}")
        name = _to_local_account_name(user)
        _refuse_if_self_or_system(name)
        return name

    def _net_user_active(self, name: str, active: bool) -> None:
        res = self._run(["net", "user", name, f"/active:{'yes' if active else 'no'}"])
        if res.returncode != 0:
            raise RuntimeError(f"net user failed: {(res.stderr or res.stdout).strip()[:200]}")

    def restrict_identity(self, user: str, minutes: Any = DEFAULT_RESTRICT_MINUTES, reason: str = "") -> str:
        name = self._check_user(user)
        mins = _minutes(minutes, DEFAULT_RESTRICT_MINUTES)
        until = self._clock() + mins * 60
        with self._mutex:
            existing = self.state["restrictions"].get(name.lower())
            if existing:
                existing["until"] = max(float(existing["until"]), until)
                self._save()
                return (f"'{name}' was already restricted - now until "
                        f"{self._until_text(existing['until'])} ({mins} min)")
            was = self._enabled(name)
            if was is False:
                return f"Account '{name}' is already disabled - left as it is (will not be re-enabled automatically)"
            self._net_user_active(name, False)
            self.state["restrictions"][name.lower()] = {
                "user": name, "until": until, "since": self._clock(), "reason": str(reason or "")[:200]}
            self._save()
        try:
            n = len(self.logoff_user(name, strict=False))
        except Exception as exc:
            n = 0
            log.debug("logoff after restrict failed: %s", exc)
        log.warning("ACCESS RESTRICTED: '%s' disabled for %d min (until %s), %d session(s) logged off",
                    name, mins, self._until_text(until), n)
        return (f"Account '{name}' disabled for {mins} min - re-enabled automatically at "
                f"{self._until_text(until)}; {n} open session(s) logged off")

    def lift_restriction(self, user: str, auto: bool = False) -> str:
        name = self._check_user(user)
        with self._mutex:
            rec = self.state["restrictions"].pop(name.lower(), None)
            self._save()
        self._net_user_active(name, True)
        log.warning("ACCESS RESTORED: '%s' re-enabled%s", name, " (time is up)" if auto else "")
        if rec is None:
            return f"Account '{name}' enabled (it was not on the restriction list)"
        return f"Account '{name}' re-enabled" + (" (restriction time is up)" if auto else "")

    def logoff_user(self, user: str, strict: bool = True) -> list[int]:
        name = str(user or "").split("\\")[-1].strip()
        if not name:
            raise RuntimeError("logoff needs a user name")
        if name.lower() in _me():
            raise RuntimeError(f"Refusing to log off '{name}': it is the account this agent runs as "
                               f"(the agent would stop)")
        if not _is_windows() and self._sessions is wts_sessions:
            raise RuntimeError("Log off only works on Windows")
        done = []
        for sid, uname in self._sessions():
            if uname.lower() == name.lower():
                if self._logoff(sid):
                    done.append(sid)
        if strict and not done:
            raise RuntimeError(f"'{name}' has no open session on this PC (nothing to log off)")
        return done

    def lock_screen(self) -> str:
        if self._lock_fn is not None:
            ok = self._lock_fn()
        elif _is_windows():
            import ctypes
            ok = bool(ctypes.windll.user32.LockWorkStation())
        else:
            raise RuntimeError("Screen lock only works on Windows")
        if not ok:
            raise RuntimeError("Windows refused to lock the screen (agent not running in the user's session?)")
        return "Screen locked - the user must enter the password again"

    # ------------------------------------------------------------- throttle
    def _check_segment(self, target: str):
        try:
            net = ipaddress.ip_network(str(target or "").strip(), strict=False)
        except ValueError:
            raise RuntimeError(f"Not an IP address or range: {target!r} (e.g. 203.0.113.7 or 192.168.1.0/24)")
        if net.prefixlen < 8:
            raise RuntimeError(f"Refusing to throttle {net}: that is (almost) the whole internet")
        for ip in self.protected_ips:
            try:
                if ipaddress.ip_address(ip) in net:
                    raise RuntimeError(f"Refusing to throttle {net}: it contains the dashboard backend "
                                       f"({ip}) - the agent would lose its connection")
            except ValueError:
                continue
        return net

    @staticmethod
    def _policy_name(net) -> str:
        return "AiBoO-Throttle-" + _NAME_SAFE.sub("-", str(net))

    def throttle(self, target: str, kbps: Any = DEFAULT_THROTTLE_KBPS,
                 minutes: Any = DEFAULT_RESTRICT_MINUTES) -> str:
        net = self._check_segment(target)
        try:
            rate = max(MIN_THROTTLE_KBPS, int(float(kbps)))
        except (TypeError, ValueError):
            rate = DEFAULT_THROTTLE_KBPS
        mins = _minutes(minutes, DEFAULT_RESTRICT_MINUTES)
        name = self._policy_name(net)
        script = (f"Remove-NetQosPolicy -Name '{name}' -PolicyStore ActiveStore -Confirm:$false "
                  f"-ErrorAction SilentlyContinue; "
                  f"New-NetQosPolicy -Name '{name}' -IPDstPrefixMatchCondition '{net}' "
                  f"-ThrottleRateActionBitsPerSecond {rate * 1000} -PolicyStore ActiveStore "
                  f"-ErrorAction Stop | Out-Null; 'OK'")
        res = self._ps(script)
        if res.returncode != 0 or "OK" not in (res.stdout or ""):
            raise RuntimeError(f"New-NetQosPolicy failed: {(res.stderr or res.stdout).strip()[:250]}")
        until = self._clock() + mins * 60
        with self._mutex:
            self.state["throttles"][str(net)] = {"segment": str(net), "policy": name, "kbps": rate,
                                                 "until": until, "since": self._clock()}
            self._save()
        log.warning("THROTTLE: traffic from this PC to %s limited to %d kbit/s for %d min", net, rate, mins)
        return (f"Upload from this PC to {net} limited to {rate} kbit/s for {mins} min "
                f"(removed automatically at {self._until_text(until)}; also gone after a reboot)")

    def remove_throttle(self, target: str, auto: bool = False) -> str:
        try:
            net = ipaddress.ip_network(str(target or "").strip(), strict=False)
        except ValueError:
            raise RuntimeError(f"Not an IP address or range: {target!r}")
        name = self._policy_name(net)
        res = self._ps(f"Remove-NetQosPolicy -Name '{name}' -PolicyStore ActiveStore -Confirm:$false "
                       f"-ErrorAction Stop; 'OK'")
        with self._mutex:
            had = self.state["throttles"].pop(str(net), None)
            self._save()
        if res.returncode != 0 and had is None:
            raise RuntimeError(f"No AiBoO throttle for {net}")
        log.warning("THROTTLE REMOVED for %s%s", net, " (time is up)" if auto else "")
        return f"Throttle for {net} removed" + (" (time is up)" if auto else "")

    # --------------------------------------------------------------- expiry
    def expire_due(self) -> list[str]:
        now = self._clock()
        done = []
        for key, rec in list(self.state["restrictions"].items()):
            if float(rec.get("until", 0)) <= now:
                try:
                    done.append(self.lift_restriction(rec.get("user") or key, auto=True))
                except Exception as exc:
                    log.error("Could not re-enable '%s' after restriction: %s", key, exc)
        for key, rec in list(self.state["throttles"].items()):
            if float(rec.get("until", 0)) <= now:
                try:
                    done.append(self.remove_throttle(key, auto=True))
                except Exception as exc:
                    with self._mutex:
                        self.state["throttles"].pop(key, None)
                        self._save()
                    log.debug("throttle %s already gone: %s", key, exc)
        return done

    def start(self) -> None:
        if self._thread is not None:
            return

        def loop():
            while not self._stop.is_set():
                try:
                    self.expire_due()
                except Exception as exc:
                    log.debug("expiry check failed: %s", exc)
                self._stop.wait(20)

        self._thread = threading.Thread(target=loop, name="AccessControlExpiry", daemon=True)
        self._thread.start()
        if self.state["restrictions"] or self.state["throttles"]:
            log.warning("Access control: %d restriction(s), %d throttle(s) active from before the restart",
                        len(self.state["restrictions"]), len(self.state["throttles"]))

    def stop(self) -> None:
        self._stop.set()

    def snapshot(self) -> dict:
        now = self._clock()
        with self._mutex:
            return {
                "restrictions": [
                    {"user": r.get("user"), "until": datetime.fromtimestamp(float(r["until"])).isoformat(),
                     "minutes_left": max(0, int((float(r["until"]) - now) // 60)), "reason": r.get("reason", "")}
                    for r in self.state["restrictions"].values()],
                "throttles": [
                    {"segment": t.get("segment"), "kbps": t.get("kbps"),
                     "until": datetime.fromtimestamp(float(t["until"])).isoformat(),
                     "minutes_left": max(0, int((float(t["until"]) - now) // 60))}
                    for t in self.state["throttles"].values()],
            }


_ac: Optional[WindowsAccessControl] = None


def get_access_control() -> WindowsAccessControl:
    global _ac
    if _ac is None:
        _ac = WindowsAccessControl()
    return _ac


def configure_access_control(state_path: Optional[str], protected_ips: Optional[list] = None,
                             start: bool = True) -> WindowsAccessControl:
    global _ac
    if _ac is not None:
        _ac.stop()
    _ac = WindowsAccessControl(state_path, protected_ips=protected_ips)
    if start:
        _ac.start()
    return _ac
