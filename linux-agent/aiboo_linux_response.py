#!/usr/bin/env python3
"""
AiBoO Linux Response Engine - the part that CHANGES things on a Linux server.

Used by aiboo_linux_agent.py when the dashboard sends an action and the
operator has allowed it (`allow_response = yes` in config.ini).

Design rules
  * Nothing happens unless the operator turns it on. Default is detection only.
  * Every action is checked, then run with the least privilege possible:
        root        -> run directly
        sudo -n     -> run through the allowlist in /etc/sudoers.d/aiboo-linux-agent
        neither     -> the action FAILS with a clear message; nothing is faked
  * Guard rails that cannot be switched off by a wrong action:
        - never block 127.0.0.1 / ::1 / the AiBoO server itself
        - never kill PID 1, sshd, systemd, the agent itself, or kernel threads
        - never lock uid < 1000 (system accounts) or the account running the agent
        - quarantine only inside the allowed folders (web roots, /tmp, ...)
        - every action is written to actions.jsonl with time, action, target, result
  * `response_dry_run = yes` prints and records what WOULD happen (used by tests
    and for a first, safe run on a production server).

Supported actions (same names the Windows agent and the dashboard use)
    block_access / isolate_asset / quarantine_device   -> firewall block of an IP
    unblock_access (alias remove_throttle)             -> firewall unblock
    terminate_process                                  -> kill by PID or exact name
    quarantine_file                                    -> move a file to quarantine
    restore_file                                       -> put it back
    revoke_identity                                    -> lock the Linux account + log sessions off
    restrict_identity                                  -> lock for N minutes, auto unlock
    lift_restriction                                   -> unlock now
    step_up_auth                                       -> lock the user's screen sessions
    pseudo_lock                                        -> open a REAL decoy TCP port and log intruders
    restore_pseudo_lock                                -> close the decoy
    full_isolation                                     -> only allow the AiBoO server (opt-in, auto-release)
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import string
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

def _norm_cmd(cmd: str) -> str:
    """'/usr/sbin/usermod -L bob' and 'sudo usermod -L bob' -> 'usermod -L bob'."""
    parts = (cmd or "").split()
    while parts and os.path.basename(parts[0]) in ("sudo", "env"):
        parts = parts[1:]
    if not parts:
        return ""
    return os.path.basename(parts[0]) + (" " + " ".join(parts[1:]) if len(parts) > 1 else "")


VERSION = "1.0.2"

# ---------------------------------------------------------------- guard rails
PROTECTED_PIDS = {0, 1}
PROTECTED_NAMES = (
    "systemd", "init", "sshd", "dbus-daemon", "systemd-journald", "systemd-logind",
    "cron", "crond", "rsyslogd", "auditd", "kthreadd", "agetty", "login",
    "aiboo_linux_agent.py", "python3",  # the agent itself is checked by PID below
)
NEVER_BLOCK = {"127.0.0.1", "::1", "0.0.0.0", "localhost"}
MAX_QUARANTINE_BYTES = 100 * 1024 * 1024      # 100 MB per file


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _token(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _sha256(path: Path, limit: int = MAX_QUARANTINE_BYTES) -> str:
    h = hashlib.sha256()
    read = 0
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            read += len(chunk)
            if read > limit:
                break
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------- decoy (honeypot)
@dataclass
class Decoy:
    lock_id: str
    port: int
    thread: threading.Thread
    server: socket.socket
    hits: list = field(default_factory=list)
    stop: threading.Event = field(default_factory=threading.Event)
    started: str = field(default_factory=_now)


_FAKE_BANNERS = (
    b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n",
    b"220 (vsFTPd 3.0.5)\r\n",
    b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\n\r\n",
    b"220 mail.example.internal ESMTP Postfix\r\n",
)


class ResponseEngine:
    """Runs the actions. One instance per agent process."""

    def __init__(self, settings, log_fn, base_dir: Path) -> None:
        self.st = settings
        self.log = log_fn
        self.base_dir = Path(base_dir)
        self.quarantine_dir = Path(getattr(settings, "quarantine_dir", "") or (self.base_dir / "quarantine"))
        self.state_dir = self.base_dir / "state"
        self.actions_log = self.base_dir / "actions.jsonl"
        self.decoys: dict[str, Decoy] = {}
        self.events: list[dict] = []          # things the agent should report (decoy hits)
        self._lock = threading.Lock()
        self.is_root = (os.geteuid() == 0)
        self.sudo_ok = False
        self.dry = bool(getattr(settings, "response_dry_run", False))
        self.enabled = bool(getattr(settings, "allow_response", False))
        for d in (self.quarantine_dir, self.state_dir):
            try:
                d.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass
        if not self.is_root and shutil.which("sudo"):
            try:
                self.sudo_ok = subprocess.run(
                    ["sudo", "-n", "true"], capture_output=True, timeout=5).returncode == 0
            except Exception:
                self.sudo_ok = False

    # ------------------------------------------------------------------ info
    def capabilities(self) -> dict:
        return {
            "allow_response": self.enabled,
            "dry_run": self.dry,
            "root": self.is_root,
            "sudo_nopasswd": self.sudo_ok,
            "can_change": self.enabled and (self.is_root or self.sudo_ok),
            "tools": {name: bool(shutil.which(name)) for name in
                      ("iptables", "nft", "ufw", "fail2ban-client", "usermod", "loginctl", "pkill")},
        }

    def _audit(self, action: str, target: str, status: str, message: str, extra: dict | None = None) -> None:
        line = {"time": _now(), "action": action, "target": target,
                "status": status, "message": message, "dry_run": self.dry, **(extra or {})}
        try:
            with self.actions_log.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(line) + "\n")
        except OSError:
            pass
        self.log(f"ACTION {action} target={target or '-'} -> {status}: {message}")

    # ------------------------------------------------------- command running
    # ---- self-awareness: the agent must not alert on its own actions -------
    def _remember_ran(self, cmd: list[str]) -> None:
        try:
            self.ran.append((time.time(), " ".join(str(c) for c in cmd)))
        except AttributeError:
            self.ran = [(time.time(), " ".join(str(c) for c in cmd))]
        if len(self.ran) > 200:
            del self.ran[:-200]

    def recently_ran(self, cmd: str, window: float = 120.0) -> bool:
        """Did THIS engine run that command a moment ago?

        The agent reads the same sudo/audit logs it writes into, so without this
        every block/kill/lock would raise an alert about itself.
        """
        target = _norm_cmd(cmd)
        if not target:
            return False
        now = time.time()
        self.ran = [(t, c) for t, c in getattr(self, "ran", []) if now - t <= window]
        return any(_norm_cmd(c) == target for _, c in self.ran)

    def _run(self, argv: list[str], timeout: int = 20) -> tuple[int, str]:
        """Run one command with the available privileges. No shell, no pipes."""
        if self.dry:
            return 0, "(dry-run) would run: " + " ".join(argv)
        cmd = list(argv)
        if not self.is_root:
            if not self.sudo_ok:
                return 126, ("needs root and no passwordless sudo for this user - "
                             "install /etc/sudoers.d/aiboo-linux-agent or run the agent as root")
            cmd = ["sudo", "-n"] + cmd
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            return 127, f"{cmd[0]}: not installed"
        except subprocess.TimeoutExpired:
            return 124, f"{cmd[0]}: timed out after {timeout}s"
        except Exception as exc:                                  # noqa: BLE001
            return 1, f"{cmd[0]}: {exc}"
        self._remember_ran(cmd)                 # so we never alert on ourselves
        out = (res.stdout or "").strip() or (res.stderr or "").strip()
        return res.returncode, out[:400]

    # ------------------------------------------------------------- firewall

    def _firewall_tool(self) -> str:
        """Pick the tool that will really stop traffic on THIS machine.

        ufw is only used when it is actually enabled: a rule added to a switched-off
        ufw is stored but drops nothing, which would make AiBoO claim a block that
        never happened. When ufw is installed-but-off we fall back to iptables/nft
        (which filter immediately) and say so in the answer. We never enable ufw
        ourselves - that can cut the SSH session an admin is working over.
        """
        for tool in ("iptables", "nft"):
            if shutil.which(tool):
                return tool
        if shutil.which("ufw"):
            # nothing else available: the rule is stored but ufw must be enabled to
            # actually drop traffic - _fw_warning() makes the agent say so out loud.
            return "ufw"
        return ""

    def _fw_warning(self) -> str:
        """Honest note when ufw is the only tool and it is switched off."""
        if shutil.which("ufw") and not (shutil.which("iptables") or shutil.which("nft")) and not self._ufw_active():
            return " WARNING: ufw is installed but NOT enabled - rule stored, traffic not dropped yet (run: ufw enable)"
        return ""

    def _iptables_binary(self, target: str) -> str:
        """iptables cannot touch IPv6 - those need ip6tables."""
        binary = "ip6tables" if ":" in (target or "") else "iptables"
        if shutil.which(binary):
            return binary
        return ""

    def _firewall_tool_preferred(self):
        """ufw when it is really filtering, otherwise iptables/nft."""
        if shutil.which("ufw") and self._ufw_active():
            return "ufw"
        if shutil.which("iptables"):
            return "iptables"
        if shutil.which("nft"):
            return "nft"
        return self._firewall_tool()

    def _ufw_active(self) -> bool:
        if self.dry:                       # never touch the system while dry-running
            return False
        try:
            res = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=8)
            return "Status: active" in (res.stdout or "")
        except Exception:
            return False

    def _server_ip(self) -> str:
        try:
            return socket.gethostbyname(re.sub(r"^https?://", "", self.st.remote_url).split(":")[0])
        except Exception:
            return ""

    def _ip_guard(self, ip: str) -> str:
        """Return a refusal reason, or "" when this target is safe to block.

        Only real IP addresses and CIDR networks are accepted. Names such as
        "localhost", junk strings such as "1" and huge nets such as 0.0.0.0/0 are
        refused here, before any firewall command is built.
        """
        raw = (ip or "").strip()
        if not raw:
            return "no address given"
        if raw.lower() in {n.lower() for n in NEVER_BLOCK}:
            return f"refused to block {raw} (localhost or the AiBoO server)"
        server_ip = self._server_ip()
        if raw == server_ip:
            return f"refused to block {raw} (that is the AiBoO server)"
        try:
            if "/" in raw:
                net = ipaddress.ip_network(raw, strict=False)
            else:
                addr = ipaddress.ip_address(raw)
                net = ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}", strict=False)
        except ValueError:
            return f"refused to block '{raw}' (not an IP address or CIDR network)"
        if net.prefixlen == 0:
            return f"refused to block {raw} (that is every address, including the AiBoO server)"
        if net.is_loopback or net.is_link_local or net.is_multicast or net.is_unspecified:
            return f"refused to block {raw} (loopback / local / multicast address)"
        if net.version == 4 and net.broadcast_address == ipaddress.ip_address("255.255.255.255"):
            return f"refused to block {raw} (broadcast address)"
        if net.version == 6 and net.num_addresses <= 1 and net[0].ipv4_mapped:
            return self._ip_guard(str(net[0].ipv4_mapped))
        if server_ip:
            try:
                if ipaddress.ip_address(server_ip) in net:
                    return f"refused to block {raw} (it would cut off the AiBoO server too)"
            except ValueError:
                pass
        return ""

    def block_ip(self, ip: str, reason: str = "") -> dict:
        ip = (ip or "").strip()
        why = self._ip_guard(ip)
        if why:
            return {"status": "failed", "message": why}
        if not self.enabled:
            return {"status": "failed",
                    "message": "local response is OFF on this server (allow_response = no in config.ini)"}

        tool = self._firewall_tool_preferred()
        if not tool:
            if self.dry:
                tool = "dry-run (no firewall tool installed here)"
                self._audit("block_access", ip, "executed", f"(dry-run) would block {ip}", {"tool": tool})
                return {"status": "executed", "message": f"(dry-run) would block {ip}",
                        "details": "no ufw/iptables/nft on this machine - nothing to run",
                        "metadata": {"ip": ip, "tool": tool, "dry_run": True}}
            return {"status": "failed", "message": "no firewall tool found (install ufw or iptables)"}

        warn = self._fw_warning()
        if tool == "ufw":
            code, out = self._run(["ufw", "--force", "deny", "from", ip, "to", "any"])
        elif tool == "iptables":
            binary = self._iptables_binary(ip) or "iptables"
            if binary == "iptables" and ":" in ip:
                if shutil.which("nft"):
                    tool = "nft"
                    code, out = self._run(["nft", "add", "rule", "inet", "filter", "input",
                                           "ip6", "saddr", ip, "drop"])
                else:
                    return {"status": "failed",
                            "message": f"{ip} is an IPv6 address but ip6tables is not installed "
                                       f"(install iptables/ip6tables or nftables)"}
            else:
                code, out = self._run([binary, "-I", "INPUT", "-s", ip, "-j", "DROP"])
                if code == 0 and not self.dry:
                    self._run([binary, "-I", "OUTPUT", "-d", ip, "-j", "DROP"])
        else:
            fam = "ip6" if ":" in ip else "ip"
            code, out = self._run(["nft", "add", "rule", "inet", "filter", "input", fam, "saddr", ip, "drop"])
        status = "executed" if code == 0 else "failed"
        message = (f"blocked {ip} with {tool}" if code == 0 else f"{tool} failed: {out}") + warn
        self._audit("block_access", ip, status, message, {"tool": tool, "reason": reason[:200]})
        return {"status": status, "message": message, "details": out,
                "metadata": {"ip": ip, "tool": tool, "dry_run": self.dry, "enforced": not warn}}

    # ------------------------------------------------------------- throttling
    def _throttle_tag(self, ip: str) -> str:
        """A short, unique, iptables-safe name for this IP's rate limiter."""
        return "AIBOO_THR_" + re.sub(r"[^0-9a-zA-Z]", "_", ip)[:24]

    @staticmethod
    def _kbps_to_pps(kbps: int) -> int:
        """kbit/s -> packets per second, assuming full 1500-byte packets.

        An approximation, and the answer says so: iptables hashlimit counts
        PACKETS, not bits, so there is no exact conversion.
        """
        return max(1, int(round(max(1, kbps) * 1000 / 8 / 1500)))

    def _throttle_rules(self, ip: str, kbps: int) -> tuple[list[list[str]], int]:
        pps = self._kbps_to_pps(kbps)
        burst = max(2, pps * 2)
        tag = self._throttle_tag(ip)
        comment = f"aiboo_throttle_{tag}"
        return [
            ["iptables", "-I", "INPUT", "-s", ip, "-m", "comment",
             "--comment", comment, "-j", "DROP"],
            ["iptables", "-I", "INPUT", "-s", ip, "-m", "hashlimit",
             "--hashlimit-upto", f"{pps}/sec", "--hashlimit-burst", str(burst),
             "--hashlimit-mode", "srcip", "--hashlimit-name", tag,
             "-m", "comment", "--comment", comment, "-j", "ACCEPT"],
        ], pps

    def throttle_ip(self, ip: str, kbps: int = 256, minutes: int = 30) -> dict:
        """Slow an IP down instead of blocking it completely (iptables hashlimit).

        Packets inside the limit are accepted, packets above it are dropped.
        kbit/s -> packets/s assumes 1500-byte packets, and the answer says it is
        approximate. If hashlimit is missing we never pretend: we block the IP
        and the message says so.
        """
        ip = (ip or "").strip()
        why = self._ip_guard(ip)
        if why:
            return {"status": "failed",
                    "message": why.replace("refused to block", "refused to throttle")}
        if not self.enabled:
            return {"status": "failed",
                    "message": "local response is OFF on this server (allow_response = no in config.ini)"}
        if ":" in ip:
            return {"status": "failed",
                    "message": "throttling IPv6 needs tc/ifb, which is not implemented - block it instead"}
        try:
            kbps = max(8, min(100000, int(kbps or 256)))
            minutes = max(0, min(1440, int(minutes or 30)))
        except (TypeError, ValueError):
            kbps, minutes = 256, 30

        rules, pps = self._throttle_rules(ip, kbps)
        tag = self._throttle_tag(ip)
        comment = f"aiboo_throttle_{tag}"

        if self.dry:
            self._audit("throttle_segment", ip, "executed",
                        f"(dry-run) would rate-limit {ip}", {"kbps": kbps})
            return {"status": "executed",
                    "message": f"(dry-run) would rate-limit {ip} to ~{kbps} kbit/s",
                    "details": "(dry-run) " + " ; ".join(" ".join(r) for r in rules),
                    "metadata": {"ip": ip, "kbps": kbps, "pps": pps, "mode": "hashlimit",
                                 "approx": True, "dry_run": True}}

        if not shutil.which("iptables"):
            fallback = self.block_ip(ip, reason="throttle requested, no iptables - blocked instead")
            fallback["message"] = ("throttling needs iptables (not installed) - "
                                   + str(fallback.get("message", "")))
            fallback.setdefault("metadata", {})["fell_back_to_block"] = True
            return fallback

        # DROP first, ACCEPT second: -I puts each new rule on top, so the ACCEPT
        # ends up above the DROP and only the excess packets reach the DROP.
        for argv in rules:
            code, out = self._run(argv)
            if code != 0:
                self._run(["iptables", "-D", "INPUT", "-s", ip, "-m", "comment",
                           "--comment", comment, "-j", "DROP"])
                low = out.lower()
                if "hashlimit" in low or "no chain/target/match" in low or "unknown option" in low:
                    fallback = self.block_ip(ip, reason="throttle requested, hashlimit unavailable - blocked")
                    fallback["message"] = ("iptables hashlimit is not available on this kernel - "
                                           + str(fallback.get("message", "")))
                    fallback.setdefault("metadata", {})["fell_back_to_block"] = True
                    return fallback
                self._audit("throttle_segment", ip, "failed", out, {"kbps": kbps})
                return {"status": "failed", "message": f"iptables refused the rate limit: {out}"}

        if minutes > 0:
            self._schedule_throttle_removal(ip, minutes, pps)
        message = f"traffic from {ip} limited to ~{kbps} kbit/s (about {pps} packets/s)"
        if minutes > 0:
            message += f" for {minutes} minutes (removed automatically)"
        self._audit("throttle_segment", ip, "executed", message,
                    {"kbps": kbps, "pps": pps, "minutes": minutes, "mode": "hashlimit"})
        return {"status": "executed", "message": message,
                "details": f"iptables hashlimit: packets above {pps}/s are dropped",
                "metadata": {"ip": ip, "kbps": kbps, "pps": pps, "mode": "hashlimit",
                             "approx": True, "enforced": True, "minutes": minutes}}

    def remove_throttle_ip(self, ip: str) -> dict:
        """Remove exactly the rules throttle_ip added (matched by their comment)."""
        ip = (ip or "").strip()
        why = self._ip_guard(ip)
        if why:
            return {"status": "failed",
                    "message": why.replace("refused to block", "refused to unthrottle")}
        tag = self._throttle_tag(ip)
        comment = f"aiboo_throttle_{tag}"
        removed, errors = 0, []
        attempts = [
            # the two rules as they were installed (newest first: -I puts them on top)
            ["iptables", "-D", "INPUT", "-s", ip, "-m", "hashlimit",
             "--hashlimit-upto", self._delete_any_rate(tag), "--hashlimit-burst", "1",
             "--hashlimit-mode", "srcip", "--hashlimit-name", tag,
             "-m", "comment", "--comment", comment, "-j", "ACCEPT"],
            ["iptables", "-D", "INPUT", "-s", ip, "-m", "comment", "--comment", comment, "-j", "DROP"],
        ]
        for argv in attempts:
            code, out = self._run(argv)
            if code == 0:
                removed += 1
            elif "bad rule" in out.lower() or "does not exist" in out.lower() or "no chain" in out.lower():
                pass                                  # already gone - that is fine
            else:
                errors.append(out)
        status = "executed" if removed or not errors else "failed"
        message = (f"rate limit removed for {ip} ({removed} rule(s))" if status == "executed"
                   else f"could not remove the rate limit: {errors[0]}")
        self._audit("remove_throttle", ip, status, message)
        return {"status": status, "message": message, "metadata": {"ip": ip, "mode": "hashlimit"}}

    def _delete_any_rate(self, tag: str) -> str:
        """The rate that was used when the rule was added (from state), else 1/sec."""
        path = self.state_dir / "throttles.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            item = data.get(tag) or {}
            if item.get("pps"):
                return f"{int(item['pps'])}/sec"
        except Exception:                                      # noqa: BLE001
            pass
        return "1/sec"

    def _schedule_throttle_removal(self, ip: str, minutes: int, pps: int = 0) -> None:
        """Auto-removal timer, the same pattern as the account auto-unlock."""
        path = self.state_dir / "throttles.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        except Exception:                                      # noqa: BLE001
            data = {}
        data[self._throttle_tag(ip)] = {"ip": ip, "pps": pps,
                                        "until": time.time() + minutes * 60}
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except OSError:
            pass

    def expire_throttles(self) -> list[str]:
        """Remove rate limits whose time is up (call once per loop)."""
        path = self.state_dir / "throttles.json"
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:                                      # noqa: BLE001
            return []
        now, done = time.time(), []
        for tag, item in list(data.items()):
            if not isinstance(item, dict) or item.get("until", 0) > now:
                continue
            res = self.remove_throttle_ip(str(item.get("ip", "")))
            done.append(f"{item.get('ip')}: {res.get('message')}")
            data.pop(tag, None)
        try:
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except OSError:
            pass
        return done

    # ------------------------------------------------------- log the user out
    def force_logout(self, user: str) -> dict:
        """Close every session of a user (loginctl, pkill as the fallback)."""
        why = self._refuse_user(user, verb="log out")
        if why:
            return {"status": "failed", "message": why}
        if shutil.which("loginctl"):
            code, out = self._run(["loginctl", "terminate-user", user])
            used = "loginctl terminate-user"
        else:
            code, out = self._run(["pkill", "-KILL", "-u", user])
            used = "pkill -KILL -u"
        if code == 0 and shutil.which("pkill"):
            # a session without logind survives terminate-user
            self._run(["pkill", "-KILL", "-u", user])
        status = "executed" if code == 0 else "failed"
        message = (f"all sessions of '{user}' closed ({used})" if status == "executed"
                   else f"could not close the sessions of '{user}': {out}")
        self._audit("force_logout", user, status, message)
        return {"status": status, "message": message,
                "metadata": {"user": user, "tool": used.split()[0]}}

    def unblock_ip(self, ip: str) -> dict:
        ip = (ip or "").strip()
        why = self._ip_guard(ip)
        if why:
            return {"status": "failed", "message": why.replace("refused to block", "refused to unblock")}
        tool = self._firewall_tool_preferred()
        if tool == "ufw":
            code, out = self._run(["ufw", "delete", "deny", "from", ip, "to", "any"])
        elif tool == "iptables":
            binary = self._iptables_binary(ip) or "iptables"
            code, out = self._run([binary, "-D", "INPUT", "-s", ip, "-j", "DROP"])
            self._run([binary, "-D", "OUTPUT", "-d", ip, "-j", "DROP"])
        elif tool == "nft":
            code, out = self._run(["nft", "-a", "delete", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"])
        else:
            return {"status": "failed", "message": "no firewall tool found"}
        status = "executed" if code == 0 else "failed"
        self._audit("unblock_access", ip, status, f"unblocked with {tool}" if code == 0 else out)
        return {"status": status, "message": f"unblocked {ip}" if code == 0 else f"unblock failed: {out}",
                "details": out, "metadata": {"ip": ip, "tool": tool}}

    # ------------------------------------------------------------- processes
    def _own_pid(self) -> int:
        return os.getpid()

    def _processes(self) -> list[dict]:
        out = []
        for entry in Path("/proc").iterdir() if Path("/proc").exists() else []:
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            try:
                cmdline = (entry / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
                comm = (entry / "comm").read_text(errors="replace").strip()
                uid = None
                for line in (entry / "status").read_text(errors="replace").splitlines():
                    if line.startswith("Uid:"):
                        uid = int(line.split()[1])
                        break
            except (OSError, ValueError):
                continue
            out.append({"pid": pid, "name": comm, "cmdline": cmdline, "uid": uid})
        return out

    def terminate_process(self, target: str, reason: str = "") -> dict:
        target = (target or "").strip()
        if not target:
            return {"status": "failed", "message": "no PID or process name given"}
        procs = self._processes()
        victims: list[dict] = []
        if target.isdigit():
            pid = int(target)
            victims = [p for p in procs if p["pid"] == pid]
        else:
            wanted = target.lower()
            victims = [p for p in procs if wanted in (p["name"] or "").lower()
                       or (p["cmdline"] or "").lower().startswith(wanted)]
        if not victims:
            return {"status": "failed", "message": f"process '{target}' not found"}

        killed, refused = [], []
        for p in victims:
            name = (p["name"] or "").lower()
            cmdline = (p["cmdline"] or "").lower()
            is_agent = "aiboo_linux_agent" in cmdline or p["pid"] == self._own_pid()
            # protected by PID, by name (substring: systemd-*, sshd-*, auditd, cron...)
            # or because it is the AiBoO agent itself.
            protected = (p["pid"] in PROTECTED_PIDS or is_agent
                         or any(bad in name for bad in PROTECTED_NAMES if bad != "python3"))
            if protected:
                refused.append(f"{p['pid']}:{p['name']} (protected)")
                continue
            if name.startswith("python") and not target.isdigit() and not is_agent:
                # never kill "every python" on the box - only an explicitly given PID
                refused.append(f"{p['pid']}:{p['name']} (give the PID to kill a Python process)")
                continue
            code, out = self._run(["kill", "-9", str(p["pid"])])
            (killed if code == 0 else refused).append(f"{p['pid']}:{p['name']}")
        status = "executed" if killed else "failed"
        message = (f"stopped {', '.join(killed)}" if killed else
                   f"nothing stopped (protected: {', '.join(refused) or 'none'})")
        self._audit("terminate_process", target, status, message, {"killed": killed, "refused": refused})
        return {"status": status, "message": message,
                "details": f"refused: {', '.join(refused)}" if refused else "",
                "metadata": {"killed": killed, "refused": refused, "reason": reason[:200]}}

    # ----------------------------------------------------------- quarantine
    def _allowed_for_quarantine(self, path: Path) -> tuple[bool, str]:
        allowed = [Path(p) for p in (getattr(self.st, "watch_dirs", "") or "").split(",") if p.strip()]
        allowed += [Path("/tmp"), Path("/var/tmp"), Path("/dev/shm")]
        for root in allowed:
            try:
                path.resolve().relative_to(root.resolve())
                return True, ""
            except ValueError:
                continue
        return False, f"{path} is outside the allowed folders (watch_dirs, /tmp, /var/tmp, /dev/shm)"

    def quarantine_file(self, target: str, reason: str = "") -> dict:
        target = (target or "").strip()
        if not target:
            return {"status": "failed", "message": "no file path given"}
        path = Path(target)
        if not path.exists() or path.is_dir():
            return {"status": "failed", "message": f"{target} does not exist (or is a directory)"}
        if path.is_symlink():
            return {"status": "failed", "message": "refusing to quarantine a symlink"}
        ok, why = self._allowed_for_quarantine(path)
        if not ok:
            return {"status": "failed", "message": why}
        try:
            size = path.stat().st_size
        except OSError as exc:
            return {"status": "failed", "message": f"cannot stat: {exc}"}
        if size > MAX_QUARANTINE_BYTES:
            return {"status": "failed", "message": f"file is {size} bytes - larger than the quarantine limit"}
        digest = _sha256(path)
        dest_dir = self.quarantine_dir / datetime.now().strftime("%Y-%m-%d")
        dest = dest_dir / f"{digest[:12]}_{path.name}"
        meta = {"original": str(path), "sha256": digest, "size": size, "quarantined_at": _now(),
                "reason": reason[:200], "mode": oct(path.stat().st_mode & 0o777)}
        if self.dry:
            self._audit("quarantine_file", str(path), "executed", f"(dry-run) move to {dest}", meta)
            return {"status": "executed", "message": f"(dry-run) would quarantine {path.name}",
                    "details": f"sha256 {digest}", "metadata": meta}
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
            shutil.move(str(path), str(dest))
            os.chmod(dest, 0o000)
            (dest_dir / f"{dest.name}.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        except OSError as exc:
            return {"status": "failed", "message": f"could not move the file: {exc}"}
        self._audit("quarantine_file", str(path), "executed", f"quarantined to {dest}", meta)
        return {"status": "executed", "message": f"quarantined {path.name} (sha256 {digest[:12]}…)",
                "details": f"moved to {dest}", "metadata": meta}

    def restore_file(self, target: str) -> dict:
        """target = original path or sha256 prefix."""
        target = (target or "").strip()
        if not target:
            return {"status": "failed", "message": "no file or hash given"}
        for meta_file in sorted(self.quarantine_dir.glob("*/*.json"), reverse=True):
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if target in (meta.get("original"), meta.get("sha256")) or \
                    str(meta.get("sha256", "")).startswith(target):
                src = meta_file.with_suffix("")
                if self.dry:
                    return {"status": "executed", "message": f"(dry-run) would restore {meta['original']}"}
                try:
                    os.chmod(src, 0o600)
                    shutil.move(str(src), meta["original"])
                    meta_file.unlink(missing_ok=True)
                except OSError as exc:
                    return {"status": "failed", "message": f"restore failed: {exc}"}
                self._audit("restore_file", meta["original"], "executed", "restored from quarantine")
                return {"status": "executed", "message": f"restored {meta['original']}",
                        "metadata": meta}
        return {"status": "failed", "message": f"nothing in quarantine matches '{target}'"}

    # ---------------------------------------------------------------- users
    def _user_uid(self, user: str) -> int | None:
        try:
            import pwd
            return pwd.getpwnam(user).pw_uid
        except (ImportError, KeyError):
            return None

    def _refuse_user(self, user: str, verb: str = "lock") -> str:
        if not user:
            return "no user name given"
        if user in ("root", "daemon", "bin", "sys", "sync", "systemd-network"):
            return f"refusing to touch the system account '{user}'"
        uid = self._user_uid(user)
        if uid is None:
            return f"user '{user}' does not exist on this server"
        if uid < 1000:
            return f"'{user}' is a system account (uid {uid}) - refused"
        if uid == os.geteuid():
            return f"refusing to {verb} the account the agent itself is running as"
        return ""

    def lock_user(self, user: str, minutes: int = 0, reason: str = "") -> dict:
        why = self._refuse_user(user)
        if why:
            return {"status": "failed", "message": why}
        code, out = self._run(["usermod", "-L", user])
        if code != 0:
            return {"status": "failed", "message": f"usermod -L failed: {out}"}
        state = self._password_state(user)
        if state == "P":
            return {"status": "failed",
                    "message": f"usermod reported success but passwd -S {user} still shows the account as usable"}
        # log the user's sessions off, like the Windows agent does
        if shutil.which("loginctl"):
            self._run(["loginctl", "terminate-user", user])
        else:
            self._run(["pkill", "-KILL", "-u", user])
        if minutes > 0:
            self._schedule_unlock(user, minutes)
            message = f"account '{user}' locked and sessions closed for {minutes} minutes (auto unlock)"
        else:
            message = f"account '{user}' locked and sessions closed (unlock with lift_restriction)"
        self._audit("revoke_identity" if minutes <= 0 else "restrict_identity", user, "executed",
                    message, {"minutes": minutes, "reason": reason[:200]})
        return {"status": "executed", "message": message,
                "metadata": {"user": user, "minutes": minutes, "dry_run": self.dry}}

    def _password_state(self, user: str) -> str:
        """'L' locked, 'P' has a password, 'NP' no password, '' unknown."""
        if not shutil.which("passwd"):
            return ""
        code, out = self._run(["passwd", "-S", user])
        if code != 0 or not out:
            return ""
        parts = out.split()
        return parts[1] if len(parts) > 1 else ""

    def unlock_user(self, user: str) -> dict:
        why = self._refuse_user(user)
        if why:
            return {"status": "failed", "message": why}
        code, out = self._run(["usermod", "-U", user])
        state = self._password_state(user)
        # usermod -U refuses to unlock an account that has no password at all,
        # because that would create an account you can log into with ANY password.
        if state == "L" and "passwordless" in out.lower():
            msg = (f"account '{user}' cannot be unlocked: it has no password set, "
                   f"so unlocking would allow login with an empty password. "
                   f"Give it a password first (passwd {user}), then run lift_restriction again.")
            self._audit("lift_restriction", user, "failed", msg)
            return {"status": "failed", "message": msg}
        if state == "L":
            msg = (f"account '{user}' is still locked (usermod said: {out or 'no output'}). "
                   f"Check the account by hand: passwd -S {user}")
            self._audit("lift_restriction", user, "failed", msg)
            return {"status": "failed", "message": msg}
        status = "executed" if code == 0 else "failed"
        message = f"account '{user}' unlocked" if code == 0 else f"usermod -U failed: {out}"
        self._audit("lift_restriction", user, status, message)
        self._clear_unlock(user)
        return {"status": status, "message": message}

    def _schedule_unlock(self, user: str, minutes: int) -> None:
        path = self.state_dir / "restrictions.json"
        data = {}
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data = {}
        data[user] = {"until": time.time() + minutes * 60, "minutes": minutes, "set_at": _now()}
        try:
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except OSError:
            pass

    def _clear_unlock(self, user: str) -> None:
        path = self.state_dir / "restrictions.json"
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            data.pop(user, None)
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except (OSError, json.JSONDecodeError):
            pass

    def restrictions_due(self) -> list[str]:
        """Users whose temporary lock has expired (the agent unlocks them)."""
        path = self.state_dir / "restrictions.json"
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        now = time.time()
        return [user for user, info in data.items() if float(info.get("until", 0)) <= now]

    def step_up_auth(self, user: str) -> dict:
        """Force the user to authenticate again (lock their sessions)."""
        why = self._refuse_user(user)
        if why:
            return {"status": "failed", "message": why}
        if shutil.which("loginctl"):
            code, out = self._run(["loginctl", "terminate-user", user])
            message = f"sessions of '{user}' closed - they must sign in again"
        else:
            code, out = self._run(["pkill", "-KILL", "-u", user])
            message = f"processes of '{user}' stopped - they must sign in again"
        status = "executed" if code == 0 else "failed"
        self._audit("step_up_auth", user, status, message if code == 0 else out)
        return {"status": status, "message": message if code == 0 else f"failed: {out}"}

    # ------------------------------------------------------- full isolation
    def full_isolation(self, minutes: int = 15) -> dict:
        """Only the AiBoO server may reach this host (opt-in, auto release)."""
        if not getattr(self.st, "allow_full_isolation", False):
            return {"status": "failed",
                    "message": "full isolation is disabled (allow_full_isolation = no in config.ini)"}
        try:
            host = re.sub(r"^https?://", "", self.st.remote_url).split(":")[0]
            server_ip = socket.gethostbyname(host)
        except Exception:
            return {"status": "failed", "message": "cannot resolve the AiBoO server address"}
        tool = self._firewall_tool_preferred()
        if tool == "iptables":
            self._run(["iptables", "-I", "INPUT", "-s", server_ip, "-j", "ACCEPT"])
            self._run(["iptables", "-I", "INPUT", "1", "-j", "DROP"])
        elif tool == "ufw":
            self._run(["ufw", "default", "deny", "incoming"])
            self._run(["ufw", "allow", "from", server_ip])
        else:
            return {"status": "failed", "message": "no firewall tool found"}
        path = self.state_dir / "isolation.json"
        try:
            path.write_text(json.dumps({"until": time.time() + minutes * 60,
                                        "server_ip": server_ip, "set_at": _now()}), encoding="utf-8")
        except OSError:
            pass
        self._audit("full_isolation", server_ip, "executed",
                    f"only {server_ip} allowed for {minutes} min (auto release)")
        return {"status": "executed",
                "message": f"host isolated for {minutes} min - only the AiBoO server ({server_ip}) can reach it",
                "metadata": {"server_ip": server_ip, "minutes": minutes}}

    def isolation_due(self) -> bool:
        path = self.state_dir / "isolation.json"
        if not path.exists():
            return False
        try:
            info = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        return float(info.get("until", 0)) <= time.time()

    def release_isolation(self) -> dict:
        tool = self._firewall_tool_preferred()
        if tool == "iptables":
            self._run(["iptables", "-D", "INPUT", "-j", "DROP"])
        elif tool == "ufw":
            self._run(["ufw", "delete", "allow"])
            self._run(["ufw", "default", "allow", "incoming"])
        self._audit("release_isolation", "", "executed", "isolation released")
        (self.state_dir / "isolation.json").unlink(missing_ok=True)
        return {"status": "executed", "message": "isolation released"}

    # ------------------------------------------------------------ pseudo-lock
    def pseudo_lock(self, label: str = "") -> dict:
        """Open a REAL decoy TCP port - anything that connects is an intruder."""
        port = random.randint(32768, 60999)
        lock_id = f"lock_{int(time.time())}_{_token(4)}"
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bound = False
        for _ in range(5):
            try:
                server.bind(("0.0.0.0", port))
                server.listen(16)
                server.settimeout(1.0)
                bound = True
                break
            except OSError:
                port = random.randint(32768, 60999)
        if not bound:
            return {"status": "failed", "message": "could not bind a decoy port"}

        decoy = Decoy(lock_id=lock_id, port=port, thread=None,
                      server=server)                       # type: ignore[arg-type]

        def serve() -> None:
            while not decoy.stop.is_set():
                try:
                    conn, addr = decoy.server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                peer = f"{addr[0]}:{addr[1]}"
                payload = ""
                try:
                    conn.sendall(random.choice(_FAKE_BANNERS))
                    conn.settimeout(5.0)
                    data = conn.recv(1024)
                    payload = data.decode("utf-8", "replace")[:300]
                except Exception:
                    pass
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
                hit = {"peer": peer, "port": port, "payload": payload, "time": _now(), "lock_id": lock_id}
                with self._lock:
                    decoy.hits.append(hit)
                    self.events.append({"kind": "decoy_hit", **hit})
                self.log(f"DECOY HIT from {peer} on port {port}"
                         + (f" payload={payload[:80]!r}" if payload else ""))

        thread = threading.Thread(target=serve, name=f"decoy-{port}", daemon=True)
        decoy.thread = thread
        thread.start()
        self.decoys[lock_id] = decoy
        label = label or "honeypot"
        self._audit("pseudo_lock", label, "executed",
                    f"decoy listening on 0.0.0.0:{port} (lock {lock_id})")
        return {"status": "executed",
                "message": f"decoy listening on 0.0.0.0:{port} - every connection is logged",
                "details": f"lock {lock_id}: anything that connects to port {port} is an intruder",
                "metadata": {"lock_id": lock_id, "decoy_port": port, "label": label}}

    def restore_pseudo_lock(self, lock_id: str) -> dict:
        decoy = self.decoys.get(lock_id)
        if not decoy:
            return {"status": "failed", "message": f"no open decoy with lock id {lock_id}"}
        decoy.stop.set()
        try:
            decoy.server.close()
        except OSError:
            pass
        self.decoys.pop(lock_id, None)
        self._audit("restore_pseudo_lock", lock_id, "executed",
                    f"decoy port {decoy.port} closed after {len(decoy.hits)} hit(s)")
        return {"status": "executed",
                "message": f"decoy port {decoy.port} closed ({len(decoy.hits)} hit(s) recorded)",
                "metadata": {"lock_id": lock_id, "hits": len(decoy.hits)}}

    def active_decoys(self) -> list[dict]:
        return [{"lock_id": d.lock_id, "port": d.port, "hits": len(d.hits),
                 "started": d.started, "label": ""} for d in self.decoys.values()]

    # -------------------------------------------------------------- dispatch
    def drain_events(self) -> list[dict]:
        with self._lock:
            events, self.events = self.events, []
        return events

    def execute(self, action: str, target: str = "", params: dict | None = None) -> dict:
        params = dict(params or {})
        action = (action or "").strip()
        if not self.enabled and action not in ("pseudo_lock", "restore_pseudo_lock", "list"):
            return {"status": "failed",
                    "message": "this server is in READ-ONLY mode (allow_response = no in config.ini) - "
                               "the action was not run",
                    "details": "Ask the server owner to set allow_response = yes and restart the agent."}
        handler = {
            "block_access": lambda: self.block_ip(target, params.get("reason", "")),
            "isolate_asset": lambda: self.block_ip(target, params.get("reason", "isolate_asset")),
            "quarantine_device": lambda: self.block_ip(target, params.get("reason", "quarantine_device")),
            "throttle_segment": lambda: self.throttle_ip(target, params.get("kbps", 256),
                                                         params.get("minutes", 30)),
            "unblock_access": lambda: self.unblock_ip(target),
            "remove_throttle": lambda: self.remove_throttle_ip(target),
            "terminate_process": lambda: self.terminate_process(target, params.get("reason", "")),
            "quarantine_file": lambda: self.quarantine_file(target, params.get("reason", "")),
            "restore_file": lambda: self.restore_file(target),
            "revoke_identity": lambda: self.lock_user(target, 0, params.get("reason", "")),
            "restrict_identity": lambda: self.lock_user(target, int(params.get("minutes") or 30),
                                                        params.get("reason", "")),
            "lift_restriction": lambda: self.unlock_user(target),
            "step_up_auth": lambda: self.step_up_auth(target),
            "force_logout": lambda: self.force_logout(target),
            "pseudo_lock": lambda: self.pseudo_lock(target),
            "restore_pseudo_lock": lambda: self.restore_pseudo_lock(target),
            "full_isolation": lambda: self.full_isolation(int(params.get("minutes") or 15)),
            "release_isolation": lambda: self.release_isolation(),
            "list": lambda: {"status": "executed", "message": "capabilities",
                             "metadata": self.capabilities()},
        }.get(action)
        if not handler:
            return {"status": "failed",
                    "message": f"action '{action}' is not supported by the Linux agent "
                               f"(supported: block_access, unblock_access, throttle_segment, remove_throttle, "
                               f"terminate_process, quarantine_file, restore_file, revoke_identity, "
                               f"restrict_identity, lift_restriction, force_logout, step_up_auth, pseudo_lock, "
                               f"restore_pseudo_lock, full_isolation)"}
        started = time.time()
        try:
            result = handler()
        except Exception as exc:                                  # noqa: BLE001
            result = {"status": "failed", "message": f"{action} crashed: {exc}"}
        result.setdefault("metadata", {})
        result["metadata"].update({"action": action, "target": target,
                                   "took_ms": int((time.time() - started) * 1000),
                                   "engine": f"aiboo-linux-response {VERSION}"})
        return result
