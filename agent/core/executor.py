"""
core/executor.py — Aiboo's local action handler.
"""
import psutil
import subprocess
import platform
import os
import logging

log = logging.getLogger("Executor")

def kill_process(pid: int) -> bool:
    """Kill a process using psutil first, fallback to taskkill."""
    try:
        proc = psutil.Process(pid)
        proc_name = proc.name()
        log.info(f"Attempting to kill {proc_name} (PID: {pid})")
        proc.kill()  # Terminate the process
        # Wait a moment to confirm
        gone, alive = psutil.wait_procs([proc], timeout=3)
        if not alive:
            log.info(f"Successfully killed {proc_name} (PID: {pid})")
            return True
        else:
            # Force kill
            proc.kill()
            log.info(f"Force killed {proc_name} (PID: {pid})")
            return True
    except psutil.NoSuchProcess:
        log.info(f"PID {pid} already dead.")
        return True
    except psutil.AccessDenied:
        log.warning(f"Access denied, falling back to taskkill for PID {pid}")
        try:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], check=True, capture_output=True)
            return True
        except Exception as e:
            log.error(f"Fallback kill failed: {e}")
            return False
    except Exception as e:
        log.error(f"Failed to kill {pid}: {e}")
        return False

def isolate_machine(allow_ip: str = "192.168.1.100") -> None:
    """Block all network traffic except to allow_ip."""
    log.info(f"Isolating machine. Allowing only {allow_ip}")
    system = platform.system()
    if system == "Windows":
        subprocess.run("netsh advfirewall firewall delete rule name='Aiboo_Block_All'", shell=True)
        subprocess.run("netsh advfirewall firewall delete rule name='Aiboo_Allow_Server'", shell=True)
        subprocess.run(f"netsh advfirewall firewall add rule name='Aiboo_Allow_Server' dir=out remoteip={allow_ip} action=allow", shell=True)
        subprocess.run("netsh advfirewall firewall add rule name='Aiboo_Block_All' dir=out action=block", shell=True)
        subprocess.run("netsh advfirewall firewall add rule name='Aiboo_Block_Inbound' dir=in action=block", shell=True)
    elif system == "Linux":
        subprocess.run("iptables -F AIBOO_CHAIN 2>/dev/null", shell=True)
        subprocess.run("iptables -X AIBOO_CHAIN 2>/dev/null", shell=True)
        subprocess.run("iptables -N AIBOO_CHAIN", shell=True)
        subprocess.run(f"iptables -A AIBOO_CHAIN -d {allow_ip} -j ACCEPT", shell=True)
        subprocess.run("iptables -A AIBOO_CHAIN -j DROP", shell=True)
        subprocess.run("iptables -I OUTPUT -j AIBOO_CHAIN", shell=True)
    log.info("Isolation applied.")

def revoke_isolation() -> None:
    """Remove all firewall blocks and restore network access."""
    log.info("Revoking isolation. Restoring network access.")
    system = platform.system()
    if system == "Windows":
        subprocess.run("netsh advfirewall firewall delete rule name='Aiboo_Block_All'", shell=True)
        subprocess.run("netsh advfirewall firewall delete rule name='Aiboo_Allow_Server'", shell=True)
        subprocess.run("netsh advfirewall firewall delete rule name='Aiboo_Block_Inbound'", shell=True)
    elif system == "Linux":
        subprocess.run("iptables -D OUTPUT -j AIBOO_CHAIN 2>/dev/null", shell=True)
        subprocess.run("iptables -F AIBOO_CHAIN 2>/dev/null", shell=True)
        subprocess.run("iptables -X AIBOO_CHAIN 2>/dev/null", shell=True)
    log.info("Network fully restored.")