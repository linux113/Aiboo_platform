"""
utils/device_fingerprint.py — Device Fingerprinting Utilities

Creates unique device fingerprints based on hardware, software,
and configuration attributes. Used by Zero Trust architecture
to verify device identity.
"""

from __future__ import annotations

import hashlib
import platform
import uuid
import re
import subprocess
import sys
import json
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone
from cachetools import TTLCache

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import winreg
    WINDOWS_REGISTRY_AVAILABLE = True
except ImportError:
    WINDOWS_REGISTRY_AVAILABLE = False


@dataclass
class DeviceFingerprint:
    """Complete device fingerprint for Zero Trust verification"""
    device_id: str
    fingerprint_hash: str
    hardware_id: str
    mac_addresses: list[str]
    cpu_id: str
    motherboard_serial: str
    disk_serial: str
    os_info: Dict[str, Any]
    installed_software_hash: str
    network_adapters: list[Dict[str, str]]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float = 0.0
    is_trusted: bool = False


class DeviceFingerprinter:
    """
    Generates and manages device fingerprints for Zero Trust authentication.
    Uses multiple hardware and software attributes to create a unique identity.
    """
    
    def __init__(self):
        self._cache: TTLCache[str, DeviceFingerprint] = TTLCache(maxsize=1000, ttl=300)
    
    def get_fingerprint(self, device_id: Optional[str] = None) -> DeviceFingerprint:
        """
        Generate a fingerprint for the current device.
        If device_id provided, generate consistent fingerprint.
        """
        if device_id and device_id in self._cache:
            return self._cache[device_id]
        
        fingerprint = self._generate_fingerprint(device_id)
        if device_id:
            self._cache[device_id] = fingerprint
        
        return fingerprint
    
    def _generate_fingerprint(self, device_id: Optional[str] = None) -> DeviceFingerprint:
        """Generate fingerprint from system attributes"""
        
        # Collect all device attributes
        hardware_id = self._get_hardware_id()
        mac_addresses = self._get_mac_addresses()
        cpu_id = self._get_cpu_id()
        motherboard_serial = self._get_motherboard_serial()
        disk_serial = self._get_disk_serial()
        os_info = self._get_os_info()
        installed_software_hash = self._get_installed_software_hash()
        network_adapters = self._get_network_adapters()
        
        # Create unique fingerprint hash from all attributes
        fingerprint_string = f"{hardware_id}{cpu_id}{motherboard_serial}{disk_serial}{os_info.get('system')}"
        fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()
        
        # If device_id provided, use it; otherwise create from fingerprint
        if not device_id:
            device_id = f"device_{fingerprint_hash[:12]}"
        
        return DeviceFingerprint(
            device_id=device_id,
            fingerprint_hash=fingerprint_hash,
            hardware_id=hardware_id,
            mac_addresses=mac_addresses,
            cpu_id=cpu_id,
            motherboard_serial=motherboard_serial,
            disk_serial=disk_serial,
            os_info=os_info,
            installed_software_hash=installed_software_hash,
            network_adapters=network_adapters,
            confidence=self._calculate_confidence(hardware_id, mac_addresses, cpu_id)
        )
    
    def _get_hardware_id(self) -> str:
        """Get unique hardware ID (Windows MachineGUID or Linux machine-id)"""
        try:
            if sys.platform == 'win32' and WINDOWS_REGISTRY_AVAILABLE:
                # Windows MachineGUID
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                    r"SOFTWARE\Microsoft\Cryptography")
                value, _ = winreg.QueryValueEx(key, "MachineGuid")
                winreg.CloseKey(key)
                return str(value)
            elif sys.platform == 'linux':
                # Linux /etc/machine-id
                with open('/etc/machine-id', 'r') as f:
                    return f.read().strip()
            elif sys.platform == 'darwin':
                # macOS Hardware UUID
                result = subprocess.run(
                    ['system_profiler', 'SPHardwareDataType'],
                    capture_output=True,
                    text=True
                )
                match = re.search(r'Hardware UUID: (.+)', result.stdout)
                if match:
                    return match.group(1).strip()
        except Exception:
            pass
        
        # Fallback: use UUID from Python
        return str(uuid.getnode())
    
    def _get_mac_addresses(self) -> list[str]:
        """Get all MAC addresses from network interfaces"""
        mac_addresses = []
        if not PSUTIL_AVAILABLE:
            # Fallback to UUID.getnode
            mac = hex(uuid.getnode()).replace('0x', '').zfill(12)
            mac = ':'.join(mac[i:i+2] for i in range(0, 12, 2))
            return [mac]
        
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == psutil.AF_LINK:
                    mac = addr.address
                    if mac and mac != '00:00:00:00:00:00':
                        mac_addresses.append(mac)
        
        return mac_addresses
    
    def _get_cpu_id(self) -> str:
        """Get CPU identifier (processor ID)"""
        try:
            if sys.platform == 'win32':
                # Windows: Get processor ID from registry
                if WINDOWS_REGISTRY_AVAILABLE:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                        r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
                    try:
                        value, _ = winreg.QueryValueEx(key, "ProcessorNameString")
                        winreg.CloseKey(key)
                        return str(value)
                    except:
                        winreg.CloseKey(key)
            elif sys.platform == 'linux':
                # Linux: Read from /proc/cpuinfo
                with open('/proc/cpuinfo', 'r') as f:
                    content = f.read()
                    match = re.search(r'processor\s+:\s+(\d+)', content)
                    match2 = re.search(r'model name\s+:\s+(.+)', content)
                    if match and match2:
                        return f"{match.group(1)}_{match2.group(1).strip()}"
        except Exception:
            pass
        
        # Fallback: platform processor info
        return platform.processor() or "unknown_cpu"
    
    def _get_motherboard_serial(self) -> str:
        """Get motherboard serial number"""
        try:
            if sys.platform == 'win32' and PSUTIL_AVAILABLE:
                # Windows: Use WMI (via psutil or subprocess)
                result = subprocess.run(
                    ['wmic', 'baseboard', 'get', 'serialnumber'],
                    capture_output=True,
                    text=True
                )
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    serial = lines[1].strip()
                    if serial and serial != 'SerialNumber':
                        return serial
        except Exception:
            pass
        
        return "unknown_motherboard"
    
    def _get_disk_serial(self) -> str:
        """Get primary disk serial number"""
        try:
            if sys.platform == 'win32':
                # Windows: Get disk serial
                result = subprocess.run(
                    ['wmic', 'diskdrive', 'get', 'serialnumber'],
                    capture_output=True,
                    text=True
                )
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    serial = lines[1].strip()
                    if serial:
                        return serial
            elif sys.platform == 'linux':
                # Linux: Read disk serial from /dev/disk
                result = subprocess.run(
                    ['lsblk', '-o', 'NAME,SERIAL', '-n'],
                    capture_output=True,
                    text=True
                )
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'sda' in line or 'nvme' in line:
                        parts = line.split()
                        if len(parts) > 1:
                            return parts[1]
        except Exception:
            pass
        
        return "unknown_disk"
    
    def _get_os_info(self) -> Dict[str, Any]:
        """Get detailed OS information"""
        return {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "hostname": platform.node(),
        }
    
    def _get_installed_software_hash(self) -> str:
        """Create hash of installed software (simplified)"""
        software_list = []
        try:
            if sys.platform == 'win32' and WINDOWS_REGISTRY_AVAILABLE:
                # Windows: Get installed applications
                keys = [
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                ]
                for reg_key in keys:
                    try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_key)
                        for i in range(1000):
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                subkey = winreg.OpenKey(key, subkey_name)
                                try:
                                    display_name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                                    if display_name:
                                        # Only include core apps for fingerprinting
                                        if any(app in display_name.lower() for app in 
                                               ['chrome', 'firefox', 'edge', 'office', 'vscode']):
                                            software_list.append(display_name)
                                except:
                                    pass
                                winreg.CloseKey(subkey)
                            except OSError:
                                break
                        winreg.CloseKey(key)
                    except:
                        pass
            elif sys.platform == 'linux':
                # Linux: Get installed packages (limited list)
                result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True)
                lines = result.stdout.strip().split('\n')
                for line in lines[:50]:  # Limit to first 50 packages
                    if 'ii' in line:
                        parts = line.split()
                        if len(parts) > 2:
                            software_list.append(parts[1])
        except Exception:
            pass
        
        software_string = '|'.join(sorted(software_list))
        return hashlib.sha256(software_string.encode()).hexdigest() if software_string else "no_software"
    
    def _get_network_adapters(self) -> list[Dict[str, str]]:
        """Get network adapter information"""
        adapters = []
        if not PSUTIL_AVAILABLE:
            return adapters
        
        for interface, addrs in psutil.net_if_addrs().items():
            adapter_info = {"name": interface}
            for addr in addrs:
                if addr.family == psutil.AF_LINK:
                    adapter_info["mac"] = addr.address
                elif addr.family == psutil.AF_INET:
                    adapter_info["ipv4"] = addr.address
                elif addr.family == psutil.AF_INET6:
                    adapter_info["ipv6"] = addr.address
            adapters.append(adapter_info)
        
        return adapters
    
    def _calculate_confidence(self, hardware_id: str, mac_addresses: list[str], cpu_id: str) -> float:
        """Calculate fingerprint confidence based on available data"""
        confidence = 0.0
        
        if hardware_id and hardware_id != "unknown" and hardware_id != str(uuid.getnode()):
            confidence += 0.4
        
        if mac_addresses and mac_addresses[0] != '00:00:00:00:00:00':
            confidence += 0.3
        
        if cpu_id and cpu_id != "unknown_cpu":
            confidence += 0.2
        
        if confidence > 0.0:
            confidence = min(confidence, 1.0)
        else:
            confidence = 0.3  # Minimal confidence if nothing is available
        
        return confidence
    
    def verify_fingerprint(self, stored_fingerprint: DeviceFingerprint, 
                          current_fingerprint: Optional[DeviceFingerprint] = None) -> tuple[bool, float, str]:
        """
        Verify if current device matches stored fingerprint.
        Returns: (is_match, confidence, reason)
        """
        if not current_fingerprint:
            current_fingerprint = self.get_fingerprint()
        
        # Check primary identifiers
        if stored_fingerprint.hardware_id != "unknown" and \
           stored_fingerprint.hardware_id != current_fingerprint.hardware_id:
            return False, 0.0, "Hardware ID mismatch"
        
        # Check MAC addresses (at least one should match)
        if stored_fingerprint.mac_addresses and current_fingerprint.mac_addresses:
            if not set(stored_fingerprint.mac_addresses) & set(current_fingerprint.mac_addresses):
                # One MAC might be enough
                if len(stored_fingerprint.mac_addresses) > 0:
                    return False, 0.2, "No matching MAC address"
        
        # Check CPU
        if stored_fingerprint.cpu_id != "unknown_cpu" and \
           stored_fingerprint.cpu_id != current_fingerprint.cpu_id:
            return False, 0.1, "CPU mismatch"
        
        # Calculate match confidence
        match_confidence = 0.5
        
        if stored_fingerprint.hardware_id == current_fingerprint.hardware_id:
            match_confidence += 0.3
        
        if any(mac in current_fingerprint.mac_addresses for mac in stored_fingerprint.mac_addresses):
            match_confidence += 0.2
        
        if stored_fingerprint.cpu_id == current_fingerprint.cpu_id:
            match_confidence += 0.1
        
        # Check software hash (less reliable)
        if stored_fingerprint.installed_software_hash == current_fingerprint.installed_software_hash:
            match_confidence += 0.1
        
        match_confidence = min(match_confidence, 1.0)
        
        is_match = match_confidence > 0.5
        reason = "Device verified" if is_match else "Device verification failed"
        
        return is_match, match_confidence, reason
    
    def create_trusted_device_record(self, device_id: str, trust_score: float = 1.0) -> Dict[str, Any]:
        """Create a trusted device record for Zero Trust database"""
        fingerprint = self.get_fingerprint(device_id)
        
        return {
            "device_id": device_id,
            "fingerprint_hash": fingerprint.fingerprint_hash,
            "hardware_id": fingerprint.hardware_id,
            "mac_addresses": fingerprint.mac_addresses,
            "cpu_id": fingerprint.cpu_id,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "last_verified": datetime.now(timezone.utc).isoformat(),
            "trust_score": trust_score,
            "confidence": fingerprint.confidence,
            "is_trusted": True,
            "device_type": self._detect_device_type(),
            "os_info": fingerprint.os_info,
        }
    
    def _detect_device_type(self) -> str:
        """Detect if device is laptop, desktop, server, etc."""
        # Simplified detection based on system info
        system = platform.system()
        if system == 'Windows':
            try:
                if WINDOWS_REGISTRY_AVAILABLE:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                        r"HARDWARE\DESCRIPTION\System\BIOS")
                    try:
                        value, _ = winreg.QueryValueEx(key, "SystemProductName")
                        winreg.CloseKey(key)
                        if 'laptop' in value.lower() or 'notebook' in value.lower():
                            return 'laptop'
                    except:
                        pass
            except:
                pass
        return 'desktop'  # Default


# Global singleton instance
_device_fingerprinter = None

def get_device_fingerprinter() -> DeviceFingerprinter:
    """Get global device fingerprinter instance"""
    global _device_fingerprinter
    if _device_fingerprinter is None:
        _device_fingerprinter = DeviceFingerprinter()
    return _device_fingerprinter