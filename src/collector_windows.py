#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collector_windows.py — Windows hardware data collector.

Uses wmic, systeminfo, and PowerShell to gather hardware details
without any third-party dependencies.
"""

import csv
import io
import logging
import os
import platform
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

SUBPROCESS_TIMEOUT = 15  # seconds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: List[str], timeout: int = SUBPROCESS_TIMEOUT) -> Optional[str]:
    """Run a subprocess and return stdout, or None on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
        return result.stdout.strip() if result.returncode == 0 else result.stdout.strip() or None
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out: %s", " ".join(cmd))
        return None
    except OSError as exc:
        logger.debug("OSError running %s: %s", cmd, exc)
        return None


def _wmic_csv(query: str) -> List[Dict[str, str]]:
    """
    Run a WMIC query with /format:csv and parse the result.

    Returns a list of row dicts.
    """
    raw = _run(["wmic"] + query.split() + ["/format:csv"], timeout=20)
    if not raw:
        return []
    rows = []
    reader = csv.DictReader(io.StringIO(raw))
    for row in reader:
        cleaned = {k.strip(): v.strip() for k, v in row.items() if k}
        rows.append(cleaned)
    return rows


def _powershell(script: str, timeout: int = 15) -> Optional[str]:
    """Execute a PowerShell one-liner and return stdout."""
    return _run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# CPU
# ---------------------------------------------------------------------------

def _collect_cpu() -> Dict[str, Any]:
    """Collect CPU info via wmic and/or PowerShell."""
    cpu: Dict[str, Any] = {}
    rows = _wmic_csv("cpu get Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed,CurrentClockSpeed,Manufacturer,ProcessorId,Caption")
    if rows:
        row = rows[0]
        cpu["model_name"] = row.get("Name", "")
        cpu["manufacturer"] = row.get("Manufacturer", "")
        cpu["caption"] = row.get("Caption", "")
        cpu["processor_id"] = row.get("ProcessorId", "")
        try:
            cpu["cores_per_socket"] = int(row.get("NumberOfCores", 1))
        except ValueError:
            cpu["cores_per_socket"] = 1
        try:
            cpu["logical_cpus"] = int(row.get("NumberOfLogicalProcessors", 1))
        except ValueError:
            cpu["logical_cpus"] = 1
        try:
            cpu["max_mhz"] = float(row.get("MaxClockSpeed", 0))
        except ValueError:
            pass
        try:
            cpu["current_mhz"] = float(row.get("CurrentClockSpeed", 0))
        except ValueError:
            pass

    # VM detection via hypervisor present flag
    ps_out = _powershell("(Get-WmiObject -Class Win32_ComputerSystem).HypervisorPresent")
    cpu["vm_detected"] = (ps_out or "").strip().lower() == "true"

    return cpu


# ---------------------------------------------------------------------------
# Memory
# ---------------------------------------------------------------------------

def _collect_memory() -> Dict[str, Any]:
    """Collect RAM info via wmic."""
    mem: Dict[str, Any] = {}

    # Total physical memory
    rows = _wmic_csv("OS get TotalVisibleMemorySize,FreePhysicalMemory")
    if rows:
        row = rows[0]
        try:
            total_kb = int(row.get("TotalVisibleMemorySize", 0))
            free_kb = int(row.get("FreePhysicalMemory", 0))
            mem["total_kb"] = total_kb
            mem["total_gb"] = round(total_kb / (1024 ** 2), 2)
            mem["available_kb"] = free_kb
        except ValueError:
            pass

    # Per-DIMM details
    dimm_rows = _wmic_csv("memorychip get Capacity,Speed,MemoryType,Manufacturer,SerialNumber,DeviceLocator")
    populated = [r for r in dimm_rows if r.get("Capacity", "0") not in ("", "0")]
    mem["dimm_populated"] = len(populated)
    mem["dimm_details"] = [
        {
            "size": f"{int(r.get('Capacity', 0)) // (1024**3)} GB",
            "speed_mhz": r.get("Speed", ""),
            "type": r.get("MemoryType", ""),
            "manufacturer": r.get("Manufacturer", ""),
            "serial": r.get("SerialNumber", ""),
            "locator": r.get("DeviceLocator", ""),
        }
        for r in populated
    ]

    return mem


# ---------------------------------------------------------------------------
# Motherboard / BIOS
# ---------------------------------------------------------------------------

def _collect_motherboard() -> Dict[str, Any]:
    """Collect board and BIOS info via wmic."""
    mb: Dict[str, Any] = {}

    # BIOS
    bios_rows = _wmic_csv("bios get Manufacturer,Name,SerialNumber,Version,ReleaseDate,SMBIOSBIOSVersion")
    if bios_rows:
        b = bios_rows[0]
        mb["bios_vendor"] = b.get("Manufacturer", "")
        mb["bios_version"] = b.get("SMBIOSBIOSVersion", b.get("Version", ""))
        mb["bios_date"] = b.get("ReleaseDate", "")
        mb["product_serial"] = b.get("SerialNumber", "")

    # Baseboard
    bb_rows = _wmic_csv("baseboard get Manufacturer,Product,SerialNumber,Version")
    if bb_rows:
        bb = bb_rows[0]
        mb["vendor"] = bb.get("Manufacturer", "")
        mb["name"] = bb.get("Product", "")
        mb["version"] = bb.get("Version", "")
        mb["serial"] = bb.get("SerialNumber", "")

    # System info
    sys_rows = _wmic_csv("computersystem get Manufacturer,Model,SystemType,TotalPhysicalMemory")
    if sys_rows:
        s = sys_rows[0]
        mb["sys_vendor"] = s.get("Manufacturer", "")
        mb["product_name"] = s.get("Model", "")

    suspicious = {"none", "to be filled by o.e.m.", "00000000", "default string", "", "system serial number"}
    serial = mb.get("product_serial", "").lower()
    mb["serial_suspicious"] = serial in suspicious

    return mb


# ---------------------------------------------------------------------------
# GPU
# ---------------------------------------------------------------------------

def _collect_gpu() -> List[Dict[str, Any]]:
    """Collect GPU list via wmic."""
    rows = _wmic_csv("path win32_VideoController get Name,AdapterRAM,DriverVersion,VideoModeDescription,PNPDeviceID")
    gpus = []
    for row in rows:
        if not row.get("Name"):
            continue
        vram_bytes = 0
        try:
            vram_bytes = int(row.get("AdapterRAM", 0))
        except ValueError:
            pass
        gpus.append(
            {
                "model": row.get("Name", ""),
                "vram_gb": round(vram_bytes / (1024 ** 3), 2) if vram_bytes else 0,
                "driver_version": row.get("DriverVersion", ""),
                "pnp_id": row.get("PNPDeviceID", ""),
            }
        )
    return gpus


# ---------------------------------------------------------------------------
# USB history
# ---------------------------------------------------------------------------

def _collect_usb_history() -> Dict[str, Any]:
    """Read USB device history from the Windows registry."""
    usb: Dict[str, Any] = {"devices": [], "flags": []}

    ps_script = (
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\*\\*' "
        "| Select-Object FriendlyName, DeviceDesc, ClassGUID, Mfg "
        "| ConvertTo-Json -Depth 2"
    )
    ps_out = _powershell(ps_script, timeout=20)
    if ps_out:
        try:
            import json
            raw = json.loads(ps_out)
            if isinstance(raw, dict):
                raw = [raw]
            devices = []
            for item in raw:
                name = item.get("FriendlyName") or item.get("DeviceDesc") or "Unknown"
                suspicious = "unknown" in name.lower() or not item.get("Mfg", "").strip()
                devices.append({"name": name, "manufacturer": item.get("Mfg", ""), "suspicious": suspicious})
            usb["devices"] = devices
            suspicious_count = sum(1 for d in devices if d["suspicious"])
            if suspicious_count > 0:
                usb["flags"].append(f"{suspicious_count} unidentified USB storage device(s) in history")
        except Exception as exc:
            logger.debug("USB history parse error: %s", exc)

    # Power events — look for USB power surge events (Event ID 43 in Microsoft-Windows-Kernel-PnP)
    evt_script = (
        "Get-WinEvent -FilterHashtable @{LogName='System'; Id=43} -MaxEvents 20 -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty Message"
    )
    evt_out = _powershell(evt_script)
    if evt_out and "surprise" in evt_out.lower():
        usb["flags"].append("USB surprise-removal events detected in system log")

    return usb


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

def _collect_network() -> List[Dict[str, str]]:
    """List network adapters via wmic."""
    rows = _wmic_csv("nicconfig where IPEnabled=TRUE get Caption,MACAddress,DefaultIPGateway,IPAddress")
    ifaces = []
    for row in rows:
        if not row.get("MACAddress"):
            continue
        ifaces.append(
            {
                "name": row.get("Caption", ""),
                "mac": row.get("MACAddress", ""),
            }
        )
    return ifaces


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def collect() -> Dict[str, Any]:
    """
    Collect all hardware information on Windows.

    Returns:
        A dict containing sub-dicts for cpu, memory, motherboard,
        gpu, usb, and network.
    """
    logger.info("Starting Windows hardware collection")
    data: Dict[str, Any] = {
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "node": platform.node(),
        }
    }

    data["cpu"] = _collect_cpu()
    data["memory"] = _collect_memory()
    data["motherboard"] = _collect_motherboard()
    data["gpu"] = _collect_gpu()
    data["usb"] = _collect_usb_history()
    data["network"] = _collect_network()

    logger.info("Windows hardware collection complete")
    return data


if __name__ == "__main__":
    import json as _json
    print(_json.dumps(collect(), indent=2, default=str))
