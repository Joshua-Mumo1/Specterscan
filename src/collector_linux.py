#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collector_linux.py — Linux / macOS hardware data collector.

Reads system information from /proc, /sys, dmidecode, and other
standard Linux interfaces.  Falls back gracefully when a data source
is unavailable.
"""

import json
import logging
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PROC_CPUINFO = Path("/proc/cpuinfo")
PROC_MEMINFO = Path("/proc/meminfo")
PROC_PARTITIONS = Path("/proc/partitions")
PROC_DISKSTATS = Path("/proc/diskstats")
SYS_DMI = Path("/sys/class/dmi/id")
SUBPROCESS_TIMEOUT = 10  # seconds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_file(path: Path, default: str = "") -> str:
    """Read a file and return its contents, or *default* on error."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError) as exc:
        logger.debug("Cannot read %s: %s", path, exc)
        return default


def _run(cmd: List[str], timeout: int = SUBPROCESS_TIMEOUT) -> Optional[str]:
    """
    Run a subprocess and return stdout as a string.

    Returns None if the command is not found, times out, or fails.
    """
    if not shutil.which(cmd[0]):
        logger.debug("Command not found: %s", cmd[0])
        return None
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out: %s", " ".join(cmd))
        return None
    except OSError as exc:
        logger.debug("OSError running %s: %s", cmd, exc)
        return None


def _dmi_field(field: str) -> str:
    """Read a single DMI sysfs field."""
    return _read_file(SYS_DMI / field).strip()


# ---------------------------------------------------------------------------
# CPU
# ---------------------------------------------------------------------------

def _collect_cpu() -> Dict[str, Any]:
    """Parse /proc/cpuinfo and supplement with lscpu."""
    cpu: Dict[str, Any] = {}

    raw = _read_file(PROC_CPUINFO)
    if raw:
        # Grab first processor block
        for line in raw.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower().replace(" ", "_")
            value = value.strip()
            if key == "model_name" and "model_name" not in cpu:
                cpu["model_name"] = value
            elif key == "cpu_mhz" and "current_mhz" not in cpu:
                try:
                    cpu["current_mhz"] = float(value)
                except ValueError:
                    pass
            elif key == "cpu_max_mhz":
                try:
                    cpu["max_mhz"] = float(value)
                except ValueError:
                    pass
            elif key == "flags" and "flags" not in cpu:
                cpu["flags"] = value.split()
            elif key == "cpu_cores" and "cores_per_socket" not in cpu:
                try:
                    cpu["cores_per_socket"] = int(value)
                except ValueError:
                    pass

        # Count physical + logical processors
        cpu["logical_cpus"] = raw.count("processor\t:")
        cpu["physical_cpus"] = len(
            set(
                re.findall(r"physical id\s*:\s*(\d+)", raw)
            )
        ) or 1

    # Supplement with lscpu
    lscpu_out = _run(["lscpu"])
    if lscpu_out:
        lscpu_map: Dict[str, str] = {}
        for line in lscpu_out.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                lscpu_map[k.strip()] = v.strip()
        cpu.setdefault("architecture", lscpu_map.get("Architecture", ""))
        cpu.setdefault("vendor", lscpu_map.get("Vendor ID", ""))
        cpu.setdefault("socket_count", int(lscpu_map.get("Socket(s)", 1)))
        cpu.setdefault("cores_per_socket", int(lscpu_map.get("Core(s) per socket", 1)))
        cpu.setdefault("threads_per_core", int(lscpu_map.get("Thread(s) per core", 1)))
        cpu.setdefault("logical_cpus", int(lscpu_map.get("CPU(s)", cpu.get("logical_cpus", 1))))
        if "CPU max MHz" in lscpu_map:
            try:
                cpu["max_mhz"] = float(lscpu_map["CPU max MHz"].replace(",", "."))
            except ValueError:
                pass
        cpu["hypervisor_vendor"] = lscpu_map.get("Hypervisor vendor", "")
        cpu["virtualization_type"] = lscpu_map.get("Virtualization type", "")

    # VM / hypervisor detection via CPUID flags
    flags = cpu.get("flags", [])
    hypervisor_flag = "hypervisor" in flags
    cpu["vm_detected"] = hypervisor_flag or bool(cpu.get("hypervisor_vendor"))

    return cpu


# ---------------------------------------------------------------------------
# Memory
# ---------------------------------------------------------------------------

def _collect_memory() -> Dict[str, Any]:
    """Parse /proc/meminfo for RAM totals."""
    mem: Dict[str, Any] = {}
    raw = _read_file(PROC_MEMINFO)
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if key == "MemTotal":
            mem["total_kb"] = int(value.split()[0])
            mem["total_gb"] = round(mem["total_kb"] / (1024 ** 2), 2)
        elif key == "MemAvailable":
            mem["available_kb"] = int(value.split()[0])
        elif key == "SwapTotal":
            mem["swap_total_kb"] = int(value.split()[0])

    # dmidecode for per-DIMM details
    dmidecode_out = _run(["dmidecode", "--type", "memory"])
    if dmidecode_out:
        slots: List[Dict[str, str]] = []
        current: Dict[str, str] = {}
        for line in dmidecode_out.splitlines():
            line = line.strip()
            if line.startswith("Memory Device"):
                if current:
                    slots.append(current)
                current = {}
            elif ":" in line:
                k, _, v = line.partition(":")
                current[k.strip()] = v.strip()
        if current:
            slots.append(current)
        populated = [s for s in slots if s.get("Size", "No Module Installed") not in ("No Module Installed", "Unknown", "")]
        mem["dimm_slots"] = len(slots)
        mem["dimm_populated"] = len(populated)
        mem["dimm_details"] = [
            {
                "size": s.get("Size", ""),
                "type": s.get("Type", ""),
                "speed_mhz": s.get("Speed", ""),
                "manufacturer": s.get("Manufacturer", ""),
                "serial": s.get("Serial Number", ""),
                "locator": s.get("Locator", ""),
            }
            for s in populated
        ]

    return mem


# ---------------------------------------------------------------------------
# Motherboard / BIOS
# ---------------------------------------------------------------------------

def _collect_motherboard() -> Dict[str, Any]:
    """Read DMI sysfs fields for board and BIOS identification."""
    mb: Dict[str, Any] = {
        "vendor": _dmi_field("board_vendor"),
        "name": _dmi_field("board_name"),
        "version": _dmi_field("board_version"),
        "serial": _dmi_field("board_serial"),
        "bios_vendor": _dmi_field("bios_vendor"),
        "bios_version": _dmi_field("bios_version"),
        "bios_date": _dmi_field("bios_date"),
        "sys_vendor": _dmi_field("sys_vendor"),
        "product_name": _dmi_field("product_name"),
        "product_serial": _dmi_field("product_serial"),
        "product_uuid": _dmi_field("product_uuid"),
        "chassis_type": _dmi_field("chassis_type"),
    }

    # Check for "None", placeholder values that suggest tampering
    suspicious_serials = {"none", "to be filled by o.e.m.", "00000000", "default string", ""}
    if mb["product_serial"].lower() in suspicious_serials:
        mb["serial_suspicious"] = True
    else:
        mb["serial_suspicious"] = False

    return mb


# ---------------------------------------------------------------------------
# GPU
# ---------------------------------------------------------------------------

def _collect_gpu() -> List[Dict[str, Any]]:
    """List GPUs via lspci."""
    gpus: List[Dict[str, Any]] = []
    lspci_out = _run(["lspci", "-mm"])
    if not lspci_out:
        return gpus
    for line in lspci_out.splitlines():
        if "VGA" in line or "3D" in line or "Display" in line:
            parts = re.split(r'"', line)
            gpus.append(
                {
                    "class": parts[1] if len(parts) > 1 else "",
                    "vendor": parts[3] if len(parts) > 3 else "",
                    "model": parts[5] if len(parts) > 5 else "",
                }
            )
    return gpus


# ---------------------------------------------------------------------------
# USB device history
# ---------------------------------------------------------------------------

def _collect_usb_history() -> Dict[str, Any]:
    """
    Collect USB device history from udevadm and system logs.

    Checks for unbranded storage or suspicious device classes.
    """
    usb: Dict[str, Any] = {"devices": [], "flags": []}

    # Current USB devices via lsusb
    lsusb_out = _run(["lsusb"])
    if lsusb_out:
        devices = []
        for line in lsusb_out.splitlines():
            m = re.match(r"Bus \d+ Device \d+: ID ([\da-f:]+) (.+)", line)
            if m:
                vid_pid = m.group(1)
                name = m.group(2).strip()
                suspicious = any(
                    tok in name.lower()
                    for tok in ("unknown", "composite", "hid-compliant", "generic")
                ) and "keyboard" not in name.lower()
                devices.append({"id": vid_pid, "name": name, "suspicious": suspicious})
        usb["devices"] = devices
        suspicious_count = sum(1 for d in devices if d["suspicious"])
        if suspicious_count > 0:
            usb["flags"].append(
                f"{suspicious_count} unidentified USB device(s) currently connected"
            )

    # Historical: /var/log/syslog or journalctl for USB killer patterns
    power_surge_patterns = [
        r"over.current",
        r"power surge",
        r"usb reset",
        r"device descriptor read.*error",
    ]
    journal_out = _run(["journalctl", "-k", "--no-pager", "-n", "500"])
    if journal_out:
        for pattern in power_surge_patterns:
            matches = re.findall(pattern, journal_out, re.IGNORECASE)
            if matches:
                usb["flags"].append(f"USB power anomaly in kernel log: '{pattern}' ({len(matches)} occurrence(s))")

    return usb


# ---------------------------------------------------------------------------
# Network interfaces
# ---------------------------------------------------------------------------

def _collect_network() -> List[Dict[str, str]]:
    """List network interfaces and their MAC addresses."""
    ifaces = []
    net_path = Path("/sys/class/net")
    if not net_path.exists():
        return ifaces
    for iface in sorted(net_path.iterdir()):
        mac = _read_file(iface / "address").strip()
        iface_type = _read_file(iface / "type").strip()
        speed_raw = _read_file(iface / "speed").strip()
        ifaces.append(
            {
                "name": iface.name,
                "mac": mac,
                "type": iface_type,
                "speed_mbps": speed_raw,
            }
        )
    return ifaces


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def collect() -> Dict[str, Any]:
    """
    Collect all hardware information on Linux / macOS.

    Returns:
        A dict containing sub-dicts for cpu, memory, motherboard,
        gpu, usb, and network.
    """
    logger.info("Starting Linux hardware collection")
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
    logger.debug("CPU collected: %s", data["cpu"].get("model_name"))

    data["memory"] = _collect_memory()
    logger.debug("Memory collected: %.1f GB", data["memory"].get("total_gb", 0))

    data["motherboard"] = _collect_motherboard()
    data["gpu"] = _collect_gpu()
    data["usb"] = _collect_usb_history()
    data["network"] = _collect_network()

    # Uptime
    uptime_raw = _read_file(Path("/proc/uptime")).split()
    if uptime_raw:
        data["uptime_seconds"] = float(uptime_raw[0])

    logger.info("Linux hardware collection complete")
    return data


if __name__ == "__main__":
    import json as _json
    print(_json.dumps(collect(), indent=2, default=str))
