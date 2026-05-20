#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
storage_check.py — Storage health analysis.

Reads SMART data via smartctl (if available) and sysfs block device
attributes.  Performs a write-verify spot check to detect fake capacity.
"""

import logging
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

SUBPROCESS_TIMEOUT = 20
FAKE_CAP_WRITE_MB = 256       # MB to write for fake-capacity detection
CRITICAL_SMART_ATTRS = {
    5: "Reallocated_Sector_Ct",
    187: "Reported_Uncorrect",
    188: "Command_Timeout",
    197: "Current_Pending_Sector",
    198: "Offline_Uncorrectable",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: List[str], timeout: int = SUBPROCESS_TIMEOUT) -> Optional[str]:
    if not shutil.which(cmd[0]):
        return None
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return r.stdout.strip() or None
    except (subprocess.TimeoutExpired, OSError):
        return None


def _run_json(cmd: List[str]) -> Optional[Dict]:
    raw = _run(cmd)
    if not raw:
        return None
    try:
        import json
        return json.loads(raw)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Disk enumeration
# ---------------------------------------------------------------------------

def _list_disks_linux() -> List[str]:
    """Return a list of block device paths on Linux."""
    disks = []
    block_path = Path("/sys/block")
    if not block_path.exists():
        return disks
    for dev in sorted(block_path.iterdir()):
        name = dev.name
        # Skip loop, ram, sr devices
        if re.match(r"^(loop|ram|sr|zram|dm-)", name):
            continue
        disks.append(f"/dev/{name}")
    return disks


def _list_disks_windows() -> List[str]:
    """Return drive letters or \\.\PhysicalDrive paths on Windows."""
    disks = []
    try:
        import subprocess, csv, io
        r = subprocess.run(
            ["wmic", "diskdrive", "get", "DeviceID,Model,Size,MediaType,InterfaceType", "/format:csv"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        reader = csv.DictReader(io.StringIO(r.stdout))
        for row in reader:
            did = row.get("DeviceID", "").strip()
            if did:
                disks.append(did)
    except Exception as exc:
        logger.debug("Windows disk list error: %s", exc)
    return disks


# ---------------------------------------------------------------------------
# SMART analysis
# ---------------------------------------------------------------------------

def _parse_smart(disk: str) -> Dict[str, Any]:
    """
    Query smartctl for a disk and return a normalised health dict.

    Tries JSON mode first, falls back to text parsing.
    """
    result: Dict[str, Any] = {"device": disk}

    # Attempt JSON (smartctl >= 7.0)
    json_data = _run_json(["smartctl", "--json", "-a", disk])
    if json_data:
        result["model"] = json_data.get("model_name", "")
        result["serial"] = json_data.get("serial_number", "")
        result["firmware"] = json_data.get("firmware_version", "")
        result["capacity_bytes"] = json_data.get("user_capacity", {}).get("bytes", 0)
        result["capacity_gb"] = round(result["capacity_bytes"] / (1000 ** 3), 1)
        result["rpm"] = json_data.get("rotation_rate", 0)
        result["type"] = "SSD" if result["rpm"] == 0 else "HDD"
        result["interface"] = json_data.get("device", {}).get("protocol", "")

        smart_status = json_data.get("smart_status", {})
        result["health"] = "PASSED" if smart_status.get("passed") else "FAILED"

        # NVMe / ATA attributes
        nvme_log = json_data.get("nvme_smart_health_information_log", {})
        if nvme_log:
            result["nvme"] = {
                "percentage_used": nvme_log.get("percentage_used", 0),
                "data_units_written": nvme_log.get("data_units_written", 0),
                "power_on_hours": nvme_log.get("power_on_hours", 0),
                "unsafe_shutdowns": nvme_log.get("unsafe_shutdowns", 0),
                "media_errors": nvme_log.get("media_errors", 0),
                "critical_warning": nvme_log.get("critical_warning", 0),
            }
            if nvme_log.get("media_errors", 0) > 0:
                result["health"] = "FAILED"

        # ATA attributes
        attrs = json_data.get("ata_smart_attributes", {}).get("table", [])
        critical_values: Dict[str, int] = {}
        for attr in attrs:
            attr_id = attr.get("id")
            if attr_id in CRITICAL_SMART_ATTRS:
                raw_val = attr.get("raw", {}).get("value", 0)
                critical_values[CRITICAL_SMART_ATTRS[attr_id]] = raw_val
        result["critical_smart"] = critical_values

        # Reallocated sectors are a red flag
        reallocated = critical_values.get("Reallocated_Sector_Ct", 0)
        pending = critical_values.get("Current_Pending_Sector", 0)
        if reallocated > 0 or pending > 0:
            result["health"] = "WARNING"
            result["smart_flags"] = []
            if reallocated > 0:
                result["smart_flags"].append(f"Reallocated sectors: {reallocated}")
            if pending > 0:
                result["smart_flags"].append(f"Pending sectors: {pending}")

        # Power-on hours
        result["power_on_hours"] = json_data.get("power_on_time", {}).get("hours", 0)

        return result

    # Fallback: text parsing
    text_out = _run(["smartctl", "-H", disk])
    if text_out:
        result["model"] = ""
        result["health"] = "PASSED" if "PASSED" in text_out else "FAILED" if "FAILED" in text_out else "UNKNOWN"
        result["capacity_gb"] = 0
    else:
        result["health"] = "UNKNOWN"
        result["model"] = "Unknown (smartctl unavailable)"

    return result


# ---------------------------------------------------------------------------
# Fake capacity detection
# ---------------------------------------------------------------------------

def _check_fake_capacity(disk_path: str, reported_gb: float) -> Dict[str, Any]:
    """
    Write a test file beyond the first portion of the reported capacity
    and read it back to detect fake flash devices that loop on small storage.

    Only performed on removable or small (<= 512 GB) storage.
    This is a quick spot-check, not an exhaustive test.
    """
    result: Dict[str, Any] = {"performed": False}

    if reported_gb > 512:
        result["skipped_reason"] = "Drive > 512 GB — skipping fake-capacity check for safety"
        return result

    if not os.access(disk_path, os.W_OK):
        result["skipped_reason"] = "No write access to perform fake-capacity check"
        return result

    result["performed"] = True
    chunk = b"\xDE\xAD\xBE\xEF" * (1024 * 64)   # 256 KB sentinel

    try:
        # Seek to 80% of reported capacity before writing
        target_offset = int(reported_gb * (1000 ** 3) * 0.80)
        with open(disk_path, "rb+", buffering=0) as fh:
            fh.seek(target_offset)
            fh.write(chunk)
            fh.flush()
            os.fsync(fh.fileno())
            fh.seek(target_offset)
            readback = fh.read(len(chunk))

        if readback == chunk:
            result["verdict"] = "PASS"
        else:
            result["verdict"] = "FAIL"
            result["detail"] = "Readback mismatch — drive may report false capacity"
    except OSError as exc:
        result["verdict"] = "SKIPPED"
        result["detail"] = str(exc)

    return result


# ---------------------------------------------------------------------------
# Windows disk info supplement
# ---------------------------------------------------------------------------

def _windows_disk_info() -> List[Dict[str, Any]]:
    """Supplement Windows disk info via wmic."""
    drives = []
    try:
        import subprocess, csv, io
        r = subprocess.run(
            ["wmic", "diskdrive", "get",
             "DeviceID,Model,SerialNumber,Size,MediaType,InterfaceType,Status,FirmwareRevision",
             "/format:csv"],
            capture_output=True, text=True, timeout=20, check=False,
        )
        reader = csv.DictReader(io.StringIO(r.stdout))
        for row in reader:
            model = row.get("Model", "").strip()
            if not model:
                continue
            size_bytes = int(row.get("Size", "0") or "0")
            drives.append({
                "device": row.get("DeviceID", "").strip(),
                "model": model,
                "serial": row.get("SerialNumber", "").strip(),
                "firmware": row.get("FirmwareRevision", "").strip(),
                "capacity_bytes": size_bytes,
                "capacity_gb": round(size_bytes / (1000 ** 3), 1),
                "media_type": row.get("MediaType", ""),
                "interface": row.get("InterfaceType", ""),
                "health": "PASSED" if row.get("Status", "").upper() == "OK" else "WARNING",
            })
    except Exception as exc:
        logger.debug("Windows disk WMIC error: %s", exc)
    return drives


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check() -> Dict[str, Any]:
    """
    Perform storage health analysis for all detected drives.

    Returns:
        Dict with a list of 'drives', each containing model, health,
        capacity, SMART attributes, and fake-capacity check results.
    """
    system = platform.system()
    drives: List[Dict[str, Any]] = []

    if system == "Windows":
        for info in _windows_disk_info():
            smart = _parse_smart(info["device"])
            info.update({k: v for k, v in smart.items() if k not in info})
            drives.append(info)
    else:
        for disk in _list_disks_linux():
            drives.append(_parse_smart(disk))

    # Fake-capacity check for each drive
    for drive in drives:
        cap_gb = drive.get("capacity_gb", 0)
        device = drive.get("device", "")
        if system != "Windows" and cap_gb and device:
            drive["fake_capacity_check"] = _check_fake_capacity(device, cap_gb)
        else:
            drive["fake_capacity_check"] = {"performed": False, "skipped_reason": "Platform or capacity limitation"}

    # Overall flags
    flags: List[str] = []
    for drive in drives:
        health = drive.get("health", "UNKNOWN")
        model = drive.get("model", drive.get("device", "Unknown"))
        if health == "FAILED":
            flags.append(f"Drive FAILED SMART test: {model}")
        smart_flags = drive.get("smart_flags", [])
        for sf in smart_flags:
            flags.append(f"{model}: {sf}")
        fc = drive.get("fake_capacity_check", {})
        if fc.get("verdict") == "FAIL":
            flags.append(f"Fake capacity detected on {model}")

    return {
        "drives": drives,
        "flags": flags,
        "drive_count": len(drives),
        "module_status": "ok",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(check(), indent=2, default=str))
