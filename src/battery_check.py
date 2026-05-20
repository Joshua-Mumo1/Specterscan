#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
battery_check.py — Battery health analysis.

Reads battery data from sysfs (Linux), ioreg (macOS), or wmic (Windows)
and computes health percentage, cycle count estimate, and degradation flags.
"""

import logging
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
SYS_POWER = Path("/sys/class/power_supply")
HEALTH_WARN_THRESHOLD = 70.0   # % — below this is a warning
HEALTH_CRIT_THRESHOLD = 50.0   # % — below this is critical
SUBPROCESS_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read(path: Path, default: str = "") -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except (OSError, PermissionError):
        return default


def _run(cmd: List[str], timeout: int = SUBPROCESS_TIMEOUT) -> Optional[str]:
    if not shutil.which(cmd[0]):
        return None
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return r.stdout.strip() or None
    except (subprocess.TimeoutExpired, OSError):
        return None


# ---------------------------------------------------------------------------
# Linux battery via /sys/class/power_supply
# ---------------------------------------------------------------------------

def _check_linux() -> Dict[str, Any]:
    """Read battery data from sysfs."""
    bat_dirs = [d for d in SYS_POWER.iterdir() if d.name.startswith("BAT")] if SYS_POWER.exists() else []
    if not bat_dirs:
        return {"present": False, "reason": "No battery detected (desktop or battery not present)"}

    bat = bat_dirs[0]
    result: Dict[str, Any] = {"present": True, "path": str(bat)}

    # Prefer energy_* values (µWh) over charge_* (µAh) — more accurate
    energy_full = int(_read(bat / "energy_full", "0") or "0")
    energy_full_design = int(_read(bat / "energy_full_design", "0") or "0")
    energy_now = int(_read(bat / "energy_now", "0") or "0")

    if not energy_full_design and not energy_full:
        # Fall back to charge_* values
        charge_full = int(_read(bat / "charge_full", "0") or "0")
        charge_design = int(_read(bat / "charge_full_design", "0") or "0")
        charge_now = int(_read(bat / "charge_now", "0") or "0")
        energy_full = charge_full
        energy_full_design = charge_design
        energy_now = charge_now

    result["energy_full_uwh"] = energy_full
    result["energy_full_design_uwh"] = energy_full_design
    result["energy_now_uwh"] = energy_now

    if energy_full_design > 0:
        result["health_pct"] = round(100.0 * energy_full / energy_full_design, 1)
    else:
        result["health_pct"] = None

    if energy_full > 0:
        result["charge_pct"] = round(100.0 * energy_now / energy_full, 1)
    else:
        result["charge_pct"] = None

    result["status"] = _read(bat / "status", "Unknown")
    result["technology"] = _read(bat / "technology", "Unknown")
    result["manufacturer"] = _read(bat / "manufacturer", "Unknown")
    result["model_name"] = _read(bat / "model_name", "Unknown")
    result["serial_number"] = _read(bat / "serial_number", "")

    # Cycle count (not always available)
    cycle_raw = _read(bat / "cycle_count", "")
    if cycle_raw.isdigit():
        result["cycle_count"] = int(cycle_raw)
    else:
        # Estimate from health degradation (rough approximation)
        health = result.get("health_pct")
        if health is not None:
            degradation = max(0.0, 100.0 - health)
            result["cycle_count_estimate"] = int(degradation * 5)  # ~0.2% per cycle
        result["cycle_count"] = None

    return result


# ---------------------------------------------------------------------------
# macOS battery via ioreg
# ---------------------------------------------------------------------------

def _check_macos() -> Dict[str, Any]:
    """Read battery data from ioreg on macOS."""
    raw = _run(["ioreg", "-l", "-n", "AppleSmartBattery"])
    if not raw:
        return {"present": False, "reason": "ioreg unavailable"}

    def _extract(key: str) -> Optional[str]:
        m = re.search(rf'"{key}"\s*=\s*(\S+)', raw)
        return m.group(1).strip('"') if m else None

    result: Dict[str, Any] = {"present": True}
    try:
        design_cap = int(_extract("DesignCapacity") or 0)
        full_cap = int(_extract("FullChargeCapacity") or 0)
        current_cap = int(_extract("CurrentCapacity") or 0)
        result["energy_full_design_uwh"] = design_cap
        result["energy_full_uwh"] = full_cap
        result["energy_now_uwh"] = current_cap
        result["health_pct"] = round(100.0 * full_cap / design_cap, 1) if design_cap else None
        result["charge_pct"] = round(100.0 * current_cap / full_cap, 1) if full_cap else None
        result["cycle_count"] = int(_extract("CycleCount") or 0)
        result["manufacturer"] = _extract("Manufacturer") or "Unknown"
        result["model_name"] = _extract("DeviceName") or "Unknown"
        result["status"] = "Charging" if (_extract("IsCharging") or "").lower() == "yes" else "Discharging"
    except (TypeError, ValueError) as exc:
        logger.debug("macOS battery parse error: %s", exc)

    return result


# ---------------------------------------------------------------------------
# Windows battery via wmic
# ---------------------------------------------------------------------------

def _check_windows() -> Dict[str, Any]:
    """Read battery data from WMIC on Windows."""
    try:
        result_raw = subprocess.run(
            ["wmic", "path", "Win32_Battery", "get",
             "DesignCapacity,FullChargeCapacity,EstimatedChargeRemaining,BatteryStatus,Manufacturer,Name,Chemistry",
             "/format:csv"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        lines = [l for l in result_raw.stdout.splitlines() if l.strip() and l.strip() != "Node"]
        if len(lines) < 2:
            return {"present": False, "reason": "No battery detected"}

        import csv, io
        reader = csv.DictReader(io.StringIO(result_raw.stdout))
        rows = [r for r in reader if any(v.strip() for v in r.values())]
        if not rows:
            return {"present": False, "reason": "No battery detected"}

        row = rows[0]
        design = int(row.get("DesignCapacity", "0") or "0")
        full = int(row.get("FullChargeCapacity", "0") or "0")
        charge_pct = float(row.get("EstimatedChargeRemaining", "0") or "0")
        result: Dict[str, Any] = {
            "present": True,
            "energy_full_design_uwh": design,
            "energy_full_uwh": full,
            "health_pct": round(100.0 * full / design, 1) if design else None,
            "charge_pct": charge_pct,
            "manufacturer": row.get("Manufacturer", "Unknown"),
            "model_name": row.get("Name", "Unknown"),
            "status": row.get("BatteryStatus", "Unknown"),
            "cycle_count": None,
        }
        return result
    except Exception as exc:
        logger.debug("Windows battery check error: %s", exc)
        return {"present": False, "reason": str(exc)}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check() -> Dict[str, Any]:
    """
    Perform battery health analysis for the current platform.

    Returns:
        Dict with health_pct, charge_pct, cycle_count, manufacturer,
        flags, and a severity rating.
    """
    system = platform.system()
    if system == "Linux":
        data = _check_linux()
    elif system == "Darwin":
        data = _check_macos()
    elif system == "Windows":
        data = _check_windows()
    else:
        data = {"present": False, "reason": f"Unsupported platform: {system}"}

    if not data.get("present", False):
        data["module_status"] = "skipped"
        return data

    # ── Severity classification ────────────────────────────────────────────
    health = data.get("health_pct")
    flags: List[str] = []

    if health is None:
        data["severity"] = "unknown"
        flags.append("Could not determine battery health — capacity data unavailable")
    elif health < HEALTH_CRIT_THRESHOLD:
        data["severity"] = "critical"
        flags.append(f"Battery severely degraded ({health:.1f}% of design capacity)")
    elif health < HEALTH_WARN_THRESHOLD:
        data["severity"] = "warning"
        flags.append(f"Battery degraded ({health:.1f}% of design capacity)")
    else:
        data["severity"] = "ok"

    # OEM battery check — unknown manufacturer is suspicious
    mfr = data.get("manufacturer", "Unknown").lower()
    if mfr in ("", "unknown", "oem", "generic", "none"):
        flags.append("Battery manufacturer unknown — may be non-OEM replacement")
        data["non_oem_suspected"] = True
    else:
        data["non_oem_suspected"] = False

    # Cycle count warning
    cycles = data.get("cycle_count")
    if cycles is not None and cycles > 800:
        flags.append(f"High cycle count ({cycles}) — battery nearing end of life")
    est_cycles = data.get("cycle_count_estimate")
    if est_cycles is not None and est_cycles > 800:
        flags.append(f"Estimated cycle count {est_cycles} — battery may be heavily used")

    data["flags"] = flags
    data["module_status"] = "ok"
    return data


if __name__ == "__main__":
    import json
    print(json.dumps(check(), indent=2, default=str))
