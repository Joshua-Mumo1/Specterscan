#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
thermal_check.py — Thermal sensor analysis.

Reads CPU, GPU, and system temperatures from sysfs (Linux), ioreg/smc
(macOS), or wmic (Windows).  Evaluates whether the cooling system is
healthy and whether temperatures are within safe operating ranges.
"""

import logging
import platform
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

SUBPROCESS_TIMEOUT = 10

# Temperature thresholds (°C)
CPU_WARN_C = 70.0
CPU_CRIT_C = 90.0
ANY_SENSOR_CRIT_C = 95.0


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
# Linux — sysfs thermal zones + hwmon
# ---------------------------------------------------------------------------

def _read_linux_sensors() -> List[Dict[str, Any]]:
    """Read all available thermal sensors from sysfs."""
    sensors: List[Dict[str, Any]] = []
    thermal_root = Path("/sys/class/thermal")
    hwmon_root = Path("/sys/class/hwmon")

    # Thermal zones
    if thermal_root.exists():
        for zone in sorted(thermal_root.iterdir()):
            if not zone.name.startswith("thermal_zone"):
                continue
            temp_raw = _read(zone / "temp")
            zone_type = _read(zone / "type", zone.name)
            if temp_raw and temp_raw.lstrip("-").isdigit():
                temp_c = int(temp_raw) / 1000.0
                sensors.append({"label": zone_type, "temp_c": temp_c, "source": str(zone)})

    # hwmon (more detailed — includes CPU cores, fans, etc.)
    if hwmon_root.exists():
        for hwmon in sorted(hwmon_root.iterdir()):
            name = _read(hwmon / "name", hwmon.name)
            for temp_file in sorted(hwmon.glob("temp*_input")):
                temp_raw = _read(temp_file)
                if temp_raw and temp_raw.lstrip("-").isdigit():
                    idx = re.search(r"temp(\d+)_input", temp_file.name)
                    label_file = temp_file.parent / f"temp{idx.group(1) if idx else '1'}_label"
                    label = _read(label_file, f"{name} sensor")
                    temp_c = int(temp_raw) / 1000.0
                    sensors.append({"label": f"{name}/{label}", "temp_c": temp_c, "source": str(temp_file)})

    return sensors


def _check_linux() -> Dict[str, Any]:
    """Linux thermal analysis."""
    sensors = _read_linux_sensors()

    # Identify CPU temperature (look for typical labels)
    cpu_labels = ["cpu", "core", "package", "x86_pkg_temp", "coretemp"]
    cpu_sensors = [
        s for s in sensors
        if any(lbl in s["label"].lower() for lbl in cpu_labels)
    ]

    cpu_temp = max((s["temp_c"] for s in cpu_sensors), default=None)

    # sensors-output supplement (lm-sensors)
    lm_out = _run(["sensors", "-A"])
    if lm_out and not cpu_sensors:
        for line in lm_out.splitlines():
            m = re.search(r"Core \d+\s*:\s*\+([\d.]+)°C", line)
            if m:
                cpu_sensors.append({"label": line.split(":")[0].strip(), "temp_c": float(m.group(1))})
        if cpu_sensors:
            cpu_temp = max(s["temp_c"] for s in cpu_sensors)

    return {
        "all_sensors": sensors,
        "cpu_sensors": cpu_sensors,
        "cpu_temp_c": cpu_temp,
    }


# ---------------------------------------------------------------------------
# macOS — ioreg / smc
# ---------------------------------------------------------------------------

def _check_macos() -> Dict[str, Any]:
    """macOS thermal analysis via ioreg."""
    raw = _run(["ioreg", "-rn", "IOHDIXController"])
    sensors: List[Dict[str, Any]] = []

    # Try powermetrics (requires root) for accurate CPU temp
    pm_out = _run(["powermetrics", "--samplers", "smc", "-n", "1", "-i", "100"])
    cpu_temp: Optional[float] = None
    if pm_out:
        for line in pm_out.splitlines():
            m = re.search(r"CPU die temperature:\s*([\d.]+)\s*C", line, re.IGNORECASE)
            if m:
                cpu_temp = float(m.group(1))
                sensors.append({"label": "CPU Die", "temp_c": cpu_temp})
                break

    return {
        "all_sensors": sensors,
        "cpu_sensors": [s for s in sensors if "cpu" in s["label"].lower()],
        "cpu_temp_c": cpu_temp,
    }


# ---------------------------------------------------------------------------
# Windows — wmic / OpenHardwareMonitor
# ---------------------------------------------------------------------------

def _check_windows() -> Dict[str, Any]:
    """Windows thermal analysis via wmic."""
    sensors: List[Dict[str, Any]] = []
    cpu_temp: Optional[float] = None

    try:
        import subprocess, csv, io
        r = subprocess.run(
            ["wmic", "/namespace:\\\\root\\wmi", "path", "MSAcpi_ThermalZoneTemperature",
             "get", "CurrentTemperature,InstanceName", "/format:csv"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        reader = csv.DictReader(io.StringIO(r.stdout))
        for row in reader:
            raw_val = row.get("CurrentTemperature", "").strip()
            name = row.get("InstanceName", "Thermal zone").strip()
            if raw_val and raw_val.isdigit():
                temp_c = (int(raw_val) - 2732) / 10.0
                sensors.append({"label": name, "temp_c": temp_c})
                if cpu_temp is None or temp_c > cpu_temp:
                    cpu_temp = temp_c
    except Exception as exc:
        logger.debug("Windows thermal read error: %s", exc)

    return {
        "all_sensors": sensors,
        "cpu_sensors": sensors,
        "cpu_temp_c": cpu_temp,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check() -> Dict[str, Any]:
    """
    Perform thermal analysis for the current platform.

    Returns:
        Dict with cpu_temp_c, all_sensors, flags, and severity.
    """
    system = platform.system()
    if system == "Linux":
        data = _check_linux()
    elif system == "Darwin":
        data = _check_macos()
    elif system == "Windows":
        data = _check_windows()
    else:
        data = {"all_sensors": [], "cpu_sensors": [], "cpu_temp_c": None}

    flags: List[str] = []
    cpu_temp = data.get("cpu_temp_c")

    if cpu_temp is None:
        data["severity"] = "unknown"
        if not data["all_sensors"]:
            flags.append("No temperature sensors accessible — may require elevated privileges")
    elif cpu_temp >= CPU_CRIT_C:
        data["severity"] = "critical"
        flags.append(f"CPU critically hot at idle/light load: {cpu_temp:.1f} °C")
    elif cpu_temp >= CPU_WARN_C:
        data["severity"] = "warning"
        flags.append(f"CPU temperature elevated: {cpu_temp:.1f} °C — check cooling")
    else:
        data["severity"] = "ok"

    # Check any sensor for critical values
    for sensor in data.get("all_sensors", []):
        t = sensor.get("temp_c", 0)
        if t >= ANY_SENSOR_CRIT_C:
            flags.append(f"Critical temperature on {sensor['label']}: {t:.1f} °C")

    # Fan info via sensors
    if system == "Linux":
        fans_out = _run(["sensors", "-A"])
        fan_rpms = []
        if fans_out:
            for line in fans_out.splitlines():
                m = re.search(r"fan\d*\s*:\s*(\d+)\s*RPM", line, re.IGNORECASE)
                if m:
                    fan_rpms.append(int(m.group(1)))
        data["fan_rpms"] = fan_rpms
        if fan_rpms and all(rpm == 0 for rpm in fan_rpms):
            flags.append("All fans reporting 0 RPM — fan failure or sensor issue")

    data["flags"] = flags
    data["module_status"] = "ok"
    return data


if __name__ == "__main__":
    import json
    print(json.dumps(check(), indent=2, default=str))
