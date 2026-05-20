#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
integrity_check.py — Hardware integrity and authenticity checks.

Cross-references reported hardware specifications against expected ranges,
checks for serial number anomalies, VM masking, and common spec-fraud
patterns found in used laptop sales.
"""

import logging
import platform
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants — known CPUs with expected specs
# ---------------------------------------------------------------------------

# Approximate expected base clock (GHz) for common CPU families
EXPECTED_CPU_BASE_GHZ: Dict[str, Tuple[float, float]] = {
    "i3":  (1.6, 3.6),
    "i5":  (1.6, 4.5),
    "i7":  (1.8, 5.5),
    "i9":  (2.3, 5.8),
    "ryzen 3": (2.6, 4.5),
    "ryzen 5": (3.0, 5.0),
    "ryzen 7": (3.2, 5.2),
    "ryzen 9": (3.5, 5.7),
    "celeron": (1.1, 2.8),
    "pentium": (1.1, 3.2),
    "core m": (0.9, 2.2),
    "m1":  (3.2, 3.2),
    "m2":  (3.5, 3.5),
    "m3":  (4.0, 4.0),
}

# Memory speed expectations (MHz min/max for DDR4/DDR5)
MEMORY_SPEED_MIN_MHZ = 1600
MEMORY_SPEED_MAX_MHZ = 8400

# Suspicious placeholder serial numbers
SUSPICIOUS_SERIALS = frozenset({
    "none", "to be filled by o.e.m.", "default string",
    "00000000", "system serial number", "n/a", "na",
    "0000000000000000", "not specified",
})

# Common fake i7/i9 indicators (i3/Celeron rebadged)
FAKE_INTEL_PATTERNS = [
    (r"core.{0,5}i[789]", r"core.{0,5}i3|celeron|pentium"),  # name says i7 but CPUID is i3
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise(s: str) -> str:
    return s.strip().lower()


def _cpu_tier(model_name: str) -> Optional[str]:
    """Return the CPU tier string ('i3', 'i7', 'ryzen 5', etc.) if detectable."""
    n = model_name.lower()
    for tier in EXPECTED_CPU_BASE_GHZ:
        if tier in n:
            return tier
    return None


def _mhz_to_ghz(mhz: float) -> float:
    return round(mhz / 1000.0, 2)


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------

def _check_cpu_authenticity(cpu: Dict[str, Any]) -> List[str]:
    """Check CPU model name against reported clock speeds."""
    flags: List[str] = []
    model = cpu.get("model_name", "")
    if not model:
        flags.append("CPU model name not reported — cannot verify authenticity")
        return flags

    tier = _cpu_tier(model)
    max_mhz = cpu.get("max_mhz", 0) or cpu.get("current_mhz", 0)
    if tier and max_mhz:
        lo, hi = EXPECTED_CPU_BASE_GHZ[tier]
        max_ghz = _mhz_to_ghz(max_mhz)
        if max_ghz < lo * 0.8:
            flags.append(
                f"CPU clock speed suspiciously low for {tier.upper()}: "
                f"{max_ghz} GHz (expected ≥ {lo} GHz) — possible rebadge or throttled chip"
            )
        if max_ghz > hi * 1.2:
            flags.append(
                f"CPU clock speed unusually high for {tier.upper()}: "
                f"{max_ghz} GHz (expected ≤ {hi} GHz) — BIOS may be reporting inflated values"
            )

    # VM / hypervisor masking
    if cpu.get("vm_detected"):
        flags.append(
            "Hypervisor / VM detected — hardware specs may be virtualised and not representative of physical hardware"
        )

    # Logical vs physical core sanity
    logical = cpu.get("logical_cpus", 0)
    physical = cpu.get("cores_per_socket", 0)
    if logical and physical and logical < physical:
        flags.append(
            f"Logical CPU count ({logical}) is less than physical cores ({physical}) — CPU may be partially disabled"
        )

    return flags


def _check_memory_authenticity(memory: Dict[str, Any]) -> List[str]:
    """Check RAM capacity and speed plausibility."""
    flags: List[str] = []
    total_gb = memory.get("total_gb", 0)

    # RAM not a power of 2 is unusual (but not impossible with dual-channel odd configs)
    if total_gb and total_gb > 0:
        # Sanity: reported RAM should be plausible for a laptop
        if total_gb < 1:
            flags.append(f"RAM extremely low: {total_gb:.2f} GB — almost certainly incorrect")
        elif total_gb > 512:
            flags.append(f"RAM appears inflated: {total_gb:.0f} GB — unlikely for a laptop")

    # DIMM speed check
    for dimm in memory.get("dimm_details", []):
        speed_raw = str(dimm.get("speed_mhz", "")).replace(" MT/s", "").replace(" MHz", "").strip()
        try:
            speed = float(speed_raw)
            if speed < MEMORY_SPEED_MIN_MHZ:
                flags.append(f"Unusually slow RAM ({speed} MHz) — check DIMM compatibility or BIOS settings")
        except (ValueError, TypeError):
            pass

    return flags


def _check_serial_numbers(motherboard: Dict[str, Any]) -> List[str]:
    """Check motherboard/product serial numbers for placeholder or suspicious values."""
    flags: List[str] = []

    for field in ("product_serial", "serial", "bios_version"):
        val = _normalise(motherboard.get(field, "") or "")
        if val in SUSPICIOUS_SERIALS:
            flags.append(
                f"Motherboard {field} is a placeholder value ('{val}') — "
                "may indicate BIOS tampering or OEM unlock"
            )
            break  # One flag is enough for serial issues

    if motherboard.get("serial_suspicious"):
        flags.append(
            "System serial number is blank or a generic placeholder — "
            "common on stolen or refurbished devices with cleared serials"
        )

    return flags


def _check_storage_consistency(storage: Dict[str, Any]) -> List[str]:
    """Check storage reported capacity against plausible ranges."""
    flags: List[str] = []
    for drive in storage.get("drives", []):
        cap_gb = drive.get("capacity_gb", 0)
        model = drive.get("model", "unknown")
        if cap_gb and cap_gb > 0:
            # Capacities that don't match standard flash sizes (e.g., 29 GB labelled as 256 GB)
            standard_sizes = [16, 32, 64, 120, 128, 240, 256, 480, 500, 512, 960, 1000, 1024, 2000, 2048, 4000, 8000]
            closest = min(standard_sizes, key=lambda x: abs(x - cap_gb))
            deviation_pct = abs(cap_gb - closest) / closest * 100 if closest else 0
            # More than 15% off a standard size could indicate a fake drive
            if deviation_pct > 15 and cap_gb < closest:
                flags.append(
                    f"Drive capacity {cap_gb:.0f} GB deviates >15% from nearest standard size "
                    f"({closest} GB) — possible fake or relabelled storage: {model}"
                )
        # SMART pre-failure indicators
        for sf in drive.get("smart_flags", []):
            flags.append(f"SMART warning on {model}: {sf}")
        if drive.get("health") == "FAILED":
            flags.append(f"Drive FAILED SMART self-test: {model} — do not buy")

    return flags


def _check_battery_consistency(battery: Dict[str, Any]) -> List[str]:
    """Cross-check battery health flags."""
    flags: List[str] = []
    if not battery.get("present", True):
        return flags
    for f in battery.get("flags", []):
        flags.append(f)
    return flags


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check(
    hardware: Dict[str, Any],
    battery: Dict[str, Any],
    storage: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Run all integrity checks across hardware, battery, and storage data.

    Args:
        hardware: Output from collector_linux or collector_windows.
        battery:  Output from battery_check.
        storage:  Output from storage_check.

    Returns:
        Dict with a combined list of flags and a pass/fail summary per area.
    """
    flags: List[str] = []
    summary: Dict[str, str] = {}

    # ── CPU ─────────────────────────────────────────────────────────────
    cpu = hardware.get("cpu", {})
    cpu_flags = _check_cpu_authenticity(cpu)
    flags.extend(cpu_flags)
    summary["cpu"] = "WARNING" if cpu_flags else "PASS"

    # ── Memory ──────────────────────────────────────────────────────────
    memory = hardware.get("memory", {})
    mem_flags = _check_memory_authenticity(memory)
    flags.extend(mem_flags)
    summary["memory"] = "WARNING" if mem_flags else "PASS"

    # ── Motherboard / Serial ─────────────────────────────────────────────
    mb = hardware.get("motherboard", {})
    serial_flags = _check_serial_numbers(mb)
    flags.extend(serial_flags)
    summary["serials"] = "WARNING" if serial_flags else "PASS"

    # ── Storage ──────────────────────────────────────────────────────────
    sto_flags = _check_storage_consistency(storage)
    flags.extend(sto_flags)
    summary["storage"] = "FAIL" if any("FAILED" in f or "do not buy" in f.lower() for f in sto_flags) \
        else "WARNING" if sto_flags else "PASS"

    # ── Battery ──────────────────────────────────────────────────────────
    bat_flags = _check_battery_consistency(battery)
    flags.extend(bat_flags)
    summary["battery"] = "WARNING" if bat_flags else "PASS"

    # ── USB history ──────────────────────────────────────────────────────
    usb_flags = hardware.get("usb", {}).get("flags", [])
    flags.extend(usb_flags)
    summary["usb"] = "WARNING" if usb_flags else "PASS"

    return {
        "flags": flags,
        "summary": summary,
        "total_issues": len(flags),
        "module_status": "ok",
    }


if __name__ == "__main__":
    import json
    # Simple smoke test with empty data
    print(json.dumps(check({}, {}, {}), indent=2))
