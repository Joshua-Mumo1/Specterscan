#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scoring.py — Weighted trust score engine.

Aggregates results from all diagnostic modules into a single 0-100
trust score and assigns a human-readable verdict.

Weights:
    Hardware Authenticity:    25%
    Thermal Health:           20%
    Battery Health:           15%
    Storage Health:           15%
    Performance Under Load:   10%
    Security Posture:         10%
    Peripheral / USB Status:   5%
"""

import logging
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Weight table (must sum to 1.0)
# ---------------------------------------------------------------------------
WEIGHTS: Dict[str, float] = {
    "hardware_authenticity": 0.25,
    "thermal":               0.20,
    "battery":               0.15,
    "storage":               0.15,
    "stress":                0.10,
    "security":              0.10,
    "usb_peripheral":        0.05,
}

# Verdict thresholds
TRUSTWORTHY_MIN = 80
CAUTION_MIN = 50


# ---------------------------------------------------------------------------
# Per-category scorers
# ---------------------------------------------------------------------------

def _score_hardware_authenticity(results: Dict[str, Any]) -> Tuple[float, List[str]]:
    """Score based on integrity check flags and VM detection."""
    flags_all: List[str] = []
    score = 100.0

    integrity = results.get("integrity", {})
    integ_flags = integrity.get("flags", [])
    flags_all.extend(integ_flags)

    # Deduct per flag, severity based on content
    for flag in integ_flags:
        fl = flag.lower()
        if any(kw in fl for kw in ("failed", "do not buy", "fake capacity", "rebadge", "vm detected")):
            score -= 25
        elif any(kw in fl for kw in ("suspicious", "tampering", "placeholder", "stolen", "cleared")):
            score -= 15
        elif any(kw in fl for kw in ("warning", "unusual", "inflated", "mismatch")):
            score -= 8
        else:
            score -= 4

    # VM detection is a strong signal
    hw = results.get("hardware", {})
    if hw.get("cpu", {}).get("vm_detected"):
        score -= 20
        flags_all.append("VM/hypervisor masking detected — physical hardware cannot be verified")

    return max(0.0, score), flags_all


def _score_thermal(results: Dict[str, Any]) -> Tuple[float, List[str]]:
    """Score based on thermal analysis."""
    thermal = results.get("thermal", {})
    flags = thermal.get("flags", [])
    severity = thermal.get("severity", "unknown")

    if severity == "ok":
        score = 100.0
    elif severity == "warning":
        score = 60.0
    elif severity == "critical":
        score = 20.0
    else:
        score = 75.0  # unknown — partial deduction

    # Stress thermal data (throttling, rapid ramp)
    stress = results.get("stress", {})
    if stress.get("module_status") == "ok":
        cpu_stress = stress.get("cpu", {})
        throttle = cpu_stress.get("cpu_throttle_pct", 0)
        temp_rise = cpu_stress.get("temp_rise_c", 0) or 0
        if throttle >= 30:
            score -= 25
        elif throttle >= 10:
            score -= 10
        if temp_rise >= 30:
            score -= 15
        elif temp_rise >= 20:
            score -= 5

    return max(0.0, score), flags + stress.get("flags", []) if stress.get("module_status") == "ok" else flags


def _score_battery(results: Dict[str, Any]) -> Tuple[float, List[str]]:
    """Score based on battery health."""
    battery = results.get("battery", {})
    flags = battery.get("flags", [])

    if not battery.get("present", True):
        return 75.0, []  # Desktop — neutral score

    health = battery.get("health_pct")
    if health is None:
        return 60.0, flags

    if health >= 80:
        score = 100.0
    elif health >= 70:
        score = 80.0
    elif health >= 50:
        score = 50.0
    else:
        score = 20.0

    if battery.get("non_oem_suspected"):
        score -= 15

    cycles = battery.get("cycle_count") or battery.get("cycle_count_estimate", 0)
    if cycles and cycles > 800:
        score -= 10

    return max(0.0, score), flags


def _score_storage(results: Dict[str, Any]) -> Tuple[float, List[str]]:
    """Score based on storage health."""
    storage = results.get("storage", {})
    flags = storage.get("flags", [])
    drives = storage.get("drives", [])

    if not drives:
        return 70.0, flags  # Couldn't check

    score = 100.0
    for drive in drives:
        health = drive.get("health", "UNKNOWN")
        if health == "FAILED":
            score -= 60
        elif health == "WARNING":
            score -= 25
        # SMART critical attributes
        smart = drive.get("critical_smart", {})
        if smart.get("Reallocated_Sector_Ct", 0) > 0:
            score -= 20
        if smart.get("Current_Pending_Sector", 0) > 0:
            score -= 15
        if smart.get("Offline_Uncorrectable", 0) > 0:
            score -= 15
        # Fake capacity
        if drive.get("fake_capacity_check", {}).get("verdict") == "FAIL":
            score -= 50

    return max(0.0, score), flags


def _score_stress(results: Dict[str, Any]) -> Tuple[float, List[str]]:
    """Score based on stress test results."""
    stress = results.get("stress", {})
    flags = stress.get("flags", [])

    if stress.get("module_status") == "skipped":
        return 75.0, []  # Neutral if skipped

    score = 100.0
    mem = stress.get("memory", {})
    disk = stress.get("disk", {})
    cpu = stress.get("cpu", {})

    if mem.get("errors_detected", 0) > 0:
        score -= 40
    if mem.get("oom_event"):
        score -= 20
    if disk.get("verify_errors", 0) > 0:
        score -= 35
    if disk.get("very_slow_flag"):
        score -= 15
    throttle = cpu.get("cpu_throttle_pct", 0)
    if throttle >= 30:
        score -= 20
    elif throttle >= 15:
        score -= 10

    return max(0.0, score), flags


def _score_security(results: Dict[str, Any]) -> Tuple[float, List[str]]:
    """Score based on security scan findings."""
    security = results.get("security", {})
    findings = security.get("findings", [])
    flags = [f["description"] for f in findings]

    score = 100.0
    for finding in findings:
        sev = finding.get("severity", "info")
        if sev == "critical":
            score -= 30
        elif sev == "warning":
            score -= 10
        else:
            score -= 2

    return max(0.0, score), flags


def _score_usb(results: Dict[str, Any]) -> Tuple[float, List[str]]:
    """Score based on USB/peripheral health."""
    hw = results.get("hardware", {})
    usb = hw.get("usb", {})
    usb_flags = usb.get("flags", [])
    score = 100.0
    for flag in usb_flags:
        fl = flag.lower()
        if "killer" in fl or "surge" in fl or "power anomaly" in fl:
            score -= 40
        elif "unidentified" in fl or "suspicious" in fl:
            score -= 15
        else:
            score -= 5
    return max(0.0, score), usb_flags


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_score(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute a weighted trust score from all diagnostic module results.

    Args:
        results: Combined results dict from the main orchestrator.

    Returns:
        Dict with final_score, verdict, category_scores, and all_flags.
    """
    scorers = {
        "hardware_authenticity": _score_hardware_authenticity,
        "thermal":               _score_thermal,
        "battery":               _score_battery,
        "storage":               _score_storage,
        "stress":                _score_stress,
        "security":              _score_security,
        "usb_peripheral":        _score_usb,
    }

    category_scores: Dict[str, float] = {}
    all_flags: List[str] = []

    for category, scorer in scorers.items():
        raw_score, flags = scorer(results)
        clamped = max(0.0, min(100.0, raw_score))
        category_scores[category] = round(clamped, 1)
        all_flags.extend(flags)

    # Weighted average
    final_score = sum(
        category_scores[cat] * weight
        for cat, weight in WEIGHTS.items()
    )
    final_score = round(max(0.0, min(100.0, final_score)), 1)

    # Verdict
    if final_score >= TRUSTWORTHY_MIN:
        verdict = "TRUSTWORTHY"
    elif final_score >= CAUTION_MIN:
        verdict = "CAUTION"
    else:
        verdict = "DO NOT BUY"

    # Deduplicate flags while preserving order
    seen: set = set()
    deduped_flags: List[str] = []
    for f in all_flags:
        if f not in seen:
            seen.add(f)
            deduped_flags.append(f)

    return {
        "final_score": final_score,
        "verdict": verdict,
        "category_scores": category_scores,
        "weights": WEIGHTS,
        "all_flags": deduped_flags,
        "module_status": "ok",
    }


if __name__ == "__main__":
    import json
    sample = {"integrity": {"flags": []}, "thermal": {"severity": "ok", "flags": []}}
    print(json.dumps(compute_score(sample), indent=2))
