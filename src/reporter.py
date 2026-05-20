#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
reporter.py — HTML report generator.

Produces a single, fully self-contained HTML file with embedded CSS, JS,
and Canvas-based charts.  No external dependencies — the file renders
identically offline.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)

TEMPLATE_PATH = Path(__file__).parent.parent / "templates" / "report_template.html"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_template() -> str:
    """Load the HTML template from disk."""
    try:
        return TEMPLATE_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        logger.error("Cannot read report template: %s", exc)
        raise


def _safe_json(obj: Any) -> str:
    """Serialise to JSON safely, converting non-serialisable objects to strings."""
    return json.dumps(obj, default=str, ensure_ascii=False, indent=2)


def _verdict_color(verdict: str) -> str:
    return {"TRUSTWORTHY": "#22c55e", "CAUTION": "#f59e0b", "DO NOT BUY": "#ef4444"}.get(verdict, "#94a3b8")


def _severity_badge(severity: str) -> str:
    colors = {"critical": "#ef4444", "warning": "#f59e0b", "info": "#60a5fa", "ok": "#22c55e"}
    return colors.get(severity, "#94a3b8")


def _build_replacements(results: Dict[str, Any]) -> Dict[str, str]:
    """Build the template substitution dict from scan results."""
    score_data = results.get("score", {})
    hw = results.get("hardware", {})
    battery = results.get("battery", {})
    storage = results.get("storage", {})
    thermal = results.get("thermal", {})
    stress = results.get("stress", {})
    security = results.get("security", {})
    integrity = results.get("integrity", {})

    final_score = score_data.get("final_score", 0)
    verdict = score_data.get("verdict", "UNKNOWN")
    verdict_color = _verdict_color(verdict)
    category_scores = score_data.get("category_scores", {})
    all_flags = score_data.get("all_flags", [])

    cpu = hw.get("cpu", {})
    memory = hw.get("memory", {})
    mb = hw.get("motherboard", {})
    gpus = hw.get("gpu", [])

    scan_time = results.get("scan_timestamp", datetime.now().isoformat())
    try:
        dt = datetime.fromisoformat(scan_time)
        scan_time_fmt = dt.strftime("%B %d, %Y at %H:%M:%S")
    except ValueError:
        scan_time_fmt = scan_time

    # ── Hardware identity rows ─────────────────────────────────────────
    def hw_row(label: str, value: str, ok: bool = True) -> str:
        icon = "✓" if ok else "✗"
        cls = "check-ok" if ok else "check-fail"
        return f'<tr><td>{label}</td><td class="{cls}">{icon} {value}</td></tr>'

    hw_rows = ""
    model_name = cpu.get("model_name", "Unknown")
    hw_rows += hw_row("CPU Model", model_name)
    cores = cpu.get("cores_per_socket", 0)
    logical = cpu.get("logical_cpus", 0)
    hw_rows += hw_row("CPU Cores / Threads", f"{cores} cores / {logical} threads")
    max_ghz = round(cpu.get("max_mhz", 0) / 1000, 2) if cpu.get("max_mhz") else 0
    hw_rows += hw_row("CPU Max Clock", f"{max_ghz} GHz" if max_ghz else "Unknown")
    hw_rows += hw_row("VM Masking", "Detected — specs may be virtualised" if cpu.get("vm_detected") else "Not detected", not cpu.get("vm_detected"))
    total_ram = memory.get("total_gb", 0)
    hw_rows += hw_row("Total RAM", f"{total_ram:.1f} GB" if total_ram else "Unknown")
    hw_rows += hw_row("Board Vendor", mb.get("vendor") or mb.get("sys_vendor") or "Unknown")
    hw_rows += hw_row("Product Serial", mb.get("product_serial", "N/A"), not mb.get("serial_suspicious", False))
    gpu_names = ", ".join(g.get("model") or g.get("vendor", "Unknown") for g in gpus) or "Unknown"
    hw_rows += hw_row("GPU(s)", gpu_names)

    # ── Storage rows ───────────────────────────────────────────────────
    storage_rows = ""
    for drive in storage.get("drives", []):
        health = drive.get("health", "UNKNOWN")
        ok = health == "PASSED"
        model = drive.get("model", drive.get("device", "Unknown"))
        cap = f"{drive.get('capacity_gb', 0):.0f} GB"
        storage_rows += hw_row(f"Drive: {model}", f"{cap} — {health}", ok)

    # ── Security findings ──────────────────────────────────────────────
    sec_findings_html = ""
    for finding in security.get("findings", []):
        color = _severity_badge(finding.get("severity", "info"))
        badge = f'<span class="badge" style="background:{color}">{finding.get("severity","info").upper()}</span>'
        desc = finding.get("description", "")
        detail = finding.get("detail", "")
        detail_html = f'<div class="finding-detail">{detail}</div>' if detail else ""
        sec_findings_html += f'<div class="finding">{badge} {desc}{detail_html}</div>'

    if not sec_findings_html:
        sec_findings_html = '<div class="finding clean">✓ No security concerns detected</div>'

    # ── Recommendations ────────────────────────────────────────────────
    recs = []
    if verdict == "DO NOT BUY":
        recs.append(("critical", "Do not purchase this device without resolving the critical issues below."))
    if cpu.get("vm_detected"):
        recs.append(("critical", "VM masking detected — require physical inspection or system wipe before purchase."))
    bat_health = battery.get("health_pct", 100)
    if bat_health is not None and bat_health < 50:
        recs.append(("critical", f"Replace battery immediately — only {bat_health:.0f}% of original capacity remains."))
    elif bat_health is not None and bat_health < 70:
        recs.append(("warning", f"Budget for battery replacement — {bat_health:.0f}% health."))
    for drive in storage.get("drives", []):
        if drive.get("health") == "FAILED":
            recs.append(("critical", f"Drive {drive.get('model','Unknown')} is failing — replace immediately before use."))
        elif drive.get("health") == "WARNING":
            recs.append(("warning", f"Drive {drive.get('model','Unknown')} has SMART warnings — monitor closely."))
    throttle = stress.get("cpu", {}).get("cpu_throttle_pct", 0) if stress.get("module_status") == "ok" else 0
    if throttle >= 20:
        recs.append(("warning", f"CPU throttles {throttle:.0f}% under load — clean vents and replace thermal paste."))
    if mb.get("serial_suspicious"):
        recs.append(("warning", "Serial number is missing — request proof of purchase and verify device history."))
    if not recs:
        recs.append(("ok", "No critical recommendations. Device appears to be in acceptable condition."))

    recs_html = ""
    colors_map = {"critical": "#ef4444", "warning": "#f59e0b", "ok": "#22c55e"}
    for severity, text in recs:
        c = colors_map.get(severity, "#94a3b8")
        recs_html += f'<div class="rec-item" style="border-left:4px solid {c}">{text}</div>'

    # ── Flags list ─────────────────────────────────────────────────────
    flags_html = ""
    for flag in all_flags[:30]:
        flags_html += f'<li class="flag-item">{flag}</li>'
    if not flags_html:
        flags_html = '<li class="flag-ok">No issues detected</li>'

    # ── Category score bars ────────────────────────────────────────────
    cat_labels = {
        "hardware_authenticity": "Hardware Authenticity",
        "thermal":               "Thermal Health",
        "battery":               "Battery Health",
        "storage":               "Storage Health",
        "stress":                "Performance Under Load",
        "security":              "Security Posture",
        "usb_peripheral":        "Peripheral Status",
    }
    score_bars_html = ""
    for cat, label in cat_labels.items():
        s = category_scores.get(cat, 75)
        bar_color = "#22c55e" if s >= 80 else "#f59e0b" if s >= 50 else "#ef4444"
        score_bars_html += f"""
        <div class="score-bar-row">
            <div class="score-bar-label">{label}</div>
            <div class="score-bar-outer">
                <div class="score-bar-inner" style="width:{s}%;background:{bar_color}"></div>
            </div>
            <div class="score-bar-value">{s:.0f}</div>
        </div>"""

    return {
        "{{TITLE}}": f"SpecterScan Report — {scan_time_fmt}",
        "{{SCAN_TIME}}": scan_time_fmt,
        "{{PLATFORM}}": results.get("platform", "Unknown"),
        "{{ELEVATED}}": "Yes (elevated)" if results.get("elevated") else "No (limited scan)",
        "{{FINAL_SCORE}}": str(int(final_score)),
        "{{VERDICT}}": verdict,
        "{{VERDICT_COLOR}}": verdict_color,
        "{{HW_ROWS}}": hw_rows,
        "{{STORAGE_ROWS}}": storage_rows,
        "{{SEC_FINDINGS}}": sec_findings_html,
        "{{RECS}}": recs_html,
        "{{FLAGS_LIST}}": flags_html,
        "{{SCORE_BARS}}": score_bars_html,
        "{{CPU_MODEL}}": model_name,
        "{{RAM_GB}}": f"{total_ram:.1f}",
        "{{BATTERY_HEALTH}}": str(int(battery.get("health_pct") or 0)),
        "{{BATTERY_PRESENT}}": "true" if battery.get("present") else "false",
        "{{STORAGE_SCORE}}": str(int(category_scores.get("storage", 75))),
        "{{TEMP_SAMPLES_JSON}}": _safe_json(thermal.get("all_sensors", [])),
        "{{STRESS_TEMP_JSON}}": _safe_json(stress.get("cpu", {}).get("temp_samples", []) if stress.get("module_status") == "ok" else []),
        "{{CATEGORY_SCORES_JSON}}": _safe_json(category_scores),
        "{{RAW_DATA_JSON}}": _safe_json(results),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_report(results: Dict[str, Any], output_path: str) -> Dict[str, Any]:
    """
    Render the HTML report template with scan results and write it to disk.

    Args:
        results:     Combined scan results dict.
        output_path: Absolute path for the output HTML file.

    Returns:
        Dict with module_status and report_path.
    """
    try:
        template = _load_template()
    except OSError as exc:
        return {"module_status": "error", "reason": str(exc)}

    try:
        replacements = _build_replacements(results)
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Failed to build report replacements: %s", exc)
        return {"module_status": "error", "reason": f"Template build error: {exc}"}

    html = template
    for placeholder, value in replacements.items():
        html = html.replace(placeholder, value)

    try:
        Path(output_path).write_text(html, encoding="utf-8")
    except OSError as exc:
        return {"module_status": "error", "reason": f"Cannot write report: {exc}"}

    logger.info("Report written to %s", output_path)
    return {
        "module_status": "ok",
        "report_path": output_path,
        "size_bytes": len(html.encode("utf-8")),
    }


if __name__ == "__main__":
    # Quick smoke test — generate report with empty data
    import json as _json, sys
    test_results: Dict[str, Any] = {
        "scan_timestamp": datetime.now().isoformat(),
        "platform": "Linux",
        "elevated": False,
        "hardware": {"cpu": {"model_name": "Test CPU"}, "memory": {"total_gb": 8}, "motherboard": {}, "gpu": [], "usb": {"flags": []}},
        "battery": {"present": False},
        "storage": {"drives": [], "flags": []},
        "thermal": {"flags": [], "severity": "ok", "all_sensors": []},
        "stress": {"module_status": "skipped"},
        "security": {"findings": []},
        "integrity": {"flags": []},
        "score": {"final_score": 82, "verdict": "TRUSTWORTHY", "category_scores": {}, "all_flags": []},
    }
    out = generate_report(test_results, "/tmp/specterscan_test.html")
    print(_json.dumps(out, indent=2))
