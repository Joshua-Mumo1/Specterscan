#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SpecterScan — Hardware Diagnostic & Trust Verification Tool
============================================================
Entry point. Orchestrates all collection, analysis, and reporting modules.

Usage:
    Linux:   sudo python3 run.py [--quick] [--no-stress]
    Windows: Run as Administrator — python run.py [--quick] [--no-stress]

Exit codes:
    0 — TRUSTWORTHY
    1 — CAUTION
    2 — DO NOT BUY
    3 — Fatal error
"""

import argparse
import logging
import os
import platform
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

# ---------------------------------------------------------------------------
# Bootstrap: ensure src/ is importable regardless of working directory
# ---------------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = ROOT_DIR / "src"
sys.path.insert(0, str(ROOT_DIR))

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
logging.basicConfig(level=logging.WARNING, format=LOG_FORMAT)
logger = logging.getLogger("specterscan")

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
CYAN = "\033[36m"
WHITE = "\033[37m"
DIM = "\033[2m"


def _supports_color() -> bool:
    """Return True if the terminal likely supports ANSI colour codes."""
    if platform.system() == "Windows":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


USE_COLOR = _supports_color()


def cprint(text: str, color: str = "", bold: bool = False) -> None:
    """Print coloured text, falling back to plain text when unsupported."""
    if USE_COLOR:
        prefix = (BOLD if bold else "") + color
        print(f"{prefix}{text}{RESET}")
    else:
        print(text)


def print_banner() -> None:
    """Print the SpecterScan ASCII banner."""
    banner = r"""
  ____  ____  ____  ___  ____  ____  ____  ___    __    _  _ 
 / ___)(  _ \(  __)/ __)(_  _)(  __)(  _ \/ __)  / _\  ( \/ )
 \___ \ ) __/ ) _)( (__   )(   ) _)  )   /\__ \ /    \  )  ( 
 (____/(__)  (____)\___) (__) (____)(__)  (____/ \_/\_/ (_/\_)
"""
    cprint(banner, CYAN, bold=True)
    cprint("  Hardware Diagnostic & Trust Verification Tool  v1.0.0", WHITE, bold=True)
    cprint("  ─────────────────────────────────────────────────────", DIM)
    print()


def print_section(title: str) -> None:
    """Print a styled section header."""
    width = 56
    cprint(f"\n  ┌{'─' * width}┐", CYAN)
    cprint(f"  │  {title:<{width - 2}}│", CYAN)
    cprint(f"  └{'─' * width}┘", CYAN)


def print_progress(step: int, total: int, label: str) -> None:
    """Print a simple progress line."""
    bar_width = 30
    filled = int(bar_width * step / total)
    bar = "█" * filled + "░" * (bar_width - filled)
    pct = int(100 * step / total)
    line = f"  [{bar}] {pct:3d}%  {label}"
    if USE_COLOR:
        sys.stdout.write(f"\r{CYAN}{line}{RESET}")
    else:
        sys.stdout.write(f"\r{line}")
    sys.stdout.flush()
    if step == total:
        print()


def check_privileges() -> bool:
    """Return True if the process has elevated privileges."""
    system = platform.system()
    if system == "Linux" or system == "Darwin":
        return os.geteuid() == 0
    elif system == "Windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    return False


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="specterscan",
        description="SpecterScan — Hardware Diagnostic & Trust Verification Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 run.py               # Full scan
  sudo python3 run.py --quick       # Skip stress tests (faster)
  sudo python3 run.py --no-stress   # Collect data but skip load tests
  sudo python3 run.py --output /tmp # Save report to /tmp/
  sudo python3 run.py --debug       # Enable verbose logging
        """,
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick scan — skip long-running stress tests",
    )
    parser.add_argument(
        "--no-stress",
        action="store_true",
        help="Skip all stress tests (same as --quick)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path.cwd(),
        help="Directory for the HTML report (default: current directory)",
    )
    parser.add_argument(
        "--stress-duration",
        type=int,
        default=30,
        metavar="SECONDS",
        help="Duration of each stress test in seconds (default: 30)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args()


def run_module(name: str, func, *args, **kwargs) -> Dict[str, Any]:
    """
    Run a diagnostic module with error isolation.

    Returns the module result dict, or an error dict if it raises.
    """
    try:
        result = func(*args, **kwargs)
        if not isinstance(result, dict):
            result = {"data": result}
        result.setdefault("module_status", "ok")
        return result
    except PermissionError as exc:
        logger.warning("Module %s skipped — insufficient permissions: %s", name, exc)
        return {"module_status": "skipped", "reason": f"Permission denied: {exc}"}
    except FileNotFoundError as exc:
        logger.warning("Module %s skipped — file not found: %s", name, exc)
        return {"module_status": "skipped", "reason": f"Not found: {exc}"}
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Module %s failed: %s", name, exc)
        return {"module_status": "error", "reason": str(exc)}


def main() -> int:
    """
    Main orchestrator.

    Returns an exit code reflecting the trust verdict.
    """
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    skip_stress = args.quick or args.no_stress
    stress_duration = args.stress_duration
    output_dir = args.output
    output_dir.mkdir(parents=True, exist_ok=True)

    print_banner()

    # ── Privilege check ────────────────────────────────────────────────────
    if not check_privileges():
        cprint(
            "  ⚠  WARNING: Not running with elevated privileges.\n"
            "     Some checks will be skipped or may show incomplete data.\n"
            "     Re-run with:  sudo python3 run.py  (Linux/macOS)\n"
            "                   Run as Administrator  (Windows)\n",
            YELLOW,
        )

    system = platform.system()
    cprint(f"  Detected OS: {system} {platform.release()}", DIM)
    cprint(f"  Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", DIM)
    if skip_stress:
        cprint("  Mode: Quick scan (stress tests disabled)", YELLOW)
    else:
        cprint(f"  Mode: Full scan (stress duration: {stress_duration}s per test)", DIM)
    print()

    # ── Lazy imports (keep startup fast) ──────────────────────────────────
    from src.collector_linux import collect as collect_linux
    from src.collector_windows import collect as collect_windows
    from src.battery_check import check as check_battery
    from src.storage_check import check as check_storage
    from src.thermal_check import check as check_thermal
    from src.stress_test import run_stress as run_stress_test
    from src.integrity_check import check as check_integrity
    from src.security_scan import scan as scan_security
    from src.scoring import compute_score
    from src.reporter import generate_report

    results: Dict[str, Any] = {
        "scan_timestamp": datetime.now().isoformat(),
        "platform": system,
        "elevated": check_privileges(),
    }

    # Define pipeline steps (name, callable, *extra_args)
    steps = [
        ("Hardware Collection", "hardware"),
        ("Battery Analysis", "battery"),
        ("Storage Health", "storage"),
        ("Thermal Analysis", "thermal"),
        ("Stress Testing", "stress"),
        ("Integrity Checks", "integrity"),
        ("Security Scan", "security"),
        ("Scoring", "score"),
        ("Report Generation", "report"),
    ]
    total_steps = len(steps)

    # ── 1. Hardware Collection ─────────────────────────────────────────────
    print_section("Step 1 / 9 — Hardware Collection")
    print_progress(0, 4, "Collecting CPU info …")
    if system == "Linux" or system == "Darwin":
        hw = run_module("collector_linux", collect_linux)
    else:
        hw = run_module("collector_windows", collect_windows)
    results["hardware"] = hw
    print_progress(4, 4, "Hardware collection complete")

    # ── 2. Battery Analysis ────────────────────────────────────────────────
    print_section("Step 2 / 9 — Battery Analysis")
    bat = run_module("battery_check", check_battery)
    results["battery"] = bat
    status = bat.get("module_status", "ok")
    if status == "ok":
        health = bat.get("health_pct", 0)
        color = GREEN if health >= 70 else YELLOW if health >= 50 else RED
        cprint(f"  Battery health: {health:.1f}%", color)
    else:
        cprint(f"  Battery: {bat.get('reason', 'unavailable')}", YELLOW)

    # ── 3. Storage Health ──────────────────────────────────────────────────
    print_section("Step 3 / 9 — Storage Health")
    sto = run_module("storage_check", check_storage)
    results["storage"] = sto
    if sto.get("module_status") == "ok":
        drives = sto.get("drives", [])
        cprint(f"  Found {len(drives)} drive(s)", DIM)
        for d in drives:
            flag = "✓" if d.get("health") == "PASSED" else "✗"
            color = GREEN if flag == "✓" else RED
            cprint(f"    {flag} {d.get('model', 'Unknown')}  —  {d.get('health', '?')}", color)

    # ── 4. Thermal Analysis ────────────────────────────────────────────────
    print_section("Step 4 / 9 — Thermal Analysis")
    therm = run_module("thermal_check", check_thermal)
    results["thermal"] = therm
    if therm.get("module_status") == "ok":
        cpu_temp = therm.get("cpu_temp_c")
        if cpu_temp is not None:
            color = GREEN if cpu_temp < 70 else YELLOW if cpu_temp < 85 else RED
            cprint(f"  CPU temperature: {cpu_temp:.1f} °C", color)

    # ── 5. Stress Testing ──────────────────────────────────────────────────
    print_section("Step 5 / 9 — Stress Testing")
    if skip_stress:
        cprint("  Stress tests skipped (--quick mode)", YELLOW)
        stress = {"module_status": "skipped", "reason": "Quick mode enabled"}
    else:
        cprint(f"  Running {stress_duration}s CPU + memory + disk stress …", DIM)
        stress = run_module("stress_test", run_stress_test, duration=stress_duration)
        if stress.get("module_status") == "ok":
            throttle = stress.get("cpu_throttle_pct", 0)
            color = GREEN if throttle < 10 else YELLOW if throttle < 30 else RED
            cprint(f"  CPU throttle during load: {throttle:.1f}%", color)
    results["stress"] = stress

    # ── 6. Integrity Checks ────────────────────────────────────────────────
    print_section("Step 6 / 9 — Integrity Checks")
    integ = run_module(
        "integrity_check",
        check_integrity,
        hardware=results["hardware"],
        battery=results["battery"],
        storage=results["storage"],
    )
    results["integrity"] = integ
    flags = integ.get("flags", [])
    if flags:
        cprint(f"  ⚠  {len(flags)} integrity flag(s) found:", YELLOW)
        for f in flags[:5]:
            cprint(f"    • {f}", YELLOW)
    else:
        cprint("  ✓  No integrity issues detected", GREEN)

    # ── 7. Security Scan ───────────────────────────────────────────────────
    print_section("Step 7 / 9 — Security Scan")
    sec = run_module("security_scan", scan_security)
    results["security"] = sec
    if sec.get("module_status") == "ok":
        findings = sec.get("findings", [])
        critical = [f for f in findings if f.get("severity") == "critical"]
        warnings = [f for f in findings if f.get("severity") == "warning"]
        if critical:
            cprint(f"  ✗ {len(critical)} critical security finding(s)", RED)
        if warnings:
            cprint(f"  ⚠  {len(warnings)} security warning(s)", YELLOW)
        if not critical and not warnings:
            cprint("  ✓  No significant security concerns", GREEN)

    # ── 8. Scoring ─────────────────────────────────────────────────────────
    print_section("Step 8 / 9 — Scoring")
    score_result = run_module("scoring", compute_score, results)
    results["score"] = score_result
    final_score = score_result.get("final_score", 0)
    verdict = score_result.get("verdict", "UNKNOWN")
    if verdict == "TRUSTWORTHY":
        v_color = GREEN
    elif verdict == "CAUTION":
        v_color = YELLOW
    else:
        v_color = RED
    cprint(f"  Final score: {final_score:.0f} / 100", WHITE, bold=True)
    cprint(f"  Verdict:     {verdict}", v_color, bold=True)

    # ── 9. Report Generation ───────────────────────────────────────────────
    print_section("Step 9 / 9 — Generating Report")
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_path = output_dir / f"specterscan_report_{timestamp}.html"
    report_result = run_module("reporter", generate_report, results, str(report_path))
    results["report"] = report_result

    # ── Final summary ──────────────────────────────────────────────────────
    print()
    cprint("  ╔══════════════════════════════════════════════════════╗", v_color, bold=True)
    cprint(f"  ║  VERDICT: {verdict:<43}║", v_color, bold=True)
    cprint(f"  ║  SCORE:   {final_score:<3.0f} / 100{' ' * 38}║", v_color, bold=True)
    cprint("  ╚══════════════════════════════════════════════════════╝", v_color, bold=True)
    print()
    if report_result.get("module_status") == "ok":
        cprint(f"  Report saved to:\n  {report_path}", CYAN)
    else:
        cprint(f"  Report generation failed: {report_result.get('reason')}", RED)
    print()

    # Return exit code based on verdict
    exit_map = {"TRUSTWORTHY": 0, "CAUTION": 1, "DO NOT BUY": 2}
    return exit_map.get(verdict, 3)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        cprint("\n\n  Scan interrupted by user.", YELLOW)
        sys.exit(3)
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Fatal error: %s", exc)
        print(f"\n  FATAL: {exc}", file=sys.stderr)
        sys.exit(3)
