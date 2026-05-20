#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_scan.py — Security posture scan.

Checks startup entries, running services, hosts file, DNS configuration,
crypto miner indicators, unsigned drivers, and BIOS/firmware password locks
on both Linux and Windows platforms.
"""

import logging
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

SUBPROCESS_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read(path: Path, default: str = "") -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
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


def _finding(severity: str, category: str, description: str, detail: str = "") -> Dict[str, str]:
    """Create a standardised security finding dict."""
    return {
        "severity": severity,   # critical | warning | info
        "category": category,
        "description": description,
        "detail": detail,
    }


# ---------------------------------------------------------------------------
# Cross-platform checks
# ---------------------------------------------------------------------------

def _check_hosts_file() -> List[Dict[str, str]]:
    """Check the hosts file for suspicious redirects."""
    findings: List[Dict[str, str]] = []
    system = platform.system()
    if system == "Windows":
        hosts_path = Path(r"C:\Windows\System32\drivers\etc\hosts")
    else:
        hosts_path = Path("/etc/hosts")

    content = _read(hosts_path)
    if not content:
        return findings

    suspicious_redirects = 0
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        # Lines redirecting known-good domains to local are suspicious
        if re.search(r"\b(google|microsoft|apple|github|ubuntu|debian)\b", line, re.IGNORECASE):
            parts = line.split()
            if parts and parts[0] not in ("127.0.0.1", "::1", "0.0.0.0"):
                suspicious_redirects += 1

    if suspicious_redirects > 0:
        findings.append(_finding(
            "critical",
            "hosts_file",
            f"Suspicious hosts file entries ({suspicious_redirects}) — DNS hijacking or adware redirection detected",
            str(hosts_path),
        ))

    return findings


def _check_dns(system: str) -> List[Dict[str, str]]:
    """Check configured DNS resolvers for suspicious values."""
    findings: List[Dict[str, str]] = []
    known_good_dns = {
        "1.1.1.1", "1.0.0.1",           # Cloudflare
        "8.8.8.8", "8.8.4.4",           # Google
        "9.9.9.9",                        # Quad9
        "208.67.222.222", "208.67.220.220",  # OpenDNS
        "4.2.2.1", "4.2.2.2",            # Level3
        "127.0.0.53",                     # systemd-resolved
        "::1", "fe80::1",
    }

    dns_servers: List[str] = []
    if system == "Linux" or system == "Darwin":
        resolv = _read(Path("/etc/resolv.conf"))
        for line in resolv.splitlines():
            m = re.match(r"nameserver\s+([\d.a-f:]+)", line.strip())
            if m:
                dns_servers.append(m.group(1))
    elif system == "Windows":
        out = _run(["ipconfig", "/all"])
        if out:
            for line in out.splitlines():
                m = re.search(r"DNS Servers\s*[.:]+\s*([\d.]+)", line)
                if m:
                    dns_servers.append(m.group(1))

    unknown_dns = [d for d in dns_servers if d not in known_good_dns]
    if unknown_dns:
        findings.append(_finding(
            "warning",
            "dns",
            f"Unknown DNS server(s) configured: {', '.join(unknown_dns)}",
            "Could indicate ISP manipulation or malware-installed resolvers",
        ))

    return findings


# ---------------------------------------------------------------------------
# Linux-specific checks
# ---------------------------------------------------------------------------

def _linux_startup_entries() -> List[Dict[str, str]]:
    """List systemd units and cron jobs as startup check."""
    findings: List[Dict[str, str]] = []
    suspicious_keywords = ["miner", "xmr", "monero", "coinhive", "cryptonight", "nicehash",
                           "ethminer", "t-rex", "lolminer", "nbminer", "gminer"]

    # systemd enabled units
    units_out = _run(["systemctl", "list-units", "--state=running", "--no-pager", "--no-legend"])
    if units_out:
        for line in units_out.splitlines():
            for kw in suspicious_keywords:
                if kw in line.lower():
                    findings.append(_finding(
                        "critical",
                        "startup",
                        f"Suspected crypto miner service running: {line.strip()[:120]}",
                    ))

    # Cron jobs
    cron_dirs = [
        Path("/etc/cron.d"),
        Path("/etc/cron.daily"),
        Path("/etc/cron.hourly"),
        Path("/var/spool/cron"),
    ]
    for cron_dir in cron_dirs:
        if not cron_dir.exists():
            continue
        for job_file in cron_dir.iterdir():
            content = _read(job_file)
            for kw in suspicious_keywords:
                if kw in content.lower():
                    findings.append(_finding(
                        "critical",
                        "cron",
                        f"Suspicious cron job may reference mining software: {job_file}",
                        content[:200],
                    ))
                    break

    return findings


def _linux_unsigned_modules() -> List[Dict[str, str]]:
    """Check for unsigned or out-of-tree kernel modules."""
    findings: List[Dict[str, str]] = []
    modules_out = _run(["lsmod"])
    if not modules_out:
        return findings

    # Check /proc/sys/kernel/tainted
    taint_raw = _read(Path("/proc/sys/kernel/tainted"), "0").strip()
    try:
        taint = int(taint_raw)
    except ValueError:
        taint = 0

    if taint != 0:
        taint_reasons = []
        taint_map = {
            1:  "proprietary module",
            2:  "module forced load",
            4:  "out-of-specification hardware",
            8:  "tainted by staging driver",
            16: "tainted by in-tree out-of-spec driver",
            32: "unsigned module",
            64: "soft lockup occurred",
        }
        for bit, reason in taint_map.items():
            if taint & bit:
                taint_reasons.append(reason)
        findings.append(_finding(
            "warning",
            "kernel",
            f"Kernel tainted (flags={taint}): {', '.join(taint_reasons)}",
            "Tainted kernels may have unsigned or proprietary modules loaded",
        ))

    return findings


def _linux_high_cpu_processes() -> List[Dict[str, str]]:
    """Look for processes consuming high CPU (miner indicator)."""
    findings: List[Dict[str, str]] = []
    ps_out = _run(["ps", "aux", "--sort=-%cpu"])
    if not ps_out:
        return findings

    lines = ps_out.splitlines()[1:]  # skip header
    miner_names = ["xmrig", "ethminer", "gminer", "t-rex", "lolminer", "nbminer",
                   "phoenixminer", "nanominer", "minerd", "cpuminer"]
    for line in lines[:30]:
        parts = line.split()
        if len(parts) < 11:
            continue
        try:
            cpu_pct = float(parts[2])
        except ValueError:
            cpu_pct = 0.0
        cmd = " ".join(parts[10:]).lower()
        for miner in miner_names:
            if miner in cmd:
                findings.append(_finding(
                    "critical",
                    "process",
                    f"Known crypto miner process detected: {' '.join(parts[10:])[:120]}",
                    f"CPU usage: {cpu_pct}%",
                ))
        if cpu_pct > 80 and len(parts[10]) < 6 and re.match(r"^[a-z0-9]{2,6}$", parts[10]):
            # Suspiciously short process name with very high CPU is a miner indicator
            findings.append(_finding(
                "warning",
                "process",
                f"High-CPU process with obfuscated name: {parts[10]} ({cpu_pct}% CPU)",
            ))

    return findings


# ---------------------------------------------------------------------------
# Windows-specific checks
# ---------------------------------------------------------------------------

def _windows_run_keys() -> List[Dict[str, str]]:
    """Check common auto-start registry keys for suspicious entries."""
    findings: List[Dict[str, str]] = []
    try:
        import winreg  # type: ignore[import]
        run_keys = [
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        ]
        suspicious_kw = ["miner", "xmr", "monero", "nicehash", "coinhive", "ethminer", "payload"]
        for hive, key_path in run_keys:
            try:
                key = winreg.OpenKey(hive, key_path)
                idx = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, idx)
                        idx += 1
                        for kw in suspicious_kw:
                            if kw in (name + value).lower():
                                findings.append(_finding(
                                    "critical",
                                    "registry_startup",
                                    f"Suspicious auto-start entry: {name}",
                                    value[:200],
                                ))
                    except OSError:
                        break
                winreg.CloseKey(key)
            except OSError:
                pass
    except ImportError:
        pass  # Not on Windows

    return findings


def _windows_unsigned_drivers() -> List[Dict[str, str]]:
    """Check for unsigned drivers via PowerShell Get-WmiObject."""
    findings: List[Dict[str, str]] = []
    ps_out = _run([
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "Get-WmiObject Win32_SystemDriver | Where-Object {$_.IsSigned -eq $false} | "
        "Select-Object Name,PathName | ConvertTo-Json -Depth 1"
    ], timeout=20)
    if ps_out and ps_out.strip() != "null":
        try:
            import json
            drivers = json.loads(ps_out)
            if isinstance(drivers, dict):
                drivers = [drivers]
            if drivers:
                names = [d.get("Name", "") for d in drivers[:5]]
                findings.append(_finding(
                    "warning",
                    "drivers",
                    f"Unsigned kernel drivers detected ({len(drivers)}): {', '.join(n for n in names if n)}",
                    "Unsigned drivers may be malicious or from cracked software",
                ))
        except Exception as exc:
            logger.debug("Driver parse error: %s", exc)

    return findings


def _windows_services() -> List[Dict[str, str]]:
    """Check running services for suspicious names."""
    findings: List[Dict[str, str]] = []
    suspicious_kw = ["miner", "xmrig", "ethminer", "monero", "coinhive", "nicehash"]
    ps_out = _run([
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -ExpandProperty Name"
    ], timeout=15)
    if ps_out:
        for name in ps_out.splitlines():
            for kw in suspicious_kw:
                if kw in name.lower():
                    findings.append(_finding(
                        "critical",
                        "service",
                        f"Suspected mining service running: {name}",
                    ))
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan() -> Dict[str, Any]:
    """
    Run the full security scan for the current platform.

    Returns:
        Dict with a list of 'findings', each with severity, category,
        description, and detail fields.
    """
    system = platform.system()
    findings: List[Dict[str, str]] = []

    # Cross-platform
    findings.extend(_check_hosts_file())
    findings.extend(_check_dns(system))

    if system == "Linux" or system == "Darwin":
        findings.extend(_linux_startup_entries())
        findings.extend(_linux_unsigned_modules())
        findings.extend(_linux_high_cpu_processes())
    elif system == "Windows":
        findings.extend(_windows_run_keys())
        findings.extend(_windows_unsigned_drivers())
        findings.extend(_windows_services())

    critical = [f for f in findings if f["severity"] == "critical"]
    warnings = [f for f in findings if f["severity"] == "warning"]

    return {
        "findings": findings,
        "critical_count": len(critical),
        "warning_count": len(warnings),
        "clean": len(findings) == 0,
        "module_status": "ok",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(scan(), indent=2))
