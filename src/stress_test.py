#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
stress_test.py — CPU, memory, and disk stress testing.

Stress tests are implemented using only the Python standard library.
CPU stress uses multiprocessing, memory stress uses bytearray allocations,
and disk stress writes/reads a temporary file.

All tests have configurable duration and measure throttling by comparing
throughput at the start vs. end of the test.
"""

import logging
import math
import multiprocessing
import os
import platform
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
THERMAL_SAMPLE_INTERVAL_S = 2.0   # seconds between temp samples during stress
DISK_WRITE_CHUNK_MB = 64           # MB per write chunk
MEMORY_ALLOC_MB = 256              # MB per memory stress block


# ---------------------------------------------------------------------------
# CPU stress worker
# ---------------------------------------------------------------------------

def _cpu_worker(duration: float, result_queue: multiprocessing.Queue) -> None:  # type: ignore[type-arg]
    """
    Busy-work CPU stress worker.

    Computes square roots and pi digits (pure FP work) for *duration* seconds,
    records total iterations, then puts the count in *result_queue*.
    """
    end_time = time.monotonic() + duration
    count = 0
    x = 0.0001
    while time.monotonic() < end_time:
        # Mixed FP operations to prevent dead-code elimination
        x = math.sqrt(x + 1.0)
        x = math.sin(x) * math.cos(x)
        x = math.log(abs(x) + 1.0) + 0.001
        count += 1
    result_queue.put(count)


# ---------------------------------------------------------------------------
# Temperature sampling (Linux only — non-blocking)
# ---------------------------------------------------------------------------

def _sample_cpu_temp_linux() -> Optional[float]:
    """Read the first available CPU thermal zone temperature."""
    thermal_root = Path("/sys/class/thermal")
    if not thermal_root.exists():
        return None
    for zone in sorted(thermal_root.iterdir()):
        if not zone.name.startswith("thermal_zone"):
            continue
        z_type = (zone / "type").read_text().strip() if (zone / "type").exists() else ""
        temp_path = zone / "temp"
        if temp_path.exists():
            raw = temp_path.read_text().strip()
            if raw.isdigit():
                return int(raw) / 1000.0
    return None


# ---------------------------------------------------------------------------
# CPU stress test
# ---------------------------------------------------------------------------

def _run_cpu_stress(duration: int) -> Dict[str, Any]:
    """
    Spawn one worker per logical CPU core, measure throughput at start and
    end, and record temperature samples throughout.

    Returns throttle_pct — percentage drop in throughput from first to
    last quarter of the test, indicating thermal throttling.
    """
    cpu_count = max(1, multiprocessing.cpu_count())
    result: Dict[str, Any] = {"cpu_count": cpu_count}

    # Divide duration into quarters; compare first vs last quarter throughput
    quarter = max(4, duration // 4)
    temp_samples: List[Optional[float]] = []

    q: multiprocessing.Queue = multiprocessing.Queue()  # type: ignore[type-arg]

    # ── First quarter ────────────────────────────────────────────────────
    workers_first = [
        multiprocessing.Process(target=_cpu_worker, args=(quarter, q))
        for _ in range(cpu_count)
    ]
    for w in workers_first:
        w.start()

    t_start_first = time.monotonic()
    while time.monotonic() - t_start_first < quarter:
        t = _sample_cpu_temp_linux()
        temp_samples.append(t)
        time.sleep(THERMAL_SAMPLE_INTERVAL_S)

    for w in workers_first:
        w.join(timeout=quarter + 5)

    first_counts = []
    while not q.empty():
        first_counts.append(q.get())
    first_throughput = sum(first_counts) / max(len(first_counts), 1)

    # ── Middle quarters (just run, no measurement) ───────────────────────
    middle_duration = duration - 2 * quarter
    if middle_duration > 0:
        workers_mid = [
            multiprocessing.Process(target=_cpu_worker, args=(middle_duration, q))
            for _ in range(cpu_count)
        ]
        for w in workers_mid:
            w.start()
        t_mid = time.monotonic()
        while time.monotonic() - t_mid < middle_duration:
            t = _sample_cpu_temp_linux()
            temp_samples.append(t)
            time.sleep(THERMAL_SAMPLE_INTERVAL_S)
        for w in workers_mid:
            w.join(timeout=middle_duration + 5)
        while not q.empty():
            q.get()  # discard

    # ── Last quarter ─────────────────────────────────────────────────────
    workers_last = [
        multiprocessing.Process(target=_cpu_worker, args=(quarter, q))
        for _ in range(cpu_count)
    ]
    for w in workers_last:
        w.start()

    t_start_last = time.monotonic()
    while time.monotonic() - t_start_last < quarter:
        t = _sample_cpu_temp_linux()
        temp_samples.append(t)
        time.sleep(THERMAL_SAMPLE_INTERVAL_S)

    for w in workers_last:
        w.join(timeout=quarter + 5)

    last_counts = []
    while not q.empty():
        last_counts.append(q.get())
    last_throughput = sum(last_counts) / max(len(last_counts), 1)

    # Throttle percentage: how much slower at the end vs the start
    if first_throughput > 0 and last_throughput >= 0:
        throttle_pct = max(0.0, (first_throughput - last_throughput) / first_throughput * 100.0)
    else:
        throttle_pct = 0.0

    # Temperature analysis
    valid_temps = [t for t in temp_samples if t is not None]
    result["cpu_throttle_pct"] = round(throttle_pct, 1)
    result["temp_samples"] = [round(t, 1) for t in valid_temps]
    result["temp_min_c"] = round(min(valid_temps), 1) if valid_temps else None
    result["temp_max_c"] = round(max(valid_temps), 1) if valid_temps else None
    result["temp_avg_c"] = round(sum(valid_temps) / len(valid_temps), 1) if valid_temps else None

    # Check for rapid temperature ramp (mining laptop / broken cooling indicator)
    if len(valid_temps) >= 4:
        first_quarter_avg = sum(valid_temps[: len(valid_temps) // 4]) / max(1, len(valid_temps) // 4)
        last_quarter_avg = sum(valid_temps[-(len(valid_temps) // 4) :]) / max(1, len(valid_temps) // 4)
        result["temp_rise_c"] = round(last_quarter_avg - first_quarter_avg, 1)
    else:
        result["temp_rise_c"] = None

    return result


# ---------------------------------------------------------------------------
# Memory stress test
# ---------------------------------------------------------------------------

def _run_memory_stress(duration: int) -> Dict[str, Any]:
    """
    Allocate large byte arrays, write a pattern, and read back to verify.

    Returns errors_detected (count of readback mismatches).
    """
    result: Dict[str, Any] = {}
    chunk_bytes = MEMORY_ALLOC_MB * 1024 * 1024
    pattern = bytes([0xAB, 0xCD, 0xEF, 0x01] * (chunk_bytes // 4))

    errors = 0
    iterations = 0
    end_time = time.monotonic() + duration
    blocks_allocated: List[bytearray] = []

    try:
        # Allocate a few blocks
        for _ in range(4):
            if time.monotonic() >= end_time:
                break
            block = bytearray(chunk_bytes)
            block[:] = pattern
            blocks_allocated.append(block)

        # Verify
        for block in blocks_allocated:
            if time.monotonic() >= end_time:
                break
            if bytes(block) != pattern:
                errors += 1
            iterations += 1

        # Write/read until timeout
        while time.monotonic() < end_time:
            block = bytearray(chunk_bytes)
            block[:] = pattern
            if bytes(block) != pattern:
                errors += 1
            iterations += 1

    except MemoryError:
        result["oom_event"] = True
        logger.warning("Memory stress: MemoryError — system RAM may be insufficient")
    finally:
        del blocks_allocated

    result["errors_detected"] = errors
    result["iterations"] = iterations
    result["alloc_mb_per_block"] = MEMORY_ALLOC_MB
    result["severity"] = "critical" if errors > 0 else "ok"

    return result


# ---------------------------------------------------------------------------
# Disk stress test
# ---------------------------------------------------------------------------

def _run_disk_stress(duration: int) -> Dict[str, Any]:
    """
    Write random data to a temporary file, read it back, verify integrity,
    and measure read/write speeds.
    """
    result: Dict[str, Any] = {}
    chunk_bytes = DISK_WRITE_CHUNK_MB * 1024 * 1024
    data = os.urandom(chunk_bytes)

    tmp_dir = tempfile.gettempdir()
    tmp_path = Path(tmp_dir) / "specterscan_disk_stress.tmp"

    write_speeds: List[float] = []  # MB/s
    read_speeds: List[float] = []   # MB/s
    verify_errors = 0
    cycles = 0
    end_time = time.monotonic() + duration

    try:
        while time.monotonic() < end_time:
            # Write
            t0 = time.monotonic()
            with open(tmp_path, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            write_time = time.monotonic() - t0
            write_speeds.append(DISK_WRITE_CHUNK_MB / max(write_time, 0.001))

            # Read + verify
            t0 = time.monotonic()
            with open(tmp_path, "rb") as fh:
                readback = fh.read()
            read_time = time.monotonic() - t0
            read_speeds.append(DISK_WRITE_CHUNK_MB / max(read_time, 0.001))

            if readback != data:
                verify_errors += 1
            cycles += 1
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass

    result["cycles"] = cycles
    result["verify_errors"] = verify_errors
    result["write_speed_mbps"] = round(sum(write_speeds) / max(len(write_speeds), 1), 1)
    result["read_speed_mbps"] = round(sum(read_speeds) / max(len(read_speeds), 1), 1)
    result["write_speed_min_mbps"] = round(min(write_speeds, default=0), 1)
    result["severity"] = "critical" if verify_errors > 0 else "ok"

    # Flag unusually slow sequential write speeds for SSD
    if result["write_speed_mbps"] < 50:
        result["slow_flag"] = True
    if result["write_speed_mbps"] < 10:
        result["very_slow_flag"] = True

    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_stress(duration: int = 30) -> Dict[str, Any]:
    """
    Run CPU, memory, and disk stress tests.

    Args:
        duration: Duration in seconds for each individual stress test.

    Returns:
        Dict with cpu, memory, disk sub-results and an overall flags list.
    """
    logger.info("Starting stress tests (duration=%ds each)", duration)
    results: Dict[str, Any] = {"duration_s": duration}
    flags: List[str] = []

    # ── CPU ───────────────────────────────────────────────────────────────
    logger.info("Running CPU stress test …")
    cpu_result = _run_cpu_stress(duration)
    results["cpu"] = cpu_result
    throttle = cpu_result.get("cpu_throttle_pct", 0)
    if throttle >= 30:
        flags.append(f"Severe CPU throttling under load: {throttle:.1f}% throughput drop — cooling failure or thermal paste issue")
    elif throttle >= 10:
        flags.append(f"CPU throttling detected under load: {throttle:.1f}% — monitor temperatures")

    temp_max = cpu_result.get("temp_max_c")
    if temp_max is not None and temp_max >= 95:
        flags.append(f"CPU reached critical temperature under load: {temp_max:.1f} °C")
    elif temp_max is not None and temp_max >= 85:
        flags.append(f"CPU reached high temperature under load: {temp_max:.1f} °C")

    temp_rise = cpu_result.get("temp_rise_c")
    if temp_rise is not None and temp_rise >= 30:
        flags.append(f"Rapid thermal ramp detected ({temp_rise:.1f} °C rise) — characteristic of mining laptops or blocked vents")

    # ── Memory ────────────────────────────────────────────────────────────
    logger.info("Running memory stress test …")
    mem_result = _run_memory_stress(min(duration, 20))
    results["memory"] = mem_result
    if mem_result.get("errors_detected", 0) > 0:
        flags.append(f"Memory errors detected during stress: {mem_result['errors_detected']} readback failure(s) — possible RAM issue")
    if mem_result.get("oom_event"):
        flags.append("Out-of-memory event during stress test — available RAM may be less than reported")

    # ── Disk ─────────────────────────────────────────────────────────────
    logger.info("Running disk stress test …")
    disk_result = _run_disk_stress(min(duration, 20))
    results["disk"] = disk_result
    if disk_result.get("verify_errors", 0) > 0:
        flags.append(f"Disk verify errors during stress: {disk_result['verify_errors']} — possible storage failure")
    if disk_result.get("very_slow_flag"):
        flags.append(f"Extremely slow disk write speed: {disk_result.get('write_speed_mbps')} MB/s — SSD may be failing or fake")

    results["flags"] = flags
    results["module_status"] = "ok"
    logger.info("Stress tests complete")
    return results


if __name__ == "__main__":
    import json
    print(json.dumps(run_stress(duration=10), indent=2, default=str))
