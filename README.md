# SpecterScan

**Hardware Diagnostic & Trust Verification Tool for Used Laptops**

> *"Trust nothing. Verify everything."*

SpecterScan performs a deep offline hardware audit in minutes — stress-testing the CPU, checking battery authenticity, probing storage for fake capacity, scanning for malware, and cross-referencing every reported spec against what the hardware actually says. It outputs a single self-contained HTML report with a 0–100 trust score and a clear verdict.

```
  ____  ____  ____  ___  ____  ____  ____  ___    __    _  _ 
 / ___)(  _ \(  __)/ __)(_  _)(  __)(  _ \/ __)  / _\  ( \/ )
 \___ \ ) __/ ) _)( (__   )(   ) _)  )   /\__ \ /    \  )  ( 
 (____/(__)  (____)\___) (__) (____)(__)  (____/ \_/\_/ (_/\_)
  Hardware Diagnostic & Trust Verification Tool  v1.0.0
```

---

## What It Detects

| Scam Type | What Sellers Do | How SpecterScan Catches It |
|-----------|-----------------|---------------------------|
| **Fake CPU** | i3/Celeron sold as i7 | Cross-checks clock speed and core count against CPUID data |
| **VM Masking** | Virtual machine presenting false specs | Detects hypervisor flags in CPUID |
| **Counterfeit SSD** | 64GB flash labelled as 512GB | Write-verify test beyond reported capacity |
| **Dead Battery** | "100% health" battery dies in 30 min | Design vs actual capacity from ACPI/sysfs |
| **Mining Laptop** | Thermally damaged, looks fine | Thermal ramp speed + CPU throttle under stress |
| **SMART Failures** | Imminent drive failure hidden | SMART attribute cross-check (reallocated sectors, pending) |
| **Non-OEM Battery** | Cheap replacement sold as original | Manufacturer ID validation |
| **Crypto Miner** | Mining software still running | Process scan + startup entry audit |
| **Stolen Device** | Serial number cleared/faked | BIOS/board serial anomaly detection |
| **USB Killer History** | Power surge damage from USB weapon | Kernel log analysis for power anomalies |
| **Suspicious DNS/Hosts** | Traffic interception configured | Hosts file + resolver validation |

---

## Quick Start

### Linux / macOS
```bash
git clone https://github.com/specterscan/specterscan
cd specterscan
sudo python3 run.py
```

### Windows (Run as Administrator)
```powershell
git clone https://github.com/specterscan/specterscan
cd specterscan
python run.py
```

**Zero pip installs required.** SpecterScan uses only the Python 3.6+ standard library.

---

## Example Output

```
  ╔══════════════════════════════════════════════════════╗
  ║  VERDICT: CAUTION                                    ║
  ║  SCORE:   61  / 100                                  ║
  ╚══════════════════════════════════════════════════════╝

  Report saved to:
  /home/user/specterscan_report_2024-01-15_14-32-01.html
```

The HTML report includes:
- **Trust score ring** with colour-coded verdict
- **Per-category score bars** (hardware, battery, storage, thermal, security)
- **Hardware identity table** (✓ / ✗ for each component)
- **Battery semi-circle health gauge** (canvas-drawn)
- **Thermal line chart** (temperature over stress test)
- **Security findings** with severity badges
- **Prioritised recommendations**
- **Raw JSON appendix** (collapsible)

---

## Example Reports

Open these in your browser immediately — no install needed:

| File | Scenario |
|------|----------|
| [`examples/example_report_healthy.html`](examples/example_report_healthy.html) | Healthy laptop — score 91, TRUSTWORTHY |
| [`examples/example_report_scam.html`](examples/example_report_scam.html) | Scam laptop — fake i7, dead battery, mining software — score 18, DO NOT BUY |
| [`examples/example_report_failing.html`](examples/example_report_failing.html) | Dying hardware — SMART failures, thermal throttle — score 44, CAUTION |

---

## Usage

```
usage: run.py [-h] [--quick] [--no-stress] [--output OUTPUT]
              [--stress-duration SECONDS] [--debug]

options:
  --quick                  Skip stress tests (faster scan)
  --no-stress              Same as --quick
  --output PATH            Directory for the HTML report (default: cwd)
  --stress-duration SECS   Duration of each stress test (default: 30s)
  --debug                  Enable verbose debug logging
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | TRUSTWORTHY (score ≥ 80) |
| `1`  | CAUTION (score 50–79) |
| `2`  | DO NOT BUY (score < 50) |
| `3`  | Fatal / scan aborted |

---

## Scoring System

SpecterScan computes a weighted average across 7 categories:

| Category | Weight | What It Measures |
|----------|--------|-----------------|
| Hardware Authenticity | 25% | CPU/RAM/serial integrity, VM masking |
| Thermal Health | 20% | Idle temps, throttling, ramp speed |
| Battery Health | 15% | Capacity vs design, OEM status, cycle count |
| Storage Health | 15% | SMART data, fake capacity check |
| Performance Under Load | 10% | Stress throughput, memory errors, disk I/O |
| Security Posture | 10% | Miners, bad startups, DNS/hosts |
| Peripheral Status | 5% | USB history, power anomalies |

**Verdicts:**
- ✅ **TRUSTWORTHY** — Score ≥ 80
- ⚠️ **CAUTION** — Score 50–79
- ❌ **DO NOT BUY** — Score < 50

---

## Platform Support

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| CPU info | ✅ `/proc/cpuinfo` + `lscpu` | ✅ `sysctl` | ✅ `wmic` |
| RAM details | ✅ `dmidecode` | ✅ `system_profiler` | ✅ `wmic` |
| Battery health | ✅ `/sys/class/power_supply` | ✅ `ioreg` | ✅ `wmic` |
| SMART/storage | ✅ `smartctl` | ✅ `smartctl` | ✅ `wmic` + `smartctl` |
| Thermal sensors | ✅ sysfs + `lm-sensors` | ✅ `powermetrics` | ✅ WMI |
| Stress testing | ✅ | ✅ | ✅ |
| USB history | ✅ `lsusb` + journal | ✅ `ioreg` | ✅ Registry |
| Startup audit | ✅ systemd + cron | ✅ launchd | ✅ Registry |

> **Note:** Some checks require elevated privileges. Always run with `sudo` (Linux/macOS) or as Administrator (Windows) for full results.

---

## Project Structure

```
specterscan/
├── run.py                      # Entry point — orchestrates everything
├── README.md
├── LICENSE                     # GPL v3
├── CONTRIBUTING.md
├── src/
│   ├── __init__.py
│   ├── collector_linux.py      # Linux/macOS hardware collection
│   ├── collector_windows.py    # Windows hardware collection
│   ├── stress_test.py          # CPU / memory / disk stress
│   ├── battery_check.py        # Battery health analysis
│   ├── storage_check.py        # SMART + fake-capacity detection
│   ├── thermal_check.py        # Temperature sensors
│   ├── integrity_check.py      # Cross-reference & authenticity checks
│   ├── security_scan.py        # Malware / miner / startup audit
│   ├── scoring.py              # Weighted trust score engine
│   └── reporter.py             # HTML report generator
├── templates/
│   └── report_template.html    # Self-contained HTML template
├── profiles/                   # Community hardware spec profiles
│   ├── dell_xps_15_9530.json
│   ├── lenovo_thinkpad_t14.json
│   ├── macbook_pro_m2.json
│   └── custom_template.json
├── docs/
│   └── known_scams.md          # Documented scam patterns
└── examples/
    ├── example_report_healthy.html
    ├── example_report_scam.html
    └── example_report_failing.html
```

---

## Requirements

- **Python 3.6+** (standard library only — no pip required)
- **Elevated privileges** for full hardware access
- **Optional tools** (enhance scan quality if present):
  - `smartctl` (smartmontools) — SMART data
  - `dmidecode` — detailed BIOS/RAM info  
  - `lm-sensors` — CPU core temperatures
  - `lsusb` — USB device enumeration

### Installing optional tools

```bash
# Ubuntu / Debian
sudo apt install smartmontools dmidecode lm-sensors usbutils

# Fedora / RHEL
sudo dnf install smartmontools dmidecode lm_sensors usbutils

# macOS
brew install smartmontools

# Windows (via winget)
winget install CrystalDewWorld.CrystalDiskInfo
```

---

## Contributing

We welcome contributions! The most impactful ways to help:

1. **Hardware profiles** — Add a `profiles/<vendor>_<model>_<year>.json` based on `custom_template.json`
2. **Scam patterns** — Document new detection methods in `docs/known_scams.md`
3. **Platform support** — Improve Windows/macOS collectors
4. **Bug reports** — Open an issue with the error message and your OS/Python version

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

---

## Known Scam Database

See [`docs/known_scams.md`](docs/known_scams.md) for a detailed reference of scam patterns SpecterScan detects.

---

## License

GPL v3 — see [LICENSE](LICENSE).

You can use, modify, and distribute this tool freely. You may not create closed-source commercial forks. Contributions must be released under the same license.

---

## The Story

A friend bought a used laptop listed as an "i7, 16GB RAM, 512GB SSD." It was slow from day one, ran hot, and the battery lasted 25 minutes. The specs were fabricated — a rebadged i3 with a counterfeit SSD and a battery at 30% of original capacity.

SpecterScan exists so the next person can run one command before handing over their money.

---

*If you're buying used, run this first.*
