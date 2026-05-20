# Known Scams SpecterScan Detects

A reference guide to hardware fraud patterns found on used laptop markets.
This document grows with community contributions — submit additions via pull request.

---

## CPU Fraud

### Fake i7 / Rebadged CPU

**Scam:** Laptop listed as Intel Core i7. Actual chip is an i3, Celeron, or Pentium with modified registry/BIOS strings.

**How SpecterScan catches it:**
- Cross-checks advertised CPU tier against actual max clock speed
- i3 Celeron masquerading as i7: base clock typically < 2.0 GHz vs i7's ≥ 2.4 GHz
- Core and thread counts inconsistent with claimed tier
- Some sellers enable 3rd-party tools that rename the CPU in Windows — SpecterScan reads CPUID-level data, not display names

**Red flags to look for manually:**
- CPU-Z shows different processor than Device Manager
- Benchmark scores 40–60% below expected for claimed tier
- Task Manager shows fewer cores than listed

---

### VM Masking

**Scam:** Device is actually a cloud server or virtual machine. Seller shows screenshots of "real hardware."

**How SpecterScan catches it:**
- `CPUID` hypervisor flag set (bit 31 of ECX in leaf 1)
- `lscpu` reports `Hypervisor vendor`
- VM-only features present (e.g. `vmx`/`svm` absent but `hypervisor` flag present)

**Why it matters:** All benchmarks from VMs are meaningless for predicting real laptop performance.

---

## Storage Fraud

### Fake SSD Capacity

**Scam:** 2TB SSD is actually 64GB flash with firmware that loops writes. Files appear to save but are silently overwritten. Common on cheap USB sticks sold as internal drives.

**How SpecterScan catches it:**
- Write-verify test: writes known data beyond the logical reported capacity boundary
- Reads back and compares — mismatches indicate capacity spoofing
- Capacity deviation check: reports 480 GB but closest standard is 512 GB — >15% deviation flags

**Common on:** AliExpress "brand new" NVMe drives, generic M.2 sticks

---

### SMART Pre-Failure Hidden by Wiped Data

**Scam:** Drive has high reallocated sector count or pending sectors. Seller does a full format to reset the "lifespan" display in tools like CrystalDiskInfo (it doesn't — SMART is read from firmware, not the OS).

**How SpecterScan catches it:**
- SMART attributes 5, 187, 197, 198 checked directly
- Any non-zero count in reallocated/pending sectors is flagged

---

## Battery Fraud

### Dead Battery Disguised

**Scam:** Battery shows 100% charge in Windows but lasts 20 minutes. Battery BMS (Battery Management System) is reporting maximum charge while actual capacity is 15–30% of design.

**How SpecterScan catches it:**
- `energy_full` from sysfs / ACPI vs `energy_full_design` gives true health
- Health below 50% triggers critical flag
- Health 50–70% triggers warning

---

### Non-OEM Battery Mislabelled as Original

**Scam:** Third-party replacement battery installed, labelled or listed as "original." May not meet safety standards.

**How SpecterScan catches it:**
- Battery manufacturer string compared against known OEM names
- Blank/generic manufacturer triggers "non-OEM suspected" flag

---

### Discharged Battery Masked by AC Power

**Scam:** Battery is completely dead but laptop is always shown plugged in. Disconnecting power causes immediate shutdown.

**How SpecterScan catches it:**
- `energy_full` near zero even when battery "present" flag is set
- Reports this as critical battery degradation

---

## Thermal Fraud

### Mining Laptop

**Scam:** Laptop was used 24/7 for cryptocurrency mining for 12+ months. Thermal paste dried out, heatsink clogged with dust. Laptop appears fine at idle but overheats under any load.

**How SpecterScan catches it:**
- Thermal ramp speed test: temperature rise > 30°C during first quarter of stress = abnormal cooling
- CPU throttle detection: > 30% throughput drop from start to end of stress test
- CPU reaches critical temperature (> 95°C) under load

**Signs in person:** Fan runs loud immediately, bottom gets very hot within 60 seconds of use, thermal paste visibly discoloured/dried on heatsink (if you open it).

---

### Blocked Vents / Dust Clogged

**Scam:** Cosmetically clean laptop with vents completely blocked internally.

**How SpecterScan catches it:**
- Same thermal ramp and throttle checks as mining laptop
- Rapid temperature rise with low initial workload

---

## Security / Malware

### Pre-installed Crypto Miner

**Scam:** Seller installs XMRig, NBMiner, or similar before selling. Buyer gets a laptop that mines for the original owner indefinitely.

**How SpecterScan catches it:**
- Checks running processes for known miner names (`xmrig`, `ethminer`, `gminer`, etc.)
- Checks systemd units and cron jobs for miner keywords
- Checks Windows registry Run keys

---

### DNS Hijacking / Hosts File Tampering

**Scam:** Seller configures malicious DNS or hosts file entries to intercept banking or account traffic after sale.

**How SpecterScan catches it:**
- DNS resolvers compared against known-good list
- Hosts file scanned for redirects of major domains (Google, Microsoft, Apple, GitHub)

---

### Unsigned Kernel Modules / Drivers

**Scam:** Rootkit or keylogger installed at kernel level. Persists through OS reinstalls if targeting UEFI.

**How SpecterScan catches it:**
- Checks `/proc/sys/kernel/tainted` for unsigned module flags
- Windows: PowerShell query for unsigned loaded drivers

---

## Physical Hardware Fraud

### BIOS Password Lock (Possible Stolen Device)

**Scam:** Laptop has a BIOS supervisor password set. Could be a stolen device with an enterprise BIOS lock (MDM, absolute) that cannot be bypassed.

**How SpecterScan catches it:**
- Checks for BIOS/DMI flags indicating locked or provisioned firmware
- Serial number check: blank or placeholder serials on devices that should have them suggest wiping

---

### USB Killer Damage

**Scam:** Previous owner connected a USB Killer device (delivers 200V via USB). Internal components may have silent damage to USB controller, battery circuits, or motherboard.

**How SpecterScan catches it:**
- Kernel log scan for USB overcurrent / power surge events
- Windows Event ID 43 (surprise removal after power event) detection

---

## Contributing

Know a scam pattern not listed here? Submit a pull request with:
1. Scam description
2. How SpecterScan catches it (or doesn't yet)
3. Detection improvement idea if applicable
