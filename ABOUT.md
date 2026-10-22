# 🛡️ About Windows Registry Monitoring System
### *Enterprise Endpoint Integrity, Differential Registry Telemetry & Defensive Auditing*
**Created & Architected by:** Piyush | **Publisher:** MADE BY PIYUSH  
**Version:** 2.4.0 (Enterprise Edition) | **Platform:** Windows 10 / 11 / Server 2016–2025 (x64)

---

## 🌟 Executive Summary

The **Windows Registry Monitoring System** is an enterprise-grade, lightweight defensive auditing and change-detection platform engineered exclusively for the Microsoft Windows ecosystem. Designed for Security Operations Center (SOC) analysts, digital forensics responders (DFIR), malware researchers, and systems administrators, the application delivers real-time situational awareness over the most exploited attack surface in Windows: the **Windows Registry**.

Traditional endpoint protection tools frequently treat the registry as an afterthought or generate noisy alerts that overwhelm analysts. The Windows Registry Monitoring System solves this by combining:
1. **Deterministic Baseline Cryptography**: Mathematically verifiable snapshots anchored with SHA-256 checksums.
2. **Sub-Second Differential Telemetry**: Instant identification of newly added, modified, deleted, or type-juggled registry keys.
3. **Static Binary Resolution**: Automatic on-disk location, command parsing, and SHA-256 hashing of referenced PE files and DLLs—with an ironclad **zero-execution guarantee**.
4. **Hardware-Tied Local Encryption**: Complete evidential data protection using AES-256-CBC with HMAC authenticated encryption wrapped in Windows DPAPI and hardware TPM 2.0.
5. **Modern SOC Operations Dashboard**: An ergonomic, dark-themed, split dual-ribbon interface with 5 switchable cyber themes, Bento KPI scorecards, interactive event filters, and an always-on-top desktop monitoring widget.

---

## 🎯 The Core Philosophy

```
  ┌─────────────────────────────────────────────────────────────┐
  │                 THE DEFENSIVE TRIAD                         │
  │                                                             │
  │   [ ZERO-EXECUTION ]    [ ZERO-KERNEL-DEPENDENCY ]          │
  │   Safe analysis that    User-mode stability without         │
  │   never runs malware    risking BSODs or kernel hooks       │
  │                                                             │
  │               [ HARDWARE-BOUND PRIVACY ]                    │
  │               Local offline encryption protected            │
  │               by TPM 2.0 and Windows DPAPI                  │
  └─────────────────────────────────────────────────────────────┘
```

- **Defensive & Read-Only**: The monitoring engine strictly audits and alerts. It never modifies, tampers with, or deletes registry hives, avoiding system instability or corrupted configurations.
- **Zero Kernel Overhead**: Unlike third-party kernel drivers that cause Blue Screens of Death (BSODs) or conflict with Windows Virtualization-Based Security (VBS), this system operates purely in user mode using certified Windows API bindings (`winreg` and `advapi32.dll`).
- **Offline & Sovereign**: Complete data privacy. The application transmits zero telemetry to external servers, cloud buckets, or third-party APIs. All baselines, logs, and database records remain strictly on the local machine.

---

## 🚀 Key Feature Highlights

### ⚡ 1. Differential Detection Engine
- Continuous polling engine configurable from **1 second to 300 seconds** (default: 5s).
- Set-theoretic comparison detects:
  - `ADDED`: New values and autostart entries.
  - `MODIFIED`: Value payload changes (e.g., toggled flags, altered arguments).
  - `DELETED`: Removed configuration keys.
  - `TYPE_CHANGED`: Type-juggling attacks (`REG_SZ` $\to$ `REG_EXPAND_SZ`).
  - `ERROR`: Access-denied transitions without generating false deletion alarms.
- Thread-safe sliding window rate-limiting suppresses notification fatigue during high-volume software installations.

### 🔬 2. Static Binary & PE Resolution
- Deep parsing of Windows command lines, environment variables (`%TEMP%`, `%APPDATA%`, `%SYSTEMROOT%`), and execution proxies:
  - Unquoted paths (progressively resolves whitespace prefixes)
  - Quoted arguments
  - `rundll32.exe` target DLL extraction
- Validates file existence on disk, measures byte size, checks file modification timestamps, and calculates chunked **SHA-256 binary hashes** without executing any untrusted code.

### 🔒 3. DPAPI & AES-256 Encrypted Database
- Embedded **SQLite3 in Write-Ahead Logging (WAL) mode** for high-concurrency event ingestion.
- Record-level encryption using **AES-256 (Fernet / CBC + HMAC-SHA256)**.
- Master cryptographic key protected by **Windows DPAPI (`crypt32.dll`)** bound directly to the user's Windows Security Identifier (SID) and motherboard TPM 2.0.
- If database files are exfiltrated by an attacker, they cannot be read or decrypted on another computer.

### 🎨 4. Five Hand-Crafted Cyber Themes
Analyst fatigue is a primary factor in SOC missed alerts. The UI includes 5 professional cyber security themes powered by a 23-token dynamic styling system:
1. **Cyber Blue Team (Default)**: Deep navy `#0B132B` and `#1C2541` with electric cyan `#00D2FF` accents.
2. **Obsidian Stealth**: Ultra-deep pitch black `#08080C` with subtle slate `#707E94` and ice blue `#38BDF8`.
3. **Matrix Terminal**: Tactical phosphor green `#00FF66` on pure OLED dark `#050D08`.
4. **Crimson Alert**: High-contrast threat-hunting emergency theme with bold crimson red `#FF3B30` highlights.
5. **Nordic Frost**: Polar arctic blue `#5EEAD4` with frosted glacial steel `#0F172A`.

### 🖥️ 5. Ergonomic Bento Dashboard & Split Ribbon Controls

![Windows Registry Monitor Dashboard](assets/dashboard_main.png)

- **Bento KPI Scorecards**: 5 prominent live metric cards:
  - 🔄 Engine Status & Polling Cadence (1s to 60s)
  - 📋 Baseline Integrity & Tracked Values
  - 📊 Total Events Captured
  - ⚠️ Suspicious / Investigation Alerts
  - ⚡ Active Scan Performance & Errors
- **Dual-Ribbon Operations Toolbar**:
  - *Engine Controls*: Start Monitoring, Stop Monitoring, Create Baseline, Rescan, Reset Baseline, **Remediate Threat**, **Auto-Clean Threats**.
  - *Investigative Tools*: Visual HTML Report, CSV Export, Settings Dialog, Mute Popups, Floating Widget, Hide to Tray.
- **Search & Quick-Filter Ribbon**: Real-time substring search across registry paths and binary payloads with instantaneous severity filter chips (`All`, `Investigation`, `Suspicious`, `Informational`, `Errors`).

### 🛡️ 6. Active Threat Remediation & Deletion Engine
- Allows security operators to safely delete malicious registry keys directly from the application.
- Uses Windows Registry API (`winreg.DeleteValue`) with privilege verification.
- Context menu integration: right-click any event row to instantly neutralize persistence.
- Complete remediation audit ledger stored in local encrypted database.

### ⏱️ 7. Dynamic Continuous Polling Engine (1s to 60s)

![Continuous Registry Polling Interval Settings](assets/polling_settings.png)

- 6 dedicated polling speeds: 1s, 2s, 5s, 10s, 30s, and 60s.
- Real-time engine adjustment: changes take effect immediately without restarting the app.
- Dedicated "💾 Save & Apply Timing Now" button inside App Settings.
- One-click quick-switch popup menu from the main dashboard header badge.

### 🪟 8. Draggable Floating Desktop Widget
- Minimizes the monitoring footprint into a sleek, unobtrusive floating HUD on your desktop.
- Displays live engine status, real-time event counts, and pulse animations.
- Fully draggable with `always-on-top` pinning.
- Hides the main dashboard from the Windows taskbar (`withdraw` + `toolwindow`), keeping analyst multi-monitor screens clear.
- Single double-click restores the full desktop dashboard instantly.

### 📈 9. Automated Visual Analytics & HTML Reports
- Generates publication-ready standalone HTML reports (`reports/visual_report_<timestamp>.html`).
- Embedded interactive **Chart.js 4.4** visualizations:
  - Severity Breakdown Doughnut Chart
  - Change Type Distribution Bar Chart
  - Hourly Event Velocity Timeline
- Complete sortable, searchable telemetry table with color-coded severity tags and one-click JSON payload inspect modal.

---

## 👥 Target Personas & Use Cases

| Target Persona | Key Value Proposition | Typical Workflow |
| :--- | :--- | :--- |
| **Enterprise SOC Analyst** | Instant alert triage on endpoint persistence without deploying heavy agent infrastructure. | Observes incoming suspicious alerts, correlates SHA-256 hashes against threat intel feeds, exports forensic CSV bundles. |
| **Incident Response (DFIR) Consultant** | Rapid baseline comparison on compromised or suspect corporate endpoints. | Creates clean baseline on gold image, deploys tool to suspect host, triggers differential scan to isolate attacker footprints in minutes. |
| **Malware Reverse Engineer** | Precise behavioral observation of malware installation routines in sandbox VMs. | Takes baseline before executing unknown sample, runs sample, rescans registry to see all dropped keys, hijacked run keys, and altered security flags. |
| **Systems / IT Administrator** | Auditing software installers and tracking unintended group policy or startup regressions. | Monitors server fleets for unauthorized startup tasks, altered services, or disabled Windows Firewall standard profiles. |
| **Privacy & Security Enthusiast** | Total visibility into telemetry and background persistence software on personal machines. | Runs application minimized at boot to catch background telemetry installers, adware injectors, or bundled startup software. |

---

## 🏗️ Technology Architecture & Technical Specifications

```
                     ┌──────────────────────────────────────────────┐
                     │          Windows Registry Monitor            │
                     │                 (main.py)                    │
                     └──────────────────────┬───────────────────────┘
                                            │
                ┌───────────────────────────┼───────────────────────────┐
                │                           │                           │
  ┌─────────────▼────────────┐ ┌────────────▼───────────┐ ┌─────────────▼────────────┐
  │   Registry Engine        │ │   Security & Database   │ │     UI & Visualization  │
  ├──────────────────────────┤ ├─────────────────────────┤ ├─────────────────────────┤
  │ • registry_scanner.py    │ │ • database.py (WAL+DPAPI│ │ • theme_manager.py (5)  │
  │ • change_detector.py     │ │ • autostart.py (Run Key)│ │ • settings_window.py    │
  │ • file_resolver.py       │ │ • alert_manager.py      │ │ • visual_reporter.py    │
  │ • winreg & advapi32      │ │ • report_generator.py   │ │ • Tkinter + ttk widgets │
  └──────────────────────────┘ └─────────────────────────┘ └─────────────────────────┘
```

### Technical Specifications
- **Programming Language**: Python 3.12 (CPython x64)
- **GUI Framework**: Native Tkinter + Ttk Custom Canvas & Theme Engine
- **Windows APIs Bound**: `winreg`, `ctypes.windll.crypt32`, `ctypes.windll.shell32`, `advapi32`
- **Cryptographic Algorithms**:
  - Storage Encryption: AES-256 in CBC mode with PKCS7 padding
  - Message Authentication: HMAC-SHA256
  - Key Protection: Windows Data Protection API (DPAPI) via `CryptProtectData` / `CryptUnprotectData`
  - Baseline Anchoring: SHA-256 (256-bit cryptographically secure hash)
- **Database Engine**: Embedded SQLite 3.45+ (WAL Journal Mode, `PRAGMA synchronous = NORMAL`)
- **Distribution Packaging**:
  - Standalone Single-File Binary: **PyInstaller 6.13** (80.20 MB, zero external dependencies)
  - Windows Setup Wizard: **Inno Setup 7.0** (81.05 MB installer with desktop icons, uninstaller, and Start Menu shortcuts)
- **Supported Operating Systems**:
  - Windows 11 (All editions, x64)
  - Windows 10 (Build 1809+, x64)
  - Windows Server 2025, 2022, 2019, 2016

---

## 👨‍💻 Author & Attribution

- **Lead Architect & Developer:** **Piyush**
- **Brand & Publisher Designation:** **MADE BY PIYUSH**
- **Contact & Support:** Built with pride for the global cybersecurity and DFIR defense community.
- **Copyright:** © 2026 Piyush. All rights reserved.
- **License:** Enterprise Defensive License — Free for educational, forensic, and internal defensive organizational deployments. Unauthorized redistribution for malicious tooling or weaponized reverse-engineering is strictly prohibited.

---

*“Security is not a static perimeter; it is the continuous, uncompromising audit of the smallest system delta.”*  
— **MADE BY PIYUSH**
