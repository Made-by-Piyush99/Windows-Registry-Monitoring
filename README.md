# Windows Registry Change Monitoring System

A defensive, read-only Windows Registry auditing and forensics tool built with Python. Monitors critical system and user registry locations for unauthorized modifications, persistence mechanisms, and security policy tampering with instant desktop alerts, local hardware-encrypted telemetry, customizable cyber themes, and background autostart capabilities.

> **⚠ Disclaimer**: This tool does NOT guarantee malware detection or complete system protection. It is an auditing aid that monitors specific registry paths for changes.

---

## What's New in v2.4 (Threat Remediation, UI Showcase & Timing Controls)

- 🛡️ **Active Threat Remediation & Deletion**:
  - Manually or automatically neutralize detected viruses, trojans, and suspicious persistence keys.
  - Safe, controlled Windows Registry API value deletion (`winreg.DeleteValue`) with Administrator verification.
  - One-click **"🛡️ Remediate Threat"** and **"⚡ Auto-Clean Threats"** batch remediation.
  - Complete cryptographic remediation audit history preserved in the local encrypted database.
- ⏱️ **Flexible Polling Frequency (1s to 60s)**:
  - 6 selectable engine cadences: 1s, 2s, 5s, 10s, 30s, and 60s.
  - Dedicated **"💾 Save Timing & Apply Immediately"** button inside App Settings.
  - Header quick-switch badge: click on `⏱️ 5s Polling` in the top right to instantly change polling intervals on the fly!
- 🖼️ **Ergonomic Visual Experience & Theme Engine**:
  - 5 cybersecurity visual profiles (Cyber Blue Team, Obsidian Stealth, Matrix Terminal, Crimson Alert, Nordic Frost).
  - 5 live Bento KPI scorecards, split operations ribbon, and multi-tab forensic inspector.
- 🔒 **Hardware-Bound AES-256 Storage**:
  - Telemetry and remediation records secured by Windows DPAPI tied to user SID and TPM 2.0.

---

## 🖼️ Application Interface & Feature Showcase

| 1. Primary SOC Telemetry Dashboard (v2.4.0) | 2. Real-Time Desktop Pop-up Alerts |
| :---: | :---: |
| ![Primary SOC Dashboard](assets/first.png) | ![Real-Time Desktop Alerts](assets/second.png) |

| 3. Windows Startup & Background Launch | 4. Dynamic Polling Interval Selector (1s to 60s) |
| :---: | :---: |
| ![Windows Startup Settings](assets/third.png) | ![Polling Interval Engine](assets/fourth.png) |

| 5. Interactive Graphical Visual Report Viewer |
| :---: |
| ![Interactive Graphical Report](assets/fifth.png) |

---

## 💻 Language & Technology Stack

The system is constructed using a high-performance, native Windows defensive stack:

| Layer | Component & Technology | Purpose |
| :--- | :--- | :--- |
| **Core Runtime** | **Python 3.12 / 3.14 (64-bit CPython)** | High-level orchestration, asynchronous threading, and telemetry pipeline. |
| **OS Interfaces** | **Native Win32 API (`winreg`, `advapi32.dll`, `ctypes`)** | Deep registry enumeration across 64-bit and 32-bit WOW64 nodes, atomic deletion. |
| **Cryptography** | **AES-256 (Fernet) + Windows DPAPI (`crypt32.dll`)** | Authenticated record encryption bound to user SID and motherboard TPM 2.0. |
| **Storage Engine** | **SQLite 3 (WAL Journal Mode)** | High-concurrency local database with VACUUM optimization and zero external dependencies. |
| **GUI Framework** | **Tkinter & Ttk Styling Engine** | High-contrast, zero-lag 60fps dark user interface with 23 dynamic theme tokens. |
| **Static Analytics** | **Chunked SHA-256 & Command Parser** | Zero-execution static PE binary resolution and unquoted path traversal verification. |
| **Packaging** | **PyInstaller 6.x & Inno Setup 7** | Standalone single-file binary (80 MB) and professional Windows wizard setup installer. |

---

## 📚 Complete Documentation Suite

This project includes a comprehensive suite of dedicated markdown manuals and presentation guides:

| Document | Purpose & Scope |
| :--- | :--- |
| **[`PRESENTATION.md`](file:///d:/Windows%20Registry%20Monitoring%20System/PRESENTATION.md)** | **16 Slide Deck Guide for PowerPoint & Pitching**: Includes slide visual wireframes, metric callouts, competitive comparison tables, and full verbatim speaker notes. |
| **[`SECURITY_ANALYSIS.md`](file:///d:/Windows%20Registry%20Monitoring%20System/SECURITY_ANALYSIS.md)** | **Security & Threat Model**: Formal STRIDE analysis, MITRE ATT&CK coverage matrix, DPAPI + AES-256 cryptographic proofs, and defensive trust boundaries. |
| **[`FORENSIC_ANALYSIS.md`](file:///d:/Windows%20Registry%20Monitoring%20System/FORENSIC_ANALYSIS.md)** | **Forensics Manual & Case Studies**: Set-theoretic delta mathematics, static PE resolution, and 5 detailed real-world attack case studies (Cobalt Strike, Defender disablement, LOLBins, etc.). |
| **[`USER_GUIDE.md`](file:///d:/Windows%20Registry%20Monitoring%20System/USER_GUIDE.md)** | **Step-by-Step Operator Manual**: Complete user guide covering installation, 5-tab settings walkthrough, cyber themes, desktop floating widget, and troubleshooting. |
| **[`ABOUT.md`](file:///d:/Windows%20Registry%20Monitoring%20System/ABOUT.md)** | **Product Profile & Specifications**: Executive vision, core philosophy, 5 cyber theme profiles, target personas, technical specs, and publisher details. |
| **[`HOW_IT_WORKS.md`](file:///d:/Windows%20Registry%20Monitoring%20System/HOW_IT_WORKS.md)** | **Technical & Architectural Reference**: Exhaustive 70KB code-level walkthrough of all modules, algorithms, data structures, and threading models. |

---

## Architecture & Directory Layout

```
D:\Windows Registry Monitoring System\
│
├── dist/
│   ├── WindowsRegistryMonitor.exe             # Standalone pre-compiled single-file executable (~76 MB)
│   └── installer/
│       └── RegistryMonitorSetup.exe           # Inno Setup 7 Windows Installer setup package
│
├── data/
│   ├── app_icon.ico                           # Cyber shield vector application icon
│   ├── baseline.json                          # Selected-path registry baseline snapshot
│   ├── registry_monitor.db                    # Local encrypted SQLite3 database (AES-256 + WAL mode)
│   ├── .security.dpapi                        # Windows DPAPI machine/user-bound encrypted master key
│   ├── logs/                                  # Audit & event logs (app.log, events.jsonl)
│   └── reports/                               # Visual PNG infographics, CSV and JSON reports
│
├── config.json                                # Application settings, themes, paths & alerting policies
├── main.py                                    # Main GUI, thread coordination & layout engine
├── database.py                                # Encrypted SQLite3 persistence & Windows DPAPI cipher
├── autostart.py                               # Windows Run registry key auto-start manager
├── theme_manager.py                           # 5 cyber theme palettes & dynamic styler
├── settings_window.py                         # 5-tab application settings & engine configuration dialog
├── registry_scanner.py                        # Read-only registry scanner & baseline persistence
├── change_detector.py                         # Delta detection, tampering & risk assessment
├── file_resolver.py                           # Command-line parsing, file metadata & risk evaluation
├── alert_manager.py                           # Alert display, deduplication & rate limiting
├── report_generator.py                        # JSONL/CSV logging, summary reports & image exports
├── visual_reporter.py                         # High-res graphical infographics & charts (Pillow + Pandas)
├── installer.iss                              # Inno Setup 7 installation package compiler script
├── build_exe.py                               # Automated PyInstaller build script for standalone .exe
├── requirements.txt                           # Dependencies specification
├── README.md                                  # Master overview & quick start guide
├── HOW_IT_WORKS.md                            # Comprehensive technical manual & architecture guide
├── PRESENTATION.md                            # 16-slide PowerPoint presentation blueprint & notes
├── SECURITY_ANALYSIS.md                       # STRIDE threat model, MITRE ATT&CK & DPAPI cryptanalysis
├── FORENSIC_ANALYSIS.md                       # Forensics handbook, delta math & 5 DFIR case studies
├── USER_GUIDE.md                              # Complete operator manual & troubleshooting guide
├── ABOUT.md                                   # Product vision, cyber themes & technical specs
└── tests/
    ├── test_change_detector.py                # 47 automated core unit tests
    └── test_settings_and_db.py                # 14 automated database, theme, autostart & UI tests (Total: 61 tests)
```

---

## Module Breakdown

| Module | Purpose |
|---|---|
| `main.py` | Modern Tkinter GUI, thread coordination, KPI cards, dual-ribbon toolbar, and floating desktop icon |
| `database.py` | Local encrypted SQLite3 database manager using AES-256 Fernet + Windows DPAPI key protection |
| `autostart.py` | Windows Run key (`HKCU\...\Run`) integration for silent boot auto-start (`--minimized`) |
| `theme_manager.py` | 5 high-contrast cybersecurity themes with tokenized color palettes |
| `settings_window.py` | Spacious 5-tab application settings dialog (Engine, Themes, Startup, Database, Alerts) |
| `registry_scanner.py` | Read-only registry key & value extraction across 64-bit and 32-bit views |
| `change_detector.py` | Baseline comparison, delta classification (ADDED, MODIFIED, DELETED, TYPE_CHANGED), severity |
| `file_resolver.py` | Executable path resolution, quoted path extraction, PE metadata, and SHA-256 computation |
| `visual_reporter.py` | Pillow and Pandas graphical visual reports and security risk charts |
| `alert_manager.py` | Desktop pop-up alerts, rate-limiting, threshold filtering, and deduplication |
| `report_generator.py` | JSONL telemetry logging, UTF-8 CSV exports, and executive summary reports |

---

## Visual Themes

The application includes 5 high-contrast dashboard themes:

1. **Cyber Blue Team** (Default): SOC dark console with glowing cyan and cobalt accents.
2. **Obsidian Stealth**: Minimalist deep carbon black with titanium and platinum contrast.
3. **Matrix Terminal**: Classic hacker emerald terminal with deep jade contrasts.
4. **Crimson Alert**: High-alert threat-hunting red and deep carbon gunmetal.
5. **Nordic Frost**: Deep arctic ice blue and slate with crisp white typography.

Switch themes instantly from **⚙️ App Settings > Themes & UI** or preview them before saving.

---

## Local Encrypted Database Architecture

To prevent unauthorized local users or external malware from snooping on monitored registry values, paths, or change histories, telemetry is stored in an encrypted SQLite database:

```
┌────────────────────────────────────────────────────────┐
│               Raw Registry Telemetry                   │
│      (Key paths, values, SHA-256 hashes, events)       │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│             AES-256 Authenticated Fernet               │
│          (Symmetric payload encryption)                │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│              Windows DPAPI Protection                  │
│       (CryptProtectData via crypt32.dll)               │
│   • Bound to Windows User Account SID & TPM Hardware   │
│   • Key stored in data/.security.dpapi                 │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│            SQLite3 Encrypted Storage                   │
│        (data/registry_monitor.db in WAL mode)          │
│   • Encrypted BLOB payloads for all events & baselines │
└────────────────────────────────────────────────────────┘
```

---

## Windows Auto-Start on Boot

Enable automatic monitoring whenever your computer starts:

1. Open **⚙️ App Settings** from the main dashboard.
2. Navigate to the **🚀 Windows Startup** tab.
3. Click **"🚀 Enable Auto-Start on PC Boot"**.
4. Check **"Start silently minimized to movable floating icon"** if desired.
5. The application registers its path and arguments in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.

---

## Installation & Deployment

### Option A: Standalone Executable (No Python Required)
Run the self-contained executable directly:
```cmd
dist\WindowsRegistryMonitor.exe
```

### Option B: Windows Installer Setup Package
Run the wizard-based installer:
```cmd
dist\installer\RegistryMonitorSetup.exe
```
Features of the installer:
- Installs to `C:\Program Files\Windows Registry Monitor`
- Configures proper modify permissions on the `data/` directory
- Creates Start Menu and Desktop shortcuts with custom cyber icon
- Configures complete uninstallation support

### Option C: Run from Source
Prerequisites: Python 3.10+ on Windows.
```cmd
git clone https://github.com/Made-by-Piyush99/Windows-Registry-Monitoring.git
cd Windows-Registry-Monitoring
pip install -r requirements.txt
python main.py
```

---

## Running Automated Tests

All 61 unit tests can be executed with Python's standard `unittest` framework:

```cmd
python -m unittest tests/test_settings_and_db.py tests/test_change_detector.py
```

All 61 tests run in ~3.5 seconds using mock data and do not modify the real Windows Registry.

---

## Publisher & Attribution

- **Application**: Windows Registry Change Monitoring System
- **Publisher**: MADE BY PIYUSH
- **Version**: 2.0.0
- **License**: Educational & Defensive Security Use
