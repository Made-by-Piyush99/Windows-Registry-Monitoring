# 🛡️ Windows Registry Monitoring System — v2.4.0 Enterprise Defensive Edition
> **Enterprise-Grade Real-Time Windows Registry Auditing & Active Threat Remediation Platform**  
> *Engineered & Built with Precision by **Piyush** (`@Made-by-Piyush99`)*

---

[![Release](https://img.shields.io/badge/Release-v2.4.0--Enterprise-00f0ff?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/Made-by-Piyush99/Windows-Registry-Monitoring/releases)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20%7C%20Server-0ea5e9?style=for-the-badge&logo=windows11&logoColor=white)](https://github.com/Made-by-Piyush99/Windows-Registry-Monitoring)
[![Tests](https://img.shields.io/badge/Automated%20Tests-65%2F65%20Passed%20(100%25)-10b981?style=for-the-badge&logo=checkmarx&logoColor=white)](https://github.com/Made-by-Piyush99/Windows-Registry-Monitoring)
[![Security](https://img.shields.io/badge/Encryption-Windows%20DPAPI-8b5cf6?style=for-the-badge&logo=auth0&logoColor=white)](https://github.com/Made-by-Piyush99/Windows-Registry-Monitoring)
[![Author](https://img.shields.io/badge/Architect-MADE%20BY%20PIYUSH-f59e0b?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Made-by-Piyush99)

---

## 🌟 Executive Overview

**Windows Registry Monitoring System v2.4.0** is a major enterprise defense release. It combines real-time registry surveillance, cryptographic baseline auditing, automated forensic file inspection, and an all-new **Active Threat Remediation Engine** that allows SOC analysts and system administrators to neutralize malicious persistence keys on-demand with zero system downtime.

---

## ⚡ What's New in v2.4.0

### 1. 🛡️ Active Threat Remediation Engine
- **One-Click Value Deletion**: Delete rogue and suspicious registry values (e.g. unauthorized startup programs, malware persistence keys, disabled Defender entries) directly from the live event log or the Forensic Inspector panel.
- **Bulk Threat Sanitization**: The new **`⚡ Auto-Clean Threats`** action identifies all un-remediated high-risk events currently in the session and prompts for safe batch removal.
- **Audit-Logged Remediation**: Every deletion is captured in SQLite with UTC timestamps, username, key path, value name, and deleted payload data for compliance records.
- **Instant UI Visual Feedback**: Neutralized threat rows turn green with a `[REMEDIATED]` badge, and the active threat counter decrements in real time.

### 2. ⏱️ Enhanced Polling Control & Direct Timing Apply
- **Dedicated "Save & Apply Timing Now" Button**: Modify polling intervals (from high-frequency 1s/2s SOC monitoring to low-impact 30s/60s scans) and apply them immediately without restarting the monitor.
- **Quick-Switch Header Badge**: Click the `⏱️ 5s Polling` badge in the application header to switch polling rates instantly via a drop-down menu.
- **Visual Card Selector**: 6 selectable interactive cards with live hover states and active-status markers.

### 3. 🖥️ Segmented Responsive Toolbar Architecture
- **Zero-Clipping Ribbon Layout**: The Operations & Control Center has been restructured into 3 dedicated ribbons:
  - **Ribbon 1 (Surveillance & Engine)**: `▶ Start Monitoring`, `⏹ Stop Monitoring`, `🔄 Rescan Registry`, `📋 Create Baseline`, `🗑 Reset Baseline`, plus prominent top-right `👻 Run in Background` and `⚙️ App Settings`.
  - **Ribbon 2 (Threat Defense & Forensics)**: `🛡️ Remediate Threat`, `⚡ Auto-Clean Threats`, `🛡️ Advanced System Monitoring`, `📊 Graphical Report`, `📁 Export Reports`.
  - **Ribbon 3 (Telemetry Filtering & Stealth)**: Real-time search entry, severity dropdown, clear button, and stealth checkboxes.
- **Glowing Teal Background Button**: `👻 Run in Background` now features a dedicated glowing teal button style (`#0d9488` with `#14b8a6` border) and instant background minimization.

### 4. 🎨 5 Pro Cyberpunk & SOC Themes
- Switch seamlessly between 5 tailor-made themes designed for dark SOC environments:
  - 🌌 **Cyber Dark** (Default — Neon cyan `#00f0ff` & emerald `#10b981`)
  - 🟢 **Matrix SOC** (High-contrast phosphor green `#00ff66`)
  - ❄️ **Nord Frost** (Clean icy arctic palette `#88c0d0`)
  - 🌅 **Solar Flare** (Warm amber `#f59e0b` & crimson alerts)
  - ☀️ **Light Minimal** (Paper white high-readability daytime mode)

### 5. 🔐 Enterprise Security & DPAPI Vault
- Webhook endpoints, API keys, and notification secrets are encrypted on-disk using the **Windows Data Protection API (DPAPI)** tied to the logged-in Windows user account.
- Zero plaintext credential leakage in configuration files or logs.

---

## 📦 Release Assets & Cryptographic Verification

| Asset File | Size | Architecture | SHA-256 Verification Checksum |
| :--- | :---: | :---: | :--- |
| **`WindowsRegistryMonitor.exe`** | `80.22 MB` | Windows x64 | `8BEE859BA0DA4527E1FEE42F4B946A21A102FB170BBFFA2724F5BDC56BD649FC` |
| **`RegistryMonitorSetup.exe`** | `81.08 MB` | Windows x64 | `61B5C2109D5B3A150D989102D8EB04AC7C6A1A51D246445C7D724E2F69E50DD7` |

> [!TIP]
> **Verify integrity in PowerShell before executing:**
> ```powershell
> Get-FileHash .\WindowsRegistryMonitor.exe -Algorithm SHA256
> ```

---

## 📸 Screenshots & Interface Showcase

| Primary Real-Time SOC Dashboard | Dynamic Polling & Interval Configuration |
| :---: | :---: |
| ![Dashboard](https://raw.githubusercontent.com/Made-by-Piyush99/Windows-Registry-Monitoring/main/assets/dashboard_main.png) | ![Settings](https://raw.githubusercontent.com/Made-by-Piyush99/Windows-Registry-Monitoring/main/assets/polling_settings.png) |

---

## 🚀 Quick Start Guide

### Option A: Portable Standalone (No Installation)
1. Download **`WindowsRegistryMonitor.exe`**.
2. Right-click and choose **Run as administrator** (required for accessing `HKEY_LOCAL_MACHINE` security keys).
3. Click **`📋 Create Baseline`** on first launch, then **`▶ Start Monitoring`**.

### Option B: Enterprise Wizard Installer
1. Download **`RegistryMonitorSetup.exe`**.
2. Run the wizard to install into `C:\Program Files\Windows Registry Monitor`.
3. Launch from the Desktop or Start Menu shortcut.

---

## 🧪 Verification & Test Coverage
- **Automated Test Suite**: `65 passed in 4.90s` (100% test pass rate)
- **Modules Verified**:
  - `test_atomic_remediation`: Value deletion, privilege denial handling, database logging.
  - `test_change_detector`: High-speed diffing, false-positive suppression, type mutations.
  - `test_timing_config`: Dynamic interval switching, bounds checking (1s - 60s).
  - `test_crypto_dpapi`: Windows DPAPI entropy verification and credential round-trip.

---

## 👤 Credits & Author

- **Lead Architect & Developer**: **Piyush** ([@Made-by-Piyush99](https://github.com/Made-by-Piyush99))
- **Repository**: [Made-by-Piyush99/Windows-Registry-Monitoring](https://github.com/Made-by-Piyush99/Windows-Registry-Monitoring)
- **License**: MIT Enterprise License
