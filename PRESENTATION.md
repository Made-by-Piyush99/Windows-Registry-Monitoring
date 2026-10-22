# Windows Registry Change Monitoring System
## Executive Pitch Deck & Technical Presentation Guide

---

# Slide 1: Title Slide

```
================================================================================
                    WINDOWS REGISTRY MONITOR v2.0
      Defensive Security Auditing, Real-Time Forensics & Encrypted Telemetry
================================================================================
                                MADE BY PIYUSH
                    Target Platform: Windows 10 / Windows 11
================================================================================
```

### Visual Layout
- **Style**: Cyber Blue Team Theme (Dark Slate `#0b0f19` background with glowing Cyan `#38bdf8` and Cobalt `#2563eb` accents).
- **Hero Graphic**: Cyber Shield Vector Emblem with an encrypted lock badge.
- **Header**: High-contrast bold typography: *Windows Registry Change Monitoring System*.
- **Sub-header**: *Enterprise-Grade Defensive Auditing, In-Memory Delta Detection, and DPAPI-Encrypted Telemetry*.
- **Presenter Metadata**: Built by Piyush | Windows Security & Forensics Engineering.

### Key Talking Points
- Welcome stakeholders, security executives, and technical reviewers.
- Introduce the fundamental challenge: The Windows Registry is the primary battleground for threat actors seeking long-term persistence, defense evasion, and credential access.
- Present Windows Registry Monitor v2.0: A lightweight, zero-dependency, defensive security tool providing instantaneous delta detection, PE binary forensics, and machine-bound encrypted storage.

### Speaker Notes
> "Good morning/afternoon, everyone. Today I am presenting the Windows Registry Change Monitoring System v2.0. The Windows Registry contains millions of settings that govern the boot process, security software, system drivers, and user applications. When an adversary breaches a system, their first objective after initial access is establishing persistence—and the Windows Registry is their #1 choice. Today, I'll walk you through how our defensive solution continuously monitors, forensically analyzes, and cryptographically safeguards registry telemetry against sophisticated adversaries."

---

# Slide 2: The Problem: The Registry as an Adversary Playground

### Visual Layout
- **Layout**: 3-Column Split Card Layout (The Threat, The Vulnerability, The Blindspot).
- **Accents**: Crimson Red (`#f43f5e`) and Warning Amber (`#f59e0b`).
- **Icons**: ⚠️ Warning Triangle | 🕷️ Spider/Malware | 👁️ Blindspot.

### Column Content

| 1. Threat Landscape | 2. System Vulnerabilities | 3. Existing Tool Blindspots |
|---|---|---|
| **90%+ of Windows malware** establishes persistence via registry Run keys, Winlogon, or startup tasks. | Registry keys can be modified silently in milliseconds without user awareness. | Traditional AV often ignores legitimate administrative utilities (`powershell.exe`, `cmd.exe`) abusing run keys. |
| Adversaries disable Windows Defender and Firewalls directly via registry tampering. | Unquoted registry paths allow local privilege escalation via path hijacking. | Heavy EDR agents introduce substantial CPU overhead and cost thousands per endpoint. |
| Fileless payloads stash malicious base64 code directly inside registry value data. | Stored telemetry from basic monitoring tools is saved in plain text, accessible to malware. | Static registry snapshot tools lack real-time alerting and on-disk binary delta correlation. |

### Speaker Notes
> "Let's examine why the registry is so dangerous. Over 90% of documented Windows threats—from commodity ransomware to APTs—utilize registry autoruns. Even worse, malware frequently tampers with policies such as `DisableAntiSpyware` or firewall profiles before dropping payloads. Most enterprises rely on bulky EDRs that consume heavy memory or static scanners that require manual checks. Most critically, simple monitoring scripts store their logs in plaintext, creating a secondary intelligence source for attackers who compromise the disk. We needed a solution that was fast, self-contained, tamper-resistant, and completely non-intrusive."

---

# Slide 3: The Solution: Windows Registry Monitor v2.0

### Visual Layout
- **Layout**: Central Solution Hub Diagram with 4 Radial Pillars.
- **Theme**: Obsidian Stealth & Cyber Blue accents.
- **Pillars**:
  - Pillar 1: **Read-Only Non-Destructive Auditing**
  - Pillar 2: **Forensic Path & SHA-256 PE Inspection**
  - Pillar 3: **Hardware-Bound AES-256 + DPAPI Encryption**
  - Pillar 4: **Modular UI with 5 Themes & Desktop Widget**

### Feature Highlights
- **Strictly Read-Only Defensive Posture**: Never alters registry keys, never terminates system processes, and never executes untrusted binaries.
- **Sub-Second Change Detection**: Identifies `ADDED`, `MODIFIED`, `DELETED`, and `TYPE_CHANGED` keys within customizable intervals (1s to 60s).
- **On-Disk File Verification**: Automatically extracts binary paths, resolves environment variables (`%SystemRoot%`), checks file existence, and hashes referenced files with SHA-256.
- **Hardware-Tied Local Database**: Sensitive telemetry is encrypted on disk with AES-256 Fernet, protected by Windows DPAPI tied to the user's Windows SID and hardware TPM.
- **Zero-Footprint Deployment**: Compiles to an 80 MB single-file standalone executable (`WindowsRegistryMonitor.exe`) or full installer package (`RegistryMonitorSetup.exe`).

### Speaker Notes
> "Windows Registry Monitor v2.0 was designed from the ground up as a defensive auditing and forensics workstation. It strictly adheres to a read-only architecture—guaranteeing it will never destabilize an operating system or trigger false-positive system crashes. It marries lightweight real-time polling with deep PE file inspection and enterprise-grade hardware cryptography."

---

# Slide 4: MITRE ATT&CK Framework Alignment

### Visual Layout
- **Layout**: Matrix Table mapping ATT&CK Tactics, Techniques, and Defensive Detection Mechanisms.
- **Badge Accents**: Cyan, Emerald, Amber, and Ruby.

| ATT&CK Tactic | Technique ID & Name | Monitored Registry Hive / Location | Detection & Alerting Mechanism |
|---|---|---|---|
| **Persistence** | **T1547.001**: Registry Run Keys & Startup Folder | `HKCU\...\CurrentVersion\Run`<br>`HKLM\...\CurrentVersion\Run`<br>`HKLM\...\WOW6432Node\Run` | Instant `ADDED` alert, unquoted space detection, and automated SHA-256 hashing. |
| **Defense Evasion** | **T1562.001**: Disable or Modify Tools | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`<br>`HKLM\...\SharedAccess\Parameters\FirewallPolicy` | `investigation_required` critical alert on policy tampering or profile deactivation. |
| **Privilege Escalation** | **T1574.009**: Unquoted Service Path | `HKLM\SYSTEM\CurrentControlSet\Services` | Flags spaces in unquoted command lines susceptible to binary interception. |
| **Execution** | **T1059.001**: PowerShell / Script Execution | Stored values containing `powershell -enc`, `wscript`, `mshta`, `cmd /c` | Regex heuristic scanner flags suspicious script-interpreter payloads. |
| **Persistence** | **T1546**: Event Triggered Execution | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | Detects unauthorized authentication package injections. |

### Speaker Notes
> "Here you see how our detection engine maps directly to the MITRE ATT&CK matrix. We focus heavily on Technique T1547.001—the ubiquitous Run key persistence mechanism—as well as Defense Evasion T1562. When malware attempts to flip a Defender toggle, our system immediately categorizes it as 'Investigation Required' and generates an instant visual alert."

---

# Slide 5: High-Level System Architecture

### Visual Layout
- **Diagram**: Flowchart showing the 3 distinct architectural layers (Worker Thread, GUI Thread, Encrypted Persistence Layer).

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CORE APPLICATION ARCHITECTURE                   │
└────────────────────────────────────────────────────────────────────────┘

  [ BACKGROUND WORKER THREAD ]                  [ MAIN GUI THREAD ]
  ┌─────────────────────────┐               ┌─────────────────────────┐
  │  registry_scanner.py    │               │  main.py Dashboard      │
  │  (winreg 64 & 32-bit)   │               │  (Tkinter UI Loop)      │
  └────────────┬────────────┘               └────────────▲────────────┘
               │                                         │
               ▼                                         │
  ┌─────────────────────────┐                   ┌────────┴────────────┐
  │  change_detector.py     │──Thread-Safe────> │  _process_queue()   │
  │  (Delta Classification) │     Queue         │  (Every 200ms)      │
  └────────────┬────────────┘                   └────────▲────────────┘
               │                                         │
               ▼                                         │
  ┌─────────────────────────┐                            │
  │  file_resolver.py       │                            │
  │  (PE Path & SHA-256)    │                            │
  └────────────┬────────────┘                            │
               │                                         │
               ▼                                         │
  [ HARDWARE-BOUND STORAGE ]                             │
  ┌──────────────────────────────────────────────────────┴────────────┐
  │  database.py: AES-256 Fernet + Windows DPAPI Master Key           │
  │  (data/registry_monitor.db in SQLite3 WAL Journal Mode)           │
  └───────────────────────────────────────────────────────────────────┘
```

### Technical Highlights
- **Decoupled Threading**: The background monitoring thread executes periodic scans independently of the UI. Even if an operator scrolls a large table or exports a PDF, registry polling is never interrupted.
- **Queue-Based Event Handover**: Zero cross-thread Tkinter calls. Events are placed in a Python thread-safe `queue.Queue` and consumed via `root.after(200, ...)` on the main thread.
- **Dual Registry Views**: Simultaneously queries native 64-bit registry keys and 32-bit `WOW6432Node` redirected keys via `KEY_WOW64_64KEY` and `KEY_WOW64_32KEY`.

### Speaker Notes
> "Our architecture separates scanning from rendering. The background thread performs low-level winreg enumeration and pushes delta events onto a thread-safe FIFO queue. The UI thread picks up these events every 200 milliseconds. This ensures complete UI responsiveness—no freezing, no stuttering—even when tracking tens of thousands of registry values."

---

# Slide 6: Local Encrypted Database (AES-256 + Windows DPAPI)

### Visual Layout
- **Layout**: 2-Column Security Deep Dive (Cryptographic Pipeline on left, Security Benefits on right).
- **Badges**: 🔒 AES-256 Fernet | 🛡️ Windows DPAPI | ⚡ SQLite3 WAL.

```
       [ RAW TELEMETRY ]
      (Keys, Values, Hashes)
               │
               ▼
   [ AES-256 AUTHENTICATED CIPHER ]
      (Fernet Symmetric Encryption)
               │
         Protected By
               │
               ▼
   [ WINDOWS DPAPI VAULT ]
   (CryptProtectData via crypt32.dll)
   • Bound to Windows User Account SID
   • Bound to Machine Hardware & TPM
   • Master Key Stored in data/.security.dpapi
               │
               ▼
   [ ENCRYPTED SQLITE3 DATABASE ]
   (data/registry_monitor.db - WAL Mode)
```

### Key Security Benefits
1. **Anti-Snooping Guarantee**: If a rogue process, local user, or attacker reads `data/registry_monitor.db`, all event payloads and baselines appear as cryptographically random binary blobs.
2. **Hardware & User Account Isolation**: Because the decryption key is protected by Windows DPAPI, copying the database or `.security.dpapi` file to an attacker's machine renders the data completely unrecoverable.
3. **High-Performance WAL Mode**: Uses SQLite's Write-Ahead Logging mode (`PRAGMA journal_mode=WAL;`), enabling simultaneous reading and writing without database locks.
4. **Maintenance Utilities**: Integrated database defragmentation (`VACUUM`) and sanitized JSON audit export directly from the UI.

### Speaker Notes
> "Security tools often create their own vulnerabilities by storing plaintext telemetry. If an attacker gains disk read access, your security logs can tell them exactly what persistence tricks you monitor. We solved this with our Encrypted Database Manager. Telemetry payloads are encrypted with AES-256 Fernet, and the key itself is encrypted using the Windows Data Protection API (DPAPI). The data is mathematically tied to the specific Windows user account and the machine's hardware TPM."

---

# Slide 7: Real-Time Change Detection & Forensic Analysis

### Visual Layout
- **Layout**: 4-Stage Forensic Pipeline (Scan → Compare → Resolve → Classify).
- **Cards**:
  - `ADDED`: Green pill, identifies new entries.
  - `MODIFIED`: Blue pill, identifies value/data type changes.
  - `DELETED`: Red pill, identifies removed entries.
  - `TAMPERED`: Orange pill, identifies on-disk file swaps without registry changes.

### The Forensic Delta Engine
- **Full Key & Subkey Tracking**: Checks registry key paths, value names, data content, and registry data types (`REG_SZ`, `REG_DWORD`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`, `REG_BINARY`).
- **Access-Denied Preservation**: If a key exists but access is denied (e.g., protected Windows Defender keys when not running as Admin), it is classified as `access_denied` status—**never falsely reported as deleted**.
- **On-Disk Binary Monitoring**: What happens if an attacker leaves the registry value unchanged, but replaces the `.exe` file on disk with a backdoor? The system computes on-disk SHA-256 hashes and triggers an immediate `FILE_MODIFIED` alert!

### Speaker Notes
> "Our change detector does far more than string comparisons. It tracks the exact registry data types and distinguishes between true deletions and access-denied conditions. Crucially, it monitors on-disk binary integrity. If an adversary overwrites a legitimate startup executable with a trojanized version without touching the registry, our system flags the SHA-256 hash change immediately."

---

# Slide 8: Executable Resolution & PE Risk Heuristics

### Visual Layout
- **Layout**: Rule Evaluation Grid showing how raw registry strings are parsed and analyzed.

```
RAW REGISTRY VALUE:
  C:\Program Files\My App\launcher.exe -silent --token=xyz

1. COMMAND TOKENIZER (file_resolver.py)
   ├── Extracted Binary Path: C:\Program Files\My App\launcher.exe
   ├── Command Arguments:     -silent --token=xyz
   └── Parse Method:          unquoted_prefix_resolution

2. METADATA & HASHING ENGINE
   ├── Exists on Disk?        YES
   ├── File Size:             1,048,576 bytes
   ├── Last Modified:         2026-10-21 18:30:12 UTC
   └── SHA-256 Hash:          8f4e2b... (64-character hash)

3. FORENSIC RISK EVALUATION
   ├── Path Check:            WARNING (Unquoted path with spaces)
   ├── Location Check:        BENIGN (Installed in Program Files)
   └── Scripting Engine:      NO (Native Portable Executable)
```

### Risk Detection Rules
- **Unquoted Path Hijack**: Flags executables containing spaces without enclosing quotes (`T1574.009`).
- **Temporary Directory Execution**: Flags binaries executing from `%TEMP%`, `%APPDATA%\Local\Temp`, or `%USERPROFILE%\Downloads`.
- **Missing File References**: Flags registry entries pointing to non-existent binaries (indicative of uninstalled programs or dropped/deleted malware).
- **Script Interpreter Payloads**: Flags direct command execution via `cmd.exe /c`, `powershell.exe -enc`, `wscript.exe`, `cscript.exe`, or `mshta.exe`.

### Speaker Notes
> "Registry values often contain complex command lines with arguments and unquoted spaces. Our file resolver intelligently parses quotes, expands environment variables like %SystemRoot%, and isolates the executable. It then inspects the physical file on disk, calculates its SHA-256 cryptographic hash, and evaluates risks such as unquoted path vulnerabilities or binaries executing out of temporary directories."

---

# Slide 9: Modern UI: 5 High-Contrast Cyber Themes

### Visual Layout
- **Layout**: 5 Theme Showcase Cards with Color Swatches.
- **Accents**: Preview of the tokenized design architecture.

```
1. CYBER BLUE TEAM (Default SOC Console)
   [#0b0f19] Dark Navy Background  |  [#38bdf8] Electric Cyan  |  [#2563eb] Cobalt Blue
   • Designed for Security Operations Center (SOC) dark-room environments.

2. OBSIDIAN STEALTH (Titanium Carbon)
   [#09090b] Carbon Black          |  [#e4e4e7] Titanium Platinum | [#71717a] Muted Slate
   • Ultra-clean minimalist styling for executive workstations and forensic laptops.

3. MATRIX TERMINAL (Hacker Emerald)
   [#05130b] Deep Jade Black       |  [#10b981] Emerald Green    |  [#6ee7b7] Mint Text
   • High-contrast retro terminal aesthetic optimized for command-line purists.

4. CRIMSON ALERT (Threat Hunter Red)
   [#140a0c] Gunmetal Black        |  [#f43f5e] Rose Crimson     |  [#fda4af] Coral Text
   • High-intensity threat-hunting mode designed for active incident response.

5. NORDIC FROST (Arctic Ice Blue)
   [#0a1120] Deep Marine Slate     |  [#38bdf8] Glacier Blue     |  [#f1f5f9] Arctic White
   • Calming, ultra-crisp modern interface for extended analytical monitoring.
```

### Technical Implementation
- **Instant Hot-Reloading**: Applying a new theme takes effect immediately across all windows, buttons, treeviews, entry fields, and status badges without restarting the application.
- **23 Semantic Color Tokens**: Centralized in `theme_manager.py` ensuring visual consistency and contrast accessibility.

### Speaker Notes
> "In response to feedback regarding cramped and straining interfaces, we introduced a modular theme engine with 5 tailored cyber themes. Whether you're operating in a dimly lit SOC watching our default Cyber Blue Team console, hunting threats during an incident using Crimson Alert, or analyzing systems using Nordic Frost, every UI element dynamically re-renders with perfect contrast."

---

# Slide 10: De-Cluttered, Spacious Dashboard Layout

### Visual Layout
- **Layout**: Annotated UI Wireframe highlighting the ergonomic redesign.

```
┌────────────────────────────────────────────────────────────────────────┐
│ 🛡️ Windows Registry Change Monitoring System     ● RUNNING | ⏱ 5s | ⚙️ │
├────────────────────────────────────────────────────────────────────────┤
│ [ SYSTEM STATUS ]  [ TOTAL CHANGES ]  [ SUSPICIOUS ]  [ SCAN ERRORS ]  │
│    ● MONITORING             5               1               0          │
├────────────────────────────────────────────────────────────────────────┤
│ OPERATIONS: [▶ Start] [⏹ Stop] [🔄 Rescan] │ BASELINE: [📋 Create]    │
│ FORENSICS:  [🛡️ Advanced] [📊 Graphic Rep] │ PREFERENCES: [⚙️ Settings] │
├────────────────────────────────────────────────────────────────────────┤
│ Search: [________________]  Severity: [All Severities ▼]  Showing 5/5  │
├────────────────────────────────────────────────────────────────────────┤
│ Timestamp           Severity    Change Type   Registry Path            │
│ 2026-10-21 18:30    Suspicious  ADDED         HKLM\...\Run             │
│ 2026-10-21 18:32    Info        MODIFIED      HKCU\...\Policies        │
├────────────────────────────────────────────────────────────────────────┤
│ TAB 1: 🛡️ Forensics   │  TAB 2: 📜 Raw Log  │  TAB 3: 🔒 Encrypted DB   │
│ Selected: C:\Windows\System32\cmd.exe (SHA-256: e3b0c44...) [📋 Copy]  │
└────────────────────────────────────────────────────────────────────────┘
```

### Ergonomic Improvements
- **Bento Metric Scorecards**: 5 prominent scorecards with colored top accent bars and clean spacing.
- **Dual-Ribbon Operations Toolbar**: Operations (Start, Stop, Rescan, Create Baseline) separated from Forensics & Preferences (Advanced System Monitoring, Graphical Report, App Settings).
- **Segmented Search & Filter Ribbon**: Dedicated real-time text query box, severity filter dropdown, clear button, and result counter.
- **3-Tab Inspector Panel**: Tab 1 for structured cards with one-click clipboard copying, Tab 2 for raw text dumps, and Tab 3 for local encrypted database metrics and vacuum tools.

### Speaker Notes
> "We completely resolved the 'cramped and squeezed' feeling of previous builds. Notice how the top toolbar is segmented into logical operational clusters. The 5 Bento metric scorecards provide instantaneous visibility into system health, while the bottom inspector notebook offers deep forensic detail without cluttering the main event view."

---

# Slide 11: System Preferences & App Settings Dialog

### Visual Layout
- **Layout**: 5-Tab Dialog Mockup highlighting configuration controls.

```
┌─────────────────────────────────────────────────────────────────────────┐
│ System Preferences & Engine Configuration                        [X]    │
├─────────────────────────────────────────────────────────────────────────┤
│ [⏱ Engine & Timing] [🎨 Themes] [🚀 Startup] [🔒 Database] [🔔 Alerts] │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   • Polling Interval (Seconds):                                         │
│     ( ) 1s Turbo    ( ) 2s Fast    (*) 5s Standard    ( ) 10s Low CPU   │
│     ( ) 30s Periodic   ( ) 60s Hourly                                   │
│                                                                         │
│   • Registry Architecture Scans:                                        │
│     [x] Scan Native 64-bit Registry                                     │
│     [x] Scan 32-bit Redirected Keys (WOW6432Node)                       │
│                                                                         │
│   • File Integrity Checks:                                              │
│     [x] Resolve executable paths from command lines                     │
│     [x] Calculate cryptographic SHA-256 file hashes                     │
│     [x] Verify binary existence on disk                                 │
│                                                                         │
│ ─────────────────────────────────────────────────────────────────────── │
│ [🔄 Reset Defaults]                   [ Cancel ]   [ 💾 Save & Apply ] │
└─────────────────────────────────────────────────────────────────────────┘
```

### Capabilities
- **Engine Hot-Reloading**: Polling intervals updated live without restarting the background thread.
- **Windows Startup Tab**: One-click registration in HKCU Run with silent `--minimized` boot behavior.
- **Database Maintenance Tab**: View record counts, verify DPAPI key status, perform SQLite `VACUUM` defragmentation, and export decrypted audit logs.
- **Alert Controls Tab**: Set popup severity thresholds (`informational`, `suspicious`, `investigation_required`) and configure alert rate limiters.

### Speaker Notes
> "The new App Settings window provides full administrative control. Operators can tune polling frequency from a 1-second turbo mode down to 60 seconds, toggle WOW6432Node bitness scanning, configure Windows boot auto-start, and maintain the local encrypted database—all from an intuitive 5-tab interface."

---

# Slide 12: Stealth Modes & Draggable Desktop Widget

### Visual Layout
- **Layout**: 2-State Visualization (Background Mode vs. Desktop Floating Icon).
- **Visuals**: Diagram of Win32 `WS_EX_TOOLWINDOW` transformation.

```
                      [ OPERATOR CLICKS 'RUN IN BACKGROUND' ]
                                         │
                     ┌───────────────────┴───────────────────┐
                     ▼                                       ▼
        [ TASKBAR CONCEALMENT ]                 [ FLOATING DESKTOP ICON ]
     • Win32 Extended Style Applied:         • Compact, stylish floating pill:
       WS_EX_TOOLWINDOW (0x80)                 [ ● MONITORING | ⚠ 3 ]
     • WS_EX_APPWINDOW (0x40000) Stripped    • Always-on-top, borderless
     • Window removed from taskbar           • Draggable anywhere with mouse
     • Zero taskbar clutter                  • Single click restores main app
```

### Operational Use Cases
1. **Unobtrusive Background Monitoring**: Administrators can keep the system running continuously without cluttering their Windows Taskbar.
2. **Minimize to Floating Icon**: Clicking the standard Windows Minimize button (`_`) automatically conceals the window and displays the movable floating desktop widget.
3. **Movable Telemetry Widget**: Drag the small indicator widget to any screen corner; it displays live status (`MONITORING` / `STOPPED`) and badge counters for detected changes.
4. **Instant Restoration**: Double-click or right-click the widget to restore the full cybersecurity console immediately.

### Speaker Notes
> "Security monitors shouldn't clutter your everyday workflow. With our stealth background engine, minimizing the app or clicking 'Run in Background' immediately removes the application from the Windows taskbar using low-level Win32 extended window styles. In its place, a compact, draggable floating widget appears on screen, showing live monitoring status and alert counters. Click it once, and the full application restores instantly."

---

# Slide 13: High-Resolution Graphical Visual Reports (Pillow + Pandas)

### Visual Layout
- **Layout**: Infographic Preview showcasing generated visual PNG reports.
- **Specs**: 1350x960 and 1380x980 high-resolution canvases.

```
┌────────────────────────────────────────────────────────────────────────┐
│ 🛡️ WINDOWS REGISTRY MONITOR — FORENSIC TELEMETRY INFOGRAPHIC          │
├────────────────────────────────────────────────────────────────────────┤
│ [ TOTAL EVENTS: 14 ]   [ SUSPICIOUS: 3 ]   [ TAMPERING: 1 ]   [ OK: 10 ]│
├──────────────────────────────────┬─────────────────────────────────────┤
│      SEVERITY BREAKDOWN          │         CHANGE TYPE ANALYSIS        │
│       (Donut Chart)              │          (Horizontal Bars)          │
│     Investigate: 1 (7.1%)        │   ADDED:       ████████ 8 (57.1%)   │
│     Suspicious:  3 (21.4%)       │   MODIFIED:    ████ 4 (28.6%)       │
│     Info:       10 (71.4%)       │   DELETED:     ██ 2 (14.3%)         │
├──────────────────────────────────┴─────────────────────────────────────┤
│ NOTABLE FORENSIC EVENTS (TOP INCIDENTS TABLE)                          │
│ Timestamp   Severity      Location           Value        Binary       │
│ 18:30:00    Suspicious    HKLM\...\Run       Backdoor     powershell   │
│ 18:32:15    Investigate   HKLM\...\Defender  DisableAV    REG_DWORD:1  │
└────────────────────────────────────────────────────────────────────────┘
```

### Visual Engine Capabilities
- **Pandas Data Structuring**: Real-time aggregation of event frequencies, severity ratios, and file risk profiles.
- **Pillow (`PIL`) Rendering**: Publication-ready graphical canvases with antialiased donut charts, proportion bars, and clean data tables.
- **In-GUI Image Viewer**: Inspect reports directly within the application with dynamic zoom controls (+25% / -25%), fit-width auto-scaling, and one-click opening in Windows default image viewers.

### Speaker Notes
> "Numbers in text logs can be hard to present to management. We built a native visual reporting engine using Pillow and Pandas that automatically compiles high-resolution infographics. The reports feature severity donut charts, change-type distribution bars, and structured incident tables—complete with an interactive in-GUI zoom viewer and PNG export."

---

# Slide 14: Automated Test Suite & Reliability Engineering

### Visual Layout
- **Layout**: Test Execution Summary Card with Green Checkmarks.
- **Metric**: **61 Automated Unit Tests | 100% Pass Rate | ~3.5s Execution**.

```
================================================================================
                    AUTOMATED TEST SUITE EXECUTION SUMMARY
================================================================================
Test Module 1: tests/test_change_detector.py .................... [47 PASS]
  • Registry enumeration & access-denied handling
  • Delta detection (ADDED, MODIFIED, DELETED, TYPE_CHANGED)
  • On-disk PE file modification detection (SHA-256 mismatch)
  • Command line tokenizer, unquoted spaces & %TEMP% heuristics
  • Desktop floating widget lifecycle & Win32 taskbar concealment
  • Pillow/Pandas graphical visual report generation

Test Module 2: tests/test_settings_and_db.py .................... [14 PASS]
  • AES-256 Fernet payload encryption & decryption cycles
  • Windows DPAPI key derivation, TPM binding & fallback logic
  • SQLite3 WAL persistence, event insertion & baseline queries
  • Database VACUUM defragmentation & sanitized JSON export
  • Windows Run registry key autostart command formatting
  • 5-theme color token completeness (23 tokens across 5 palettes)
  • AppSettingsWindow UI state persistence & thread interval hot-reload
--------------------------------------------------------------------------------
TOTAL SUITE: 61 TESTS PASSED | 0 FAILURES | 0 ERRORS | TIME: 3.874s
================================================================================
```

### Reliability Principles
- **Hermetic Unit Testing**: Tests use in-memory and temporary mock data structures—**zero modifications to the host Windows Registry**.
- **Cross-View Testing**: Validates that 64-bit and 32-bit registry redirection operates properly across test iterations.

### Speaker Notes
> "Quality and stability are essential when running on production Windows endpoints. Our test suite includes 61 automated unit tests covering every single component—from winreg parsing and delta calculation to AES-256 encryption, DPAPI recovery, theme tokens, and visual report rendering. The entire test suite completes in under 4 seconds with a 100% pass rate."

---

# Slide 15: Enterprise Deployment & Distribution

### Visual Layout
- **Layout**: 2 Distribution Paths (Standalone Executable vs. Windows Setup Installer).
- **Badges**: 📦 PyInstaller Standalone | 🛠️ Inno Setup 7 Installer.

| Feature | Option A: Standalone Executable | Option B: Wizard Setup Installer |
|---|---|---|
| **Binary File** | `dist\WindowsRegistryMonitor.exe` | `dist\installer\RegistryMonitorSetup.exe` |
| **File Size** | **80.20 MB** | **81.05 MB** |
| **Prerequisites** | None (Python runtime bundled) | None (Single installer package) |
| **Installation Path** | Portable (Runs anywhere: USB, Desktop) | `C:\Program Files\Windows Registry Monitor` |
| **Shortcuts** | None (Direct launch) | Desktop & Start Menu Program Group |
| **Privileges** | Standard User or Administrator | Administrator (Configures ACL permissions) |
| **Uninstaller** | Delete file | Standard Windows Control Panel Uninstaller |
| **Attribution** | Built by Piyush | **MADE BY PIYUSH** (Registered Publisher) |

### Enterprise Readiness
- **Frozen Path Bootstrap**: Automatically extracts default configuration files next to the executable if not present.
- **Multi-User Directory Permissions**: The Inno Setup installer configures `authusers-modify` permissions on `{app}\data` so non-elevated user accounts can still write to encrypted databases and logs.

### Speaker Notes
> "For distribution, we offer two ready-to-use binaries. Option A is a portable 80 MB single-file executable that requires zero installation—perfect for incident response USB drives. Option B is a modern Inno Setup 7 installer that places the system into Program Files, registers shortcuts, configures directory permissions, and provides clean Windows uninstallation."

---

# Slide 16: Summary & Live Demonstration Walkthrough

### Visual Layout
- **Layout**: 4-Step Live Demo Checklist & Value Proposition Summary.
- **Accents**: Cyber Blue Glow & Bold Call-To-Action.

### Live Demonstration Sequence
1. **Launch**: Double-click `dist\WindowsRegistryMonitor.exe` — observe immediate appearance of the Cyber Blue console with zero black terminal flashes.
2. **Settings**: Open `⚙️ App Settings` — demonstrate switching to `Matrix Terminal` theme and setting polling to 2s Turbo.
3. **Baseline**: Click `📋 Create Baseline` — show 45+ values captured and saved to the encrypted SQLite database.
4. **Detection Simulation**: Add a benign key or run a rescan — observe instantaneous scorecard counter increments and forensic inspector card population.
5. **Stealth**: Click `👻 Run in Background` — observe taskbar icon vanish and floating desktop widget appear; drag it with the mouse and click to restore.
6. **Reporting**: Click `📊 Graphical Report` — inspect the rendered high-resolution PNG in the built-in zoom viewer.

### Conclusion & Q&A
- **Comprehensive Protection**: Bridges the gap between static scripts and expensive EDR tools.
- **Privacy & Security**: Encrypted database guarantees telemetry confidentiality.
- **Production Ready**: Fully tested, documented, and compiled.

```
================================================================================
                          THANK YOU!
               QUESTIONS, FEEDBACK & LIVE AUDIT DEMO
================================================================================
```

### Speaker Notes
> "To summarize, the Windows Registry Change Monitoring System v2.0 delivers proactive defensive auditing, PE binary forensics, and hardware-encrypted persistence in a lightweight, beautiful package. I'd now like to transition into our live demonstration. Thank you, and I look forward to your questions."

---
*Windows Registry Change Monitoring System — Presentation & Pitch Deck Reference*
