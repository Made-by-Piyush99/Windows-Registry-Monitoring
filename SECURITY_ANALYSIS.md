# Windows Registry Change Monitoring System
## Threat Model, Cryptographic Architecture & Security Analysis Report

---

## 1. Executive Security Summary

The **Windows Registry Change Monitoring System** is engineered specifically for defensive operations in zero-trust, enterprise, and incident response environments. Operating under a strict **Zero-Impact Defensive Philosophy**, the application is hardened against exploitation, telemetry tampering, and privilege leakage.

### Core Security Guarantees
- **Strictly Read-Only Operations**: The engine never writes to, modifies, or deletes any monitored Windows Registry hive or key.
- **Zero Binary Execution**: Referenced executables are parsed, triaged, and hashed using cryptographic SHA-256 routines, but are **never executed, injected into, or loaded into memory**.
- **Hardware-Bound Telemetry Encryption**: All stored baselines, change logs, and forensic records are protected with AES-256 Fernet authenticated encryption, with master keys encapsulated via the **Windows Data Protection API (DPAPI)**.
- **Zero Administrative Drift**: The software does not modify operating system security policies, firewall rules, or Windows Defender configurations.

---

## 2. STRIDE Threat Model & Security Controls

The STRIDE methodology was applied during system design to evaluate attack vectors targeting both the monitored host and the monitoring application itself:

| STRIDE Threat Category | Potential Attack Vector | Applied Defensive Security Controls | Residual Risk Level |
|---|---|---|---|
| **S - Spoofing** | Attacker impersonates legitimate registry values or writes fake change events to confuse analysts. | • Deterministic event fingerprinting (`change_type\|path\|name\|view`).<br>• Local SQLite database encrypted and authenticated with HMAC-SHA256.<br>• File metadata cross-checked against actual filesystem records on disk. | **LOW** |
| **T - Tampering** | Attacker tampers with historical logs (`events.jsonl`, `registry_monitor.db`) or modifies `baseline.json` to hide persistence. | • Baseline JSON files protected by an internal SHA-256 integrity hash verification check.<br>• Telemetry stored in an AES-256 encrypted SQLite database bound to the logged-in user via Windows DPAPI.<br>• Atomic temporary-file-and-rename writes prevent corrupt state injection. | **LOW** |
| **R - Repudiation** | Attacker claims registry modifications were made by legitimate system components. | • Granular audit logging with millisecond UTC timestamps (`ISO 8601`).<br>• Full command-line tokenization capturing arguments, flags, and physical binary paths.<br>• Cryptographic SHA-256 hashing identifies exact file versions referenced. | **NEGLIGIBLE** |
| **I - Information Disclosure** | Rogue processes, unprivileged users, or forensic tools dump monitored keys or sensitive configuration data from disk. | • All stored registry telemetry payloads encrypted via AES-256 Fernet.<br>• Master key protected by Windows DPAPI (`CryptProtectData`) tied to the user's Windows Security Identifier (SID) and machine hardware.<br>• Memory cleared during garbage collection; no unencrypted temporary caches left on disk. | **NEGLIGIBLE** |
| **D - Denial of Service** | Rapid registry churn or registry flood attacks exhaust GUI memory or freeze the monitoring engine. | • Thread-safe FIFO `queue.Queue` with bounded queue capacity.<br>• Desktop alert rate-limiting (default 3s delay) and fingerprint-based deduplication.<br>• Monitoring thread runs independently in background; UI consumes events via `root.after()`. | **LOW** |
| **E - Elevation of Privilege** | Attacker leverages unquoted path vulnerabilities or command-line parser bugs in the monitoring tool to execute arbitrary code. | • Tool parses command strings with pure Python regular expressions and string splitting—**zero use of `os.system()`, `subprocess.Popen(..., shell=True)`, or `eval()`**.<br>• Inno Setup installer configures strict file permissions (`authusers-modify` only on `data/` subdirectories). | **NEGLIGIBLE** |

---

## 3. Cryptographic Deep-Dive: Local Encrypted Persistence

To solve the prevalent vulnerability where defensive monitoring tools leave plaintext telemetry logs on disk, Windows Registry Monitor v2.0 implements a multi-tier cryptographic architecture.

```
┌────────────────────────────────────────────────────────────────────────┐
│                      CRYPTOGRAPHIC TELEMETRY VAULT                     │
└────────────────────────────────────────────────────────────────────────┘

 [ Plaintext Telemetry ]
   • Event IDs, Timestamps, Delta Types
   • Registry Key Paths, Value Names & Data
   • File System Metadata & SHA-256 Hashes
             │
             ▼
 [ Serialization Engine ]
   • JSON utf-8 serialization with strict escaping
             │
             ▼
 [ Symmetric Encryption: AES-256 Fernet ]
   • Algorithm: AES-128/256 in CBC mode with PKCS7 padding
   • Integrity: HMAC-SHA256 authentication tag
   • Ephemeral Initialization Vector (IV) generated per record
             │
       Cryptographic Key
             │
             ▼
 [ Windows DPAPI Vault (crypt32.dll) ]
   • CryptProtectData / CryptUnprotectData
   • Bound to User Account SID & System TPM
   • Master Key File: data/.security.dpapi
             │
             ▼
 [ Encrypted Storage: SQLite3 WAL ]
   • Database: data/registry_monitor.db
   • High-throughput Write-Ahead Logging (PRAGMA journal_mode=WAL;)
   • Ciphertext stored as opaque SQLite BLOBs
```

### 3.1 Fernet Authenticated Encryption Pipeline
Fernet guarantees that ciphertext cannot be read, manipulated, or altered without the key:
1. **Key Generation**: A 256-bit URL-safe base64-encoded secret key is created on initialization.
2. **Encryption Mechanism**:
   $$\text{Ciphertext} = \text{Version} \parallel \text{Timestamp} \parallel \text{IV} \parallel \text{AES-CBC-256}(\text{Payload}) \parallel \text{HMAC-SHA256}(\dots)$$
3. **Authentication**: Any bit-flip or ciphertext corruption causes HMAC validation to fail, immediately throwing an `InvalidSignature` exception and preventing corrupted payload ingestion.

### 3.2 Windows DPAPI Key Isolation
The Fernet symmetric key must itself be stored securely on disk. Rather than relying on hardcoded keys, Windows Registry Monitor binds the key to the operating system's native **Data Protection API (DPAPI)**:
- **Win32 Function**: `ctypes.windll.crypt32.CryptProtectData` and `CryptUnprotectData`.
- **Security Binding**: The key is encrypted using the logged-in user's Windows Security Identifier (SID) derived from their Windows login password hash and combined with machine-specific hardware entropy (TPM / LSA master key).
- **Physical Disk Theft Protection**: If the physical drive is removed from the computer, or if another user logs onto the same machine, DPAPI will refuse to decrypt `data/.security.dpapi`, protecting all telemetry.

---

## 4. MITRE ATT&CK Mapping & Threat Detection Signatures

The detection engine continuously maps inspected registry keys to the MITRE ATT&CK framework:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        MITRE ATT&CK MATRIX MAP                         │
└────────────────────────────────────────────────────────────────────────┘

  T1547.001 (Persistence)         T1562.001 (Defense Evasion)
  HKCU/HKLM Run & RunOnce         Windows Defender & Firewall
            │                                  │
            ▼                                  ▼
  ┌──────────────────┐               ┌──────────────────┐
  │ ADDED / MODIFIED │               │ Tampering Deltas │
  └─────────┬────────┘               └─────────┬────────┘
            │                                  │
            ▼                                  ▼
  ┌─────────────────────────────────────────────────────┐
  │  Heuristic Evaluator (change_detector.py)           │
  │  • Suspicious Strings: powershell, cmd /c, mshta    │
  │  • Sensitive Categories: Defender, Firewall, UAC    │
  └─────────────────────────┬───────────────────────────┘
                            │
                            ▼
  ┌─────────────────────────────────────────────────────┐
  │  File Resolver & PE Inspector (file_resolver.py)    │
  │  • T1574.009: Unquoted Path with spaces             │
  │  • Temp execution: %TEMP%, %APPDATA%\Local\Temp     │
  │  • On-Disk Tampering: Binary modified (SHA-256)     │
  └─────────────────────────────────────────────────────┘
```

### Detailed Signature Matrix

#### 1. Persistence: Run & RunOnce Keys (T1547.001)
- **Monitored Locations**:
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
  - `HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
- **Detection Logic**: Any `ADDED` key in these categories is automatically assigned `suspicious` severity. Referenced binaries are immediately resolved, checked for existence, and hashed.

#### 2. Defense Evasion: Windows Defender & Firewall Tampering (T1562.001)
- **Monitored Locations**:
  - `HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`
  - `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`
  - `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile`
  - `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile`
  - `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile`
- **Detection Logic**: Any modification or deletion of settings such as `DisableAntiSpyware`, `DisableRealtimeMonitoring`, or `EnableFirewall` immediately triggers an `investigation_required` high-severity alert.

#### 3. Privilege Escalation: Unquoted Service Path Interception (T1574.009)
- **Vulnerability**: Command lines containing spaces without enclosing quotes (e.g., `C:\Program Files\Sub Dir\app.exe`) allow unprivileged local users with write access to parent directories to drop `C:\Program.exe` or `C:\Program Files\Sub.exe`.
- **Detection Logic**: The tokenizer analyzes executable paths, detecting spaces without enclosing quotes, flagging them as `WARNING` risk items in forensic reports.

#### 4. Execution: Living-off-the-Land Binaries (LOLBins) (T1059.001 / T1218)
- **Patterns**:
  - `powershell.exe -enc`, `-encodedcommand`, `-w hidden`
  - `cmd.exe /c`, `wscript.exe`, `cscript.exe`
  - `mshta.exe`, `regsvr32.exe /s /u /i`
  - `certutil -urlcache -split -f`, `bitsadmin /transfer`
  - Scripts with extensions `.vbs`, `.js`, `.ps1`, `.bat`
- **Detection Logic**: Scans all string data for these substrings; any match raises event severity to `suspicious`.

---

## 5. Binary On-Disk Integrity & Payload Swap Detection

Traditional registry monitors only compare registry string deltas. If an adversary compromises a system, they frequently perform a **Payload Swap Attack**:
1. The adversary leaves the registry entry intact:
   `HKCU\...\Run\Updater = "C:\Users\Alice\AppData\Local\App\updater.exe"`
2. The adversary overwrites `updater.exe` on disk with a Cobalt Strike beacon or backdoor.
3. Conventional registry monitoring tools detect **zero** registry changes and remain silent.

### The Defensive Solution
Windows Registry Monitor tracks the **cryptographic SHA-256 fingerprint** of every referenced executable:
- When a registry scan completes without registry deltas, the file resolver re-computes the on-disk SHA-256 hash.
- If the current hash does not match the baseline hash, the engine emits a specialized `FILE_MODIFIED` alert.
- If the binary is deleted from disk, a `FILE_DELETED` alert is emitted.

---

## 6. Access Control & Privilege Management

### 6.1 Administrator vs. Standard User Execution
- **Standard User**:
  - Successfully monitors all user-level hives (`HKEY_CURRENT_USER`).
  - Read access to standard `HKEY_LOCAL_MACHINE` policies.
  - Can run silently minimized with full local encrypted database support.
- **Administrator Elevation**:
  - Required for reading protected security keys (such as `HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection` and `SYSTEM\CurrentControlSet\Control\Lsa`).
  - Required for running the Inno Setup wizard installer into `%ProgramFiles%`.
- **Access-Denied Preservation Guarantee**:
  - When running without Administrator privileges, inaccessible system keys return `OSError` / `PermissionError`.
  - The scanner catches this and sets `status = "access_denied"`.
  - The delta engine **never treats an access-denied key as a deletion**, preventing false alarms when switching between user contexts.

---

## 7. Residual Risks & Hardening Recommendations

While Windows Registry Monitor v2.0 provides robust defensive visibility, operators must understand the fundamental physical boundaries of user-mode polling tools:

1. **Polling Gap Window**:
   - Because user-mode monitoring operates on a polling interval (1s to 60s), an attacker who creates a registry key, executes their payload, and deletes the key within a 200ms window will not be detected by polling.
   - *Recommendation*: For sub-millisecond kernel-level capture, deploy Sysmon (Event ID 12, 13, 14) or an enterprise EDR alongside Windows Registry Monitor.
2. **Kernel Driver Tampering**:
   - If an attacker deploys a Bring-Your-Own-Vulnerable-Driver (BYOVD) rootkit (Ring 0), they can hook `NtQueryValueKey` or hide registry keys from user-mode APIs.
   - *Recommendation*: Enable Secure Boot and Driver Signature Enforcement (DSE) across all monitored workstations.
3. **Administrator Key Revocation**:
   - A local SYSTEM or TrustedInstaller process can strip read permissions from registry keys.
   - *Recommendation*: Monitor Windows Security Event ID 4657 (A registry value was modified) via centralized SIEM forwarding.

---

*Windows Registry Change Monitoring System — Security Analysis & Threat Model*
