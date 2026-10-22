# Contributing to Windows Registry Monitoring System

First off, thank you for considering contributing to the **Windows Registry Monitoring System**! Defensive security tools thrive on peer review, continuous testing, and community improvements.

---

## 🏛️ Core Architectural Invariants

When submitting pull requests or making modifications, you must adhere to the **Defensive Triad**:

1. **Zero-Execution Guarantee**:
   - The tool must **never** execute, launch, or invoke any referenced binary, script, or executable found in the registry.
   - File inspection must be strictly read-only (`os.path.isfile`, `os.stat`, chunked `hashlib.sha256`).

2. **Zero-Kernel-Dependency**:
   - Maintain pure user-mode operation via standard Win32 / `winreg` / `ctypes` bindings.
   - Do not introduce kernel drivers or unverified native hooks that could destabilize client systems.

3. **Privacy & Offline Integrity**:
   - Zero telemetry should leave the host. Do not introduce outbound network calls, cloud dependencies, or tracking pings.
   - Telemetry stored on disk must remain protected by the AES-256 and Windows DPAPI encryption pipeline.

---

## 🛠️ Development Setup

1. **Prerequisites**:
   - Python 3.10+ (Python 3.12 64-bit recommended) on Windows 10/11.
   - Git with Git LFS installed (`git lfs install`).
   - Inno Setup 7 (optional, for compiling `installer.iss`).

2. **Clone the Repository**:
   ```powershell
   git clone https://github.com/Made-by-Piyush99/Windows-Registry-Monitoring.git
   cd Windows-Registry-Monitoring
   ```

3. **Install Dependencies**:
   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

---

## 🧪 Running Automated Tests

Before submitting any Pull Request, ensure that all 61 automated unit tests pass cleanly:

```powershell
# Run the complete test suite
python -m unittest tests/test_settings_and_db.py tests/test_change_detector.py
```

Expected output:
```
Ran 61 tests in ~3.6s
OK
```

All tests execute in memory using mock registry fixtures and temporary folders; they do **not** alter the actual Windows Registry or write to real system hives.

---

## 📦 Building Standalone Executables & Installer

```powershell
# Compile the single-file executable (dist/WindowsRegistryMonitor.exe)
python build_exe.py

# Compile the Inno Setup wizard installer (dist/installer/RegistryMonitorSetup.exe)
# Requires Inno Setup 7:
& "C:\Users\$env:USERNAME\AppData\Local\Programs\Inno Setup 7\ISCC.exe" installer.iss
```

---

## 📋 Pull Request Checklist

- [ ] Code follows PEP 8 style conventions.
- [ ] No regression in existing automated tests (61/61 passing).
- [ ] New features or logic additions include corresponding unit tests in `tests/`.
- [ ] Documentation (`README.md`, `HOW_IT_WORKS.md`, `USER_GUIDE.md`) is updated to reflect any UI or configuration changes.
- [ ] Publisher attribution maintained: **MADE BY PIYUSH**.

---

*Thank you for helping keep Windows endpoints secure and transparent!*
