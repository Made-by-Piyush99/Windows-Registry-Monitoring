# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| 1.x     | :x:                |

---

## Reporting a Vulnerability

The **Windows Registry Monitoring System** is a defensive security utility designed to operate in sensitive environments. We treat all security considerations with the highest priority.

If you discover a security vulnerability, privilege leak, cryptographic bypass, or unintended execution risk in this codebase:

1. **Do NOT open a public GitHub Issue.**
2. Send an email with reproduction details, crash dumps, or proof-of-concept steps to the project architect:
   - **Architect:** Piyush (MADE BY PIYUSH)
   - Subject: `[SECURITY] Windows Registry Monitoring System Vulnerability Report`
3. We will acknowledge receipt within 48 hours and work on a verified patch.

---

## Security Principles of this Project

- **Read-Only Operation**: The application strictly interrogates registry keys and on-disk files in read-only mode.
- **Zero-Execution Guarantee**: Referenced paths, scripts, and binaries are never executed.
- **Cryptographic Enclaves**: All local event telemetry is encrypted at rest using AES-256 (Fernet) with keys secured via Windows DPAPI and hardware TPM 2.0.
