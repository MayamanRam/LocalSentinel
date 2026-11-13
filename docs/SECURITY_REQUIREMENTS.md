# Security Requirements & Threat Hardening — LocalSentinel EDR v2.0

## 1. Security Engineering Objectives

LocalSentinel is designed in accordance with **OWASP ASVS**, **NIST CSF 2.0 (DE.CM - Continuous Monitoring)**, and **CIS Controls Version 8 (Control 8: Audit Log Management & Control 10: Malware Defenses)**.

## 2. Security Controls & Standards

### 2.1 Least Privilege & Safe System Queries
- LocalSentinel operates within the current user privilege context.
- When encountering protected system processes (`csrss.exe`, `lsass.exe`, `smss.exe`), the process inspection engine catches access violations and logs records with unavailable status without crashing or escalating privileges.

### 2.2 SQL Injection Prevention
- Dynamic string concatenation and string interpolation in SQL statements are strictly forbidden.
- All database write and read operations utilize parameterized queries with `@`/`$` parameters (`SqliteParameter`).
- Table name validation for row counting utilizes hardcoded switch cases to prevent SQL injection.
- Verified by **Semgrep Static Application Security Testing (SAST)** with 0 findings.

### 2.3 Secret Management & Privacy
- No hardcoded API keys, private certificates, or cleartext credentials exist within the source code.
- Data collected is minimized strictly to local execution telemetry; no personal document contents or keystrokes are recorded.

### 2.4 Cryptographic File Hashing & Non-blocking I/O
- SHA-256 calculation utilizes non-exclusive file sharing flags (`FileShare.ReadWrite | FileShare.Delete`) to avoid locking files in use by legitimate applications or triggering race conditions.
- Cryptographic hash outputs are cached in thread-safe dictionaries to prevent denial-of-service via repetitive disk read loops.
