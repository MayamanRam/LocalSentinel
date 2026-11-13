# Detailed Security Findings & Remediation Log — LocalSentinel EDR v2.0

## 1. Overview

This document provides technical details, vulnerability reproduction steps, and verification logs for security findings identified during the security assessment of LocalSentinel.

---

### Finding ID: SEC-FIND-001
- **Vulnerability**: Potential SQL Injection via Dynamic Table Query
- **CWE**: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **OWASP Category**: A03:2021 - Injection
- **Severity**: Medium
- **Location**: `LocalSentinel/Data/DatabaseService.cs`
- **Initial Vulnerable Code**:
  ```csharp
  private static long GetRowCount(SqliteConnection connection, string tableName)
  {
      using var command = connection.CreateCommand();
      command.CommandText = $"SELECT COUNT(*) FROM {tableName};"; // Flagged by Semgrep
      object? result = command.ExecuteScalar();
      return result is long count ? count : 0;
  }
  ```
- **Remediation**:
  Replaced string interpolation with a compile-time static switch statement mapping valid table names directly to fixed SQL literals:
  ```csharp
  private static long GetRowCount(SqliteConnection connection, string tableName)
  {
      using var command = connection.CreateCommand();
      command.CommandText = tableName switch
      {
          "ProcessEvents" => "SELECT COUNT(*) FROM ProcessEvents;",
          "FileEvents" => "SELECT COUNT(*) FROM FileEvents;",
          "NetworkEvents" => "SELECT COUNT(*) FROM NetworkEvents;",
          "UsbEvents" => "SELECT COUNT(*) FROM UsbEvents;",
          "Alerts" => "SELECT COUNT(*) FROM Alerts;",
          _ => "SELECT 0;"
      };
      object? result = command.ExecuteScalar();
      return result is long count ? count : 0;
  }
  ```
- **Verification**: Verified using Semgrep rule `csharp.lang.security.sqli.csharp-sqli.csharp-sqli`. Result: **Passed (0 Findings)**.

---

### Finding ID: SEC-FIND-002
- **Vulnerability**: UI Thread Denial-of-Service via Synchronous File Hashing & WMI
- **CWE**: CWE-400 (Uncontrolled Resource Consumption)
- **Severity**: Medium
- **Location**: `LocalSentinel/MainWindow.xaml.cs` (legacy timer loops)
- **Initial Vulnerable Code**:
  ProcessTimer_Tick ran on the WPF Dispatcher thread, invoking `CalculateSha256` and WMI queries synchronously for every new process detected.
- **Remediation**:
  Moved cryptographic hashing, certificate verification, and WMI lookups to background task threads using `Task.Run` and thread-safe caches (`ConcurrentDictionary`).
- **Verification**: UI remains responsive at 60 FPS even when 50+ processes spawn simultaneously.

---

### Finding ID: SEC-FIND-003
- **Vulnerability**: Lack of Alert Persistence & Transient Forensic State
- **CWE**: CWE-778 (Insufficient Logging)
- **Severity**: Low
- **Location**: `LocalSentinel/Data/DatabaseService.cs`
- **Initial Vulnerable Code**:
  Security alerts were only counted via an in-memory session integer (`alertCount++`) without database persistence or detail logging.
- **Remediation**:
  Created a persistent `Alerts` table in SQLite storing timestamps, severity levels, MITRE ATT&CK techniques, tactics, target entities, descriptions, and remediation guidance.
- **Verification**: Verified by automated database integration tests in `DatabaseServiceTests.Alerts_CanBeInsertedAndRetrieved`.
