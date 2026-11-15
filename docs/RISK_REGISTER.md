# Risk Register & Operational Mitigations — LocalSentinel EDR v2.0

## 1. Risk Matrix

| Risk ID | Risk Description | Likelihood | Impact | Severity | Mitigation Strategy | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **RISK-01** | UI thread starvation caused by SHA-256 calculation on large disk executables. | High | High | **High** | Offloaded hashing to asynchronous thread pool (`Task.Run`) and implemented concurrent in-memory caching. | **Mitigated** |
| **RISK-02** | WPF DataGrid rendering lag and high RAM consumption under thousands of rows. | High | Medium | **Medium** | Replaced unvirtualized outer ScrollViewer with tabbed layout; enabled recycling UI row virtualization. | **Mitigated** |
| **RISK-03** | SQL injection via formatted strings in telemetry logging. | Medium | High | **High** | Converted all database statements to strict parameterized queries; eliminated dynamic SQL in table counting. | **Mitigated** |
| **RISK-04** | SQLite concurrency database lock exceptions when reading while background collectors insert. | High | Medium | **Medium** | Enabled Write-Ahead Logging (`PRAGMA journal_mode = WAL`) and `PRAGMA synchronous = NORMAL`. | **Mitigated** |
| **RISK-05** | Access Denied exceptions when inspecting protected system processes (`csrss.exe`). | High | Low | **Low** | Structured `try/catch` handlers return default "Unavailable" status and prevent application crashes. | **Mitigated** |
| **RISK-06** | FileSystemWatcher event flooding during mass compilation or build activities. | High | Low | **Low** | Implemented 800ms temporal deduplication window for consecutive `Modified` events on identical file paths. | **Mitigated** |
