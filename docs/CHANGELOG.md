# Changelog — LocalSentinel

All notable changes to the LocalSentinel project are documented in this file.

## [2.0.0] - 2026-11-13 (Major Enterprise Refactoring & EDR Enhancement)

### Added
- **MITRE ATT&CK Threat Detection Engine**: Introduced `ThreatDetectionEngine` mapping telemetry to 10+ MITRE ATT&CK techniques across Process, Filesystem, Network, and USB domains.
- **Alert Management Center**: Added dedicated `Alerts` tab with severity badges, MITRE tactic/technique details, search queries, severity dropdown filtering, and remediation guidance.
- **Forensic Export Subsystem**: Implemented `ForensicExportService` with structured JSON forensic snapshot generation and RFC 4180 compliant CSV exports for all tables.
- **Asynchronous Multithreaded Processing**: Refactored collectors to run CPU- and I/O-heavy operations (file hashing, certificate validation, WMI queries, SQLite inserts) on background tasks off the UI thread.
- **UI Virtualization**: Replaced unvirtualized vertical scroll layout with high-performance tabbed navigation supporting WPF row and column recycling virtualization.
- **Universal Multi-Domain Search**: Implemented real-time text search across Process, File, Network, USB, and Security Alert tables using WPF `ICollectionView`.
- **Operator Monitoring Controls**: Added "Pause / Resume Monitoring" and "Clear Session / Wipe Database" controls.
- **Comprehensive Automated Testing Suite**: Added `LocalSentinel.Tests` containing 29 xUnit unit and integration tests covering detection heuristics, crypto hashing, database persistence, and exports (100% pass rate).
- **Comprehensive Documentation Suite**: Added `PRD.md`, `TRD.md`, `ARCHITECTURE.md`, `APP_FLOW.md`, `UI_UX_DESIGN_BRIEF.md`, `DATABASE_SCHEMA.md`, `API_SPECIFICATION.md`, `SECURITY_REQUIREMENTS.md`, `THREAT_MODEL.md`, `SECURITY_VERIFICATION_MATRIX.md`, `TESTING_STRATEGY.md`, `IMPLEMENTATION_PLAN.md`, `DEPLOYMENT_GUIDE.md`, `CI_CD_GUIDE.md`, `RISK_REGISTER.md`, `SECURITY_AUDIT_REPORT.md`, `SECURITY_FINDINGS.md`.

### Changed
- **Renamed File**: Corrected filename typo `FIleEventRecord.cs` to `FileEventRecord.cs`.
- **Database Optimization**: Migrated SQLite database to Write-Ahead Logging (`PRAGMA journal_mode = WAL`) and added performance indexes on all `Timestamp` columns.
- **Code Separation**: Decoupled monolithic 1,965-line `MainWindow.xaml.cs` into modular services (`ProcessInspectionService`, `ThreatDetectionEngine`, `ForensicExportService`, `DatabaseService`).

### Fixed
- **Semgrep SQL Injection Finding**: Fixed dynamic table name interpolation in row count queries by migrating to literal SQL queries and parameterized operations.
- **UI Freezing**: Eliminated synchronous SHA-256 calculation and WMI querying on the WPF Dispatcher thread.
- **Process Name Normalization**: Fixed `.exe` suffix handling so both bare process names and full executable names are evaluated accurately.

---

## [1.0.0] - 2026-10-07 (Initial Prototype)
- Initial prototype monitoring process IDs, filesystem changes, TCP sockets, and USB devices.
