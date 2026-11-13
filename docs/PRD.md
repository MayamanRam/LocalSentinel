# Product Requirements Document (PRD) — LocalSentinel EDR v2.0

## 1. Executive Summary

**LocalSentinel** is an enterprise-grade, lightweight Endpoint Detection and Response (EDR) and live digital forensics monitoring agent designed for Windows endpoints. It continuously observes operating system telemetry across process execution, filesystem integrity, active network sockets, and removable USB storage devices. By combining real-time behavioral heuristics with signature analysis and the MITRE ATT&CK® matrix, LocalSentinel alerts security analysts to malicious activity while preserving forensic evidence in an optimized local SQLite database.

## 2. Business & Security Objectives

- **Local Telemetry Collection**: Provide real-time, non-intrusive visibility into Windows endpoint behavior without relying on external cloud connectivity.
- **Threat Detection**: Surface high-fidelity security alerts for evasive execution techniques (obfuscated PowerShell cradles, LOLBins abuse, shadow copy deletion, ransomware canaries, and C2 beaconing).
- **Forensic Chain of Custody**: Persist event streams into a tamper-resistant SQLite database with Write-Ahead Logging (WAL) and provide cryptographically hashed JSON and CSV export packages for SIEM ingestion.
- **SOC Operator Experience**: Deliver a responsive, high-contrast, cybersecurity-themed UI complying with WCAG 2.2 AA accessibility standards.

## 3. Target Audience & Personas

- **SOC Tier 1/2 Analysts**: Requires quick triage of endpoint anomalies, MITRE ATT&CK mapping, and actionable remediation steps.
- **Incident Responders & Digital Forensic Investigators**: Requires complete event logs, file SHA-256 hashes, Authenticode certificate status, parent-child process lineage, and RFC 4180 CSV exports.
- **Security Engineers & System Administrators**: Requires non-disruptive, performant monitoring with low CPU and memory footprint (< 1% CPU utilization on idle, responsive UI under heavy load).

## 4. Functional Requirements

### 4.1 Process Execution Monitoring
- Query running processes at 1-second intervals and detect newly spawned processes.
- Capture: PID, Process Name, Executable Path, Command Line, Parent PID, Parent Process Name.
- Compute cryptographic SHA-256 hash with thread-safe memory caching.
- Inspect Authenticode digital signatures, certificate chain trust, and signer identity.

### 4.2 File Integrity Monitoring (FIM)
- Monitor critical user directories (`Desktop`, `Documents`, `Downloads`) using asynchronous `FileSystemWatcher`.
- Record: `Created`, `Modified`, `Deleted`, `Renamed` events.
- Implement intelligent UI deduplication to prevent event flood on rapid file modifications while preserving complete raw forensic records in persistent storage.

### 4.3 Network Socket Auditing
- Inspect active TCPv4 and TCPv6 sockets using native Windows IP Helper APIs (`iphlpapi.dll`).
- Record: Protocol, Local Address/Port, Remote Address/Port, Connection State, Owning PID, and Owning Process Name.
- Detect outbound connections on known Command and Control (C2) framework ports (4444, 50050, 1337, 6667, 31337).

### 4.4 USB Storage Device Telemetry
- Monitor removable media hardware insertions and removals via Windows Management Instrumentation (WMI).
- Capture: Device Model, Serial Number, Plug-and-Play (PNP) Device ID.
- Flag newly attached devices to audit against endpoint Data Loss Prevention (DLP) policies.

### 4.5 Threat Detection & MITRE ATT&CK Mapping
- Rule-based behavioral engine evaluating telemetry against 10+ MITRE ATT&CK techniques.
- Alert attributes: Severity (Critical, High, Medium, Low, Info), Rule ID, Rule Name, Tactic, Technique ID, Target Entity, Description, Remediation Recommendation.

### 4.6 Forensics Export & Data Management
- Export full JSON snapshot report with machine metadata and SHA-256 verification hash.
- Export modular CSV files for Alerts, Process Inventory, Filesystem Changes, Network Sockets, and USB Peripherals.
- Database maintenance: Metric calculation, row counts, disk storage size, and session wipe/vacuum.

## 5. Non-Functional Requirements

- **Performance**: Zero UI stuttering during intense I/O (hashing, signature evaluation, and WMI lookups run on background thread pools).
- **Scalability**: Virtualized DataGrids handling thousands of records at 60 FPS.
- **Resilience**: Graceful error handling when encountering protected system processes (`csrss.exe`, `lsass.exe`).
- **Data Integrity**: Parameterized SQLite queries with Write-Ahead Logging (WAL) and synchronous normal pragma.
