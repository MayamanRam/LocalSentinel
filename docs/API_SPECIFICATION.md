# API & Forensic Export Specification — LocalSentinel EDR v2.0

## 1. Internal Service API Interfaces

### 1.1 Threat Detection Engine API
`ThreatDetectionEngine` provides behavioral evaluation methods for each telemetry type:

```csharp
public class ThreatDetectionEngine
{
    public List<AlertRecord> EvaluateProcessEvent(ProcessEventRecord record);
    public List<AlertRecord> EvaluateFileEvent(FileEventRecord record);
    public List<AlertRecord> EvaluateNetworkEvent(NetworkEventRecord record);
    public List<AlertRecord> EvaluateUsbEvent(UsbEventRecord record);
}
```

### 1.2 Forensic Export Service API
`ForensicExportService` provides serialization and hash computation methods:

```csharp
public static class ForensicExportService
{
    public static string ExportToJson(ForensicExportReport report, string destinationPath);
    public static string ExportAlertsToCsv(IEnumerable<AlertRecord> alerts, string destinationPath);
    public static string ExportProcessesToCsv(IEnumerable<ProcessEventRecord> records, string destinationPath);
    public static string ExportFilesToCsv(IEnumerable<FileEventRecord> records, string destinationPath);
    public static string ExportNetworkToCsv(IEnumerable<NetworkEventRecord> records, string destinationPath);
    public static string ExportUsbToCsv(IEnumerable<UsbEventRecord> records, string destinationPath);
}
```

## 2. JSON Forensic Snapshot Schema

When exporting a complete snapshot via `ExportToJson()`, the output matches the following JSON contract:

```json
{
  "ExportId": "c8f2a1b9d4e743a691b0f5e13d9a7812",
  "GeneratedAt": "2026-11-13T14:45:00.0000000Z",
  "MachineName": "SEC-OPS-HOST",
  "OperatingSystem": "Microsoft Windows NT 10.0.26300.0",
  "TotalAlerts": 1,
  "TotalProcesses": 142,
  "TotalFileEvents": 28,
  "TotalNetworkEvents": 56,
  "TotalUsbEvents": 1,
  "Alerts": [
    {
      "Id": 1,
      "Timestamp": "2026-11-13T14:42:15.1234567+05:45",
      "Severity": 4,
      "SeverityText": "Critical",
      "RuleId": "RULE-PROC-001",
      "RuleName": "Suspicious Obfuscated PowerShell Execution",
      "MitreTechniqueId": "T1059.001",
      "MitreTactic": "Execution",
      "Source": "Process",
      "Description": "PowerShell process 4412 executed with encoded or hidden download cradle flags.",
      "EntityIdentifier": "PID 4412 (powershell.exe)",
      "Remediation": "Inspect the decoded script block, terminate process if unapproved, and isolate endpoint."
    }
  ],
  "Processes": [],
  "FileEvents": [],
  "NetworkEvents": [],
  "UsbEvents": []
}
```

## 3. CSV File Formats (RFC 4180)

All CSV exports comply with RFC 4180 standards:
- UTF-8 encoding.
- Comma `,` separator.
- Fields containing commas, quotation marks, or newlines are enclosed in double quotes with embedded quotes escaped as `""`.
- Return value of export function provides the cryptographic SHA-256 integrity hash of the written file.
