# Security Verification Matrix & MITRE ATT&CK® Mapping — LocalSentinel EDR v2.0

## 1. MITRE ATT&CK Matrix Coverage

| Rule ID | Rule Name | MITRE Technique | Tactic | Severity | Automated Test Verification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **RULE-PROC-001** | Suspicious Obfuscated PowerShell Execution | T1059.001 | Execution | **Critical** | `EvaluateProcessEvent_Detects_ObfuscatedPowerShell_EncodedCommand` |
| **RULE-PROC-001** | Hidden Download Cradle Execution | T1059.001 | Execution | **High** | `EvaluateProcessEvent_Detects_HiddenDownloadCradle` |
| **RULE-PROC-002** | LOLBin Abuse — Certutil Ingress Tool | T1105 / T1218 | Command & Control | **High** | `EvaluateProcessEvent_Detects_CertutilIngressAbuse` |
| **RULE-PROC-002** | LOLBin Abuse — Mshta Remote Script | T1218.005 | Defense Evasion | **High** | `EvaluateProcessEvent_Detects_MshtaRemoteScript` |
| **RULE-PROC-003** | Inhibit Recovery / Shadow Copy Deletion | T1490 | Impact | **Critical** | `EvaluateProcessEvent_Detects_ShadowCopyDeletion` |
| **RULE-PROC-004** | Untrusted Binary Execution in Staging | T1204.002 | Execution | **Medium** | `EvaluateProcessEvent_Detects_UnsignedBinaryInDownloads` |
| **RULE-PROC-005** | Masquerading Double Extension Binary | T1036.007 | Defense Evasion | **High** | `EvaluateProcessEvent_Detects_MasqueradingDoubleExtension` |
| **RULE-PROC-006** | Office Application Spawning Command Shell | T1059.003 | Execution | **High** | `EvaluateProcessEvent_Detects_OfficeSpawningShell` |
| **RULE-FILE-001** | Ransomware Known Extension Canary | T1486 | Impact | **Critical** | `EvaluateFileEvent_Detects_RansomwareExtension` |
| **RULE-FILE-002** | Persistence via Startup Folder Dropper | T1547.001 | Persistence | **High** | `EvaluateFileEvent_Detects_StartupFolderPersistence` |
| **RULE-NET-001** | Suspicious C2 Port Connection | T1071 | Command & Control | **High** | `EvaluateNetworkEvent_Detects_C2PortConnection` |
| **RULE-NET-002** | Script Interpreter Outbound Socket | T1071.001 | Command & Control | **Medium** | `EvaluateNetworkEvent_Detects_PowerShellOutboundSocket` |
| **RULE-USB-001** | Removable USB Storage Hardware Attachment | T1200 / T1091 | Initial Access | **Low** | `EvaluateUsbEvent_Detects_RemovableStorageAttached` |

## 2. Security Test Execution Summary

- **Total Test Cases**: 29 automated tests.
- **Passing Rate**: 100% (29 passed, 0 failed, 0 skipped).
- **SAST Tool**: Semgrep Community Ruleset (84 security rules executed across 204 files).
- **SAST Result**: 0 findings, 0 blocking issues.
- **Dependency Scan**: `dotnet list package --vulnerable` reported 0 vulnerable packages.
