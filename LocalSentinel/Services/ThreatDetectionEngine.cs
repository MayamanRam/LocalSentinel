using LocalSentinel.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace LocalSentinel.Services
{
    public class ThreatDetectionEngine
    {
        private static readonly HashSet<string> RansomwareExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".locked", ".crypto", ".crypted", ".enc", ".wnry", ".wannacry",
            ".locky", ".phobos", ".dharma", ".makop", ".blackcat", ".alphv"
        };

        private static readonly HashSet<int> SuspiciousC2Ports = new()
        {
            4444,   // Metasploit Default
            50050,  // Cobalt Strike Default TeamServer
            1337,   // Classic backdoor port
            31337,  // Elite backdoor port
            6667    // IRC Botnet
        };

        private static readonly HashSet<string> OfficeAndReaderProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "winword", "excel", "powerpnt", "outlook", "acrord32", "acrobat"
        };

        private static readonly HashSet<string> ShellProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "bash"
        };

        private readonly string tempDirectory;
        private readonly string downloadsDirectory;
        private readonly string startupDirectory;

        public ThreatDetectionEngine()
        {
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            tempDirectory = Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            downloadsDirectory = Path.Combine(userProfile, "Downloads");
            startupDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                @"Microsoft\Windows\Start Menu\Programs\Startup"
            );
        }

        // Custom directory constructor for unit testing
        public ThreatDetectionEngine(string testTempDir, string testDownloadsDir, string testStartupDir)
        {
            tempDirectory = testTempDir;
            downloadsDirectory = testDownloadsDir;
            startupDirectory = testStartupDir;
        }

        private static string NormalizeProcessName(string? name)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                return string.Empty;
            }

            string trimmed = name.Trim();
            return trimmed.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                ? trimmed.Substring(0, trimmed.Length - 4).ToLowerInvariant()
                : trimmed.ToLowerInvariant();
        }

        public List<AlertRecord> EvaluateProcessEvent(ProcessEventRecord record)
        {
            List<AlertRecord> alerts = new();

            if (record == null)
            {
                return alerts;
            }

            string procLower = NormalizeProcessName(record.ProcessName);
            string cmdLine = record.CommandLine ?? "";
            string cmdLineLower = cmdLine.ToLowerInvariant();
            string execPath = record.ExecutablePath ?? "";

            // RULE-PROC-001: Suspicious PowerShell Obfuscation or Web Download
            if (procLower.Contains("powershell") || procLower.Contains("pwsh"))
            {
                bool hasEncoded = cmdLineLower.Contains("-enc ") ||
                                 cmdLineLower.Contains("-encodedcommand ") ||
                                 cmdLineLower.Contains("-e ");
                bool hasHidden = cmdLineLower.Contains("-w hidden") ||
                                cmdLineLower.Contains("-windowstyle hidden");
                bool hasDownload = cmdLineLower.Contains("downloadstring") ||
                                  cmdLineLower.Contains("downloadfile") ||
                                  cmdLineLower.Contains("invoke-webrequest") ||
                                  cmdLineLower.Contains("iwr ") ||
                                  cmdLineLower.Contains("iex ") ||
                                  cmdLineLower.Contains("invoke-expression");

                if (hasEncoded || (hasHidden && hasDownload))
                {
                    alerts.Add(new AlertRecord
                    {
                        Timestamp = DateTime.Now,
                        Severity = hasEncoded ? AlertSeverity.Critical : AlertSeverity.High,
                        RuleId = "RULE-PROC-001",
                        RuleName = "Suspicious Obfuscated PowerShell Execution",
                        MitreTechniqueId = "T1059.001",
                        MitreTactic = "Execution",
                        Source = "Process",
                        Description = $"PowerShell process {record.ProcessId} executed with encoded or hidden download cradle flags.",
                        EntityIdentifier = $"PID {record.ProcessId} ({record.ProcessName})",
                        Remediation = "Inspect the decoded script block, terminate process if unapproved, and isolate endpoint."
                    });
                }
            }

            // RULE-PROC-002: LOLBins Abuse
            if (procLower == "certutil" || procLower == "certutil.exe")
            {
                if (cmdLineLower.Contains("-urlcache") || cmdLineLower.Contains("-split"))
                {
                    alerts.Add(new AlertRecord
                    {
                        Timestamp = DateTime.Now,
                        Severity = AlertSeverity.High,
                        RuleId = "RULE-PROC-002",
                        RuleName = "Living-off-the-Land Binary (LOLBin) Abuse - Certutil Ingress Tool",
                        MitreTechniqueId = "T1105",
                        MitreTactic = "Command and Control",
                        Source = "Process",
                        Description = $"Certutil was invoked with download flags: '{cmdLine}'",
                        EntityIdentifier = $"PID {record.ProcessId} (certutil)",
                        Remediation = "Certutil downloading remote files is a common ingress technique. Quarantine downloaded artifacts."
                    });
                }
            }
            else if (procLower == "mshta" || procLower == "mshta.exe")
            {
                if (cmdLineLower.Contains("http:") || cmdLineLower.Contains("https:") || cmdLineLower.Contains("vbscript:"))
                {
                    alerts.Add(new AlertRecord
                    {
                        Timestamp = DateTime.Now,
                        Severity = AlertSeverity.High,
                        RuleId = "RULE-PROC-002",
                        RuleName = "Living-off-the-Land Binary (LOLBin) Abuse - Mshta Remote Script",
                        MitreTechniqueId = "T1218.005",
                        MitreTactic = "Defense Evasion",
                        Source = "Process",
                        Description = $"Mshta executed inline script or remote payload: '{cmdLine}'",
                        EntityIdentifier = $"PID {record.ProcessId} (mshta)",
                        Remediation = "Terminate mshta process immediately and check network connections."
                    });
                }
            }

            // RULE-PROC-003: Inhibiting System Recovery (Shadow Copy Deletion)
            if (cmdLineLower.Contains("delete shadows") ||
                (procLower.Contains("vssadmin") && cmdLineLower.Contains("delete")) ||
                (procLower.Contains("wmic") && cmdLineLower.Contains("shadowcopy delete")) ||
                (procLower.Contains("bcdedit") && cmdLineLower.Contains("ignoreallfailures")))
            {
                alerts.Add(new AlertRecord
                {
                    Timestamp = DateTime.Now,
                    Severity = AlertSeverity.Critical,
                    RuleId = "RULE-PROC-003",
                    RuleName = "Inhibiting System Recovery / Shadow Copy Deletion",
                    MitreTechniqueId = "T1490",
                    MitreTactic = "Impact",
                    Source = "Process",
                    Description = $"Command attempt detected to delete volume shadow copies: '{cmdLine}'",
                    EntityIdentifier = $"PID {record.ProcessId} ({record.ProcessName})",
                    Remediation = "Ransomware pre-cursor detected! Immediate endpoint containment advised."
                });
            }

            // RULE-PROC-004: Untrusted or Unsigned Binary in Downloads / Temp
            if (!string.IsNullOrWhiteSpace(execPath))
            {
                bool inDownloads = !string.IsNullOrWhiteSpace(downloadsDirectory) &&
                                   execPath.StartsWith(downloadsDirectory, StringComparison.OrdinalIgnoreCase);
                bool inTemp = !string.IsNullOrWhiteSpace(tempDirectory) &&
                              execPath.StartsWith(tempDirectory, StringComparison.OrdinalIgnoreCase);

                if (inDownloads || inTemp)
                {
                    bool weakSignature = record.SignatureStatus == "Unsigned" ||
                                         record.SignatureStatus == "Unavailable" ||
                                         !record.SignatureTrusted;

                    if (weakSignature)
                    {
                        alerts.Add(new AlertRecord
                        {
                            Timestamp = DateTime.Now,
                            Severity = AlertSeverity.Medium,
                            RuleId = "RULE-PROC-004",
                            RuleName = "Untrusted Binary Execution from Staging Directory",
                            MitreTechniqueId = "T1204.002",
                            MitreTactic = "Execution",
                            Source = "Process",
                            Description = $"Unsigned or untrusted binary '{record.ProcessName}' executed from {(inDownloads ? "Downloads" : "Temp")} folder.",
                            EntityIdentifier = execPath,
                            Remediation = "Verify application publisher and compute SHA-256 hash for threat intelligence lookup."
                        });
                    }
                }

                // RULE-PROC-005: Masquerading / Double Extension (.pdf.exe, .doc.exe, etc.)
                string fileName = Path.GetFileName(execPath).ToLowerInvariant();
                if (fileName.EndsWith(".pdf.exe") || fileName.EndsWith(".doc.exe") ||
                    fileName.EndsWith(".docx.exe") || fileName.EndsWith(".xlsx.exe") ||
                    fileName.EndsWith(".zip.exe"))
                {
                    alerts.Add(new AlertRecord
                    {
                        Timestamp = DateTime.Now,
                        Severity = AlertSeverity.High,
                        RuleId = "RULE-PROC-005",
                        RuleName = "Masquerading Double Extension Binary",
                        MitreTechniqueId = "T1036.007",
                        MitreTactic = "Defense Evasion",
                        Source = "Process",
                        Description = $"Executable has a deceptive double extension '{fileName}'.",
                        EntityIdentifier = execPath,
                        Remediation = "Quarantine binary; deceptive extensions are used to trick users into running malware."
                    });
                }
            }

            // RULE-PROC-006: Suspicious Parent-Child Process Relationship
            if (!string.IsNullOrWhiteSpace(record.ParentProcessName))
            {
                string parentLower = NormalizeProcessName(record.ParentProcessName);
                if (OfficeAndReaderProcesses.Contains(parentLower) && ShellProcesses.Contains(procLower))
                {
                    alerts.Add(new AlertRecord
                    {
                        Timestamp = DateTime.Now,
                        Severity = AlertSeverity.High,
                        RuleId = "RULE-PROC-006",
                        RuleName = "Suspicious Shell Spawned by Office / Document Reader",
                        MitreTechniqueId = "T1059.003",
                        MitreTactic = "Execution",
                        Source = "Process",
                        Description = $"Office application '{record.ParentProcessName}' spawned command interpreter '{record.ProcessName}'.",
                        EntityIdentifier = $"PID {record.ProcessId} spawned by {record.ParentProcessName} (PID {record.ParentProcessId})",
                        Remediation = "Common macro or exploit weaponization. Kill child process tree and inspect source document."
                    });
                }
            }

            return alerts;
        }

        public List<AlertRecord> EvaluateFileEvent(FileEventRecord record)
        {
            List<AlertRecord> alerts = new();

            if (record == null)
            {
                return alerts;
            }

            string fullPath = record.FullPath ?? "";
            string ext = Path.GetExtension(fullPath);

            // RULE-FILE-001: Ransomware extension canary
            if (!string.IsNullOrWhiteSpace(ext) && RansomwareExtensions.Contains(ext))
            {
                alerts.Add(new AlertRecord
                {
                    Timestamp = DateTime.Now,
                    Severity = AlertSeverity.Critical,
                    RuleId = "RULE-FILE-001",
                    RuleName = "Potential Ransomware Activity (Known Ransomware Extension)",
                    MitreTechniqueId = "T1486",
                    MitreTactic = "Impact",
                    Source = "FileSystem",
                    Description = $"File operation '{record.EventType}' observed on file with known ransomware extension: {record.FileName}",
                    EntityIdentifier = fullPath,
                    Remediation = "Isolate host immediately and verify active processes encrypting files."
                });
            }

            // RULE-FILE-002: File created in Startup folder
            if (!string.IsNullOrWhiteSpace(startupDirectory) &&
                fullPath.StartsWith(startupDirectory, StringComparison.OrdinalIgnoreCase) &&
                (record.EventType == "Created" || record.EventType == "Renamed"))
            {
                alerts.Add(new AlertRecord
                {
                    Timestamp = DateTime.Now,
                    Severity = AlertSeverity.High,
                    RuleId = "RULE-FILE-002",
                    RuleName = "Persistence Mechanism via Startup Directory",
                    MitreTechniqueId = "T1547.001",
                    MitreTactic = "Persistence",
                    Source = "FileSystem",
                    Description = $"New startup item detected in user Startup folder: {record.FileName}",
                    EntityIdentifier = fullPath,
                    Remediation = "Verify whether this startup item is authorized; remove unauthorized persistence items."
                });
            }

            return alerts;
        }

        public List<AlertRecord> EvaluateNetworkEvent(NetworkEventRecord record)
        {
            List<AlertRecord> alerts = new();

            if (record == null)
            {
                return alerts;
            }

            // RULE-NET-001: Connection to known C2 port
            if (SuspiciousC2Ports.Contains(record.RemotePort))
            {
                alerts.Add(new AlertRecord
                {
                    Timestamp = DateTime.Now,
                    Severity = AlertSeverity.High,
                    RuleId = "RULE-NET-001",
                    RuleName = "Suspicious Outbound Port Associated with C2 Frameworks",
                    MitreTechniqueId = "T1071",
                    MitreTactic = "Command and Control",
                    Source = "Network",
                    Description = $"Process '{record.ProcessName ?? "Unknown"}' connected to suspicious port {record.RemotePort} on {record.RemoteAddress}.",
                    EntityIdentifier = $"{record.RemoteAddress}:{record.RemotePort}",
                    Remediation = "Block remote IP address, inspect process memory and command line for beaconing activity."
                });
            }

            // RULE-NET-002: Scripting interpreter opening outbound network socket
            if (!string.IsNullOrWhiteSpace(record.ProcessName))
            {
                string proc = NormalizeProcessName(record.ProcessName);
                if ((ShellProcesses.Contains(proc) || proc.Contains("powershell") || proc.Contains("pwsh") || proc.Contains("cmd") || proc.Contains("mshta")) &&
                    record.RemoteAddress != "127.0.0.1" && record.RemoteAddress != "::1" && !record.RemoteAddress.StartsWith("0.0.0.0"))
                {
                    alerts.Add(new AlertRecord
                    {
                        Timestamp = DateTime.Now,
                        Severity = AlertSeverity.Medium,
                        RuleId = "RULE-NET-002",
                        RuleName = "Script Interpreter Outbound Network Socket",
                        MitreTechniqueId = "T1071.001",
                        MitreTactic = "Command and Control",
                        Source = "Network",
                        Description = $"Shell/Script host '{record.ProcessName}' (PID {record.ProcessId}) opened outbound socket to {record.RemoteAddress}:{record.RemotePort}.",
                        EntityIdentifier = $"{record.ProcessName} -> {record.RemoteAddress}:{record.RemotePort}",
                        Remediation = "Verify if command-line tool is running legitimate automated administration or downloading payloads."
                    });
                }
            }

            return alerts;
        }

        public List<AlertRecord> EvaluateUsbEvent(UsbEventRecord record)
        {
            List<AlertRecord> alerts = new();

            if (record == null)
            {
                return alerts;
            }

            if (record.EventType.Equals("Connected", StringComparison.OrdinalIgnoreCase))
            {
                alerts.Add(new AlertRecord
                {
                    Timestamp = DateTime.Now,
                    Severity = AlertSeverity.Low,
                    RuleId = "RULE-USB-001",
                    RuleName = "Removable Storage Device Attached",
                    MitreTechniqueId = "T1200",
                    MitreTactic = "Initial Access",
                    Source = "USB",
                    Description = $"Removable storage device '{record.DeviceName}' (S/N: {record.SerialNumber ?? "Unknown"}) attached to system.",
                    EntityIdentifier = record.DeviceName,
                    Remediation = "Audit device serial number against endpoint DLP and peripheral access authorization policies."
                });
            }

            return alerts;
        }
    }
}
