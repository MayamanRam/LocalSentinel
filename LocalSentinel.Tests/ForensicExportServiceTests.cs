using LocalSentinel.Models;
using LocalSentinel.Services;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using Xunit;

namespace LocalSentinel.Tests
{
    public class ForensicExportServiceTests : IDisposable
    {
        private readonly List<string> tempFiles = new();

        private string GetTempFilePath(string ext)
        {
            string path = Path.Combine(Path.GetTempPath(), $"ForensicExportTest_{Guid.NewGuid():N}.{ext}");
            tempFiles.Add(path);
            return path;
        }

        public void Dispose()
        {
            foreach (var path in tempFiles)
            {
                try
                {
                    if (File.Exists(path))
                    {
                        File.Delete(path);
                    }
                }
                catch
                {
                    // Ignore cleanup issues
                }
            }
        }

        [Fact]
        public void ExportToJson_ProducesValidJson_AndComputesValidSha256()
        {
            string exportPath = GetTempFilePath("json");
            var report = new ForensicExportReport
            {
                TotalAlerts = 1,
                TotalProcesses = 1,
                Alerts = new List<AlertRecord>
                {
                    new AlertRecord
                    {
                        Id = 1,
                        RuleId = "RULE-PROC-001",
                        RuleName = "Encoded PowerShell",
                        Severity = AlertSeverity.Critical,
                        Description = "Dangerous encoded string detected"
                    }
                },
                Processes = new List<ProcessEventRecord>
                {
                    new ProcessEventRecord
                    {
                        Id = 1,
                        ProcessName = "powershell.exe",
                        ProcessId = 1234
                    }
                }
            };

            string hash = ForensicExportService.ExportToJson(report, exportPath);

            Assert.True(File.Exists(exportPath));
            Assert.False(string.IsNullOrWhiteSpace(hash));
            Assert.Equal(64, hash.Length); // Valid SHA-256 hex length

            string jsonContent = File.ReadAllText(exportPath);
            using var doc = JsonDocument.Parse(jsonContent);
            var root = doc.RootElement;

            Assert.Equal(1, root.GetProperty("TotalAlerts").GetInt32());
            Assert.Equal(1, root.GetProperty("TotalProcesses").GetInt32());
            Assert.NotEmpty(root.GetProperty("ExportId").GetString()!);
        }

        [Fact]
        public void ExportAlertsToCsv_ProducesRFC4180EscapedCsv()
        {
            string exportPath = GetTempFilePath("csv");
            var alerts = new List<AlertRecord>
            {
                new AlertRecord
                {
                    Id = 10,
                    Severity = AlertSeverity.High,
                    RuleId = "RULE-TEST-01",
                    RuleName = "Comma, and \"Quote\" Rule",
                    MitreTechniqueId = "T1059",
                    MitreTactic = "Execution",
                    Source = "Process",
                    EntityIdentifier = "PID 999",
                    Description = "Line 1\nLine 2 description with, comma",
                    Remediation = "Verify and eliminate"
                }
            };

            string hash = ForensicExportService.ExportAlertsToCsv(alerts, exportPath);

            Assert.True(File.Exists(exportPath));
            Assert.Equal(64, hash.Length);

            string[] lines = File.ReadAllLines(exportPath);
            Assert.True(lines.Length >= 2);
            Assert.StartsWith("Id,Timestamp,Severity", lines[0]);
            // Check that quotes and commas were escaped properly
            string data = File.ReadAllText(exportPath);
            Assert.Contains("\"Comma, and \"\"Quote\"\" Rule\"", data);
        }

        [Fact]
        public void ExportProcessesToCsv_ExportsAllFields()
        {
            string exportPath = GetTempFilePath("csv");
            var records = new List<ProcessEventRecord>
            {
                new ProcessEventRecord
                {
                    Id = 1,
                    ProcessName = "explorer.exe",
                    ProcessId = 1000,
                    ExecutablePath = @"C:\Windows\explorer.exe",
                    CommandLine = "explorer.exe",
                    Sha256 = "ABCDEF123456",
                    SignatureStatus = "Signed",
                    SignerName = "Microsoft Windows",
                    SignatureTrusted = true
                }
            };

            string hash = ForensicExportService.ExportProcessesToCsv(records, exportPath);

            Assert.True(File.Exists(exportPath));
            string[] lines = File.ReadAllLines(exportPath);
            Assert.Equal(2, lines.Length);
            Assert.Contains("explorer.exe", lines[1]);
            Assert.Contains("Microsoft Windows", lines[1]);
        }

        [Fact]
        public void ExportFilesToCsv_ExportsAllFields()
        {
            string exportPath = GetTempFilePath("csv");
            var records = new List<FileEventRecord>
            {
                new FileEventRecord
                {
                    Id = 1,
                    EventType = "Renamed",
                    FileName = "ransomware.exe",
                    FullPath = @"C:\Users\User\ransomware.exe",
                    OldPath = @"C:\Users\User\download.tmp"
                }
            };

            string hash = ForensicExportService.ExportFilesToCsv(records, exportPath);

            Assert.True(File.Exists(exportPath));
            string[] lines = File.ReadAllLines(exportPath);
            Assert.Equal(2, lines.Length);
            Assert.Contains("Renamed", lines[1]);
            Assert.Contains("download.tmp", lines[1]);
        }

        [Fact]
        public void ExportNetworkToCsv_ExportsAllFields()
        {
            string exportPath = GetTempFilePath("csv");
            var records = new List<NetworkEventRecord>
            {
                new NetworkEventRecord
                {
                    Id = 1,
                    Protocol = "TCPv4",
                    LocalAddress = "127.0.0.1",
                    LocalPort = 8080,
                    RemoteAddress = "192.168.1.1",
                    RemotePort = 443,
                    ConnectionState = "Established",
                    ProcessId = 1234,
                    ProcessName = "test.exe"
                }
            };

            string hash = ForensicExportService.ExportNetworkToCsv(records, exportPath);

            Assert.True(File.Exists(exportPath));
            string[] lines = File.ReadAllLines(exportPath);
            Assert.Equal(2, lines.Length);
            Assert.Contains("8080", lines[1]);
            Assert.Contains("test.exe", lines[1]);
        }

        [Fact]
        public void ExportUsbToCsv_ExportsAllFields()
        {
            string exportPath = GetTempFilePath("csv");
            var records = new List<UsbEventRecord>
            {
                new UsbEventRecord
                {
                    Id = 1,
                    EventType = "Connected",
                    DeviceName = "Corsair Flash",
                    SerialNumber = "SN12345",
                    PnpDeviceId = "USB\\TEST"
                }
            };

            string hash = ForensicExportService.ExportUsbToCsv(records, exportPath);

            Assert.True(File.Exists(exportPath));
            string[] lines = File.ReadAllLines(exportPath);
            Assert.Equal(2, lines.Length);
            Assert.Contains("Corsair Flash", lines[1]);
        }
    }
}

