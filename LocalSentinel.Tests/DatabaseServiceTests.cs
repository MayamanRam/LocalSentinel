using LocalSentinel.Data;
using LocalSentinel.Models;
using System;
using System.IO;
using Xunit;

namespace LocalSentinel.Tests
{
    public class DatabaseServiceTests : IDisposable
    {
        private readonly string tempDbPath;
        private readonly DatabaseService db;

        public DatabaseServiceTests()
        {
            tempDbPath = Path.Combine(Path.GetTempPath(), $"LocalSentinel_Test_{Guid.NewGuid():N}.db");
            db = new DatabaseService(tempDbPath);
            db.InitializeDatabase();
        }

        public void Dispose()
        {
            try
            {
                if (File.Exists(tempDbPath))
                {
                    File.Delete(tempDbPath);
                }
                string wal = $"{tempDbPath}-wal";
                string shm = $"{tempDbPath}-shm";
                if (File.Exists(wal)) File.Delete(wal);
                if (File.Exists(shm)) File.Delete(shm);
            }
            catch
            {
                // Ignore cleanup lock issues on test exit
            }
        }

        [Fact]
        public void ProcessEvents_CanBeInsertedAndRetrieved()
        {
            var record = new ProcessEventRecord
            {
                Timestamp = DateTime.Now,
                ProcessName = "cmd.exe",
                ProcessId = 1234,
                ParentProcessName = "explorer.exe",
                ParentProcessId = 4321,
                ExecutablePath = @"C:\Windows\System32\cmd.exe",
                CommandLine = "cmd.exe /c dir",
                Sha256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
                SignatureStatus = "Signed",
                SignerName = "Microsoft Windows",
                SignatureTrusted = true
            };

            db.AddProcessEvent(record);
            var results = db.GetRecentProcessEvents(10);

            Assert.Single(results);
            var retrieved = results[0];
            Assert.Equal("cmd.exe", retrieved.ProcessName);
            Assert.Equal(1234, retrieved.ProcessId);
            Assert.Equal("explorer.exe", retrieved.ParentProcessName);
            Assert.Equal(4321, retrieved.ParentProcessId);
            Assert.True(retrieved.SignatureTrusted);
            Assert.Equal("Yes", retrieved.SignatureTrustDisplay);
        }

        [Fact]
        public void FileEvents_CanBeInsertedAndRetrieved()
        {
            var record = new FileEventRecord
            {
                Timestamp = DateTime.Now,
                EventType = "Created",
                FileName = "threat.exe",
                FullPath = @"C:\Users\User\Downloads\threat.exe",
                OldPath = null
            };

            db.AddFileEvent(record);
            var results = db.GetRecentFileEvents(10);

            Assert.Single(results);
            var retrieved = results[0];
            Assert.Equal("Created", retrieved.EventType);
            Assert.Equal("threat.exe", retrieved.FileName);
            Assert.Equal(@"C:\Users\User\Downloads\threat.exe", retrieved.FullPath);
        }

        [Fact]
        public void NetworkEvents_CanBeInsertedAndRetrieved()
        {
            var record = new NetworkEventRecord
            {
                Timestamp = DateTime.Now,
                Protocol = "TCPv4",
                LocalAddress = "192.168.1.100",
                LocalPort = 55432,
                RemoteAddress = "104.244.42.1",
                RemotePort = 443,
                ConnectionState = "Established",
                ProcessId = 5000,
                ProcessName = "browser.exe"
            };

            db.AddNetworkEvent(record);
            var results = db.GetRecentNetworkEvents(10);

            Assert.Single(results);
            var retrieved = results[0];
            Assert.Equal("browser.exe", retrieved.ProcessName);
            Assert.Equal(5000, retrieved.ProcessId);
            Assert.Equal(443, retrieved.RemotePort);
            Assert.Equal("Established", retrieved.ConnectionState);
        }

        [Fact]
        public void UsbEvents_CanBeInsertedAndRetrieved()
        {
            var record = new UsbEventRecord
            {
                Timestamp = DateTime.Now,
                EventType = "Connected",
                DeviceName = "Kingston DataTraveler 3.0",
                SerialNumber = "0014D1187C17F12127161F7A",
                PnpDeviceId = @"USB\VID_0951&PID_1666\0014D1187C17F12127161F7A"
            };

            db.AddUsbEvent(record);
            var results = db.GetRecentUsbEvents(10);

            Assert.Single(results);
            var retrieved = results[0];
            Assert.Equal("Connected", retrieved.EventType);
            Assert.Equal("Kingston DataTraveler 3.0", retrieved.DeviceName);
        }

        [Fact]
        public void Alerts_CanBeInsertedAndRetrieved()
        {
            var alert = new AlertRecord
            {
                Timestamp = DateTime.Now,
                Severity = AlertSeverity.Critical,
                RuleId = "RULE-PROC-001",
                RuleName = "Suspicious Obfuscated PowerShell Execution",
                MitreTechniqueId = "T1059.001",
                MitreTactic = "Execution",
                Source = "Process",
                Description = "PowerShell executed with -enc flag",
                EntityIdentifier = "PID 4412 (powershell.exe)",
                Remediation = "Isolate host and investigate payload."
            };

            db.AddAlert(alert);
            var results = db.GetRecentAlerts(10);

            Assert.Single(results);
            var retrieved = results[0];
            Assert.Equal("RULE-PROC-001", retrieved.RuleId);
            Assert.Equal(AlertSeverity.Critical, retrieved.Severity);
            Assert.Equal("T1059.001", retrieved.MitreTechniqueId);
            Assert.Equal("#DC2626", retrieved.SeverityBadgeColor);
        }

        [Fact]
        public void MetricsAndClearEvents_FunctionCorrectly()
        {
            db.AddProcessEvent(new ProcessEventRecord { ProcessName = "test.exe", ProcessId = 111 });
            db.AddFileEvent(new FileEventRecord { FileName = "test.txt", FullPath = @"C:\test.txt", EventType = "Created" });
            db.AddNetworkEvent(new NetworkEventRecord { Protocol = "TCP", LocalAddress = "127.0.0.1", RemoteAddress = "127.0.0.1" });
            db.AddUsbEvent(new UsbEventRecord { DeviceName = "Flash", EventType = "Connected" });
            db.AddAlert(new AlertRecord { RuleId = "TEST-01", RuleName = "Test" });

            var metricsBefore = db.GetMetrics();
            Assert.Equal(1, metricsBefore.ProcessCount);
            Assert.Equal(1, metricsBefore.FileCount);
            Assert.Equal(1, metricsBefore.NetworkCount);
            Assert.Equal(1, metricsBefore.UsbCount);
            Assert.Equal(1, metricsBefore.AlertCount);
            Assert.True(metricsBefore.DatabaseSizeBytes > 0);

            db.ClearAllEvents();

            var metricsAfter = db.GetMetrics();
            Assert.Equal(0, metricsAfter.ProcessCount);
            Assert.Equal(0, metricsAfter.FileCount);
            Assert.Equal(0, metricsAfter.NetworkCount);
            Assert.Equal(0, metricsAfter.UsbCount);
            Assert.Equal(0, metricsAfter.AlertCount);
        }
    }
}

