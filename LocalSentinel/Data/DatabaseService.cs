using LocalSentinel.Models;
using Microsoft.Data.Sqlite;
using System;
using System.Collections.Generic;
using System.IO;

namespace LocalSentinel.Data
{
    public class DatabaseMetrics
    {
        public long ProcessCount { get; set; }
        public long FileCount { get; set; }
        public long NetworkCount { get; set; }
        public long UsbCount { get; set; }
        public long AlertCount { get; set; }
        public long DatabaseSizeBytes { get; set; }
    }

    public class DatabaseService
    {
        private readonly string connectionString;
        private readonly string databaseFilePath;

        public DatabaseService() : this(GetDefaultDatabasePath())
        {
        }

        public DatabaseService(string dbPath)
        {
            databaseFilePath = dbPath;
            string? directory = Path.GetDirectoryName(dbPath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            connectionString = $"Data Source={dbPath}";
        }

        public string DatabasePath => databaseFilePath;

        private static string GetDefaultDatabasePath()
        {
            string dataFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "LocalSentinel"
            );
            return Path.Combine(dataFolder, "LocalSentinel.db");
        }

        private SqliteConnection CreateOpenConnection()
        {
            var connection = new SqliteConnection(connectionString);
            connection.Open();

            // Enable WAL mode for high performance concurrent reading/writing
            using var cmd = connection.CreateCommand();
            cmd.CommandText = "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;";
            cmd.ExecuteNonQuery();

            return connection;
        }

        public void InitializeDatabase()
        {
            using var connection = CreateOpenConnection();
            using var command = connection.CreateCommand();

            command.CommandText = """
                CREATE TABLE IF NOT EXISTS ProcessEvents
                (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Timestamp TEXT NOT NULL,
                    ProcessName TEXT NOT NULL,
                    ProcessId INTEGER NOT NULL,
                    ParentProcessName TEXT,
                    ParentProcessId INTEGER,
                    ExecutablePath TEXT,
                    CommandLine TEXT,
                    Sha256 TEXT,
                    SignatureStatus TEXT,
                    SignerName TEXT,
                    SignatureTrusted INTEGER
                );

                CREATE TABLE IF NOT EXISTS FileEvents
                (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Timestamp TEXT NOT NULL,
                    EventType TEXT NOT NULL,
                    FileName TEXT NOT NULL,
                    FullPath TEXT NOT NULL,
                    OldPath TEXT
                );

                CREATE TABLE IF NOT EXISTS NetworkEvents
                (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Timestamp TEXT NOT NULL,
                    Protocol TEXT NOT NULL,
                    LocalAddress TEXT NOT NULL,
                    LocalPort INTEGER NOT NULL,
                    RemoteAddress TEXT NOT NULL,
                    RemotePort INTEGER NOT NULL,
                    ConnectionState TEXT NOT NULL,
                    ProcessId INTEGER,
                    ProcessName TEXT
                );

                CREATE TABLE IF NOT EXISTS UsbEvents
                (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Timestamp TEXT NOT NULL,
                    EventType TEXT NOT NULL,
                    DeviceName TEXT NOT NULL,
                    SerialNumber TEXT,
                    PnpDeviceId TEXT
                );

                CREATE TABLE IF NOT EXISTS Alerts
                (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Timestamp TEXT NOT NULL,
                    Severity TEXT NOT NULL,
                    RuleId TEXT NOT NULL,
                    RuleName TEXT NOT NULL,
                    MitreTechniqueId TEXT NOT NULL,
                    MitreTactic TEXT NOT NULL,
                    Source TEXT NOT NULL,
                    Description TEXT NOT NULL,
                    EntityIdentifier TEXT NOT NULL,
                    Remediation TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS IX_ProcessEvents_Timestamp ON ProcessEvents(Timestamp);
                CREATE INDEX IF NOT EXISTS IX_FileEvents_Timestamp ON FileEvents(Timestamp);
                CREATE INDEX IF NOT EXISTS IX_NetworkEvents_Timestamp ON NetworkEvents(Timestamp);
                CREATE INDEX IF NOT EXISTS IX_UsbEvents_Timestamp ON UsbEvents(Timestamp);
                CREATE INDEX IF NOT EXISTS IX_Alerts_Timestamp ON Alerts(Timestamp);
                """;

            command.ExecuteNonQuery();
        }

        // ================= Process Events =================

        public void AddProcessEvent(ProcessEventRecord record)
        {
            using var connection = CreateOpenConnection();
            using var command = connection.CreateCommand();

            command.CommandText = """
                INSERT INTO ProcessEvents
                (
                    Timestamp, ProcessName, ProcessId, ParentProcessName, ParentProcessId,
                    ExecutablePath, CommandLine, Sha256, SignatureStatus, SignerName, SignatureTrusted
                )
                VALUES
                (
                    $timestamp, $processName, $processId, $parentProcessName, $parentProcessId,
                    $executablePath, $commandLine, $sha256, $signatureStatus, $signerName, $signatureTrusted
                );
                """;

            command.Parameters.AddWithValue("$timestamp", record.Timestamp.ToString("O"));
            command.Parameters.AddWithValue("$processName", record.ProcessName);
            command.Parameters.AddWithValue("$processId", record.ProcessId);
            command.Parameters.AddWithValue("$parentProcessName", record.ParentProcessName ?? (object)DBNull.Value);
            command.Parameters.AddWithValue("$parentProcessId", record.ParentProcessId.HasValue ? record.ParentProcessId.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("$executablePath", record.ExecutablePath ?? (object)DBNull.Value);
            command.Parameters.AddWithValue("$commandLine", record.CommandLine ?? (object)DBNull.Value);
            command.Parameters.AddWithValue("$sha256", record.Sha256 ?? (object)DBNull.Value);
            command.Parameters.AddWithValue("$signatureStatus", record.SignatureStatus);
            command.Parameters.AddWithValue("$signerName", record.SignerName ?? (object)DBNull.Value);
            command.Parameters.AddWithValue("$signatureTrusted", record.SignatureTrusted ? 1 : 0);

            command.ExecuteNonQuery();
        }

        public List<ProcessEventRecord> GetRecentProcessEvents(int limit = 100)
        {
            var events = new List<ProcessEventRecord>();
            using var connection = CreateOpenConnection();
            using var command = connection.CreateCommand();

            command.CommandText = """
                SELECT Id, Timestamp, ProcessName, ProcessId, ParentProcessName, ParentProcessId,
                       ExecutablePath, CommandLine, Sha256, SignatureStatus, SignerName, SignatureTrusted
                FROM ProcessEvents
                ORDER BY Id DESC
                LIMIT $limit;
                """;

            command.Parameters.AddWithValue("$limit", limit);

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                events.Add(new ProcessEventRecord
                {
                    Id = reader.GetInt64(0),
                    Timestamp = DateTime.Parse(reader.GetString(1)),
                    ProcessName = reader.GetString(2),
                    ProcessId = Convert.ToInt32(reader.GetInt64(3)),
                    ParentProcessName = reader.IsDBNull(4) ? null : reader.GetString(4),
                    ParentProcessId = reader.IsDBNull(5) ? null : Convert.ToInt32(reader.GetInt64(5)),
                    ExecutablePath = reader.IsDBNull(6) ? null : reader.GetString(6),
                    CommandLine = reader.IsDBNull(7) ? null : reader.GetString(7),
                    Sha256 = reader.IsDBNull(8) ? null : reader.GetString(8),
                    SignatureStatus = reader.IsDBNull(9) ? "Unknown" : reader.GetString(9),
                    SignerName = reader.IsDBNull(10) ? null : reader.GetString(10),
                    SignatureTrusted = !reader.IsDBNull(11) && reader.GetInt64(11) == 1
                });
            }

            return events;
        }

        // ================= File Events =================

        public void AddFileEvent(FileEventRecord record)
        {
            using var connection = CreateOpenConnection();
            using var command = connection.CreateCommand();

            command.CommandText = """
                INSERT INTO FileEvents (Timestamp, EventType, FileName, FullPath, OldPath)
                VALUES ($timestamp, $eventType, $fileName, $fullPath, $oldPath);
                """;

            command.Parameters.AddWithValue("$timestamp", record.Timestamp.ToString("O"));
            command.Parameters.AddWithValue("$eventType", record.EventType);
            command.Parameters.AddWithValue("$fileName", record.FileName);
            command.Parameters.AddWithValue("$fullPath", record.FullPath);
            command.Parameters.AddWithValue("$oldPath", record.OldPath ?? (object)DBNull.Value);

            command.ExecuteNonQuery();
        }

        public List<FileEventRecord> GetRecentFileEvents(int limit = 250)
        {
            var events = new List<FileEventRecord>();
            using var connection = CreateOpenConnection();
            using var command = connection.CreateCommand();

            command.CommandText = """
                SELECT Id, Timestamp, EventType, FileName, FullPath, OldPath
                FROM FileEvents
                ORDER BY Id DESC
                LIMIT $limit;
                """;

            command.Parameters.AddWithValue("$limit", limit);

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                events.Add(new FileEventRecord
                {
                    Id = reader.GetInt64(0),
                    Timestamp = DateTime.Parse(reader.GetString(1)),
                    EventType = reader.GetString(2),
                    FileName = reader.GetString(3),
                    FullPath = reader.GetString(4),
                    OldPath = reader.IsDBNull(5) ? null : reader.GetString(5)
                });
            }

            return events;
        }

        // ================= Network Events =================

        public void AddNetworkEvent(NetworkEventRecord record)
        {
            using var connection = CreateOpenConnection();
            using var command = connection.CreateCommand();

            command.CommandText = """
                INSERT INTO NetworkEvents
                (Timestamp, Protocol, LocalAddress, LocalPort, RemoteAddress, RemotePort, ConnectionState, ProcessId, ProcessName)
                VALUES
                ($timestamp, $protocol, $localAddress, $localPort, $remoteAddress, $remotePort, $connectionState, $processId, $processName);
                """;

            command.Parameters.AddWithValue("$timestamp", record.Timestamp.ToString("O"));
            command.Parameters.AddWithValue("$protocol", record.Protocol);
            command.Parameters.AddWithValue("$localAddress", record.LocalAddress);
            command.Parameters.AddWithValue("$localPort", record.LocalPort);
            command.Parameters.AddWithValue("$remoteAddress", record.RemoteAddress);
            command.Parameters.AddWithValue("$remotePort", record.RemotePort);
            command.Parameters.AddWithValue("$connectionState", record.ConnectionState);
            command.Parameters.AddWithValue("$processId", record.ProcessId.HasValue ? record.ProcessId.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("$processName", record.ProcessName ?? (object)DBNull.Value);

            command.ExecuteNonQuery();
        }

        public List<NetworkEventRecord> GetRecentNetworkEvents(int limit = 100)
        {
            var events = new List<NetworkEventRecord>();
            using var connection = CreateOpenConnection();
            using var command = connection.CreateCommand();

            command.CommandText = """
                SELECT Id, Timestamp, Protocol, LocalAddress, LocalPort, RemoteAddress, RemotePort, ConnectionState, ProcessId, ProcessName
                FROM NetworkEvents
                ORDER BY Id DESC
                LIMIT $limit;
                """;

            command.Parameters.AddWithValue("$limit", limit);

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                events.Add(new NetworkEventRecord
                {
                    Id = reader.GetInt64(0),
                    Timestamp = DateTime.Parse(reader.GetString(1)),
                    Protocol = reader.GetString(2),
                    LocalAddress = reader.GetString(3),
                    LocalPort = Convert.ToInt32(reader.GetInt64(4)),
                    RemoteAddress = reader.GetString(5),
                    RemotePort = Convert.ToInt32(reader.GetInt64(6)),
                    ConnectionState = reader.GetString(7),
                    ProcessId = reader.IsDBNull(8) ? null : Convert.ToInt32(reader.GetInt64(8)),
                    ProcessName = reader.IsDBNull(9) ? null : reader.GetString(9)
                });
            }

            return events;
        }

        // ================= USB Events =================

        public void AddUsbEvent(UsbEventRecord record)
        {
            using var connection = CreateOpenConnection();
            using var command = connection.CreateCommand();

            command.CommandText = """
                INSERT INTO UsbEvents (Timestamp, EventType, DeviceName, SerialNumber, PnpDeviceId)
                VALUES ($timestamp, $eventType, $deviceName, $serialNumber, $pnpDeviceId);
                """;

            command.Parameters.AddWithValue("$timestamp", record.Timestamp.ToString("O"));
            command.Parameters.AddWithValue("$eventType", record.EventType);
            command.Parameters.AddWithValue("$deviceName", record.DeviceName);
            command.Parameters.AddWithValue("$serialNumber", record.SerialNumber ?? (object)DBNull.Value);
            command.Parameters.AddWithValue("$pnpDeviceId", record.PnpDeviceId ?? (object)DBNull.Value);

            command.ExecuteNonQuery();
        }

        public List<UsbEventRecord> GetRecentUsbEvents(int limit = 100)
        {
            var events = new List<UsbEventRecord>();
            using var connection = CreateOpenConnection();
            using var command = connection.CreateCommand();

            command.CommandText = """
                SELECT Id, Timestamp, EventType, DeviceName, SerialNumber, PnpDeviceId
                FROM UsbEvents
                ORDER BY Id DESC
                LIMIT $limit;
                """;

            command.Parameters.AddWithValue("$limit", limit);

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                events.Add(new UsbEventRecord
                {
                    Id = reader.GetInt64(0),
                    Timestamp = DateTime.Parse(reader.GetString(1)),
                    EventType = reader.GetString(2),
                    DeviceName = reader.GetString(3),
                    SerialNumber = reader.IsDBNull(4) ? null : reader.GetString(4),
                    PnpDeviceId = reader.IsDBNull(5) ? null : reader.GetString(5)
                });
            }

            return events;
        }

        // ================= Alerts =================

        public void AddAlert(AlertRecord alert)
        {
            using var connection = CreateOpenConnection();
            using var command = connection.CreateCommand();

            command.CommandText = """
                INSERT INTO Alerts
                (Timestamp, Severity, RuleId, RuleName, MitreTechniqueId, MitreTactic, Source, Description, EntityIdentifier, Remediation)
                VALUES
                ($timestamp, $severity, $ruleId, $ruleName, $mitreTechniqueId, $mitreTactic, $source, $description, $entityIdentifier, $remediation);
                """;

            command.Parameters.AddWithValue("$timestamp", alert.Timestamp.ToString("O"));
            command.Parameters.AddWithValue("$severity", alert.Severity.ToString());
            command.Parameters.AddWithValue("$ruleId", alert.RuleId);
            command.Parameters.AddWithValue("$ruleName", alert.RuleName);
            command.Parameters.AddWithValue("$mitreTechniqueId", alert.MitreTechniqueId);
            command.Parameters.AddWithValue("$mitreTactic", alert.MitreTactic);
            command.Parameters.AddWithValue("$source", alert.Source);
            command.Parameters.AddWithValue("$description", alert.Description);
            command.Parameters.AddWithValue("$entityIdentifier", alert.EntityIdentifier);
            command.Parameters.AddWithValue("$remediation", alert.Remediation);

            command.ExecuteNonQuery();
        }

        public List<AlertRecord> GetRecentAlerts(int limit = 100)
        {
            var alerts = new List<AlertRecord>();
            using var connection = CreateOpenConnection();
            using var command = connection.CreateCommand();

            command.CommandText = """
                SELECT Id, Timestamp, Severity, RuleId, RuleName, MitreTechniqueId, MitreTactic, Source, Description, EntityIdentifier, Remediation
                FROM Alerts
                ORDER BY Id DESC
                LIMIT $limit;
                """;

            command.Parameters.AddWithValue("$limit", limit);

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                string severityStr = reader.GetString(2);
                Enum.TryParse(severityStr, true, out AlertSeverity severity);

                alerts.Add(new AlertRecord
                {
                    Id = reader.GetInt64(0),
                    Timestamp = DateTime.Parse(reader.GetString(1)),
                    Severity = severity,
                    RuleId = reader.GetString(3),
                    RuleName = reader.GetString(4),
                    MitreTechniqueId = reader.GetString(5),
                    MitreTactic = reader.GetString(6),
                    Source = reader.GetString(7),
                    Description = reader.GetString(8),
                    EntityIdentifier = reader.GetString(9),
                    Remediation = reader.GetString(10)
                });
            }

            return alerts;
        }

        // ================= Metrics & Maintenance =================

        public DatabaseMetrics GetMetrics()
        {
            using var connection = CreateOpenConnection();

            var metrics = new DatabaseMetrics();
            metrics.ProcessCount = GetRowCount(connection, "ProcessEvents");
            metrics.FileCount = GetRowCount(connection, "FileEvents");
            metrics.NetworkCount = GetRowCount(connection, "NetworkEvents");
            metrics.UsbCount = GetRowCount(connection, "UsbEvents");
            metrics.AlertCount = GetRowCount(connection, "Alerts");

            if (File.Exists(databaseFilePath))
            {
                metrics.DatabaseSizeBytes = new FileInfo(databaseFilePath).Length;
            }

            return metrics;
        }

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

        public void ClearAllEvents()
        {
            using var connection = CreateOpenConnection();
            using var command = connection.CreateCommand();

            command.CommandText = """
                DELETE FROM ProcessEvents;
                DELETE FROM FileEvents;
                DELETE FROM NetworkEvents;
                DELETE FROM UsbEvents;
                DELETE FROM Alerts;
                VACUUM;
                """;

            command.ExecuteNonQuery();
        }
    }
}
