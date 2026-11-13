using LocalSentinel.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace LocalSentinel.Services
{
    public class ForensicExportReport
    {
        public string ExportId { get; set; } = Guid.NewGuid().ToString("N");
        public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
        public string MachineName { get; set; } = Environment.MachineName;
        public string OperatingSystem { get; set; } = Environment.OSVersion.ToString();
        public int TotalAlerts { get; set; }
        public int TotalProcesses { get; set; }
        public int TotalFileEvents { get; set; }
        public int TotalNetworkEvents { get; set; }
        public int TotalUsbEvents { get; set; }
        public List<AlertRecord> Alerts { get; set; } = new();
        public List<ProcessEventRecord> Processes { get; set; } = new();
        public List<FileEventRecord> FileEvents { get; set; } = new();
        public List<NetworkEventRecord> NetworkEvents { get; set; } = new();
        public List<UsbEventRecord> UsbEvents { get; set; } = new();
    }

    public static class ForensicExportService
    {
        public static string ExportToJson(ForensicExportReport report, string destinationPath)
        {
            var options = new JsonSerializerOptions
            {
                WriteIndented = true
            };

            string json = JsonSerializer.Serialize(report, options);
            File.WriteAllText(destinationPath, json, Encoding.UTF8);

            return ComputeFileSha256(destinationPath);
        }

        public static string ExportAlertsToCsv(IEnumerable<AlertRecord> alerts, string destinationPath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Id,Timestamp,Severity,RuleId,RuleName,MitreTechniqueId,MitreTactic,Source,EntityIdentifier,Description,Remediation");

            foreach (var a in alerts)
            {
                sb.AppendLine(string.Join(",",
                    a.Id,
                    EscapeCsv(a.Timestamp.ToString("O")),
                    EscapeCsv(a.SeverityText),
                    EscapeCsv(a.RuleId),
                    EscapeCsv(a.RuleName),
                    EscapeCsv(a.MitreTechniqueId),
                    EscapeCsv(a.MitreTactic),
                    EscapeCsv(a.Source),
                    EscapeCsv(a.EntityIdentifier),
                    EscapeCsv(a.Description),
                    EscapeCsv(a.Remediation)
                ));
            }

            File.WriteAllText(destinationPath, sb.ToString(), Encoding.UTF8);
            return ComputeFileSha256(destinationPath);
        }

        public static string ExportProcessesToCsv(IEnumerable<ProcessEventRecord> records, string destinationPath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Id,Timestamp,ProcessName,ProcessId,ParentProcessName,ParentProcessId,ExecutablePath,CommandLine,Sha256,SignatureStatus,SignerName,SignatureTrusted");

            foreach (var r in records)
            {
                sb.AppendLine(string.Join(",",
                    r.Id,
                    EscapeCsv(r.Timestamp.ToString("O")),
                    EscapeCsv(r.ProcessName),
                    r.ProcessId,
                    EscapeCsv(r.ParentProcessName ?? ""),
                    r.ParentProcessId?.ToString() ?? "",
                    EscapeCsv(r.ExecutablePath ?? ""),
                    EscapeCsv(r.CommandLine ?? ""),
                    EscapeCsv(r.Sha256 ?? ""),
                    EscapeCsv(r.SignatureStatus),
                    EscapeCsv(r.SignerName ?? ""),
                    r.SignatureTrusted ? "1" : "0"
                ));
            }

            File.WriteAllText(destinationPath, sb.ToString(), Encoding.UTF8);
            return ComputeFileSha256(destinationPath);
        }

        public static string ExportFilesToCsv(IEnumerable<FileEventRecord> records, string destinationPath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Id,Timestamp,EventType,FileName,FullPath,OldPath");

            foreach (var r in records)
            {
                sb.AppendLine(string.Join(",",
                    r.Id,
                    EscapeCsv(r.Timestamp.ToString("O")),
                    EscapeCsv(r.EventType),
                    EscapeCsv(r.FileName),
                    EscapeCsv(r.FullPath),
                    EscapeCsv(r.OldPath ?? "")
                ));
            }

            File.WriteAllText(destinationPath, sb.ToString(), Encoding.UTF8);
            return ComputeFileSha256(destinationPath);
        }

        public static string ExportNetworkToCsv(IEnumerable<NetworkEventRecord> records, string destinationPath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Id,Timestamp,Protocol,LocalAddress,LocalPort,RemoteAddress,RemotePort,ConnectionState,ProcessId,ProcessName");

            foreach (var r in records)
            {
                sb.AppendLine(string.Join(",",
                    r.Id,
                    EscapeCsv(r.Timestamp.ToString("O")),
                    EscapeCsv(r.Protocol),
                    EscapeCsv(r.LocalAddress),
                    r.LocalPort,
                    EscapeCsv(r.RemoteAddress),
                    r.RemotePort,
                    EscapeCsv(r.ConnectionState),
                    r.ProcessId?.ToString() ?? "",
                    EscapeCsv(r.ProcessName ?? "")
                ));
            }

            File.WriteAllText(destinationPath, sb.ToString(), Encoding.UTF8);
            return ComputeFileSha256(destinationPath);
        }

        public static string ExportUsbToCsv(IEnumerable<UsbEventRecord> records, string destinationPath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Id,Timestamp,EventType,DeviceName,SerialNumber,PnpDeviceId");

            foreach (var r in records)
            {
                sb.AppendLine(string.Join(",",
                    r.Id,
                    EscapeCsv(r.Timestamp.ToString("O")),
                    EscapeCsv(r.EventType),
                    EscapeCsv(r.DeviceName),
                    EscapeCsv(r.SerialNumber ?? ""),
                    EscapeCsv(r.PnpDeviceId ?? "")
                ));
            }

            File.WriteAllText(destinationPath, sb.ToString(), Encoding.UTF8);
            return ComputeFileSha256(destinationPath);
        }

        private static string EscapeCsv(string? field)
        {
            if (string.IsNullOrEmpty(field))
            {
                return "";
            }

            if (field.Contains(",") || field.Contains("\"") || field.Contains("\n") || field.Contains("\r"))
            {
                return $"\"{field.Replace("\"", "\"\"")}\"";
            }

            return field;
        }

        private static string ComputeFileSha256(string filePath)
        {
            using var sha = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            byte[] hash = sha.ComputeHash(stream);
            return Convert.ToHexString(hash);
        }
    }
}

