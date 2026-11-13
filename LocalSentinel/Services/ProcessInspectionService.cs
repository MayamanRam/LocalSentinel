using LocalSentinel.Models;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LocalSentinel.Services
{
    public class ProcessInspectionService
    {
        private readonly ConcurrentDictionary<string, string?> hashCache = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, SignatureInfo> signatureCache = new(StringComparer.OrdinalIgnoreCase);

        public string? CalculateSha256(string? filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath))
            {
                return null;
            }

            if (hashCache.TryGetValue(filePath, out string? cachedHash))
            {
                return cachedHash;
            }

            if (!File.Exists(filePath))
            {
                return null;
            }

            try
            {
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var sha256 = SHA256.Create();
                string hash = Convert.ToHexString(sha256.ComputeHash(stream));
                hashCache[filePath] = hash;
                return hash;
            }
            catch
            {
                return null;
            }
        }

        public SignatureInfo GetSignatureInfo(string? filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                return new SignatureInfo
                {
                    Status = "Unavailable",
                    IsTrusted = false
                };
            }

            if (signatureCache.TryGetValue(filePath, out SignatureInfo? cachedInfo))
            {
                return cachedInfo;
            }

            var result = new SignatureInfo();

            try
            {
#pragma warning disable SYSLIB0057
                var certificate = X509Certificate.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
                using var certificate2 = new X509Certificate2(certificate);

                string signerName = certificate2.GetNameInfo(X509NameType.SimpleName, false);
                if (string.IsNullOrWhiteSpace(signerName))
                {
                    signerName = certificate2.Subject;
                }

                result.Status = "Signed";
                result.SignerName = signerName;

                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                result.IsTrusted = chain.Build(certificate2);
            }
            catch (CryptographicException)
            {
                result.Status = "Unsigned";
                result.IsTrusted = false;
            }
            catch
            {
                result.Status = "Unavailable";
                result.IsTrusted = false;
            }

            signatureCache[filePath] = result;
            return result;
        }

        public (int? ParentProcessId, string? ParentProcessName, string? CommandLine) GetExtendedProcessInfo(int processId)
        {
            int? parentProcessId = null;
            string? parentProcessName = null;
            string? commandLine = null;

            try
            {
                string query = $"SELECT ParentProcessId, CommandLine FROM Win32_Process WHERE ProcessId = {processId}";
                using var searcher = new ManagementObjectSearcher(query);
                using var results = searcher.Get();

                foreach (ManagementObject processInfo in results)
                {
                    if (processInfo["ParentProcessId"] != null)
                    {
                        parentProcessId = Convert.ToInt32(processInfo["ParentProcessId"]);
                    }

                    commandLine = processInfo["CommandLine"]?.ToString();
                    break;
                }

                if (parentProcessId.HasValue && parentProcessId.Value > 0)
                {
                    try
                    {
                        using var parentProcess = Process.GetProcessById(parentProcessId.Value);
                        parentProcessName = parentProcess.ProcessName;
                    }
                    catch
                    {
                        // Parent process may have already exited
                    }
                }
            }
            catch
            {
                // Protected Windows system processes may restrict WMI access
            }

            return (parentProcessId, parentProcessName, commandLine);
        }

        public ProcessEventRecord CreateProcessRecord(Process process)
        {
            string processName = process.ProcessName;
            int processId = process.Id;
            string? executablePath = null;

            try
            {
                executablePath = process.MainModule?.FileName;
            }
            catch
            {
                // Access denied for protected system processes (e.g. csrss, lsass)
            }

            string? sha256 = CalculateSha256(executablePath);
            var signatureInfo = GetSignatureInfo(executablePath);
            var (parentPid, parentName, cmdLine) = GetExtendedProcessInfo(processId);

            return new ProcessEventRecord
            {
                Timestamp = DateTime.Now,
                ProcessName = processName,
                ProcessId = processId,
                ParentProcessName = parentName,
                ParentProcessId = parentPid,
                ExecutablePath = executablePath,
                CommandLine = cmdLine,
                Sha256 = sha256,
                SignatureStatus = signatureInfo.Status,
                SignerName = signatureInfo.SignerName,
                SignatureTrusted = signatureInfo.IsTrusted
            };
        }
    }
}

