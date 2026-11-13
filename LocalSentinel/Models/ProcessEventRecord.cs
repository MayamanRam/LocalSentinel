using System;

namespace LocalSentinel.Models
{
    public class ProcessEventRecord
    {
        public long Id { get; set; }

        public DateTime Timestamp { get; set; }

        public string ProcessName { get; set; } = "";

        public int ProcessId { get; set; }

        public string? ParentProcessName { get; set; }

        public int? ParentProcessId { get; set; }

        public string? ExecutablePath { get; set; }

        public string? CommandLine { get; set; }

        public string? Sha256 { get; set; }

        public string SignatureStatus { get; set; } = "Unknown";

        public string? SignerName { get; set; }

        public bool SignatureTrusted { get; set; }

        public string SignatureTrustDisplay
        {
            get
            {
                if (SignatureStatus == "Unavailable" || SignatureStatus == "Unknown")
                {
                    return "Unknown";
                }

                if (SignatureStatus == "Unsigned")
                {
                    return "No";
                }

                return SignatureTrusted ? "Yes" : "No";
            }
        }

        public string TrustBadgeColor => SignatureTrustDisplay switch
        {
            "Yes" => "#16A34A",      // Green
            "No" => "#DC2626",       // Red
            _ => "#64748B"           // Gray
        };
    }
}
