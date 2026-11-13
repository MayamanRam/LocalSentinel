using System;

namespace LocalSentinel.Models
{
    public class NetworkEventRecord
    {
        public long Id { get; set; }

        public DateTime Timestamp { get; set; }

        public string Protocol { get; set; } = "TCP";

        public string LocalAddress { get; set; } = "";

        public int LocalPort { get; set; }

        public string RemoteAddress { get; set; } = "";

        public int RemotePort { get; set; }

        public string ConnectionState { get; set; } = "";

        public int? ProcessId { get; set; }

        public string? ProcessName { get; set; }

        public string EndpointDisplay => $"{RemoteAddress}:{RemotePort}";

        public string StateBadgeColor => ConnectionState switch
        {
            "Established" => "#16A34A",
            "Listen" => "#0284C7",
            "TimeWait" => "#64748B",
            "CloseWait" => "#D97706",
            "SynSent" => "#EA580C",
            _ => "#475569"
        };
    }
}
