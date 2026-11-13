using System;

namespace LocalSentinel.Models
{
    public class UsbEventRecord
    {
        public long Id { get; set; }

        public DateTime Timestamp { get; set; }

        public string EventType { get; set; } = "";

        public string DeviceName { get; set; } = "USB storage device";

        public string? SerialNumber { get; set; }

        public string? PnpDeviceId { get; set; }

        public string EventTypeBadgeColor => EventType switch
        {
            "Connected" => "#16A34A",
            "Removed" => "#EA580C",
            _ => "#64748B"
        };
    }
}
