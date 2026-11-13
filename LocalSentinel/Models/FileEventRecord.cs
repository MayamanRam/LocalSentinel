using System;

namespace LocalSentinel.Models
{
    public class FileEventRecord
    {
        public long Id { get; set; }

        public DateTime Timestamp { get; set; }

        public string EventType { get; set; } = "";

        public string FileName { get; set; } = "";

        public string FullPath { get; set; } = "";

        public string? OldPath { get; set; }

        public string EventTypeBadgeColor => EventType switch
        {
            "Created" => "#16A34A",   // Emerald/Green
            "Modified" => "#0284C7",  // Sky Blue
            "Deleted" => "#DC2626",   // Red
            "Renamed" => "#D97706",   // Amber
            _ => "#64748B"
        };
    }
}
