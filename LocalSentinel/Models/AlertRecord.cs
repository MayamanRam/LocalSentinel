using System;

namespace LocalSentinel.Models
{
    public enum AlertSeverity
    {
        Info,
        Low,
        Medium,
        High,
        Critical
    }

    public class AlertRecord
    {
        public long Id { get; set; }

        public DateTime Timestamp { get; set; } = DateTime.Now;

        public AlertSeverity Severity { get; set; } = AlertSeverity.Medium;

        public string RuleId { get; set; } = "";

        public string RuleName { get; set; } = "";

        public string MitreTechniqueId { get; set; } = "";

        public string MitreTactic { get; set; } = "";

        public string Source { get; set; } = "";

        public string Description { get; set; } = "";

        public string EntityIdentifier { get; set; } = "";

        public string Remediation { get; set; } = "";

        public string SeverityText => Severity.ToString();

        public string SeverityBadgeColor => Severity switch
        {
            AlertSeverity.Critical => "#DC2626", // Red 600
            AlertSeverity.High => "#EA580C",     // Orange 600
            AlertSeverity.Medium => "#D97706",   // Amber 600
            AlertSeverity.Low => "#2563EB",      // Blue 600
            AlertSeverity.Info => "#475569",     // Slate 600
            _ => "#64748B"
        };
    }
}

