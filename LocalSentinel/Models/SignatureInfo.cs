namespace LocalSentinel.Models
{
    public class SignatureInfo
    {
        public string Status { get; set; } = "Unknown";

        public string? SignerName { get; set; }

        public bool IsTrusted { get; set; }
    }
}
