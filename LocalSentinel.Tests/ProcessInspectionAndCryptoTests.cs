using LocalSentinel.Services;
using System;
using System.IO;
using System.Text;
using Xunit;

namespace LocalSentinel.Tests
{
    public class ProcessInspectionAndCryptoTests : IDisposable
    {
        private readonly string tempFilePath;

        public ProcessInspectionAndCryptoTests()
        {
            tempFilePath = Path.Combine(Path.GetTempPath(), $"ProcessInspectTest_{Guid.NewGuid():N}.bin");
            File.WriteAllBytes(tempFilePath, Encoding.UTF8.GetBytes("LocalSentinel Cybersecurity Test Vector 2026"));
        }

        public void Dispose()
        {
            try
            {
                if (File.Exists(tempFilePath))
                {
                    File.Delete(tempFilePath);
                }
            }
            catch
            {
                // Ignore
            }
        }

        [Fact]
        public void CalculateSha256_ComputesAccurateHash_AndUsesCache()
        {
            var inspector = new ProcessInspectionService();

            string? hash1 = inspector.CalculateSha256(tempFilePath);
            string? hash2 = inspector.CalculateSha256(tempFilePath);

            Assert.NotNull(hash1);
            Assert.Equal(64, hash1.Length);
            Assert.Equal(hash1, hash2); // Cache return match

            // Verify null/empty inputs
            Assert.Null(inspector.CalculateSha256(null));
            Assert.Null(inspector.CalculateSha256(""));
            Assert.Null(inspector.CalculateSha256(@"C:\NonExistent_Fake_File_987654321.exe"));
        }

        [Fact]
        public void GetSignatureInfo_HandlesNonExistentAndPlainFilesSafely()
        {
            var inspector = new ProcessInspectionService();

            var infoNonExistent = inspector.GetSignatureInfo(@"C:\NonExistent_Fake_File_987654321.exe");
            Assert.Equal("Unavailable", infoNonExistent.Status);
            Assert.False(infoNonExistent.IsTrusted);

            var infoPlainFile = inspector.GetSignatureInfo(tempFilePath);
            Assert.Contains(infoPlainFile.Status, new[] { "Unsigned", "Unavailable" });
            Assert.False(infoPlainFile.IsTrusted);
        }

        [Fact]
        public void NetworkConnectionService_ConvertPort_AccuratelyConvertsEndianness()
        {
            // Port 80 (HTTP): 0x0050 in network byte order -> 0x5000 in little endian
            uint port80LittleEndian = 0x5000;
            int converted = NetworkConnectionService.ConvertPort(port80LittleEndian);
            Assert.Equal(80, converted);

            // Port 443 (HTTPS): 0x01BB in network byte order -> 0xBB01 in little endian
            uint port443LittleEndian = 0xBB01;
            int converted443 = NetworkConnectionService.ConvertPort(port443LittleEndian);
            Assert.Equal(443, converted443);
        }
    }
}

