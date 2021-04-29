using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace CrcUT
{
    [Trait("CrcUT", "CRC-03")]
    public class Crc03Tests
    {
        [Theory(DisplayName = "CRC-3/ROHC")]
        [InlineData("N", "01", "001")]
        [InlineData("Ni", "00", "000")]
        [InlineData("Nic", "03", "011")]
        [InlineData("Nie", "00", "000")]
        public void Crc3RohcTest(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc3Rohc);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
            hashVal.GetBinString(true).ShouldBe(bin);
        }
    }
}