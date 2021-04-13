using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace CrcUT
{
    [Trait("CrcUT", "CRC-04")]
    public class Crc04Tests
    {
        [Theory(DisplayName = "CRC-4/ITU")]
        [InlineData("N", "07", "0111")]
        [InlineData("Ni", "04", "0100")]
        [InlineData("Nic", "09", "1001")]
        [InlineData("Nice", "0A", "1010")]
        public void Crc4ItuTest(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc4Itu);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString(true).ShouldBe(bin);
        }
    }
}