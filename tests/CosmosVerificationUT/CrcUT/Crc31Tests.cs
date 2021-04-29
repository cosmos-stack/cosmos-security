using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace CrcUT
{
    [Trait("CrcUT", "Crc31Tests")]
    public class Crc31Tests
    {
        [Theory(DisplayName = "CRC-31/PHILIPS")]
        [InlineData("Nice", "DE558074", "11011110010101011000000001110100", "11011110010101011000000001110100")]
        [InlineData("Nice Boat", "976B2F3F", "10010111011010110010111100111111", "10010111011010110010111100111111")]
        public void Crc31PhilipsTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc31Philips);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
            hashVal.GetBinString().ShouldBe(bin);
            hashVal.GetBinString(true).ShouldBe(binWithZero);
        }
    }
}