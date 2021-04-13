using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace CrcUT
{
    [Trait("CrcUT", "Crc13Tests")]
    public class Crc13Tests
    {
        [Theory(DisplayName = "CRC-13/BBC")]
        [InlineData("Nice", "FB16", "1111101100010110", "1111101100010110")]
        [InlineData("Nice Boat", "EF10", "1110111100010000", "1110111100010000")]
        public void Crc13BbcTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc13Bbc);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
    }
}