using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace CrcUT
{
    [Trait("CrcUT", "Crc10Tests")]
    public class Crc10Tests
    {
        [Theory(DisplayName = "CRC-10")]
        [InlineData("Nice", "3B02", "11101100000010", "11101100000010")]
        [InlineData("Nice Boat", "3C03", "11110000000011", "11110000000011")]
        public void Crc10Test(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc10);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }

        [Theory(DisplayName = "CRC-10/CDMA2000")]
        [InlineData("Nice", "4502", "100010100000010", "100010100000010")]
        [InlineData("Nice Boat", "C500", "1100010100000000", "1100010100000000")]
        public void Crc10Cdma2000Test(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc10Cdma2000);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
    }
}