using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace CrcUT
{
    [Trait("CrcUT", "Crc11Tests")]
    public class Crc11Tests
    {
        [Theory(DisplayName = "CRC-11")]
        [InlineData("Nice", "4900", "100100100000000", "100100100000000")]
        [InlineData("Nice Boat", "8D02", "1000110100000010", "1000110100000010")]
        public void Crc11Test(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc11);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
    }
}