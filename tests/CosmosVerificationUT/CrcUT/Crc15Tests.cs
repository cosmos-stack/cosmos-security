using Cosmos.Security.Verification.CRC;
using Shouldly;
using Xunit;

namespace CrcUT
{
    [Trait("CrcUT", "Crc15Tests")]
    public class Crc15Tests
    {
        [Theory(DisplayName = "CRC-15")]
        [InlineData("Nice", "1E06", "1111000000110", "001111000000110")]
        [InlineData("Nice Boat", "E679", "1110011001111001", "1110011001111001")]
        public void Crc15Test(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc15);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }

        [Theory(DisplayName = "CRC-15/MPT1732")]
        [InlineData("Nice", "C378", "1100001101111000", "1100001101111000")]
        [InlineData("Nice Boat", "917B", "1001000101111011", "1001000101111011")]
        public void Crc15Mpt1732Test(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc15Mpt1327);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
    }
}