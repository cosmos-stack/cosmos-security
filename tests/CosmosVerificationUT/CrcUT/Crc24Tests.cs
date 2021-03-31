using Cosmos.Security.Verification.CRC;
using Shouldly;
using Xunit;

namespace CrcUT
{
    [Trait("CrcUT", "Crc24Tests")]
    public class Crc24Tests
    {
        [Theory(DisplayName = "CRC-24")]
        [InlineData("Nice", "73F029", "11100111111000000101001", "011100111111000000101001")]
        [InlineData("Nice Boat", "510DA0", "10100010000110110100000", "010100010000110110100000")]
        public void Crc24Test(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc24);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }

        [Theory(DisplayName = "CRC-24/FlexrayA")]
        [InlineData("Nice", "69C5D3", "11010011100010111010011", "011010011100010111010011")]
        [InlineData("Nice Boat", "A8E7FF", "101010001110011111111111", "101010001110011111111111")]
        public void Crc24FlexrayATest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc24FlexrayA);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }

        [Theory(DisplayName = "CRC-24/FlexrayB")]
        [InlineData("Nice", "868FF1", "100001101000111111110001", "100001101000111111110001")]
        [InlineData("Nice Boat", "ADBD99", "101011011011110110011001", "101011011011110110011001")]
        public void Crc24FlexrayBTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc24FlexrayB);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
    }
}