using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace CrcUT
{
    [Trait("CrcUT", "Crc40Tests")]
    public class Crc40Tests
    {
        [Theory(DisplayName = "CRC-40/GSM")]
        [InlineData("Nice", "F3690C3EE6", "1111001101101001000011000011111011100110", "1111001101101001000011000011111011100110")]
        [InlineData("Nice Boat", "02F58189C3", "1011110101100000011000100111000011", "0000001011110101100000011000100111000011")]
        public void Crc40GsmTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc40Gsm);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
            hashVal.GetBinString().ShouldBe(bin);
            hashVal.GetBinString(true).ShouldBe(binWithZero);
        }
    }
}