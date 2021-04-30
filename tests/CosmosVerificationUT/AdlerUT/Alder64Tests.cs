using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace AdlerUT
{
    [Trait("AdlerUT", "Adler64Tests")]
    public class Adler64Tests
    {
        [Theory(DisplayName = "Adler-64")]
        [InlineData("Nice", "80010000A2030000", "111111111111110111111111111111101011101111111010000000000000000", "0111111111111110111111111111111101011101111111010000000000000000")]
        [InlineData("Nice Boat", "260300004D0F0000", "10011000000011000000000000000001001101000011110000000000000000", "0010011000000011000000000000000001001101000011110000000000000000")]
        [InlineData("Nice Boat, James love Jane very much.", "B70C000057ED0000", "100100011110011111111111111111110101000000100110000000000000000", "0100100011110011111111111111111110101000000100110000000000000000")]
        public void Adler64Test(string data, string hex, string bin, string binWithZero)
        {
            var function = AdlerFactory.Create(AdlerTypes.Adler64);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
            hashVal.GetBinString().ShouldBe(bin);
            hashVal.GetBinString(true).ShouldBe(binWithZero);
        }
    }
}