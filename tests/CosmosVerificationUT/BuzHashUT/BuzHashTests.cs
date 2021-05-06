using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace BuzHashUT
{
    [Trait("BuzHashUT", "BuzHashTests")]
    public class BuzHashTests
    {
        [Theory]
        [InlineData("Image", "6E")]
        public void BuzHashBit8Test(string data, string hex)
        {
            var function = BuzHash.Create(BuzHashTypes.BuzHashBit8);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Image", "7179")]
        public void BuzHashBit16Test(string data, string hex)
        {
            var function = BuzHash.Create(BuzHashTypes.BuzHashBit16);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Image", "6A796DFA")]
        public void BuzHashBit32Test(string data, string hex)
        {
            var function = BuzHash.Create(BuzHashTypes.BuzHashBit32);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Image", "76796DFAD7845903")]
        public void BuzHashBit64Test(string data, string hex)
        {
            var function = BuzHash.Create(BuzHashTypes.BuzHashBit64);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }
    }
}