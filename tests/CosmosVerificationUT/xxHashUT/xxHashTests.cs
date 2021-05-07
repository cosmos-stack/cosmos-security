using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace xxHashUT
{
    [Trait("xxHashUT", "xxHashTests")]
    public class xxHashTests
    {
        [Theory]
        [InlineData("a", "56740D55")]
        [InlineData("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aliquam at erat vel nulla gravida convallis eget non quam orci aliquam.","C2D3E309")]
        public void xxHash32Test(string data, string hex)
        {
            var function = xxHash.Create(xxHashTypes.xxHashBit32);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("a", "5B6E8CA9F1C44ED2")]
        [InlineData("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aliquam at erat vel nulla gravida convallis eget non quam orci aliquam.","C430D602EE4FDCF7")]
        public void xxHash64Test(string data, string hex)
        {
            var function = xxHash.Create(xxHashTypes.xxHashBit64);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }
    }
}