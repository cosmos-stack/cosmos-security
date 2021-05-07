using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace MetroHashUT
{
    [Trait("MetroHashUT", "MetroHashTests")]
    public class MetroHashTests
    {
        [Theory]
        [InlineData("Image", "D01FD1CADFEAA710")]
        public void MetroHash64Test(string data, string hex)
        {
            var function = MetroHash.Create(MetroHashTypes.MetroHashBit64);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Image", "CC54CF3D63C526EEB2857EB584C1C395")]
        public void MetroHash128Test(string data, string hex)
        {
            var function = MetroHash.Create(MetroHashTypes.MetroHashBit128);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }
    }
}