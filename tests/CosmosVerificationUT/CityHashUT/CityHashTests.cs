using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace BuzHashUT
{
    [Trait("CityHashUT", "CityHashTests")]
    public class CityHashTests
    {
        [Theory]
        [InlineData("Image", "0909EE4B")]
        public void CityHashBit32Test(string data, string hex)
        {
            var function = CityHashFactory.Create(CityHashTypes.CityHashBit32);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Image", "2CA33B437DC7FFDE")]
        public void CityHashBit64Test(string data, string hex)
        {
            var function = CityHashFactory.Create(CityHashTypes.CityHashBit64);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Image", "EDD09172411F26276569671C3EE4A259")]
        public void CityHashBit128Test(string data, string hex)
        {
            var function = CityHashFactory.Create(CityHashTypes.CityHashBit128);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }
    }
}