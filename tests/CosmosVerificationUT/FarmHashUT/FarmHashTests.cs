using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace FarmHashUT
{
    [Trait("FarmHashUT", "FarmHashTests")]
    public class FarmHashTests
    {
        [Theory]
        [InlineData("Image Nice", "7A50E5F4")]
        public void FarmHash32Test(string data, string hex)
        {
            var function = FarmHashFactory.Create(FarmHashTypes.Fingerprint32);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Image Nice", "4A00593690B7BF6B")]
        public void FarmHash64Test(string data, string hex)
        {
            var function = FarmHashFactory.Create(FarmHashTypes.Fingerprint64);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Image Nice", "C2C4C9B6A4376433B07259963D5961E2")]
        public void FarmHash128Test(string data, string hex)
        {
            var function = FarmHashFactory.Create(FarmHashTypes.Fingerprint128);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }
    }
}