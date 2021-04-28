using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace MurmurHashUT
{
    [Trait("MurmurHashUT","MurmurHash1Tests")]
    public class MurmurHash1Tests
    {
        [Theory(DisplayName = "MurmurHash1")]
        [InlineData("image", "6D3604AB")]
        [InlineData("The quick brown fox jumps over the lazy dog", "851E251A")]
        public void MM1(string data, string hex)
        {
            var function = MurmurHashFactory.Create(MurmurHashTypes.MurmurHash1);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }
    }
}