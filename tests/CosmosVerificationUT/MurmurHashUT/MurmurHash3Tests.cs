using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace MurmurHashUT
{
    [Trait("MurmurHashUT", "MurmurHash3Tests")]
    public class MurmurHash3Tests
    {
        [Theory(DisplayName = "MurmurHash3")]
        [InlineData("image", "1492C3C8")]
        [InlineData("The quick brown fox jumps over the lazy dog", "23F74F2E")]
        public void MM3(string data, string hex)
        {
            var function = MurmurHashFactory.Create(MurmurHashTypes.MurmurHash3);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }

        [Theory(DisplayName = "MurmurHash3/32")]
        [InlineData("image", "1492C3C8")]
        [InlineData("The quick brown fox jumps over the lazy dog", "23F74F2E")]
        public void MM3Bit32(string data, string hex)
        {
            var function = MurmurHashFactory.Create(MurmurHashTypes.MurmurHash3Bit32);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }

        [Theory(DisplayName = "MurmurHash3/128")]
        [InlineData("image", "F71C38180A2F8DA2CB0B0723A5B1A4B4")]
        [InlineData("The quick brown fox jumps over the lazy dog", "6C1B07BC7BBC4BE347939AC4A93C437A")]
        public void MM3Bit128(string data, string hex)
        {
            var function = MurmurHashFactory.Create(MurmurHashTypes.MurmurHash3Bit128);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }
    }
}