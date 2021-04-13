using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace MurmurHashUT
{
    [Trait("MurmurHashUT", "MurmurHash2Tests")]
    public class MurmurHash2Tests
    {
        [Theory(DisplayName = "MurmurHash2")]
        [InlineData("image", "4E84226B85264128")]
        [InlineData("The quick brown fox jumps over the lazy dog", "1B862A0433CA8955")]
        public void MM2(string data, string hex)
        {
            var function = MurmurHashFactory.Create(MurmurHashTypes.MurmurHash2);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }
        
        [Theory(DisplayName = "MurmurHash2/32")]
        [InlineData("image", "CE1C45E9")]
        [InlineData("The quick brown fox jumps over the lazy dog", "D0292721")]
        public void MM2Bit32(string data, string hex)
        {
            var function = MurmurHashFactory.Create(MurmurHashTypes.MurmurHash2Bit32);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }
        
        [Theory(DisplayName = "MurmurHash2/64")]
        [InlineData("image", "4E84226B85264128")]
        [InlineData("The quick brown fox jumps over the lazy dog", "1B862A0433CA8955")]
        public void MM2Bit6(string data, string hex)
        {
            var function = MurmurHashFactory.Create(MurmurHashTypes.MurmurHash2Bit64);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }
    }
}