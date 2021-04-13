using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace ShaUT
{
    [Trait("ShaUT","Sha1Tests")]
    public class Sha1Tests
    {
        [Theory(DisplayName = "Sha1")]
        [InlineData("image", "0E76292794888D4F1FA75FB3AFF4CA27C58F56A6")]
        [InlineData("The quick brown fox jumps over the lazy dog", "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12")]
        public void Sha1Test(string data, string hex)
        {
            var function = ShaFactory.Create(ShaTypes.Sha1);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }
    }
}