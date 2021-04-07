using Cosmos.Security.Verification.SM;
using Shouldly;
using Xunit;

namespace SmUT
{
    [Trait("SmUT", "Sm3Tests")]
    public class Sm3Tests
    {
        [Theory(DisplayName = "Sm3")]
        [InlineData("image", "712E4E88219F253644798B92C82B711B178AE0BF8EE785196F14E1C20A477ED3")]
        [InlineData("天下无敌", "C1B8D9314F9877FCE3669031A2A03F605B0CCD25A985AB579E8B7C107525058E")]
        [InlineData("The quick brown fox jumps over the lazy dog", "5FDFE814B8573CA021983970FC79B2218C9570369B4859684E2E4C3FC76CB8EA")]
        public void SM3Test(string data, string hex)
        {
            var function = Sm3Factory.Create();
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }
    }
}