using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace PearsonUT
{
    [Trait("PearsonUT", "PearsonTests")]
    public class PearsonTests
    {
        [Theory]
        [InlineData("1234", "E9")]
        [InlineData("d243a412051b5ba25266ed673e034a0594c0f64cf794e2ed108cb47ac53bc2bf", "9E")]
        [InlineData("Nice to see you", "EF")]
        public void PearsonTest(string data, string hex)
        {
            var function = PearsonFactory.Create();
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }
    }
}