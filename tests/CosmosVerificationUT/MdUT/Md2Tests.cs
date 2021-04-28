using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace MdUT
{
    [Trait("MdUT", "Md2Tests")]
    public class Md2Tests
    {
        [Theory(DisplayName = "Md2")]
        [InlineData("The quick brown fox jumps over the lazy dog", "03D85A0D629D2C442E987525319FC471")]
        public void Md2Test(string data, string hex)
        {
            var function = MdFactory.Create(MdTypes.Md2);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }
    }
}