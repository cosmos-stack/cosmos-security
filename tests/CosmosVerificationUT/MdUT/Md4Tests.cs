using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace MdUT
{
    [Trait("MdUT", "Md4Tests")]
    public class Md4Tests
    {
        [Theory(DisplayName = "Md4")]
        [InlineData("image", "0849E54FDE86FE2091E1B8FB5713BE65")]
        [InlineData("The quick brown fox jumps over the lazy dog", "1BEE69A46BA811185C194762ABAEAE90")]
        public void Md4Test(string data, string hex)
        {
            var function = MdFactory.Create(MdTypes.Md4);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }
    }
}