using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace DjbUT
{
    [Trait("DjbUT", "Time33Tests")]
    public class Time33Tests
    {
        [Theory(DisplayName = "DJBX33A/Time33")]
        [InlineData("image", "A87CA80F")]
        [InlineData("image0", "D811B804")]
        [InlineData("image1", "D911B804")]
        public void Time33Test(string data, string hex)
        {
            var function = Time33Factory.Create();
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }
    }
}