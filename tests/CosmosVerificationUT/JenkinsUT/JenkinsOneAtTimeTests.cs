using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace JenkinsUT
{
    [Trait("JenkinsUT", "JenkinsOneAtTimeTests")]
    public class JenkinsOneAtTimeTests
    {
        [Theory]
        [InlineData("Image", "B5FEE568")]
        public void JenkinsOneAtTimeTest(string data, string hex)
        {
            var function = JenkinsFactory.Create(JenkinsTypes.OneAtTime);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }
    }
}