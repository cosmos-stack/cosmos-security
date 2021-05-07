using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace JenkinsUT
{
    [Trait("JenkinsUT", "JenkinsLookupTests")]
    public class JenkinsLookupTests
    {
        [Theory]
        [InlineData("Image", "D4FECFA9")]
        public void JenkinsLookup2Test(string data, string hex)
        {
            var function = JenkinsFactory.Create(JenkinsTypes.Lookup2);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Image", "15BC3809")]
        public void JenkinsLookup3Bit32Test(string data, string hex)
        {
            var function = JenkinsFactory.Create(JenkinsTypes.Lookup3Bit32);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Image", "15BC3809EE9CF13F")]
        public void JenkinsLookup3Bit64Test(string data, string hex)
        {
            var function = JenkinsFactory.Create(JenkinsTypes.Lookup3Bit64);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }
    }
}