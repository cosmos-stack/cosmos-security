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
            var function = BernsteinHashFactory.Create(BernsteinHashTypes.Time33);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }
        
        [Theory(DisplayName = "BernsteinHash")]
        [InlineData("image", "837CA907")]
        [InlineData("image0", "130DD9FC")]
        [InlineData("image1", "140DD9FC")]
        public void BernsteinHashTest(string data, string hex)
        {
            var function = BernsteinHashFactory.Create(BernsteinHashTypes.BernsteinHash);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }
        
        [Theory(DisplayName = "ModifiedBernsteinHash")]
        [InlineData("image", "67639C07")]
        [InlineData("image0", "77D028FB")]
        [InlineData("image1", "76D028FB")]
        public void ModifiedBernsteinHashTest(string data, string hex)
        {
            var function = BernsteinHashFactory.Create(BernsteinHashTypes.ModifiedBernsteinHash);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }
    }
}