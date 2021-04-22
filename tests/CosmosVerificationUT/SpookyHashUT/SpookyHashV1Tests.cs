using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace SpookyHashUT
{
    [Trait("SpookyHashUT", "SpookyHashV1Tests")]
    public class SpookyHashV1Tests
    {
        [Theory]
        [InlineData("Image", "5338097F")]
        [InlineData("Bob love James and James also love Bob.", "F4D645EB")]
        public void SpookyHashBit32Test(string data, string hex)
        {
            var function = SpookyHashFactory.Create(SpookyHashTypes.SpookyHash1Bit32);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Image", "5338097FD9B6047A")]
        [InlineData("Bob love James and James also love Bob.", "F4D645EBC32B620F")]
        public void SpookyHashBit64Test(string data, string hex)
        {
            var function = SpookyHashFactory.Create(SpookyHashTypes.SpookyHash1Bit64);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Image", "5338097FD9B6047ACA3BF1800575485D")]
        [InlineData("Bob love James and James also love Bob.", "F4D645EBC32B620FE8A7FC7BFFE3D7FB")]
        public void SpookyHashBit128Test(string data, string hex)
        {
            var function = SpookyHashFactory.Create(SpookyHashTypes.SpookyHash1Bit128);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }
    }
}