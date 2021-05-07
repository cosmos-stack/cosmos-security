using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace SpookyHashUT
{
    [Trait("SpookyHashUT","SpookyHashV2Tests")]
    public class SpookyHashV2Tests
    {
        [Theory]
        [InlineData("Image","EB7D2DCC")]
        [InlineData("Bob love James and James also love Bob.","1C3CC79F")]
        public void SpookyHashBit32Test(string data, string hex)
        {
            var function = SpookyHashFactory.Create(SpookyHashTypes.SpookyHash2Bit32);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }
        
        [Theory]
        [InlineData("Image","EB7D2DCC1385680F")]
        [InlineData("Bob love James and James also love Bob.","1C3CC79F2D95D407")]
        public void SpookyHashBit64Test(string data, string hex)
        {
            var function = SpookyHashFactory.Create(SpookyHashTypes.SpookyHash2Bit64);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Image","EB7D2DCC1385680FDFF3C6AF0E0D8153")]
        [InlineData("Bob love James and James also love Bob.","1C3CC79F2D95D407E79B7B284154B64B")]
        public void SpookyHashBit128Test(string data, string hex)
        {
            var function = SpookyHashFactory.Create(SpookyHashTypes.SpookyHash2Bit128);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }
    }
}