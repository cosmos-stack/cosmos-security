using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace BlakeUT
{
    [Trait("BlakeUT", "Blake1Tests")]
    public class Blake1Tests
    {
        // [Theory]
        // [InlineData("Discard medicine more than two years old.", "22297d373b751f581944bb26315133f6fda2f0bf60f65db773900f61f81b7e79")]
        // [InlineData("The quick brown fox jumps over the lazy dog","7576698EE9CAD30173080678E5965916ADBB11CB5245D386BF1FFDA1CB26C9D7")]
        // public void Blake256Test(string data, string hex)
        // {
        //     var function = BlakeFactory.Create(BlakeTypes.Blake256);
        //     var hashVal = function.ComputeHash(data);
        //     hashVal.AsHexString(true).ShouldBe(hex);
        // }

        [Theory]
        [InlineData("Discard medicine more than two years old.", "B130505F7E4F980F872964954CAB9AE263FF4D5DB008DADA06E1F078CC17E124E8CE9372567DCEDE106C412A3214043C69138A179BE6862E77A80A60939345F1")]
        [InlineData("The quick brown fox jumps over the lazy dog", "1F7E26F63B6AD25A0896FD978FD050A1766391D2FD0471A77AFB975E5034B7AD2D9CCF8DFB47ABBBE656E1B82FBC634BA42CE186E8DC5E1CE09A885D41F43451")]
        public void Blake512Test(string data, string hex)
        {
            var function = BlakeFactory.Create(BlakeTypes.Blake512);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }
    }
}