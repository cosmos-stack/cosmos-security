using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace ShaUT
{
    [Trait("ShaUT", "SHa3Tests")]
    public class SHa3Tests
    {
        [Theory(DisplayName = "Sha3/256")]
        [InlineData("image", "EEE4DC3D290B9B193EBBAD5ADB5F07712F94BB178DAA7B33F5D7E870984FAB1D")]
        [InlineData("The quick brown fox jumps over the lazy dog", "69070DDA01975C8C120C3AADA1B282394E7F032FA9CF32F4CB2259A0897DFC04")]
        public void Sha3Bit256Test(string data, string hex)
        {
            var function = ShaFactory.Create(ShaTypes.Sha3Bit256);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }

        [Theory(DisplayName = "Sha3/224")]
        [InlineData("image", "622EF4E25AA58C4169F32B903ED53B1A76CC556581093D6A8A8A0898")]
        [InlineData("Hello World!", "716596AFADFA17CD1CB35133829A02B03E4EED398CE029CE78A2161D")]
        [InlineData("The quick brown fox jumps over the lazy dog", "D15DADCEAA4D5D7BB3B48F446421D542E08AD8887305E28D58335795")]
        public void Sha3Bit224Test(string data, string hex)
        {
            var function = ShaFactory.Create(ShaTypes.Sha3Bit224);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }

        [Theory(DisplayName = "Sha3/384")]
        [InlineData("image", "85E4EE4FE2204FD1155F3DF214DC30C49014767A12948E84B7086C4825D3C7051477B42F6D8806A98DA2F58525BAABCE")]
        [InlineData("The quick brown fox jumps over the lazy dog", "7063465E08A93BCE31CD89D2E3CA8F602498696E253592ED26F07BF7E703CF328581E1471A7BA7AB119B1A9EBDF8BE41")]
        public void Sha3Bit384Test(string data, string hex)
        {
            var function = ShaFactory.Create(ShaTypes.Sha3Bit384);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }

        [Theory(DisplayName = "Sha3/512")]
        [InlineData("image", "4172ADCA0DAEC581C146D499B2E0CA699E465C8C8490C97C910BDE840A107FF349835F71615187CF1AAB84B88F2159FFAF910BA2F88725963B8B07CECA7E3D4A")]
        [InlineData("The quick brown fox jumps over the lazy dog", "01DEDD5DE4EF14642445BA5F5B97C15E47B9AD931326E4B0727CD94CEFC44FFF23F07BF543139939B49128CAF436DC1BDEE54FCB24023A08D9403F9B4BF0D450")]
        public void Sha3Bit512Test(string data, string hex)
        {
            var function = ShaFactory.Create(ShaTypes.Sha3Bit512);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }
    }
}