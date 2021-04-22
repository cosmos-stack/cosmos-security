using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace BlakeUT
{
    [Trait("BlakeUT", "Blake2Tests")]
    public class Blake2Tests
    {
        [Theory]
        [InlineData("HHHHAAAALLLLOOOOWWWWEEEELLLLTTTT", "BBC9E82DBF9A8897A5EC2F6836C381DBE27AC0B8ECD9912AFA67459EF9474D70A52BF24AD5DCF29DBB8004D19A387B6516CC47FFAE99D59D52EFC013456C6B48")]
        public void Blake2BTest(string data, string hex)
        {
            var function = BlakeFactory.Create(BlakeTypes.Blake2B);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }
        
        [Theory]
        [InlineData("HHHHAAAALLLLOOOOWWWWEEEELLLLTTTT", "4C02B80D515F400156A5F2B26085E5B13B590AE613D331B0E5B9BF1AAB69F09A")]
        public void Blake2STest(string data, string hex)
        {
            var function = BlakeFactory.Create(BlakeTypes.Blake2S);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }
    }
}