using Cosmos.Security.Encryption;
using Xunit;

namespace Hash
{
    public class SM3Tests
    {
        [Fact]
        public void HashTest()
        {
            var s = SM3HashingProvider.Signature("天下无敌");
            Assert.Equal("wbjZMU+Yd/zjZpAxoqA/YFsMzSWphatXnot8EHUlBY4=", s);
        }
    }
}
