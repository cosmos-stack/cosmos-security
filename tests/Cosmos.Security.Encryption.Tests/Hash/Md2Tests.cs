using Cosmos.Security.Encryption;
using Xunit;

namespace Hash
{
    public class Md2Tests
    {
        [Fact]
        public void Md2()
        {
            var signature = MD2HashingProvider.Signature("The quick brown fox jumps over the lazy dog");
            Assert.Equal("03D85A0D629D2C442E987525319FC471", signature);
        }
    }
}