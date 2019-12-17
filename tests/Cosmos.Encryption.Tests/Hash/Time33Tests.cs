using Xunit;

namespace Cosmos.Encryption.Tests.Hash {
    public class Time33Tests {
        [Fact]
        public void Tme33() {
            var signature = Time33HashingProvider.Signature("image");
            var signature0 = Time33HashingProvider.Signature("image0");
            var signature1 = Time33HashingProvider.Signature("image1");
            Assert.Equal(262700200, signature);
            Assert.Equal(79172056, signature0);
            Assert.Equal(79172057, signature1);
        }
    }
}