using Xunit;

namespace Cosmos.Encryption.Tests.Hash {
    public class Time33Tests {
        [Theory]
        [InlineData("image", 262700200)]
        [InlineData("image0", 79172056)]
        [InlineData("image1", 79172057)]
        public void Tme33(string data, long expectedValue) {
            var signature = Time33HashingProvider.Signature(data);
            Assert.Equal(expectedValue, signature);
        }
    }
}