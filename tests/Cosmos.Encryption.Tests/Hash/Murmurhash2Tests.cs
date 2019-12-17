using Xunit;

namespace Cosmos.Encryption.Tests.Hash {
    public class Murmurhash2Tests {
        [Fact]
        public void MM2() {
            var signature = MurmurHash2Provider.Signature("image");
            Assert.Equal((uint) 868806358, signature);
        }
    }
}