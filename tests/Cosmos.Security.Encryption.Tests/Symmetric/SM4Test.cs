using Cosmos.Security.Encryption;
using Xunit;

namespace Symmetric
{
    public class SM4Test
    {
        [Fact]
        public void Encrypt_ECB()
        {
            var key = "1234567890123456";
            var s = SM4EncryptionProvider.Encrypt("天下无双", key);
            var o = SM4EncryptionProvider.Decrypt(s, key);
            Assert.Equal("天下无双", o);
        }

        [Fact]
        public void Encrypt_CBC()
        {
            var key = "1234567890123456";
            var s = SM4EncryptionProvider.Encrypt("天下无双", key, "1234567890123456");
            var o = SM4EncryptionProvider.Decrypt(s, key, "1234567890123456");
            Assert.Equal("天下无双", o);
        }
    }
}
