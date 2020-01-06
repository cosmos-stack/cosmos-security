using System.Security.Cryptography;
using Xunit;

namespace Cosmos.Encryption.Tests.Asymmetric {
    public class RsaTests {
        [Fact]
        public void EncryptDecrypt_R1024_XML_Test() {
            var key = RSAEncryptionProvider.CreateKey(RSAKeySizeTypes.R1024);
#if NET451
            var signature = RSAEncryptionProvider.EncryptByPublicKey("image", key.PublicKey, true);
            var origin = RSAEncryptionProvider.DecryptByPrivateKey(signature, key.PrivateKey, true);
#else
            var signature = RSAEncryptionProvider.EncryptByPublicKey("image", key.PublicKey, RSAEncryptionPadding.OaepSHA1);
            var origin = RSAEncryptionProvider.DecryptByPrivateKey(signature, key.PrivateKey, RSAEncryptionPadding.OaepSHA1);
#endif
            Assert.Equal("image", origin);
        }

        [Fact]
        public void EncryptDecrypt_R2048_XML_Test() {
            var key = RSAEncryptionProvider.CreateKey();
#if NET451
            var signature = RSAEncryptionProvider.EncryptByPublicKey("image", key.PublicKey, true);
            var origin = RSAEncryptionProvider.DecryptByPrivateKey(signature, key.PrivateKey, true);
#else
            var signature = RSAEncryptionProvider.EncryptByPublicKey("image", key.PublicKey, RSAEncryptionPadding.OaepSHA1);
            var origin = RSAEncryptionProvider.DecryptByPrivateKey(signature, key.PrivateKey, RSAEncryptionPadding.OaepSHA1);
#endif
            Assert.Equal("image", origin);
        }

        [Fact]
        public void EncryptDecrypt_R3072_XML_Test() {
            var key = RSAEncryptionProvider.CreateKey(RSAKeySizeTypes.R3072);
#if NET451
            var signature = RSAEncryptionProvider.EncryptByPublicKey("image", key.PublicKey, true);
            var origin = RSAEncryptionProvider.DecryptByPrivateKey(signature, key.PrivateKey, true);
#else
            var signature = RSAEncryptionProvider.EncryptByPublicKey("image", key.PublicKey, RSAEncryptionPadding.OaepSHA1);
            var origin = RSAEncryptionProvider.DecryptByPrivateKey(signature, key.PrivateKey, RSAEncryptionPadding.OaepSHA1);
#endif
            Assert.Equal("image", origin);
        }

        [Fact]
        public void EncryptDecrypt_R4096_XML_Test() {
            var key = RSAEncryptionProvider.CreateKey(RSAKeySizeTypes.R4096);
#if NET451
            var signature = RSAEncryptionProvider.EncryptByPublicKey("image", key.PublicKey, true);
            var origin = RSAEncryptionProvider.DecryptByPrivateKey(signature, key.PrivateKey, true);
#else
            var signature = RSAEncryptionProvider.EncryptByPublicKey("image", key.PublicKey, RSAEncryptionPadding.OaepSHA1);
            var origin = RSAEncryptionProvider.DecryptByPrivateKey(signature, key.PrivateKey, RSAEncryptionPadding.OaepSHA1);
#endif
            Assert.Equal("image", origin);
        }

        [Fact]
        public void EncryptDecrypt_R1024_JSON_Test() {
            var key = RSAEncryptionProvider.CreateKey(RSAKeySizeTypes.R1024, RSAKeyTypes.JSON);
#if NET451
            var signature = RSAEncryptionProvider.EncryptByPublicKey("image", key.PublicKey, true, keyType: RSAKeyTypes.JSON);
            var origin = RSAEncryptionProvider.DecryptByPrivateKey(signature, key.PrivateKey, true, keyType: RSAKeyTypes.JSON);
#else
            var signature = RSAEncryptionProvider.EncryptByPublicKey("image", key.PublicKey, RSAEncryptionPadding.OaepSHA1, keyType: RSAKeyTypes.JSON);
            var origin = RSAEncryptionProvider.DecryptByPrivateKey(signature, key.PrivateKey, RSAEncryptionPadding.OaepSHA1, keyType: RSAKeyTypes.JSON);
#endif
            Assert.Equal("image", origin);
        }

        [Fact]
        public void EncryptDecrypt_R2048_JSON_Test() {
            var key = RSAEncryptionProvider.CreateKey(keyType: RSAKeyTypes.JSON);
#if NET451
            var signature = RSAEncryptionProvider.EncryptByPublicKey("image", key.PublicKey, true, keyType: RSAKeyTypes.JSON);
            var origin = RSAEncryptionProvider.DecryptByPrivateKey(signature, key.PrivateKey, true, keyType: RSAKeyTypes.JSON);
#else
            var signature = RSAEncryptionProvider.EncryptByPublicKey("image", key.PublicKey, RSAEncryptionPadding.OaepSHA1, keyType: RSAKeyTypes.JSON);
            var origin = RSAEncryptionProvider.DecryptByPrivateKey(signature, key.PrivateKey, RSAEncryptionPadding.OaepSHA1, keyType: RSAKeyTypes.JSON);
#endif
            Assert.Equal("image", origin);
        }

        [Fact]
        public void EncryptDecrypt_R3072_JSON_Test() {
            var key = RSAEncryptionProvider.CreateKey(RSAKeySizeTypes.R3072, RSAKeyTypes.JSON);
#if NET451
            var signature = RSAEncryptionProvider.EncryptByPublicKey("image", key.PublicKey, true, keyType: RSAKeyTypes.JSON);
            var origin = RSAEncryptionProvider.DecryptByPrivateKey(signature, key.PrivateKey, true, keyType: RSAKeyTypes.JSON);
#else
            var signature = RSAEncryptionProvider.EncryptByPublicKey("image", key.PublicKey, RSAEncryptionPadding.OaepSHA1, keyType: RSAKeyTypes.JSON);
            var origin = RSAEncryptionProvider.DecryptByPrivateKey(signature, key.PrivateKey, RSAEncryptionPadding.OaepSHA1, keyType: RSAKeyTypes.JSON);
#endif
            Assert.Equal("image", origin);
        }

        [Fact]
        public void EncryptDecrypt_R4096_JSON_Test() {
            var key = RSAEncryptionProvider.CreateKey(RSAKeySizeTypes.R4096, RSAKeyTypes.JSON);
#if NET451
            var signature = RSAEncryptionProvider.EncryptByPublicKey("image", key.PublicKey, true, keyType: RSAKeyTypes.JSON);
            var origin = RSAEncryptionProvider.DecryptByPrivateKey(signature, key.PrivateKey, true, keyType: RSAKeyTypes.JSON);
#else
            var signature = RSAEncryptionProvider.EncryptByPublicKey("image", key.PublicKey, RSAEncryptionPadding.OaepSHA1, keyType: RSAKeyTypes.JSON);
            var origin = RSAEncryptionProvider.DecryptByPrivateKey(signature, key.PrivateKey, RSAEncryptionPadding.OaepSHA1, keyType: RSAKeyTypes.JSON);
#endif
            Assert.Equal("image", origin);
        }
    }
}