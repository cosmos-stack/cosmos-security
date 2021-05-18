#if !(NET451 || NET452)
using System.Security.Cryptography;
using Cosmos.Security.Cryptography;
using Shouldly;
using Xunit;

#else
using Cosmos.Security.Cryptography;
using Shouldly;
using Xunit;

#endif

namespace RsaUT
{
    public class RsaTests
    {
        [Fact]
        public void EncryptDecrypt_R1024_XML_Test()
        {
            var key = RsaKeyGenerator.Generate(AsymmetricKeyMode.Both, RsaKeySize.L1024);
            var function = RsaFactory.Create(key);
#if NET451 || NET452
            var cipherVal = function.EncryptByPublicKey("image", true);
            var originVal = function.DecryptByPrivateKey(cipherVal.CipherData, true);
#else
            var cipherVal = function.EncryptByPublicKey("image", RSAEncryptionPadding.OaepSHA1);
            var originVal = function.DecryptByPrivateKey(cipherVal.CipherData, RSAEncryptionPadding.OaepSHA1);
#endif
            Assert.Equal("image", originVal.GetOriginalDataDescriptor().GetString());
        }

        [Fact]
        public void EncryptDecrypt_R2048_XML_Test()
        {
            var key = RsaKeyGenerator.Generate(AsymmetricKeyMode.Both, RsaKeySize.L2048);
            var function = RsaFactory.Create(key);
#if NET451 || NET452
            var cipherVal = function.EncryptByPublicKey("image", true);
            var originVal = function.DecryptByPrivateKey(cipherVal.CipherData, true);
#else
            var cipherVal = function.EncryptByPublicKey("image", RSAEncryptionPadding.OaepSHA1);
            var originVal = function.DecryptByPrivateKey(cipherVal.CipherData, RSAEncryptionPadding.OaepSHA1);
#endif
            Assert.Equal("image", originVal.GetOriginalDataDescriptor().GetString());
        }

        [Fact]
        public void EncryptDecrypt_R3072_XML_Test()
        {
            var key = RsaKeyGenerator.Generate(AsymmetricKeyMode.Both, RsaKeySize.L3072);
            var function = RsaFactory.Create(key);
#if NET451 || NET452
            var cipherVal = function.EncryptByPublicKey("image", true);
            var originVal = function.DecryptByPrivateKey(cipherVal.CipherData, true);
#else
            var cipherVal = function.EncryptByPublicKey("image", RSAEncryptionPadding.OaepSHA1);
            var originVal = function.DecryptByPrivateKey(cipherVal.CipherData, RSAEncryptionPadding.OaepSHA1);
#endif
            Assert.Equal("image", originVal.GetOriginalDataDescriptor().GetString());
        }

        [Fact]
        public void EncryptDecrypt_R4096_XML_Test()
        {
            var key = RsaKeyGenerator.Generate(AsymmetricKeyMode.Both, RsaKeySize.L4096);
            var function = RsaFactory.Create(key);
#if NET451 || NET452
            var cipherVal = function.EncryptByPublicKey("image", true);
            var originVal = function.DecryptByPrivateKey(cipherVal.CipherData, true);
#else
            var cipherVal = function.EncryptByPublicKey("image", RSAEncryptionPadding.OaepSHA1);
            var originVal = function.DecryptByPrivateKey(cipherVal.CipherData, RSAEncryptionPadding.OaepSHA1);
#endif
            Assert.Equal("image", originVal.GetOriginalDataDescriptor().GetString());
        }

        [Fact]
        public void EncryptDecrypt_R1024_JSON_Test()
        {
            var key = RsaKeyGenerator.Generate(AsymmetricKeyMode.Both, RsaKeySize.L1024, RsaKeyFormat.JSON);
            var function = RsaFactory.Create(key);
#if NET451 || NET452
            var cipherVal = function.EncryptByPublicKey("image", true);
            var originVal = function.DecryptByPrivateKey(cipherVal.CipherData, true);
#else
            var cipherVal = function.EncryptByPublicKey("image", RSAEncryptionPadding.OaepSHA1);
            var originVal = function.DecryptByPrivateKey(cipherVal.CipherData, RSAEncryptionPadding.OaepSHA1);
#endif
            Assert.Equal("image", originVal.GetOriginalDataDescriptor().GetString());
        }

        [Fact]
        public void EncryptDecrypt_R2048_JSON_Test()
        {
            var key = RsaKeyGenerator.Generate(AsymmetricKeyMode.Both, RsaKeySize.L2048, RsaKeyFormat.JSON);
            var function = RsaFactory.Create(key);
#if NET451 || NET452
            var cipherVal = function.EncryptByPublicKey("image", true);
            var originVal = function.DecryptByPrivateKey(cipherVal.CipherData, true);
#else
            var cipherVal = function.EncryptByPublicKey("image", RSAEncryptionPadding.OaepSHA1);
            var originVal = function.DecryptByPrivateKey(cipherVal.CipherData, RSAEncryptionPadding.OaepSHA1);
#endif
            Assert.Equal("image", originVal.GetOriginalDataDescriptor().GetString());
        }

        [Fact]
        public void EncryptDecrypt_R3072_JSON_Test()
        {
            var key = RsaKeyGenerator.Generate(AsymmetricKeyMode.Both, RsaKeySize.L3072, RsaKeyFormat.JSON);
            var function = RsaFactory.Create(key);
#if NET451 || NET452
            var cipherVal = function.EncryptByPublicKey("image", true);
            var originVal = function.DecryptByPrivateKey(cipherVal.CipherData, true);
#else
            var cipherVal = function.EncryptByPublicKey("image", RSAEncryptionPadding.OaepSHA1);
            var originVal = function.DecryptByPrivateKey(cipherVal.CipherData, RSAEncryptionPadding.OaepSHA1);
#endif
            Assert.Equal("image", originVal.GetOriginalDataDescriptor().GetString());
        }

        [Fact]
        public void EncryptDecrypt_R4096_JSON_Test()
        {
            var key = RsaKeyGenerator.Generate(AsymmetricKeyMode.Both, RsaKeySize.L4096, RsaKeyFormat.JSON);
            var function = RsaFactory.Create(key);
#if NET451 || NET452
            var cipherVal = function.EncryptByPublicKey("image", true);
            var originVal = function.DecryptByPrivateKey(cipherVal.CipherData, true);
#else
            var cipherVal = function.EncryptByPublicKey("image", RSAEncryptionPadding.OaepSHA1);
            var originVal = function.DecryptByPrivateKey(cipherVal.CipherData, RSAEncryptionPadding.OaepSHA1);
#endif
            Assert.Equal("image", originVal.GetOriginalDataDescriptor().GetString());
        }
    }
}