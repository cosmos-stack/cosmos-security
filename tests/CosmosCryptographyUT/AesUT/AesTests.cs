using Cosmos.Conversions;
using Cosmos.Security.Cryptography;
using Shouldly;
using Xunit;

namespace AesUT
{
    public class AesTests
    {
        [Fact]
        public void Encrypt_L128_Test()
        {
            var key = AesFactory.GenerateKey(AesTypes.Aes128);
            var function = AesFactory.Create(AesTypes.Aes128, key);
            var cryptoVal0 = function.Encrypt("实现中华民族伟大复兴的中国梦");
            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData);
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("实现中华民族伟大复兴的中国梦");

            var cryptoVal2 = function.Decrypt(BaseConv.ToBase64(cryptoVal0.CipherData), CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("实现中华民族伟大复兴的中国梦");
        }

        [Fact]
        public void Encrypt_L192_Test()
        {
            var key = AesFactory.GenerateKey(AesTypes.Aes192);
            var function = AesFactory.Create(AesTypes.Aes192, key);
            var cryptoVal0 = function.Encrypt("实现中华民族伟大复兴的中国梦");
            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData);
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("实现中华民族伟大复兴的中国梦");

            var cryptoVal2 = function.Decrypt(BaseConv.ToBase64(cryptoVal0.CipherData), CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("实现中华民族伟大复兴的中国梦");
        }

        [Fact]
        public void Encrypt_L256_Test()
        {
            var key = AesFactory.GenerateKey(AesTypes.Aes256);
            var function = AesFactory.Create(AesTypes.Aes256, key);
            var cryptoVal0 = function.Encrypt("实现中华民族伟大复兴的中国梦");
            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData);
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("实现中华民族伟大复兴的中国梦");

            var cryptoVal2 = function.Decrypt(BaseConv.ToBase64(cryptoVal0.CipherData), CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("实现中华民族伟大复兴的中国梦");
        }

        [Fact]
        public void Encrypt_L128_WithSalt_Test()
        {
            var key = AesFactory.GenerateKey(AesTypes.Aes128);
            var function = AesFactory.Create(AesTypes.Aes128, key);
            var cryptoVal0 = function.Encrypt("实现中华民族伟大复兴的中国梦", "12345678");
            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData, "12345678");
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("实现中华民族伟大复兴的中国梦");

            var cryptoVal2 = function.Decrypt(BaseConv.ToBase64(cryptoVal0.CipherData), "12345678", CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("实现中华民族伟大复兴的中国梦");
        }

        [Fact]
        public void Encrypt_L192_WithSalt_Test()
        {
            var key = AesFactory.GenerateKey(AesTypes.Aes192);
            var function = AesFactory.Create(AesTypes.Aes192, key);
            var cryptoVal0 = function.Encrypt("实现中华民族伟大复兴的中国梦", "12345678");
            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData, "12345678");
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("实现中华民族伟大复兴的中国梦");

            var cryptoVal2 = function.Decrypt(BaseConv.ToBase64(cryptoVal0.CipherData), "12345678", CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("实现中华民族伟大复兴的中国梦");
        }

        [Fact]
        public void Encrypt_L256_WithSalt_Test()
        {
            var key = AesFactory.GenerateKey(AesTypes.Aes256);
            var function = AesFactory.Create(AesTypes.Aes256, key);
            var cryptoVal0 = function.Encrypt("实现中华民族伟大复兴的中国梦", "12345678");
            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData, "12345678");
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("实现中华民族伟大复兴的中国梦");

            var cryptoVal2 = function.Decrypt(BaseConv.ToBase64(cryptoVal0.CipherData), "12345678", CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("实现中华民族伟大复兴的中国梦");
        }
    }
}