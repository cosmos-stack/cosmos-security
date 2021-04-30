using System.Text;
using Cosmos.Conversions;
using Cosmos.Security.Cryptography;
using Shouldly;
using Xunit;

namespace DesUT
{
    public class TripleDesTests
    {
        [Fact]
        public void EncryptDecrypt_L128_Test()
        {
            var key = DesFactory.GenerateKey(DesTypes.TripleDES128, "alexinea&#%12!", "forerunner", Encoding.UTF8);
            var function = DesFactory.Create(DesTypes.TripleDES128, key);
            var cryptoVal0 = function.Encrypt("image");

            BaseConv.ToBase64(cryptoVal0.CipherData).ShouldBe("pG8iQQQVIQY=");

            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData);
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("image");

            var cryptoVal2 = function.Decrypt(BaseConv.ToBase64(cryptoVal0.CipherData), CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("image");
        }

        [Fact]
        public void EncryptDecrypt_WithSalt_L128_Test()
        {
            var key = DesFactory.GenerateKey(DesTypes.TripleDES128, "alexinea&#%12!", "forerunner", Encoding.UTF8);
            var function = DesFactory.Create(DesTypes.TripleDES128, key);
            var cryptoVal0 = function.Encrypt("image", "123412341234");

            BaseConv.ToBase64(cryptoVal0.CipherData).ShouldBe("A1Wq2SHzNwU=");

            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData, "123412341234");
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("image");

            var cryptoVal2 = function.Decrypt(BaseConv.ToBase64(cryptoVal0.CipherData), "123412341234", CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("image");
        }

        [Fact]
        public void EncryptDecrypt_L192_Test()
        {
            var key = DesFactory.GenerateKey(DesTypes.TripleDES192, "alexinea&#%12!", "forerunner", Encoding.UTF8);
            var function = DesFactory.Create(DesTypes.TripleDES192, key);
            var cryptoVal0 = function.Encrypt("image");

            BaseConv.ToBase64(cryptoVal0.CipherData).ShouldBe("Y6tAf/GrLx8=");

            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData);
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("image");

            var cryptoVal2 = function.Decrypt(BaseConv.ToBase64(cryptoVal0.CipherData), CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("image");
        }

        [Fact]
        public void EncryptDecrypt_WithSalt_L192_Test()
        {
            var key = DesFactory.GenerateKey(DesTypes.TripleDES192, "alexinea&#%12!", "forerunner", Encoding.UTF8);
            var function = DesFactory.Create(DesTypes.TripleDES192, key);
            var cryptoVal0 = function.Encrypt("image", "123412341234");

            BaseConv.ToBase64(cryptoVal0.CipherData).ShouldBe("nmTHXan4jN8=");

            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData, "123412341234");
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("image");

            var cryptoVal2 = function.Decrypt(BaseConv.ToBase64(cryptoVal0.CipherData), "123412341234", CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("image");
        }
        
        [Fact]
        public void EncryptDecrypt_WithAutoCreateKey_L128_Test()
        {
            var key = DesFactory.GenerateKey(DesTypes.TripleDES128);
            var function = DesFactory.Create(DesTypes.TripleDES128, key);
            var cryptoVal0 = function.Encrypt("实现中华民族伟大复兴的中国梦");
            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData);
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("实现中华民族伟大复兴的中国梦");

            var cryptoVal2 = function.Decrypt(BaseConv.ToBase64(cryptoVal0.CipherData), CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("实现中华民族伟大复兴的中国梦");
        }

        [Fact]
        public void EncryptDecrypt_WithSalt_WithAutoCreateKey_L128_Test()
        {
            var key = DesFactory.GenerateKey(DesTypes.TripleDES128);
            var function = DesFactory.Create(DesTypes.TripleDES128, key);
            var cryptoVal0 = function.Encrypt("实现中华民族伟大复兴的中国梦", "123412341234");
            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData, "123412341234");
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("实现中华民族伟大复兴的中国梦");

            var cryptoVal2 = function.Decrypt(BaseConv.ToBase64(cryptoVal0.CipherData), "123412341234", CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("实现中华民族伟大复兴的中国梦");
        }

        [Fact]
        public void EncryptDecrypt_WithAutoCreateKey_L192_Test()
        {
            var key = DesFactory.GenerateKey(DesTypes.TripleDES192);
            var function = DesFactory.Create(DesTypes.TripleDES192, key);
            var cryptoVal0 = function.Encrypt("实现中华民族伟大复兴的中国梦");
            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData);
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("实现中华民族伟大复兴的中国梦");

            var cryptoVal2 = function.Decrypt(BaseConv.ToBase64(cryptoVal0.CipherData), CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("实现中华民族伟大复兴的中国梦");
        }

        [Fact]
        public void EncryptDecrypt_WithSalt_WithAutoCreateKey_L192_Test()
        {
            var key = DesFactory.GenerateKey(DesTypes.TripleDES192);
            var function = DesFactory.Create(DesTypes.TripleDES192, key);
            var cryptoVal0 = function.Encrypt("实现中华民族伟大复兴的中国梦", "123412341234");
            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData, "123412341234");
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("实现中华民族伟大复兴的中国梦");

            var cryptoVal2 = function.Decrypt(BaseConv.ToBase64(cryptoVal0.CipherData), "123412341234", CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("实现中华民族伟大复兴的中国梦");
        }
    }
}