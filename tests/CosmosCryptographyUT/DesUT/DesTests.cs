using System.Text;
using Cosmos.Conversions;
using Cosmos.Security.Cryptography;
using Shouldly;
using Xunit;

namespace DesUT
{
    public class DesTests
    {
        [Fact]
        public void EncryptDecrypt_Test()
        {
            var key = DesFactory.GenerateKey(DesTypes.DES, "alexinea", "forerunner", Encoding.UTF8);
            var function = DesFactory.Create(DesTypes.DES, key);
            var cryptoVal0 = function.Encrypt("image");

            BaseConv.ToBase64(cryptoVal0.CipherData).ShouldBe("fJ2yrnAPaH0=");

            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData);
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("image");

            var cryptoVal2 = function.Decrypt(BaseConv.ToBase64(cryptoVal0.CipherData), CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("image");
        }

        [Fact]
        public void EncryptDecrypt_WithSalt_Test()
        {
            var key = DesFactory.GenerateKey(DesTypes.DES, "alexinea", "forerunner", Encoding.UTF8);
            var function = DesFactory.Create(DesTypes.DES, key);
            var cryptoVal0 = function.Encrypt("image", "123412341234");

            BaseConv.ToBase64(cryptoVal0.CipherData).ShouldBe("s4h5u8hA/2Y=");

            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData, "123412341234");
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("image");

            var cryptoVal2 = function.Decrypt(BaseConv.ToBase64(cryptoVal0.CipherData), "123412341234", CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("image");
        }

        [Fact]
        public void EncryptDecrypt_WithAutoCreateKey_Test()
        {
            var key = DesFactory.GenerateKey();
            var function = DesFactory.Create(DesTypes.DES, key);
            var cryptoVal0 = function.Encrypt("image");

            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData);
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("image");

            var cryptoVal2 = function.Decrypt(BaseConv.ToBase64(cryptoVal0.CipherData), CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("image");
        }

        [Fact]
        public void EncryptDecrypt_WithSalt_WithAutoCreateKey_Test()
        {
            var key = DesFactory.GenerateKey(DesTypes.DES);
            var function = DesFactory.Create(DesTypes.DES, key);
            var cryptoVal0 = function.Encrypt("image", "123412341234");

            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData, "123412341234");
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("image");

            var cryptoVal2 = function.Decrypt(BaseConv.ToBase64(cryptoVal0.CipherData), "123412341234", CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("image");
        }
    }
}