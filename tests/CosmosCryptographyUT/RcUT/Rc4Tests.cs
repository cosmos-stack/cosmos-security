using System.Text;
using Cosmos.Conversions;
using Cosmos.Security.Cryptography;
using Shouldly;
using Xunit;

namespace RcUT
{
    public class Rc4Tests
    {
        [Fact]
        public void Encrypt()
        {
            var key = RcFactory.GenerateKey("alexinea", Encoding.UTF8);
            var function = RcFactory.Create(RcTypes.RC4, key);
            var cryptoVal0 = function.Encrypt("image");

            BaseConv.ToBase64(cryptoVal0.CipherData).ShouldBe("I2YRaZo=");
        }

        [Fact]
        public void Decrypt()
        {
            var key = RcFactory.GenerateKey("alexinea", Encoding.UTF8);
            var function = RcFactory.Create(RcTypes.RC4, key);
            var cryptoVal0 = function.Encrypt("image");

            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData);
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("image");

            var cryptoVal2 = function.Decrypt("I2YRaZo=", CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("image");
        }
    }
}