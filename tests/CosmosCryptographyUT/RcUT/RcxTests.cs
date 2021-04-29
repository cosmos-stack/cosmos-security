using System.Text;
using Cosmos.Conversions;
using Cosmos.Security.Cryptography;
using Shouldly;
using Xunit;

namespace Symmetric
{
    public class RcxTests
    {
        [Fact]
        public void Encrypt()
        {
            var key = RcFactory.GenerateKey(RcTypes.RCX, "alexinea", Encoding.UTF8);
            var function = RcFactory.Create(RcTypes.RCX, key);
            var cryptoVal0 = function.Encrypt("ABCDDDDDDDDDDDDDDDDDDDDDD");

            BaseConv.ToBase64(cryptoVal0.CipherData).ShouldBe("C+YxcfWRWMVCIjbX21qXcG9OXq25jJTHmw==");
        }

        [Fact]
        public void Encrypt_ThreeRCX()
        {
            var key = RcFactory.GenerateKey(RcTypes.ThreeRCX, "alexinea", Encoding.UTF8);
            var function = RcFactory.Create(RcTypes.ThreeRCX, key);
            var cryptoVal0 = function.Encrypt("ABCDDDDDDDDDDDDDDDDDDDDDD");

            BaseConv.ToBase64(cryptoVal0.CipherData).ShouldBe("JPTCrl2N6xae4GCEXfzUiSa9YrwSa80HDg==");
        }

        [Fact]
        public void Decrypt()
        {
            var key = RcFactory.GenerateKey(RcTypes.RCX, "alexinea", Encoding.UTF8);
            var function = RcFactory.Create(RcTypes.RCX, key);
            var cryptoVal0 = function.Encrypt("ABCDDDDDDDDDDDDDDDDDDDDDD");

            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData);
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("ABCDDDDDDDDDDDDDDDDDDDDDD");

            var cryptoVal2 = function.Decrypt("C+YxcfWRWMVCIjbX21qXcG9OXq25jJTHmw==", CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("ABCDDDDDDDDDDDDDDDDDDDDDD");
        }

        [Fact]
        public void Decrypt_ThreeRCX()
        {
            var key = RcFactory.GenerateKey(RcTypes.ThreeRCX, "alexinea", Encoding.UTF8);
            var function = RcFactory.Create(RcTypes.ThreeRCX, key);
            var cryptoVal0 = function.Encrypt("ABCDDDDDDDDDDDDDDDDDDDDDD");

            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData);
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("ABCDDDDDDDDDDDDDDDDDDDDDD");

            var cryptoVal2 = function.Decrypt("JPTCrl2N6xae4GCEXfzUiSa9YrwSa80HDg==", CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("ABCDDDDDDDDDDDDDDDDDDDDDD");
        }
    }
}