using System.Text;
using Cosmos.Conversions;
using Cosmos.Security.Cryptography;
using Shouldly;
using Xunit;

namespace Symmetric
{
    public class RcyTests
    {
        [Fact]
        public void Encrypt()
        {
            var key = RcFactory.GenerateKey(RcTypes.RCY, "alexinea", Encoding.UTF8);
            var function = RcFactory.Create(RcTypes.RCY, key);
            var cryptoVal0 = function.Encrypt("ABCDDDDDDDDDDDDDDDDDDDDDD");

            BaseConv.ToBase64(cryptoVal0.CipherData).ShouldBe("QCMiN9UlyMhNypE52bTzJaAlFAdFddB1mw==");
        }

        [Fact]
        public void Encrypt_ThreeRCY()
        {
            var key = RcFactory.GenerateKey(RcTypes.ThreeRCY, "alexinea", Encoding.UTF8);
            var function = RcFactory.Create(RcTypes.ThreeRCY, key);
            var cryptoVal0 = function.Encrypt("ABCDDDDDDDDDDDDDDDDDDDDDD");

            BaseConv.ToBase64(cryptoVal0.CipherData).ShouldBe("SHNK5w4Qc42CRf6YoE3V4JvZMtObzUWgRQ==");
        }

        [Fact]
        public void Decrypt()
        {
            var key = RcFactory.GenerateKey(RcTypes.RCY, "alexinea", Encoding.UTF8);
            var function = RcFactory.Create(RcTypes.RCY, key);
            var cryptoVal0 = function.Encrypt("ABCDDDDDDDDDDDDDDDDDDDDDD");

            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData);
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("ABCDDDDDDDDDDDDDDDDDDDDDD");

            var cryptoVal2 = function.Decrypt("QCMiN9UlyMhNypE52bTzJaAlFAdFddB1mw==", CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("ABCDDDDDDDDDDDDDDDDDDDDDD");
        }

        [Fact]
        public void Decrypt_ThreeRCY()
        {
            var key = RcFactory.GenerateKey(RcTypes.ThreeRCY, "alexinea", Encoding.UTF8);
            var function = RcFactory.Create(RcTypes.ThreeRCY, key);
            var cryptoVal0 = function.Encrypt("ABCDDDDDDDDDDDDDDDDDDDDDD");

            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData);
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("ABCDDDDDDDDDDDDDDDDDDDDDD");

            var cryptoVal2 = function.Decrypt("SHNK5w4Qc42CRf6YoE3V4JvZMtObzUWgRQ==", CipherTextTypes.Base64Text);
            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("ABCDDDDDDDDDDDDDDDDDDDDDD");
        }
    }
}