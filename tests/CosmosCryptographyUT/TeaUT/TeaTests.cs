using System.Text;
using Cosmos.Conversions;
using Cosmos.Security.Cryptography;
using Cosmos.Security.Encryption;
using Shouldly;
using Xunit;

namespace TeaUT
{
    public class TEATests
    {
        [Fact]
        public void XXTEATest()
        {
            var key = TeaFactory.GenerateKey("alexinea", Encoding.UTF8);
            var function = TeaFactory.Create(TeaTypes.XXTEA, key);
            var cryptoVal0 = function.Encrypt("AlexLEWIS");

            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData);
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("AlexLEWIS");

            var cryptoVal2 = function.Decrypt(BaseConv.ToBase64(cryptoVal0.CipherData), CipherTextTypes.Base64Text);

            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("AlexLEWIS");
        }

        [Fact]
        public void XTEATest()
        {
            var key = TeaFactory.GenerateKey("alexineaalexinea", Encoding.UTF8);
            var function = TeaFactory.Create(TeaTypes.XTEA, key);
            var cryptoVal0 = function.Encrypt("AlexLEWISAlexLEWISAlexLEWISAlexLEWISAlexLEWISAlexLEWISAlexLEWIS");

            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData);
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("AlexLEWISAlexLEWISAlexLEWISAlexLEWISAlexLEWISAlexLEWISAlexLEWIS");

            var cryptoVal2 = function.Decrypt(BaseConv.ToBase64(cryptoVal0.CipherData), CipherTextTypes.Base64Text);

            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("AlexLEWISAlexLEWISAlexLEWISAlexLEWISAlexLEWISAlexLEWISAlexLEWIS");
        }

        [Fact]
        public void TEATest()
        {
            var key = TeaFactory.GenerateKey("alexinea", Encoding.UTF8);
            var function = TeaFactory.Create(TeaTypes.TEA, key);
            var cryptoVal0 = function.Encrypt("AlexLEWIS      ");

            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData);
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("AlexLEWIS      ");

            var cryptoVal2 = function.Decrypt(BaseConv.ToBase64(cryptoVal0.CipherData), CipherTextTypes.Base64Text);

            cryptoVal2.GetOriginalDataDescriptor().GetString().ShouldBe("AlexLEWIS      ");
        }
    }
}