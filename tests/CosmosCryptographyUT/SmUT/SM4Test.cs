using Cosmos.Security.Cryptography;
using Shouldly;
using Xunit;

namespace SmUT
{
    public class SM4Test
    {
        [Fact]
        public void Encrypt_ECB()
        {
            var key = Sm4Factory.GenerateKey("1234567890123456");
            var function = Sm4Factory.Create(Sm4Types.ECB, key);
            var cryptoVal0 = function.Encrypt("天下无双");
            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData);
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("天下无双");
        }

        [Fact]
        public void Encrypt_ECB_WithAutoKey()
        {
            var key = Sm4Factory.GenerateKey(Sm4Types.ECB);
            var function = Sm4Factory.Create(Sm4Types.ECB, key);
            var cryptoVal0 = function.Encrypt("天下无双");
            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData);
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("天下无双");
        }

        [Fact]
        public void Encrypt_CBC()
        {
            var key = Sm4Factory.GenerateKey("1234567890123456", "1234567890123456");
            var function = Sm4Factory.Create(Sm4Types.CBC, key);
            var cryptoVal0 = function.Encrypt("天下无双");
            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData);
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("天下无双");
        }

        [Fact]
        public void Encrypt_CBC_WithAutoKey()
        {
            var key = Sm4Factory.GenerateKey(Sm4Types.CBC);
            var function = Sm4Factory.Create(Sm4Types.CBC, key);
            var cryptoVal0 = function.Encrypt("天下无双");
            var cryptoVal1 = function.Decrypt(cryptoVal0.CipherData);
            cryptoVal1.GetOriginalDataDescriptor().GetString().ShouldBe("天下无双");
        }
    }
}