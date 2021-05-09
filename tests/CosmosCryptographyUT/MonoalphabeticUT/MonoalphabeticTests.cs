using Cosmos.Security.Cryptography;
using Xunit;

namespace MonoalphabeticUT
{
    [Trait("MonoalphabeticUT", "MonoalphabeticTests")]
    public class MonoalphabeticTests
    {
        private readonly IMonoalphabetic function = MonoalphabeticFactory.Create();

        [Fact]
        public void EncryptTest()
        {
            //Arrange
            string plain = "abcd";

            //Act
            var cryptoVal1 = function.Encrypt(plain);

            //Assert
            Assert.NotEqual(cryptoVal1.GetCipherDataDescriptor().GetString(), plain);

            //Act
            var cryptoVal2 = function.Decrypt(cryptoVal1.GetCipherDataDescriptor().GetString());

            //Assert
            Assert.Equal(plain, cryptoVal2.GetOriginalDataDescriptor().GetString());
        }
    }
}