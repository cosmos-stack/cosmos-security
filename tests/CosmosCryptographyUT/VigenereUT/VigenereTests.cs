using Cosmos.Security.Cryptography;
using Xunit;

namespace VigenereUT
{
    [Trait("VigenereUT", "VigenereTests")]
    public class VigenereTests
    {
        [Fact]
        public void Vigenere_EncryptTest()
        {
            //Arrange
            var function = VigenereFactory.Create("lemon");
            var plain = "attackatdawn";
            var cypher = "lxfopvefrnhr";

            //Act
            var cryptoVal = function.Encrypt(plain);

            //Assert
            Assert.Equal(cypher, cryptoVal.GetCipherDataDescriptor().GetString());
        }

        [Fact]
        public void DecryptTest()
        {
            //Arrange
            var function = VigenereFactory.Create("lemon");
            var plain = "attackatdawn";
            var cypher = "lxfopvefrnhr";

            //Act
            var cryptoVal = function.Decrypt(cypher);

            //Assert
            Assert.Equal(plain, cryptoVal.GetOriginalDataDescriptor().GetString());
        }
    }
}