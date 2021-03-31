using Cosmos.Security.Encryption.Abstractions;
using Cosmos.Security.Encryption.Algorithms;
using Xunit;

namespace Algorithms
{
    public class VigenereTests
    {
        [Fact]
        public void Vigenere_EncryptTest()
        {
            //Arrange
            IEncryptionAlgorithm target = new Vigenere("lemon");
            string plain = "attackatdawn";
            string cypher = "lxfopvefrnhr";

            //Act
            string actual = target.Encrypt(plain);

            //Assert
            Assert.Equal(cypher, actual);
        }

        [Fact]
        public void DecryptTest()
        {
            //Arrange
            IEncryptionAlgorithm target = new Vigenere("lemon");
            string plain = "attackatdawn";
            string cypher = "lxfopvefrnhr";

            //Act
            string actual = target.Decrypt(cypher);

            //Assert
            Assert.Equal(plain, actual);
        }
    }
}