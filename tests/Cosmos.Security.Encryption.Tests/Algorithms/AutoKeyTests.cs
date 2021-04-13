using Cosmos.Security.Cryptography;
using Cosmos.Security.Encryption.Abstractions;
using Cosmos.Security.Encryption.Algorithms;
using Xunit;

namespace Algorithms
{
    public class AutoKeyTests
    {
        [Fact]
        public void AutoKey_EncryptTest()
        {
            //Arrange
            ICryptoAlgorithm target = new AutoKey("deceptive");
            string plain = "wearediscoveredsaveyourself";
            string cypher = "zicvtwqngkzeiigasxstslvvwla";

            //Act
            string actual = target.Encrypt(plain);

            //Assert
            Assert.Equal(cypher, actual);
        }

        [Fact]
        public void AutoKey_DecryptTest()
        {
            //Arrange
            ICryptoAlgorithm target = new AutoKey("deceptivewearediscoveredsav");
            string plain = "wearediscoveredsaveyourself";
            string cypher = "zicvtwqngkzeiigasxstslvvwla";

            //Act
            string actual = target.Decrypt(cypher);

            //Assert
            Assert.Equal(plain, actual);
        }
    }
}