using Cosmos.Security.Cryptography;
using Xunit;

namespace CeaserUT
{
    [Trait("CeaserUT", "CeaserTests")]
    public class CeaserTests
    {
        readonly ICeaser function;

        public CeaserTests()
        {
            function = CeaserFactory.Create(3);
        }

        [Fact]
        public void EncryptTest()
        {
            //Arrange
            var plain = "meetmeafterthetogaparty";
            var cypher = "phhwphdiwhuwkhwrjdsduwb";

            //Act
            var cryptoVal = function.Encrypt(plain);

            //Assert
            Assert.Equal(cypher, cryptoVal.GetCipherDataDescriptor().GetString());
        }

        [Fact]
        public void DecryptTest()
        {
            //Arrange
            var plain = "meetmeafterthetogaparty";
            var cypher = "phhwphdiwhuwkhwrjdsduwb";

            //Act
            var cryptoVal = function.Decrypt(cypher);

            //Assert
            Assert.Equal(plain, cryptoVal.GetOriginalDataDescriptor().GetString());
        }
    }
}