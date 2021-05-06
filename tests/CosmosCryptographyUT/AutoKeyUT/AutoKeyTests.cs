using Cosmos.Security.Cryptography;
using Xunit;

namespace AutoKeyUT
{
    [Trait("AutoKeyUT", "AutoKeyTests")]
    public class AutoKeyTests
    {
        [Fact]
        public void AutoKey_EncryptTest()
        {
            //Arrange
            var function = AutoKeyFactory.Create("deceptive");
            var plain = "wearediscoveredsaveyourself";
            var cypher = "zicvtwqngkzeiigasxstslvvwla";

            //Act
            var cryptoVal = function.Encrypt(plain);

            //Assert
            Assert.Equal(cypher, cryptoVal.GetCipherDataDescriptor().GetString());
        }

        [Fact]
        public void AutoKey_DecryptTest()
        {
            //Arrange
            var function = AutoKeyFactory.Create("deceptivewearediscoveredsav");
            var plain = "wearediscoveredsaveyourself";
            var cypher = "zicvtwqngkzeiigasxstslvvwla";

            //Act
            var cryptoVal = function.Decrypt(cypher);

            //Assert
            Assert.Equal(plain, cryptoVal.GetOriginalDataDescriptor().GetString());
        }
    }
}