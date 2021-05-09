using Cosmos.Security.Cryptography;
using Xunit;

namespace RailFenceUT
{
    [Trait("RailFenceUT", "RailFenceTests")]
    public class RailFenceTests
    {
        readonly IRailFence _function;

        public RailFenceTests()
        {
            _function = RailFenceFactory.Create(2);
        }

        [Fact]
        public void EncryptTest()
        {
            //Arrange
            var plain = "meetmeafterthegraduationparty";
            var cypher = "mematrhgautopryetefeterdainat*";

            //Act
            var cryptoVal = _function.Encrypt(plain);

            //Assert
            Assert.Equal(cypher, cryptoVal.GetCipherDataDescriptor().GetString());
        }

        [Fact]
        public void DecryptTest()
        {
            //Arrange
            var plain = "meetmeafterthegraduationparty*";
            var cypher = "mematrhgautopryetefeterdainat*";

            //Act
            var cryptoVal = _function.Decrypt(cypher);

            //Assert
            Assert.Equal(plain, cryptoVal.GetOriginalDataDescriptor().GetString());
        }
    }
}