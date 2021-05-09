using Cosmos.Security.Cryptography;
using Xunit;

namespace PlayFairUT
{
    [Trait("PlayFairUT", "PlayFairTests")]
    public class PlayFairTests
    {
        readonly IPlayFair _function;

        public PlayFairTests()
        {
            _function = PlayFairFactory.Create("playfairexample");
        }

        [Fact]
        public void EncryptTest()
        {
            //Arrange
            var plain = "hidethegoldinthetreestump";
            var cypher = "bmodzbxdnabekudmuixmmouvif";

            //Act
            var cryptoVal = _function.Encrypt(plain);

            //Assert
            Assert.Equal(cypher, cryptoVal.GetCipherDataDescriptor().GetString());
        }

        [Fact]
        public void DecryptTest()
        {
            //Arrange
            var plain = "hidethegoldinthetrexestump";
            var cypher = "bmodzbxdnabekudmuixmmouvif";

            //Act
            var cryptoVal = _function.Decrypt(cypher);

            //Assert
            Assert.Equal(plain, cryptoVal.GetOriginalDataDescriptor().GetString());
        }
    }
}