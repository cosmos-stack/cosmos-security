using Cosmos.Security.Cryptography;
using Xunit;

namespace RowTranspositionUT
{
    [Trait("RowTranspositionUT", "RowTranspositionTests")]
    public class RowTranspositionTests
    {
        readonly IRowTransposition _function;

        public RowTranspositionTests()
        {
            _function = RowTranspositionFactory.Create(new int[] {4, 3, 1, 2, 5, 6, 7});
        }

        [Fact]
        public void EncryptTest()
        {
            //Arrange
            var plain = "attackpostponeduntiltwoam";
            var cypher = "ttna aptm tsuo aodw coi* knl* pet* ";

            //Act
            var cryptoVal = _function.Encrypt(plain);

            //Assert
            Assert.Equal(cypher, cryptoVal.GetCipherDataDescriptor().GetString());
        }

        [Fact()]
        public void DecryptTest()
        {
            //Arrange
            var plain = "attackpostponeduntiltwoam";
            var cypher = "ttna aptm tsuo aodw coi* knl* pet* ";

            //Act
            var cryptoVal = _function.Decrypt(cypher);

            //Assert
            Assert.Equal(plain, cryptoVal.GetOriginalDataDescriptor().GetString());
        }
    }
}