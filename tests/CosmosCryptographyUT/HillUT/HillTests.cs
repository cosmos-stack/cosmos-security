using Cosmos.Security.Cryptography;
using Xunit;

namespace HillUT
{
    [Trait("HillUT", "HillTests")]
    public class HillTests
    {
        readonly int[,] matrix;
        readonly IHill function;

        public HillTests()
        {
            matrix = new int[3, 3];

            matrix[0, 0] = 17;
            matrix[0, 1] = 21;
            matrix[0, 2] = 2;

            matrix[1, 0] = 17;
            matrix[1, 1] = 18;
            matrix[1, 2] = 2;

            matrix[2, 0] = 5;
            matrix[2, 1] = 21;
            matrix[2, 2] = 19;

            function = HillFactory.Create(matrix);
        }

        [Fact]
        public void EncryptTest()
        {
            //Arrange
            string plain = "paymoremoney";
            string cypher = "lnshdlewmtrw";

            //Act
            var cryptoVal = function.Encrypt(plain);

            //Assert
            Assert.Equal(cypher, cryptoVal.GetCipherDataDescriptor().GetString());
        }

        [Fact]
        public void DecryptTest()
        {
            //Arrange
            string plain = "paymoremoney";
            string cypher = "lnshdlewmtrw";

            //Act
            var cryptoVal = function.Decrypt(cypher);

            //Assert
            Assert.Equal(plain, cryptoVal.GetOriginalDataDescriptor().GetString());
        }
    }
}