using System.Text;
using Cosmos.Security.Encryption;
using Xunit;

namespace Asymmetric
{
    public class SM2Test
    {
        private static string PubKey = "041E353292615666BB47F6358D3E893394D34AF30D64875E2E422182C15885D3ECA697C345EED99268D3CAC5F6054780C34433E1BF12EBFF1F744B67A2F6863CFB";
        private static string PriKey = "00FAB34B54C026D158B54C88BC0463CB79B22661C7C870AD2A0455300E05471CE1";

        [Theory]
        [InlineData("Hello World", SM2Mode.C1C2C3)]
        [InlineData("神圣的电风扇", SM2Mode.C1C2C3)]
        [InlineData("机动战士 GUNDAM", SM2Mode.C1C2C3)]
        [InlineData("ウルトラマンシリーズ", SM2Mode.C1C2C3)]
        [InlineData("Hello World", SM2Mode.C1C3C2)]
        [InlineData("神圣的电风扇", SM2Mode.C1C3C2)]
        [InlineData("机动战士 GUNDAM", SM2Mode.C1C3C2)]
        [InlineData("ウルトラマンシリーズ", SM2Mode.C1C3C2)]
        public void EncryptDecrypt(string originalString, SM2Mode mode)
        {
            var encStr = SM2EncryptionProvider.EncryptByPublicKey(originalString, PubKey, mode: mode);
            var decodedStr = SM2EncryptionProvider.DecryptByPrivateKey(encStr, PriKey, mode: mode);
            Assert.Equal(originalString, decodedStr);
        }

        [Theory]
        [InlineData("Hello World", SM2Mode.C1C2C3)]
        [InlineData("神圣的电风扇", SM2Mode.C1C2C3)]
        [InlineData("机动战士 GUNDAM", SM2Mode.C1C2C3)]
        [InlineData("ウルトラマンシリーズ", SM2Mode.C1C2C3)]
        [InlineData("Hello World", SM2Mode.C1C3C2)]
        [InlineData("神圣的电风扇", SM2Mode.C1C3C2)]
        [InlineData("机动战士 GUNDAM", SM2Mode.C1C3C2)]
        [InlineData("ウルトラマンシリーズ", SM2Mode.C1C3C2)]
        public void EncryptDecryptWithGenKey(string originalString, SM2Mode mode)
        {
            var key = SM2EncryptionProvider.CreateKey();
            var encStr = SM2EncryptionProvider.EncryptByPublicKey(originalString, key.PublicKey, mode: mode);
            var decodedStr = SM2EncryptionProvider.DecryptByPrivateKey(encStr, key.PrivateKey, mode: mode);
            Assert.Equal(originalString, decodedStr);
        }

        // [Theory]
        // [InlineData("Hello World")]
        // [InlineData("神圣的电风扇")]
        // [InlineData("机动战士 GUNDAM")]
        // [InlineData("ウルトラマンシリーズ")]
        [Fact]
        public void Signature( /*string originalString*/)
        {
            string originalString = "Hello World";
            byte[] sourceData = Encoding.UTF8.GetBytes(originalString);
            var userId = "ALICE123@YAHOO.COM";
            var userIdBytes = Encoding.UTF8.GetBytes(userId);
            // var pubkS = Hex.Decode(Encoding.UTF8.GetBytes(PubKey)); // Encoding.UTF8.GetBytes(StringToHexString(PubKey, Encoding.UTF8));
            // byte[] c = SM2EncryptionProvider.Signature(sourceData, Encoding.UTF8.GetBytes(userId), pubkS);
            // var prikS = Hex.Decode(Encoding.UTF8.GetBytes(PriKey)); // Encoding.UTF8.GetBytes(StringToHexString(PriKey, Encoding.UTF8));
            //var vs = SM2EncryptionProvider.Verify(c, sourceData, Encoding.UTF8.GetBytes(userId), prikS);
            // Assert.True(vs);

            var s = SM2EncryptionProvider.Signature2(sourceData, userIdBytes, Encoding.UTF8.GetBytes(PubKey));
            var v = SM2EncryptionProvider.Verify2(userIdBytes, Encoding.UTF8.GetBytes(PriKey), sourceData, s);
            Assert.True(v);
        }
    }
}