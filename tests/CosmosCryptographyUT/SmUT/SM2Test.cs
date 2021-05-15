using Shouldly;
using Xunit;
using Cosmos.Security.Cryptography;

namespace SmUT
{
    public class SM2Test
    {
        // private static string PubKey = "041E353292615666BB47F6358D3E893394D34AF30D64875E2E422182C15885D3ECA697C345EED99268D3CAC5F6054780C34433E1BF12EBFF1F744B67A2F6863CFB";
        // private static string PriKey = "00FAB34B54C026D158B54C88BC0463CB79B22661C7C870AD2A0455300E05471CE1";

        private static string PubKey =
            "MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////v////////////////////8AAAAA//////////8wRAQg/////v////////////////////8AAAAA//////////wEICjp+p6dn140TVqeS89lCafzl4n1FauPkt28vUFNlA6TBEEEMsSuLB8ZgRlfmQRGajnJlI/jC7/yZgvhcVpFiTNMdMe8Nzai9PZ3nFm9zuNraSFT0KmHfMYqR0AC3zLlITnwoAIhAP////7///////////////9yA99rIcYFK1O79Ak51UEjAgEBA0IABLrtGW6bMf6kzyS7I2RZPB/KEfbADb9w4DgzcRbjai5z8ICeCrs2/XQavBj2OEkghb52pQQcNsN/aW9OIMVVsqo=";

        private static string PriKey =
            "MIICSwIBADCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////v////////////////////8AAAAA//////////8wRAQg/////v////////////////////8AAAAA//////////wEICjp+p6dn140TVqeS89lCafzl4n1FauPkt28vUFNlA6TBEEEMsSuLB8ZgRlfmQRGajnJlI/jC7/yZgvhcVpFiTNMdMe8Nzai9PZ3nFm9zuNraSFT0KmHfMYqR0AC3zLlITnwoAIhAP////7///////////////9yA99rIcYFK1O79Ak51UEjAgEBBIIBVTCCAVECAQEEILRiRXMgH0/4TSt3us7g8AMJGhG4p5LbpMFcDwuVTSG6oIHjMIHgAgEBMCwGByqGSM49AQECIQD////+/////////////////////wAAAAD//////////zBEBCD////+/////////////////////wAAAAD//////////AQgKOn6np2fXjRNWp5Lz2UJp/OXifUVq4+S3by9QU2UDpMEQQQyxK4sHxmBGV+ZBEZqOcmUj+MLv/JmC+FxWkWJM0x0x7w3NqL09necWb3O42tpIVPQqYd8xipHQALfMuUhOfCgAiEA/////v///////////////3ID32shxgUrU7v0CTnVQSMCAQGhRANCAAS67RlumzH+pM8kuyNkWTwfyhH2wA2/cOA4M3EW42ouc/CAngq7Nv10GrwY9jhJIIW+dqUEHDbDf2lvTiDFVbKq";

        [Theory]
        [InlineData("Hello World")]
        [InlineData("神圣的电风扇")]
        [InlineData("机动战士 GUNDAM")]
        [InlineData("ウルトラマンシリーズ")]
        public void EncryptDecrypt(string originalString)
        {
            var key = Sm2KeyGenerator.Generate(AsymmetricKeyMode.Both, PubKey, PriKey);
            var function = Sm2Factory.Create(key);
            var cipherVal = function.Encrypt(originalString);
            var originalVal = function.Decrypt(cipherVal.CipherData);
            originalVal.GetOriginalDataDescriptor().GetString().ShouldBe(originalString);
        }

        [Theory]
        [InlineData("Hello World")]
        [InlineData("神圣的电风扇")]
        [InlineData("机动战士 GUNDAM")]
        [InlineData("ウルトラマンシリーズ")]
        public void EncryptDecryptWithGenKey(string originalString)
        {
            var key = Sm2KeyGenerator.Generate(AsymmetricKeyMode.Both);
            var function = Sm2Factory.Create(key);
            var cipherVal = function.Encrypt(originalString);
            var originalVal = function.Decrypt(cipherVal.CipherData);
            originalVal.GetOriginalDataDescriptor().GetString().ShouldBe(originalString);
        }

        [Theory]
        [InlineData("Hello World")]
        [InlineData("神圣的电风扇")]
        [InlineData("机动战士 GUNDAM")]
        [InlineData("ウルトラマンシリーズ")]
        //[Fact]
        public void Signature(string originalString)
        {
            var key = Sm2KeyGenerator.Generate(AsymmetricKeyMode.Both);
            var function = Sm2Factory.Create(key);
            var signVal = function.Sign(originalString);
            var v = function.Verify(originalString, signVal.GetSignatureDescriptor().GetBase64String(), SignatureTextTypes.Base64Text);

            v.ShouldBeTrue();
        }
    }
}