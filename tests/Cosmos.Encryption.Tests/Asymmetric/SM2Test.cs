using System;
using System.Text;
using Cosmos.Encryption.Asymmetric;
using Org.BouncyCastle.Utilities.Encoders;
using Xunit;

namespace Cosmos.Encryption.Tests.Asymmetric {
    public class SM2Test {

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
        public void EncryptDecrypt(string originalString, SM2Mode mode) {
            //var encoding = Encoding.UTF8;

            //1. 源数据数组
            //byte[] sourceData = Encoding.UTF8.GetBytes(originalString);
            //byte[] pubk = Encoding.UTF8.GetBytes(PubKey);
            //string encStr = SM2EncryptionProvider.EncryptByPublicKey(sourceData, Hex.Decode(pubk));
            string encStr = SM2EncryptionProvider.EncryptByPublicKey(originalString, PubKey, mode: mode);

            //byte[] prik = Encoding.UTF8.GetBytes(PriKey);
            //var data = Hex.Decode(Encoding.UTF8.GetBytes(encStr));
            //var decodedData = SM2EncryptionProvider.DecryptByPrivateKey(data, Hex.Decode(prik));
            //var decodedStr = Encoding.UTF8.GetString(decodedData);
            var decodedStr = SM2EncryptionProvider.DecryptByPrivateKey(encStr, PriKey, mode: mode);

            // //国密规范测试私钥
            // string prik = "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";
            //
            // //2. 私钥先转十六进制，然后进行Base64编码
            //var prikS = Encoding.UTF8.GetBytes(StringToHexString(PriKey, Encoding.UTF8));
            //
            // //国密规范测试用户ID
            //var userId = "ALICE123@YAHOO.COM";
            //
            // //获取userId十六进制字符串
            //
            // //3.用userId和私钥，对明文数据签名(userid、prik、sourceData)
            //byte[] c = SM2EncryptionProvider.Signature(sourceData, Encoding.UTF8.GetBytes(userId), prikS);

            //国密规范测试公钥
            //var pubk = "040AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857";
            //var pubkS = Encoding.UTF8.GetBytes(StringToHexString(PubKey, Encoding.UTF8));

            //4.用公钥进行验签(userId、pubk、sourceData、签名数据c)
            //var vs = SM2EncryptionProvider.Verify(c, sourceData, Encoding.UTF8.GetBytes(userId), pubkS);
            //
            // //5.SM2加密算法
            // byte[] cipherText = SM2EncryptionProvider.Encrypt(sourceData, pubkS);
            //
            // //6.SM2解密算法
            // var o = SM2EncryptionProvider.Decrypt(cipherText, prikS);
            //
            // var os = encoding.GetString(o);


            //Assert.True(vs);
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
        public void EncryptDecryptWithGenKey(string originalString, SM2Mode mode) {
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
        public void Signature( /*string originalString*/) {
            string originalString = "Hello World";
            byte[] sourceData = Encoding.UTF8.GetBytes(originalString);
            var userId = "ALICE123@YAHOO.COM";
            var pubkS = Hex.Decode(Encoding.UTF8.GetBytes(PubKey)); // Encoding.UTF8.GetBytes(StringToHexString(PubKey, Encoding.UTF8));
            byte[] c = SM2EncryptionProvider.Signature(sourceData, Encoding.UTF8.GetBytes(userId), pubkS);
            var prikS = Hex.Decode(Encoding.UTF8.GetBytes(PriKey)); // Encoding.UTF8.GetBytes(StringToHexString(PriKey, Encoding.UTF8));
            var vs = SM2EncryptionProvider.Verify(c, sourceData, Encoding.UTF8.GetBytes(userId), prikS);
            Assert.True(vs);
        }

        public static string StringToHexString(string s, Encoding encode) {
            //return s;
            byte[] b = encode.GetBytes(s); //按照指定编码将string编程字节数组
            string result = string.Empty;
            for (int i = 0; i < b.Length; i++) //逐字节变为16进制字符，以%隔开
            {
                result += "%" + Convert.ToString(b[i], 16);
            }

            return result;
        }

    }
}