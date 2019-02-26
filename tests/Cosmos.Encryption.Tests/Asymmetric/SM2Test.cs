using System;
using System.Text;
using Cosmos.Encryption.Asymmetric;
using Microsoft.VisualBasic.CompilerServices;
using Xunit;

namespace Cosmos.Encryption.Tests.Asymmetric
{
    public class SM2Test
    {
        [Fact]
        public void EncryptDecrypt()
        {
            var originString = "message digest";
            var encoding = Encoding.Default;

            //1. 源数据数组
            byte[] sourceData = encoding.GetBytes(originString);

            //国密规范测试私钥
            string prik = "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";

            //2. 私钥先转十六进制，然后进行Base64编码
            var prikS = encoding.GetBytes(StringToHexString(prik, encoding));

            //国密规范测试用户ID
            var userId = "ALICE123@YAHOO.COM";

            //获取userId十六进制字符串

            //3.用userId和私钥，对明文数据签名(userid、prik、sourceData)
            byte[] c = SM2EncryptionProvider.Signature(sourceData, encoding.GetBytes(userId), prikS);

            //国密规范测试公钥
            var pubk = "040AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857";
            var pubkS = encoding.GetBytes(StringToHexString(pubk, encoding));

            //4.用公钥进行验签(userId、pubk、sourceData、签名数据c)
            var vs = SM2EncryptionProvider.Verify(c, sourceData, encoding.GetBytes(userId), pubkS);

            //5.SM2加密算法
            byte[] cipherText = SM2EncryptionProvider.Encrypt(sourceData, pubkS);

            //6.SM2解密算法
            var o = SM2EncryptionProvider.Decrypt(cipherText, prikS);

            var os = encoding.GetString(o);

            Assert.True(vs);
            Assert.Equal(originString, os);
        }

        public static string StringToHexString(string s, Encoding encode)
        {
            return s;
            byte[] b = encode.GetBytes(s);//按照指定编码将string编程字节数组
            string result = string.Empty;
            for (int i = 0; i < b.Length; i++)//逐字节变为16进制字符，以%隔开
            {
                result += "%" + Convert.ToString(b[i], 16);
            }
            return result;
        }

    }
}
