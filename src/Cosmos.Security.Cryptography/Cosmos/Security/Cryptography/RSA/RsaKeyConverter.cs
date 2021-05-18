using System;
using System.IO;
using System.Xml.Linq;
using Cosmos.Conversions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace Cosmos.Security.Cryptography
{
    internal class RsaKeyConverter : IRsaKeyConverter
    {
        private RsaKeyConverter() { }

        private static readonly IRsaKeyConverter Instance = new RsaKeyConverter();

        /// <summary>
        /// Public Key Convert pem->xml
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public string PublicKeyPemPkcs8ToXml(string publicKey) => Impl.PublicKeyPemPkcs8ToXml(publicKey);

        /// <summary>
        /// Public Key Convert xml->pem
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public string PublicKeyXmlToPem(string publicKey) => Impl.PublicKeyXmlToPem(publicKey);

        /// <summary>
        /// Private Key Convert Pkcs1->xml
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public string PrivateKeyPkcs1ToXml(string privateKey) => Impl.PrivateKeyPkcs1ToXml(privateKey);

        /// <summary>
        /// Private Key Convert xml->Pkcs1
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public string PrivateKeyXmlToPkcs1(string privateKey) => Impl.PrivateKeyXmlToPkcs1(privateKey);

        /// <summary>
        /// Private Key Convert Pkcs8->xml
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public string PrivateKeyPkcs8ToXml(string privateKey) => Impl.PrivateKeyPkcs8ToXml(privateKey);

        /// <summary>
        /// Private Key Convert xml->Pkcs8
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public string PrivateKeyXmlToPkcs8(string privateKey) => Impl.PrivateKeyXmlToPkcs8(privateKey);

        /// <summary>
        /// Private Key Convert Pkcs1->Pkcs8
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public string PrivateKeyPkcs1ToPkcs8(string privateKey) => Impl.PrivateKeyPkcs1ToPkcs8(privateKey);

        /// <summary>
        /// Private Key Convert Pkcs8->Pkcs1
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public string PrivateKeyPkcs8ToPkcs1(string privateKey) => Impl.PrivateKeyPkcs8ToPkcs1(privateKey);

        public static IRsaKeyConverter GetInstance() => Instance;

        private static class Impl
        {
            public static string PublicKeyPemPkcs8ToXml(string publicKey)
            {
                var pemReader = new PemReader(new StringReader(publicKey.AppendPkcs8PublicKeyFormat()));
                if (pemReader.ReadObject() is not RsaKeyParameters rsaKey)
                    throw new Exception("Public key format is incorrect");

                var publicElement = new XElement("RSAKeyValue");

                //Modulus
                var publicModulus = new XElement("Modulus", Convert.ToBase64String(rsaKey.Modulus.ToByteArrayUnsigned()));

                //Exponent
                var publicExponent = new XElement("Exponent", Convert.ToBase64String(rsaKey.Exponent.ToByteArrayUnsigned()));

                publicElement.Add(publicModulus);
                publicElement.Add(publicExponent);

                return publicElement.ToString();
            }

            public static string PublicKeyXmlToPem(string publicKey)
            {
                var root = XElement.Parse(publicKey);

                //Modulus
                var modulus = root.Element("Modulus");

                //Exponent
                var exponent = root.Element("Exponent");

                var rsaKeyParameters = new RsaKeyParameters(
                    false,
                    new BigInteger(1, Convert.FromBase64String(modulus!.Value)),
                    new BigInteger(1, Convert.FromBase64String(exponent!.Value)));

                using var writer = new StringWriter();
                var pemWriter = new PemWriter(writer);

                pemWriter.WriteObject(rsaKeyParameters);
                pemWriter.Writer.Close();

                return writer.ToString();
            }

            public static string PrivateKeyPkcs1ToXml(string privateKey)
            {
                var pemReader = new PemReader(new StringReader(privateKey.AppendPkcs1PrivateKeyFormat()));
                if (pemReader.ReadObject() is not AsymmetricCipherKeyPair asymmetricCipherKeyPair)
                    throw new Exception("Private key format is incorrect");

                var rsaPrivateCrtKeyParameters = (RsaPrivateCrtKeyParameters) PrivateKeyFactory.CreateKey(PrivateKeyInfoFactory.CreatePrivateKeyInfo(asymmetricCipherKeyPair.Private));

                var element = new XElement("RSAKeyValue");

                var privateModulus = new XElement("Modulus", Convert.ToBase64String(rsaPrivateCrtKeyParameters.Modulus.ToByteArrayUnsigned()));
                var privateExponent = new XElement("Exponent", Convert.ToBase64String(rsaPrivateCrtKeyParameters.PublicExponent.ToByteArrayUnsigned()));
                var privateP = new XElement("P", Convert.ToBase64String(rsaPrivateCrtKeyParameters.P.ToByteArrayUnsigned()));
                var privateQ = new XElement("Q", Convert.ToBase64String(rsaPrivateCrtKeyParameters.Q.ToByteArrayUnsigned()));
                var privateDp = new XElement("DP", Convert.ToBase64String(rsaPrivateCrtKeyParameters.DP.ToByteArrayUnsigned()));
                var privateDq = new XElement("DQ", Convert.ToBase64String(rsaPrivateCrtKeyParameters.DQ.ToByteArrayUnsigned()));
                var privateInverseQ = new XElement("InverseQ", Convert.ToBase64String(rsaPrivateCrtKeyParameters.QInv.ToByteArrayUnsigned()));
                var privateD = new XElement("D", Convert.ToBase64String(rsaPrivateCrtKeyParameters.Exponent.ToByteArrayUnsigned()));

                element.Add(privateModulus);
                element.Add(privateExponent);
                element.Add(privateP);
                element.Add(privateQ);
                element.Add(privateDp);
                element.Add(privateDq);
                element.Add(privateInverseQ);
                element.Add(privateD);

                return element.ToString();
            }

            public static string PrivateKeyXmlToPkcs1(string privateKey)
            {
                var root = XElement.Parse(privateKey);

                var modulus = root.Element("Modulus");
                var exponent = root.Element("Exponent");
                var p = root.Element("P");
                var q = root.Element("Q");
                var dp = root.Element("DP");
                var dq = root.Element("DQ");
                var inverseQ = root.Element("InverseQ");
                var d = root.Element("D");

                var rsaPrivateCrtKeyParameters = new RsaPrivateCrtKeyParameters(
                    new BigInteger(1, Convert.FromBase64String(modulus.Value)),
                    new BigInteger(1, Convert.FromBase64String(exponent.Value)),
                    new BigInteger(1, Convert.FromBase64String(d.Value)),
                    new BigInteger(1, Convert.FromBase64String(p.Value)),
                    new BigInteger(1, Convert.FromBase64String(q.Value)),
                    new BigInteger(1, Convert.FromBase64String(dp.Value)),
                    new BigInteger(1, Convert.FromBase64String(dq.Value)),
                    new BigInteger(1, Convert.FromBase64String(inverseQ.Value)));

                using var writer = new StringWriter();
                var pemWriter = new PemWriter(writer);

                pemWriter.WriteObject(rsaPrivateCrtKeyParameters);
                pemWriter.Writer.Close();

                return writer.ToString();
            }

            public static string PrivateKeyPkcs8ToXml(string privateKey)
            {
                var privateKeyBytes = BaseConv.FromBase64(privateKey.RemovePkcs8PrivateKeyFormat());
                var privateKeyParam = (RsaPrivateCrtKeyParameters) PrivateKeyFactory.CreateKey(privateKeyBytes);

                //Key
                var element = new XElement("RSAKeyValue");

                var privateModulus = new XElement("Modulus", Convert.ToBase64String(privateKeyParam.Modulus.ToByteArrayUnsigned()));
                var privateExponent = new XElement("Exponent", Convert.ToBase64String(privateKeyParam.PublicExponent.ToByteArrayUnsigned()));
                var privateP = new XElement("P", Convert.ToBase64String(privateKeyParam.P.ToByteArrayUnsigned()));
                var privateQ = new XElement("Q", Convert.ToBase64String(privateKeyParam.Q.ToByteArrayUnsigned()));
                var privateDp = new XElement("DP", Convert.ToBase64String(privateKeyParam.DP.ToByteArrayUnsigned()));
                var privateDq = new XElement("DQ", Convert.ToBase64String(privateKeyParam.DQ.ToByteArrayUnsigned()));
                var privateInverseQ = new XElement("InverseQ", Convert.ToBase64String(privateKeyParam.QInv.ToByteArrayUnsigned()));
                var privateD = new XElement("D", Convert.ToBase64String(privateKeyParam.Exponent.ToByteArrayUnsigned()));

                element.Add(privateModulus);
                element.Add(privateExponent);
                element.Add(privateP);
                element.Add(privateQ);
                element.Add(privateDp);
                element.Add(privateDq);
                element.Add(privateInverseQ);
                element.Add(privateD);

                return element.ToString();
            }

            public static string PrivateKeyXmlToPkcs8(string privateKey)
            {
                var root = XElement.Parse(privateKey);

                var modulus = root.Element("Modulus");
                var exponent = root.Element("Exponent");
                var p = root.Element("P");
                var q = root.Element("Q");
                var dp = root.Element("DP");
                var dq = root.Element("DQ");
                var inverseQ = root.Element("InverseQ");
                var d = root.Element("D");

                var rsaPrivateCrtKeyParameters = new RsaPrivateCrtKeyParameters(
                    new BigInteger(1, Convert.FromBase64String(modulus.Value)),
                    new BigInteger(1, Convert.FromBase64String(exponent.Value)),
                    new BigInteger(1, Convert.FromBase64String(d.Value)),
                    new BigInteger(1, Convert.FromBase64String(p.Value)),
                    new BigInteger(1, Convert.FromBase64String(q.Value)),
                    new BigInteger(1, Convert.FromBase64String(dp.Value)),
                    new BigInteger(1, Convert.FromBase64String(dq.Value)),
                    new BigInteger(1, Convert.FromBase64String(inverseQ.Value)));

                using var writer = new StringWriter();
                
                var pemWriter = new PemWriter(writer);
                var pkcs8 = new Pkcs8Generator(rsaPrivateCrtKeyParameters);

                pemWriter.WriteObject(pkcs8);
                pemWriter.Writer.Close();
                return writer.ToString();
            }

            public static string PrivateKeyPkcs1ToPkcs8(string privateKey)
            {
                var pemReader = new PemReader(new StringReader(privateKey.AppendPkcs1PrivateKeyFormat()));

                if (pemReader.ReadObject() is not AsymmetricCipherKeyPair asymmetricCipherKeyPair)
                    throw new ArgumentException($"Unknown format for Private Key: cannot convert to {nameof(AsymmetricCipherKeyPair)}.");

                using var writer = new StringWriter();
                var pemWriter = new PemWriter(writer);

                var pkcs8Gen = new Pkcs8Generator(asymmetricCipherKeyPair.Private);
                pemWriter.WriteObject(pkcs8Gen);
                pemWriter.Writer.Close();

                return writer.ToString();
            }

            public static string PrivateKeyPkcs8ToPkcs1(string privateKey)
            {
                var pemReader = new PemReader(new StringReader(privateKey.AppendPkcs8PrivateKeyFormat()));

                if (pemReader.ReadObject() is not RsaPrivateCrtKeyParameters rsaPrivateCrtKeyParameters)
                    throw new ArgumentException($"Unknown format for Private Key: cannot convert to {nameof(RsaPrivateCrtKeyParameters)}.");

                var keyParameter = PrivateKeyFactory.CreateKey(PrivateKeyInfoFactory.CreatePrivateKeyInfo(rsaPrivateCrtKeyParameters));
                
                using var writer = new StringWriter();
                var pemWriter = new PemWriter(writer);

                pemWriter.WriteObject(keyParameter);
                pemWriter.Writer.Close();

                return writer.ToString();
            }
        }
    }
}