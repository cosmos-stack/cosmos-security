using System;
using System.IO;
using System.Security.Cryptography;
using System.Xml;
using Cosmos.Conversions;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using MsRSA = System.Security.Cryptography.RSA;

// ReSharper disable InconsistentNaming
// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Cryptography
{
    internal static class RsaInstanceExtensions
    {
        #region Xml

        public static void ImportKeyInLvccXml(this MsRSA rsa, string xmlString)
        {
            RSAParameters parameters = new RSAParameters();

            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlString);

            // ReSharper disable once PossibleNullReferenceException
            if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
            {
                foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case "Modulus":
                            parameters.Modulus = (string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText));
                            break;
                        case "Exponent":
                            parameters.Exponent = (string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText));
                            break;
                        case "P":
                            parameters.P = (string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText));
                            break;
                        case "Q":
                            parameters.Q = (string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText));
                            break;
                        case "DP":
                            parameters.DP = (string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText));
                            break;
                        case "DQ":
                            parameters.DQ = (string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText));
                            break;
                        case "InverseQ":
                            parameters.InverseQ = (string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText));
                            break;
                        case "D":
                            parameters.D = (string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText));
                            break;
                    }
                }
            }
            else
            {
                throw new Exception("Invalid XML RSA key.");
            }

            rsa.ImportParameters(parameters);
        }

        public static string ExportKeyInLvccXml(this MsRSA rsa, bool includePrivateParameters)
        {
            RSAParameters parameters = rsa.ExportParameters(includePrivateParameters);

            // ReSharper disable once UseStringInterpolation
            return string.Format(
                "<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null,
                parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null,
                parameters.P != null ? Convert.ToBase64String(parameters.P) : null,
                parameters.Q != null ? Convert.ToBase64String(parameters.Q) : null,
                parameters.DP != null ? Convert.ToBase64String(parameters.DP) : null,
                parameters.DQ != null ? Convert.ToBase64String(parameters.DQ) : null,
                parameters.InverseQ != null ? Convert.ToBase64String(parameters.InverseQ) : null,
                parameters.D != null ? Convert.ToBase64String(parameters.D) : null);
        }

        #endregion

        #region JSON

        internal static void ImportKeyInJson(this MsRSA rsa, string jsonString)
        {
            if (string.IsNullOrEmpty(jsonString))
            {
                throw new ArgumentNullException(nameof(jsonString));
            }

            var parameters = new RSAParameters();

            try
            {
                var paramsJson = JsonConvert.DeserializeObject<RsaJsonParameters>(jsonString);

                parameters.Modulus = paramsJson.Modulus != null ? Convert.FromBase64String(paramsJson.Modulus) : null;
                parameters.Exponent =
                    paramsJson.Exponent != null ? Convert.FromBase64String(paramsJson.Exponent) : null;
                parameters.P = paramsJson.P != null ? Convert.FromBase64String(paramsJson.P) : null;
                parameters.Q = paramsJson.Q != null ? Convert.FromBase64String(paramsJson.Q) : null;
                parameters.DP = paramsJson.DP != null ? Convert.FromBase64String(paramsJson.DP) : null;
                parameters.DQ = paramsJson.DQ != null ? Convert.FromBase64String(paramsJson.DQ) : null;
                parameters.InverseQ =
                    paramsJson.InverseQ != null ? Convert.FromBase64String(paramsJson.InverseQ) : null;
                parameters.D = paramsJson.D != null ? Convert.FromBase64String(paramsJson.D) : null;
            }
            catch
            {
                throw new Exception("Invalid Json RSA key.");
            }

            rsa.ImportParameters(parameters);
        }

        internal static string ExportKeyInJson(this MsRSA rsa, bool includePrivateParameters)
        {
            var parameters = rsa.ExportParameters(includePrivateParameters);

            var parasJson = new RsaJsonParameters()
            {
                Modulus = parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null,
                Exponent = parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null,
                P = parameters.P != null ? Convert.ToBase64String(parameters.P) : null,
                Q = parameters.Q != null ? Convert.ToBase64String(parameters.Q) : null,
                DP = parameters.DP != null ? Convert.ToBase64String(parameters.DP) : null,
                DQ = parameters.DQ != null ? Convert.ToBase64String(parameters.DQ) : null,
                InverseQ = parameters.InverseQ != null ? Convert.ToBase64String(parameters.InverseQ) : null,
                D = parameters.D != null ? Convert.ToBase64String(parameters.D) : null
            };

            return JsonConvert.SerializeObject(parasJson);
        }

        #endregion

        #region Pkcs#1

        public static void TouchFromPublicKeyInPkcs1(this MsRSA rsa, string publicKey, out RSAParameters parameters)
        {
            var pr = new PemReader(new StringReader(publicKey.RemovePkcs1PublicKeyFormat()));
            if (pr.ReadObject() is not RsaKeyParameters rsaKey)
            {
                throw new Exception("Public key format is incorrect");
            }

            parameters = new RSAParameters
            {
                Modulus = rsaKey.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaKey.Exponent.ToByteArrayUnsigned()
            };

            rsa.ImportParameters(parameters);
        }

        public static void TouchFromPrivateKeyInPkcs1(this MsRSA rsa, string privateKey, out RSAParameters parameters)
        {
            var pr = new PemReader(new StringReader(privateKey.RemovePkcs1PrivateKeyFormat()));
            if (!(pr.ReadObject() is AsymmetricCipherKeyPair asymmetricCipherKeyPair))
            {
                throw new Exception("Private key format is incorrect");
            }

            var rsaPrivateCrtKeyParameters = (RsaPrivateCrtKeyParameters) PrivateKeyFactory.CreateKey(
                PrivateKeyInfoFactory.CreatePrivateKeyInfo(asymmetricCipherKeyPair.Private));

            parameters = new RSAParameters
            {
                Modulus = rsaPrivateCrtKeyParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaPrivateCrtKeyParameters.PublicExponent.ToByteArrayUnsigned(),
                P = rsaPrivateCrtKeyParameters.P.ToByteArrayUnsigned(),
                Q = rsaPrivateCrtKeyParameters.Q.ToByteArrayUnsigned(),
                DP = rsaPrivateCrtKeyParameters.DP.ToByteArrayUnsigned(),
                DQ = rsaPrivateCrtKeyParameters.DQ.ToByteArrayUnsigned(),
                InverseQ = rsaPrivateCrtKeyParameters.QInv.ToByteArrayUnsigned(),
                D = rsaPrivateCrtKeyParameters.Exponent.ToByteArrayUnsigned()
            };

            rsa.ImportParameters(parameters);
        }

        public static string GetPublicKeyInPkcs1(this MsRSA rsa)
        {
            var privateKeyParameters = rsa.ExportParameters(false);
            var rsaKeyParameters = new RsaKeyParameters(
                false,
                new BigInteger(1, privateKeyParameters.Modulus),
                new BigInteger(1, privateKeyParameters.Exponent));

            using var writer = new StringWriter();
            var pemWriter = new PemWriter(writer);
            pemWriter.WriteObject(rsaKeyParameters);
            pemWriter.Writer.Close();
            return writer.ToString();
        }

        public static string GetPrivateKeyInPkcs1(this MsRSA rsa)
        {
            var privateKeyParameters = rsa.ExportParameters(true);
            var rsaPrivateCrtKeyParameters = new RsaPrivateCrtKeyParameters(
                new BigInteger(1, privateKeyParameters.Modulus),
                new BigInteger(1, privateKeyParameters.Exponent),
                new BigInteger(1, privateKeyParameters.D),
                new BigInteger(1, privateKeyParameters.P),
                new BigInteger(1, privateKeyParameters.Q),
                new BigInteger(1, privateKeyParameters.DP),
                new BigInteger(1, privateKeyParameters.DQ),
                new BigInteger(1, privateKeyParameters.InverseQ));

            using var writer = new StringWriter();
            var pemWriter = new PemWriter(writer);
            pemWriter.WriteObject(rsaPrivateCrtKeyParameters);
            pemWriter.Writer.Close();
            return writer.ToString();
        }

        #endregion

        #region Pkcs#8

        public static void TouchFromPublicKeyInPkcs8(this MsRSA rsa, string publicKey, out RSAParameters parameters)
        {
            var publicKeyBytes = BaseConv.FromBase64(publicKey.RemovePkcs8PublicKeyFormat());
            var publicKeyParam = (RsaKeyParameters) PublicKeyFactory.CreateKey(publicKeyBytes);

            parameters = new RSAParameters
            {
                Modulus = publicKeyParam.Modulus.ToByteArrayUnsigned(),
                Exponent = publicKeyParam.Exponent.ToByteArrayUnsigned()
            };

            rsa.ImportParameters(parameters);
        }

        public static void TouchFromPrivateKeyInPkcs8(this MsRSA rsa, string privateKey, out RSAParameters parameters)
        {
            var privateKeyBytes = BaseConv.FromBase64(privateKey.RemovePkcs8PrivateKeyFormat());
            var privateKeyParam = (RsaPrivateCrtKeyParameters) PrivateKeyFactory.CreateKey(privateKeyBytes);

            parameters = new RSAParameters
            {
                Modulus = privateKeyParam.Modulus.ToByteArrayUnsigned(),
                Exponent = privateKeyParam.PublicExponent.ToByteArrayUnsigned(),
                P = privateKeyParam.P.ToByteArrayUnsigned(),
                Q = privateKeyParam.Q.ToByteArrayUnsigned(),
                DP = privateKeyParam.DP.ToByteArrayUnsigned(),
                DQ = privateKeyParam.DQ.ToByteArrayUnsigned(),
                InverseQ = privateKeyParam.QInv.ToByteArrayUnsigned(),
                D = privateKeyParam.Exponent.ToByteArrayUnsigned()
            };

            rsa.ImportParameters(parameters);
        }

        public static string GetPublicKeyInPkcs8(this MsRSA rsa)
        {
            var publicKeyParameters = rsa.ExportParameters(false);
            var rsaKeyParameters = new RsaKeyParameters(
                false,
                new BigInteger(1, publicKeyParameters.Modulus),
                new BigInteger(1, publicKeyParameters.Exponent));

            using var writer = new StringWriter();
            var pemWriter = new PemWriter(writer);
            var pkcs8 = new Pkcs8Generator(rsaKeyParameters);

            pemWriter.WriteObject(pkcs8); //pemWriter.WriteObject(rsaKeyParameters);
            pemWriter.Writer.Close();
            return writer.ToString();
        }

        public static string GetPrivateKeyInPkcs8(this MsRSA rsa)
        {
            var privateKeyParameters = rsa.ExportParameters(true);
            var rsaKeyParameters = new RsaPrivateCrtKeyParameters(
                new BigInteger(1, privateKeyParameters.Modulus),
                new BigInteger(1, privateKeyParameters.Exponent),
                new BigInteger(1, privateKeyParameters.D),
                new BigInteger(1, privateKeyParameters.P),
                new BigInteger(1, privateKeyParameters.Q),
                new BigInteger(1, privateKeyParameters.DP),
                new BigInteger(1, privateKeyParameters.DQ),
                new BigInteger(1, privateKeyParameters.InverseQ));

            using var writer = new StringWriter();
            var pemWriter = new PemWriter(writer);
            var pkcs8 = new Pkcs8Generator(rsaKeyParameters);

            pemWriter.WriteObject(pkcs8);
            pemWriter.Writer.Close();
            return writer.ToString();
        }

        #endregion
    }
}