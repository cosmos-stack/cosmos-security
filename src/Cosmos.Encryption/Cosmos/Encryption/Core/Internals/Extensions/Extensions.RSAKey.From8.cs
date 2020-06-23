using System;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace Cosmos.Encryption.Core.Internals.Extensions
{
    // ReSharper disable once InconsistentNaming
    internal static partial class RSAKeyExtensions
    {
        // ReSharper disable once IdentifierTypo
        public static void FromPkcs8PublicString(this RSA rsa, string publicKey, out RSAParameters parameters)
        {
            publicKey = RSAPemFormatHelper.Pkcs8PublicKeyFormatRemove(publicKey);
            var publicKeyParam = (RsaKeyParameters) PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));

            parameters = new RSAParameters
            {
                Modulus = publicKeyParam.Modulus.ToByteArrayUnsigned(),
                Exponent = publicKeyParam.Exponent.ToByteArrayUnsigned()
            };

            rsa.ImportParameters(parameters);
        }

        // ReSharper disable once IdentifierTypo
        public static void FromPkcs8PrivateString(this RSA rsa, string privateKey, out RSAParameters parameters)
        {
            privateKey = RSAPemFormatHelper.Pkcs8PrivateKeyFormatRemove(privateKey);
            var privateKeyParam = (RsaPrivateCrtKeyParameters) PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));

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

        public static string ToPkcs8PublicString(this RSA rsa)
        {
            var privateKeyParameters = rsa.ExportParameters(false);
            RsaKeyParameters rsaKeyParameters = new RsaKeyParameters(
                false,
                new BigInteger(1, privateKeyParameters.Modulus),
                new BigInteger(1, privateKeyParameters.Exponent));

            using var sw = new StringWriter();
            var pWrt = new PemWriter(sw);
            pWrt.WriteObject(rsaKeyParameters);
            pWrt.Writer.Close();
            return sw.ToString();
        }

        public static string ToPkcs8PrivateString(this RSA rsa)
        {
            var privateKeyParameters = rsa.ExportParameters(true);
            RsaPrivateCrtKeyParameters rsaPrivateCrtKeyParameters = new RsaPrivateCrtKeyParameters(
                new BigInteger(1, privateKeyParameters.Modulus),
                new BigInteger(1, privateKeyParameters.Exponent),
                new BigInteger(1, privateKeyParameters.D),
                new BigInteger(1, privateKeyParameters.P),
                new BigInteger(1, privateKeyParameters.Q),
                new BigInteger(1, privateKeyParameters.DP),
                new BigInteger(1, privateKeyParameters.DQ),
                new BigInteger(1, privateKeyParameters.InverseQ));

            using var privateSw = new StringWriter();
            var privatePemWriter = new PemWriter(privateSw);
            var pkcs8 = new Pkcs8Generator(rsaPrivateCrtKeyParameters);

            privatePemWriter.WriteObject(pkcs8);
            privatePemWriter.Writer.Close();
            return privateSw.ToString();
        }
    }
}