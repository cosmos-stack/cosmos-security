using System;
using System.Security.Cryptography;
using System.Text;
#if NETCOREAPP3_1 || NETSTANDARD2_1
using Cosmos.Conversions;
#endif
using Cosmos.Encryption.Core;
using Cosmos.Encryption.Core.Internals.Extensions;

// ReSharper disable once CheckNamespace
namespace Cosmos.Encryption
{
    // ReSharper disable once InconsistentNaming
    public static partial class RSAEncryptionProvider
    {
        #region Extensions for export and import

        /// <summary>
        /// Export RSA private key
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="type"></param>
        /// <param name="usePemFormat"></param>
        /// <returns></returns>
        public static string ExportPrivateKey(this RSA rsa, RSAKeyTypes type, bool usePemFormat = false)
        {
            var key = type switch
            {
                RSAKeyTypes.XML  => rsa.ToLvccXmlString(true),
                RSAKeyTypes.JSON => rsa.ToJsonString(true),
#if NETCOREAPP3_1 || NETSTANDARD2_1
                RSAKeyTypes.Pkcs1 => Base64Converter.ToBase64String(rsa.ExportRSAPrivateKey()),
                RSAKeyTypes.Pkcs8 => Base64Converter.ToBase64String(rsa.ExportPkcs8PrivateKey()),
#else
                RSAKeyTypes.Pkcs1 => rsa.ToPkcs1PrivateString(),
                RSAKeyTypes.Pkcs8 => rsa.ToPkcs8PrivateString(),
#endif
                _ => throw new NotSupportedException("Unknown RSA key type.")
            };

            if (usePemFormat)
            {
                key = type switch
                {
                    RSAKeyTypes.XML   => key,
                    RSAKeyTypes.JSON  => key,
                    RSAKeyTypes.Pkcs1 => RSAPemFormatHelper.Pkcs1PrivateKeyFormat(key),
                    RSAKeyTypes.Pkcs8 => RSAPemFormatHelper.Pkcs8PrivateKeyFormat(key),
                    _                 => throw new NotSupportedException("Unknown RSA key type.")
                };
            }

            return key;
        }

        /// <summary>
        /// Export RSA public key
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="type"></param>
        /// <param name="usePemFormat"></param>
        /// <returns></returns>
        public static string ExportPublicKey(this RSA rsa, RSAKeyTypes type, bool usePemFormat = false)
        {
            var key = type switch
            {
                RSAKeyTypes.XML  => rsa.ToLvccXmlString(false),
                RSAKeyTypes.JSON => rsa.ToJsonString(false),
#if NETCOREAPP3_1 || NETSTANDARD2_1
                RSAKeyTypes.Pkcs1 => Base64Converter.ToBase64String(rsa.ExportRSAPublicKey()),
                RSAKeyTypes.Pkcs8 => Base64Converter.ToBase64String(rsa.ExportRSAPublicKey()),
#else
                RSAKeyTypes.Pkcs1 => rsa.ToPkcs1PublicString(),
                RSAKeyTypes.Pkcs8 => rsa.ToPkcs8PublicString(),
#endif
                _ => throw new NotSupportedException("Unknown RSA key type.")
            };

            if (usePemFormat)
            {
                key = type switch
                {
                    RSAKeyTypes.XML   => key,
                    RSAKeyTypes.JSON  => key,
                    RSAKeyTypes.Pkcs1 => RSAPemFormatHelper.Pkcs1PublicKeyFormat(key),
                    RSAKeyTypes.Pkcs8 => RSAPemFormatHelper.Pkcs8PublicKeyFormat(key),
                    _                 => throw new NotSupportedException("Unknown RSA key type.")
                };
            }

            return key;
        }

        /// <summary>
        /// Import RSA private key
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="type"></param>
        /// <param name="privateKey"></param>
        /// <param name="isPem"></param>
        public static void ImportPrivateKey(this RSA rsa, RSAKeyTypes type, string privateKey, bool isPem = false)
        {
            if (isPem)
            {
                privateKey = type switch
                {
                    RSAKeyTypes.XML   => privateKey,
                    RSAKeyTypes.JSON  => privateKey,
                    RSAKeyTypes.Pkcs1 => RSAPemFormatHelper.Pkcs1PrivateKeyFormatRemove(privateKey),
                    RSAKeyTypes.Pkcs8 => RSAPemFormatHelper.Pkcs8PrivateKeyFormatRemove(privateKey),
                    _                 => throw new NotSupportedException("Unknown RSA key type.")
                };
            }

            switch (type)
            {
                case RSAKeyTypes.XML:
                    rsa.FromLvccXmlString(privateKey);
                    break;

                case RSAKeyTypes.JSON:
                    rsa.FromJsonString(privateKey);
                    break;

                case RSAKeyTypes.Pkcs1:
#if NETCOREAPP3_1 || NETSTANDARD2_1
                    rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out _);
#else
                    rsa.FromPkcs1PrivateString(privateKey, out _);
#endif
                    break;

                case RSAKeyTypes.Pkcs8:
#if NETCOREAPP3_1 || NETSTANDARD2_1
                    rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKey), out _);
#else
                    rsa.FromPkcs8PrivateString(privateKey, out _);
#endif
                    break;
            }
        }

        /// <summary>
        /// Import RSA public key
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="type"></param>
        /// <param name="publicKey"></param>
        /// <param name="isPem"></param>
        public static void ImportPublicKey(this RSA rsa, RSAKeyTypes type, string publicKey, bool isPem = false)
        {
            if (isPem)
            {
                publicKey = type switch
                {
                    RSAKeyTypes.XML   => publicKey,
                    RSAKeyTypes.JSON  => publicKey,
                    RSAKeyTypes.Pkcs1 => RSAPemFormatHelper.Pkcs1PublicKeyFormatRemove(publicKey),
                    RSAKeyTypes.Pkcs8 => RSAPemFormatHelper.Pkcs8PublicKeyFormatRemove(publicKey),
                    _                 => throw new NotSupportedException("Unknown RSA key type.")
                };
            }

            switch (type)
            {
                case RSAKeyTypes.XML:
                    rsa.FromLvccXmlString(publicKey);
                    break;

                case RSAKeyTypes.JSON:
                    rsa.FromJsonString(publicKey);
                    break;

                case RSAKeyTypes.Pkcs1:
#if NETCOREAPP3_1 || NETSTANDARD2_1
                    rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out _);
                    break;
#else
                    rsa.FromPkcs1PublicString(publicKey, out _);
                    break;
#endif

                case RSAKeyTypes.Pkcs8:
#if NETCOREAPP3_1 || NETSTANDARD2_1
                    rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out _);
                    break;
#else
                    rsa.FromPkcs8PublicString(publicKey, out _);
                    break;
#endif
            }
        }

        #endregion

        #region Extensions for touching RSA utils.

        private static RSABase TouchRsaUtilFromPublicKey(RSAKeyTypes keyType, Encoding encoding, string publicKey, RSAKeySizeTypes sizeType)
        {
            RSABase rsa = keyType switch
            {
                RSAKeyTypes.XML   => new RSAXmlUtil(encoding, publicKey, keySize: (int) sizeType),
                RSAKeyTypes.JSON  => new RSAJsonUtil(encoding, publicKey, keySize: (int) sizeType),
                RSAKeyTypes.Pkcs1 => new RSAPkcs1Util(encoding, publicKey, keySize: (int) sizeType),
                RSAKeyTypes.Pkcs8 => new RSAPkcs8Util(encoding, publicKey, keySize: (int) sizeType),
                _                 => throw new NotSupportedException("Unknown RSA key type.")
            };

            return rsa;
        }

        private static RSABase TouchRsaUtilFromPrivateKey(RSAKeyTypes keyType, Encoding encoding, string privateKey, RSAKeySizeTypes sizeType)
        {
            RSABase rsa = keyType switch
            {
                RSAKeyTypes.XML   => new RSAXmlUtil(encoding, null, privateKey, (int) sizeType),
                RSAKeyTypes.JSON  => new RSAJsonUtil(encoding, null, privateKey, (int) sizeType),
                RSAKeyTypes.Pkcs1 => new RSAPkcs1Util(encoding, null, privateKey, (int) sizeType),
                RSAKeyTypes.Pkcs8 => new RSAPkcs8Util(encoding, null, privateKey, (int) sizeType),
                _                 => throw new NotSupportedException("Unknown RSA key type."),
            };

            return rsa;
        }

        #endregion
    }
}