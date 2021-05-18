#if NETCOREAPP3_1 || NETSTANDARD2_1
using System;
using Cosmos.Conversions;
#else
using System;
#endif
using MsRSA = System.Security.Cryptography.RSA;

// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Cryptography
{
    public static class RsaExtensions
    {
        /// <summary>
        /// Export RSA private key
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="format"></param>
        /// <param name="usePemFormat"></param>
        /// <returns></returns>
        public static string ExportPrivateKey(this MsRSA rsa, RsaKeyFormat format, bool usePemFormat = false)
        {
            var key = format switch
            {
                RsaKeyFormat.XML => rsa.ExportKeyInLvccXml(true),
                RsaKeyFormat.JSON => rsa.ExportKeyInJson(true),
#if NETCOREAPP3_1 || NETSTANDARD2_1
                RsaKeyFormat.Pkcs1 => BaseConv.ToBase64(rsa.ExportRSAPrivateKey()),
                RsaKeyFormat.Pkcs8 => BaseConv.ToBase64(rsa.ExportPkcs8PrivateKey()),
#else
                RsaKeyFormat.Pkcs1 => rsa.GetPrivateKeyInPkcs1(),
                RsaKeyFormat.Pkcs8 => rsa.GetPrivateKeyInPkcs8(),
#endif
                _ => throw new NotSupportedException("Unknown RSA key type.")
            };

            if (usePemFormat)
            {
                key = format switch
                {
                    RsaKeyFormat.XML => key,
                    RsaKeyFormat.JSON => key,
                    RsaKeyFormat.Pkcs1 => key.RemovePkcs1PrivateKeyFormat(),
                    RsaKeyFormat.Pkcs8 => key.RemovePkcs8PrivateKeyFormat(),
                    _ => throw new NotSupportedException("Unknown RSA key type.")
                };
            }

            return key;
        }

        /// <summary>
        /// Export RSA public key
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="format"></param>
        /// <param name="usePemFormat"></param>
        /// <returns></returns>
        public static string ExportPublicKey(this MsRSA rsa, RsaKeyFormat format, bool usePemFormat = false)
        {
            var key = format switch
            {
                RsaKeyFormat.XML => rsa.ExportKeyInLvccXml(false),
                RsaKeyFormat.JSON => rsa.ExportKeyInJson(false),
#if NETCOREAPP3_1 || NETSTANDARD2_1
                RsaKeyFormat.Pkcs1 => BaseConv.ToBase64(rsa.ExportRSAPublicKey()),
                RsaKeyFormat.Pkcs8 => BaseConv.ToBase64(rsa.ExportRSAPublicKey()),
#else
                RsaKeyFormat.Pkcs1 => rsa.GetPublicKeyInPkcs1(),
                RsaKeyFormat.Pkcs8 => rsa.GetPublicKeyInPkcs8(),
#endif
                _ => throw new NotSupportedException("Unknown RSA key type.")
            };

            if (usePemFormat)
            {
                key = format switch
                {
                    RsaKeyFormat.XML => key,
                    RsaKeyFormat.JSON => key,
                    RsaKeyFormat.Pkcs1 => key.RemovePkcs1PublicKeyFormat(),
                    RsaKeyFormat.Pkcs8 => key.RemovePkcs8PublicKeyFormat(),
                    _ => throw new NotSupportedException("Unknown RSA key type.")
                };
            }

            return key;
        }

        /// <summary>
        /// Import RSA private key
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="format"></param>
        /// <param name="privateKey"></param>
        /// <param name="isPem"></param>
        public static void ImportPrivateKey(this MsRSA rsa, RsaKeyFormat format, string privateKey, bool isPem = false)
        {
            if (isPem)
            {
                privateKey = format switch
                {
                    RsaKeyFormat.XML => privateKey,
                    RsaKeyFormat.JSON => privateKey,
                    RsaKeyFormat.Pkcs1 => privateKey.RemovePkcs1PrivateKeyFormat(),
                    RsaKeyFormat.Pkcs8 => privateKey.RemovePkcs8PrivateKeyFormat(),
                    _ => throw new NotSupportedException("Unknown RSA key type.")
                };
            }

            switch (format)
            {
                case RsaKeyFormat.XML:
                    rsa.ImportKeyInLvccXml(privateKey);
                    break;

                case RsaKeyFormat.JSON:
                    rsa.ImportKeyInJson(privateKey);
                    break;

                case RsaKeyFormat.Pkcs1:
#if NETCOREAPP3_1 || NETSTANDARD2_1
                    rsa.ImportRSAPrivateKey(BaseConv.FromBase64(privateKey), out _);
#else
                    rsa.TouchFromPrivateKeyInPkcs1(privateKey, out _);
#endif
                    break;

                case RsaKeyFormat.Pkcs8:
#if NETCOREAPP3_1 || NETSTANDARD2_1
                    rsa.ImportPkcs8PrivateKey(BaseConv.FromBase64(privateKey), out _);
#else
                    rsa.TouchFromPrivateKeyInPkcs8(privateKey, out _);
#endif
                    break;
            }
        }

        /// <summary>
        /// Import RSA public key
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="format"></param>
        /// <param name="publicKey"></param>
        /// <param name="isPem"></param>
        public static void ImportPublicKey(this MsRSA rsa, RsaKeyFormat format, string publicKey, bool isPem = false)
        {
            if (isPem)
            {
                publicKey = format switch
                {
                    RsaKeyFormat.XML => publicKey,
                    RsaKeyFormat.JSON => publicKey,
                    RsaKeyFormat.Pkcs1 => publicKey.RemovePkcs1PublicKeyFormat(),
                    RsaKeyFormat.Pkcs8 => publicKey.RemovePkcs8PublicKeyFormat(),
                    _ => throw new NotSupportedException("Unknown RSA key type.")
                };
            }

            switch (format)
            {
                case RsaKeyFormat.XML:
                    rsa.ImportKeyInLvccXml(publicKey);
                    break;

                case RsaKeyFormat.JSON:
                    rsa.ImportKeyInJson(publicKey);
                    break;

                case RsaKeyFormat.Pkcs1:
#if NETCOREAPP3_1 || NETSTANDARD2_1
                    rsa.ImportRSAPublicKey(BaseConv.FromBase64(publicKey), out _);
#else
                    rsa.TouchFromPublicKeyInPkcs1(publicKey, out _);
#endif
                    break;

                case RsaKeyFormat.Pkcs8:
#if NETCOREAPP3_1 || NETSTANDARD2_1
                    rsa.ImportRSAPublicKey(BaseConv.FromBase64(publicKey), out _);
#else
                    rsa.TouchFromPublicKeyInPkcs8(publicKey, out _);
#endif
                    break;
            }
        }
    }
}