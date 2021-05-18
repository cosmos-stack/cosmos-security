using System.Collections.Generic;
using System.IO;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Cryptography
{
    internal static class RsaPemFormatExtensions
    {
        /// <summary>
        /// Format Pkcs8 format private key
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static string AppendPkcs8PrivateKeyFormat(this string privateKey)
        {
            if (privateKey.StartsWith(RsaKey.PRIVATE_KEY_START))
            {
                return privateKey;
            }

            var res = new List<string> {RsaKey.PRIVATE_KEY_START};

            var pos = 0;

            while (pos < privateKey.Length)
            {
                var count = privateKey.Length - pos < 64 ? privateKey.Length - pos : 64;
                res.Add(privateKey.Substring(pos, count));
                pos += count;
            }

            res.Add(RsaKey.PRIVATE_KEY_END);
            var resStr = string.Join(RsaKey.R_N, res);
            return resStr;
        }

        /// <summary>
        /// Format pkcs8 public key
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static string AppendPkcs8PublicKeyFormat(this string publicKey)
        {
            if (publicKey.StartsWith(RsaKey.PUBLIC_KEY_START))
            {
                return publicKey;
            }

            var res = new List<string> {RsaKey.PUBLIC_KEY_START};
            var pos = 0;

            while (pos < publicKey.Length)
            {
                var count = publicKey.Length - pos < 64 ? publicKey.Length - pos : 64;
                res.Add(publicKey.Substring(pos, count));
                pos += count;
            }

            res.Add(RsaKey.PUBLIC_KEY_END);
            var resStr = string.Join(RsaKey.R_N, res);
            return resStr;
        }

        /// <summary>
        /// Used for Pkcs8
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static string RemovePkcs8PublicKeyFormat(this string publicKey)
        {
            return RemovePkcs8PublicKeyFormatIfNeed(publicKey, false);
        }

        /// <summary>
        /// Used for Pkcs8
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static string RemovePkcs8PublicKeyFormatIfNeed(this StringWriter writer, bool keepingFormat)
        {
            return RemovePkcs8PublicKeyFormatIfNeed(writer.ToString(), keepingFormat);
        }

        /// <summary>
        /// Used for Pkcs8
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static string RemovePkcs8PublicKeyFormatIfNeed(this string publicKey, bool keepingFormat)
        {
            if (!publicKey.StartsWith(RsaKey.PUBLIC_KEY_START))
                return publicKey;
            return keepingFormat
                ? publicKey
                : publicKey
                  .ReplaceToEmpty(RsaKey.PUBLIC_KEY_START)
                  .ReplaceToEmpty(RsaKey.PUBLIC_KEY_END)
                  .ReplaceToEmpty(RsaKey.R_N);
        }

        /// <summary>
        /// Used for Pkcs8
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static string RemovePkcs8PrivateKeyFormat(this string privateKey)
        {
            return RemovePkcs8PrivateKeyFormatIfNeed(privateKey, false);
        }

        /// <summary>
        /// Used for Pkcs8
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static string RemovePkcs8PrivateKeyFormatIfNeed(this StringWriter writer, bool keepingFormat)
        {
            return RemovePkcs8PrivateKeyFormatIfNeed(writer.ToString(), keepingFormat);
        }

        /// <summary>
        /// Used for Pkcs8
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static string RemovePkcs8PrivateKeyFormatIfNeed(this string privateKey, bool keepingFormat)
        {
            if (!privateKey.StartsWith(RsaKey.PRIVATE_KEY_START))
                return privateKey;
            return keepingFormat
                ? privateKey
                : privateKey
                  .ReplaceToEmpty(RsaKey.PRIVATE_KEY_START)
                  .ReplaceToEmpty(RsaKey.PRIVATE_KEY_END)
                  .ReplaceToEmpty(RsaKey.R_N);
        }


        /// <summary>
        /// Format Pkcs1 format private key
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static string AppendPkcs1PrivateKeyFormat(this string privateKey)
        {
            if (privateKey.StartsWith(RsaKey.RSA_PRIVATE_KEY_START))
            {
                return privateKey;
            }

            var res = new List<string> {RsaKey.RSA_PRIVATE_KEY_START};

            var pos = 0;

            while (pos < privateKey.Length)
            {
                var count = privateKey.Length - pos < 64 ? privateKey.Length - pos : 64;
                res.Add(privateKey.Substring(pos, count));
                pos += count;
            }

            res.Add(RsaKey.RSA_PRIVATE_KEY_END);
            var resStr = string.Join(RsaKey.R_N, res);
            return resStr;
        }

        /// <summary>
        /// Format pkcs1 public key
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static string AppendPkcs1PublicKeyFormat(this string publicKey)
        {
            if (publicKey.StartsWith(RsaKey.RSA_PUBLIC_KEY_START))
            {
                return publicKey;
            }

            var res = new List<string> {RsaKey.RSA_PUBLIC_KEY_START};
            var pos = 0;

            while (pos < publicKey.Length)
            {
                var count = publicKey.Length - pos < 64 ? publicKey.Length - pos : 64;
                res.Add(publicKey.Substring(pos, count));
                pos += count;
            }

            res.Add(RsaKey.RSA_PUBLIC_KEY_END);
            var resStr = string.Join(RsaKey.R_N, res);
            return resStr;
        }

        /// <summary>
        /// Used for Pkcs1
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static string RemovePkcs1PublicKeyFormat(this string publicKey)
        {
            return RemovePkcs1PublicKeyFormatIfNeed(publicKey, false);
        }

        /// <summary>
        /// Used for Pkcs1
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static string RemovePkcs1PublicKeyFormatIfNeed(this StringWriter writer, bool keepingFormat)
        {
            return RemovePkcs1PublicKeyFormatIfNeed(writer.ToString(), keepingFormat);
        }

        /// <summary>
        /// Used for Pkcs1
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static string RemovePkcs1PublicKeyFormatIfNeed(this string publicKey, bool keepingFormat)
        {
            if (!publicKey.StartsWith(RsaKey.RSA_PUBLIC_KEY_START))
                return publicKey;
            return keepingFormat
                ? publicKey
                : publicKey
                  .ReplaceToEmpty(RsaKey.RSA_PUBLIC_KEY_START)
                  .ReplaceToEmpty(RsaKey.RSA_PUBLIC_KEY_END)
                  .ReplaceToEmpty(RsaKey.R_N);
        }

        /// <summary>
        /// Used for Pkcs1
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static string RemovePkcs1PrivateKeyFormat(this string privateKey)
        {
            return RemovePkcs1PrivateKeyFormatIfNeed(privateKey, false);
        }

        /// <summary>
        /// Used for Pkcs1
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static string RemovePkcs1PrivateKeyFormatIfNeed(this StringWriter writer, bool keepingFormat)
        {
            return RemovePkcs1PrivateKeyFormatIfNeed(writer.ToString(), keepingFormat);
        }

        /// <summary>
        /// Used for Pkcs1
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static string RemovePkcs1PrivateKeyFormatIfNeed(this string privateKey, bool keepingFormat)
        {
            if (!privateKey.StartsWith(RsaKey.RSA_PRIVATE_KEY_START))
                return privateKey;
            return keepingFormat
                ? privateKey
                : privateKey
                  .ReplaceToEmpty(RsaKey.PRIVATE_KEY_START)
                  .ReplaceToEmpty(RsaKey.PRIVATE_KEY_END)
                  .ReplaceToEmpty(RsaKey.R_N);
        }

        private static string ReplaceToEmpty(this string str, string oldValue) => str.Replace(oldValue, "");
    }
}