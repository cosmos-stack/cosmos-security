using System.Security.Cryptography;
using System.Text;
using Cosmos.Encryption.Core.Internals;

// ReSharper disable once CheckNamespace
namespace Cosmos.Encryption
{
    /// <summary>
    /// Asymmetric/DSA encryption.
    /// Reference: X-New-Life
    ///     https://github.com/NewLifeX/X/blob/master/NewLife.Core/Security/DSAHelper.cs
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static class DSAEncryptionProvider
    {
        /// <summary>
        /// Create a new <see cref="DSAKey"/>
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static DSAKey CreateKey(int keySize = 1024)
        {
            using (var provider = new DSACryptoServiceProvider(keySize))
            {
                var key = new DSAKey();
                var pa = provider.ExportParameters(true);
                key.PrivateKey = provider.ToXmlString(true);
                key.PublicKey = provider.ToXmlString(false);
                return key;
            }
        }

        /// <summary>
        /// Signature
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static byte[] Signature(byte[] buffer, string privateKey)
        {
            using (var provider = new DSACryptoServiceProvider())
            {
                provider.FromXmlString(privateKey);
                return provider.SignData(buffer);
            }
        }

        /// <summary>
        /// Signature
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] Signature(byte[] buffer, DSAKey key)
        {
            Checker.Key(key);
            return Signature(buffer, key.PrivateKey);
        }

        /// <summary>
        /// Signature
        /// </summary>
        /// <param name="data"></param>
        /// <param name="privateKey"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static byte[] Signature(string data, string privateKey, Encoding encoding = null)
        {
            encoding = EncodingHelper.Fixed(encoding);
            return Signature(encoding.GetBytes(data), privateKey);
        }

        /// <summary>
        /// Signature
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static byte[] Signature(string data, DSAKey key, Encoding encoding = null)
        {
            encoding = EncodingHelper.Fixed(encoding);
            return Signature(encoding.GetBytes(data), key);
        }

        /// <summary>
        /// Verify
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="publicKey"></param>
        /// <param name="rgbSignature"></param>
        /// <returns></returns>
        public static bool Verify(byte[] buffer, string publicKey, byte[] rgbSignature)
        {
            using (var provider = new DSACryptoServiceProvider())
            {
                provider.FromXmlString(publicKey);
                return provider.VerifyData(buffer, rgbSignature);
            }
        }

        /// <summary>
        /// Verify
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="key"></param>
        /// <param name="rgbSignature"></param>
        /// <returns></returns>
        public static bool Verify(byte[] buffer, DSAKey key, byte[] rgbSignature)
        {
            Checker.Key(key);
            return Verify(buffer, key.PublicKey, rgbSignature);
        }
    }
}