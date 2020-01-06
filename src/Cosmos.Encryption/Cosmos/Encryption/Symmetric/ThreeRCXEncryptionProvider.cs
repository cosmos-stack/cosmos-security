/*
 * Reference to:
 *     https://github.com/toolgood/RCX/blob/master/ToolGood.RcxTest/ToolGood.RcxCrypto/RCX.cs
 *     Author: ToolGood
 *     GitHub: https://github.com/toolgood
 */


using System;
using System.Text;
using Cosmos.Encryption.Abstractions;
using Cosmos.Encryption.Core.Internals;
using Cosmos.Internals;

// ReSharper disable once CheckNamespace
namespace Cosmos.Encryption {
    /// <summary>
    /// Three RCX encryption provider
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public sealed class ThreeRCXEncryptionProvider : ISymmetricEncryption {
        private ThreeRCXEncryptionProvider() { }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="encoding"></param>
        /// <param name="order"></param>
        /// <returns></returns>
        public static string Encrypt(string data, string key, Encoding encoding = null, RCXOrder order = RCXOrder.DESC) {
            encoding = EncodingHelper.Fixed(encoding);
            var dataBytes = encoding.GetBytes(data);
            var keyBytes = encoding.GetBytes(key);
            return Convert.ToBase64String(EncryptCore(dataBytes, keyBytes, order));
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="encoding"></param>
        /// <param name="order"></param>
        /// <returns></returns>
        public static string Encrypt(byte[] data, string key, Encoding encoding = null, RCXOrder order = RCXOrder.DESC) {
            encoding = EncodingHelper.Fixed(encoding);
            var keyBytes = encoding.GetBytes(key);
            return Convert.ToBase64String(EncryptCore(data, keyBytes, order));
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="order"></param>
        /// <returns></returns>
        public static byte[] Encrypt(byte[] data, byte[] key, RCXOrder order = RCXOrder.DESC) {
            return EncryptCore(data, key, order);
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="encoding"></param>
        /// <param name="order"></param>
        /// <returns></returns>
        public static string Decrypt(string data, string key, Encoding encoding = null, RCXOrder order = RCXOrder.DESC) {
            encoding = EncodingHelper.Fixed(encoding);
            var dataBytes = Convert.FromBase64String(data);
            var keyBytes = encoding.GetBytes(key);
            return encoding.GetString(EncryptCore(dataBytes, keyBytes, order));
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="order"></param>
        /// <returns></returns>
        public static byte[] Decrypt(byte[] data, byte[] key, RCXOrder order = RCXOrder.DESC) {
            return EncryptCore(data, key, order);
        }

        private static byte[] EncryptCore(byte[] dataBytes, byte[] keyBytes, RCXOrder order = RCXOrder.DESC) {
            var first = RCXEncryptionProvider.Encrypt(dataBytes, keyBytes, order);
            var second = RCXEncryptionProvider.Encrypt(first, keyBytes, order);
            return RCXEncryptionProvider.Encrypt(second, keyBytes, order);
        }
    }
}