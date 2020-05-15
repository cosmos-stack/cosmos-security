/*
 * Reference to:
 *     https://github.com/toolgood/RCX/blob/master/ToolGood.RcxTest/ToolGood.RcxCrypto/RCX.cs
 *     Author: ToolGood
 *     GitHub: https://github.com/toolgood
 */


using System;
using System.Text;
using Cosmos.Encryption.Abstractions;
using Cosmos.Optionals;

// ReSharper disable once CheckNamespace
namespace Cosmos.Encryption {
    /// <summary>
    /// Three RCX encryption provider
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public sealed class ThreeRCYEncryptionProvider : ISymmetricEncryption {
        private ThreeRCYEncryptionProvider() { }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="encoding"></param>
        /// <param name="order"></param>
        /// <returns></returns>
        public static string Encrypt(string data, string key, Encoding encoding = null, RCYOrder order = RCYOrder.DESC) {
            encoding = encoding.SafeValue();
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
        public static string Encrypt(byte[] data, string key, Encoding encoding = null, RCYOrder order = RCYOrder.DESC) {
            return Convert.ToBase64String(EncryptCore(data, encoding.SafeValue().GetBytes(key), order));
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="order"></param>
        /// <returns></returns>
        public static byte[] Encrypt(byte[] data, byte[] key, RCYOrder order = RCYOrder.DESC) {
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
        public static string Decrypt(string data, string key, Encoding encoding = null, RCYOrder order = RCYOrder.DESC) {
            encoding = encoding.SafeValue();
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
        public static byte[] Decrypt(byte[] data, byte[] key, RCYOrder order = RCYOrder.DESC) {
            return EncryptCore(data, key, order);
        }

        private static byte[] EncryptCore(byte[] dataBytes, byte[] keyBytes, RCYOrder order = RCYOrder.DESC) {
            var first = RCYEncryptionProvider.Encrypt(dataBytes, keyBytes, order);
            var second = RCYEncryptionProvider.Encrypt(first, keyBytes, order);
            return RCYEncryptionProvider.Encrypt(second, keyBytes, order);
        }
    }
}