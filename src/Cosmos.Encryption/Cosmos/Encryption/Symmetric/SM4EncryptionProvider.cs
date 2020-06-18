using System;
using System.Text;
using Cosmos.Encryption.Abstractions;
using Cosmos.Encryption.Core;
using Cosmos.Optionals;

namespace Cosmos.Encryption.Symmetric
{
    /// <summary>
    /// SM4 encryption provider
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public sealed class SM4EncryptionProvider : ISymmetricEncryption
    {
        private SM4EncryptionProvider() { }

        /// <summary>
        /// Encrypt data by SM4-ECB
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string Encrypt(string data, string key, Encoding encoding = null)
        {
            encoding = encoding.SafeValue();
            return Convert.ToBase64String(Encrypt(encoding.GetBytes(data), encoding.GetBytes(key)));
        }

        /// <summary>
        /// Encrypt data by SM4-ECB
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string Encrypt(byte[] data, string key, Encoding encoding = null)
        {
            encoding = encoding.SafeValue();
            return Convert.ToBase64String(Encrypt(data, encoding.GetBytes(key)));
        }

        /// <summary>
        /// Encrypt data by SM4-ECB
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] Encrypt(byte[] data, byte[] key)
        {
            var ctx = new SM4Context {IsPadding = true, Mode = SM4Core.SM4_ENCRYPT};
            var sm4 = new SM4Core();
            sm4.sm4_setkey_enc(ctx, key);
            return sm4.sm4_crypt_ecb(ctx, data);
        }

        /// <summary>
        /// Encrypt data by SM4-CBC
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string Encrypt(string data, string key, string iv, Encoding encoding = null)
        {
            encoding = encoding.SafeValue();
            return Convert.ToBase64String(Encrypt(encoding.GetBytes(data), encoding.GetBytes(key), encoding.GetBytes(iv)));
        }

        /// <summary>
        /// Encrypt data by SM4-CBC
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string Encrypt(byte[] data, string key, string iv, Encoding encoding = null)
        {
            encoding = encoding.SafeValue();
            return Convert.ToBase64String(Encrypt(data, encoding.GetBytes(key), encoding.GetBytes(iv)));
        }

        /// <summary>
        /// Encrypt data by SM4-CBC
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public static byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
        {
            var ctx = new SM4Context {IsPadding = true, Mode = SM4Core.SM4_ENCRYPT};
            var sm4 = new SM4Core();
            sm4.sm4_setkey_enc(ctx, key);
            return sm4.sm4_crypt_cbc(ctx, iv, data);
        }

        /// <summary>
        /// Decrypt data by SM4-ECB
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string Decrypt(string data, string key, Encoding encoding = null)
        {
            encoding = encoding.SafeValue();
            return encoding.GetString(Decrypt(Convert.FromBase64String(data), encoding.GetBytes(key)));
        }

        /// <summary>
        /// Decrypt data by SM4-ECB
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string Decrypt(byte[] data, string key, Encoding encoding = null)
        {
            encoding = encoding.SafeValue();
            return encoding.GetString(Decrypt(data, encoding.GetBytes(key)));
        }

        /// <summary>
        /// Decrypt data by SM4-ECB
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] Decrypt(byte[] data, byte[] key)
        {
            var ctx = new SM4Context {IsPadding = true, Mode = SM4Core.SM4_DECRYPT};
            var sm4 = new SM4Core();
            sm4.sm4_setkey_dec(ctx, key);
            return sm4.sm4_crypt_ecb(ctx, data);
        }

        /// <summary>
        /// Decrypt data by SM4-CBC
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string Decrypt(string data, string key, string iv, Encoding encoding = null)
        {
            encoding = encoding.SafeValue();
            return encoding.GetString(Decrypt(Convert.FromBase64String(data), encoding.GetBytes(key), encoding.GetBytes(iv)));
        }

        /// <summary>
        /// Decrypt data by SM4-CBC
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string Decrypt(byte[] data, string key, string iv, Encoding encoding = null)
        {
            encoding = encoding.SafeValue();
            return encoding.GetString(Decrypt(data, encoding.GetBytes(key), encoding.GetBytes(iv)));
        }

        /// <summary>
        /// Decrypt data by SM4-CBC
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public static byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            var ctx = new SM4Context {IsPadding = true, Mode = SM4Core.SM4_DECRYPT};
            var sm4 = new SM4Core();
            sm4.sm4_setkey_dec(ctx, key);
            return sm4.sm4_crypt_cbc(ctx, iv, data);
        }
    }
}