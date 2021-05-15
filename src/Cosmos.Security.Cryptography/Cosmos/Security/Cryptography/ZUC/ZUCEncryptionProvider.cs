using System;
using Cosmos.Security.Encryption.Core;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Encryption
{
    /// <summary>
    /// ZUC encryption provider. BUG: THERE ARE SEVERAL BUG HERE, DO NOT USE THIS PROVIDER NOW!
    /// </summary>
    // ReSharper disable once InconsistentNaming
    internal static class ZUCEncryptionProvider
    {
        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public static byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
        {
            var zuc = new ZUCCore(FixKey(key), FixKey(iv));
            var v = new byte[data.Length];
            Array.Copy(data, 0, v, 0, data.Length);
            zuc.GenerateKeyStream(ZUCCore.Utils.StrToLongs(v, 0, 0), v.Length);
            return v;
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public static byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            var zuc = new ZUCCore(FixKey(key), FixKey(iv));
            var v = new byte[data.Length];
            Array.Copy(data, 0, v, 0, data.Length);
            zuc.GenerateKeyStream(ZUCCore.Utils.StrToLongs(v, 0, 0), v.Length);
            return v;
        }

        private static byte[] FixKey(byte[] key)
        {
            if (key.Length == 16) return key;
            byte[] fixedKey = new byte[16];
            if (key.Length < 16)
            {
                key.CopyTo(fixedKey, 0);
            }
            else
            {
                Array.Copy(key, 0, fixedKey, 0, 16);
            }

            return fixedKey;
        }
    }
}