using System;
using System.Text;
using Cosmos.Encryption.Abstractions;
using Cosmos.Encryption.Core.Internals;

namespace Cosmos.Encryption.Symmetric
{
    public sealed class XTEAEncryptionProvider : ISymmetricEncyption
    {
        private XTEAEncryptionProvider() { }

        public static string Encrypt(string data, string key, Encoding encoding = null)
        {
            if (string.IsNullOrWhiteSpace(data))
                return string.Empty;

            if (encoding == null)
                encoding = Encoding.UTF8;

            return Convert.ToBase64String(Encrypt(encoding.GetBytes(data), encoding.GetBytes(key)));
        }


        public static string Encrypt(byte[] data, string key, Encoding encoding = null)
        {
            if (data.Length == 0)
                return string.Empty;

            if (encoding == null)
                encoding = Encoding.UTF8;

            return Convert.ToBase64String(Encrypt(data, encoding.GetBytes(key)));
        }

        public static byte[] Encrypt(byte[] data, byte[] key)
        {
            if (data.Length == 0)
                return data;

            return XTEACore.Encrypt(data, FixKey(key));
        }

        public static string Decrypt(string data, string key, Encoding encoding = null)
        {
            if (string.IsNullOrWhiteSpace(data))
                return data;

            if (encoding == null)
                encoding = Encoding.UTF8;

            return encoding.GetString(Decrypt(Convert.FromBase64String(data), encoding.GetBytes(key)));
        }

        public static string Decrypt(byte[] data, string key, Encoding encoding = null)
        {
            if (data.Length == 0)
                return string.Empty;

            if (encoding == null)
                encoding = Encoding.UTF8;

            return encoding.GetString(Decrypt(data, encoding.GetBytes(key)));
        }

        public static byte[] Decrypt(byte[] data, byte[] key)
        {
            if (data.Length == 0)
                return data;

            return XTEACore.Decrypt(data, key);
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
