using System;
using System.Text;
using Cosmos.Encryption.Abstractions;
using Cosmos.Encryption.Core.Internals;

namespace Cosmos.Encryption.Symmetric
{
    // ReSharper disable once InconsistentNaming
    public sealed class TEAEncryptionProvider : ISymmetricEncyption
    {
        private TEAEncryptionProvider() { }

        public static string GenerateTeaKey() => TeaCore.GenerateTeaKey();

        public static string Encrypt(string data, string key, Encoding encoding = null)
        {
            if (string.IsNullOrWhiteSpace(data))
                return string.Empty;

            encoding = EncodingHelper.Fixed(encoding);
            return Convert.ToBase64String(Encrypt(encoding.GetBytes(data), encoding.GetBytes(key)));
        }

        public static string Encrypt(byte[] data, string key, Encoding encoding = null)
        {
            if (data.Length == 0)
                return string.Empty;

            encoding = EncodingHelper.Fixed(encoding);
            return Convert.ToBase64String(Encrypt(data, encoding.GetBytes(key)));
        }

        public static byte[] Encrypt(byte[] data, byte[] key)
        {
            if (data.Length == 0)
                return data;

            var v = TeaCore.StrConvert.StrToLongs(data, 0, 0);
            var k = TeaCore.StrConvert.StrToLongs(FixKey(key), 0, 16);

            return TeaCore.EncryptBlock(v, k);
        }

        public static string Decrypt(string data, string key, Encoding encoding = null)
        {
            if (string.IsNullOrWhiteSpace(data))
                return string.Empty;

            encoding = EncodingHelper.Fixed(encoding);
            return encoding.GetString(Decrypt(Convert.FromBase64String(data), encoding.GetBytes(key))).TrimEnd('\0');
        }

        public static string Decrypt(byte[] data, string key, Encoding encoding = null)
        {
            if (data.Length == 0)
                return string.Empty;

            encoding = EncodingHelper.Fixed(encoding);
            return encoding.GetString(Decrypt(data, encoding.GetBytes(key))).TrimEnd('\0');
        }

        public static byte[] Decrypt(byte[] data, byte[] key)
        {
            if (data.Length == 0)
                return data;

            var v = TeaCore.StrConvert.StrToLongs(data, 0, 0);
            var k = TeaCore.StrConvert.StrToLongs(FixKey(key), 0, 16);

            return TeaCore.DecryptBlock(v, k);
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
