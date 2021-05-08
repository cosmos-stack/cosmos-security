using System;
using System.Text;
using Cosmos.Optionals;

// ReSharper disable CheckNamespace

namespace Cosmos.Security.Cryptography
{
    public sealed class TeaKey : ISymmetricCryptoKey
    {
        public TeaKey(string pwd, Encoding encoding = null)
        {
            encoding = encoding.SafeEncodingValue();
            Key = encoding.SafeEncodingValue().GetBytes(pwd);
        }

        public TeaKey(byte[] pwd)
        {
            Key = CloneBytes(ref pwd);
        }

        /// <summary>
        /// TEA key
        /// </summary>
        public byte[] Key { get; }

        /// <summary>
        /// Size of Key
        /// </summary>
        public int Size => 16;

        internal byte[] GetKey() => FixKey(Key);

        private static byte[] CloneBytes(ref byte[] data)
        {
            if (data == null)
                return new byte[0];

            var ret = new byte[data.Length];
            Array.Copy(data, 0, ret, 0, data.Length);
            return ret;
        }

        private static byte[] FixKey(byte[] key)
        {
            if (key.Length == 16)
                return key;

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