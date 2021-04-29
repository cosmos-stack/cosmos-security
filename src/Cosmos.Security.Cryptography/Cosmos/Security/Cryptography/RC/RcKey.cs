using System;
using System.Text;
using Cosmos.Optionals;

// ReSharper disable CheckNamespace

namespace Cosmos.Security.Cryptography
{
    public sealed class RcKey : ISymmetricCryptoKey
    {
        public RcKey(string pwd, Encoding encoding = null)
        {
            encoding = encoding.SafeEncodingValue();
            Key = encoding.SafeEncodingValue().GetBytes(pwd);
        }

        public RcKey(byte[] pwd)
        {
            Key = CloneBytes(ref pwd);
        }

        /// <summary>
        /// Des key
        /// </summary>
        public byte[] Key { get; }

        /// <summary>
        /// Size of Key
        /// </summary>
        public int Size => 256;

        internal byte[] GetKey() => Key;

        private static byte[] CloneBytes(ref byte[] data)
        {
            if (data == null)
                return new byte[0];
            var ret = new byte[data.Length];
            Array.Copy(data, 0, ret, 0, data.Length);
            return ret;
        }
    }
}