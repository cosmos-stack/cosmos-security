using System;
using System.Text;
using Cosmos.Optionals;
using Cosmos.Security.Cryptography.Core.SymmetricAlgorithmImpls;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Cryptography
{
    public sealed class Sm4Key : ISymmetricCryptoKeyWithInitializationVector
    {
        /// <summary>
        /// Create a new SmKey instance for SM4 with ECB Mode.
        /// </summary>
        /// <param name="pwd"></param>
        /// <param name="encoding"></param>
        public Sm4Key(string pwd, Encoding encoding = null)
        {
            Key = encoding.SafeEncodingValue().GetBytes(pwd);
            IV = new byte[0];
        }

        /// <summary>
        /// Create a new SmKey instance for SM4 with ECB Mode.
        /// </summary>
        /// <param name="pwd"></param>
        public Sm4Key(byte[] pwd)
        {
            Key = CloneBytes(ref pwd);
            IV = new byte[0];
        }

        /// <summary>
        /// Create a new SmKey instance for SM4 with CBC Mode.
        /// </summary>
        /// <param name="pwd"></param>
        /// <param name="iv"></param>
        /// <param name="encoding"></param>
        public Sm4Key(string pwd, string iv, Encoding encoding = null)
        {
            encoding = encoding.SafeEncodingValue();
            Key = encoding.GetBytes(pwd);
            IV = string.IsNullOrWhiteSpace(iv) ? new byte[0] : encoding.GetBytes(iv);
        }

        /// <summary>
        /// Create a new SmKey instance for SM4 with CBC Mode.
        /// </summary>
        /// <param name="pwd"></param>
        /// <param name="iv"></param>
        public Sm4Key(byte[] pwd, byte[] iv)
        {
            Key = CloneBytes(ref pwd);
            IV = CloneBytes(ref iv);
        }

        /// <summary>
        /// SM4 key
        /// </summary>
        public byte[] Key { get; }

        /// <summary>
        /// SM4 IV
        /// </summary>
        public byte[] IV { get; }

        /// <summary>
        /// Size of Key
        /// </summary>
        public int Size => 16;

        internal byte[] GetKey()
        {
            return SymmetricKeyHelper.ComputeRealValue(Key, null, 128);
        }

        internal byte[] GetIV()
        {
            if (IV == null || IV.Length == 0)
                return new byte[0];

            var iv = new byte[IV.Length];
            Array.Copy(IV, 0, iv, 0, IV.Length);
            return iv;
        }

        private static byte[] CloneBytes(ref byte[] data)
        {
            if (data == null || data.Length == 0)
                return new byte[0];
            var ret = new byte[data.Length];
            Array.Copy(data, 0, ret, 0, data.Length);
            return ret;
        }
    }
}