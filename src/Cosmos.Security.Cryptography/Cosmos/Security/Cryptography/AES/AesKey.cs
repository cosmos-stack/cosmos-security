using System;
using System.Text;
using Cosmos.Optionals;
using Cosmos.Security.Cryptography.Core.SymmetricAlgorithmImpls;

// ReSharper disable CheckNamespace
// ReSharper disable InconsistentNaming

namespace Cosmos.Security.Cryptography
{
    /// <summary>
    /// Aes key
    /// </summary>
    public sealed class AesKey : ISymmetricCryptoKeyWithInitializationVector
    {
        public AesKey(AesTypes type, string pwd, string iv, Encoding encoding = null)
        {
            encoding = encoding.SafeEncodingValue();
            Size = (int) type;
            Key = encoding.SafeEncodingValue().GetBytes(pwd);
            IV = encoding.SafeEncodingValue().GetBytes(iv);
        }

        public AesKey(AesTypes type, byte[] pwd, byte[] iv)
        {
            Size = (int) type;
            Key = CloneBytes(ref pwd);
            IV = CloneBytes(ref iv);
        }

        /// <summary>
        /// Des key
        /// </summary>
        public byte[] Key { get; }

        /// <summary>
        /// Des IV
        /// </summary>
        public byte[] IV { get; }

        /// <summary>
        /// Size of Key
        /// </summary>
        public int Size { get; }

        internal byte[] GetKey()
        {
            return SymmetricKeyHelper.ComputeRealValue(Key, null, Size);
        }

        internal byte[] GetKey(byte[] saltBytes)
        {
            var finalSaltBytes = CloneBytes(ref saltBytes);
            return SymmetricKeyHelper.ComputeRealValue(Key, finalSaltBytes, Size);
        }

        internal byte[] GetKey(string salt, Encoding encoding)
        {
            var finalSaltBytes = string.IsNullOrWhiteSpace(salt)
                ? new byte[0]
                : encoding.SafeEncodingValue().GetBytes(salt);
            return SymmetricKeyHelper.ComputeRealValue(Key, finalSaltBytes, Size);
        }

        internal byte[] GetIV()
        {
            return SymmetricKeyHelper.ComputeRealValue(IV, null, 128);
        }

        internal byte[] GetIV(byte[] saltBytes)
        {
            var finalSaltBytes = CloneBytes(ref saltBytes);
            return SymmetricKeyHelper.ComputeRealValue(IV, finalSaltBytes, 128);
        }

        internal byte[] GetIV(string salt, Encoding encoding)
        {
            var finalSaltBytes = string.IsNullOrWhiteSpace(salt)
                ? new byte[0]
                : encoding.SafeEncodingValue().GetBytes(salt);
            return SymmetricKeyHelper.ComputeRealValue(IV, finalSaltBytes, 128);
        }

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