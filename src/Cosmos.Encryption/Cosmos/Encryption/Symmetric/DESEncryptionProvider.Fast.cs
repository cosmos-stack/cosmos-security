using System;
using System.Security.Cryptography;
using Cosmos.Encryption.Abstractions;
using Cosmos.Encryption.Core;

// ReSharper disable once CheckNamespace
namespace Cosmos.Encryption
{
    // ReSharper disable once InconsistentNaming
    public sealed partial class DESEncryptionProvider : IFastSymmetricEncryption
    {
        /// <summary>
        /// Create a DES key.
        /// </summary>
        /// <returns></returns>
        public static byte[] FastCreateKey()
        {
            return SymmetricAlgorithmHelper.CreateKey<DES>();
        }

        /// <summary>
        /// DES encryption.
        /// </summary>
        /// <param name="source"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] FastEncrypt(ArraySegment<byte> source, byte[] key)
        {
            return SymmetricAlgorithmHelper.Encrypt<DES>(source, key);
        }

        /// <summary>
        /// DES decryption.
        /// </summary>
        /// <param name="source"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] FastDecrypt(ArraySegment<byte> source, byte[] key)
        {
            return SymmetricAlgorithmHelper.Decrypt<DES>(source, key);
        }
    }
}