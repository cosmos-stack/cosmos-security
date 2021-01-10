using System;
using System.Security.Cryptography;
using Cosmos.Encryption.Abstractions;
using Cosmos.Encryption.Core;

// ReSharper disable once CheckNamespace
namespace Cosmos.Encryption
{
    // ReSharper disable once InconsistentNaming
    public sealed partial class AESEncryptionProvider : IFastSymmetricEncryption
    {
        /// <summary>
        /// Create an AES key.
        /// </summary>
        /// <returns></returns>
        public static byte[] FastCreateKey()
        {
            return SymmetricAlgorithmHelper.CreateKey<Aes>();
        }

        /// <summary>
        /// AES encryption.
        /// </summary>
        /// <param name="source"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] FastEncrypt(ArraySegment<byte> source, byte[] key)
        {
            return SymmetricAlgorithmHelper.Encrypt<Aes>(source, key);
        }

        /// <summary>
        /// AES decryption.
        /// </summary>
        /// <param name="source"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] FastDecrypt(ArraySegment<byte> source, byte[] key)
        {
            return SymmetricAlgorithmHelper.Decrypt<Aes>(source, key);
        }
    }
}