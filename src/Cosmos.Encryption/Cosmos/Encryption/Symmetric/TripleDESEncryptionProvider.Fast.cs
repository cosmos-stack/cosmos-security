using System;
using System.Security.Cryptography;
using System.Text;
using Cosmos.Encryption.Abstractions;
using Cosmos.Encryption.Core;
using Cosmos.Optionals;

// ReSharper disable once CheckNamespace
namespace Cosmos.Encryption
{
    // ReSharper disable once InconsistentNaming
    public sealed partial class TripleDESEncryptionProvider : IFastSymmetricEncryption
    {
        /// <summary>
        /// Create a TripleDES key.
        /// </summary>
        /// <returns></returns>
        public static byte[] FastCreateKey()
        {
            return SymmetricAlgorithmHelper.CreateKey<TripleDES>();
        }

        /// <summary>
        /// TripleDES encryption.
        /// </summary>
        /// <param name="source"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] FastEncrypt(ArraySegment<byte> source, byte[] key)
        {
            return SymmetricAlgorithmHelper.Encrypt<TripleDES>(source, key);
        }

        /// <summary>
        /// TripleDES decryption.
        /// </summary>
        /// <param name="source"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] FastDecrypt(ArraySegment<byte> source, byte[] key)
        {
            return SymmetricAlgorithmHelper.Decrypt<TripleDES>(source, key);
        }
    }
}