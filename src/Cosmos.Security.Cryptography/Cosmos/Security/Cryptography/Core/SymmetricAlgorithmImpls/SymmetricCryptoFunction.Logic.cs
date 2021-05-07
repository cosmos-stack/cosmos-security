using System;
using System.IO;
using System.Security.Cryptography;

namespace Cosmos.Security.Cryptography.Core.SymmetricAlgorithmImpls
{
    internal abstract class LogicSymmetricCryptoFunction<TKey> : SymmetricCryptoFunctionWithSalt<TKey>
    {
        /// <summary>
        /// Nice encryption code
        /// </summary>
        /// <typeparam name="TCryptoServiceProvider"></typeparam>
        /// <param name="sourceBytes"></param>
        /// <param name="count"></param>
        /// <param name="offset"></param>
        /// <param name="keyBytes"></param>
        /// <param name="ivBytes"></param>
        /// <returns></returns>
        protected static byte[] EncryptCore<TCryptoServiceProvider>(byte[] sourceBytes, int offset, int count, byte[] keyBytes, byte[] ivBytes)
            where TCryptoServiceProvider : SymmetricAlgorithm, new()
        {
            using var provider = new TCryptoServiceProvider {Key = keyBytes, IV = ivBytes};
            
            using var ms = new MemoryStream();
            using var cs = new CryptoStream(ms, provider.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(sourceBytes, offset, count);
            cs.FlushFinalBlock();

            return ms.ToArray();
        }

        /// <summary>
        /// Nice encryption code
        /// </summary>
        /// <typeparam name="TCryptoServiceProvider"></typeparam>
        /// <param name="originalBytes"></param>
        /// <param name="keyBytes"></param>
        /// <param name="ivBytes"></param>
        /// <returns></returns>
        protected static byte[] EncryptCore<TCryptoServiceProvider>(ArraySegment<byte> originalBytes, byte[] keyBytes, byte[] ivBytes)
            where TCryptoServiceProvider : SymmetricAlgorithm, new()
        {
            using var provider = new TCryptoServiceProvider {Key = keyBytes, IV = ivBytes};

            using var ms = new MemoryStream();
            using var cs = new CryptoStream(ms, provider.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(originalBytes.Array!, originalBytes.Offset, originalBytes.Count);
            cs.FlushFinalBlock();

            return ms.ToArray();
        }

        /// <summary>
        /// Nice decryption core
        /// </summary>
        /// <typeparam name="TCryptoServiceProvider"></typeparam>
        /// <param name="encryptBytes"></param>
        /// <param name="count"></param>
        /// <param name="offset"></param>
        /// <param name="keyBytes"></param>
        /// <param name="ivBytes"></param>
        /// <returns></returns>
        protected static byte[] DecryptCore<TCryptoServiceProvider>(byte[] encryptBytes, int offset, int count, byte[] keyBytes, byte[] ivBytes)
            where TCryptoServiceProvider : SymmetricAlgorithm, new()
        {
            using var provider = new TCryptoServiceProvider {Key = keyBytes, IV = ivBytes};

            using var ms = new MemoryStream();
            using var cs = new CryptoStream(ms, provider.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(encryptBytes, offset, count);
            cs.FlushFinalBlock();

            return ms.ToArray();
        }

        /// <summary>
        /// Nice decryption core
        /// </summary>
        /// <typeparam name="TCryptoServiceProvider"></typeparam>
        /// <param name="encryptBytes"></param>
        /// <param name="keyBytes"></param>
        /// <param name="ivBytes"></param>
        /// <returns></returns>
        protected static byte[] DecryptCore<TCryptoServiceProvider>(ArraySegment<byte> encryptBytes, byte[] keyBytes, byte[] ivBytes)
            where TCryptoServiceProvider : SymmetricAlgorithm, new()
        {
            using var provider = new TCryptoServiceProvider {Key = keyBytes, IV = ivBytes};

            using var ms = new MemoryStream();
            using var cs = new CryptoStream(ms, provider.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(encryptBytes.Array!, encryptBytes.Offset, encryptBytes.Count);
            cs.FlushFinalBlock();

            return ms.ToArray();
        }
    }
}