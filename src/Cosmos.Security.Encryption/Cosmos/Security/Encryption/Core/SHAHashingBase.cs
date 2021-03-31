using System;
using System.Security.Cryptography;
using System.Text;
using Cosmos.Optionals;

namespace Cosmos.Security.Encryption.Core
{
    /// <summary>
    /// Abstrace SHAHashingBase encryption.
    /// Reference: Seay Xu
    ///     https://github.com/godsharp/GodSharp.Encryption/blob/master/src/GodSharp.Shared/Encryption/Hash/SHAHashingBase/SHA.cs
    /// Editor: AlexLEWIS
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public abstract class SHAHashingBase
    {
        /// <summary>
        /// SHAHashingBase hash algorithm core.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="encoding"></param>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        protected static string Encrypt<T>(string data, Encoding encoding = null) where T : HashAlgorithm, new()
        {
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            using HashAlgorithm hash = new T();
            var bytes = hash.ComputeHash(encoding.SafeEncodingValue().GetBytes(data));

            var sbStr = new StringBuilder();
            foreach (var b in bytes)
            {
                sbStr.Append(b.ToString("X2"));
            }

            return sbStr.ToString();
        }

        /// <summary>
        /// SHAHashingBase hash algorithm core.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="data"></param>
        /// <returns></returns>
        protected static byte[] Encrypt<T>(byte[] data) where T : HashAlgorithm, new()
        {
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            using HashAlgorithm hash = new T();
            return hash.ComputeHash(data);
        }
    }
}