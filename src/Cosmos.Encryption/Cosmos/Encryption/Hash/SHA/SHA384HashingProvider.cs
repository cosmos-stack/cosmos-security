using System.Security.Cryptography;
using System.Text;
using Cosmos.Encryption.Core;
using Cosmos.Encryption.Core.Internals.Extensions;

// ReSharper disable once CheckNamespace
namespace Cosmos.Encryption
{
    /// <summary>
    /// Hash/SHA384 hashing provider.
    /// Reference: Seay Xu
    ///     https://github.com/godsharp/GodSharp.Encryption/blob/master/src/GodSharp.Shared/Encryption/Hash/SHA/SHA384.cs
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public sealed class SHA384HashingProvider : SHAHashingBase
    {
        private SHA384HashingProvider() { }

        /// <summary>
        /// SHA384 encrypt method
        /// </summary>
        /// <param name="data">The string to be encrypted,not null.</param>
        /// <param name="isIncludeHyphen"></param>
        /// <param name="encoding">The <see cref="T:System.Text.Encoding"/>,default is Encoding.UTF8.</param>
        /// <param name="isUpper"></param>
        /// <returns>The encrypted string.</returns>
        public static string Signature(string data, bool isUpper = true, bool isIncludeHyphen = false, Encoding encoding = null)
            => Encrypt<SHA384CryptoServiceProvider>(data, encoding).ToFixUpperCase(isUpper).ToFixHyphenChar(isIncludeHyphen);

        /// <summary>
        /// SHA384 hashing method
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] Signature(byte[] data)
            => Encrypt<SHA384CryptoServiceProvider>(data);

        /// <summary>
        /// Verify 
        /// </summary>
        /// <param name="comparison"></param>
        /// <param name="data">The string to be encrypted,not null.</param>
        /// <param name="isIncludeHyphen"></param>
        /// <param name="encoding">The <see cref="T:System.Text.Encoding"/>,default is Encoding.UTF8.</param>
        /// <param name="isUpper"></param>
        /// <returns></returns>
        public static bool Verify(string comparison, string data, bool isUpper = true, bool isIncludeHyphen = false, Encoding encoding = null)
            => comparison == Signature(data, isUpper, isIncludeHyphen, encoding);
    }
}