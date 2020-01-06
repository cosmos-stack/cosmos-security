using System.Security.Cryptography;
using System.Text;
using Cosmos.Encryption.Core.Internals.Extensions;
using Cosmos.Internals;

// ReSharper disable once CheckNamespace
namespace Cosmos.Encryption {
    /// <summary>
    /// MD4 Hashing provider
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static class MD4HashingProvider {
        /// <summary>
        /// MD4 hashing method
        /// </summary>
        /// <param name="data">The string need to hash.</param>
        /// <param name="encoding">The <see cref="T:System.Text.Encoding"/>,default is Encoding.UTF8.</param>
        /// <returns>Hashed string.</returns>
        public static string Signature(string data, Encoding encoding = null) {
            return SignatureHash(data, encoding).ToHexString();
        }

        /// <summary>
        /// MD4 hashing method
        /// </summary>
        /// <param name="data">The data need to hash.</param>
        /// <returns>Hashed string.</returns>
        public static string Signature(byte[] data) {
            return Core(data).ToHexString();
        }

        /// <summary>
        /// MD4 hashing method
        /// </summary>
        /// <param name="data">The string need to hash.</param>
        /// <param name="encoding">The <see cref="T:System.Text.Encoding"/>,default is Encoding.UTF8.</param>
        /// <returns>Hashed string.</returns>
        public static byte[] SignatureHash(string data, Encoding encoding = null) {
            encoding = EncodingHelper.Fixed(encoding);
            return Core(encoding.GetBytes(data));
        }

        /// <summary>
        /// MD4 hashing method
        /// </summary>
        /// <param name="data">The data need to hash.</param>
        /// <returns>Hashed string.</returns>
        public static byte[] SignatureHash(byte[] data) {
            return Core(data);
        }

        private static byte[] Core(byte[] buffer) {
            using var md4 = new MD4CryptoServiceProvider();
            return md4.ComputeHash(buffer);
        }

        /// <summary>
        /// Verify 
        /// </summary>
        /// <param name="comparison"></param>
        /// <param name="data">The string of encrypt.</param>
        /// <param name="encoding">The <see cref="T:System.Text.Encoding"/>,default is Encoding.UTF8.</param>
        /// <returns></returns>
        public static bool Verify(string comparison, string data, Encoding encoding = null)
            => comparison == Signature(data, encoding);
    }
}