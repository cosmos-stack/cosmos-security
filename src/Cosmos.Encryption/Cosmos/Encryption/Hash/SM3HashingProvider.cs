using System;
using System.Text;
using Cosmos.Encryption.Core;
using Cosmos.Encryption.Core.Internals;
using Cosmos.Internals;

// ReSharper disable once CheckNamespace
namespace Cosmos.Encryption {
    /// <summary>
    /// SM3 hashing provider
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static class SM3HashingProvider {
        /// <summary>
        /// SM3 hashing method.
        /// </summary>
        /// <param name="data">The string need to hash.</param>
        /// <param name="encoding">The <see cref="T:System.Text.Encoding"/>,default is Encoding.UTF8.</param>
        /// <returns>Hashed string.</returns>
        public static string Signature(string data, Encoding encoding = null) {
            encoding = EncodingHelper.Fixed(encoding);
            var sm3 = SM3Core.Create("SM3");
            var hashBytes = sm3.ComputeHash(encoding.GetBytes(data));
            return Convert.ToBase64String(hashBytes);
        }

        /// <summary>
        /// Verify 
        /// </summary>
        /// <param name="comparison"></param>
        /// <param name="data">The string need to hash.</param>
        /// <param name="encoding">The <see cref="T:System.Text.Encoding"/>,default is Encoding.UTF8.</param>
        /// <returns></returns>
        public static bool Verify(string comparison, string data, Encoding encoding = null)
            => comparison == Signature(data, encoding);
    }
}