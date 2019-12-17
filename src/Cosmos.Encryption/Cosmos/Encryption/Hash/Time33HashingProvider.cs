using System.Text;
using Cosmos.Encryption.Core.Internals;

// ReSharper disable once CheckNamespace
namespace Cosmos.Encryption {
    /// <summary>
    /// Time33  / DBJ33A hashing provider
    /// Reference to:
    ///     http://www.nowamagic.net/academy/detail/3008097
    ///     https://www.cnblogs.com/52fhy/p/5007456.html
    /// </summary>
    public static class Time33HashingProvider {
        /// <summary>
        /// Signature
        /// </summary>
        /// <param name="data">The string you want to hash.</param>
        /// <param name="encoding">The <see cref="T:System.Text.Encoding"/>,default is Encoding.UTF8.</param>
        /// <returns></returns>
        public static long Signature(string data, Encoding encoding = null) {
            Checker.Data(data);

            encoding = EncodingHelper.Fixed(encoding);

            var bytes = encoding.GetBytes(data);

            return Signature(bytes);
        }
        
        /// <summary>
        /// Signature
        /// </summary>
        /// <param name="data">The data need to hash.</param>
        /// <returns></returns>
        public static long Signature(byte[] data) {
            Checker.Buffer(data);

            long hash = 5381;
            for (int i = 0, len = data.Length; i < len; ++i) {
                hash += (hash << 5) + data[i];
            }

            hash &= 0x7fffffff;

            return hash;
        }

        /// <summary>
        /// Verify 
        /// </summary>
        /// <param name="comparison"></param>
        /// <param name="data">The string of encrypt.</param>
        /// <param name="encoding">The <see cref="T:System.Text.Encoding"/>,default is Encoding.UTF8.</param>
        /// <returns></returns>
        public static bool Verify(long comparison, string data, Encoding encoding = null)
            => comparison == Signature(data, encoding);
    }
}