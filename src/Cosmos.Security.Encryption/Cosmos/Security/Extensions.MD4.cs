using System.Text;
using Cosmos.Security.Encryption;

namespace Cosmos.Security
{
    /// <summary>
    /// Extensions for encryption
    /// </summary>
    public static partial class Extensions
    {
        /// <summary>
        /// To MD4
        /// </summary>
        /// <param name="data"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        // ReSharper disable once InconsistentNaming
        public static string ToMD4(this string data, Encoding encoding = null) => MD4HashingProvider.Signature(data, encoding);

        /// <summary>
        /// To MD4
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        // ReSharper disable once InconsistentNaming
        public static byte[] ToMD4(this byte[] data) => MD4HashingProvider.SignatureHash(data);
    }
}