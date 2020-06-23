using System.Text;
using Cosmos.Encryption;

namespace Cosmos.Extensions
{
    /// <summary>
    /// Extensions for encryption
    /// </summary>
    public static partial class Extensions
    {
        /// <summary>
        /// To SM3
        /// </summary>
        /// <param name="data"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        // ReSharper disable once InconsistentNaming
        public static string ToSM3(this string data, Encoding encoding = null) => SM3HashingProvider.Signature(data, encoding);
    }
}