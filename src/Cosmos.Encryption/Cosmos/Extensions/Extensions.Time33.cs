using System.Text;
using Cosmos.Encryption;

namespace Cosmos.Extensions
{
    public static partial class Extensions
    {
        /// <summary>
        /// To Time33 / DBJ33A
        /// </summary>
        /// <param name="data"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        // ReSharper disable once InconsistentNaming
        public static long ToTime33(this string data, Encoding encoding = null) => Time33HashingProvider.Signature(data, encoding);

        /// <summary>
        /// To Time33 / DBJ33A
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        // ReSharper disable once InconsistentNaming
        public static long ToTime33(this byte[] data) => Time33HashingProvider.Signature(data);
    }
}