using System.Text;
using Cosmos.Security.Encryption;

namespace Cosmos.Security
{
    public static partial class Extensions
    {
        /// <summary>
        /// To 16bit MD5
        /// </summary>
        /// <param name="data"></param>
        /// <param name="isUpper"></param>
        /// <param name="isIncludeHyphen"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        // ReSharper disable once InconsistentNaming
        public static string To16MD5(this string data, bool isUpper = true, bool isIncludeHyphen = false, Encoding encoding = null)
            => MD5HashingProvider.Signature(data, MD5BitTypes.L16, isUpper, isIncludeHyphen, encoding);

        /// <summary>
        /// To 32bit MD5
        /// </summary>
        /// <param name="data"></param>
        /// <param name="isUpper"></param>
        /// <param name="isIncludeHyphen"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        // ReSharper disable once InconsistentNaming
        public static string To32MD5(this string data, bool isUpper = true, bool isIncludeHyphen = false, Encoding encoding = null)
            => MD5HashingProvider.Signature(data, MD5BitTypes.L32, isUpper, isIncludeHyphen, encoding);

        /// <summary>
        /// To 64bit MD5
        /// </summary>
        /// <param name="data"></param>
        /// <param name="isUpper"></param>
        /// <param name="isIncludeHyphen"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        // ReSharper disable once InconsistentNaming
        public static string To64MD5(this string data, bool isUpper = true, bool isIncludeHyphen = false, Encoding encoding = null)
            => MD5HashingProvider.Signature(data, MD5BitTypes.L64, isUpper, isIncludeHyphen, encoding);
    }
}