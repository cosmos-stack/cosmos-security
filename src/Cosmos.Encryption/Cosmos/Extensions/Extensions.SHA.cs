using System;
using System.Text;
using Cosmos.Encryption;
using Cosmos.Encryption.Core.Internals.Extensions;

namespace Cosmos.Extensions {
    public static partial class Extensions {
        /// <summary>
        /// To SHA1
        /// </summary>
        /// <param name="data"></param>
        /// <param name="isUpper"></param>
        /// <param name="isIncludeHyphen"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        // ReSharper disable once InconsistentNaming
        public static string ToSHA1(this string data, bool isUpper = true, bool isIncludeHyphen = false, Encoding encoding = null) {
            return SHA1HashingProvider.Signature(data, isUpper, isIncludeHyphen, encoding);
        }

        /// <summary>
        /// To SHA1
        /// </summary>
        /// <param name="data"></param>
        /// <param name="isUpper"></param>
        /// <param name="isIncludeHyphen"></param>
        /// <returns></returns>
        // ReSharper disable once InconsistentNaming
        public static string ToSHA1(this byte[] data, bool isUpper = true, bool isIncludeHyphen = false) {
            var hashBytes = SHA1HashingProvider.Signature(data);
            var str = BitConverter.ToString(hashBytes);
            return str.ToFixUpperCase(isUpper).ToFixHyphenChar(isIncludeHyphen);
        }

        /// <summary>
        /// To SHA256
        /// </summary>
        /// <param name="data"></param>
        /// <param name="isUpper"></param>
        /// <param name="isIncludeHyphen"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        // ReSharper disable once InconsistentNaming
        public static string ToSHA256(this string data, bool isUpper = true, bool isIncludeHyphen = false, Encoding encoding = null) {
            return SHA256HashingProvider.Signature(data, isUpper, isIncludeHyphen, encoding);
        }

        /// <summary>
        /// To SHA256
        /// </summary>
        /// <param name="data"></param>
        /// <param name="isUpper"></param>
        /// <param name="isIncludeHyphen"></param>
        /// <returns></returns>
        // ReSharper disable once InconsistentNaming
        public static string ToSHA256(this byte[] data, bool isUpper = true, bool isIncludeHyphen = false) {
            var hashBytes = SHA256HashingProvider.Signature(data);
            var str = BitConverter.ToString(hashBytes);
            return str.ToFixUpperCase(isUpper).ToFixHyphenChar(isIncludeHyphen);
        }

        /// <summary>
        /// To SHA384
        /// </summary>
        /// <param name="data"></param>
        /// <param name="isUpper"></param>
        /// <param name="isIncludeHyphen"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        // ReSharper disable once InconsistentNaming
        public static string ToSHA384(this string data, bool isUpper = true, bool isIncludeHyphen = false, Encoding encoding = null) {
            return SHA384HashingProvider.Signature(data, isUpper, isIncludeHyphen, encoding);
        }

        /// <summary>
        /// To SHA384
        /// </summary>
        /// <param name="data"></param>
        /// <param name="isUpper"></param>
        /// <param name="isIncludeHyphen"></param>
        /// <returns></returns>
        // ReSharper disable once InconsistentNaming
        public static string ToSHA384(this byte[] data, bool isUpper = true, bool isIncludeHyphen = false) {
            var hashBytes = SHA384HashingProvider.Signature(data);
            var str = BitConverter.ToString(hashBytes);
            return str.ToFixUpperCase(isUpper).ToFixHyphenChar(isIncludeHyphen);
        }

        /// <summary>
        /// To SHA512
        /// </summary>
        /// <param name="data"></param>
        /// <param name="isUpper"></param>
        /// <param name="isIncludeHyphen"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        // ReSharper disable once InconsistentNaming
        public static string ToSHA512(this string data, bool isUpper = true, bool isIncludeHyphen = false, Encoding encoding = null) {
            return SHA512HashingProvider.Signature(data, isUpper, isIncludeHyphen, encoding);
        }

        /// <summary>
        /// To SHA512
        /// </summary>
        /// <param name="data"></param>
        /// <param name="isUpper"></param>
        /// <param name="isIncludeHyphen"></param>
        /// <returns></returns>
        // ReSharper disable once InconsistentNaming
        public static string ToSHA512(this byte[] data, bool isUpper = true, bool isIncludeHyphen = false) {
            var hashBytes = SHA512HashingProvider.Signature(data);
            var str = BitConverter.ToString(hashBytes);
            return str.ToFixUpperCase(isUpper).ToFixHyphenChar(isIncludeHyphen);
        }
    }
}