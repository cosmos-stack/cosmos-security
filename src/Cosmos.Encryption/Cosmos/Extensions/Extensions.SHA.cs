using System;
using System.Text;
using Cosmos.Encryption;
using Cosmos.Encryption.Core.Internals;
using Cosmos.Encryption.Core.Internals.Extensions;

namespace Cosmos.Extensions
{
    public static partial class Extensions
    {
        public static string ToSHA1(this string data, bool isUpper = true, bool isIncludeHyphen = false, Encoding encoding = null)
        {
            return SHA1HashingProvider.Signature(data, isUpper, isIncludeHyphen, encoding);
        }

        public static string ToSHA1(this byte[] data, bool isUpper = true, bool isIncludeHyphen = false)
        {
            var hashBytes = SHA1HashingProvider.Signature(data);
            var str = BitConverter.ToString(hashBytes);
            return str.ToFixUpperCase(isUpper).ToFixHyphenChar(isIncludeHyphen);
        }

        public static string ToSHA256(this string data, bool isUpper = true, bool isIncludeHyphen = false, Encoding encoding = null)
        {
            return SHA256HashingProvider.Signature(data, isUpper, isIncludeHyphen, encoding);
        }

        public static string ToSHA256(this byte[] data, bool isUpper = true, bool isIncludeHyphen = false)
        {
            var hashBytes = SHA256HashingProvider.Signature(data);
            var str = BitConverter.ToString(hashBytes);
            return str.ToFixUpperCase(isUpper).ToFixHyphenChar(isIncludeHyphen);
        }

        public static string ToSHA384(this string data, bool isUpper = true, bool isIncludeHyphen = false, Encoding encoding = null)
        {
            return SHA384HashingProvider.Signature(data, isUpper, isIncludeHyphen, encoding);
        }

        public static string ToSHA384(this byte[] data, bool isUpper = true, bool isIncludeHyphen = false)
        {
            var hashBytes = SHA384HashingProvider.Signature(data);
            var str = BitConverter.ToString(hashBytes);
            return str.ToFixUpperCase(isUpper).ToFixHyphenChar(isIncludeHyphen);
        }

        public static string ToSHA512(this string data, bool isUpper = true, bool isIncludeHyphen = false, Encoding encoding = null)
        {
            return SHA512HashingProvider.Signature(data, isUpper, isIncludeHyphen, encoding);
        }

        public static string ToSHA512(this byte[] data, bool isUpper = true, bool isIncludeHyphen = false)
        {
            var hashBytes = SHA512HashingProvider.Signature(data);
            var str = BitConverter.ToString(hashBytes);
            return str.ToFixUpperCase(isUpper).ToFixHyphenChar(isIncludeHyphen);
        }
    }
}
