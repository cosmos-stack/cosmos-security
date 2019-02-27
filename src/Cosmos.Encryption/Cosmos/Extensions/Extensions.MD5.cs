using System.Text;
using Cosmos.Encryption;

namespace Cosmos.Extensions
{
    public static partial class Extensions
    {
        public static string To16MD5(this string data, bool isUpper = true, bool isIncludeHyphen = false, Encoding encoding = null)
            => MD5HashingProvider.Signature(data, MD5BitTypes.L16, isUpper, isIncludeHyphen, encoding);


        public static string To32MD5(this string data, bool isUpper = true, bool isIncludeHyphen = false, Encoding encoding = null)
            => MD5HashingProvider.Signature(data, MD5BitTypes.L32, isUpper, isIncludeHyphen, encoding);
        
        public static string To64MD5(this string data, bool isUpper = true, bool isIncludeHyphen = false, Encoding encoding = null)
            => MD5HashingProvider.Signature(data, MD5BitTypes.L64, isUpper, isIncludeHyphen, encoding);
    }
}
