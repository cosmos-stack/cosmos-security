namespace Cosmos.Encryption.Core.Internals.Extensions {
    internal static class StringExtensions {
        public static string ReplaceToEmpty(this string str, string oldValue) {
            return str.Replace(oldValue, "");
        }

        public static string ToFixUpperCase(this string origin, bool isUpper) {
            return isUpper ? origin.ToUpper() : origin.ToLower();
        }

        public static string ToFixHyphenChar(this string origin, bool isIncludeHyphen) {
            return isIncludeHyphen ? origin : origin.Replace("-", "");
        }
    }
}