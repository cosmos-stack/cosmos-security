using System.Text;

namespace Cosmos.Extensions {
    internal static class EncodingExtensions {
        public static Encoding Fixed(this Encoding encoding) {
            return encoding ?? Encoding.UTF8;
        }
    }
}