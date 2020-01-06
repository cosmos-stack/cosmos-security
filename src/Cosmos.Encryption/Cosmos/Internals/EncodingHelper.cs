using System.Text;

namespace Cosmos.Internals {
    internal static class EncodingHelper {
        public static Encoding Fixed(Encoding encoding) {
            return encoding ?? Encoding.UTF8;
        }
    }
}