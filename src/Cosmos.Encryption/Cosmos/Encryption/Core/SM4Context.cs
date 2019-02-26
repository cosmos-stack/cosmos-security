/*
 * Reference to:
 *      https://www.2cto.com/kf/201603/496248.html
 */

namespace Cosmos.Encryption.Core
{
    // ReSharper disable InconsistentNaming
    public class SM4Context
    {
        public int Mode { get; set; }

        public long[] SK { get; }

        public bool IsPadding { get; set; }

        public SM4Context()
        {
            Mode = 1;
            IsPadding = true;
            SK = new long[32];
        }
    }
}
