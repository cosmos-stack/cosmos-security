/*
 * Reference to:
 *      https://www.2cto.com/kf/201603/496248.html
 */

namespace Cosmos.Encryption.Core
{
    /// <summary>
    /// SM4 Context
    /// </summary>
    // ReSharper disable InconsistentNaming
    public class SM4Context
    {
        /// <summary>
        /// Mode
        /// </summary>
        public int Mode { get; set; }

        /// <summary>
        /// SK
        /// </summary>
        public long[] SK { get; }

        /// <summary>
        /// Is padding
        /// </summary>
        public bool IsPadding { get; set; }

        /// <summary>
        /// SM4 Context
        /// </summary>
        public SM4Context()
        {
            Mode = 1;
            IsPadding = true;
            SK = new long[32];
        }
    }
}
