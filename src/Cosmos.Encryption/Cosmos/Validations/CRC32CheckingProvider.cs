using System.IO;
using Cosmos.Validations.Core;

namespace Cosmos.Validations {
    /// <summary>
    /// CRC 32 checking provider
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public sealed class CRC32CheckingProvider : CRCCheckingBase<uint, int> {
        /// <summary>
        /// Seed
        /// </summary>
        public const uint Seed = 0xFFFFFFFF;

        private CRC32CheckingProvider() { }

        /// <summary>
        /// Compute
        /// </summary>
        /// <param name="buf"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public static uint Compute(byte[] buf, int offset = 0, int count = -1) {
            return Compute<CRC32>(buf, offset, count);
        }

        /// <summary>
        /// Compute
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public static uint Compute(Stream stream, int count = -1) {
            return Compute<CRC32>(stream, count);
        }

        /// <summary>
        /// Compute
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="position"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public static uint Compute(Stream stream, long position = -1, int count = -1) {
            return Compute<CRC32>(stream, position, count);
        }
    }
}