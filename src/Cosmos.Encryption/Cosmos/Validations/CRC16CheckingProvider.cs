using System.IO;
using Cosmos.Validations.Core;

namespace Cosmos.Validations {
    /// CRC16 checking provider
    /// Author: X-New-Life
    ///     https://github.com/NewLifeX/X/blob/master/NewLife.Core/Security/Crc16.cs
    // ReSharper disable once InconsistentNaming
    public sealed class CRC16CheckingProvider : CRCCheckingBase<ushort, short> {
        /// <summary>
        /// Seed
        /// </summary>
        public const ushort Seed = 0xFFFF;

        private CRC16CheckingProvider() { }

        /// <summary>
        /// Compute
        /// </summary>
        /// <param name="buf"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public static ushort Compute(byte[] buf, int offset = 0, int count = -1) {
            return Compute<CRC16>(buf, offset, count);
        }

        /// <summary>
        /// Compute
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public static ushort Compute(Stream stream, int count = -1) {
            return Compute<CRC16>(stream, count);
        }

        /// <summary>
        /// Compute
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="position"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public static ushort Compute(Stream stream, long position = -1, int count = -1) {
            return Compute<CRC16>(stream, position, count);
        }
    }
}