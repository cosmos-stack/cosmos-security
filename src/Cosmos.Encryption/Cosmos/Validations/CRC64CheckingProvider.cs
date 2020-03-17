using System;
using System.IO;
using Cosmos.Validations.Core;

namespace Cosmos.Validations {
    /// <summary>
    /// CRC 32 checking provider
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public class CRC64CheckingProvider : CRCCheckingBase<ulong, long> {
        /// <summary>
        /// The size of CRC64 checksum in bytes.
        /// </summary>
        public const int Size = 8;

        /// <summary>
        /// Seed
        /// </summary>
        public const ulong Seed = 0xFFFFFFFFFFFFFFFF;

        private CRC64CheckingProvider() { }

        /// <summary>
        /// Compute
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="buf"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public static ulong Compute(CRC64Mode mode, byte[] buf, int offset = 0, int count = -1) {
            switch (mode) {
                case CRC64Mode.IsoMode:
                    return Compute<ISO_CRC64>(buf, offset, count);
                case CRC64Mode.EcmaMode:
                    return Compute<ECMA_CRC64>(buf, offset, count);
                default:
                    throw new ArgumentException("Unknown CRC64 mode.");
            }
        }

        /// <summary>
        /// Compute
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="stream"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public static ulong Compute(CRC64Mode mode, Stream stream, int count = -1) {
            switch (mode) {
                case CRC64Mode.IsoMode:
                    return Compute<ISO_CRC64>(stream, count);
                case CRC64Mode.EcmaMode:
                    return Compute<ECMA_CRC64>(stream, count);
                default:
                    throw new ArgumentException("Unknown CRC64 mode.");
            }
        }

        /// <summary>
        /// Compute
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="stream"></param>
        /// <param name="position"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public static ulong Compute(CRC64Mode mode, Stream stream, long position = -1, int count = -1) {
            switch (mode) {
                case CRC64Mode.IsoMode:
                    return Compute<ISO_CRC64>(stream, position, count);
                case CRC64Mode.EcmaMode:
                    return Compute<ECMA_CRC64>(stream, position, count);
                default:
                    throw new ArgumentException("Unknown CRC64 mode.");
            }
        }
    }
}