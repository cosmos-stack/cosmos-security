using System;
using System.IO;
using Cosmos.Internals;
using Cosmos.Validations.Abstractions;
using Cosmos.Validations.Core;

namespace Cosmos.Validations {
    /// <summary>
    /// CRC16
    /// Author: X-New-Life
    ///     https://github.com/NewLifeX/X/blob/master/NewLife.Core/Security/Crc16.cs
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public sealed class CRC16 : ICRC<CRC16, ushort, short> {
        /// <inheritdoc />
        public ushort Value { get; set; } = CRC16CheckingProvider.Seed;

        // ReSharper disable once InconsistentNaming
        private ushort[] CRCTable { get; } = CRCTableGenerator.GenerationCRC16Table();

        /// <summary>
        /// Reset
        /// </summary>
        /// <returns></returns>
        public CRC16 Reset() {
            Value = CRC16CheckingProvider.Seed;
            return this;
        }

        /// <summary>
        /// Update
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public CRC16 Update(short value) {
            Value = (ushort) ((Value << 8) ^ CRCTable[(Value >> 8) ^ value]);
            return this;
        }

        /// <summary>
        /// Update
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public CRC16 Update(byte[] buffer, int offset = 0, int count = -1) {
            Checker.Buffer(buffer);

            if (count <= 0) count = buffer.Length;
            if (offset < 0 || offset + count > buffer.Length) {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }

            Value ^= Value;
            for (var i = 0; i < count; i++) {
                Value = (ushort) ((Value << 8) ^ CRCTable[(Value >> 8 ^ buffer[offset + i]) & 0xFF]);
            }

            return this;
        }

        /// <summary>
        /// Update
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public CRC16 Update(Stream stream, long count = -1) {
            Checker.Stream(stream);

            if (count <= 0) count = long.MaxValue;

            while (--count >= 0) {
                var b = stream.ReadByte();
                if (b == -1) break;

                Value ^= (byte) b;
                for (var i = 0; i < 8; i++) {
                    if ((Value & 0x0001) != 0)
                        Value = (ushort) ((Value >> 1) ^ 0xa001);
                    else
                        Value = (ushort) (Value >> 1);
                }
            }

            return this;
        }
    }
}