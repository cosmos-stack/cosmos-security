using System;
using Cosmos.Validations.Core;

namespace Cosmos.Validations
{
    /// <summary>
    /// ECMA CRC64
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public sealed class ECMA_CRC64 : CRC64<ECMA_CRC64>
    {
        /// <summary>
        /// Value
        /// </summary>
        public ulong Value { get; set; } = CRC64CheckingProvider.Seed;

        // ReSharper disable once InconsistentNaming
        private ulong[] CRCTable { get; } = CRCTableGenerator.GenerationCRC64Table(CRCTableGenerator.CRC64_ECMA_POLY);

        /// <inheritdoc />
        public override ECMA_CRC64 Reset()
        {
            Value = CRC64CheckingProvider.Seed;
            return this;
        }

        /// <inheritdoc />
        public override ECMA_CRC64 Update(byte[] buffer, int offset = 0, long count = -1)
        {
            Checker.Buffer(buffer);

            if (count <= 0 || count > buffer.Length)
            {
                count = buffer.Length;
            }

            if (offset < 0 || offset + count > buffer.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }

            while (--count >= 0)
            {
                Value = CRCTable[(Value ^ buffer[offset++]) & 0x0ff] ^ ((~Value >> 8) & 0x00FFFFFFFFFFFFFF);
            }

            return this;
        }
    }
}