using System;
using System.IO;
using System.Text;
using Cosmos.Conversions;
using Cosmos.Optionals;
using Cosmos.Validations.Abstractions;
using Cosmos.Validations.Core;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validations {
    /// <summary>
    /// Base CRC64
    /// </summary>
    /// <typeparam name="TCRC64"></typeparam>
    public abstract class CRC64<TCRC64> : ICRC<TCRC64, ulong, long>
        where TCRC64 : class, ICRC<TCRC64, ulong, long>, new() {

        /// <summary>
        /// Value
        /// </summary>
        public ulong Value { get; set; } = CRC64CheckingProvider.Seed;

        /// <summary>
        /// Reset
        /// </summary>
        /// <returns></returns>
        public abstract TCRC64 Reset();

        /// <inheritdoc />
        public TCRC64 Update(long value) {
            return Update(BitConverter.GetBytes(value));
        }

        /// <summary>
        /// Update
        /// </summary>
        /// <param name="value"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public TCRC64 Update(string value, Encoding encoding = null) {
            return Update(
                string.IsNullOrWhiteSpace(value)
                    ? CRCTableGenerator.EmptyBytes()
                    : encoding.SafeValue().GetBytes(value));
        }

        /// <inheritdoc />
        public abstract TCRC64 Update(byte[] buffer, int offset = 0, long count = -1);

        /// <inheritdoc />
        public TCRC64 Update(Stream stream, long count = -1) {
            Checker.Stream(stream);
            return Update(stream.CastToBytes(), 0, count);
        }
    }
}