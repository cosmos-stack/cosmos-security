using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Numerics;

namespace Cosmos.Security.Verification
{
    public sealed class FnvPrimeOffset
    {
        public IReadOnlyList<UInt32> Prime { get; }
        public IReadOnlyList<UInt32> Offset { get; }

        private static readonly ConcurrentDictionary<(BigInteger, int), IReadOnlyList<UInt32>> _calculatedUintArrays = new();

        private FnvPrimeOffset(IReadOnlyList<UInt32> prime, IReadOnlyList<UInt32> offset)
        {
            Debug.Assert(prime != null);
            Debug.Assert(offset != null);

            Prime = prime;
            Offset = offset;
        }

        public static FnvPrimeOffset Create(int bitSize, BigInteger prime, BigInteger offset)
        {
            if (bitSize <= 0 || bitSize % 32 != 0)
                throw new ArgumentOutOfRangeException(nameof(bitSize), $"{nameof(bitSize)} must be a positive a multiple of 32.");

            if (prime <= BigInteger.Zero)
                throw new ArgumentOutOfRangeException(nameof(prime), $"{nameof(prime)} must greater than zero.");

            if (offset <= BigInteger.Zero)
                throw new ArgumentOutOfRangeException(nameof(offset), $"{nameof(offset)} must greater than zero.");

            return new FnvPrimeOffset(
                _calculatedUintArrays.GetOrAdd((prime, bitSize), ToUInt32Array),
                _calculatedUintArrays.GetOrAdd((offset, bitSize), ToUInt32Array));
        }

        private static IReadOnlyList<UInt32> ToUInt32Array((BigInteger, int) tuple)
        {
            return ToUInt32Array(tuple.Item1, tuple.Item2);
        }

        private static IReadOnlyList<UInt32> ToUInt32Array(BigInteger value, int bitSize)
        {
            Debug.Assert(bitSize > 0);
            Debug.Assert(bitSize % 32 == 0);


            var uint32Values = new UInt32[bitSize / 32];
            var bigIntegerBytes = value.ToByteArray();


            var copyLength = uint32Values.Length * 4;

            if (bigIntegerBytes.Length < copyLength)
                copyLength = bigIntegerBytes.Length;


            Buffer.BlockCopy(
                bigIntegerBytes, 0,
                uint32Values, 0,
                copyLength);

            return uint32Values;
        }
    }
}