using System;
using System.Threading;
using Cosmos.Security.Verification.Core;
// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    internal partial class MurmurHash3Function
    {
        private class BlockTransformer32 : BlockTransformerBase<BlockTransformer32>
        {
            private UInt32 _hashValue;

            private int _bytesProcessed = 0;

            public BlockTransformer32() : base(inputBlockSize: 4) { }

            public BlockTransformer32(UInt32 seed) : this()
            {
                _hashValue = seed;
            }

            protected override void CopyStateTo(BlockTransformer32 other)
            {
                base.CopyStateTo(other);

                other._hashValue = _hashValue;

                other._bytesProcessed = _bytesProcessed;
            }

            protected override void TransformByteGroupsInternal(ArraySegment<byte> data)
            {
                var dataArray = data.Array;
                var dataOffset = data.Offset;
                var dataCount = data.Count;

                var endOffset = dataOffset + dataCount;

                var tempHashValue = _hashValue;

                for (var currentOffset = dataOffset; currentOffset < endOffset; currentOffset += 4)
                {
                    UInt32 k1 = BitConverter.ToUInt32(dataArray, currentOffset);

                    k1 *= c1_32;
                    k1 = RotateLeft(k1, 15);
                    k1 *= c2_32;

                    tempHashValue ^= k1;
                    tempHashValue = RotateLeft(tempHashValue, 13);
                    tempHashValue = (tempHashValue * 5) + 0xe6546b64;
                }

                _hashValue = tempHashValue;

                _bytesProcessed += dataCount;
            }

            protected override IHashValue FinalizeHashValueInternal(CancellationToken cancellationToken)
            {
                var remainder = FinalizeInputBuffer;
                var remainderCount = (remainder?.Length).GetValueOrDefault();

                var tempHashValue = _hashValue;

                var tempBytesProcessed = _bytesProcessed;

                if (remainderCount > 0)
                {
                    UInt32 k2 = 0;

                    switch (remainderCount)
                    {
                        case 3:
                            k2 ^= (UInt32) remainder[2] << 16;
                            goto case 2;
                        case 2:
                            k2 ^= (UInt32) remainder[1] << 8;
                            goto case 1;
                        case 1:
                            k2 ^= (UInt32) remainder[0];
                            break;
                    }

                    k2 *= c1_32;
                    k2 = RotateLeft(k2, 15);
                    k2 *= c2_32;
                    tempHashValue ^= k2;

                    tempBytesProcessed += remainderCount;
                }


                tempHashValue ^= (UInt32) tempBytesProcessed;
                Mix(ref tempHashValue);

                return new HashValue(
                    BitConverter.GetBytes(tempHashValue),
                    32);
            }

            private static void Mix(ref UInt32 h)
            {
                h ^= h >> 16;
                h *= 0x85ebca6b;
                h ^= h >> 13;
                h *= 0xc2b2ae35;
                h ^= h >> 16;
            }

            private static UInt32 RotateLeft(UInt32 operand, int shiftCount)
            {
                shiftCount &= 0x1f;

                return
                    (operand << shiftCount) |
                    (operand >> (32 - shiftCount));
            }
        }
    }
}