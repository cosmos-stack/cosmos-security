using System;
using System.Linq;
using System.Threading;
using Cosmos.Security.Verification.Core;
// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public partial class MurmurHash3Function
    {
        private class BlockTransformer128 : BlockTransformerBase<BlockTransformer128>
        {
            private UInt64 _hashValue1;
            private UInt64 _hashValue2;

            private int _bytesProcessed = 0;

            public BlockTransformer128() : base(inputBlockSize: 16) { }

            public BlockTransformer128(UInt64 seed) : this()
            {
                _hashValue1 = seed;
                _hashValue2 = seed;
            }

            protected override void CopyStateTo(BlockTransformer128 other)
            {
                base.CopyStateTo(other);

                other._hashValue1 = _hashValue1;
                other._hashValue2 = _hashValue2;

                other._bytesProcessed = _bytesProcessed;
            }

            protected override void TransformByteGroupsInternal(ArraySegment<byte> data)
            {
                var dataArray = data.Array;
                var dataOffset = data.Offset;
                var dataCount = data.Count;

                var endOffset = dataOffset + dataCount;

                var tempHashValue1 = _hashValue1;
                var tempHashValue2 = _hashValue2;

                for (var currentOffset = dataOffset; currentOffset < endOffset; currentOffset += 16)
                {
                    UInt64 k1 = BitConverter.ToUInt64(dataArray, currentOffset);
                    UInt64 k2 = BitConverter.ToUInt64(dataArray, currentOffset + 8);

                    k1 *= c1_128;
                    k1 = RotateLeft(k1, 31);
                    k1 *= c2_128;
                    tempHashValue1 ^= k1;

                    tempHashValue1 = RotateLeft(tempHashValue1, 27);
                    tempHashValue1 += tempHashValue2;
                    tempHashValue1 = (tempHashValue1 * 5) + 0x52dce729;

                    k2 *= c2_128;
                    k2 = RotateLeft(k2, 33);
                    k2 *= c1_128;
                    tempHashValue2 ^= k2;

                    tempHashValue2 = RotateLeft(tempHashValue2, 31);
                    tempHashValue2 += tempHashValue1;
                    tempHashValue2 = (tempHashValue2 * 5) + 0x38495ab5;
                }

                _hashValue1 = tempHashValue1;
                _hashValue2 = tempHashValue2;

                _bytesProcessed += dataCount;
            }

            protected override IHashValue FinalizeHashValueInternal(CancellationToken cancellationToken)
            {
                var remainder = FinalizeInputBuffer;
                var remainderCount = (remainder?.Length).GetValueOrDefault();

                var tempHashValue1 = _hashValue1;
                var tempHashValue2 = _hashValue2;

                var tempBytesProcessed = _bytesProcessed;

                if (remainderCount > 0)
                {
                    UInt64 k1 = 0;
                    UInt64 k2 = 0;

                    switch (remainderCount)
                    {
                        case 15:
                            k2 ^= (UInt64) remainder[14] << 48;
                            goto case 14;
                        case 14:
                            k2 ^= (UInt64) remainder[13] << 40;
                            goto case 13;
                        case 13:
                            k2 ^= (UInt64) remainder[12] << 32;
                            goto case 12;
                        case 12:
                            k2 ^= (UInt64) remainder[11] << 24;
                            goto case 11;
                        case 11:
                            k2 ^= (UInt64) remainder[10] << 16;
                            goto case 10;
                        case 10:
                            k2 ^= (UInt64) remainder[9] << 8;
                            goto case 9;
                        case 9:
                            k2 ^= ((UInt64) remainder[8]);
                            k2 *= c2_128;
                            k2 = RotateLeft(k2, 33);
                            k2 *= c1_128;
                            tempHashValue2 ^= k2;

                            goto case 8;

                        case 8:
                            k1 ^= BitConverter.ToUInt64(remainder, 0);
                            break;

                        case 7:
                            k1 ^= (UInt64) remainder[6] << 48;
                            goto case 6;
                        case 6:
                            k1 ^= (UInt64) remainder[5] << 40;
                            goto case 5;
                        case 5:
                            k1 ^= (UInt64) remainder[4] << 32;
                            goto case 4;
                        case 4:
                            k1 ^= (UInt64) remainder[3] << 24;
                            goto case 3;
                        case 3:
                            k1 ^= (UInt64) remainder[2] << 16;
                            goto case 2;
                        case 2:
                            k1 ^= (UInt64) remainder[1] << 8;
                            goto case 1;
                        case 1:
                            k1 ^= (UInt64) remainder[0];
                            break;
                    }

                    k1 *= c1_128;
                    k1 = RotateLeft(k1, 31);
                    k1 *= c2_128;
                    tempHashValue1 ^= k1;

                    tempBytesProcessed += remainderCount;
                }


                tempHashValue1 ^= (UInt64) tempBytesProcessed;
                tempHashValue2 ^= (UInt64) tempBytesProcessed;

                tempHashValue1 += tempHashValue2;
                tempHashValue2 += tempHashValue1;

                Mix(ref tempHashValue1);
                Mix(ref tempHashValue2);

                tempHashValue1 += tempHashValue2;
                tempHashValue2 += tempHashValue1;

                var hashValueBytes = BitConverter.GetBytes(tempHashValue1)
                                                 .Concat(BitConverter.GetBytes(tempHashValue2))
                                                 .ToArray();

                return new HashValue(hashValueBytes, 128);
            }

            private static void Mix(ref UInt64 k)
            {
                k ^= k >> 33;
                k *= 0xff51afd7ed558ccd;
                k ^= k >> 33;
                k *= 0xc4ceb9fe1a85ec53;
                k ^= k >> 33;
            }

            private static UInt64 RotateLeft(UInt64 operand, int shiftCount)
            {
                shiftCount &= 0x3f;

                return
                    (operand << shiftCount) |
                    (operand >> (64 - shiftCount));
            }
        }
    }
}