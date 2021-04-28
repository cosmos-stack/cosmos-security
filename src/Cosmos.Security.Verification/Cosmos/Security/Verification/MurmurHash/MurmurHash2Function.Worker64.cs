using System;
using System.Threading;
using Cosmos.Security.Verification.Core;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    internal partial class MurmurHash2Function
    {
        protected IHashValue ComputeHash64(ArraySegment<byte> data, CancellationToken cancellationToken)
        {
            var dataArray = data.Array;
            var dataOffset = data.Offset;
            var dataCount = data.Count;

            var endOffset = dataOffset + dataCount;
            var remainderCount = dataCount % 8;

            ulong hashValue = _config.Seed ^ ((ulong) dataCount * _mixConstant64);

            // Process 8-byte groups
            {
                var groupEndOffset = endOffset - remainderCount;

                for (var currentOffset = dataOffset; currentOffset < groupEndOffset; currentOffset += 8)
                {
                    ulong k = BitConverter.ToUInt64(dataArray, currentOffset);

                    k *= _mixConstant64;
                    k ^= k >> 47;
                    k *= _mixConstant64;

                    hashValue ^= k;
                    hashValue *= _mixConstant64;
                }
            }

            // Process remainder
            if (remainderCount > 0)
            {
                var remainderOffset = endOffset - remainderCount;

                switch (remainderCount)
                {
                    case 7:
                        hashValue ^= (ulong) dataArray[remainderOffset + 6] << 48;
                        goto case 6;
                    case 6:
                        hashValue ^= (ulong) dataArray[remainderOffset + 5] << 40;
                        goto case 5;
                    case 5:
                        hashValue ^= (ulong) dataArray[remainderOffset + 4] << 32;
                        goto case 4;
                    case 4:
                        hashValue ^= (ulong) BitConverter.ToUInt32(dataArray, remainderOffset);
                        break;

                    case 3:
                        hashValue ^= (ulong) dataArray[remainderOffset + 2] << 16;
                        goto case 2;
                    case 2:
                        hashValue ^= (ulong) dataArray[remainderOffset + 1] << 8;
                        goto case 1;
                    case 1:
                        hashValue ^= (ulong) dataArray[remainderOffset];
                        break;
                }

                ;

                hashValue *= _mixConstant64;
            }


            hashValue ^= hashValue >> 47;
            hashValue *= _mixConstant64;
            hashValue ^= hashValue >> 47;

            return new HashValue(
                BitConverter.GetBytes(hashValue),
                64);
        }
    }
}