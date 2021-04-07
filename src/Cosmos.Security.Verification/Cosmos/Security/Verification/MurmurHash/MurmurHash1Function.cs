using System;
using System.Threading;
using Cosmos.Reflection;
using Cosmos.Security.Verification.Core;

namespace Cosmos.Security.Verification.MurmurHash
{
    public class MurmurHash1Function : HashFunctionBase, IMurmurHash<MurmurHash1Config>
    {
        private const UInt32 _m = 0XC6A4A793;

        private readonly MurmurHash1Config _config;

        public MurmurHash1Function(MurmurHash1Config config)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
        }

        public MurmurHash1Config Config => _config.DeepCopy(DeepCopyOptions.ExpressionCopier);

        public override int HashSizeInBits => 32;

        protected override IHashValue ComputeHashInternal(ArraySegment<byte> data, CancellationToken cancellationToken)
        {
            var dataArray = data.Array;
            var dataOffset = data.Offset;
            var dataCount = data.Count;

            var endOffset = dataOffset + dataCount;
            var remainderCount = dataCount % 4;

            UInt32 hashValue = _config.Seed ^ ((UInt32) dataCount * _m);

            // Process 4-byte groups
            {
                var groupEndOffset = endOffset - remainderCount;

                for (var currentOffset = dataOffset; currentOffset < groupEndOffset; currentOffset += 4)
                {
                    hashValue += BitConverter.ToUInt32(dataArray, currentOffset);
                    hashValue *= _m;
                    hashValue ^= hashValue >> 16;
                }
            }

            // Process remainder
            if (remainderCount > 0)
            {
                var remainderOffset = endOffset - remainderCount;

                switch (remainderCount)
                {
                    case 3:
                        hashValue += (UInt32) dataArray[remainderOffset + 2] << 16;
                        goto case 2;
                    case 2:
                        hashValue += (UInt32) dataArray[remainderOffset + 1] << 8;
                        goto case 1;
                    case 1:
                        hashValue += (UInt32) dataArray[remainderOffset];
                        break;
                }

                ;

                hashValue *= _m;
                hashValue ^= hashValue >> 16;
            }


            hashValue *= _m;
            hashValue ^= hashValue >> 10;
            hashValue *= _m;
            hashValue ^= hashValue >> 17;

            return new HashValue(
                BitConverter.GetBytes(hashValue),
                32);
        }
    }
}