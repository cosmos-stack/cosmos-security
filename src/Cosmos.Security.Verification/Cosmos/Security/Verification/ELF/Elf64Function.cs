using System;
using System.Threading;
using Cosmos.Security.Verification.Core;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    internal class Elf64Function : StreamableHashFunctionBase, IELF64
    {
        public override int HashSizeInBits => 32;

        public override IBlockTransformer CreateBlockTransformer() => new BlockTransformer();

        #region Internal Implementation of BlockTransformer

        private class BlockTransformer : BlockTransformerBase<BlockTransformer>
        {
            private UInt32 _hashValue;

            protected override void CopyStateTo(BlockTransformer other)
            {
                base.CopyStateTo(other);

                other._hashValue = _hashValue;
            }

            protected override void TransformByteGroupsInternal(ArraySegment<byte> data)
            {
                var dataArray = data.Array;
                var endOffset = data.Offset + data.Count;

                var tempHashValue = _hashValue;

                for (var currentOffset = data.Offset; currentOffset < endOffset; ++currentOffset)
                {
                    tempHashValue <<= 4;
                    tempHashValue += dataArray[currentOffset];

                    var tmp = tempHashValue & 0xF0000000;

                    if (tmp != 0)
                        tempHashValue ^= tmp >> 24;

                    tempHashValue &= 0x0FFFFFFF;
                }

                _hashValue = tempHashValue;
            }

            protected override IHashValue FinalizeHashValueInternal(CancellationToken cancellationToken)
            {
                return new HashValue(
                    BitConverter.GetBytes(_hashValue),
                    32);
            }
        }

        #endregion
    }
}