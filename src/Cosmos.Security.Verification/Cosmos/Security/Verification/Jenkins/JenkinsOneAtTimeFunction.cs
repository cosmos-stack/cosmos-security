using System;
using System.Threading;
using Cosmos.Security.Verification.Core;

namespace Cosmos.Security.Verification
{
    internal class JenkinsOneAtTimeFunction : StreamableHashFunctionBase, IStreamableJenkins
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
                    tempHashValue += dataArray[currentOffset];
                    tempHashValue += (tempHashValue << 10);
                    tempHashValue ^= (tempHashValue >> 6);
                }

                _hashValue = tempHashValue;
            }

            protected override IHashValue FinalizeHashValueInternal(CancellationToken cancellationToken)
            {
                var finalHashValue = _hashValue;
                finalHashValue += finalHashValue << 3;
                finalHashValue ^= finalHashValue >> 11;
                finalHashValue += finalHashValue << 15;

                return new HashValue(
                    BitConverter.GetBytes(finalHashValue),
                    32);
            }
        }

        #endregion
    }
}