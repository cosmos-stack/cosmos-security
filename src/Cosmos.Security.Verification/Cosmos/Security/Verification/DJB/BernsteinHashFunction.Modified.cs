using System;
using System.Threading;
using Cosmos.Security.Verification.Core;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public class ModifiedBernsteinHashFunction : StreamableHashFunctionBase
    {
        public override int HashSizeInBits => 32;

        public override IBlockTransformer CreateBlockTransformer() => new BlockTransformer();

        #region Internal Implementation of BlockTransformer

        private class BlockTransformer : BlockTransformerBase<BlockTransformer>
        {
            private uint _hashValue;

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
                    tempHashValue = (33 * tempHashValue) ^ dataArray[currentOffset];

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