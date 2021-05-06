using System;

// ReSharper disable CheckNamespace

namespace Cosmos.Security.Verification
{
    internal class Fnv1AFunction : Fnv1Base
    {
        public Fnv1AFunction(FnvConfig config) : base(config) { }

        public override IBlockTransformer CreateBlockTransformer()
        {
            return _config.HashSizeInBits switch
            {
                32 => new BlockTransformer_32Bit(_fnvPrimeOffset),
                64 => new BlockTransformer_64Bit(_fnvPrimeOffset),
                _ => new BlockTransformer_Extended(_fnvPrimeOffset)
            };
        }

        #region Internal Implementation of BlockTransformer

        private class BlockTransformer_32Bit : BlockTransformer_32BitBase<BlockTransformer_32Bit>
        {
            public BlockTransformer_32Bit() { }

            public BlockTransformer_32Bit(FnvPrimeOffset fnvPrimeOffset) : base(fnvPrimeOffset) { }

            protected override void TransformByteGroupsInternal(ArraySegment<byte> data)
            {
                var dataArray = data.Array;
                var dataCount = data.Count;
                var endOffset = data.Offset + dataCount;

                var tempHashValue = _hashValue;
                var tempPrime = _prime;

                for (int currentOffset = data.Offset; currentOffset < endOffset; ++currentOffset)
                {
                    tempHashValue ^= dataArray[currentOffset];
                    tempHashValue *= tempPrime;
                }

                _hashValue = tempHashValue;
            }
        }

        private class BlockTransformer_64Bit : BlockTransformer_64BitBase<BlockTransformer_64Bit>
        {
            public BlockTransformer_64Bit() { }

            public BlockTransformer_64Bit(FnvPrimeOffset fnvPrimeOffset) : base(fnvPrimeOffset) { }

            protected override void TransformByteGroupsInternal(ArraySegment<byte> data)
            {
                var dataArray = data.Array;
                var dataCount = data.Count;
                var endOffset = data.Offset + dataCount;

                var tempHashValue = _hashValue;
                var tempPrime = _prime;

                for (int currentOffset = data.Offset; currentOffset < endOffset; ++currentOffset)
                {
                    tempHashValue ^= dataArray[currentOffset];
                    tempHashValue *= tempPrime;
                }

                _hashValue = tempHashValue;
            }
        }

        private class BlockTransformer_Extended : BlockTransformer_ExtendedBase<BlockTransformer_Extended>
        {
            public BlockTransformer_Extended() { }

            public BlockTransformer_Extended(FnvPrimeOffset fnvPrimeOffset) : base(fnvPrimeOffset) { }

            protected override void TransformByteGroupsInternal(ArraySegment<byte> data)
            {
                var dataArray = data.Array;
                var dataCount = data.Count;
                var endOffset = data.Offset + dataCount;

                var tempHashValue = _hashValue;
                var tempPrime = _prime;

                var tempHashSizeInBytes = _hashSizeInBytes;

                for (int currentOffset = data.Offset; currentOffset < endOffset; ++currentOffset)
                {
                    tempHashValue[0] ^= dataArray[currentOffset];
                    tempHashValue = ExtendedMultiply(tempHashValue, tempPrime, tempHashSizeInBytes);
                }

                _hashValue = tempHashValue;
            }
        }

        #endregion
    }
}