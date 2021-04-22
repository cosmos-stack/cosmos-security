using System;

namespace Cosmos.Security.Verification
{
    public class Fnv1Function : Fnv1Base
    {
        public Fnv1Function(FnvConfig config) : base(config) { }

        public override IBlockTransformer CreateBlockTransformer()
        {
            switch (_config.HashSizeInBits)
            {
                case 32:
                    return new BlockTransformer_32Bit(_fnvPrimeOffset);

                case 64:
                    return new BlockTransformer_64Bit(_fnvPrimeOffset);

                default:
                    return new BlockTransformer_Extended(_fnvPrimeOffset);
            }
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
                    tempHashValue *= tempPrime;
                    tempHashValue ^= dataArray[currentOffset];
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
                    tempHashValue *= tempPrime;
                    tempHashValue ^= dataArray[currentOffset];
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
                    tempHashValue = ExtendedMultiply(tempHashValue, tempPrime, tempHashSizeInBytes);
                    tempHashValue[0] ^= dataArray[currentOffset];
                }

                _hashValue = tempHashValue;
            }
        }

        #endregion
    }
}