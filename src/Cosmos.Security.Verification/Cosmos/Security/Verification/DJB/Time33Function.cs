using System;
using System.Linq;
using System.Threading;
using Cosmos.IO.Buffers;
using Cosmos.Security.Verification.Core;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public class Time33Function : StreamableHashFunctionBase
    {
        public override int HashSizeInBits => 32;

        internal Time33Function() { }

        public override IBlockTransformer CreateBlockTransformer() => new Time33BlockTransformer();

        #region Internal Implementation of BlockTransformer

        private class Time33BlockTransformer : BlockTransformerBase<Time33BlockTransformer>
        {
            private byte[] _hashValue;
            public Time33BlockTransformer() { }

            protected override void CopyStateTo(Time33BlockTransformer other)
            {
                base.CopyStateTo(other);

                other._hashValue = _hashValue;
            }

            protected override void TransformByteGroupsInternal(ArraySegment<byte> data)
            {
                long hash = 5381;
                var dataArray = data.ToArray();

                for (int i = 0, len = data.Count; i < len; ++i)
                    hash += (hash << 5) + dataArray[i];

                _hashValue = new byte[8];
                BinaryDigitWriter.Write(_hashValue, 0, hash & 0x7fffffff);
            }

            protected override IHashValue FinalizeHashValueInternal(CancellationToken cancellationToken)
            {
                return new HashValue(_hashValue, 32);
            }
        }

        #endregion
    }
}