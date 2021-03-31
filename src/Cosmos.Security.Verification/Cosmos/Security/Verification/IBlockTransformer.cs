using System;
using System.Threading;

namespace Cosmos.Security.Verification
{
    public interface IBlockTransformer
    {
        IBlockTransformer Clone();

        void TransformBytes(byte[] data);

        void TransformBytes(byte[] data, CancellationToken cancellationToken);

        void TransformBytes(byte[] data, int offset, int count);

        void TransformBytes(byte[] data, int offset, int count, CancellationToken cancellationToken);

        void TransformBytes(ArraySegment<byte> data);

        void TransformBytes(ArraySegment<byte> data, CancellationToken cancellationToken);

        IHashValue FinalizeHashValue();

        IHashValue FinalizeHashValue(CancellationToken cancellationToken);
    }
}