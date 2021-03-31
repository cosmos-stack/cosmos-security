using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Cosmos.Security.Verification.Core
{
    public abstract class StreamableHashFunctionBase : HashFunctionBase, IStreamableHashFunction
    {
        public abstract IBlockTransformer CreateBlockTransformer();

        public IHashValue ComputeHash(Stream data) => ComputeHash(data, CancellationToken.None);

        public IHashValue ComputeHash(Stream data, CancellationToken cancellationToken)
        {
            if (data is null)
                throw new ArgumentNullException(nameof(data));
            if (!data.CanRead)
                throw new ArgumentException("Stream must be readable.", nameof(data));
            return ComputeHashInternal(data, cancellationToken);
        }

        public Task<IHashValue> ComputeHashAsync(Stream data) => ComputeHashAsync(data, CancellationToken.None);

        public Task<IHashValue> ComputeHashAsync(Stream data, CancellationToken cancellationToken)
        {
            if (data is null)
                throw new ArgumentNullException(nameof(data));
            if (!data.CanRead)
                throw new ArgumentException("Stream must be readable.", nameof(data));
            return ComputeHashAsyncInternal(data, cancellationToken);
        }

        protected override IHashValue ComputeHashInternal(ArraySegment<byte> data, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var memoryStream = new MemoryStream(data.Array, data.Offset, data.Count, false);
            return ComputeHashInternal(memoryStream, cancellationToken);
        }

        protected IHashValue ComputeHashInternal(Stream data, CancellationToken cancellationToken)
        {
            var blockTransformer = CreateBlockTransformer();
            var buffer = new byte[4096];

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var bytesRead = data.Read(buffer, 0, 4096);

                if (bytesRead == 0)
                    break;

                blockTransformer.TransformBytes(buffer, 0, bytesRead, cancellationToken);
            }

            return blockTransformer.FinalizeHashValue(cancellationToken);
        }

        protected async Task<IHashValue> ComputeHashAsyncInternal(Stream data, CancellationToken cancellationToken)
        {
            var blockTransformer = CreateBlockTransformer();
            var buffer = new byte[4096];

            while (true)
            {
                var bytesRead = await data.ReadAsync(buffer, 0, 4096, cancellationToken)
                                          .ConfigureAwait(false);

                if (bytesRead == 0)
                    break;

                blockTransformer.TransformBytes(buffer, 0, bytesRead, cancellationToken);
            }

            return blockTransformer.FinalizeHashValue(cancellationToken);
        }
    }
}