using System;
using System.Text;
using System.Threading;

namespace Cosmos.Security.Verification
{
    public interface IHashAlgorithm
    {
        IHashValue ComputeHash(byte[] data);

        IHashValue ComputeHash(byte[] data, CancellationToken cancellationToken);

        IHashValue ComputeHash(byte[] data, int offset, int count);

        IHashValue ComputeHash(byte[] data, int offset, int count, CancellationToken cancellationToken);

        IHashValue ComputeHash(string data, Encoding encoding = null);

        IHashValue ComputeHash(string data, CancellationToken cancellationToken);

        IHashValue ComputeHash(string data, Encoding encoding, CancellationToken cancellationToken);

        IHashValue ComputeHash(ArraySegment<byte> data);

        IHashValue ComputeHash(ArraySegment<byte> data, CancellationToken cancellationToken);
    }
}