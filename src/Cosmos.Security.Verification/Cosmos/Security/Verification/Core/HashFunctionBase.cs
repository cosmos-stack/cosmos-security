using System;
using System.Text;
using System.Threading;
using Cosmos.Optionals;

namespace Cosmos.Security.Verification.Core
{
    public abstract class HashFunctionBase : IHashFunction
    {
        public abstract int HashSizeInBits { get; }

        public IHashValue ComputeHash(byte[] data)
        {
            return ComputeHash(data, CancellationToken.None);
        }

        public IHashValue ComputeHash(byte[] data, CancellationToken cancellationToken)
        {
            if (data is null)
                throw new ArgumentNullException(nameof(data));
            return ComputeHash(data, 0, data.Length, cancellationToken);
        }

        public IHashValue ComputeHash(byte[] data, int offset, int count)
        {
            return ComputeHash(data, offset, count, CancellationToken.None);
        }

        public IHashValue ComputeHash(byte[] data, int offset, int count, CancellationToken cancellationToken)
        {
            if (data is null)
                throw new ArgumentNullException(nameof(data));
            if (offset < 0 || offset > data.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > data.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            return ComputeHash(new ArraySegment<byte>(data, offset, count), cancellationToken);
        }

        public IHashValue ComputeHash(string data, Encoding encoding = null)
        {
            return ComputeHash(encoding.SafeEncodingValue().GetBytes(data));
        }

        public IHashValue ComputeHash(string data, CancellationToken cancellationToken)
        {
            return ComputeHash(data, null, cancellationToken);
        }

        public IHashValue ComputeHash(string data, Encoding encoding, CancellationToken cancellationToken)
        {
            return ComputeHash(encoding.SafeEncodingValue().GetBytes(data), cancellationToken);
        }

        public IHashValue ComputeHash(ArraySegment<byte> data)
        {
            return ComputeHash(data, CancellationToken.None);
        }

        public IHashValue ComputeHash(ArraySegment<byte> data, CancellationToken cancellationToken)
        {
            return ComputeHashInternal(data, cancellationToken);
        }

        protected abstract IHashValue ComputeHashInternal(ArraySegment<byte> data, CancellationToken cancellationToken);
    }
}