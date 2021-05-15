using System;
using System.Text;
using System.Threading;
using Cosmos.Optionals;

// ReSharper disable CheckNamespace

namespace Cosmos.Security.Cryptography
{
    internal abstract partial class Sm2CryptoFunction
    {
        public virtual ICryptoValue DecryptByPrivateKey(byte[] buffer)
        {
            return DecryptByPrivateKey(buffer, CancellationToken.None);
        }

        public virtual ICryptoValue DecryptByPrivateKey(byte[] buffer, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            return DecryptByPrivateKey(buffer, 0, buffer.Length, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(byte[] buffer, int offset, int count)
        {
            return DecryptByPrivateKey(buffer, offset, count, CancellationToken.None);
        }

        public virtual ICryptoValue DecryptByPrivateKey(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || offset > buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            return DecryptByPrivateKey(new ArraySegment<byte>(buffer, offset, count), cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(string text, Encoding encoding = null)
        {
            return DecryptByPrivateKey(text, encoding, CancellationToken.None);
        }

        public virtual ICryptoValue DecryptByPrivateKey(string text, CancellationToken cancellationToken)
        {
            return DecryptByPrivateKey(text, Encoding.UTF8, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(string text, Encoding encoding, CancellationToken cancellationToken)
        {
            return DecryptByPrivateKey(encoding.SafeEncodingValue().GetBytes(text), cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(ArraySegment<byte> buffer)
        {
            return DecryptByPrivateKey(buffer, CancellationToken.None);
        }

        public virtual ICryptoValue DecryptByPrivateKey(ArraySegment<byte> buffer, CancellationToken cancellationToken)
        {
            return DecryptByPrivateKeyInternal(buffer, cancellationToken);
        }

        protected abstract ICryptoValue DecryptByPrivateKeyInternal(ArraySegment<byte> cipherBytes, CancellationToken cancellationToken);
    }
}