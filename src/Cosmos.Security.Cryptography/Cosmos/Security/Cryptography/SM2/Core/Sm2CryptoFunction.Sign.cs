using System;
using System.Text;
using System.Threading;
using Cosmos.Optionals;

// ReSharper disable CheckNamespace

namespace Cosmos.Security.Cryptography
{
    internal abstract partial class Sm2CryptoFunction
    {
        public virtual ISignValue SignByPublicKey(byte[] buffer)
        {
            return SignByPublicKey(buffer, CancellationToken.None);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            return SignByPublicKey(buffer, 0, buffer.Length, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, int offset, int count)
        {
            return SignByPublicKey(buffer, offset, count, CancellationToken.None);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || offset > buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            return SignByPublicKey(new ArraySegment<byte>(buffer, offset, count), cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(string text, Encoding encoding = null)
        {
            return SignByPublicKey(text, encoding, CancellationToken.None);
        }

        public virtual ISignValue SignByPublicKey(string text, CancellationToken cancellationToken)
        {
            return SignByPublicKey(text, Encoding.UTF8, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(string text, Encoding encoding, CancellationToken cancellationToken)
        {
            return SignByPublicKey(encoding.SafeEncodingValue().GetBytes(text), cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(ArraySegment<byte> buffer)
        {
            return SignByPublicKey(buffer, CancellationToken.None);
        }

        public virtual ISignValue SignByPublicKey(ArraySegment<byte> buffer, CancellationToken cancellationToken)
        {
            return SignByPublicKeyInternal(buffer, cancellationToken);
        }

        protected abstract ISignValue SignByPublicKeyInternal(ArraySegment<byte> buffer, CancellationToken cancellationToken);
        
        public virtual ISignValue SignByPrivateKey(byte[] buffer)
        {
            return SignByPrivateKey(buffer, CancellationToken.None);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            return SignByPrivateKey(buffer, 0, buffer.Length, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, int offset, int count)
        {
            return SignByPrivateKey(buffer, offset, count, CancellationToken.None);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || offset > buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            return SignByPrivateKey(new ArraySegment<byte>(buffer, offset, count), cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(string text, Encoding encoding = null)
        {
            return SignByPrivateKey(text, encoding, CancellationToken.None);
        }

        public virtual ISignValue SignByPrivateKey(string text, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(text, Encoding.UTF8, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(string text, Encoding encoding, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(encoding.SafeEncodingValue().GetBytes(text), cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(ArraySegment<byte> buffer)
        {
            return SignByPrivateKey(buffer, CancellationToken.None);
        }

        public virtual ISignValue SignByPrivateKey(ArraySegment<byte> buffer, CancellationToken cancellationToken)
        {
            return SignByPrivateKeyInternal(buffer, cancellationToken);
        }

        protected abstract ISignValue SignByPrivateKeyInternal(ArraySegment<byte> buffer, CancellationToken cancellationToken);
    }
}