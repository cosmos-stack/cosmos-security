using System;
using System.Text;
using System.Threading;
using Cosmos.Optionals;

// ReSharper disable CheckNamespace

namespace Cosmos.Security.Cryptography
{
    internal abstract partial class Sm2CryptoFunction
    {
        public virtual bool VerifyByPublicKey(byte[] buffer, byte[] signature)
        {
            return VerifyByPublicKey(buffer, signature, CancellationToken.None);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, byte[] signature, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            return VerifyByPublicKey(buffer, 0, buffer.Length, signature, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature)
        {
            return VerifyByPublicKey(buffer, offset, count, signature, CancellationToken.None);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || offset > buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
             return VerifyByPublicKey(new ArraySegment<byte>(buffer, offset, count), signature, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(string text, string signature, Encoding encoding = null)
        {
            return VerifyByPublicKey(text, signature, encoding, CancellationToken.None);
        }

        public virtual bool VerifyByPublicKey(string text, string signature, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(text, signature, Encoding.UTF8, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(string text, string signature, Encoding encoding, CancellationToken cancellationToken)
        {
            encoding = encoding.SafeEncodingValue();
            return VerifyByPublicKey(encoding.GetBytes(text), encoding.GetBytes(signature), cancellationToken);
        }

        public virtual bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature)
        {
            return VerifyByPublicKey(buffer, signature, CancellationToken.None);
        }

        public virtual bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, CancellationToken cancellationToken)
        {
            return VerifyByPublicKeyInternal(buffer, signature, cancellationToken);
        }

        protected abstract bool VerifyByPublicKeyInternal(ArraySegment<byte> buffer, byte[] signature, CancellationToken cancellationToken);
        
        public virtual bool VerifyByPrivateKey(byte[] buffer, byte[] signature)
        {
            return VerifyByPrivateKey(buffer, signature, CancellationToken.None);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, byte[] signature, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            return VerifyByPrivateKey(buffer, 0, buffer.Length, signature, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature)
        {
            return VerifyByPrivateKey(buffer, offset, count, signature, CancellationToken.None);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || offset > buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            return VerifyByPrivateKey(new ArraySegment<byte>(buffer, offset, count), signature, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(string text, string signature, Encoding encoding = null)
        {
            return VerifyByPrivateKey(text, signature, encoding, CancellationToken.None);
        }

        public virtual bool VerifyByPrivateKey(string text, string signature, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(text, signature, Encoding.UTF8, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(string text, string signature, Encoding encoding, CancellationToken cancellationToken)
        {
            encoding = encoding.SafeEncodingValue();
            return VerifyByPrivateKey(encoding.GetBytes(text), encoding.GetBytes(signature), cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature)
        {
            return VerifyByPrivateKey(buffer, signature, CancellationToken.None);
        }

        public virtual bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKeyInternal(buffer, signature, cancellationToken);
        }

        protected abstract bool VerifyByPrivateKeyInternal(ArraySegment<byte> buffer, byte[] signature, CancellationToken cancellationToken);

    }
}