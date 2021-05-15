using System;
using System.Text;
using System.Threading;
using Cosmos.Optionals;

// ReSharper disable CheckNamespace

namespace Cosmos.Security.Cryptography
{
    internal abstract partial class Sm2CryptoFunction
    {
        public virtual ICryptoValue EncryptByPublicKey(byte[] originalBytes)
        {
            return EncryptByPublicKey(originalBytes, CancellationToken.None);
        }

        public virtual ICryptoValue EncryptByPublicKey(byte[] originalBytes, CancellationToken cancellationToken)
        {
            if (originalBytes is null)
                throw new ArgumentNullException(nameof(originalBytes));
            return EncryptByPublicKey(originalBytes, 0, originalBytes.Length, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPublicKey(byte[] originalBytes, int offset, int count)
        {
            return EncryptByPublicKey(originalBytes, offset, count, CancellationToken.None);
        }

        public virtual ICryptoValue EncryptByPublicKey(byte[] originalBytes, int offset, int count, CancellationToken cancellationToken)
        {
            if (originalBytes is null)
                throw new ArgumentNullException(nameof(originalBytes));
            if (offset < 0 || offset > originalBytes.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > originalBytes.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            return EncryptByPublicKey(new ArraySegment<byte>(originalBytes, offset, count), cancellationToken);
        }

        public virtual ICryptoValue EncryptByPublicKey(string text, Encoding encoding = null)
        {
            return EncryptByPublicKey(text, encoding, CancellationToken.None);
        }

        public virtual ICryptoValue EncryptByPublicKey(string text, CancellationToken cancellationToken)
        {
            return EncryptByPublicKey(text, Encoding.UTF8, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPublicKey(string text, Encoding encoding, CancellationToken cancellationToken)
        {
            return EncryptByPublicKey(encoding.SafeEncodingValue().GetBytes(text), cancellationToken);
        }

        public virtual ICryptoValue EncryptByPublicKey(ArraySegment<byte> originalBytes)
        {
            return EncryptByPublicKey(originalBytes, CancellationToken.None);
        }

        public virtual ICryptoValue EncryptByPublicKey(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
            return EncryptByPublicKeyInternal(originalBytes, cancellationToken);
        }

        protected abstract ICryptoValue EncryptByPublicKeyInternal(ArraySegment<byte> originalBytes, CancellationToken cancellationToken);
    }
}