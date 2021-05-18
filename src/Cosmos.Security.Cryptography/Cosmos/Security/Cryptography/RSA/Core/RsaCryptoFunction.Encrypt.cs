#if NET451 || NET452
using System;
using System.Text;
using System.Threading;
#else
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
#endif
using Cosmos.Optionals;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Cryptography
{
    internal abstract partial class RsaCryptoFunction
    {
#if NET451 || NET452
        public virtual ICryptoValue EncryptByPublicKey(byte[] originalBytes)
        {
            return EncryptByPublicKey(originalBytes, true);
        }
        
        public virtual ICryptoValue EncryptByPublicKey(byte[] originalBytes, bool fOEAP)
        {
            return EncryptByPublicKey(originalBytes, fOEAP, CancellationToken.None);
        }

        public virtual ICryptoValue EncryptByPublicKey(byte[] originalBytes, CancellationToken cancellationToken)
        {
            return EncryptByPublicKey(originalBytes, true, cancellationToken);
        }
        public virtual ICryptoValue EncryptByPublicKey(byte[] originalBytes, bool fOEAP, CancellationToken cancellationToken)
        {
            if (originalBytes is null)
                throw new ArgumentNullException(nameof(originalBytes));
            return EncryptByPublicKey(originalBytes, 0, originalBytes.Length, fOEAP, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPublicKey(byte[] originalBytes, int offset, int count)
        {
            return EncryptByPublicKey(originalBytes, offset, count, true);
        }

        public virtual ICryptoValue EncryptByPublicKey(byte[] originalBytes, int offset, int count, bool fOEAP)
        {
            return EncryptByPublicKey(originalBytes, offset, count, fOEAP, CancellationToken.None);
        }

        public virtual ICryptoValue EncryptByPublicKey(byte[] originalBytes, int offset, int count, CancellationToken cancellationToken)
        {
            return EncryptByPublicKey(originalBytes, offset, count, true, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPublicKey(byte[] originalBytes, int offset, int count, bool fOEAP, CancellationToken cancellationToken)
        {
            if (originalBytes is null)
                throw new ArgumentNullException(nameof(originalBytes));
            if (offset < 0 || offset > originalBytes.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > originalBytes.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            return EncryptByPublicKey(new ArraySegment<byte>(originalBytes, offset, count), fOEAP, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPublicKey(string text, Encoding encoding = null)
        {
            return EncryptByPublicKey(text, true, encoding);
        }

        public virtual ICryptoValue EncryptByPublicKey(string text, bool fOEAP, Encoding encoding = null)
        {
            return EncryptByPublicKey(text, fOEAP, encoding, CancellationToken.None);
        }

        public virtual ICryptoValue EncryptByPublicKey(string text, CancellationToken cancellationToken)
        {
            return EncryptByPublicKey(text, true, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPublicKey(string text, bool fOEAP, CancellationToken cancellationToken)
        {
            return EncryptByPublicKey(text, fOEAP, Encoding.UTF8, cancellationToken);
        }
        
        public virtual ICryptoValue EncryptByPublicKey(string text, Encoding encoding, CancellationToken cancellationToken)
        {
            return EncryptByPublicKey(text, true, encoding, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPublicKey(string text, bool fOEAP, Encoding encoding, CancellationToken cancellationToken)
        {
            return EncryptByPublicKey(encoding.SafeEncodingValue().GetBytes(text), fOEAP, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPublicKey(ArraySegment<byte> originalBytes)
        {
            return EncryptByPublicKey(originalBytes, true);
        }

        public virtual ICryptoValue EncryptByPublicKey(ArraySegment<byte> originalBytes, bool fOEAP)
        {
            return EncryptByPublicKey(originalBytes, fOEAP, CancellationToken.None);
        }
        
        public virtual ICryptoValue EncryptByPublicKey(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
            return EncryptByPublicKey(originalBytes, true, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPublicKey(ArraySegment<byte> originalBytes, bool fOEAP, CancellationToken cancellationToken)
        {
            return EncryptByPublicKeyInternal(originalBytes, fOEAP, cancellationToken);
        }

        protected abstract ICryptoValue EncryptByPublicKeyInternal(ArraySegment<byte> originalBytes, bool fOEAP, CancellationToken cancellationToken);
        
        public virtual ICryptoValue EncryptByPrivateKey(byte[] originalBytes)
        {
            return EncryptByPrivateKey(originalBytes, CancellationToken.None);
        }
        
        public virtual ICryptoValue EncryptByPrivateKey(byte[] originalBytes, CancellationToken cancellationToken)
        {
            if (originalBytes is null)
                throw new ArgumentNullException(nameof(originalBytes));
            return EncryptByPrivateKey(originalBytes, 0, originalBytes.Length, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPrivateKey(byte[] originalBytes, int offset, int count)
        {
            return EncryptByPrivateKey(originalBytes, offset, count, CancellationToken.None);
        }
        
        public virtual ICryptoValue EncryptByPrivateKey(byte[] originalBytes, int offset, int count, CancellationToken cancellationToken)
        {
            if (originalBytes is null)
                throw new ArgumentNullException(nameof(originalBytes));
            if (offset < 0 || offset > originalBytes.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > originalBytes.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            return EncryptByPrivateKey(new ArraySegment<byte>(originalBytes, offset, count), cancellationToken);
        }

        public virtual ICryptoValue EncryptByPrivateKey(string text, Encoding encoding = null)
        {
            return EncryptByPrivateKey(text, encoding, CancellationToken.None);
        }

        public virtual ICryptoValue EncryptByPrivateKey(string text, CancellationToken cancellationToken)
        {
            return EncryptByPrivateKey(text, Encoding.UTF8, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPrivateKey(string text, Encoding encoding, CancellationToken cancellationToken)
        {
            return EncryptByPrivateKey(encoding.SafeEncodingValue().GetBytes(text), cancellationToken);
        }

        public virtual ICryptoValue EncryptByPrivateKey(ArraySegment<byte> originalBytes)
        {
            return EncryptByPrivateKey(originalBytes, CancellationToken.None);
        }

        public virtual ICryptoValue EncryptByPrivateKey(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
            return EncryptByPrivateKeyInternal(originalBytes, cancellationToken);
        }

        protected abstract ICryptoValue EncryptByPrivateKeyInternal(ArraySegment<byte> originalBytes, CancellationToken cancellationToken);
#else

        public virtual ICryptoValue EncryptByPublicKey(byte[] originalBytes)
        {
            return EncryptByPublicKey(originalBytes, RSAEncryptionPadding.Pkcs1);
        }

        public virtual ICryptoValue EncryptByPublicKey(byte[] originalBytes, RSAEncryptionPadding padding)
        {
            return EncryptByPublicKey(originalBytes, padding, CancellationToken.None);
        }

        public virtual ICryptoValue EncryptByPublicKey(byte[] originalBytes, CancellationToken cancellationToken)
        {
            return EncryptByPublicKey(originalBytes, RSAEncryptionPadding.Pkcs1, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPublicKey(byte[] originalBytes, RSAEncryptionPadding padding, CancellationToken cancellationToken)
        {
            if (originalBytes is null)
                throw new ArgumentNullException(nameof(originalBytes));
            return EncryptByPublicKey(originalBytes, 0, originalBytes.Length, padding, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPublicKey(byte[] originalBytes, int offset, int count)
        {
            return EncryptByPublicKey(originalBytes, offset, count, RSAEncryptionPadding.Pkcs1);
        }

        public virtual ICryptoValue EncryptByPublicKey(byte[] originalBytes, int offset, int count, RSAEncryptionPadding padding)
        {
            return EncryptByPublicKey(originalBytes, offset, count, padding, CancellationToken.None);
        }

        public virtual ICryptoValue EncryptByPublicKey(byte[] originalBytes, int offset, int count, CancellationToken cancellationToken)
        {
            return EncryptByPublicKey(originalBytes, offset, count, RSAEncryptionPadding.Pkcs1, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPublicKey(byte[] originalBytes, int offset, int count, RSAEncryptionPadding padding, CancellationToken cancellationToken)
        {
            if (originalBytes is null)
                throw new ArgumentNullException(nameof(originalBytes));
            if (offset < 0 || offset > originalBytes.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > originalBytes.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            if (padding is null)
                throw new ArgumentNullException(nameof(padding));
            return EncryptByPublicKey(new ArraySegment<byte>(originalBytes, offset, count), padding, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPublicKey(string text, Encoding encoding = null)
        {
            return EncryptByPublicKey(text, RSAEncryptionPadding.Pkcs1, encoding);
        }

        public virtual ICryptoValue EncryptByPublicKey(string text, RSAEncryptionPadding padding, Encoding encoding = null)
        {
            return EncryptByPublicKey(text, padding, encoding, CancellationToken.None);
        }

        public virtual ICryptoValue EncryptByPublicKey(string text, CancellationToken cancellationToken)
        {
            return EncryptByPublicKey(text, RSAEncryptionPadding.Pkcs1, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPublicKey(string text, RSAEncryptionPadding padding, CancellationToken cancellationToken)
        {
            return EncryptByPublicKey(text, padding, Encoding.UTF8, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPublicKey(string text, Encoding encoding, CancellationToken cancellationToken)
        {
            return EncryptByPublicKey(text, RSAEncryptionPadding.Pkcs1, encoding, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPublicKey(string text, RSAEncryptionPadding padding, Encoding encoding, CancellationToken cancellationToken)
        {
            return EncryptByPublicKey(encoding.SafeEncodingValue().GetBytes(text), padding, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPublicKey(ArraySegment<byte> originalBytes)
        {
            return EncryptByPublicKey(originalBytes, RSAEncryptionPadding.Pkcs1);
        }

        public virtual ICryptoValue EncryptByPublicKey(ArraySegment<byte> originalBytes, RSAEncryptionPadding padding)
        {
            return EncryptByPublicKey(originalBytes, padding, CancellationToken.None);
        }

        public virtual ICryptoValue EncryptByPublicKey(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
            return EncryptByPublicKey(originalBytes, RSAEncryptionPadding.Pkcs1, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPublicKey(ArraySegment<byte> originalBytes, RSAEncryptionPadding padding, CancellationToken cancellationToken)
        {
            return EncryptByPublicKeyInternal(originalBytes, padding, cancellationToken);
        }

        protected abstract ICryptoValue EncryptByPublicKeyInternal(ArraySegment<byte> originalBytes, RSAEncryptionPadding padding, CancellationToken cancellationToken);

        public virtual ICryptoValue EncryptByPrivateKey(byte[] originalBytes)
        {
            return EncryptByPrivateKey(originalBytes, RSAEncryptionPadding.Pkcs1);
        }

        public virtual ICryptoValue EncryptByPrivateKey(byte[] originalBytes, RSAEncryptionPadding padding)
        {
            return EncryptByPrivateKey(originalBytes, padding, CancellationToken.None);
        }

        public virtual ICryptoValue EncryptByPrivateKey(byte[] originalBytes, CancellationToken cancellationToken)
        {
            return EncryptByPrivateKey(originalBytes, RSAEncryptionPadding.Pkcs1, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPrivateKey(byte[] originalBytes, RSAEncryptionPadding padding, CancellationToken cancellationToken)
        {
            if (originalBytes is null)
                throw new ArgumentNullException(nameof(originalBytes));
            return EncryptByPrivateKey(originalBytes, 0, originalBytes.Length, padding, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPrivateKey(byte[] originalBytes, int offset, int count)
        {
            return EncryptByPrivateKey(originalBytes, offset, count, RSAEncryptionPadding.Pkcs1);
        }

        public virtual ICryptoValue EncryptByPrivateKey(byte[] originalBytes, int offset, int count, RSAEncryptionPadding padding)
        {
            return EncryptByPrivateKey(originalBytes, offset, count, padding, CancellationToken.None);
        }

        public virtual ICryptoValue EncryptByPrivateKey(byte[] originalBytes, int offset, int count, CancellationToken cancellationToken)
        {
            return EncryptByPrivateKey(originalBytes, offset, count, RSAEncryptionPadding.Pkcs1, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPrivateKey(byte[] originalBytes, int offset, int count, RSAEncryptionPadding padding, CancellationToken cancellationToken)
        {
            if (originalBytes is null)
                throw new ArgumentNullException(nameof(originalBytes));
            if (offset < 0 || offset > originalBytes.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > originalBytes.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            if (padding is null)
                throw new ArgumentNullException(nameof(padding));
            return EncryptByPrivateKey(new ArraySegment<byte>(originalBytes, offset, count), padding, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPrivateKey(string text, Encoding encoding = null)
        {
            return EncryptByPrivateKey(text, RSAEncryptionPadding.Pkcs1, encoding);
        }

        public virtual ICryptoValue EncryptByPrivateKey(string text, RSAEncryptionPadding padding, Encoding encoding = null)
        {
            return EncryptByPrivateKey(text, padding, encoding, CancellationToken.None);
        }

        public virtual ICryptoValue EncryptByPrivateKey(string text, CancellationToken cancellationToken)
        {
            return EncryptByPrivateKey(text, RSAEncryptionPadding.Pkcs1, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPrivateKey(string text, RSAEncryptionPadding padding, CancellationToken cancellationToken)
        {
            return EncryptByPrivateKey(text, padding, Encoding.UTF8, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPrivateKey(string text, Encoding encoding, CancellationToken cancellationToken)
        {
            return EncryptByPrivateKey(text, RSAEncryptionPadding.Pkcs1, encoding, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPrivateKey(string text, RSAEncryptionPadding padding, Encoding encoding, CancellationToken cancellationToken)
        {
            return EncryptByPrivateKey(encoding.SafeEncodingValue().GetBytes(text), padding, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPrivateKey(ArraySegment<byte> originalBytes)
        {
            return EncryptByPrivateKey(originalBytes, RSAEncryptionPadding.Pkcs1);
        }

        public virtual ICryptoValue EncryptByPrivateKey(ArraySegment<byte> originalBytes, RSAEncryptionPadding padding)
        {
            return EncryptByPrivateKey(originalBytes, padding, CancellationToken.None);
        }

        public virtual ICryptoValue EncryptByPrivateKey(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
            return EncryptByPrivateKey(originalBytes, RSAEncryptionPadding.Pkcs1, cancellationToken);
        }

        public virtual ICryptoValue EncryptByPrivateKey(ArraySegment<byte> originalBytes, RSAEncryptionPadding padding, CancellationToken cancellationToken)
        {
            return EncryptByPrivateKeyInternal(originalBytes, padding, cancellationToken);
        }

        protected abstract ICryptoValue EncryptByPrivateKeyInternal(ArraySegment<byte> originalBytes, RSAEncryptionPadding padding, CancellationToken cancellationToken);
#endif
    }
}