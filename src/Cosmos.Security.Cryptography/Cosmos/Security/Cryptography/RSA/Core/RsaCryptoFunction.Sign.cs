using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Cosmos.Optionals;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Cryptography
{
    internal abstract partial class RsaCryptoFunction
    {
#if NET451 || NET452
        public virtual ISignValue SignByPublicKey(byte[] buffer)
        {
            return SignByPublicKey(buffer, HashAlgorithmName.MD5);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, HashAlgorithmName hashAlgorithmName)
        {
            return SignByPublicKey(buffer, hashAlgorithmName, CancellationToken.None);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, CancellationToken cancellationToken)
        {
            return SignByPublicKey(buffer, HashAlgorithmName.MD5, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            return SignByPublicKey(buffer, 0, buffer.Length, hashAlgorithmName, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, int offset, int count)
        {
            return SignByPublicKey(buffer, offset, count, HashAlgorithmName.MD5);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName)
        {
            return SignByPublicKey(buffer, offset, count, hashAlgorithmName, CancellationToken.None);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return SignByPublicKey(buffer, offset, count, HashAlgorithmName.MD5, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || offset > buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            return SignByPublicKey(new ArraySegment<byte>(buffer, offset, count), hashAlgorithmName, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(string text, Encoding encoding = null)
        {
            return SignByPublicKey(text, HashAlgorithmName.MD5, encoding);
        }

        public virtual ISignValue SignByPublicKey(string text, HashAlgorithmName hashAlgorithmName, Encoding encoding = null)
        {
            return SignByPublicKey(text, hashAlgorithmName, encoding, CancellationToken.None);
        }

        public virtual ISignValue SignByPublicKey(string text, CancellationToken cancellationToken)
        {
            return SignByPublicKey(text, HashAlgorithmName.MD5, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(string text, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            return SignByPublicKey(text, hashAlgorithmName, Encoding.UTF8, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(string text, Encoding encoding, CancellationToken cancellationToken)
        {
            return SignByPublicKey(text, HashAlgorithmName.MD5, encoding, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(string text, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken)
        {
            return SignByPublicKey(encoding.SafeEncodingValue().GetBytes(text), hashAlgorithmName, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(ArraySegment<byte> buffer)
        {
            return SignByPublicKey(buffer, HashAlgorithmName.MD5);
        }

        public virtual ISignValue SignByPublicKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName)
        {
            return SignByPublicKey(buffer, hashAlgorithmName, CancellationToken.None);
        }

        public virtual ISignValue SignByPublicKey(ArraySegment<byte> buffer, CancellationToken cancellationToken)
        {
            return SignByPublicKey(buffer, HashAlgorithmName.MD5, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            return SignByPublicKeyInternal(buffer, hashAlgorithmName, cancellationToken);
        }

        protected abstract ISignValue SignByPublicKeyInternal(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        public virtual ISignValue SignByPrivateKey(byte[] buffer)
        {
            return SignByPrivateKey(buffer, HashAlgorithmName.MD5);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, HashAlgorithmName hashAlgorithmName)
        {
            return SignByPrivateKey(buffer, hashAlgorithmName, CancellationToken.None);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(buffer, HashAlgorithmName.MD5, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            return SignByPrivateKey(buffer, 0, buffer.Length, hashAlgorithmName, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, int offset, int count)
        {
            return SignByPrivateKey(buffer, offset, count, HashAlgorithmName.MD5);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName)
        {
            return SignByPrivateKey(buffer, offset, count, hashAlgorithmName, CancellationToken.None);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(buffer, offset, count, HashAlgorithmName.MD5, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || offset > buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            return SignByPrivateKey(new ArraySegment<byte>(buffer, offset, count), hashAlgorithmName, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(string text, Encoding encoding = null)
        {
            return SignByPrivateKey(text, HashAlgorithmName.MD5, encoding);
        }

        public virtual ISignValue SignByPrivateKey(string text, HashAlgorithmName hashAlgorithmName, Encoding encoding = null)
        {
            return SignByPrivateKey(text, hashAlgorithmName, encoding, CancellationToken.None);
        }

        public virtual ISignValue SignByPrivateKey(string text, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(text, HashAlgorithmName.MD5, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(string text, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(text, hashAlgorithmName, Encoding.UTF8, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(string text, Encoding encoding, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(text, HashAlgorithmName.MD5, encoding, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(string text, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(encoding.SafeEncodingValue().GetBytes(text), hashAlgorithmName, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(ArraySegment<byte> buffer)
        {
            return SignByPrivateKey(buffer, HashAlgorithmName.MD5);
        }

        public virtual ISignValue SignByPrivateKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName)
        {
            return SignByPrivateKey(buffer, hashAlgorithmName, CancellationToken.None);
        }

        public virtual ISignValue SignByPrivateKey(ArraySegment<byte> buffer, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(buffer, HashAlgorithmName.MD5, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            return SignByPrivateKeyInternal(buffer, hashAlgorithmName, cancellationToken);
        }

        protected abstract ISignValue SignByPrivateKeyInternal(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

#else
        public virtual ISignValue SignByPublicKey(byte[] buffer)
        {
            return SignByPublicKey(buffer, RSASignaturePadding.Pkcs1);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, RSASignaturePadding padding)
        {
            return SignByPublicKey(buffer, HashAlgorithmName.MD5, padding);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, HashAlgorithmName hashAlgorithmName)
        {
            return SignByPublicKey(buffer, hashAlgorithmName, RSASignaturePadding.Pkcs1);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            return SignByPublicKey(buffer, hashAlgorithmName, padding, CancellationToken.None);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, CancellationToken cancellationToken)
        {
            return SignByPublicKey(buffer, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return SignByPublicKey(buffer, HashAlgorithmName.MD5, padding, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            return SignByPublicKey(buffer, hashAlgorithmName, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            return SignByPublicKey(buffer, 0, buffer.Length, hashAlgorithmName, padding, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, int offset, int count)
        {
            return SignByPublicKey(buffer, offset, count, RSASignaturePadding.Pkcs1);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, int offset, int count, RSASignaturePadding padding)
        {
            return SignByPublicKey(buffer, offset, count, HashAlgorithmName.MD5, padding);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName)
        {
            return SignByPublicKey(buffer, offset, count, hashAlgorithmName, RSASignaturePadding.Pkcs1, CancellationToken.None);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            return SignByPublicKey(buffer, offset, count, hashAlgorithmName, padding, CancellationToken.None);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return SignByPublicKey(buffer, offset, count, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, int offset, int count, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return SignByPublicKey(buffer, offset, count, HashAlgorithmName.MD5, padding, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            return SignByPublicKey(buffer, offset, count, hashAlgorithmName, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || offset > buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            if (padding is null)
                throw new ArgumentNullException(nameof(padding));
            return SignByPublicKey(new ArraySegment<byte>(buffer, offset, count), hashAlgorithmName, padding, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(string text, Encoding encoding = null)
        {
            return SignByPublicKey(text, RSASignaturePadding.Pkcs1, encoding);
        }

        public virtual ISignValue SignByPublicKey(string text, RSASignaturePadding padding, Encoding encoding = null)
        {
            return SignByPublicKey(text, HashAlgorithmName.MD5, padding, encoding);
        }

        public virtual ISignValue SignByPublicKey(string text, HashAlgorithmName hashAlgorithmName, Encoding encoding = null)
        {
            return SignByPublicKey(text, hashAlgorithmName, RSASignaturePadding.Pkcs1, encoding);
        }

        public virtual ISignValue SignByPublicKey(string text, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding = null)
        {
            return SignByPublicKey(text, hashAlgorithmName, padding, encoding, CancellationToken.None);
        }

        public virtual ISignValue SignByPublicKey(string text, CancellationToken cancellationToken)
        {
            return SignByPublicKey(text, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(string text, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return SignByPublicKey(text, HashAlgorithmName.MD5, padding, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(string text, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            return SignByPublicKey(text, hashAlgorithmName, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(string text, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return SignByPublicKey(text, hashAlgorithmName, padding, Encoding.UTF8, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(string text, Encoding encoding, CancellationToken cancellationToken)
        {
            return SignByPublicKey(text, RSASignaturePadding.Pkcs1, encoding, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(string text, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken)
        {
            return SignByPublicKey(text, HashAlgorithmName.MD5, padding, encoding, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(string text, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken)
        {
            return SignByPublicKey(text, hashAlgorithmName, RSASignaturePadding.Pkcs1, encoding, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(string text, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken)
        {
            return SignByPublicKey(encoding.SafeEncodingValue().GetBytes(text), hashAlgorithmName, padding, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(ArraySegment<byte> buffer)
        {
            return SignByPublicKey(buffer, RSASignaturePadding.Pkcs1);
        }

        public virtual ISignValue SignByPublicKey(ArraySegment<byte> buffer, RSASignaturePadding padding)
        {
            return SignByPublicKey(buffer, HashAlgorithmName.MD5, padding);
        }

        public virtual ISignValue SignByPublicKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName)
        {
            return SignByPublicKey(buffer, hashAlgorithmName, RSASignaturePadding.Pkcs1);
        }

        public virtual ISignValue SignByPublicKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            return SignByPublicKey(buffer, hashAlgorithmName, padding, CancellationToken.None);
        }

        public virtual ISignValue SignByPublicKey(ArraySegment<byte> buffer, CancellationToken cancellationToken)
        {
            return SignByPublicKey(buffer, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(ArraySegment<byte> buffer, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return SignByPublicKey(buffer, HashAlgorithmName.MD5, padding, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            return SignByPublicKey(buffer, hashAlgorithmName, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual ISignValue SignByPublicKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return SignByPublicKeyInternal(buffer, hashAlgorithmName, padding, cancellationToken);
        }

        protected abstract ISignValue SignByPublicKeyInternal(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken);

        public virtual ISignValue SignByPrivateKey(byte[] buffer)
        {
            return SignByPrivateKey(buffer, RSASignaturePadding.Pkcs1);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, RSASignaturePadding padding)
        {
            return SignByPrivateKey(buffer, HashAlgorithmName.MD5, padding);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, HashAlgorithmName hashAlgorithmName)
        {
            return SignByPrivateKey(buffer, hashAlgorithmName, RSASignaturePadding.Pkcs1);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            return SignByPrivateKey(buffer, hashAlgorithmName, padding, CancellationToken.None);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(buffer, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(buffer, HashAlgorithmName.MD5, padding, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            return SignByPrivateKey(buffer, hashAlgorithmName, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            return SignByPrivateKey(buffer, 0, buffer.Length, hashAlgorithmName, padding, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, int offset, int count)
        {
            return SignByPrivateKey(buffer, offset, count, RSASignaturePadding.Pkcs1);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, RSASignaturePadding padding)
        {
            return SignByPrivateKey(buffer, offset, count, HashAlgorithmName.MD5, padding);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName)
        {
            return SignByPrivateKey(buffer, offset, count, hashAlgorithmName, RSASignaturePadding.Pkcs1, CancellationToken.None);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            return SignByPrivateKey(buffer, offset, count, hashAlgorithmName, padding, CancellationToken.None);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(buffer, offset, count, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(buffer, offset, count, HashAlgorithmName.MD5, padding, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(buffer, offset, count, hashAlgorithmName, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || offset > buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            if (padding is null)
                throw new ArgumentNullException(nameof(padding));
            return SignByPrivateKey(new ArraySegment<byte>(buffer, offset, count), hashAlgorithmName, padding, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(string text, Encoding encoding = null)
        {
            return SignByPrivateKey(text, RSASignaturePadding.Pkcs1, encoding);
        }

        public virtual ISignValue SignByPrivateKey(string text, RSASignaturePadding padding, Encoding encoding = null)
        {
            return SignByPrivateKey(text, HashAlgorithmName.MD5, padding, encoding);
        }

        public virtual ISignValue SignByPrivateKey(string text, HashAlgorithmName hashAlgorithmName, Encoding encoding = null)
        {
            return SignByPrivateKey(text, hashAlgorithmName, RSASignaturePadding.Pkcs1, encoding);
        }

        public virtual ISignValue SignByPrivateKey(string text, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding = null)
        {
            return SignByPrivateKey(text, hashAlgorithmName, padding, encoding, CancellationToken.None);
        }

        public virtual ISignValue SignByPrivateKey(string text, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(text, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(string text, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(text, HashAlgorithmName.MD5, padding, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(string text, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(text, hashAlgorithmName, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(string text, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(text, hashAlgorithmName, padding, Encoding.UTF8, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(string text, Encoding encoding, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(text, RSASignaturePadding.Pkcs1, encoding, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(string text, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(text, HashAlgorithmName.MD5, padding, encoding, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(string text, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(text, hashAlgorithmName, RSASignaturePadding.Pkcs1, encoding, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(string text, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(encoding.SafeEncodingValue().GetBytes(text), hashAlgorithmName, padding, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(ArraySegment<byte> buffer)
        {
            return SignByPrivateKey(buffer, RSASignaturePadding.Pkcs1);
        }

        public virtual ISignValue SignByPrivateKey(ArraySegment<byte> buffer, RSASignaturePadding padding)
        {
            return SignByPrivateKey(buffer, HashAlgorithmName.MD5, padding);
        }

        public virtual ISignValue SignByPrivateKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName)
        {
            return SignByPrivateKey(buffer, hashAlgorithmName, RSASignaturePadding.Pkcs1);
        }

        public virtual ISignValue SignByPrivateKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            return SignByPrivateKey(buffer, hashAlgorithmName, padding, CancellationToken.None);
        }

        public virtual ISignValue SignByPrivateKey(ArraySegment<byte> buffer, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(buffer, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(ArraySegment<byte> buffer, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(buffer, HashAlgorithmName.MD5, padding, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            return SignByPrivateKey(buffer, hashAlgorithmName, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual ISignValue SignByPrivateKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return SignByPrivateKeyInternal(buffer, hashAlgorithmName, padding, cancellationToken);
        }

        protected abstract ISignValue SignByPrivateKeyInternal(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken);
#endif
    }
}