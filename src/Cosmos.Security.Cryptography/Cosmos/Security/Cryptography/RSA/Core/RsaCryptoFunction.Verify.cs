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
        public virtual bool VerifyByPublicKey(byte[] buffer, byte[] signature)
        {
            return VerifyByPublicKey(buffer, signature, HashAlgorithmName.MD5);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName)
        {
            return VerifyByPublicKey(buffer, signature, hashAlgorithmName, CancellationToken.None);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, byte[] signature, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(buffer, signature, HashAlgorithmName.MD5, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            return VerifyByPublicKey(buffer, 0, buffer.Length, signature, hashAlgorithmName, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature)
        {
            return VerifyByPublicKey(buffer, offset, count, signature, HashAlgorithmName.MD5);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName)
        {
            return VerifyByPublicKey(buffer, offset, count, signature, hashAlgorithmName, CancellationToken.None);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(buffer, offset, count, signature, HashAlgorithmName.MD5, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || offset > buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            return VerifyByPublicKey(new ArraySegment<byte>(buffer, offset, count), signature, hashAlgorithmName, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(string text, string signature, Encoding encoding = null)
        {
            return VerifyByPublicKey(text, signature, HashAlgorithmName.MD5, encoding);
        }

        public virtual bool VerifyByPublicKey(string text, string signature, HashAlgorithmName hashAlgorithmName, Encoding encoding = null)
        {
            return VerifyByPublicKey(text, signature, hashAlgorithmName, encoding, CancellationToken.None);
        }

        public virtual bool VerifyByPublicKey(string text, string signature, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(text, signature, HashAlgorithmName.MD5, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(string text, string signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(text, signature, hashAlgorithmName, Encoding.UTF8, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(string text, string signature, Encoding encoding, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(text, signature, HashAlgorithmName.MD5, encoding, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(string text, string signature, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken)
        {
            encoding = encoding.SafeEncodingValue();
            return VerifyByPublicKey(encoding.GetBytes(text), encoding.GetBytes(signature), hashAlgorithmName, cancellationToken);
        }

        public bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPublicKey(text, signature, signatureTextType, HashAlgorithmName.MD5, encoding, CancellationToken.None, customSignatureTextConverter);
        }

        public bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPublicKey(text, signature, signatureTextType, hashAlgorithmName, encoding, CancellationToken.None, customSignatureTextConverter);
        }

        public bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPublicKey(text, signature, signatureTextType, HashAlgorithmName.MD5, Encoding.UTF8, cancellationToken, customSignatureTextConverter);
        }

        public bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPublicKey(text, signature, signatureTextType, hashAlgorithmName, Encoding.UTF8, cancellationToken, customSignatureTextConverter);
        }

        public bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPublicKey(text, signature, signatureTextType, HashAlgorithmName.MD5, encoding, cancellationToken, customSignatureTextConverter);
        }

        public bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken,
            Func<string, byte[]> customSignatureTextConverter = null)
        {
            encoding = encoding.SafeEncodingValue();

            var finalSignature = signatureTextType.GetBytes(signature, encoding, customSignatureTextConverter);

            return VerifyByPublicKey(encoding.GetBytes(text), finalSignature, hashAlgorithmName, CancellationToken.None);
        }

        public virtual bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature)
        {
            return VerifyByPublicKey(buffer, signature, HashAlgorithmName.MD5);
        }

        public virtual bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName)
        {
            return VerifyByPublicKey(buffer, signature, hashAlgorithmName, CancellationToken.None);
        }

        public virtual bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(buffer, signature, HashAlgorithmName.MD5, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            return VerifyByPublicKeyInternal(buffer, signature, hashAlgorithmName, cancellationToken);
        }

        protected abstract bool VerifyByPublicKeyInternal(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        public virtual bool VerifyByPrivateKey(byte[] buffer, byte[] signature)
        {
            return VerifyByPrivateKey(buffer, signature, HashAlgorithmName.MD5);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName)
        {
            return VerifyByPrivateKey(buffer, signature, hashAlgorithmName, CancellationToken.None);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, byte[] signature, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(buffer, signature, HashAlgorithmName.MD5, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            return VerifyByPrivateKey(buffer, 0, buffer.Length, signature, hashAlgorithmName, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature)
        {
            return VerifyByPrivateKey(buffer, offset, count, signature, HashAlgorithmName.MD5);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName)
        {
            return VerifyByPrivateKey(buffer, offset, count, signature, hashAlgorithmName, CancellationToken.None);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(buffer, offset, count, signature, HashAlgorithmName.MD5, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || offset > buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            return VerifyByPrivateKey(new ArraySegment<byte>(buffer, offset, count), signature, hashAlgorithmName, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(string text, string signature, Encoding encoding = null)
        {
            return VerifyByPrivateKey(text, signature, HashAlgorithmName.MD5, encoding);
        }

        public virtual bool VerifyByPrivateKey(string text, string signature, HashAlgorithmName hashAlgorithmName, Encoding encoding = null)
        {
            return VerifyByPrivateKey(text, signature, hashAlgorithmName, encoding, CancellationToken.None);
        }

        public virtual bool VerifyByPrivateKey(string text, string signature, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(text, signature, HashAlgorithmName.MD5, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(string text, string signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(text, signature, hashAlgorithmName, Encoding.UTF8, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(string text, string signature, Encoding encoding, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(text, signature, HashAlgorithmName.MD5, encoding, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(string text, string signature, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken)
        {
            encoding = encoding.SafeEncodingValue();
            return VerifyByPrivateKey(encoding.GetBytes(text), encoding.GetBytes(signature), hashAlgorithmName, cancellationToken);
        }

        public bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPrivateKey(text, signature, signatureTextType, HashAlgorithmName.MD5, encoding, CancellationToken.None, customSignatureTextConverter);
        }

        public bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPrivateKey(text, signature, signatureTextType, hashAlgorithmName, encoding, CancellationToken.None, customSignatureTextConverter);
        }

        public bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPrivateKey(text, signature, signatureTextType, HashAlgorithmName.MD5, Encoding.UTF8, cancellationToken, customSignatureTextConverter);
        }

        public bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPrivateKey(text, signature, signatureTextType, hashAlgorithmName, Encoding.UTF8, cancellationToken, customSignatureTextConverter);
        }

        public bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPrivateKey(text, signature, signatureTextType, HashAlgorithmName.MD5, encoding, cancellationToken, customSignatureTextConverter);
        }

        public bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken,
            Func<string, byte[]> customSignatureTextConverter = null)
        {
            encoding = encoding.SafeEncodingValue();

            var finalSignature = signatureTextType.GetBytes(signature, encoding, customSignatureTextConverter);

            return VerifyByPrivateKey(encoding.GetBytes(text), finalSignature, hashAlgorithmName, CancellationToken.None);
        }

        public virtual bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature)
        {
            return VerifyByPrivateKey(buffer, signature, HashAlgorithmName.MD5);
        }

        public virtual bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName)
        {
            return VerifyByPrivateKey(buffer, signature, hashAlgorithmName, CancellationToken.None);
        }

        public virtual bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(buffer, signature, HashAlgorithmName.MD5, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKeyInternal(buffer, signature, hashAlgorithmName, cancellationToken);
        }

        protected abstract bool VerifyByPrivateKeyInternal(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);
#else
        public virtual bool VerifyByPublicKey(byte[] buffer, byte[] signature)
        {
            return VerifyByPublicKey(buffer, signature, RSASignaturePadding.Pkcs1);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, byte[] signature, RSASignaturePadding padding)
        {
            return VerifyByPublicKey(buffer, signature, HashAlgorithmName.MD5, padding);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName)
        {
            return VerifyByPublicKey(buffer, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            return VerifyByPublicKey(buffer, signature, hashAlgorithmName, padding, CancellationToken.None);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, byte[] signature, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(buffer, signature, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, byte[] signature, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(buffer, signature, HashAlgorithmName.MD5, padding, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            return VerifyByPublicKey(buffer, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            return VerifyByPublicKey(buffer, 0, buffer.Length, signature, hashAlgorithmName, padding, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature)
        {
            return VerifyByPublicKey(buffer, offset, count, signature, RSASignaturePadding.Pkcs1);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, RSASignaturePadding padding)
        {
            return VerifyByPublicKey(buffer, offset, count, signature, HashAlgorithmName.MD5, padding);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName)
        {
            return VerifyByPublicKey(buffer, offset, count, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1, CancellationToken.None);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            return VerifyByPublicKey(buffer, offset, count, signature, hashAlgorithmName, padding, CancellationToken.None);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(buffer, offset, count, signature, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(buffer, offset, count, signature, HashAlgorithmName.MD5, padding, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(buffer, offset, count, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || offset > buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            if (padding is null)
                throw new ArgumentNullException(nameof(padding));
            return VerifyByPublicKey(new ArraySegment<byte>(buffer, offset, count), signature, hashAlgorithmName, padding, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(string text, string signature, Encoding encoding = null)
        {
            return VerifyByPublicKey(text, signature, RSASignaturePadding.Pkcs1, encoding);
        }

        public virtual bool VerifyByPublicKey(string text, string signature, RSASignaturePadding padding, Encoding encoding = null)
        {
            return VerifyByPublicKey(text, signature, HashAlgorithmName.MD5, padding, encoding);
        }

        public virtual bool VerifyByPublicKey(string text, string signature, HashAlgorithmName hashAlgorithmName, Encoding encoding = null)
        {
            return VerifyByPublicKey(text, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1, encoding);
        }

        public virtual bool VerifyByPublicKey(string text, string signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding = null)
        {
            return VerifyByPublicKey(text, signature, hashAlgorithmName, padding, encoding, CancellationToken.None);
        }

        public virtual bool VerifyByPublicKey(string text, string signature, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(text, signature, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(string text, string signature, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(text, signature, HashAlgorithmName.MD5, padding, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(string text, string signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(text, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(string text, string signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(text, signature, hashAlgorithmName, padding, Encoding.UTF8, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(string text, string signature, Encoding encoding, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(text, signature, RSASignaturePadding.Pkcs1, encoding, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(string text, string signature, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(text, signature, HashAlgorithmName.MD5, padding, encoding, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(string text, string signature, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(text, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1, encoding, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(string text, string signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken)
        {
            encoding = encoding.SafeEncodingValue();
            return VerifyByPublicKey(encoding.GetBytes(text), encoding.GetBytes(signature), hashAlgorithmName, padding, cancellationToken);
        }

        public bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPublicKey(text, signature, signatureTextType, RSASignaturePadding.Pkcs1, encoding, customSignatureTextConverter);
        }

        public bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, RSASignaturePadding padding, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPublicKey(text, signature, signatureTextType, HashAlgorithmName.MD5, padding, encoding, customSignatureTextConverter);
        }

        public bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPublicKey(text, signature, signatureTextType, hashAlgorithmName, RSASignaturePadding.Pkcs1, encoding, customSignatureTextConverter);
        }

        public bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding = null,
            Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPublicKey(text, signature, signatureTextType, hashAlgorithmName, padding, encoding, CancellationToken.None, customSignatureTextConverter);
        }

        public bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPublicKey(text, signature, signatureTextType, RSASignaturePadding.Pkcs1, cancellationToken, customSignatureTextConverter);
        }

        public bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, RSASignaturePadding padding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPublicKey(text, signature, signatureTextType, HashAlgorithmName.MD5, padding, Encoding.UTF8, cancellationToken, customSignatureTextConverter);
        }

        public bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPublicKey(text, signature, signatureTextType, hashAlgorithmName, RSASignaturePadding.Pkcs1, Encoding.UTF8, cancellationToken, customSignatureTextConverter);
        }

        public bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken,
            Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPublicKey(text, signature, signatureTextType, hashAlgorithmName, padding, Encoding.UTF8, cancellationToken, customSignatureTextConverter);
        }

        public bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPublicKey(text, signature, signatureTextType, HashAlgorithmName.MD5, RSASignaturePadding.Pkcs1, encoding, cancellationToken, customSignatureTextConverter);
        }

        public bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPublicKey(text, signature, signatureTextType, HashAlgorithmName.MD5, padding, encoding, cancellationToken, customSignatureTextConverter);
        }

        public bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken,
            Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPublicKey(text, signature, signatureTextType, hashAlgorithmName, RSASignaturePadding.Pkcs1, encoding, cancellationToken, customSignatureTextConverter);
        }

        public bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken,
            Func<string, byte[]> customSignatureTextConverter = null)
        {
            encoding = encoding.SafeEncodingValue();

            var finalSignature = signatureTextType.GetBytes(signature, encoding, customSignatureTextConverter);

            return VerifyByPublicKey(encoding.GetBytes(text), finalSignature, hashAlgorithmName, padding, CancellationToken.None);
        }

        public virtual bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature)
        {
            return VerifyByPublicKey(buffer, signature, RSASignaturePadding.Pkcs1);
        }

        public virtual bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, RSASignaturePadding padding)
        {
            return VerifyByPublicKey(buffer, signature, HashAlgorithmName.MD5, padding);
        }

        public virtual bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName)
        {
            return VerifyByPublicKey(buffer, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1);
        }

        public virtual bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            return VerifyByPublicKey(buffer, signature, hashAlgorithmName, padding, CancellationToken.None);
        }

        public virtual bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(buffer, signature, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(buffer, signature, HashAlgorithmName.MD5, padding, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            return VerifyByPublicKey(buffer, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return VerifyByPublicKeyInternal(buffer, signature, hashAlgorithmName, padding, cancellationToken);
        }

        protected abstract bool VerifyByPublicKeyInternal(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken);

        public virtual bool VerifyByPrivateKey(byte[] buffer, byte[] signature)
        {
            return VerifyByPrivateKey(buffer, signature, RSASignaturePadding.Pkcs1);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, byte[] signature, RSASignaturePadding padding)
        {
            return VerifyByPrivateKey(buffer, signature, HashAlgorithmName.MD5, padding);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName)
        {
            return VerifyByPrivateKey(buffer, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            return VerifyByPrivateKey(buffer, signature, hashAlgorithmName, padding, CancellationToken.None);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, byte[] signature, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(buffer, signature, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, byte[] signature, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(buffer, signature, HashAlgorithmName.MD5, padding, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            return VerifyByPrivateKey(buffer, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            return VerifyByPrivateKey(buffer, 0, buffer.Length, signature, hashAlgorithmName, padding, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature)
        {
            return VerifyByPrivateKey(buffer, offset, count, signature, RSASignaturePadding.Pkcs1);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, RSASignaturePadding padding)
        {
            return VerifyByPrivateKey(buffer, offset, count, signature, HashAlgorithmName.MD5, padding);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName)
        {
            return VerifyByPrivateKey(buffer, offset, count, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1, CancellationToken.None);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            return VerifyByPrivateKey(buffer, offset, count, signature, hashAlgorithmName, padding, CancellationToken.None);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(buffer, offset, count, signature, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(buffer, offset, count, signature, HashAlgorithmName.MD5, padding, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(buffer, offset, count, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || offset > buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            if (padding is null)
                throw new ArgumentNullException(nameof(padding));
            return VerifyByPrivateKey(new ArraySegment<byte>(buffer, offset, count), signature, hashAlgorithmName, padding, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(string text, string signature, Encoding encoding = null)
        {
            return VerifyByPrivateKey(text, signature, RSASignaturePadding.Pkcs1, encoding);
        }

        public virtual bool VerifyByPrivateKey(string text, string signature, RSASignaturePadding padding, Encoding encoding = null)
        {
            return VerifyByPrivateKey(text, signature, HashAlgorithmName.MD5, padding, encoding);
        }

        public virtual bool VerifyByPrivateKey(string text, string signature, HashAlgorithmName hashAlgorithmName, Encoding encoding = null)
        {
            return VerifyByPrivateKey(text, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1, encoding);
        }

        public virtual bool VerifyByPrivateKey(string text, string signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding = null)
        {
            return VerifyByPrivateKey(text, signature, hashAlgorithmName, padding, encoding, CancellationToken.None);
        }

        public virtual bool VerifyByPrivateKey(string text, string signature, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(text, signature, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(string text, string signature, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(text, signature, HashAlgorithmName.MD5, padding, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(string text, string signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(text, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(string text, string signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(text, signature, hashAlgorithmName, padding, Encoding.UTF8, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(string text, string signature, Encoding encoding, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(text, signature, RSASignaturePadding.Pkcs1, encoding, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(string text, string signature, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(text, signature, HashAlgorithmName.MD5, padding, encoding, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(string text, string signature, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(text, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1, encoding, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(string text, string signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken)
        {
            encoding = encoding.SafeEncodingValue();
            return VerifyByPrivateKey(encoding.GetBytes(text), encoding.GetBytes(signature), hashAlgorithmName, padding, cancellationToken);
        }

        public bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPrivateKey(text, signature, signatureTextType, HashAlgorithmName.MD5, RSASignaturePadding.Pkcs1, encoding, CancellationToken.None, customSignatureTextConverter);
        }

        public bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, RSASignaturePadding padding, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPrivateKey(text, signature, signatureTextType, HashAlgorithmName.MD5, padding, encoding, CancellationToken.None, customSignatureTextConverter);
        }

        public bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPrivateKey(text, signature, signatureTextType, hashAlgorithmName, RSASignaturePadding.Pkcs1, encoding, CancellationToken.None, customSignatureTextConverter);
        }

        public bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding = null,
            Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPrivateKey(text, signature, signatureTextType, hashAlgorithmName, padding, encoding, CancellationToken.None, customSignatureTextConverter);
        }

        public bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPrivateKey(text, signature, signatureTextType, HashAlgorithmName.MD5, RSASignaturePadding.Pkcs1, Encoding.UTF8, cancellationToken, customSignatureTextConverter);
        }

        public bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, RSASignaturePadding padding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPrivateKey(text, signature, signatureTextType, HashAlgorithmName.MD5, padding, Encoding.UTF8, cancellationToken, customSignatureTextConverter);
        }

        public bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPrivateKey(text, signature, signatureTextType, hashAlgorithmName, RSASignaturePadding.Pkcs1, Encoding.UTF8, cancellationToken, customSignatureTextConverter);
        }

        public bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken,
            Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPrivateKey(text, signature, signatureTextType, hashAlgorithmName, padding, Encoding.UTF8, cancellationToken, customSignatureTextConverter);
        }

        public bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPrivateKey(text, signature, signatureTextType, HashAlgorithmName.MD5, RSASignaturePadding.Pkcs1, encoding, cancellationToken, customSignatureTextConverter);
        }

        public bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPrivateKey(text, signature, signatureTextType, HashAlgorithmName.MD5, padding, encoding, cancellationToken, customSignatureTextConverter);
        }

        public bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken,
            Func<string, byte[]> customSignatureTextConverter = null)
        {
            return VerifyByPrivateKey(text, signature, signatureTextType, hashAlgorithmName, RSASignaturePadding.Pkcs1, encoding, cancellationToken, customSignatureTextConverter);
        }

        public bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken,
            Func<string, byte[]> customSignatureTextConverter = null)
        {
            encoding = encoding.SafeEncodingValue();

            var finalSignature = signatureTextType.GetBytes(signature, encoding, customSignatureTextConverter);

            return VerifyByPrivateKey(encoding.GetBytes(text), finalSignature, hashAlgorithmName, padding, CancellationToken.None);
        }

        public virtual bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature)
        {
            return VerifyByPrivateKey(buffer, signature, RSASignaturePadding.Pkcs1);
        }

        public virtual bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, RSASignaturePadding padding)
        {
            return VerifyByPrivateKey(buffer, signature, HashAlgorithmName.MD5, padding);
        }

        public virtual bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName)
        {
            return VerifyByPrivateKey(buffer, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1);
        }

        public virtual bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            return VerifyByPrivateKey(buffer, signature, hashAlgorithmName, padding, CancellationToken.None);
        }

        public virtual bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(buffer, signature, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(buffer, signature, HashAlgorithmName.MD5, padding, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKey(buffer, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1, cancellationToken);
        }

        public virtual bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            return VerifyByPrivateKeyInternal(buffer, signature, hashAlgorithmName, padding, cancellationToken);
        }

        protected abstract bool VerifyByPrivateKeyInternal(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken);
#endif
    }
}