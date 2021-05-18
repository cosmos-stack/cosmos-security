#if NET451 || NET452
using System;
using System.Text;
using System.Threading;
using Cosmos.Conversions;
#else
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Cosmos.Conversions;
#endif
using Cosmos.Optionals;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Cryptography
{
    internal abstract partial class RsaCryptoFunction
    {
#if NET451 || NET452
        public virtual ICryptoValue DecryptByPublicKey(byte[] originalBytes)
        {
            return DecryptByPublicKey(originalBytes, CancellationToken.None);
        }

        public virtual ICryptoValue DecryptByPublicKey(byte[] originalBytes, CancellationToken cancellationToken)
        {
            if (originalBytes is null)
                throw new ArgumentNullException(nameof(originalBytes));
            return DecryptByPublicKey(originalBytes, 0, originalBytes.Length, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPublicKey(byte[] originalBytes, int offset, int count)
        {
            return DecryptByPublicKey(originalBytes, offset, count, CancellationToken.None);
        }

        public virtual ICryptoValue DecryptByPublicKey(byte[] originalBytes, int offset, int count, CancellationToken cancellationToken)
        {
            if (originalBytes is null)
                throw new ArgumentNullException(nameof(originalBytes));
            if (offset < 0 || offset > originalBytes.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > originalBytes.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            return DecryptByPublicKey(new ArraySegment<byte>(originalBytes, offset, count), cancellationToken);
        }

        public virtual ICryptoValue DecryptByPublicKey(string cipherText, Encoding encoding = null)
        {
            return DecryptByPublicKey(cipherText, encoding, CancellationToken.None);
        }

        public virtual ICryptoValue DecryptByPublicKey(string cipherText, CancellationToken cancellationToken)
        {
            return DecryptByPublicKey(cipherText, Encoding.UTF8, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPublicKey(string cipherText, Encoding encoding, CancellationToken cancellationToken)
        {
            return DecryptByPublicKey(encoding.SafeEncodingValue().GetBytes(cipherText), cancellationToken);
        }

        public ICryptoValue DecryptByPublicKey(string cipherText, CipherTextTypes cipherTextType, Encoding encoding = null, Func<string, byte[]> customCipherTextConverter = null)
        {
            return DecryptByPublicKey(cipherText, cipherTextType, Encoding.UTF8, CancellationToken.None, customCipherTextConverter);
        }

        public ICryptoValue DecryptByPublicKey(string cipherText, CipherTextTypes cipherTextType, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null)
        {
            return DecryptByPublicKey(cipherText, cipherTextType, Encoding.UTF8, cancellationToken, customCipherTextConverter);
        }

        public ICryptoValue DecryptByPublicKey(string cipherText, CipherTextTypes cipherTextType, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null)
        {
            encoding = encoding.SafeEncodingValue();

            var finalCipherText = cipherTextType.GetBytes(cipherText, encoding, customCipherTextConverter);

            return DecryptByPublicKey(finalCipherText, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPublicKey(ArraySegment<byte> originalBytes)
        {
            return DecryptByPublicKey(originalBytes, CancellationToken.None);
        }

        public virtual ICryptoValue DecryptByPublicKey(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
            return DecryptByPublicKeyInternal(originalBytes, cancellationToken);
        }

        protected abstract ICryptoValue DecryptByPublicKeyInternal(ArraySegment<byte> cipherBytes, CancellationToken cancellationToken);

        public virtual ICryptoValue DecryptByPrivateKey(byte[] originalBytes)
        {
            return DecryptByPrivateKey(originalBytes, true);
        }

        public virtual ICryptoValue DecryptByPrivateKey(byte[] originalBytes, bool fOEAP)
        {
            return DecryptByPrivateKey(originalBytes, fOEAP, CancellationToken.None);
        }

        public virtual ICryptoValue DecryptByPrivateKey(byte[] originalBytes, CancellationToken cancellationToken)
        {
            return DecryptByPrivateKey(originalBytes, true, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(byte[] originalBytes, bool fOEAP, CancellationToken cancellationToken)
        {
            if (originalBytes is null)
                throw new ArgumentNullException(nameof(originalBytes));
            return DecryptByPrivateKey(originalBytes, 0, originalBytes.Length, fOEAP, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(byte[] originalBytes, int offset, int count)
        {
            return DecryptByPrivateKey(originalBytes, offset, count, true);
        }

        public virtual ICryptoValue DecryptByPrivateKey(byte[] originalBytes, int offset, int count, bool fOEAP)
        {
            return DecryptByPrivateKey(originalBytes, offset, count, fOEAP, CancellationToken.None);
        }

        public virtual ICryptoValue DecryptByPrivateKey(byte[] originalBytes, int offset, int count, CancellationToken cancellationToken)
        {
            return DecryptByPrivateKey(originalBytes, offset, count, true, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(byte[] originalBytes, int offset, int count, bool fOEAP, CancellationToken cancellationToken)
        {
            if (originalBytes is null)
                throw new ArgumentNullException(nameof(originalBytes));
            if (offset < 0 || offset > originalBytes.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > originalBytes.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            return DecryptByPrivateKey(new ArraySegment<byte>(originalBytes, offset, count), fOEAP, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(string cipherText, Encoding encoding = null)
        {
            return DecryptByPrivateKey(cipherText, true, encoding);
        }

        public virtual ICryptoValue DecryptByPrivateKey(string cipherText, bool fOEAP, Encoding encoding = null)
        {
            return DecryptByPrivateKey(cipherText, fOEAP, encoding, CancellationToken.None);
        }

        public virtual ICryptoValue DecryptByPrivateKey(string cipherText, CancellationToken cancellationToken)
        {
            return DecryptByPrivateKey(cipherText, true, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(string cipherText, bool fOEAP, CancellationToken cancellationToken)
        {
            return DecryptByPrivateKey(cipherText, fOEAP, Encoding.UTF8, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(string cipherText, Encoding encoding, CancellationToken cancellationToken)
        {
            return DecryptByPrivateKey(cipherText, true, encoding, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(string cipherText, bool fOEAP, Encoding encoding, CancellationToken cancellationToken)
        {
            return DecryptByPrivateKey(encoding.SafeEncodingValue().GetBytes(cipherText), fOEAP, cancellationToken);
        }

        public ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType, Encoding encoding = null, Func<string, byte[]> customCipherTextConverter = null)
        {
            return DecryptByPrivateKey(cipherText, cipherTextType, true, encoding, CancellationToken.None, customCipherTextConverter);
        }

        public ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType, bool fOEAP, Encoding encoding = null, Func<string, byte[]> customCipherTextConverter = null)
        {
            return DecryptByPrivateKey(cipherText, cipherTextType, fOEAP, encoding, CancellationToken.None, customCipherTextConverter);
        }

        public ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null)
        {
            return DecryptByPrivateKey(cipherText, cipherTextType, true, Encoding.UTF8, cancellationToken, customCipherTextConverter);
        }

        public ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType, bool fOEAP, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null)
        {
            return DecryptByPrivateKey(cipherText, cipherTextType, fOEAP, Encoding.UTF8, cancellationToken, customCipherTextConverter);
        }

        public ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null)
        {
            return DecryptByPrivateKey(cipherText, cipherTextType, true, encoding, cancellationToken, customCipherTextConverter);
        }

        public ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType, bool fOEAP, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null)
        {
            encoding = encoding.SafeEncodingValue();

            var finalCipherText = cipherTextType.GetBytes(cipherText, encoding, customCipherTextConverter);

            return DecryptByPrivateKey(finalCipherText, fOEAP, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(ArraySegment<byte> originalBytes)
        {
            return DecryptByPrivateKey(originalBytes, true);
        }

        public virtual ICryptoValue DecryptByPrivateKey(ArraySegment<byte> originalBytes, bool fOEAP)
        {
            return DecryptByPrivateKey(originalBytes, fOEAP, CancellationToken.None);
        }

        public virtual ICryptoValue DecryptByPrivateKey(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
            return DecryptByPrivateKey(originalBytes, true, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(ArraySegment<byte> originalBytes, bool fOEAP, CancellationToken cancellationToken)
        {
            return DecryptByPrivateKeyInternal(originalBytes, fOEAP, cancellationToken);
        }

        protected abstract ICryptoValue DecryptByPrivateKeyInternal(ArraySegment<byte> cipherBytes, bool fOEAP, CancellationToken cancellationToken);
#else
        public virtual ICryptoValue DecryptByPublicKey(byte[] buffer)
        {
            return DecryptByPublicKey(buffer, RSAEncryptionPadding.Pkcs1);
        }

        public virtual ICryptoValue DecryptByPublicKey(byte[] buffer, RSAEncryptionPadding padding)
        {
            return DecryptByPublicKey(buffer, padding, CancellationToken.None);
        }

        public virtual ICryptoValue DecryptByPublicKey(byte[] buffer, CancellationToken cancellationToken)
        {
            return DecryptByPublicKey(buffer, RSAEncryptionPadding.Pkcs1, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPublicKey(byte[] buffer, RSAEncryptionPadding padding, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            return DecryptByPublicKey(buffer, 0, buffer.Length, padding, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPublicKey(byte[] buffer, int offset, int count)
        {
            return DecryptByPublicKey(buffer, offset, count, RSAEncryptionPadding.Pkcs1);
        }

        public virtual ICryptoValue DecryptByPublicKey(byte[] buffer, int offset, int count, RSAEncryptionPadding padding)
        {
            return DecryptByPublicKey(buffer, offset, count, padding, CancellationToken.None);
        }

        public virtual ICryptoValue DecryptByPublicKey(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return DecryptByPublicKey(buffer, offset, count, RSAEncryptionPadding.Pkcs1, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPublicKey(byte[] buffer, int offset, int count, RSAEncryptionPadding padding, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || offset > buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            if (padding is null)
                throw new ArgumentNullException(nameof(padding));
            return DecryptByPublicKey(new ArraySegment<byte>(buffer, offset, count), padding, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPublicKey(string cipherText, Encoding encoding = null)
        {
            return DecryptByPublicKey(cipherText, RSAEncryptionPadding.Pkcs1, encoding);
        }

        public virtual ICryptoValue DecryptByPublicKey(string cipherText, RSAEncryptionPadding padding, Encoding encoding = null)
        {
            return DecryptByPublicKey(cipherText, padding, encoding, CancellationToken.None);
        }

        public virtual ICryptoValue DecryptByPublicKey(string cipherText, CancellationToken cancellationToken)
        {
            return DecryptByPublicKey(cipherText, RSAEncryptionPadding.Pkcs1, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPublicKey(string cipherText, RSAEncryptionPadding padding, CancellationToken cancellationToken)
        {
            return DecryptByPublicKey(cipherText, padding, Encoding.UTF8, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPublicKey(string cipherText, Encoding encoding, CancellationToken cancellationToken)
        {
            return DecryptByPublicKey(cipherText, RSAEncryptionPadding.Pkcs1, encoding, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPublicKey(string cipherText, RSAEncryptionPadding padding, Encoding encoding, CancellationToken cancellationToken)
        {
            return DecryptByPublicKey(encoding.SafeEncodingValue().GetBytes(cipherText), padding, cancellationToken);
        }

        public ICryptoValue DecryptByPublicKey(string cipherText, CipherTextTypes cipherTextType, Encoding encoding = null, Func<string, byte[]> customCipherTextConverter = null)
        {
            return DecryptByPublicKey(cipherText, cipherTextType, RSAEncryptionPadding.Pkcs1, encoding, CancellationToken.None, customCipherTextConverter);
        }

        public ICryptoValue DecryptByPublicKey(string cipherText, CipherTextTypes cipherTextType, RSAEncryptionPadding padding, Encoding encoding = null, Func<string, byte[]> customCipherTextConverter = null)
        {
            return DecryptByPublicKey(cipherText, cipherTextType, padding, encoding, CancellationToken.None, customCipherTextConverter);
        }

        public ICryptoValue DecryptByPublicKey(string cipherText, CipherTextTypes cipherTextType, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null)
        {
            return DecryptByPublicKey(cipherText, cipherTextType, RSAEncryptionPadding.Pkcs1, Encoding.UTF8, cancellationToken, customCipherTextConverter);
        }

        public ICryptoValue DecryptByPublicKey(string cipherText, CipherTextTypes cipherTextType, RSAEncryptionPadding padding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null)
        {
            return DecryptByPublicKey(cipherText, cipherTextType, padding, Encoding.UTF8, cancellationToken, customCipherTextConverter);
        }

        public ICryptoValue DecryptByPublicKey(string cipherText, CipherTextTypes cipherTextType, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null)
        {
            return DecryptByPublicKey(cipherText, cipherTextType, RSAEncryptionPadding.Pkcs1, encoding, cancellationToken, customCipherTextConverter);
        }

        public ICryptoValue DecryptByPublicKey(string cipherText, CipherTextTypes cipherTextType, RSAEncryptionPadding padding, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null)
        {
            encoding = encoding.SafeEncodingValue();

            var finalCipherText = cipherTextType.GetBytes(cipherText, encoding, customCipherTextConverter);

            return DecryptByPublicKey(finalCipherText, padding, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPublicKey(ArraySegment<byte> buffer)
        {
            return DecryptByPublicKey(buffer, RSAEncryptionPadding.Pkcs1);
        }

        public virtual ICryptoValue DecryptByPublicKey(ArraySegment<byte> buffer, RSAEncryptionPadding padding)
        {
            return DecryptByPublicKey(buffer, padding, CancellationToken.None);
        }

        public virtual ICryptoValue DecryptByPublicKey(ArraySegment<byte> buffer, CancellationToken cancellationToken)
        {
            return DecryptByPublicKey(buffer, RSAEncryptionPadding.Pkcs1, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPublicKey(ArraySegment<byte> buffer, RSAEncryptionPadding padding, CancellationToken cancellationToken)
        {
            return DecryptByPublicKeyInternal(buffer, padding, cancellationToken);
        }

        protected abstract ICryptoValue DecryptByPublicKeyInternal(ArraySegment<byte> cipherBytes, RSAEncryptionPadding padding, CancellationToken cancellationToken);

        public virtual ICryptoValue DecryptByPrivateKey(byte[] buffer)
        {
            return DecryptByPrivateKey(buffer, RSAEncryptionPadding.Pkcs1);
        }

        public virtual ICryptoValue DecryptByPrivateKey(byte[] buffer, RSAEncryptionPadding padding)
        {
            return DecryptByPrivateKey(buffer, padding, CancellationToken.None);
        }

        public virtual ICryptoValue DecryptByPrivateKey(byte[] buffer, CancellationToken cancellationToken)
        {
            return DecryptByPrivateKey(buffer, RSAEncryptionPadding.Pkcs1, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(byte[] buffer, RSAEncryptionPadding padding, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            return DecryptByPrivateKey(buffer, 0, buffer.Length, padding, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(byte[] buffer, int offset, int count)
        {
            return DecryptByPrivateKey(buffer, offset, count, RSAEncryptionPadding.Pkcs1);
        }

        public virtual ICryptoValue DecryptByPrivateKey(byte[] buffer, int offset, int count, RSAEncryptionPadding padding)
        {
            return DecryptByPrivateKey(buffer, offset, count, padding, CancellationToken.None);
        }

        public virtual ICryptoValue DecryptByPrivateKey(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return DecryptByPrivateKey(buffer, offset, count, RSAEncryptionPadding.Pkcs1, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(byte[] buffer, int offset, int count, RSAEncryptionPadding padding, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || offset > buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            if (padding is null)
                throw new ArgumentNullException(nameof(padding));
            return DecryptByPrivateKey(new ArraySegment<byte>(buffer, offset, count), padding, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(string cipherText, Encoding encoding = null)
        {
            return DecryptByPrivateKey(cipherText, RSAEncryptionPadding.Pkcs1, encoding);
        }

        public virtual ICryptoValue DecryptByPrivateKey(string cipherText, RSAEncryptionPadding padding, Encoding encoding = null)
        {
            return DecryptByPrivateKey(cipherText, padding, encoding, CancellationToken.None);
        }

        public virtual ICryptoValue DecryptByPrivateKey(string cipherText, CancellationToken cancellationToken)
        {
            return DecryptByPrivateKey(cipherText, RSAEncryptionPadding.Pkcs1, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(string cipherText, RSAEncryptionPadding padding, CancellationToken cancellationToken)
        {
            return DecryptByPrivateKey(cipherText, padding, Encoding.UTF8, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(string cipherText, Encoding encoding, CancellationToken cancellationToken)
        {
            return DecryptByPrivateKey(cipherText, RSAEncryptionPadding.Pkcs1, encoding, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(string cipherText, RSAEncryptionPadding padding, Encoding encoding, CancellationToken cancellationToken)
        {
            return DecryptByPrivateKey(encoding.SafeEncodingValue().GetBytes(cipherText), padding, cancellationToken);
        }

        public ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType, Encoding encoding = null, Func<string, byte[]> customCipherTextConverter = null)
        {
            return DecryptByPrivateKey(cipherText, cipherTextType, RSAEncryptionPadding.Pkcs1, encoding, CancellationToken.None, customCipherTextConverter);
        }

        public ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType, RSAEncryptionPadding padding, Encoding encoding = null, Func<string, byte[]> customCipherTextConverter = null)
        {
            return DecryptByPrivateKey(cipherText, cipherTextType, padding, encoding, CancellationToken.None, customCipherTextConverter);
        }

        public ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null)
        {
            return DecryptByPrivateKey(cipherText, cipherTextType, RSAEncryptionPadding.Pkcs1, Encoding.UTF8, cancellationToken, customCipherTextConverter);
        }

        public ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType, RSAEncryptionPadding padding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null)
        {
            return DecryptByPrivateKey(cipherText, cipherTextType, padding, Encoding.UTF8, cancellationToken, customCipherTextConverter);
        }

        public ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null)
        {
            return DecryptByPrivateKey(cipherText, cipherTextType, RSAEncryptionPadding.Pkcs1, encoding, cancellationToken, customCipherTextConverter);
        }

        public ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType, RSAEncryptionPadding padding, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null)
        {
            encoding = encoding.SafeEncodingValue();

            var finalCipherText = cipherTextType.GetBytes(cipherText, encoding, customCipherTextConverter);

            return DecryptByPrivateKey(finalCipherText, padding, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(ArraySegment<byte> buffer)
        {
            return DecryptByPrivateKey(buffer, RSAEncryptionPadding.Pkcs1);
        }

        public virtual ICryptoValue DecryptByPrivateKey(ArraySegment<byte> buffer, RSAEncryptionPadding padding)
        {
            return DecryptByPrivateKey(buffer, padding, CancellationToken.None);
        }

        public virtual ICryptoValue DecryptByPrivateKey(ArraySegment<byte> buffer, CancellationToken cancellationToken)
        {
            return DecryptByPrivateKey(buffer, RSAEncryptionPadding.Pkcs1, cancellationToken);
        }

        public virtual ICryptoValue DecryptByPrivateKey(ArraySegment<byte> buffer, RSAEncryptionPadding padding, CancellationToken cancellationToken)
        {
            return DecryptByPrivateKeyInternal(buffer, padding, cancellationToken);
        }

        protected abstract ICryptoValue DecryptByPrivateKeyInternal(ArraySegment<byte> cipherBytes, RSAEncryptionPadding padding, CancellationToken cancellationToken);
#endif
    }
}