using System;
using System.Text;
using System.Threading;
using Cosmos.Conversions;
using Cosmos.Optionals;

namespace Cosmos.Security.Cryptography.Core.SymmetricAlgorithmImpls
{
    internal abstract class SymmetricCryptoFunctionWithSalt<TKey> : SymmetricCryptoFunction<TKey>, ISymmetricCryptoWithSaltAlgorithm
    {
        public virtual ICryptoValue Encrypt(byte[] originalBytes, byte[] saltBytes)
        {
            return Encrypt(originalBytes, saltBytes, CancellationToken.None);
        }

        public virtual ICryptoValue Encrypt(byte[] originalBytes, byte[] saltBytes, CancellationToken cancellationToken)
        {
            if (originalBytes is null)
                throw new ArgumentNullException(nameof(originalBytes));
            return Encrypt(originalBytes, 0, originalBytes.Length, saltBytes, cancellationToken);
        }

        public virtual ICryptoValue Encrypt(byte[] originalBytes, int offset, int count, byte[] saltBytes)
        {
            return Encrypt(originalBytes, offset, count, saltBytes, CancellationToken.None);
        }

        public virtual ICryptoValue Encrypt(byte[] originalBytes, int offset, int count, byte[] saltBytes, CancellationToken cancellationToken)
        {
            if (originalBytes is null)
                throw new ArgumentNullException(nameof(originalBytes));
            if (offset < 0 || offset > originalBytes.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > originalBytes.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            return Encrypt(new ArraySegment<byte>(originalBytes, offset, count), saltBytes, cancellationToken);
        }

        public virtual ICryptoValue Encrypt(byte[] originalBytes, string salt, Encoding encoding = null)
        {
            return Encrypt(originalBytes, salt, encoding, CancellationToken.None);
        }

        public virtual ICryptoValue Encrypt(byte[] originalBytes, string salt, CancellationToken cancellationToken)
        {
            return Encrypt(originalBytes, salt, Encoding.UTF8, cancellationToken);
        }

        public virtual ICryptoValue Encrypt(byte[] originalBytes, string salt, Encoding encoding, CancellationToken cancellationToken)
        {
            if (originalBytes is null)
                throw new ArgumentNullException(nameof(originalBytes));
            return Encrypt(originalBytes, 0, originalBytes.Length, salt, encoding, cancellationToken);
        }

        public virtual ICryptoValue Encrypt(byte[] originalBytes, int offset, int count, string salt, Encoding encoding = null)
        {
            return Encrypt(originalBytes, offset, count, salt, encoding, CancellationToken.None);
        }

        public virtual ICryptoValue Encrypt(byte[] originalBytes, int offset, int count, string salt, CancellationToken cancellationToken)
        {
            return Encrypt(originalBytes, offset, count, salt, Encoding.UTF8, cancellationToken);
        }

        public virtual ICryptoValue Encrypt(byte[] originalBytes, int offset, int count, string salt, Encoding encoding, CancellationToken cancellationToken)
        {
            if (originalBytes is null)
                throw new ArgumentNullException(nameof(originalBytes));
            if (offset < 0 || offset > originalBytes.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > originalBytes.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            var saltBytes = string.IsNullOrWhiteSpace(salt) ? new byte[0] : encoding.SafeEncodingValue().GetBytes(salt);
            return Encrypt(originalBytes, offset, count, saltBytes, cancellationToken);
        }

        public virtual ICryptoValue Encrypt(string originalText, string salt, Encoding encoding = null)
        {
            return Encrypt(originalText, salt, Encoding.UTF8, CancellationToken.None);
        }

        public virtual ICryptoValue Encrypt(string originalText, string salt, CancellationToken cancellationToken)
        {
            return Encrypt(originalText, salt, Encoding.UTF8, cancellationToken);
        }

        public virtual ICryptoValue Encrypt(string originalText, string salt, Encoding encoding, CancellationToken cancellationToken)
        {
            encoding = encoding.SafeEncodingValue();
            var saltBytes = string.IsNullOrWhiteSpace(salt) ? new byte[0] : encoding.GetBytes(salt);
            return Encrypt(encoding.GetBytes(originalText), saltBytes, cancellationToken);
        }

        public virtual ICryptoValue Encrypt(ArraySegment<byte> originalBytes, byte[] saltBytes)
        {
            return Encrypt(originalBytes, saltBytes, CancellationToken.None);
        }

        public virtual ICryptoValue Encrypt(ArraySegment<byte> originalBytes, byte[] saltBytes, CancellationToken cancellationToken)
        {
            return EncryptInternal(originalBytes, saltBytes, cancellationToken);
        }

        public virtual ICryptoValue Encrypt(ArraySegment<byte> originalBytes, string salt, Encoding encoding = null)
        {
            return Encrypt(originalBytes, salt, encoding, CancellationToken.None);
        }

        public virtual ICryptoValue Encrypt(ArraySegment<byte> originalBytes, string salt, CancellationToken cancellationToken)
        {
            return Encrypt(originalBytes, salt, Encoding.UTF8, cancellationToken);
        }

        public virtual ICryptoValue Encrypt(ArraySegment<byte> originalBytes, string salt, Encoding encoding, CancellationToken cancellationToken)
        {
            encoding = encoding.SafeEncodingValue();
            var saltBytes = string.IsNullOrWhiteSpace(salt) ? new byte[0] : encoding.GetBytes(salt);
            return Encrypt(originalBytes, saltBytes, cancellationToken);
        }

        protected abstract ICryptoValue EncryptInternal(ArraySegment<byte> originalBytes, byte[] saltBytes, CancellationToken cancellationToken);

        public virtual ICryptoValue Decrypt(byte[] cipherBytes, byte[] saltBytes)
        {
            return Decrypt(cipherBytes, saltBytes, CancellationToken.None);
        }

        public virtual ICryptoValue Decrypt(byte[] cipherBytes, byte[] saltBytes, CancellationToken cancellationToken)
        {
            if (cipherBytes is null)
                throw new ArgumentNullException(nameof(cipherBytes));
            return Decrypt(cipherBytes, 0, cipherBytes.Length, saltBytes, cancellationToken);
        }

        public virtual ICryptoValue Decrypt(byte[] cipherBytes, int offset, int count, byte[] saltBytes)
        {
            return Decrypt(cipherBytes, offset, count, saltBytes, CancellationToken.None);
        }

        public virtual ICryptoValue Decrypt(byte[] cipherBytes, int offset, int count, byte[] saltBytes, CancellationToken cancellationToken)
        {
            if (cipherBytes is null)
                throw new ArgumentNullException(nameof(cipherBytes));
            if (offset < 0 || offset > cipherBytes.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > cipherBytes.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            return Decrypt(new ArraySegment<byte>(cipherBytes, offset, count), saltBytes, cancellationToken);
        }

        public virtual ICryptoValue Decrypt(byte[] cipherBytes, string salt, Encoding encoding = null)
        {
            return Decrypt(cipherBytes, salt, encoding, CancellationToken.None);
        }

        public virtual ICryptoValue Decrypt(byte[] cipherBytes, string salt, CancellationToken cancellationToken)
        {
            return Decrypt(cipherBytes, salt, Encoding.UTF8, cancellationToken);
        }

        public virtual ICryptoValue Decrypt(byte[] cipherBytes, string salt, Encoding encoding, CancellationToken cancellationToken)
        {
            if (cipherBytes is null)
                throw new ArgumentNullException(nameof(cipherBytes));
            return Decrypt(cipherBytes, 0, cipherBytes.Length, salt, cancellationToken);
        }

        public virtual ICryptoValue Decrypt(byte[] cipherBytes, int offset, int count, string salt, Encoding encoding = null)
        {
            return Decrypt(cipherBytes, offset, count, salt, encoding, CancellationToken.None);
        }

        public virtual ICryptoValue Decrypt(byte[] cipherBytes, int offset, int count, string salt, CancellationToken cancellationToken)
        {
            return Decrypt(cipherBytes, offset, count, salt, Encoding.UTF8, cancellationToken);
        }

        public virtual ICryptoValue Decrypt(byte[] cipherBytes, int offset, int count, string salt, Encoding encoding, CancellationToken cancellationToken)
        {
            if (cipherBytes is null)
                throw new ArgumentNullException(nameof(cipherBytes));
            if (offset < 0 || offset > cipherBytes.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > cipherBytes.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            var saltBytes = string.IsNullOrWhiteSpace(salt) ? new byte[0] : encoding.SafeEncodingValue().GetBytes(salt);
            return Decrypt(new ArraySegment<byte>(cipherBytes, offset, count), saltBytes, cancellationToken);
        }

        public virtual ICryptoValue Decrypt(string cipherText, string salt, Encoding encoding = null)
        {
            return Decrypt(cipherText, salt, CipherTextTypes.PlainText, Encoding.UTF8, CancellationToken.None);
        }

        public virtual ICryptoValue Decrypt(string cipherText, string salt, CancellationToken cancellationToken)
        {
            return Decrypt(cipherText, salt, CipherTextTypes.PlainText, Encoding.UTF8, cancellationToken);
        }

        public virtual ICryptoValue Decrypt(string cipherText, string salt, Encoding encoding, CancellationToken cancellationToken)
        {
            return Decrypt(cipherText, salt, CipherTextTypes.PlainText, encoding, cancellationToken);
        }

        public ICryptoValue Decrypt(string cipherText, string salt, CipherTextTypes cipherTextType, Encoding encoding = null, Func<string, byte[]> customCipherTextConverter = null)
        {
            return Decrypt(cipherText, salt, cipherTextType, encoding, CancellationToken.None, customCipherTextConverter);
        }

        public ICryptoValue Decrypt(string cipherText, string salt, CipherTextTypes cipherTextType, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null)
        {
            return Decrypt(cipherText, salt, cipherTextType, Encoding.UTF8, cancellationToken, customCipherTextConverter);
        }

        public ICryptoValue Decrypt(string cipherText, string salt, CipherTextTypes cipherTextType, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null)
        {
            encoding = encoding.SafeEncodingValue();

            var finalCipherText = cipherTextType.GetBytes(cipherText, encoding, customCipherTextConverter);

            var saltBytes = string.IsNullOrWhiteSpace(salt) ? new byte[0] : encoding.GetBytes(salt);

            return Decrypt(finalCipherText, saltBytes, cancellationToken);
        }

        public virtual ICryptoValue Decrypt(ArraySegment<byte> cipherBytes, byte[] saltBytes)
        {
            return Decrypt(cipherBytes, saltBytes, CancellationToken.None);
        }

        public virtual ICryptoValue Decrypt(ArraySegment<byte> cipherBytes, byte[] saltBytes, CancellationToken cancellationToken)
        {
            return DecryptInternal(cipherBytes, saltBytes, cancellationToken);
        }

        public virtual ICryptoValue Decrypt(ArraySegment<byte> cipherBytes, string salt, Encoding encoding = null)
        {
            return Decrypt(cipherBytes, salt, encoding, CancellationToken.None);
        }

        public virtual ICryptoValue Decrypt(ArraySegment<byte> cipherBytes, string salt, CancellationToken cancellationToken)
        {
            return Decrypt(cipherBytes, salt, Encoding.UTF8, cancellationToken);
        }

        public virtual ICryptoValue Decrypt(ArraySegment<byte> cipherBytes, string salt, Encoding encoding, CancellationToken cancellationToken)
        {
            encoding = encoding.SafeEncodingValue();
            var saltBytes = string.IsNullOrWhiteSpace(salt) ? new byte[0] : encoding.GetBytes(salt);
            return Decrypt(cipherBytes, saltBytes, cancellationToken);
        }

        protected abstract ICryptoValue DecryptInternal(ArraySegment<byte> cipherBytes, byte[] saltBytes, CancellationToken cancellationToken);
    }
}