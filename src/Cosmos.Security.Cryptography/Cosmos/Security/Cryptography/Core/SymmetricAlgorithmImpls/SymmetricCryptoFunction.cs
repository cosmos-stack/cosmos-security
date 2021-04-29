using System;
#if NETFRAMEWORK
using System.Linq;
#endif
using System.Text;
using System.Threading;
using Cosmos.Conversions;
using Cosmos.Optionals;

namespace Cosmos.Security.Cryptography.Core.SymmetricAlgorithmImpls
{
    internal abstract class SymmetricCryptoFunction<TKey> : ISymmetricCryptoFunction
    {
        public abstract TKey Key { get; }

        public abstract int KeySize { get; }

        public virtual ICryptoValue Encrypt(byte[] originalBytes)
        {
            return Encrypt(originalBytes, CancellationToken.None);
        }

        public virtual ICryptoValue Encrypt(byte[] originalBytes, CancellationToken cancellationToken)
        {
            if (originalBytes is null)
                throw new ArgumentNullException(nameof(originalBytes));
            return Encrypt(originalBytes, 0, originalBytes.Length, cancellationToken);
        }

        public virtual ICryptoValue Encrypt(byte[] originalBytes, int offset, int count)
        {
            return Encrypt(originalBytes, offset, count, CancellationToken.None);
        }

        public virtual ICryptoValue Encrypt(byte[] originalBytes, int offset, int count, CancellationToken cancellationToken)
        {
            if (originalBytes is null)
                throw new ArgumentNullException(nameof(originalBytes));
            if (offset < 0 || offset > originalBytes.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > originalBytes.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            return Encrypt(new ArraySegment<byte>(originalBytes, offset, count), cancellationToken);
        }

        public virtual ICryptoValue Encrypt(string originalText, Encoding encoding = null)
        {
            return Encrypt(originalText, encoding, CancellationToken.None);
        }

        public virtual ICryptoValue Encrypt(string originalText, CancellationToken cancellationToken)
        {
            return Encrypt(originalText, Encoding.UTF8, cancellationToken);
        }

        public virtual ICryptoValue Encrypt(string originalText, Encoding encoding, CancellationToken cancellationToken)
        {
            return Encrypt(encoding.SafeEncodingValue().GetBytes(originalText), cancellationToken);
        }

        public virtual ICryptoValue Encrypt(ArraySegment<byte> originalBytes)
        {
            return Encrypt(originalBytes, CancellationToken.None);
        }

        public virtual ICryptoValue Encrypt(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
            return EncryptInternal(originalBytes, cancellationToken);
        }

        protected abstract ICryptoValue EncryptInternal(ArraySegment<byte> originalBytes, CancellationToken cancellationToken);

        public virtual ICryptoValue Decrypt(byte[] cipherBytes)
        {
            return Decrypt(cipherBytes, CancellationToken.None);
        }

        public virtual ICryptoValue Decrypt(byte[] cipherBytes, CancellationToken cancellationToken)
        {
            if (cipherBytes is null)
                throw new ArgumentNullException(nameof(cipherBytes));
            return Decrypt(cipherBytes, 0, cipherBytes.Length, cancellationToken);
        }

        public virtual ICryptoValue Decrypt(byte[] cipherBytes, int offset, int count)
        {
            return Decrypt(cipherBytes, offset, count, CancellationToken.None);
        }

        public virtual ICryptoValue Decrypt(byte[] cipherBytes, int offset, int count, CancellationToken cancellationToken)
        {
            if (cipherBytes is null)
                throw new ArgumentNullException(nameof(cipherBytes));
            if (offset < 0 || offset > cipherBytes.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > cipherBytes.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            return Decrypt(new ArraySegment<byte>(cipherBytes, offset, count), cancellationToken);
        }

        public virtual ICryptoValue Decrypt(string cipherText, Encoding encoding = null)
        {
            return Decrypt(cipherText, CipherTextTypes.PlainText, encoding, CancellationToken.None);
        }

        public virtual ICryptoValue Decrypt(string cipherText, CancellationToken cancellationToken)
        {
            return Decrypt(cipherText, CipherTextTypes.PlainText, Encoding.UTF8, cancellationToken);
        }

        public virtual ICryptoValue Decrypt(string cipherText, Encoding encoding, CancellationToken cancellationToken)
        {
            return Decrypt(cipherText, CipherTextTypes.PlainText, encoding, cancellationToken);
        }

        public ICryptoValue Decrypt(string cipherText, CipherTextTypes cipherTextType, Encoding encoding = null, Func<string, byte[]> customCipherTextConverter = null)
        {
            return Decrypt(cipherText, cipherTextType, encoding, CancellationToken.None, customCipherTextConverter);
        }

        public ICryptoValue Decrypt(string cipherText, CipherTextTypes cipherTextType, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null)
        {
            return Decrypt(cipherText, cipherTextType, Encoding.UTF8, cancellationToken, customCipherTextConverter);
        }

        public ICryptoValue Decrypt(string cipherText, CipherTextTypes cipherTextType, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null)
        {
            encoding = encoding.SafeEncodingValue();

            var finalCipherText = cipherTextType switch
            {
                CipherTextTypes.PlainText => encoding.GetBytes(cipherText),
                CipherTextTypes.Base32Text => BaseConv.FromBase32(cipherText),
                CipherTextTypes.Base64Text => BaseConv.FromBase64(cipherText),
                CipherTextTypes.Base91Text => BaseConv.FromBase91(cipherText),
                CipherTextTypes.Base256Text => BaseConv.FromBase256(cipherText),
                CipherTextTypes.ZBase32Text => BaseConv.FromZBase32(cipherText),
                _ => customCipherTextConverter is null ? encoding.GetBytes(cipherText) : customCipherTextConverter(cipherText)
            };

            return Decrypt(finalCipherText, cancellationToken);
        }

        public virtual ICryptoValue Decrypt(ArraySegment<byte> cipherBytes)
        {
            return Decrypt(cipherBytes, CancellationToken.None);
        }

        public virtual ICryptoValue Decrypt(ArraySegment<byte> cipherBytes, CancellationToken cancellationToken)
        {
            return DecryptInternal(cipherBytes, cancellationToken);
        }

        protected abstract ICryptoValue DecryptInternal(ArraySegment<byte> cipherBytes, CancellationToken cancellationToken);

        protected static ICryptoValue CreateCryptoValue(string original, string cipher, CryptoMode direction, Action<TrimOptions> optionsAct = null)
        {
            return CryptoValueBuilder
                   .Create()
                   .OriginalTextIs(original)
                   .CipherTextIs(cipher)
                   .ProcessingDirection(direction)
                   .Configure(optionsAct)
                   .Build();
        }

        protected static ICryptoValue CreateCryptoValue(byte[] originalBytes, byte[] cipherBytes, CryptoMode direction, Action<TrimOptions> optionsAct = null)
        {
            return CryptoValueBuilder
                   .Create()
                   .OriginalTextIs(originalBytes)
                   .CipherTextIs(cipherBytes)
                   .ProcessingDirection(direction)
                   .Configure(optionsAct)
                   .Build();
        }

        protected static byte[] GetBytes(ArraySegment<byte> data)
        {
            return data.ToArray();
        }

        protected static string GetString(ArraySegment<byte> data, Encoding encoding)
        {
            return encoding.SafeEncodingValue().GetString(GetBytes(data));
        }
    }
}