using System;
using System.Linq;
using System.Text;
using System.Threading;
using Cosmos.Conversions;
using Cosmos.Optionals;

namespace Cosmos.Security.Cryptography.Core.AsymmetricAlgorithmImpls
{
    internal abstract class AsymmetricSignFunction<TKey> : IAsymmetricSignFunction
        where TKey : IAsymmetricCryptoKey
    {
        public abstract TKey Key { get; }

        public abstract int KeySize { get; }

        #region Sign

        public virtual ISignValue Sign(byte[] buffer)
        {
            return Sign(buffer, CancellationToken.None);
        }

        public virtual ISignValue Sign(byte[] buffer, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            return Sign(buffer, 0, buffer.Length, cancellationToken);
        }

        public virtual ISignValue Sign(byte[] buffer, int offset, int count)
        {
            return Sign(buffer, offset, count, CancellationToken.None);
        }

        public virtual ISignValue Sign(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (buffer is null)
                throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || offset > buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            return Sign(new ArraySegment<byte>(buffer, offset, count), cancellationToken);
        }

        public virtual ISignValue Sign(string text, Encoding encoding = null)
        {
            return Sign(text, encoding, CancellationToken.None);
        }

        public virtual ISignValue Sign(string text, CancellationToken cancellationToken)
        {
            return Sign(text, Encoding.UTF8, cancellationToken);
        }

        public virtual ISignValue Sign(string text, Encoding encoding, CancellationToken cancellationToken)
        {
            return Sign(encoding.SafeEncodingValue().GetBytes(text), cancellationToken);
        }

        public virtual ISignValue Sign(ArraySegment<byte> buffer)
        {
            return Sign(buffer, CancellationToken.None);
        }

        public virtual ISignValue Sign(ArraySegment<byte> buffer, CancellationToken cancellationToken)
        {
            return SignInternal(buffer, cancellationToken);
        }

        protected abstract ISignValue SignInternal(ArraySegment<byte> buffer, CancellationToken cancellationToken);

        #endregion

        #region Verify

        public virtual bool Verify(byte[] rgbData, byte[] rgbSignature)
        {
            return Verify(rgbData, rgbSignature, CancellationToken.None);
        }

        public virtual bool Verify(byte[] rgbData, byte[] rgbSignature, CancellationToken cancellationToken)
        {
            if (rgbData is null)
                throw new ArgumentNullException(nameof(rgbData));
            if (rgbSignature is null)
                throw new ArgumentNullException(nameof(rgbSignature));
            return Verify(rgbData, 0, rgbData.Length, rgbSignature, cancellationToken);
        }

        public virtual bool Verify(byte[] rgbData, int offset, int count, byte[] rgbSignature)
        {
            return Verify(rgbData, offset, count, rgbSignature, CancellationToken.None);
        }

        public virtual bool Verify(byte[] rgbData, int offset, int count, byte[] rgbSignature, CancellationToken cancellationToken)
        {
            if (rgbData is null)
                throw new ArgumentNullException(nameof(rgbData));
            if (rgbSignature is null)
                throw new ArgumentNullException(nameof(rgbSignature));
            if (offset < 0 || offset > rgbData.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be a value greater than or equal to zero and less than or equal to the length of the array.");
            if (count < 0 || count > rgbData.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count), "Count must be a value greater than or equal to zero and less than the the remaining length of the array after the offset value.");
            return Verify(new ArraySegment<byte>(rgbData, offset, count), new ArraySegment<byte>(rgbSignature), cancellationToken);
        }

        public virtual bool Verify(string rgbText, string rgbSignature, Encoding encoding = null)
        {
            return Verify(rgbText, rgbSignature, encoding, CancellationToken.None);
        }

        public virtual bool Verify(string rgbText, string rgbSignature, CancellationToken cancellationToken)
        {
            return Verify(rgbText, rgbSignature, Encoding.UTF8, cancellationToken);
        }

        public virtual bool Verify(string rgbText, string rgbSignature, Encoding encoding, CancellationToken cancellationToken)
        {
            encoding = encoding.SafeEncodingValue();
            return Verify(encoding.GetBytes(rgbText), encoding.GetBytes(rgbSignature), cancellationToken);
        }

        public bool Verify(string rgbText, string rgbSignature, SignatureTextTypes signatureTextType, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return Verify(rgbText, rgbSignature, signatureTextType, encoding, CancellationToken.None, customSignatureTextConverter);
        }

        public bool Verify(string rgbText, string rgbSignature, SignatureTextTypes signatureTextType, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null)
        {
            return Verify(rgbText, rgbSignature, signatureTextType, Encoding.UTF8, cancellationToken, customSignatureTextConverter);
        }

        public bool Verify(string rgbText, string rgbSignature, SignatureTextTypes signatureTextType, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null)
        {
            encoding = encoding.SafeEncodingValue();

            var finalSignature = signatureTextType.GetBytes(rgbSignature, encoding, customSignatureTextConverter);

            return Verify(encoding.GetBytes(rgbText), finalSignature, cancellationToken);
        }

        public virtual bool Verify(ArraySegment<byte> rgbData, ArraySegment<byte> rgbSignature)
        {
            return Verify(rgbData, rgbSignature, CancellationToken.None);
        }

        public virtual bool Verify(ArraySegment<byte> rgbData, ArraySegment<byte> rgbSignature, CancellationToken cancellationToken)
        {
            return VerifyInternal(rgbData, rgbSignature, cancellationToken);
        }

        protected abstract bool VerifyInternal(ArraySegment<byte> rgbData, ArraySegment<byte> rgbSignature, CancellationToken cancellationToken);

        #endregion

        protected static ISignValue CreateSignValue(byte[] signature, Action<TrimOptions> optionsAct = null)
        {
            TrimOptions options = new TrimOptions();
            optionsAct?.Invoke(options);

            return new SignValue(signature, options);
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