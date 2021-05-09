using System;
using System.Text;
using System.Threading;

namespace Cosmos.Security.Cryptography
{
    public interface IAsymmetricSignAlgorithm : ICryptoAlgorithm
    {
        ISignValue Sign(byte[] buffer);

        ISignValue Sign(byte[] buffer, CancellationToken cancellationToken);

        ISignValue Sign(byte[] buffer, int offset, int count);

        ISignValue Sign(byte[] buffer, int offset, int count, CancellationToken cancellationToken);

        ISignValue Sign(string text, Encoding encoding = null);

        ISignValue Sign(string text, CancellationToken cancellationToken);

        ISignValue Sign(string text, Encoding encoding, CancellationToken cancellationToken);

        ISignValue Sign(ArraySegment<byte> buffer);

        ISignValue Sign(ArraySegment<byte> buffer, CancellationToken cancellationToken);

        bool Verify(byte[] rgbData, byte[] rgbSignature);

        bool Verify(byte[] rgbData, byte[] rgbSignature, CancellationToken cancellationToken);

        bool Verify(byte[] rgbData, int offset, int count, byte[] rgbSignature);

        bool Verify(byte[] rgbData, int offset, int count, byte[] rgbSignature, CancellationToken cancellationToken);

        bool Verify(string rgbText, string rgbSignature, Encoding encoding = null);

        bool Verify(string rgbText, string rgbSignature, CancellationToken cancellationToken);

        bool Verify(string rgbText, string rgbSignature, Encoding encoding, CancellationToken cancellationToken);

        bool Verify(string rgbText, string rgbSignature, SignatureTextTypes signatureTextType, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null);

        bool Verify(string rgbText, string rgbSignature, SignatureTextTypes signatureTextType, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool Verify(string rgbText, string rgbSignature, SignatureTextTypes signatureTextType, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool Verify(ArraySegment<byte> rgbData, ArraySegment<byte> rgbSignature);

        bool Verify(ArraySegment<byte> rgbData, ArraySegment<byte> rgbSignature, CancellationToken cancellationToken);
    }

    public interface IAsymmetricCryptoAlgorithm : IAsymmetricSignAlgorithm
    {
        ICryptoValue Encrypt(byte[] originalBytes);

        ICryptoValue Encrypt(byte[] originalBytes, CancellationToken cancellationToken);

        ICryptoValue Encrypt(byte[] originalBytes, int offset, int count);

        ICryptoValue Encrypt(byte[] originalBytes, int offset, int count, CancellationToken cancellationToken);

        ICryptoValue Encrypt(string text, Encoding encoding = null);

        ICryptoValue Encrypt(string text, CancellationToken cancellationToken);

        ICryptoValue Encrypt(string text, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue Encrypt(ArraySegment<byte> originalBytes);

        ICryptoValue Encrypt(ArraySegment<byte> originalBytes, CancellationToken cancellationToken);

        ICryptoValue Decrypt(byte[] cipherBytes);

        ICryptoValue Decrypt(byte[] cipherBytes, CancellationToken cancellationToken);

        ICryptoValue Decrypt(byte[] cipherBytes, int offset, int count);

        ICryptoValue Decrypt(byte[] cipherBytes, int offset, int count, CancellationToken cancellationToken);

        ICryptoValue Decrypt(string cipherText, Encoding encoding = null);

        ICryptoValue Decrypt(string cipherText, CancellationToken cancellationToken);

        ICryptoValue Decrypt(string cipherText, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue Decrypt(string cipherText, CipherTextTypes cipherTextType, Encoding encoding = null, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue Decrypt(string cipherText, CipherTextTypes cipherTextType, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue Decrypt(string cipherText, CipherTextTypes cipherTextType, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue Decrypt(ArraySegment<byte> cipherBytes);

        ICryptoValue Decrypt(ArraySegment<byte> cipherBytes, CancellationToken cancellationToken);
    }
}