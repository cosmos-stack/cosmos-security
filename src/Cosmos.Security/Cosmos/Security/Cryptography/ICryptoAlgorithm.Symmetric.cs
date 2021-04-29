using System;
using System.Text;
using System.Threading;

namespace Cosmos.Security.Cryptography
{
    public interface ISymmetricCryptoAlgorithm : ICryptoAlgorithm
    {
        ICryptoValue Encrypt(byte[] originalBytes);

        ICryptoValue Encrypt(byte[] originalBytes, CancellationToken cancellationToken);

        ICryptoValue Encrypt(byte[] originalBytes, int offset, int count);

        ICryptoValue Encrypt(byte[] originalBytes, int offset, int count, CancellationToken cancellationToken);

        ICryptoValue Encrypt(string originalText, Encoding encoding = null);

        ICryptoValue Encrypt(string originalText, CancellationToken cancellationToken);

        ICryptoValue Encrypt(string originalText, Encoding encoding, CancellationToken cancellationToken);

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