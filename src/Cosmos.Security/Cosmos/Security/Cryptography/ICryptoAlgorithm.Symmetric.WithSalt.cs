using System;
using System.Text;
using System.Threading;

namespace Cosmos.Security.Cryptography
{
    public interface ISymmetricCryptoWithSaltAlgorithm : ISymmetricCryptoAlgorithm
    {
        ICryptoValue Encrypt(byte[] originalBytes, byte[] saltBytes);

        ICryptoValue Encrypt(byte[] originalBytes, byte[] saltBytes, CancellationToken cancellationToken);

        ICryptoValue Encrypt(byte[] originalBytes, int offset, int count, byte[] saltBytes);

        ICryptoValue Encrypt(byte[] originalBytes, int offset, int count, byte[] saltBytes, CancellationToken cancellationToken);

        ICryptoValue Encrypt(byte[] originalBytes, string salt, Encoding encoding = null);

        ICryptoValue Encrypt(byte[] originalBytes, string salt, CancellationToken cancellationToken);

        ICryptoValue Encrypt(byte[] originalBytes, string salt, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue Encrypt(byte[] originalBytes, int offset, int count, string salt, Encoding encoding = null);

        ICryptoValue Encrypt(byte[] originalBytes, int offset, int count, string salt, CancellationToken cancellationToken);

        ICryptoValue Encrypt(byte[] originalBytes, int offset, int count, string salt, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue Encrypt(string originalText, string salt, Encoding encoding = null);

        ICryptoValue Encrypt(string originalText, string salt, CancellationToken cancellationToken);

        ICryptoValue Encrypt(string originalText, string salt, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue Encrypt(ArraySegment<byte> originalBytes, byte[] saltBytes);

        ICryptoValue Encrypt(ArraySegment<byte> originalBytes, byte[] saltBytes, CancellationToken cancellationToken);

        ICryptoValue Encrypt(ArraySegment<byte> originalBytes, string salt, Encoding encoding = null);

        ICryptoValue Encrypt(ArraySegment<byte> originalBytes, string salt, CancellationToken cancellationToken);

        ICryptoValue Encrypt(ArraySegment<byte> originalBytes, string salt, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue Decrypt(byte[] cipherBytes, byte[] saltBytes);

        ICryptoValue Decrypt(byte[] cipherBytes, byte[] saltBytes, CancellationToken cancellationToken);

        ICryptoValue Decrypt(byte[] cipherBytes, int offset, int count, byte[] saltBytes);

        ICryptoValue Decrypt(byte[] cipherBytes, int offset, int count, byte[] saltBytes, CancellationToken cancellationToken);

        ICryptoValue Decrypt(byte[] cipherBytes, string salt, Encoding encoding = null);

        ICryptoValue Decrypt(byte[] cipherBytes, string salt, CancellationToken cancellationToken);

        ICryptoValue Decrypt(byte[] cipherBytes, string salt, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue Decrypt(byte[] cipherBytes, int offset, int count, string salt, Encoding encoding = null);

        ICryptoValue Decrypt(byte[] cipherBytes, int offset, int count, string salt, CancellationToken cancellationToken);

        ICryptoValue Decrypt(byte[] cipherBytes, int offset, int count, string salt, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue Decrypt(string cipherText, string salt, Encoding encoding = null);

        ICryptoValue Decrypt(string cipherText, string salt, CancellationToken cancellationToken);

        ICryptoValue Decrypt(string cipherText, string salt, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue Decrypt(string cipherText, string salt, CipherTextTypes cipherTextType, Encoding encoding = null, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue Decrypt(string cipherText, string salt, CipherTextTypes cipherTextType, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue Decrypt(string cipherText, string salt, CipherTextTypes cipherTextType, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue Decrypt(ArraySegment<byte> cipherBytes, byte[] saltBytes);

        ICryptoValue Decrypt(ArraySegment<byte> cipherBytes, byte[] saltBytes, CancellationToken cancellationToken);

        ICryptoValue Decrypt(ArraySegment<byte> cipherBytes, string salt, Encoding encoding = null);

        ICryptoValue Decrypt(ArraySegment<byte> cipherBytes, string salt, CancellationToken cancellationToken);

        ICryptoValue Decrypt(ArraySegment<byte> cipherBytes, string salt, Encoding encoding, CancellationToken cancellationToken);
    }
}