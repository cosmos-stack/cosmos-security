using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Cosmos.Security.Cryptography
{
#if NET451 || NET452
    public interface IRSA : IAsymmetricCryptoAlgorithm
    {
        #region Encrypt

        ICryptoValue EncryptByPublicKey(byte[] originalBytes);

        ICryptoValue EncryptByPublicKey(byte[] originalBytes, bool fOEAP);

        ICryptoValue EncryptByPublicKey(byte[] originalBytes, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(byte[] originalBytes, bool fOEAP, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(byte[] originalBytes, int offset, int count);

        ICryptoValue EncryptByPublicKey(byte[] originalBytes, int offset, int count, bool fOEAP);

        ICryptoValue EncryptByPublicKey(byte[] originalBytes, int offset, int count, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(byte[] originalBytes, int offset, int count, bool fOEAP, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(string text, Encoding encoding = null);

        ICryptoValue EncryptByPublicKey(string text, bool fOEAP, Encoding encoding = null);

        ICryptoValue EncryptByPublicKey(string text, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(string text, bool fOEAP, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(string text, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(string text, bool fOEAP, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(ArraySegment<byte> originalBytes);

        ICryptoValue EncryptByPublicKey(ArraySegment<byte> originalBytes, bool fOEAP);

        ICryptoValue EncryptByPublicKey(ArraySegment<byte> originalBytes, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(ArraySegment<byte> originalBytes, bool fOEAP, CancellationToken cancellationToken);

        ICryptoValue EncryptByPrivateKey(byte[] originalBytes);

        ICryptoValue EncryptByPrivateKey(byte[] originalBytes, CancellationToken cancellationToken);

        ICryptoValue EncryptByPrivateKey(byte[] originalBytes, int offset, int count);

        ICryptoValue EncryptByPrivateKey(byte[] originalBytes, int offset, int count, CancellationToken cancellationToken);

        ICryptoValue EncryptByPrivateKey(string text, Encoding encoding = null);

        ICryptoValue EncryptByPrivateKey(string text, CancellationToken cancellationToken);

        ICryptoValue EncryptByPrivateKey(string text, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue EncryptByPrivateKey(ArraySegment<byte> originalBytes);

        ICryptoValue EncryptByPrivateKey(ArraySegment<byte> originalBytes, CancellationToken cancellationToken);

        #endregion

        #region Decrypt

        ICryptoValue DecryptByPublicKey(byte[] originalBytes);

        ICryptoValue DecryptByPublicKey(byte[] originalBytes, CancellationToken cancellationToken);

        ICryptoValue DecryptByPublicKey(byte[] originalBytes, int offset, int count);

        ICryptoValue DecryptByPublicKey(byte[] originalBytes, int offset, int count, CancellationToken cancellationToken);

        ICryptoValue DecryptByPublicKey(string cipherText, Encoding encoding = null);

        ICryptoValue DecryptByPublicKey(string cipherText, CancellationToken cancellationToken);

        ICryptoValue DecryptByPublicKey(string cipherText, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue DecryptByPublicKey(string cipherText, CipherTextTypes cipherTextType, Encoding encoding = null, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue DecryptByPublicKey(string cipherText, CipherTextTypes cipherTextType, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue DecryptByPublicKey(string cipherText, CipherTextTypes cipherTextType, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue DecryptByPublicKey(ArraySegment<byte> originalBytes);

        ICryptoValue DecryptByPublicKey(ArraySegment<byte> originalBytes, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(byte[] originalBytes);

        ICryptoValue DecryptByPrivateKey(byte[] originalBytes, bool fOEAP);

        ICryptoValue DecryptByPrivateKey(byte[] originalBytes, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(byte[] originalBytes, bool fOEAP, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(byte[] originalBytes, int offset, int count);

        ICryptoValue DecryptByPrivateKey(byte[] originalBytes, int offset, int count, bool fOEAP);

        ICryptoValue DecryptByPrivateKey(byte[] originalBytes, int offset, int count, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(byte[] originalBytes, int offset, int count, bool fOEAP, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(string cipherText, Encoding encoding = null);

        ICryptoValue DecryptByPrivateKey(string cipherText, bool fOEAP, Encoding encoding = null);

        ICryptoValue DecryptByPrivateKey(string cipherText, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(string cipherText, bool fOEAP, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(string cipherText, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(string cipherText, bool fOEAP, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType, Encoding encoding = null, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType, bool fOEAP, Encoding encoding = null, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType, bool fOEAP, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType, bool fOEAP, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue DecryptByPrivateKey(ArraySegment<byte> originalBytes);

        ICryptoValue DecryptByPrivateKey(ArraySegment<byte> originalBytes, bool fOEAP);

        ICryptoValue DecryptByPrivateKey(ArraySegment<byte> originalBytes, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(ArraySegment<byte> originalBytes, bool fOEAP, CancellationToken cancellationToken);

        #endregion

        #region Sign

        ISignValue SignByPublicKey(byte[] buffer);

        ISignValue SignByPublicKey(byte[] buffer, HashAlgorithmName hashAlgorithmName);

        ISignValue SignByPublicKey(byte[] buffer, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(byte[] buffer, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(byte[] buffer, int offset, int count);

        ISignValue SignByPublicKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName);

        ISignValue SignByPublicKey(byte[] buffer, int offset, int count, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(string text, Encoding encoding = null);

        ISignValue SignByPublicKey(string text, HashAlgorithmName hashAlgorithmName, Encoding encoding = null);

        ISignValue SignByPublicKey(string text, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(string text, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(string text, Encoding encoding, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(string text, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(ArraySegment<byte> buffer);

        ISignValue SignByPublicKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName);

        ISignValue SignByPublicKey(ArraySegment<byte> buffer, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(byte[] buffer);

        ISignValue SignByPrivateKey(byte[] buffer, HashAlgorithmName hashAlgorithmName);

        ISignValue SignByPrivateKey(byte[] buffer, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(byte[] buffer, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(byte[] buffer, int offset, int count);

        ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName);

        ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(string text, Encoding encoding = null);

        ISignValue SignByPrivateKey(string text, HashAlgorithmName hashAlgorithmName, Encoding encoding = null);

        ISignValue SignByPrivateKey(string text, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(string text, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(string text, Encoding encoding, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(string text, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(ArraySegment<byte> buffer);

        ISignValue SignByPrivateKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName);

        ISignValue SignByPrivateKey(ArraySegment<byte> buffer, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        #endregion

        #region Verify

        bool VerifyByPublicKey(byte[] buffer, byte[] signature);

        bool VerifyByPublicKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName);

        bool VerifyByPublicKey(byte[] buffer, byte[] signature, CancellationToken cancellationToken);

        bool VerifyByPublicKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature);

        bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName);

        bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, CancellationToken cancellationToken);

        bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        bool VerifyByPublicKey(string text, string signature, Encoding encoding = null);

        bool VerifyByPublicKey(string text, string signature, HashAlgorithmName hashAlgorithmName, Encoding encoding = null);

        bool VerifyByPublicKey(string text, string signature, CancellationToken cancellationToken);

        bool VerifyByPublicKey(string text, string signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        bool VerifyByPublicKey(string text, string signature, Encoding encoding, CancellationToken cancellationToken);

        bool VerifyByPublicKey(string text, string signature, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken);
        
        bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature);

        bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName);

        bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, CancellationToken cancellationToken);

        bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(byte[] buffer, byte[] signature);

        bool VerifyByPrivateKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName);

        bool VerifyByPrivateKey(byte[] buffer, byte[] signature, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature);

        bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName);

        bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(string text, string signature, Encoding encoding = null);

        bool VerifyByPrivateKey(string text, string signature, HashAlgorithmName hashAlgorithmName, Encoding encoding = null);

        bool VerifyByPrivateKey(string text, string signature, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(string text, string signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(string text, string signature, Encoding encoding, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(string text, string signature, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature);

        bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName);

        bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        #endregion
    }
#else
    public interface IRSA
    {
        #region Encrypt

        ICryptoValue EncryptByPublicKey(byte[] originalBytes);

        ICryptoValue EncryptByPublicKey(byte[] originalBytes, RSAEncryptionPadding padding);

        ICryptoValue EncryptByPublicKey(byte[] originalBytes, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(byte[] originalBytes, RSAEncryptionPadding padding, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(byte[] originalBytes, int offset, int count);

        ICryptoValue EncryptByPublicKey(byte[] originalBytes, int offset, int count, RSAEncryptionPadding padding);

        ICryptoValue EncryptByPublicKey(byte[] originalBytes, int offset, int count, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(byte[] originalBytes, int offset, int count, RSAEncryptionPadding padding, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(string text, Encoding encoding = null);

        ICryptoValue EncryptByPublicKey(string text, RSAEncryptionPadding padding, Encoding encoding = null);

        ICryptoValue EncryptByPublicKey(string text, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(string text, RSAEncryptionPadding padding, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(string text, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(string text, RSAEncryptionPadding padding, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(ArraySegment<byte> originalBytes);

        ICryptoValue EncryptByPublicKey(ArraySegment<byte> originalBytes, RSAEncryptionPadding padding);

        ICryptoValue EncryptByPublicKey(ArraySegment<byte> originalBytes, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(ArraySegment<byte> originalBytes, RSAEncryptionPadding padding, CancellationToken cancellationToken);

        ICryptoValue EncryptByPrivateKey(byte[] originalBytes);

        ICryptoValue EncryptByPrivateKey(byte[] originalBytes, RSAEncryptionPadding padding);

        ICryptoValue EncryptByPrivateKey(byte[] originalBytes, CancellationToken cancellationToken);

        ICryptoValue EncryptByPrivateKey(byte[] originalBytes, RSAEncryptionPadding padding, CancellationToken cancellationToken);

        ICryptoValue EncryptByPrivateKey(byte[] originalBytes, int offset, int count);

        ICryptoValue EncryptByPrivateKey(byte[] originalBytes, int offset, int count, RSAEncryptionPadding padding);

        ICryptoValue EncryptByPrivateKey(byte[] originalBytes, int offset, int count, CancellationToken cancellationToken);

        ICryptoValue EncryptByPrivateKey(byte[] originalBytes, int offset, int count, RSAEncryptionPadding padding, CancellationToken cancellationToken);

        ICryptoValue EncryptByPrivateKey(string text, Encoding encoding = null);

        ICryptoValue EncryptByPrivateKey(string text, RSAEncryptionPadding padding, Encoding encoding = null);

        ICryptoValue EncryptByPrivateKey(string text, CancellationToken cancellationToken);

        ICryptoValue EncryptByPrivateKey(string text, RSAEncryptionPadding padding, CancellationToken cancellationToken);

        ICryptoValue EncryptByPrivateKey(string text, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue EncryptByPrivateKey(string text, RSAEncryptionPadding padding, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue EncryptByPrivateKey(ArraySegment<byte> originalBytes);

        ICryptoValue EncryptByPrivateKey(ArraySegment<byte> originalBytes, RSAEncryptionPadding padding);

        ICryptoValue EncryptByPrivateKey(ArraySegment<byte> originalBytes, CancellationToken cancellationToken);

        ICryptoValue EncryptByPrivateKey(ArraySegment<byte> originalBytes, RSAEncryptionPadding padding, CancellationToken cancellationToken);

        #endregion

        #region Decrypt

        ICryptoValue DecryptByPublicKey(byte[] buffer);

        ICryptoValue DecryptByPublicKey(byte[] buffer, RSAEncryptionPadding padding);

        ICryptoValue DecryptByPublicKey(byte[] buffer, CancellationToken cancellationToken);

        ICryptoValue DecryptByPublicKey(byte[] buffer, RSAEncryptionPadding padding, CancellationToken cancellationToken);

        ICryptoValue DecryptByPublicKey(byte[] buffer, int offset, int count);

        ICryptoValue DecryptByPublicKey(byte[] buffer, int offset, int count, RSAEncryptionPadding padding);

        ICryptoValue DecryptByPublicKey(byte[] buffer, int offset, int count, CancellationToken cancellationToken);

        ICryptoValue DecryptByPublicKey(byte[] buffer, int offset, int count, RSAEncryptionPadding padding, CancellationToken cancellationToken);

        ICryptoValue DecryptByPublicKey(string cipherText, Encoding encoding = null);

        ICryptoValue DecryptByPublicKey(string cipherText, RSAEncryptionPadding padding, Encoding encoding = null);

        ICryptoValue DecryptByPublicKey(string cipherText, CancellationToken cancellationToken);

        ICryptoValue DecryptByPublicKey(string cipherText, RSAEncryptionPadding padding, CancellationToken cancellationToken);

        ICryptoValue DecryptByPublicKey(string cipherText, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue DecryptByPublicKey(string cipherText, RSAEncryptionPadding padding, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue DecryptByPublicKey(string cipherText,CipherTextTypes cipherTextType,  Encoding encoding = null, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue DecryptByPublicKey(string cipherText,CipherTextTypes cipherTextType,  RSAEncryptionPadding padding, Encoding encoding = null, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue DecryptByPublicKey(string cipherText,CipherTextTypes cipherTextType,  CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue DecryptByPublicKey(string cipherText, CipherTextTypes cipherTextType, RSAEncryptionPadding padding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue DecryptByPublicKey(string cipherText,CipherTextTypes cipherTextType,  Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue DecryptByPublicKey(string cipherText, CipherTextTypes cipherTextType, RSAEncryptionPadding padding, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null);
        
        ICryptoValue DecryptByPublicKey(ArraySegment<byte> buffer);

        ICryptoValue DecryptByPublicKey(ArraySegment<byte> buffer, RSAEncryptionPadding padding);

        ICryptoValue DecryptByPublicKey(ArraySegment<byte> buffer, CancellationToken cancellationToken);

        ICryptoValue DecryptByPublicKey(ArraySegment<byte> buffer, RSAEncryptionPadding padding, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(byte[] buffer);

        ICryptoValue DecryptByPrivateKey(byte[] buffer, RSAEncryptionPadding padding);

        ICryptoValue DecryptByPrivateKey(byte[] buffer, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(byte[] buffer, RSAEncryptionPadding padding, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(byte[] buffer, int offset, int count);

        ICryptoValue DecryptByPrivateKey(byte[] buffer, int offset, int count, RSAEncryptionPadding padding);

        ICryptoValue DecryptByPrivateKey(byte[] buffer, int offset, int count, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(byte[] buffer, int offset, int count, RSAEncryptionPadding padding, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(string cipherText, Encoding encoding = null);

        ICryptoValue DecryptByPrivateKey(string cipherText, RSAEncryptionPadding padding, Encoding encoding = null);

        ICryptoValue DecryptByPrivateKey(string cipherText, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(string cipherText, RSAEncryptionPadding padding, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(string cipherText, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(string cipherText, RSAEncryptionPadding padding, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType,  Encoding encoding = null, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType,  RSAEncryptionPadding padding, Encoding encoding = null, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType,  CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType,  RSAEncryptionPadding padding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue DecryptByPrivateKey(string cipherText,  CipherTextTypes cipherTextType, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue DecryptByPrivateKey(string cipherText, CipherTextTypes cipherTextType, RSAEncryptionPadding padding, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customCipherTextConverter = null);

        ICryptoValue DecryptByPrivateKey(ArraySegment<byte> buffer);

        ICryptoValue DecryptByPrivateKey(ArraySegment<byte> buffer, RSAEncryptionPadding padding);

        ICryptoValue DecryptByPrivateKey(ArraySegment<byte> buffer, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(ArraySegment<byte> buffer, RSAEncryptionPadding padding, CancellationToken cancellationToken);

        #endregion

        #region Sign

        ISignValue SignByPublicKey(byte[] buffer);

        ISignValue SignByPublicKey(byte[] buffer, RSASignaturePadding padding);

        ISignValue SignByPublicKey(byte[] buffer, HashAlgorithmName hashAlgorithmName);

        ISignValue SignByPublicKey(byte[] buffer, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding);

        ISignValue SignByPublicKey(byte[] buffer, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(byte[] buffer, RSASignaturePadding padding, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(byte[] buffer, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(byte[] buffer, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(byte[] buffer, int offset, int count);

        ISignValue SignByPublicKey(byte[] buffer, int offset, int count, RSASignaturePadding padding);

        ISignValue SignByPublicKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName);

        ISignValue SignByPublicKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding);

        ISignValue SignByPublicKey(byte[] buffer, int offset, int count, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(byte[] buffer, int offset, int count, RSASignaturePadding padding, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(string text, Encoding encoding = null);

        ISignValue SignByPublicKey(string text, RSASignaturePadding padding, Encoding encoding = null);

        ISignValue SignByPublicKey(string text, HashAlgorithmName hashAlgorithmName, Encoding encoding = null);

        ISignValue SignByPublicKey(string text, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding = null);

        ISignValue SignByPublicKey(string text, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(string text, RSASignaturePadding padding, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(string text, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(string text, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(string text, Encoding encoding, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(string text, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(string text, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(string text, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(ArraySegment<byte> buffer);

        ISignValue SignByPublicKey(ArraySegment<byte> buffer, RSASignaturePadding padding);

        ISignValue SignByPublicKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName);

        ISignValue SignByPublicKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding);

        ISignValue SignByPublicKey(ArraySegment<byte> buffer, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(ArraySegment<byte> buffer, RSASignaturePadding padding, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(byte[] buffer);

        ISignValue SignByPrivateKey(byte[] buffer, RSASignaturePadding padding);

        ISignValue SignByPrivateKey(byte[] buffer, HashAlgorithmName hashAlgorithmName);

        ISignValue SignByPrivateKey(byte[] buffer, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding);

        ISignValue SignByPrivateKey(byte[] buffer, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(byte[] buffer, RSASignaturePadding padding, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(byte[] buffer, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(byte[] buffer, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(byte[] buffer, int offset, int count);

        ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, RSASignaturePadding padding);

        ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName);

        ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding);

        ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, RSASignaturePadding padding, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(string text, Encoding encoding = null);

        ISignValue SignByPrivateKey(string text, RSASignaturePadding padding, Encoding encoding = null);

        ISignValue SignByPrivateKey(string text, HashAlgorithmName hashAlgorithmName, Encoding encoding = null);

        ISignValue SignByPrivateKey(string text, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding = null);

        ISignValue SignByPrivateKey(string text, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(string text, RSASignaturePadding padding, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(string text, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(string text, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(string text, Encoding encoding, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(string text, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(string text, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(string text, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(ArraySegment<byte> buffer);

        ISignValue SignByPrivateKey(ArraySegment<byte> buffer, RSASignaturePadding padding);

        ISignValue SignByPrivateKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName);

        ISignValue SignByPrivateKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding);

        ISignValue SignByPrivateKey(ArraySegment<byte> buffer, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(ArraySegment<byte> buffer, RSASignaturePadding padding, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken);

        #endregion

        #region Verify

        bool VerifyByPublicKey(byte[] buffer, byte[] signature);

        bool VerifyByPublicKey(byte[] buffer, byte[] signature, RSASignaturePadding padding);

        bool VerifyByPublicKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName);

        bool VerifyByPublicKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding);

        bool VerifyByPublicKey(byte[] buffer, byte[] signature, CancellationToken cancellationToken);

        bool VerifyByPublicKey(byte[] buffer, byte[] signature, RSASignaturePadding padding, CancellationToken cancellationToken);

        bool VerifyByPublicKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        bool VerifyByPublicKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken);

        bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature);

        bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, RSASignaturePadding padding);

        bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName);

        bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding);

        bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, CancellationToken cancellationToken);

        bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, RSASignaturePadding padding, CancellationToken cancellationToken);

        bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken);

        bool VerifyByPublicKey(string text, string signature, Encoding encoding = null);

        bool VerifyByPublicKey(string text, string signature, RSASignaturePadding padding, Encoding encoding = null);

        bool VerifyByPublicKey(string text, string signature, HashAlgorithmName hashAlgorithmName, Encoding encoding = null);

        bool VerifyByPublicKey(string text, string signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding = null);

        bool VerifyByPublicKey(string text, string signature, CancellationToken cancellationToken);

        bool VerifyByPublicKey(string text, string signature, RSASignaturePadding padding, CancellationToken cancellationToken);

        bool VerifyByPublicKey(string text, string signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        bool VerifyByPublicKey(string text, string signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken);

        bool VerifyByPublicKey(string text, string signature, Encoding encoding, CancellationToken cancellationToken);

        bool VerifyByPublicKey(string text, string signature, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken);

        bool VerifyByPublicKey(string text, string signature, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken);

        bool VerifyByPublicKey(string text, string signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken);

        bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, RSASignaturePadding padding, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, RSASignaturePadding padding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPublicKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature);

        bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, RSASignaturePadding padding);

        bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName);

        bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding);

        bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, CancellationToken cancellationToken);

        bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, RSASignaturePadding padding, CancellationToken cancellationToken);

        bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(byte[] buffer, byte[] signature);

        bool VerifyByPrivateKey(byte[] buffer, byte[] signature, RSASignaturePadding padding);

        bool VerifyByPrivateKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName);

        bool VerifyByPrivateKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding);

        bool VerifyByPrivateKey(byte[] buffer, byte[] signature, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(byte[] buffer, byte[] signature, RSASignaturePadding padding, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(byte[] buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature);

        bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, RSASignaturePadding padding);

        bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName);

        bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding);

        bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, RSASignaturePadding padding, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(string text, string signature, Encoding encoding = null);

        bool VerifyByPrivateKey(string text, string signature, RSASignaturePadding padding, Encoding encoding = null);

        bool VerifyByPrivateKey(string text, string signature, HashAlgorithmName hashAlgorithmName, Encoding encoding = null);

        bool VerifyByPrivateKey(string text, string signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding = null);

        bool VerifyByPrivateKey(string text, string signature, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(string text, string signature, RSASignaturePadding padding, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(string text, string signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(string text, string signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(string text, string signature, Encoding encoding, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(string text, string signature, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(string text, string signature, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(string text, string signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, RSASignaturePadding padding, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding = null, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, RSASignaturePadding padding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPrivateKey(string text, string signature, SignatureTextTypes signatureTextType, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding, CancellationToken cancellationToken, Func<string, byte[]> customSignatureTextConverter = null);

        bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature);

        bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, RSASignaturePadding padding);

        bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName);

        bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding);

        bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, RSASignaturePadding padding, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken);

        #endregion
    }
#endif
}