using System;
using System.Text;
using System.Threading;

// ReSharper disable InconsistentNaming
// ReSharper disable CheckNamespace

namespace Cosmos.Security.Cryptography
{
    public interface ISM2 : IAsymmetricCryptoFunction
    {
        #region Encrypt

        ICryptoValue EncryptByPublicKey(byte[] originalBytes);

        ICryptoValue EncryptByPublicKey(byte[] originalBytes, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(byte[] originalBytes, int offset, int count);

        ICryptoValue EncryptByPublicKey(byte[] originalBytes, int offset, int count, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(string text, Encoding encoding = null);

        ICryptoValue EncryptByPublicKey(string text, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(string text, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue EncryptByPublicKey(ArraySegment<byte> originalBytes);

        ICryptoValue EncryptByPublicKey(ArraySegment<byte> originalBytes, CancellationToken cancellationToken);

        #endregion

        #region Decrypt

        ICryptoValue DecryptByPrivateKey(byte[] buffer);

        ICryptoValue DecryptByPrivateKey(byte[] buffer, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(byte[] buffer, int offset, int count);

        ICryptoValue DecryptByPrivateKey(byte[] buffer, int offset, int count, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(string text, Encoding encoding = null);

        ICryptoValue DecryptByPrivateKey(string text, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(string text, Encoding encoding, CancellationToken cancellationToken);

        ICryptoValue DecryptByPrivateKey(ArraySegment<byte> buffer);

        ICryptoValue DecryptByPrivateKey(ArraySegment<byte> buffer, CancellationToken cancellationToken);

        #endregion

        #region Sign

        ISignValue SignByPublicKey(byte[] buffer);

        ISignValue SignByPublicKey(byte[] buffer, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(byte[] buffer, int offset, int count);

        ISignValue SignByPublicKey(byte[] buffer, int offset, int count, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(string text, Encoding encoding = null);

        ISignValue SignByPublicKey(string text, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(string text, Encoding encoding, CancellationToken cancellationToken);

        ISignValue SignByPublicKey(ArraySegment<byte> buffer);

        ISignValue SignByPublicKey(ArraySegment<byte> buffer, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(byte[] buffer);

        ISignValue SignByPrivateKey(byte[] buffer, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(byte[] buffer, int offset, int count);

        ISignValue SignByPrivateKey(byte[] buffer, int offset, int count, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(string text, Encoding encoding = null);

        ISignValue SignByPrivateKey(string text, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(string text, Encoding encoding, CancellationToken cancellationToken);

        ISignValue SignByPrivateKey(ArraySegment<byte> buffer);

        ISignValue SignByPrivateKey(ArraySegment<byte> buffer, CancellationToken cancellationToken);

        #endregion

        #region Verify

        bool VerifyByPublicKey(byte[] buffer, byte[] signature);

        bool VerifyByPublicKey(byte[] buffer, byte[] signature, CancellationToken cancellationToken);

        bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature);

        bool VerifyByPublicKey(byte[] buffer, int offset, int count, byte[] signature, CancellationToken cancellationToken);

        bool VerifyByPublicKey(string text, string signature, Encoding encoding = null);

        bool VerifyByPublicKey(string text, string signature, CancellationToken cancellationToken);

        bool VerifyByPublicKey(string text, string signature, Encoding encoding, CancellationToken cancellationToken);

        bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature);

        bool VerifyByPublicKey(ArraySegment<byte> buffer, byte[] signature, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(byte[] buffer, byte[] signature);

        bool VerifyByPrivateKey(byte[] buffer, byte[] signature, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature);

        bool VerifyByPrivateKey(byte[] buffer, int offset, int count, byte[] signature, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(string text, string signature, Encoding encoding = null);

        bool VerifyByPrivateKey(string text, string signature, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(string text, string signature, Encoding encoding, CancellationToken cancellationToken);

        bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature);

        bool VerifyByPrivateKey(ArraySegment<byte> buffer, byte[] signature, CancellationToken cancellationToken);

        #endregion
    }
}