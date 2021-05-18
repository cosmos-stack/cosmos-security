using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

// ReSharper disable RedundantAssignment
// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Cryptography
{
    internal sealed class RsaFunction : RsaCryptoFunction, IRSA
    {
        public RsaFunction(RsaKey key) : base(key) { }

        #region Encrypt

        protected override ICryptoValue EncryptInternal(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
#if NET451 || NET452
            return EncryptByPublicKeyInternal(originalBytes, true, cancellationToken);
#else
            return EncryptByPublicKeyInternal(originalBytes, RSAEncryptionPadding.Pkcs1, cancellationToken);
#endif
        }

#if NET451 || NET452
        protected override ICryptoValue EncryptByPublicKeyInternal(ArraySegment<byte> originalBytes, bool fOEAP, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePublicKey())
                throw new ArgumentException("There is no PublicKey in current RsaKey instance.");
            var rsa = TouchRsaUtilFromPublicKey(Key.Format, Encoding.UTF8, Key.PublicKey, Key.Size);

            var originalData = GetBytes(originalBytes);
            var cipherData = rsa.EncryptByPublicKey(originalData, fOEAP);

            return CreateCryptoValue(originalData, cipherData, CryptoMode.Encrypt);
        }

        protected override ICryptoValue EncryptByPrivateKeyInternal(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePrivateKey())
                throw new ArgumentException("There is no PrivateKey in current RsaKey instance.");
            var rsa = TouchRsaUtilFromPrivateKey(Key.Format, Encoding.UTF8, Key.PrivateKey, Key.Size);

            var originalData = GetBytes(originalBytes);

            var cipherData = rsa.EncryptByPrivateKey(originalData);

            return CreateCryptoValue(originalData, cipherData, CryptoMode.Encrypt);
        }
#else
        protected override ICryptoValue EncryptByPublicKeyInternal(ArraySegment<byte> originalBytes, RSAEncryptionPadding padding, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePublicKey())
                throw new ArgumentException("There is no PublicKey in current RsaKey instance.");
            var rsa = TouchRsaUtilFromPublicKey(Key.Format, Encoding.UTF8, Key.PublicKey, Key.Size);

            var originalData = GetBytes(originalBytes);
            var cipherData = rsa.EncryptByPublicKey(originalData, padding);

            return CreateCryptoValue(originalData, cipherData, CryptoMode.Encrypt);
        }

        protected override ICryptoValue EncryptByPrivateKeyInternal(ArraySegment<byte> originalBytes, RSAEncryptionPadding padding, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePrivateKey())
                throw new ArgumentException("There is no PrivateKey in current RsaKey instance.");
            var rsa = TouchRsaUtilFromPrivateKey(Key.Format, Encoding.UTF8, Key.PrivateKey, Key.Size);

            var originalData = GetBytes(originalBytes);

            var cipherData = rsa.EncryptByPrivateKey(originalData, padding);

            return CreateCryptoValue(originalData, cipherData, CryptoMode.Encrypt);
        }
#endif

        #endregion

        #region Decrypt

        protected override ICryptoValue DecryptInternal(ArraySegment<byte> cipherBytes, CancellationToken cancellationToken)
        {
#if NET451 || NET452
            return DecryptByPrivateKeyInternal(cipherBytes, true, cancellationToken);
#else
            return DecryptByPrivateKeyInternal(cipherBytes, RSAEncryptionPadding.Pkcs1, cancellationToken);
#endif
        }

#if NET451 || NET452
        protected override ICryptoValue DecryptByPublicKeyInternal(ArraySegment<byte> cipherBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePublicKey())
                throw new ArgumentException("There is no PublicKey in current RsaKey instance.");
            var rsa = TouchRsaUtilFromPublicKey(Key.Format, Encoding.UTF8, Key.PublicKey, Key.Size);

            var cipherData = GetBytes(cipherBytes);
            var originalData = rsa.DecryptByPublicKey(cipherData);

            return CreateCryptoValue(originalData, cipherData, CryptoMode.Decrypt);
        }

        protected override ICryptoValue DecryptByPrivateKeyInternal(ArraySegment<byte> cipherBytes, bool fOEAP, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePrivateKey())
                throw new ArgumentException("There is no PrivateKey in current RsaKey instance.");
            var rsa = TouchRsaUtilFromPrivateKey(Key.Format, Encoding.UTF8, Key.PrivateKey, Key.Size);

            var cipherData = GetBytes(cipherBytes);

            var originalData = rsa.DecryptByPrivateKey(cipherData, fOEAP);

            return CreateCryptoValue(originalData, cipherData, CryptoMode.Decrypt);
        }
#else
        protected override ICryptoValue DecryptByPublicKeyInternal(ArraySegment<byte> cipherBytes, RSAEncryptionPadding padding, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePublicKey())
                throw new ArgumentException("There is no PublicKey in current RsaKey instance.");
            var rsa = TouchRsaUtilFromPublicKey(Key.Format, Encoding.UTF8, Key.PublicKey, Key.Size);

            var cipherData = GetBytes(cipherBytes);
            var originalData = rsa.DecryptByPublicKey(cipherData, padding);

            return CreateCryptoValue(originalData, cipherData, CryptoMode.Decrypt);
        }

        protected override ICryptoValue DecryptByPrivateKeyInternal(ArraySegment<byte> cipherBytes, RSAEncryptionPadding padding, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePrivateKey())
                throw new ArgumentException("There is no PrivateKey in current RsaKey instance.");
            var rsa = TouchRsaUtilFromPrivateKey(Key.Format, Encoding.UTF8, Key.PrivateKey, Key.Size);

            var cipherData = GetBytes(cipherBytes);

            var originalData = rsa.DecryptByPrivateKey(cipherData, padding);

            return CreateCryptoValue(originalData, cipherData, CryptoMode.Decrypt);
        }
#endif

        #endregion

        #region Sign

        protected override ISignValue SignInternal(ArraySegment<byte> buffer, CancellationToken cancellationToken)
        {
#if NET451 || NET452
            return SignByPrivateKeyInternal(buffer, HashAlgorithmName.MD5, cancellationToken);
#else
            return SignByPrivateKeyInternal(buffer, HashAlgorithmName.MD5, RSASignaturePadding.Pkcs1, cancellationToken);
#endif
        }

#if NET451 || NET452
        protected override ISignValue SignByPublicKeyInternal(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePublicKey())
                throw new ArgumentException("There is no PublicKey in current RsaKey instance.");
            var rsa = TouchRsaUtilFromPublicKey(Key.Format, Encoding.UTF8, Key.PublicKey, Key.Size);

            var signature = rsa.SignByPublicKey(buffer.ToArray(), hashAlgorithmName);

            return CreateSignValue(signature);
        }

        protected override ISignValue SignByPrivateKeyInternal(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePrivateKey())
                throw new ArgumentException("There is no PrivateKey in current RsaKey instance.");
            var rsa = TouchRsaUtilFromPublicKey(Key.Format, Encoding.UTF8, Key.PrivateKey, Key.Size);

            var signature = rsa.SignByPrivateKey(buffer.ToArray(), hashAlgorithmName);

            return CreateSignValue(signature);
        }
#else
        protected override ISignValue SignByPublicKeyInternal(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePublicKey())
                throw new ArgumentException("There is no PublicKey in current RsaKey instance.");
            var rsa = TouchRsaUtilFromPublicKey(Key.Format, Encoding.UTF8, Key.PublicKey, Key.Size);

            var signature = rsa.SignByPublicKey(buffer.ToArray(), hashAlgorithmName, padding);

            return CreateSignValue(signature);
        }

        protected override ISignValue SignByPrivateKeyInternal(ArraySegment<byte> buffer, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePrivateKey())
                throw new ArgumentException("There is no PrivateKey in current RsaKey instance.");
            var rsa = TouchRsaUtilFromPublicKey(Key.Format, Encoding.UTF8, Key.PrivateKey, Key.Size);

            var signature = rsa.SignByPrivateKey(buffer.ToArray(), hashAlgorithmName, padding);

            return CreateSignValue(signature);
        }
#endif

        #endregion

        #region Verify

        protected override bool VerifyInternal(ArraySegment<byte> rgbData, ArraySegment<byte> rgbSignature, CancellationToken cancellationToken)
        {
#if NET451 || NET452
            return VerifyByPublicKeyInternal(rgbData, GetBytes(rgbSignature), HashAlgorithmName.MD5, cancellationToken);
#else
            return VerifyByPublicKeyInternal(rgbData, GetBytes(rgbSignature), HashAlgorithmName.MD5, RSASignaturePadding.Pkcs1, cancellationToken);
#endif
        }

#if NET451 || NET452
        protected override bool VerifyByPublicKeyInternal(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePublicKey())
                throw new ArgumentException("There is no PublicKey in current RsaKey instance.");
            var rsa = TouchRsaUtilFromPublicKey(Key.Format, Encoding.UTF8, Key.PublicKey, Key.Size);

            return rsa.VerifyByPublicKey(buffer.ToArray(), signature, hashAlgorithmName);
        }

        protected override bool VerifyByPrivateKeyInternal(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePrivateKey())
                throw new ArgumentException("There is no PrivateKey in current RsaKey instance.");
            var rsa = TouchRsaUtilFromPublicKey(Key.Format, Encoding.UTF8, Key.PrivateKey, Key.Size);

            return rsa.VerifyByPrivateKey(buffer.ToArray(), signature, hashAlgorithmName);
        }
#else
        protected override bool VerifyByPublicKeyInternal(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePublicKey())
                throw new ArgumentException("There is no PublicKey in current RsaKey instance.");
            var rsa = TouchRsaUtilFromPublicKey(Key.Format, Encoding.UTF8, Key.PublicKey, Key.Size);

            return rsa.VerifyByPublicKey(buffer.ToArray(), signature, hashAlgorithmName, padding);
        }

        protected override bool VerifyByPrivateKeyInternal(ArraySegment<byte> buffer, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePrivateKey())
                throw new ArgumentException("There is no PrivateKey in current RsaKey instance.");
            var rsa = TouchRsaUtilFromPublicKey(Key.Format, Encoding.UTF8, Key.PrivateKey, Key.Size);

            return rsa.VerifyByPrivateKey(buffer.ToArray(), signature, hashAlgorithmName, padding);
        }
#endif

        #endregion

        #region Touch Instance of Internal RSA Impls/Utils

        private static RsaUtilBase TouchRsaUtilFromPublicKey(RsaKeyFormat keyFormat, Encoding encoding, string publicKey, int size)
        {
            RsaUtilBase rsa = keyFormat switch
            {
                RsaKeyFormat.XML => new RsaXmlUtil(encoding, publicKey, keySize: size),
                RsaKeyFormat.JSON => new RsaJsonUtil(encoding, publicKey, keySize: size),
                RsaKeyFormat.Pkcs1 => new RsaPkcs1Util(encoding, publicKey, keySize: size),
                RsaKeyFormat.Pkcs8 => new RsaPkcs8Util(encoding, publicKey, keySize: size),
                _ => throw new NotSupportedException("Unknown RSA key type.")
            };

            return rsa;
        }

        private static RsaUtilBase TouchRsaUtilFromPrivateKey(RsaKeyFormat keyFormat, Encoding encoding, string privateKey, int size)
        {
            RsaUtilBase rsa = keyFormat switch
            {
                RsaKeyFormat.XML => new RsaXmlUtil(encoding, null, privateKey, size),
                RsaKeyFormat.JSON => new RsaJsonUtil(encoding, null, privateKey, size),
                RsaKeyFormat.Pkcs1 => new RsaPkcs1Util(encoding, null, privateKey, size),
                RsaKeyFormat.Pkcs8 => new RsaPkcs8Util(encoding, null, privateKey, size),
                _ => throw new NotSupportedException("Unknown RSA key type."),
            };

            return rsa;
        }

        #endregion
    }
}