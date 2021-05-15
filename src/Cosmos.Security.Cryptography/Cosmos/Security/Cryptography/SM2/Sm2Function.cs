using System;
using System.Threading;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

// ReSharper disable CheckNamespace

namespace Cosmos.Security.Cryptography
{
    internal sealed class Sm2Function : Sm2CryptoFunction, ISM2
    {
        public Sm2Function(Sm2Key key) : base(key) { }

        #region Encrypt

        protected override ICryptoValue EncryptInternal(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
            return EncryptByPublicKeyInternal(originalBytes, cancellationToken);
        }

        protected override ICryptoValue EncryptByPublicKeyInternal(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePublicKey())
                throw new ArgumentException("There is no PublicKey in current Sm2Key instance.");

            // get public key
            var publicKey = Key.GetPublicKey();
            var cipherParams = publicKey.Parameters;
            var parametersWithRandom = new ParametersWithRandom(cipherParams);

            // create a sm2 engine
            var engine = new SM2Engine();

            // init
            engine.Init(true, parametersWithRandom);

            // encrypt
            var cipherBytes = engine.ProcessBlock(originalBytes.Array, originalBytes.Offset, originalBytes.Count);

            return CreateCryptoValue(GetBytes(originalBytes), cipherBytes, CryptoMode.Encrypt);
        }

        #endregion

        #region Decrypt

        protected override ICryptoValue DecryptInternal(ArraySegment<byte> cipherBytes, CancellationToken cancellationToken)
        {
            return DecryptByPrivateKeyInternal(cipherBytes, cancellationToken);
        }

        protected override ICryptoValue DecryptByPrivateKeyInternal(ArraySegment<byte> cipherBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePrivateKey())
                throw new ArgumentException("There is no PrivateKey in current Sm2Key instance.");

            // get private key
            var privateKey = Key.GetPrivateKey();
            var cipherParams = privateKey.Parameters;

            // create a sm2 engine
            var engine = new SM2Engine();

            // init
            engine.Init(false, cipherParams);

            // decrypt
            var originalBytes = engine.ProcessBlock(cipherBytes.Array, cipherBytes.Offset, cipherBytes.Count);

            return CreateCryptoValue(originalBytes, GetBytes(cipherBytes), CryptoMode.Decrypt);
        }

        #endregion

        #region Sign

        protected override ISignValue SignInternal(ArraySegment<byte> buffer, CancellationToken cancellationToken)
        {
            return SignByPrivateKeyInternal(buffer, cancellationToken);
        }

        protected override ISignValue SignByPublicKeyInternal(ArraySegment<byte> buffer, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePublicKey())
                throw new ArgumentException("There is no PublicKey in current Sm2Key instance.");

            // get public key
            var publicKey = Key.GetPublicKey();

            // create a signer
            var signer = new SM2Signer();

            // init
            signer.Init(true, publicKey);

            signer.BlockUpdate(buffer.Array, buffer.Offset, buffer.Count);

            var signature = signer.GenerateSignature();

            return CreateSignValue(signature);
        }

        protected override ISignValue SignByPrivateKeyInternal(ArraySegment<byte> buffer, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePrivateKey())
                throw new ArgumentException("There is no PrivateKey in current Sm2Key instance.");

            // get private key
            var privateKey = Key.GetPrivateKey();

            // create a signer
            var signer = new SM2Signer();

            // init
            signer.Init(true, privateKey);

            signer.BlockUpdate(buffer.Array, buffer.Offset, buffer.Count);

            var signature = signer.GenerateSignature();

            return CreateSignValue(signature);
        }

        #endregion

        #region Verify

        protected override bool VerifyInternal(ArraySegment<byte> rgbData, ArraySegment<byte> rgbSignature, CancellationToken cancellationToken)
        {
            return VerifyByPublicKeyInternal(rgbData, GetBytes(rgbSignature), cancellationToken);
        }

        protected override bool VerifyByPublicKeyInternal(ArraySegment<byte> buffer, byte[] signature, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePublicKey())
                throw new ArgumentException("There is no PublicKey in current Sm2Key instance.");

            // get public key
            var publicKey = Key.GetPublicKey();

            // create a signer
            var signer = new SM2Signer();

            // init
            signer.Init(false, publicKey);

            signer.BlockUpdate(buffer.Array, buffer.Offset, buffer.Count);

            return signer.VerifySignature(signature);
        }

        protected override bool VerifyByPrivateKeyInternal(ArraySegment<byte> buffer, byte[] signature, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePrivateKey())
                throw new ArgumentException("There is no PrivateKey in current Sm2Key instance.");

            // get private key
            var privateKey = Key.GetPrivateKey();

            // create a signer
            var signer = new SM2Signer();

            // init
            signer.Init(false, privateKey);

            signer.BlockUpdate(buffer.Array, buffer.Offset, buffer.Count);

            return signer.VerifySignature(signature);
        }

        #endregion
    }
}