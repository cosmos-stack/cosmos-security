using System;
using System.Security.Cryptography;
using System.Threading;
using Cosmos.Security.Cryptography.Core.AsymmetricAlgorithmImpls;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Cryptography
{
    internal sealed class DsaFunction : AsymmetricSignFunction<DsaKey>, IDSA
    {
        public DsaFunction(DsaKey key)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
        }

        public override DsaKey Key { get; }

        public override int KeySize => Key.Size;

        protected override ISignValue SignInternal(ArraySegment<byte> buffer, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePrivateKey())
                throw new ArgumentException("The PrivateKey does not exist and cannot be signed.");

            using var provider = new DSACryptoServiceProvider();

            provider.FromXmlString(Key.PrivateKey);

            var signature = provider.SignData(GetBytes(buffer));

            return CreateSignValue(signature);
        }

        protected override bool VerifyInternal(ArraySegment<byte> rgbData, ArraySegment<byte> rgbSignature, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Key.IncludePublicKey())
                throw new ArgumentException("The PublicKey does not exist and cannot be signed.");

            using var provider = new DSACryptoServiceProvider();

            provider.FromXmlString(Key.PublicKey);

            return provider.VerifyData(GetBytes(rgbData), GetBytes(rgbSignature));
        }
    }
}