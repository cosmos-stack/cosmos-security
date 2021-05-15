using System;
using Cosmos.Security.Cryptography.Core.AsymmetricAlgorithmImpls;

// ReSharper disable CheckNamespace

namespace Cosmos.Security.Cryptography
{
    internal abstract partial class Sm2CryptoFunction : AsymmetricCryptoFunction<Sm2Key>, ISM2
    {
        protected Sm2CryptoFunction(Sm2Key key)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
        }

        public override Sm2Key Key { get; }

        public override int KeySize => Key.Size;
    }
}