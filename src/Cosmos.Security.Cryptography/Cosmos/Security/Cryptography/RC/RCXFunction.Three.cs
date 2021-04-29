using System;
using System.Linq;
using System.Threading;
using Cosmos.Security.Cryptography.Core;
using Cosmos.Security.Cryptography.Core.SymmetricAlgorithmImpls;

// ReSharper disable CheckNamespace
// ReSharper disable InconsistentNaming

namespace Cosmos.Security.Cryptography
{
    internal class ThreeRCXFunction : SymmetricCryptoFunction<RcKey>, IRC
    {
        public ThreeRCXFunction(RcKey key, RcOrder order = RcOrder.DESC)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
            Order = order;
        }

        public override RcKey Key { get; }

        public override int KeySize => Key.Size;

        public RcOrder Order { get; set; }

        protected override ICryptoValue EncryptInternal(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var data = GetBytes(originalBytes);
            var cipher = EncryptCore(data, Key.GetKey(), Order);
            return CreateCryptoValue(data, cipher, CryptoMode.Encrypt);
        }

        protected override ICryptoValue DecryptInternal(ArraySegment<byte> cipherBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var cipher = GetBytes(cipherBytes);
            var original = EncryptCore(cipher, Key.GetKey(), Order);
            return CreateCryptoValue(original, cipher, CryptoMode.Decrypt);
        }

        private static byte[] EncryptCore(byte[] dataBytes, byte[] keyBytes, RcOrder order = RcOrder.DESC)
        {
            var pointer = dataBytes;

            for (var counter = 0; counter < 3; ++counter)
                pointer = RCXFunction.EncryptCore(pointer, keyBytes, order);

            return pointer;
        }
    }
}