using System;
#if NETFRAMEWORK
using System.Linq;
#endif
using System.Security.Cryptography;
using System.Threading;
using Cosmos.Security.Cryptography.Core.SymmetricAlgorithmImpls;

// ReSharper disable CheckNamespace
namespace Cosmos.Security.Cryptography
{
    internal class TripleDesFunction : LogicSymmetricCryptoFunction<DesKey>, IDES
    {
        public TripleDesFunction(DesKey key)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
        }

        public override DesKey Key { get; }

        public override int KeySize => Key.Size;

        protected override ICryptoValue EncryptInternal(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
            var cipher = EncryptCore<TripleDESCryptoServiceProvider>(originalBytes, Key.GetKey(), Key.GetIV());
            return CreateCryptoValue(originalBytes.ToArray(), cipher, CryptoMode.Encrypt);
        }

        protected override ICryptoValue EncryptInternal(ArraySegment<byte> originalBytes, byte[] saltBytes, CancellationToken cancellationToken)
        {
            var cipher = EncryptCore<TripleDESCryptoServiceProvider>(originalBytes, Key.GetKey(saltBytes), Key.GetIV(saltBytes));
            return CreateCryptoValue(originalBytes.ToArray(), cipher, CryptoMode.Encrypt);
        }

        protected override ICryptoValue DecryptInternal(ArraySegment<byte> cipherBytes, CancellationToken cancellationToken)
        {
            var original = DecryptCore<TripleDESCryptoServiceProvider>(cipherBytes, Key.GetKey(), Key.GetIV());
            return CreateCryptoValue(original, cipherBytes.ToArray(), CryptoMode.Decrypt);
        }

        protected override ICryptoValue DecryptInternal(ArraySegment<byte> cipherBytes, byte[] saltBytes, CancellationToken cancellationToken)
        {
            var original = DecryptCore<TripleDESCryptoServiceProvider>(cipherBytes, Key.GetKey(saltBytes), Key.GetIV(saltBytes));
            return CreateCryptoValue(original, cipherBytes.ToArray(), CryptoMode.Decrypt);
        }
    }
}