using System;
using System.Text;
using System.Threading;
using Cosmos.Security.Cryptography.Core;
using Cosmos.Security.Cryptography.Core.Internals;
using Cosmos.Security.Cryptography.Core.SymmetricAlgorithmImpls;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Cryptography
{
    internal class VigenereFunction : SymmetricCryptoFunction<string>, IVigenere
    {
        public VigenereFunction(string key)
        {
            Key = key;
        }

        public override string Key { get; }

        public override int KeySize => Key.Length;

        protected override ICryptoValue EncryptInternal(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var original = GetString(originalBytes, Encoding.UTF8);
            return CreateCryptoValue(original,
                ProcessFunc()(Key)(original)(CryptoMode.Encrypt),
                CryptoMode.Encrypt);
        }

        protected override ICryptoValue DecryptInternal(ArraySegment<byte> cipherBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var cipher = GetString(cipherBytes, Encoding.UTF8);
            return CreateCryptoValue(
                ProcessFunc()(Key)(cipher)(CryptoMode.Decrypt),
                cipher,
                CryptoMode.Decrypt);
        }
        
        private static Func<string, Func<string, Func<CryptoMode, string>>> ProcessFunc() => key => message => mode =>
        {
            key = key.ToString().ToLower().Replace(" ", "");
            key = DuplicateKeyFunc()(key)(message);
            return AlgorithmUtils.Shift(message, key, mode, AlphabetDictionaryGenerator.Generate());
        };

        private static Func<string, Func<string, string>> DuplicateKeyFunc() => key => message =>
        {
            if (key.Length < message.Length)
            {
                var length = message.Length - key.Length;

                for (var i = 0; i < length; i++)
                {
                    key += key[i % key.Length];
                }
            }

            return key;
        };
    }
}