using System;
using System.Linq;
using System.Text;
using System.Threading;
using Cosmos.Security.Cryptography.Core;
using Cosmos.Security.Cryptography.Core.Internals;
using Cosmos.Security.Cryptography.Core.SymmetricAlgorithmImpls;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Cryptography
{
    internal class CeaserFunction : SymmetricCryptoFunction<int>, ICeaser
    {
        public CeaserFunction(int key)
        {
            Key = key;
        }

        public override int Key { get; }

        public override int KeySize => 32;

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

        private static Func<int, Func<string, Func<CryptoMode, string>>> ProcessFunc() => key => message => mode =>
        {
            var sbRet = new StringBuilder();
            var alphabet = AlphabetDictionaryGenerator.Generate();

            foreach (var c in message)
            {
                var res = AlgorithmUtils.GetAlphabetPositionFunc()
                    (alphabet[c]) /*char position*/
                    (key)
                    (mode); /*encryption algorithm mode*/

                sbRet.Append(alphabet.Keys.ElementAt(res % 26));
            }

            return sbRet.ToString();
        };
    }
}