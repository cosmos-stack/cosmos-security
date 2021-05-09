using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using Cosmos.Security.Cryptography.Core;
using Cosmos.Security.Cryptography.Core.Internals;
using Cosmos.Security.Cryptography.Core.SymmetricAlgorithmImpls;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Cryptography
{
    internal class MonoalphabeticFunction : SymmetricCryptoFunction<object>, IMonoalphabetic
    {
        private Dictionary<char, char> AlphabetShuffled { get; }
        private Dictionary<char, char> AlphabetShuffledReverse { get; }

        public MonoalphabeticFunction()
        {
            AlphabetShuffledReverse = new Dictionary<char, char>();
            AlphabetShuffled = new Dictionary<char, char>();
            ShuffleAlphabet();
        }

        private void ShuffleAlphabet()
        {
            var r = new Random(DateTime.Now.Millisecond);
            var alphabetKeys = AlphabetDictionaryGenerator.Generate().Keys;
            var alphabetCopy = alphabetKeys.ToList();

            foreach (var character in alphabetKeys)
            {
                var characterPosition = r.Next(0, alphabetCopy.Count);
                var randomCharacter = alphabetCopy[characterPosition];
                AlphabetShuffled.Add(character, randomCharacter);
                AlphabetShuffledReverse.Add(randomCharacter, character);
                alphabetCopy.RemoveAt(characterPosition);
            }
        }

        public override object Key { get; }

        public override int KeySize => 0;

        protected override ICryptoValue EncryptInternal(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var original = GetString(originalBytes, Encoding.UTF8);
            return CreateCryptoValue(original,
                ProcessFunc()(AlphabetShuffled)(AlphabetShuffledReverse)(original)(CryptoMode.Encrypt),
                CryptoMode.Encrypt);
        }

        protected override ICryptoValue DecryptInternal(ArraySegment<byte> cipherBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var cipher = GetString(cipherBytes, Encoding.UTF8);
            return CreateCryptoValue(
                ProcessFunc()(AlphabetShuffled)(AlphabetShuffledReverse)(cipher)(CryptoMode.Decrypt),
                cipher,
                CryptoMode.Decrypt);
        }

        private static Func<Dictionary<char, char>, Func<Dictionary<char, char>, Func<string, Func<CryptoMode, string>>>> ProcessFunc()
            => alphabetShuffled => alphabetShuffledReverse => token => mode =>
            {
                var sbRet = new StringBuilder();

                for (var i = 0; i < token.Length; i++)
                {
                    switch (mode)
                    {
                        case CryptoMode.Encrypt:
                            sbRet.Append(alphabetShuffled[token[i]]);
                            break;
                        case CryptoMode.Decrypt:
                            sbRet.Append(alphabetShuffledReverse[token[i]]);
                            break;
                    }
                }

                return sbRet.ToString();
            };
    }
}