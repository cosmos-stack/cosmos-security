using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Cosmos.Security.Cryptography;
using Cosmos.Security.Encryption.Abstractions;
using Cosmos.Security.Encryption.Core.Internals;

namespace Cosmos.Security.Encryption.Algorithms
{
    /// <summary>
    /// Monoalphabetic encryption algorithm
    /// for more info, please view:
    ///     https://www.codeproject.com/Articles/63432/Classical-Encryption-Techniques
    /// Author: Omar-Salem
    ///     https://github.com/Omar-Salem/Classical-Encryption-Techniques/blob/master/EncryptionAlgorithms/Concrete/Monoalphabetic.cs
    /// </summary>
    // ReSharper disable once IdentifierTypo
    public sealed class Monoalphabetic : ICryptoAlgorithm
    {
        private Dictionary<char, char> AlphabetShuffled { get; }
        private Dictionary<char, char> AlphabetShuffledReverse { get; }

        /// <summary>
        /// Create a new instance of <see cref="Monoalphabetic"/>
        /// </summary>
        // ReSharper disable once IdentifierTypo
        public Monoalphabetic()
        {
            AlphabetShuffledReverse = new Dictionary<char, char>();
            AlphabetShuffled = new Dictionary<char, char>();
            ShuffleAlphabet();
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="plainText"></param>
        /// <returns></returns>
        public string Encrypt(string plainText) =>
            ProcessFunc()(AlphabetShuffled)(AlphabetShuffledReverse)(plainText)(EncryptionAlgorithmMode.Encrypt);

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns></returns>
        public string Decrypt(string cipher) =>
            ProcessFunc()(AlphabetShuffled)(AlphabetShuffledReverse)(cipher)(EncryptionAlgorithmMode.Decrypt);

        private static Func<Dictionary<char, char>, Func<Dictionary<char, char>, Func<string, Func<EncryptionAlgorithmMode, string>>>> ProcessFunc()
            => alphabetShuffled => alphabetShuffledReverse => token => mode =>
            {
                var sbRet = new StringBuilder();

                for (var i = 0; i < token.Length; i++)
                {
                    switch (mode)
                    {
                        case EncryptionAlgorithmMode.Encrypt:
                            sbRet.Append(alphabetShuffled[token[i]]);
                            break;
                        case EncryptionAlgorithmMode.Decrypt:
                            sbRet.Append(alphabetShuffledReverse[token[i]]);
                            break;
                    }
                }

                return sbRet.ToString();
            };

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
    }
}