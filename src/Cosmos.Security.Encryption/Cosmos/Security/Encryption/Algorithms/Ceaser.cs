using System;
using System.Linq;
using System.Text;
using Cosmos.Security.Cryptography;
using Cosmos.Security.Encryption.Abstractions;
using Cosmos.Security.Encryption.Core.Internals;

namespace Cosmos.Security.Encryption.Algorithms
{
    /// <summary>
    /// Ceaser encryption algorithm
    /// for more info, please view:
    ///     https://www.codeproject.com/Articles/63432/Classical-Encryption-Techniques
    /// Author: Omar-Salem
    ///     https://github.com/Omar-Salem/Classical-Encryption-Techniques/blob/master/EncryptionAlgorithms/Concrete/Ceaser.cs
    /// </summary>
    public sealed class Ceaser : ICryptoAlgorithm
    {
        private int Key { get; }

        /// <summary>
        /// Create a new instance of <see cref="Ceaser"/>
        /// </summary>
        /// <param name="key"></param>
        public Ceaser(int key) => Key = key;

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="plainText"></param>
        /// <returns></returns>
        public string Encrypt(string plainText) => ProcessFunc()(Key)(plainText)(EncryptionAlgorithmMode.Encrypt);

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns></returns>
        public string Decrypt(string cipher) => ProcessFunc()(Key)(cipher)(EncryptionAlgorithmMode.Decrypt);

        private static Func<int, Func<string, Func<EncryptionAlgorithmMode, string>>> ProcessFunc() => key => message => mode =>
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