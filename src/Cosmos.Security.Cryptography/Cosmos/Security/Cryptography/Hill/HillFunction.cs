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
    internal class HillFunction : SymmetricCryptoFunction<int[,]>, IHill
    {
        public HillFunction(int[,] matrix)
        {
            Key = matrix;
        }

        public override int[,] Key { get; }

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

        private static Func<int[,], Func<string, Func<CryptoMode, string>>> ProcessFunc() => key => message => mode =>
        {
            var sbRet = new StringBuilder();
            var matrix = new MatrixClass(key);
            var alphabet = AlphabetDictionaryGenerator.Generate();

            if (mode == CryptoMode.Decrypt)
            {
                matrix = matrix.Inverse();
            }

            var pos = 0;
            var matrixSize = key.GetLength(0);

            while (pos < message.Length)
            {
                for (var i = 0; i < matrixSize; i++)
                {
                    var charPosition = 0;

                    for (var j = 0; j < matrixSize; j++)
                    {
                        charPosition += (int) matrix[j, i].Numerator * alphabet[message.Substring(pos, matrixSize)[j]];
                    }

                    sbRet.Append(alphabet.Keys.ElementAt(charPosition % 26));
                }

                pos += matrixSize;
            }

            return sbRet.ToString();
        };
    }
}