using System;
using System.Text;
using System.Threading;
using Cosmos.Security.Cryptography.Core;
using Cosmos.Security.Cryptography.Core.SymmetricAlgorithmImpls;

namespace Cosmos.Security.Cryptography
{
    internal class RailFenceFunction : SymmetricCryptoFunction<int>, IRailFence
    {
        public RailFenceFunction(int key)
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
            var rows = key;
            var columns = (int) Math.Ceiling((double) message.Length / rows);
            var matrix = FillArrayFunc()(message)(rows)(columns)(mode);
            var sbStr = new StringBuilder();

            foreach (char c in matrix)
            {
                sbStr.Append(c);
            }

            return sbStr.ToString();
        };

        private static Func<string, Func<int, Func<int, Func<CryptoMode, char[,]>>>> FillArrayFunc()
            => message => rowsCount => columnsCount => mode =>
            {
                int charPosition = 0, length = 0, width = 0;
                var matrix = new char[rowsCount, columnsCount];

                switch (mode)
                {
                    case CryptoMode.Encrypt:
                        length = rowsCount;
                        width = columnsCount;
                        break;

                    case CryptoMode.Decrypt:
                        matrix = new char[columnsCount, rowsCount];
                        width = rowsCount;
                        length = columnsCount;
                        break;
                }

                for (var i = 0; i < width; i++)
                {
                    for (var j = 0; j < length; j++)
                    {
                        if (charPosition < message.Length)
                        {
                            matrix[j, i] = message[charPosition];
                        }
                        else
                        {
                            matrix[j, i] = '*';
                        }

                        charPosition++;
                    }
                }

                return matrix;
            };
    }
}