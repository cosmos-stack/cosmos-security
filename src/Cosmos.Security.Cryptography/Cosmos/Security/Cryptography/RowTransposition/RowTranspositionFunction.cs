using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using Cosmos.Security.Cryptography.Core;
using Cosmos.Security.Cryptography.Core.SymmetricAlgorithmImpls;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Cryptography
{
    internal class RowTranspositionFunction : SymmetricCryptoFunction<int[]>, IRowTransposition
    {
        public RowTranspositionFunction(int[] key)
        {
            Key = key;
        }

        public override int[] Key { get; }

        public override int KeySize => Key.Length * 32;

        protected override ICryptoValue EncryptInternal(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var original = GetString(originalBytes, Encoding.UTF8);
          
            int columns = 0, rows = 0;
            var rowsPositions = FillPositionsDictionary(Key, original, ref columns, ref rows);
            var matrix2 = new char[rows, columns];

            //Fill Mareix
            var charPosition = 0;
            for (var i = 0; i < rows; i++)
            {
                for (var j = 0; j < columns; j++)
                {
                    matrix2[i, j] = charPosition < original.Length
                        ? original[charPosition]
                        : '*';
                    charPosition++;
                }
            }

            var sbStr = new StringBuilder();

            for (var i = 0; i < columns; i++)
            {
                for (var j = 0; j < rows; j++)
                {
                    sbStr.Append(matrix2[j, rowsPositions[i + 1]]);
                }

                sbStr.Append(" ");
            }

            return CreateCryptoValue(original, sbStr.ToString(), CryptoMode.Encrypt);
        }

        protected override ICryptoValue DecryptInternal(ArraySegment<byte> cipherBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var cipher = GetString(cipherBytes, Encoding.UTF8);
          
            int columns = 0, rows = 0;
            var rowsPositions = FillPositionsDictionary(Key, cipher, ref columns, ref rows);
            var matrix = new char[rows, columns];

            //Fill Matrix
            var charPosition = 0;
            for (var i = 0; i < columns; i++)
            {
                for (var j = 0; j < rows; j++)
                {
                    matrix[j, rowsPositions[i + 1]] = cipher[charPosition];
                    charPosition++;
                }
            }

            var sbStr = new StringBuilder();

            foreach (var c in matrix)
            {
                if (c != '*' && c != ' ')
                {
                    sbStr.Append(c);
                }
            }

            return CreateCryptoValue(sbStr.ToString(), cipher, CryptoMode.Decrypt);
        }

        private static Dictionary<int, int> FillPositionsDictionary(int[] key, string token, ref int columns, ref int rows)
        {
            var result = new Dictionary<int, int>();
            columns = key.Length;
            rows = (int) Math.Ceiling((double) token.Length / columns);
            /*  we need something to tell where to start
             *        4  3  1  2  5  6  7               Key
             *        
             *        0  1  2  3  4  5  6               Value
             */
            //attack postponed until two am xyz
            for (var i = 0; i < columns; i++)
            {
                result.Add(key[i], i);
            }

            return result;
        }
    }
}