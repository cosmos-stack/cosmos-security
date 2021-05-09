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
    internal class PlayFairFunction : SymmetricCryptoFunction<string>, IPlayFair
    {
        public PlayFairFunction(string key)
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
            //Key:Charcater
            //Value:Position
            var characterPositionsInMatrix = new Dictionary<char, string>();

            //Key:Position
            //Value:Charcater
            var positionCharacterInMatrix = new Dictionary<string, char>();

            FillMatrixFunc()(key.Distinct().ToArray())(characterPositionsInMatrix)(positionCharacterInMatrix);

            if (mode == CryptoMode.Encrypt)
            {
                message = RepairWordFunc()(message);
            }

            var sbStr = new StringBuilder();

            for (var i = 0; i < message.Length; i += 2)
            {
                var substringOf2 = message.Substring(i, 2); //get characters from text by pairs
                //get Row & Column of each character
                var rc1 = characterPositionsInMatrix[substringOf2[0]];
                var rc2 = characterPositionsInMatrix[substringOf2[1]];

                if (rc1[0] == rc2[0]) //Same Row, different Column
                {
                    int newC1 = 0, newC2 = 0;

                    switch (mode)
                    {
                        case CryptoMode.Encrypt: //Increment Columns
                            newC1 = (int.Parse(rc1[1].ToString()) + 1) % 5;
                            newC2 = (int.Parse(rc2[1].ToString()) + 1) % 5;
                            break;
                        case CryptoMode.Decrypt: //Decrement Columns
                            newC1 = (int.Parse(rc1[1].ToString()) - 1) % 5;
                            newC2 = (int.Parse(rc2[1].ToString()) - 1) % 5;
                            break;
                    }

                    newC1 = RepairNegativeFunc()(newC1);
                    newC2 = RepairNegativeFunc()(newC2);

                    sbStr.Append(positionCharacterInMatrix[rc1[0].ToString() + newC1.ToString()]);
                    sbStr.Append(positionCharacterInMatrix[rc2[0].ToString() + newC2.ToString()]);
                }
                else if (rc1[1] == rc2[1])
                {
                    //Same Column, different Row

                    int newR1 = 0, newR2 = 0;

                    switch (mode)
                    {
                        case CryptoMode.Encrypt: //Increment Rows
                            newR1 = (int.Parse(rc1[0].ToString()) + 1) % 5;
                            newR2 = (int.Parse(rc2[0].ToString()) + 1) % 5;
                            break;
                        case CryptoMode.Decrypt: //Decrement Rows
                            newR1 = (int.Parse(rc1[0].ToString()) - 1) % 5;
                            newR2 = (int.Parse(rc2[0].ToString()) - 1) % 5;
                            break;
                    }

                    newR1 = RepairNegativeFunc()(newR1);
                    newR2 = RepairNegativeFunc()(newR2);

                    sbStr.Append(positionCharacterInMatrix[newR1.ToString() + rc1[1].ToString()]);
                    sbStr.Append(positionCharacterInMatrix[newR2.ToString() + rc2[1].ToString()]);
                }
                else
                {
                    //different Row & Column

                    //1st character:row of 1st + col of 2nd
                    //2nd character:row of 2nd + col of 1st
                    sbStr.Append(positionCharacterInMatrix[rc1[0].ToString() + rc2[1].ToString()]);
                    sbStr.Append(positionCharacterInMatrix[rc2[0].ToString() + rc1[1].ToString()]);
                }
            }

            return sbStr.ToString();
        };

        private static Func<string, string> RepairWordFunc() => message =>
        {
            var trimmed = message.Replace(" ", "");
            var sbStr = new StringBuilder();

            for (var i = 0; i < trimmed.Length; i++)
            {
                sbStr.Append(trimmed[i]);

                if (i < trimmed.Length - 1 && message[i] == message[i + 1]) //check if two consecutive letters are the same
                {
                    sbStr.Append('x');
                }
            }

            if (sbStr.Length % 2 != 0) //check if length is even
            {
                sbStr.Append('x');
            }

            return sbStr.ToString();
        };

        private static Func<IList<char>, Func<Dictionary<char, string>, Action<Dictionary<string, char>>>> FillMatrixFunc()
            => key => characterPositionsInMatrix => positionCharacterInMatrix =>
            {
                var matrix = new char[5, 5];
                var keyPosition = 0;
                var charPosition = 0;

                var alphabetPlayFair = AlphabetDictionaryGenerator.Generate().Keys.ToList();
                alphabetPlayFair.Remove('j');

                for (var i = 0; i < 5; i++)
                {
                    for (var j = 0; j < 5; j++)
                    {
                        if (charPosition < key.Count)
                        {
                            matrix[i, j] = key[charPosition]; //fill matrix with key
                            alphabetPlayFair.Remove(key[charPosition]);
                            charPosition++;
                        }
                        else
                        {
                            //key finished...fill with rest of alphabet
                            matrix[i, j] = alphabetPlayFair[keyPosition];
                            keyPosition++;
                        }

                        var position = i.ToString() + j.ToString();
                        //store character positions in dictionary to avoid searching everytime
                        characterPositionsInMatrix.Add(matrix[i, j], position);
                        positionCharacterInMatrix.Add(position, matrix[i, j]);
                    }
                }
            };

        private static Func<int, int> RepairNegativeFunc() => number => number < 0 ? number + 5 : number;
    }
}