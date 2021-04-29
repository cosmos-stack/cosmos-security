using System;
using System.Linq;
using System.Threading;
using Cosmos.Security.Cryptography.Core;
using Cosmos.Security.Cryptography.Core.SymmetricAlgorithmImpls;

/*
 * Reference to:
 *     https://github.com/toolgood/RCX/blob/master/ToolGood.RcxTest/ToolGood.RcxCrypto/RCX.cs
 *     Author: ToolGood
 *     GitHub: https://github.com/toolgood
 */

// ReSharper disable CheckNamespace
// ReSharper disable InconsistentNaming

namespace Cosmos.Security.Cryptography
{
    internal class RCXFunction : SymmetricCryptoFunction<RcKey>, IRC
    {
        private const int KEY_LENGTH = 256;

        public RCXFunction(RcKey key, RcOrder order = RcOrder.ASC)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
            Order = order;
        }

        public override RcKey Key { get; }

        public override int KeySize => Key.Size;
        
        public RcOrder Order { get; set; }

        protected override ICryptoValue EncryptInternal(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var data = GetBytes(originalBytes);
            var cipher = EncryptCore(data, Key.GetKey(), Order);
            return CreateCryptoValue(data, cipher, CryptoMode.Encrypt);
        }

        protected override ICryptoValue DecryptInternal(ArraySegment<byte> cipherBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var cipher = GetBytes(cipherBytes);
            var original = EncryptCore(cipher, Key.GetKey(), Order);
            return CreateCryptoValue(original, cipher, CryptoMode.Decrypt);
        }

        internal static unsafe byte[] EncryptCore(byte[] data, byte[] pass, RcOrder order)
        {
            byte[] mBox = GetKey(pass, KEY_LENGTH);
            byte[] output = new byte[data.Length];
            //int i = 0, j = 0;

            if (order == RcOrder.ASC)
            {
                fixed (byte* _mBox = &mBox[0])
                fixed (byte* _data = &data[0])
                fixed (byte* _output = &output[0])
                {
                    var length = data.Length;
                    int i = 0, j = 0;
                    for (Int64 offset = 0; offset < length; offset++)
                    {
                        i = (++i) & 0xFF;
                        j = (j + *(_mBox + i)) & 0xFF;

                        byte a = *(_data + offset);
                        byte c = (byte) (a ^ *(_mBox + ((*(_mBox + i) + *(_mBox + j)) & 0xFF)));
                        *(_output + offset) = c;

                        byte temp = *(_mBox + a);
                        *(_mBox + a) = *(_mBox + c);
                        *(_mBox + c) = temp;
                        j = (j + a + c);
                    }
                }
            }
            else
            {
                fixed (byte* _mBox = &mBox[0])
                fixed (byte* _data = &data[0])
                fixed (byte* _output = &output[0])
                {
                    // ReSharper disable once UnusedVariable
                    var length = data.Length;
                    int i = 0, j = 0;
                    for (int offset = data.Length - 1; offset >= 0; offset--)
                    {
                        i = (++i) & 0xFF;
                        j = (j + *(_mBox + i)) & 0xFF;

                        byte a = *(_data + offset);
                        byte c = (byte) (a ^ *(_mBox + ((*(_mBox + i) + *(_mBox + j)) & 0xFF)));
                        *(_output + offset) = c;

                        byte temp = *(_mBox + a);
                        *(_mBox + a) = *(_mBox + c);
                        *(_mBox + c) = temp;
                        j = (j + a + c);
                    }
                }
            }

            return output;
        }

        private static unsafe byte[] GetKey(byte[] pass, int kLen)
        {
            byte[] mBox = new byte[kLen];
            fixed (byte* _mBox = &mBox[0])
            {
                for (long i = 0; i < kLen; i++)
                {
                    *(_mBox + i) = (byte) i;
                }

                long j = 0;
                var length = pass.Length;
                fixed (byte* _pass = &pass[0])
                {
                    for (long i = 0; i < kLen; i++)
                    {
                        j = (j + *(_mBox + i) + *(_pass + (i % length))) % kLen;
                        byte temp = *(_mBox + i);
                        *(_mBox + i) = *(_mBox + j);
                        *(_mBox + j) = temp;
                    }
                }
            }

            return mBox;
        }
    }
}