/*
 * Reference to:
 *     https://github.com/toolgood/RCX/blob/master/ToolGood.RcxTest/ToolGood.RcxCrypto/RCY.cs
 *     Author: ToolGood
 *     GitHub: https://github.com/toolgood
 */

using System;
using System.Text;
using Cosmos.Optionals;
using Cosmos.Security.Encryption.Abstractions;

// ReSharper disable InconsistentNaming
// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Encryption
{
    /// <summary>
    /// Symmetric/RCY encryption.
    /// Reference: https://github.com/toolgood/RCX/
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public sealed class RCYEncryptionProvider : ISymmetricEncryption
    {
        // ReSharper disable once InconsistentNaming
        private const int KEY_LENGTH = 256;

        private RCYEncryptionProvider() { }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="encoding"></param>
        /// <param name="order"></param>
        /// <returns></returns>
        public static string Encrypt(string data, string key, Encoding encoding = null, RCYOrder order = RCYOrder.ASC)
        {
            encoding = encoding.SafeEncodingValue();
            return Convert.ToBase64String(EncryptCore(encoding.GetBytes(data), encoding.GetBytes(key), order));
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="encoding"></param>
        /// <param name="order"></param>
        /// <returns></returns>
        public static string Encrypt(byte[] data, string key, Encoding encoding = null, RCYOrder order = RCYOrder.ASC)
        {
            encoding = encoding.SafeEncodingValue();
            return Convert.ToBase64String(EncryptCore(data, encoding.GetBytes(key), order));
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="order"></param>
        /// <returns></returns>
        public static byte[] Encrypt(byte[] data, byte[] key, RCYOrder order = RCYOrder.ASC)
        {
            return EncryptCore(data, key, order);
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="encoding"></param>
        /// <param name="order"></param>
        /// <returns></returns>
        public static string Decrypt(string data, string key, Encoding encoding = null, RCYOrder order = RCYOrder.ASC)
        {
            encoding = encoding.SafeEncodingValue();
            return encoding.GetString(EncryptCore(Convert.FromBase64String(data), encoding.GetBytes(key), order));
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="order"></param>
        /// <returns></returns>
        public static byte[] Decrypt(byte[] data, byte[] key, RCYOrder order = RCYOrder.ASC)
        {
            return EncryptCore(data, key, order);
        }

        private static unsafe byte[] EncryptCore(byte[] data, byte[] pass, RCYOrder order)
        {
            byte[] mBox = GetKey(pass, KEY_LENGTH);
            byte[] output = new byte[data.Length];
            int i = 0, j = 0;
            var length = data.Length;

            if (order == RCYOrder.ASC)
            {
                fixed (byte* _mBox = &mBox[0])
                    fixed (byte* _data = &data[0])
                        fixed (byte* _output = &output[0])
                        {
                            for (Int64 offset = 0; offset < length; offset++)
                            {
                                i = (++i) & 0xFF;
                                j = (j + *(_mBox + i)) & 0xFF;

                                byte a = *(_data + offset);
                                byte c = (byte) (a ^ *(_mBox + ((*(_mBox + i) & *(_mBox + j)))));
                                *(_output + offset) = c;

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
                            for (int offset = data.Length - 1; offset >= 0; offset--)
                            {
                                i = (++i) & 0xFF;
                                j = (j + *(_mBox + i)) & 0xFF;

                                byte a = *(_data + offset);
                                byte c = (byte) (a ^ *(_mBox + ((*(_mBox + i) & *(_mBox + j)))));
                                *(_output + offset) = c;

                                j = (j + a + c);
                            }
                        }
            }

            //int i = 0, j = 0;
            //byte a, c;

            //if (order == OrderType.Asc) {
            //    for (int offset = 0; offset < data.Length; offset++) {
            //        i = (++i) & 0xFF;
            //        j = (j + mBox[i]) & 0xFF;

            //        a = data[offset];
            //        c = (byte)(a ^ mBox[(mBox[i] & mBox[j])]);
            //        output[offset] = c;

            //        j = j + (int)a + (int)c;
            //    }
            //} else {
            //    for (int offset = data.Length - 1; offset >= 0; offset--) {
            //        i = (++i) & 0xFF;
            //        j = (j + mBox[i]) & 0xFF;

            //        a = data[offset];
            //        c = (byte)(a ^ mBox[(mBox[i] & mBox[j])]);
            //        output[offset] = c;

            //        j = j + (int)a + (int)c;
            //    }
            //}
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
                var lengh = pass.Length;
                fixed (byte* _pass = &pass[0])
                {
                    for (long i = 0; i < kLen; i++)
                    {
                        j = (j + *(_mBox + i) + *(_pass + (i % lengh))) % kLen;
                        byte temp = *(_mBox + i);
                        *(_mBox + i) = *(_mBox + j);
                        *(_mBox + j) = temp;
                    }
                }
            }

            //for (Int64 i = 0; i < kLen; i++) {
            //    mBox[i] = (byte)i;
            //}
            //Int64 j = 0;
            //for (Int64 i = 0; i < kLen; i++) {
            //    j = (j + mBox[i] + pass[i % pass.Length]) % kLen;
            //    byte temp = mBox[i];
            //    mBox[i] = mBox[j];
            //    mBox[j] = temp;
            //}
            return mBox;
        }
    }
}