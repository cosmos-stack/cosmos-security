using System;
using System.Text;

// ReSharper disable RedundantAssignment
// ReSharper disable InconsistentNaming
// ReSharper disable RedundantCast

namespace Cosmos.Security.Verification.MessageDigest
{
    public partial class MdFunction
    {
        private class Md6Worker : IMessageDigestWorker
        {
            private readonly uint _d;
            private readonly uint _L;
            private readonly uint _r;

            private readonly string _key;
            private readonly bool _isHex;


            public Md6Worker(MdConfig config)
            {
                config.CheckParams();
                
                _d = (uint) config.HashSizeInBits;
                _L = config.ModeControl;
                _r = config.NumberOfRound;

                _key = config.Key;
                _isHex = config.IsHexString;
            }

            public byte[] Hash(ReadOnlySpan<byte> buff)
            {
                ulong len = (ulong) buff.Length * 8;

                ulong[] message = GetMessage(buff, (ulong) buff.Length);

                var (key, keyLen, newR) = GetKey(ref message, _d, _r, _key, _isHex);

                var hashVal = GetHashValue(ref message, ref len, _d, newR, _L, key, keyLen);

                FixHashValue(ref hashVal, _d);

                return hashVal;
            }

            private static ulong[] GetMessage(ReadOnlySpan<byte> buff, ulong len)
            {
                ulong[] message = new ulong[len / 8 + (ulong) (len % 8 > 0 ? 1 : 0)];

                ulong readCount = (ulong) message.Length;
                byte[] buf = new byte[8];

                for (ulong k = 0; k < readCount; ++k)
                {
                    int copySize = k < readCount - 1
                        ? 8
                        : (int) ((len % 8 > 0) ? (len % 8) : 8);

                    buff.Slice((int) k * 8, copySize).CopyTo(buf);

                    if (BitConverter.IsLittleEndian)
                    {
                        message[k] |= (ulong) buf[0] << 56;
                        message[k] |= (ulong) buf[1] << 48;
                        message[k] |= (ulong) buf[2] << 40;
                        message[k] |= (ulong) buf[3] << 32;
                        message[k] |= (ulong) buf[4] << 24;
                        message[k] |= (ulong) buf[5] << 16;
                        message[k] |= (ulong) buf[6] << 8;
                        message[k] |= (ulong) buf[7];
                    }
                    else
                    {
                        message[k] = BitConverter.ToUInt64(buf, 0);
                    }

                    Array.Clear(buf, 0, buf.Length);
                }

                return message;
            }

            private static (ulong[] key, uint keyLen, uint newR) GetKey(ref ulong[] message, uint d, uint r, string keyStr, bool isHexString)
            {
                uint _keyLen = (uint) keyStr.Length;
                if (_keyLen > 512)
                    throw new ArgumentException("Key file too big. Expected length <= 512 bytes.");
                var _key = new ulong[8];

                byte[] buf = new byte[8];

                byte[] stringArray;
                if (!isHexString)
                {
                    stringArray = Encoding.UTF8.GetBytes(keyStr);
                }
                else
                {
                    stringArray = StringToByteArray(keyStr);
                    _keyLen /= 2;
                }

                ulong readCount = (ulong) (_keyLen / 8 + ((_keyLen % 8 > 0) ? 1 : 0));

                for (ulong k = 0; k < readCount; ++k)
                {
                    int copySize = 0;
                    if (k < (readCount - 1))
                    {
                        copySize = 8;
                    }
                    else
                    {
                        copySize = (int) ((_keyLen % 8 > 0) ? (_keyLen % 8) : 8);
                    }

                    Array.Copy(stringArray, (int) k * 8, buf, 0, copySize);
                    if (BitConverter.IsLittleEndian)
                    {
                        _key[k] |= (ulong) buf[0] << 56;
                        _key[k] |= (ulong) buf[1] << 48;
                        _key[k] |= (ulong) buf[2] << 40;
                        _key[k] |= (ulong) buf[3] << 32;
                        _key[k] |= (ulong) buf[4] << 24;
                        _key[k] |= (ulong) buf[5] << 16;
                        _key[k] |= (ulong) buf[6] << 8;
                        _key[k] |= (ulong) buf[7];
                    }
                    else
                    {
                        message[k] = BitConverter.ToUInt64(buf, 0);
                    }

                    Array.Clear(buf, 0, buf.Length);
                }

                var _newR = r;

                if (_newR == 0)
                {
                    _newR = 40 + d / 4;
                    if ((_keyLen != 0) && (_newR < 80))
                    {
                        _newR = 80;
                    }
                }

                return (_key, _keyLen, _newR);
            }

            private static byte[] GetHashValue(ref ulong[] message, ref ulong messageLen, uint d, uint r, uint L, ulong[] key, uint keyLen)
            {
                ulong[] res = ModeOfOperation(ref message, ref messageLen, d, r, L, key, keyLen);

                byte[] hashValue = new byte[(d + 7) / 8];
                int i = 0;
                while (i < hashValue.Length)
                {
                    ulong val = res[res.Length - 1 - i / 8];
                    int k = 0;
                    while ((i < hashValue.Length) && (k < 8))
                    {
                        byte mask = 0xFF;
                        hashValue[hashValue.Length - 1 - i++] = (byte) (val & mask);
                        val = val >> 8;
                        ++k;
                    }
                }

                byte bitoffset = (byte) (d % 8);
                if (bitoffset > 0)
                {
                    for (int k = 0; k < hashValue.Length - 1; ++k)
                    {
                        hashValue[k] = (byte) ((hashValue[k] << (8 - bitoffset)) | (hashValue[k + 1] >> bitoffset));
                    }

                    hashValue[hashValue.Length - 1] = (byte) (hashValue[hashValue.Length - 1] << (8 - bitoffset));
                }

                return hashValue;
            }

            private static ulong[] ModeOfOperation(ref ulong[] message, ref ulong messageLen, uint d, uint r, uint L, ulong[] key, uint keyLen)
            {
                uint l = 0;
                while (true)
                {
                    ++l;
                    if (l == L + 1)
                    {
                        return SEQ(message, messageLen, d, r, L, key, keyLen);
                    }
                    else
                    {
                        message = PAR(ref message, messageLen, d, r, L, key, keyLen, l);
                        if (message.Length == cw)
                        {
                            return message;
                        }

                        messageLen = (ulong) message.LongLength * 64;

                        // ReSharper disable once RedundantNameQualifier
                        System.GC.Collect();
                    }
                }
            }

            private static void FixHashValue(ref byte[] hashVal, uint d)
            {
                if ((d % 8 < 5) && (d % 8 > 0))
                {
                    for (var i = hashVal.Length - 1; i >= 0; --i)
                    {
                        var l = hashVal[i];
                        l = (byte) (l >> 4);

                        if (i > 0)
                        {
                            var h = (byte) (hashVal[i - 1] & 15);
                            h = (byte) (h << 4);
                            l = (byte) (h + l);
                        }

                        hashVal[i] = l;
                    }
                }
            }

            #region PAR

            public const int bw = 64; //words
            public const int cw = 16; //words     

            private static ulong[] Q =
            {
                0x7311c2812425cfa0,
                0x6432286434aac8e7,
                0xb60450e9ef68b7c1,
                0xe8fb23908d9f06f1,
                0xdd2e76cba691e5bf,
                0x0cd0d63b2c30bc41,
                0x1f8ccf6823058f8a,
                0x54e5ed5b88e3775d,
                0x4ad12aae0a6d6031,
                0x3e7f16bb88222e0d,
                0x8af8671d3fb50c2c,
                0x995ad1178bd25c31,
                0xc878c1dd04c4b633,
                0x3b72066c7a1552ac,
                0x0d6f3522631effcb
            }; // 960 bits of √6 as a sequence of 15 64-bit words

            private static ulong[] PAR(ref ulong[] message, ulong messageLen, uint d, uint r, uint L, ulong[] key, uint keyLen, uint l)
            {
                ulong p = (ulong) message.LongLength * 64 - messageLen + ((message.LongLength % bw) > 0 ? (((ulong) bw - (ulong) message.LongLength % bw) * 64) : 0);

                ulong j = (ulong) (message.Length / bw) + (ulong) (message.LongLength % bw > 0 ? 1 : 0);
                uint z = (uint) (j == 1 ? 1 : 0);
                ulong V = 0;
                V |= r;
                V = V << 8;
                V |= L;
                V = V << 4;
                V |= z;
                V = V << 16;
                V |= p;
                V = V << 8;
                V |= keyLen;
                V = V << 12;
                V |= d;
                ulong noPadding = 0xFFFFFFF0000FFFFF;
                ulong[] Ci = new ulong[cw];
                ulong[] Res = new ulong[cw * j];
                ulong[] fVal = new ulong[n];
                Array.Copy(Q, 0, fVal, 0, Q.Length);
                Array.Copy(key, 0, fVal, Q.Length, key.Length);
                for (ulong i = 0; i < j; ++i)
                {
                    ulong localV = V;
                    if (i < j - 1)
                        localV &= noPadding;

                    ulong U = l;
                    U = U << 56;
                    U |= i;

                    fVal[Q.Length + key.Length] = U;
                    fVal[Q.Length + key.Length + 1] = localV;
                    if (i < j - 1)
                    {
                        Array.Copy(message, bw * (Int64) i, fVal, Q.Length + key.Length + 2, bw);
                    }
                    else
                    {
                        if (message.LongLength % bw > 0)
                        {
                            Array.Copy(message, bw * (Int64) i, fVal, Q.Length + key.Length + 2, message.LongLength % bw);
                            for (Int64 k = message.LongLength % bw; k < bw; ++k)
                            {
                                fVal[k + Q.Length + key.Length + 2] = 0;
                            }
                        }
                        else
                        {
                            Array.Copy(message, bw * (Int64) i, fVal, Q.Length + key.Length + 2, bw);
                        }
                    }

                    //call to compress
                    Ci = Compress(ref fVal, r);
                    Array.Copy(Ci, 0, Res, cw * (Int64) i, cw);
                }

                return Res;
            }

            #endregion

            #region SEQ

            private const uint n = 89; //words

            private static ulong[] SEQ(ulong[] message, ulong messageLen, uint d, uint r, uint L, ulong[] key, uint keyLen)
            {
                ulong p = (ulong) message.LongLength * 64 - messageLen + ((message.LongLength % (bw - cw)) > 0 ? (((ulong) (bw - cw) - (ulong) message.LongLength % (bw - cw)) * 64) : 0);

                ulong j = (ulong) (message.Length / (bw - cw)) + (ulong) (message.LongLength % (bw - cw) > 0 ? 1 : 0);

                ulong V = 0;
                V |= r;
                V = V << 8;
                V |= L;
                V = V << 4;
                //V |= z;
                V = V << 16;
                V |= p;
                V = V << 8;
                V |= keyLen;
                V = V << 12;
                V |= d;

                ulong noPadding = 0xFFFFFFF0000FFFFF;
                ulong z = 0x0000001000000000;

                ulong[] C = new ulong[cw];
                ulong[] fVal = new ulong[n];
                Array.Copy(Q, 0, fVal, 0, Q.Length);
                Array.Copy(key, 0, fVal, Q.Length, key.Length);
                for (ulong i = 0; i < j; ++i)
                {
                    ulong localV = V;
                    if (i < j - 1)
                    {
                        localV &= noPadding;
                    }
                    else
                    {
                        localV |= z;
                    }

                    ulong U = (L + 1);
                    U = U << 56;
                    U |= i;


                    fVal[Q.Length + key.Length] = U;
                    fVal[Q.Length + key.Length + 1] = localV;
                    Array.Copy(C, 0, fVal, Q.Length + key.Length + 2, C.Length);
                    if (i < j - 1)
                    {
                        Array.Copy(message, (bw - cw) * (Int64) i, fVal, Q.Length + key.Length + 2 + C.Length, (bw - cw));
                    }
                    else
                    {
                        if (message.LongLength % (bw - cw) > 0)
                        {
                            Array.Copy(message, (bw - cw) * (Int64) i, fVal, Q.Length + key.Length + 2 + C.Length, message.LongLength % (bw - cw));
                            for (Int64 k = message.LongLength % (bw - cw); k < (bw - cw); ++k)
                            {
                                fVal[k + Q.Length + key.Length + 2 + C.Length] = 0;
                            }
                        }
                        else
                        {
                            Array.Copy(message, (bw - cw) * (Int64) i, fVal, Q.Length + key.Length + 2 + C.Length, (bw - cw));
                        }
                    }

                    //call to compress
                    C = Compress(ref fVal, r);
                }

                return C;
            }

            #endregion

            #region Compress

            private const uint t0 = 17;
            private const uint t1 = 18;
            private const uint t2 = 21;
            private const uint t3 = 31;
            private const uint t4 = 67;

            private static int[] ri = {10, 5, 13, 10, 11, 12, 2, 7, 14, 15, 7, 13, 11, 7, 6, 12};
            private static int[] li = {11, 24, 9, 16, 15, 9, 27, 15, 6, 2, 29, 8, 15, 5, 31, 9};

            private const ulong S0 = 0x0123456789abcdef;
            private const ulong Sdot = 0x7311c2812425cfa0;

            private static ulong[] Compress(ref ulong[] N, uint r)
            {
                ulong[] C = new ulong[cw];

                uint t = r * cw;

                ulong[] A = new ulong[t + n];
                Array.Copy(N, 0, A, 0, n);

                ulong Si = S0;
                for (uint i = n, j = 0; j < r; ++j)
                {
                    for (uint k = 0; k < 16; ++k, ++i)
                    {
                        ulong x = Si ^ A[i - n] ^ A[i - t0];
                        x ^= (A[i - t1] & A[i - t2]) ^ (A[i - t3] & A[i - t4]);
                        x ^= (x >> ri[(i - n) % 16]);
                        A[i] = x ^ (x << li[(i - n) % 16]);
                    }

                    Si = (Si << 1 | Si >> 63) ^ (Si & Sdot);
                }

                Array.Copy(A, t + n - cw, C, 0, cw);
                return C;
            }

            #endregion

            private static byte[] StringToByteArray(string hex)
            {
                var numberChars = hex.Length;
                var bytes = new byte[numberChars];
                for (var i = 0; i < numberChars; i += 2)
                    bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
                return bytes;
            }
        }
    }
}