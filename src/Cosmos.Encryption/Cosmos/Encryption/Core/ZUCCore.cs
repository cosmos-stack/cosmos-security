using System;

/*
 * Reference to:
 *      https://github.com/zhebinhu/ZUC
 *      Author: zhebinhu
 */

namespace Cosmos.Encryption.Core
{
    internal class ZUCCore
    {
        private readonly byte[] _key;
        private readonly byte[] _iv;

        private const int MASK = int.MaxValue;
        private const long LMASK = long.MaxValue;

        public ZUCCore(byte[] key, byte[] iv)
        {
            _key = new byte[16];
            _iv = new byte[16];

            Array.Copy(key, 0, _key, 0, key.Length);
            Array.Copy(iv, 0, _iv, 0, iv.Length);

            Initialization(Utils.StrToInt32s(_key, 0, 0), Utils.StrToInt32s(_iv, 0, 0));
        }

        /// <summary>
        /// state registers LFSR
        /// </summary>
        private int[] LFSR_S = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

        /// <summary>
        /// registers
        /// </summary>
        private int F_R1 = 0;

        private int F_R2 = 0;

        /// <summary>
        /// output of BR procedure
        /// </summary>
        private int[] BRC_X = {0, 0, 0, 0};

        /* S-boxes */
        private int[] S0 =
        {
            0x3e, 0x72, 0x5b, 0x47, 0xca, 0xe0, 0x00, 0x33, 0x04, 0xd1, 0x54, 0x98, 0x09, 0xb9, 0x6d, 0xcb,
            0x7b, 0x1b, 0xf9, 0x32, 0xaf, 0x9d, 0x6a, 0xa5, 0xb8, 0x2d, 0xfc, 0x1d, 0x08, 0x53, 0x03, 0x90,
            0x4d, 0x4e, 0x84, 0x99, 0xe4, 0xce, 0xd9, 0x91, 0xdd, 0xb6, 0x85, 0x48, 0x8b, 0x29, 0x6e, 0xac,
            0xcd, 0xc1, 0xf8, 0x1e, 0x73, 0x43, 0x69, 0xc6, 0xb5, 0xbd, 0xfd, 0x39, 0x63, 0x20, 0xd4, 0x38,
            0x76, 0x7d, 0xb2, 0xa7, 0xcf, 0xed, 0x57, 0xc5, 0xf3, 0x2c, 0xbb, 0x14, 0x21, 0x06, 0x55, 0x9b,
            0xe3, 0xef, 0x5e, 0x31, 0x4f, 0x7f, 0x5a, 0xa4, 0x0d, 0x82, 0x51, 0x49, 0x5f, 0xba, 0x58, 0x1c,
            0x4a, 0x16, 0xd5, 0x17, 0xa8, 0x92, 0x24, 0x1f, 0x8c, 0xff, 0xd8, 0xae, 0x2e, 0x01, 0xd3, 0xad,
            0x3b, 0x4b, 0xda, 0x46, 0xeb, 0xc9, 0xde, 0x9a, 0x8f, 0x87, 0xd7, 0x3a, 0x80, 0x6f, 0x2f, 0xc8,
            0xb1, 0xb4, 0x37, 0xf7, 0x0a, 0x22, 0x13, 0x28, 0x7c, 0xcc, 0x3c, 0x89, 0xc7, 0xc3, 0x96, 0x56,
            0x07, 0xbf, 0x7e, 0xf0, 0x0b, 0x2b, 0x97, 0x52, 0x35, 0x41, 0x79, 0x61, 0xa6, 0x4c, 0x10, 0xfe,
            0xbc, 0x26, 0x95, 0x88, 0x8a, 0xb0, 0xa3, 0xfb, 0xc0, 0x18, 0x94, 0xf2, 0xe1, 0xe5, 0xe9, 0x5d,
            0xd0, 0xdc, 0x11, 0x66, 0x64, 0x5c, 0xec, 0x59, 0x42, 0x75, 0x12, 0xf5, 0x74, 0x9c, 0xaa, 0x23,
            0x0e, 0x86, 0xab, 0xbe, 0x2a, 0x02, 0xe7, 0x67, 0xe6, 0x44, 0xa2, 0x6c, 0xc2, 0x93, 0x9f, 0xf1,
            0xf6, 0xfa, 0x36, 0xd2, 0x50, 0x68, 0x9e, 0x62, 0x71, 0x15, 0x3d, 0xd6, 0x40, 0xc4, 0xe2, 0x0f,
            0x8e, 0x83, 0x77, 0x6b, 0x25, 0x05, 0x3f, 0x0c, 0x30, 0xea, 0x70, 0xb7, 0xa1, 0xe8, 0xa9, 0x65,
            0x8d, 0x27, 0x1a, 0xdb, 0x81, 0xb3, 0xa0, 0xf4, 0x45, 0x7a, 0x19, 0xdf, 0xee, 0x78, 0x34, 0x60
        };

        private int[] S1 =
        {
            0x55, 0xc2, 0x63, 0x71, 0x3b, 0xc8, 0x47, 0x86, 0x9f, 0x3c, 0xda, 0x5b, 0x29, 0xaa, 0xfd, 0x77,
            0x8c, 0xc5, 0x94, 0x0c, 0xa6, 0x1a, 0x13, 0x00, 0xe3, 0xa8, 0x16, 0x72, 0x40, 0xf9, 0xf8, 0x42,
            0x44, 0x26, 0x68, 0x96, 0x81, 0xd9, 0x45, 0x3e, 0x10, 0x76, 0xc6, 0xa7, 0x8b, 0x39, 0x43, 0xe1,
            0x3a, 0xb5, 0x56, 0x2a, 0xc0, 0x6d, 0xb3, 0x05, 0x22, 0x66, 0xbf, 0xdc, 0x0b, 0xfa, 0x62, 0x48,
            0xdd, 0x20, 0x11, 0x06, 0x36, 0xc9, 0xc1, 0xcf, 0xf6, 0x27, 0x52, 0xbb, 0x69, 0xf5, 0xd4, 0x87,
            0x7f, 0x84, 0x4c, 0xd2, 0x9c, 0x57, 0xa4, 0xbc, 0x4f, 0x9a, 0xdf, 0xfe, 0xd6, 0x8d, 0x7a, 0xeb,
            0x2b, 0x53, 0xd8, 0x5c, 0xa1, 0x14, 0x17, 0xfb, 0x23, 0xd5, 0x7d, 0x30, 0x67, 0x73, 0x08, 0x09,
            0xee, 0xb7, 0x70, 0x3f, 0x61, 0xb2, 0x19, 0x8e, 0x4e, 0xe5, 0x4b, 0x93, 0x8f, 0x5d, 0xdb, 0xa9,
            0xad, 0xf1, 0xae, 0x2e, 0xcb, 0x0d, 0xfc, 0xf4, 0x2d, 0x46, 0x6e, 0x1d, 0x97, 0xe8, 0xd1, 0xe9,
            0x4d, 0x37, 0xa5, 0x75, 0x5e, 0x83, 0x9e, 0xab, 0x82, 0x9d, 0xb9, 0x1c, 0xe0, 0xcd, 0x49, 0x89,
            0x01, 0xb6, 0xbd, 0x58, 0x24, 0xa2, 0x5f, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xb8, 0x95, 0xe4,
            0xd0, 0x91, 0xc7, 0xce, 0xed, 0x0f, 0xb4, 0x6f, 0xa0, 0xcc, 0xf0, 0x02, 0x4a, 0x79, 0xc3, 0xde,
            0xa3, 0xef, 0xea, 0x51, 0xe6, 0x6b, 0x18, 0xec, 0x1b, 0x2c, 0x80, 0xf7, 0x74, 0xe7, 0xff, 0x21,
            0x5a, 0x6a, 0x54, 0x1e, 0x41, 0x31, 0x92, 0x35, 0xc4, 0x33, 0x07, 0x0a, 0xba, 0x7e, 0x0e, 0x34,
            0x88, 0xb1, 0x98, 0x7c, 0xf3, 0x3d, 0x60, 0x6c, 0x7b, 0xca, 0xd3, 0x1f, 0x32, 0x65, 0x04, 0x28,
            0x64, 0xbe, 0x85, 0x9b, 0x2f, 0x59, 0x8a, 0xd7, 0xb0, 0x25, 0xac, 0xaf, 0x12, 0x03, 0xe2, 0xf2
        };

        /* D constants */
        private int[] EK_d =
        {
            0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
            0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC
        };

        private static int AddM(int a, int b)
        {
            int c = a + b;
            return (c & 0x7FFFFFFF) + (UInt32MoveRight((int) (c & 0x80000000), 31));
        }

        private static int MulByPow2(int x, int k)
        {
            return ((((x) << k) | (UInt32MoveRight(x, 31 - k))) & 0x7FFFFFFF);
        }

        private static int UInt32MoveRight(int value, int pos)
        {
            if (pos != 0)
            {
                //无符号整数最高位不表示正负但操作数还是有符号的，有符号数右移1位，正数时高位补0，负数时高位补1
                value = value >> 1;
                //和整数最大值进行逻辑与运算，运算后的结果为忽略表示正负值的最高位
                value = value & MASK;
                //逻辑运算后的值无符号，对无符号的值直接做右移运算，计算剩下的位
                value = value >> pos - 1;
            }

            return value;
        }

        private static long UInt64MoveRight(long value, int pos)
        {
            if (pos != 0)
            {
                //无符号整数最高位不表示正负但操作数还是有符号的，有符号数右移1位，正数时高位补0，负数时高位补1
                value = value >> 1;
                //和整数最大值进行逻辑与运算，运算后的结果为忽略表示正负值的最高位
                value = value & LMASK;
                //逻辑运算后的值无符号，对无符号的值直接做右移运算，计算剩下的位
                value = value >> pos - 1;
            }

            return value;
        }

        /* LFSR */
        private void LFSRWithInitializationMode(int u)
        {
            int f, v;

            f = LFSR_S[0];
            v = MulByPow2(LFSR_S[0], 8);
            f = AddM(f, v);

            v = MulByPow2(LFSR_S[4], 20);
            f = AddM(f, v);

            v = MulByPow2(LFSR_S[10], 21);
            f = AddM(f, v);

            v = MulByPow2(LFSR_S[13], 17);
            f = AddM(f, v);

            v = MulByPow2(LFSR_S[15], 15);
            f = AddM(f, v);

            f = AddM(f, u);

            /* update the state */
            for (int i = 0; i < 15; ++i)
            {
                LFSR_S[i] = LFSR_S[i + 1];
            }

            LFSR_S[15] = f;
        }

        /* LFSR with work mode */
        private void LFSRWithWorkMode()
        {
            int f, v;

            f = LFSR_S[0];
            v = MulByPow2(LFSR_S[0], 8);
            f = AddM(f, v);

            v = MulByPow2(LFSR_S[4], 20);
            f = AddM(f, v);

            v = MulByPow2(LFSR_S[10], 21);
            f = AddM(f, v);

            v = MulByPow2(LFSR_S[13], 17);
            f = AddM(f, v);

            v = MulByPow2(LFSR_S[15], 15);
            f = AddM(f, v);

            /* update state */
            for (int i = 0; i < 15; ++i)
            {
                LFSR_S[i] = LFSR_S[i + 1];
            }

            LFSR_S[15] = f;
        }

        /* Bit Reorganization Procedure */
        private void BitReorganization()
        {
            BRC_X[0] = ((LFSR_S[15] & 0x7FFF8000) << 1) | (LFSR_S[14] & 0xFFFF);
            BRC_X[1] = ((LFSR_S[11] & 0xFFFF) << 16) | (UInt32MoveRight(LFSR_S[9], 15));
            BRC_X[2] = ((LFSR_S[7] & 0xFFFF) << 16) | (UInt32MoveRight(LFSR_S[5], 15));
            BRC_X[3] = ((LFSR_S[2] & 0xFFFF) << 16) | (UInt32MoveRight(LFSR_S[0], 15));
        }

        private static long ROT(long a, int k)
        {
            return (((a) << k) | (UInt64MoveRight(a, 32 - k)));
        }

        /* linear transformation L1 */
        private static long L1(long X)
        {
            return (X ^ ROT(X, 2) ^ ROT(X, 10) ^ ROT(X, 18) ^ ROT(X, 24));
        }

        /* linear transformation L2 */
        private static long L2(long X)
        {
            return (X ^ ROT(X, 8) ^ ROT(X, 14) ^ ROT(X, 22) ^ ROT(X, 30));
        }

        /* create 32-bit word */

        private static int MAKEU32(int a, int b, int c, int d)
        {
            return (int) (((long) a << 24) | ((long) b << 16) | ((long) c << 8) | ((long) d));
        }

        /* non-linear function F */
        private long F()
        {
            long W, W1, W2, u, v;

            W = (BRC_X[0] ^ F_R1) + F_R2;
            W = W & 0x00000000FFFFFFFFL;
            W1 = F_R1 + BRC_X[1];
            W1 = W1 & 0x00000000FFFFFFFFL;
            W2 = F_R2 ^ BRC_X[2];
            W2 = W2 & 0x00000000FFFFFFFFL;
            u = L1((W1 << 16) & 0x00000000FFFFFFFFL | (UInt64MoveRight(W2, 16)));
            u = u & 0x00000000FFFFFFFFL;
            v = L2((W2 << 16) & 0x00000000FFFFFFFFL | (UInt64MoveRight(W1, 16)));
            v = v & 0x00000000FFFFFFFFL;
            F_R1 = MAKEU32(S0[(int) (UInt64MoveRight(u, 24))], S1[(int) ((UInt64MoveRight(u, 16)) & 0xFF)], S0[(int) ((UInt64MoveRight(u, 8)) & 0xFF)], S1[(int) (u & 0xFF)]);
            F_R2 = MAKEU32(S0[(int) (UInt64MoveRight(v, 24))], S1[(int) ((UInt64MoveRight(v, 16)) & 0xFF)], S0[(int) ((UInt64MoveRight(v, 8)) & 0xFF)], S1[(int) (v & 0xFF)]);

            return W;
        }

        private static int MAKEU31(int a, int b, int c)
        {
            return (int) (((long) ((long) (0)
                                 | (int) (a)) << 23)
                        | ((long) (b) << 8)
                        | (long) ((long) (0)
                                | (int) (c)));
        }

        private void Initialization(int[] k, int[] iv)
        {
            long w;

            /* expand key */
            for (int i = 0; i < 16; ++i)
            {
                LFSR_S[i] = MAKEU31(k[i], EK_d[i], iv[i]);
            }

            long nCount = 32;
            while (nCount > 0)
            {
                BitReorganization();
                w = F();
                LFSRWithInitializationMode((int) (UInt64MoveRight(w, 1)));
                nCount--;
            }

            BitReorganization();
            F();
            LFSRWithWorkMode();
        }

        public void GenerateKeyStream(long[] pKeyStream, long KeyStreamLen)
        {
            /* working cycles */
            for (int i = 0; i < KeyStreamLen; ++i)
            {
                BitReorganization();
                pKeyStream[i] = F() ^ BRC_X[3] & 0x00000000ffffffffL;
                LFSRWithWorkMode();
            }
        }

        private static string ByteToHexStr(byte[] bytes)
        {
            string returnStr = "";
            if (bytes != null)
            {
                for (int i = 0; i < bytes.Length; i++)
                {
                    returnStr += bytes[i].ToString("X2");
                }
            }

            return returnStr;
        }

        public static class Utils
        {
            public static Int32[] StrToInt32s(byte[] s, int startIdx, int length)
            {
                if (length <= 0) length = s.Length;

                int fs = length / 4;
                int ls = length % 4;
                Int32[] l = new Int32[fs + ((ls > 0) ? 1 : 0)];
                int idx = startIdx;
                for (var i = 0; i < fs; i++)
                {
                    l[i] = (int) s[idx++] |
                           ((int) s[idx++] << 8) |
                           ((int) s[idx++] << 16) |
                           ((int) s[idx++] << 24);
                }

                if (ls > 0)
                {
                    // note running off the end of the string generates nulls since 
                    // bitwise operators treat NaN as 0
                    byte[] v = new byte[4] {0, 0, 0, 0};
                    for (var i = 0; i < ls; i++)
                    {
                        v[i] = s[fs * 4 + i];
                    }

                    l[fs] = BitConverter.ToInt32(v, 0);
                }

                return l;
            }

            public static Int64[] StrToLongs(byte[] s, int startIdx, int length)
            {
                if (length <= 0) length = s.Length;

                int fs = length / 4;
                int ls = length % 4;
                Int64[] l = new Int64[fs + ((ls > 0) ? 1 : 0)];
                int idx = startIdx;
                for (var i = 0; i < fs; i++)
                {
                    l[i] = (uint) s[idx++] |
                           ((uint) s[idx++] << 8) |
                           ((uint) s[idx++] << 16) |
                           ((uint) s[idx++] << 24);
                }

                if (ls > 0)
                {
                    // note running off the end of the string generates nulls since 
                    // bitwise operators treat NaN as 0
                    byte[] v = new byte[4] {0, 0, 0, 0};
                    for (var i = 0; i < ls; i++)
                    {
                        v[i] = s[fs * 4 + i];
                    }

                    l[fs] = BitConverter.ToUInt32(v, 0);
                }

                return l;
            }
        }
    }
}