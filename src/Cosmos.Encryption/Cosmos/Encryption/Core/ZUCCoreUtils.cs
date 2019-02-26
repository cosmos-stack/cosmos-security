//using System;
//using System.Runtime.CompilerServices;

//namespace Cosmos.Encryption.Core
//{
//    internal static class ZUCCoreUtils
//    {
//        public static string Int2Bin(int value, int length)
//        {
//            var ret = Convert.ToString(value, 2);
//            return ret.PadLeft(length, '0');
//        }

//        public static int LoopLeftShift(int value, int k)
//        {
//            var charArray = Int2Bin(value, 32).ToCharArray();
//            for (var i = 0; i < k; i++)
//                MoveLeftAndAppend(charArray);

//            return Convert.ToInt32(new string(charArray), 2);

//            void MoveLeftAndAppend(char[] charSet)
//            {
//                var c0 = charSet[0];
//                for (var i = 0; i < charSet.Length - 1; i++)
//                    charSet[i] = charSet[i + 1];
//                charSet[charSet.Length - 1] = c0;
//            }
//        }

//        public static int[] KeyLoading(int key, int iv)
//        {
//            var keyStr = Int2Bin(key, 128);
//            var ivStr = Int2Bin(iv, 128);
//            var ret = new int[16];
//            for (var i = 0; i < 16; i++)
//            {
//                var temp = keyStr.Substring(i * 8, 8);
//                temp += Convert.ToString(ZUCCoreConstants.D[i], 2);
//                temp += ivStr.Substring(i * 8, 8);
//                ret[i] = Convert.ToInt32(temp, 2);
//            }

//            return ret;
//        }

//        public static int[] BitRec(int[] lfsr)
//        {
//            return new[]
//            {
//                Convert.ToInt32(Int2Bin(lfsr[15], 31).Substring(0, 16) + Int2Bin(lfsr[14], 31).Substring(15), 2),
//                Convert.ToInt32(Int2Bin(lfsr[11], 31).Substring(15) + Int2Bin(lfsr[9], 31).Substring(0, 16), 2),
//                Convert.ToInt32(Int2Bin(lfsr[7], 31).Substring(15) + Int2Bin(lfsr[5], 31).Substring(0, 16), 2),
//                Convert.ToInt32(Int2Bin(lfsr[2], 31).Substring(15) + Int2Bin(lfsr[0], 31).Substring(0, 16), 2),
//            };
//        }

//        public static string S(int a)
//        {
//            var aStr = Int2Bin(a, 32);
//            var index = new int[8];
//            for (var i = 0; i < 8; i++)
//                index[i] = Convert.ToInt32(aStr.Substring(4 * i, 4), 2);

//            return Box(index[0], index[1], 1) + Box(index[2], index[3], 2) +
//                   Box(index[4], index[5], 1) + Box(index[6], index[7], 2);

//            string Box(int a1, int a2, int k)
//            {
//                return Int2Bin(k == 1 ? ZUCCoreConstants.S2_0[a1][a2] : ZUCCoreConstants.S2_1[a1][a2], 8);
//            }
//        }

//        public static int[] LFSRMode(int u, int[] lfsr, int k)
//        {
//            var s16 = Math.Pow(2, 15) * lfsr[15] +
//                      Math.Pow(2, 17) * lfsr[13] +
//                      Math.Pow(2, 21) * lfsr[10] +
//                      Math.Pow(2, 20) * lfsr[4] +
//                      (1 + Math.Pow(2, 8)) * lfsr[0];

//            if (k == 1)
//                s16 = (u + s16) % (Math.Pow(2, 31) - 1);
//            else
//                s16 = s16 % (Math.Pow(2, 31) - 1);

//            var i16 = (int)s16;

//            if (i16 == 0)
//                i16 = (int)Math.Pow(2, 21) - 1;

//            MoveLeftAndAppend(lfsr, i16);

//            return lfsr;

//            void MoveLeftAndAppend(int[] LFSR, int last)
//            {
//                for (var i = 0; i < LFSR.Length - 1; i++)
//                    LFSR[i] = LFSR[i + 1];
//                LFSR[LFSR.Length - 1] = last;
//            }
//        }

//        public static (int W, int R1, int R2) F(int[] x, int r1, int r2)
//        {
//            var modules = Math.Pow(2, 32);
//            var w = ((x[0] ^ r1) + r2) % modules;
//            var w1 = (r1 + x[1]) % modules;
//            var w2 = r2 ^ x[2];

//            int iw1 = (int)w1, iw2 = (int)w2;
//            var temp1 = Int2Bin(iw1, 32).Substring(16, 16) + Int2Bin(iw2, 32).Substring(0, 16);
//            var temp2 = Int2Bin(iw2, 32).Substring(16, 16) + Int2Bin(iw1, 32).Substring(0, 16);

//            var temp3 = Convert.ToInt32(temp1, 2);
//            var temp4 = Convert.ToInt32(temp2, 2);

//            temp3 = temp3 ^ (LoopLeftShift(temp3, 2)) ^ (LoopLeftShift(temp3, 10)) ^ (LoopLeftShift(temp3, 18)) ^ (LoopLeftShift(temp3, 24));
//            temp4 = temp4 ^ (LoopLeftShift(temp4, 8)) ^ (LoopLeftShift(temp4, 14)) ^ (LoopLeftShift(temp4, 22)) ^ (LoopLeftShift(temp4, 30));

//            var r1Str = S(temp3);
//            var r2Str = S(temp4);

//            return ((int)w, Convert.ToInt32(r1Str, 2), Convert.ToInt32(r2Str, 2));
//        }

//        public static (int[] LFSR, int R1, int R2) Init(int key, int iv)
//        {
//            var LFSR = KeyLoading(key, iv);
//            int R1 = 0, R2 = 0;
//            for (var i = 0; i < 32; i++)
//            {
//                var X = BitRec(LFSR);
//                var (W, WR1, WR2) = F(X, R1, R2);
//                R1 = WR1;
//                R2 = WR2;
//                LFSR = LFSRMode(W >> 1, LFSR, 1);
//            }

//            var X2 = BitRec(LFSR);
//            var (W2, WR21, WR22) = F(X2, R1, R2);
//            LFSR = LFSRMode(W2 >> 1, LFSR, 2);
//            return (LFSR, WR21, WR22);
//        }

//        public static (int[] LFSR, int R1, int R2, int Z) Work(int[] LFSR, int R1, int R2)
//        {
//            var X = BitRec(LFSR);
//            var (W, WR1, WR2) = F(X, R1, R2);
//            var Z = W ^ X[3];
//            LFSR = LFSRMode(W >> 1, LFSR, 2);
//            return (LFSR, WR1, WR2, Z);
//        }
//    }
//}
