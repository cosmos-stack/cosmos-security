using System;
using System.Text;

/*
 * Reference to:
 *      https://github.com/amos74/TEACrypt
 *      Author: amos74
 *      MIT
 */

namespace Cosmos.Encryption.Core
{
    internal class TeaCore
    {
        private const uint DELTA = 0x9E3779B9;

        private string teakey;
        private uint[] teakeyArr;

        public static string GenerateTeaKey()
        {
            DateTimeOffset now = DateTime.Now;
            //long time = now.ToUnixTimeMilliseconds();  // for above .NET Ver 3.6
            long time = (long)((now - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds);
            long random = (long)(new Random().NextDouble() * 65536);
            long keyValue = time * random;
            return $"{keyValue:D16}";
        }

        /**
         * sum = 0 
         */
        public uint Encrypt(uint[] v, uint[] k, uint sum)
        {
            uint v0 = v[0], v1 = v[1];
            uint k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
            for (int i = 0; i < 32; i++)
            {
                sum += DELTA;
                v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
                v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
            }
            v[0] = v0; v[1] = v1;
            return sum;
        }

        /**
         * sum = 0xC6EF3720 
         */
        public uint Decrypt(uint[] v, uint[] k, uint sum)
        {
            uint v0 = v[0], v1 = v[1];
            uint k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
            for (int i = 0; i < 32; i++)
            {
                v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
                v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
                sum -= DELTA;
            }
            v[0] = v0; v[1] = v1;
            return sum;
        }

        public static byte[] EncryptBlock(uint[] v, uint[] k)
        {
            if (v == null || k == null) return null;

            int n = v.Length;
            if (n == 0) return null;
            if (n <= 1) return new byte[1] { 0 }; // algorithm doesn't work for n<2 so fudge by adding a null

            uint q = (uint)(6 + 52 / n);

            n--;
            uint z = v[n], y = v[0];
            uint mx, e, sum = 0;

            while (q-- > 0)
            {  // 6 + 52/n operations gives between 6 & 32 mixes on each word
                sum += DELTA;
                e = sum >> 2 & 3;

                for (int p = 0; p < n; p++)
                {
                    y = v[p + 1];
                    mx = (z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);
                    z = v[p] += mx;
                }
                y = v[0];
                mx = (z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[n & 3 ^ e] ^ z);
                z = v[n] += mx;
            }

            return StrConvert.LongsToStr(v);
        }

        public static byte[] DecryptBlock(uint[] v, uint[] k)
        {
            if (v == null || k == null) return null;

            uint n = (uint)v.Length;
            if (n == 0) return null;
            if (n <= 1) return new byte[1] { 0 }; // algorithm doesn't work for n<2 so fudge by adding a null

            uint q = (uint)(6 + 52 / n);

            n--;
            uint z = v[n], y = v[0];
            uint mx, e, sum = q * DELTA;
            uint p = 0;

            while (sum != 0)
            {
                e = sum >> 2 & 3;

                for (p = n; p > 0; p--)
                {
                    z = v[p - 1];
                    mx = (z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);
                    y = v[p] -= mx;
                }

                z = v[n];
                mx = (z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);
                y = v[0] -= mx;

                sum -= DELTA;
            }

            return StrConvert.LongsToStr(v);
        }

        public static string Encrypt(string plainText, string teaKey, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(plainText)) return null;
            if (string.IsNullOrEmpty(teaKey)) return null;
            if (encoding == null) encoding = Encoding.UTF8;

            byte[] x = Encoding.UTF8.GetBytes(plainText);
            uint[] v = StrConvert.StrToLongs(x, 0, 0);
            // simply convert first 16 chars of password as key
            x = encoding.GetBytes(teaKey);
            uint[] k = StrConvert.StrToLongs(x, 0, 16);

            byte[] encryptText = EncryptBlock(v, k);

            return Convert.ToBase64String(encryptText);
        }

        public static string Decrypt(string cipherText, string teaKey, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(cipherText)) return null;
            if (string.IsNullOrEmpty(teaKey)) return null;
            if (encoding == null) encoding = Encoding.UTF8;

            byte[] x = Convert.FromBase64String(cipherText);
            uint[] v = StrConvert.StrToLongs(x, 0, 0);
            // simply convert first 16 chars of password as key
            x = encoding.GetBytes(teaKey);
            uint[] k = StrConvert.StrToLongs(x, 0, 16);

            byte[] decryptText = DecryptBlock(v, k);

            return encoding.GetString(decryptText);
        }

        public TeaCore(string teaKey)
        {
            SetTeaKey(teaKey);
        }

        public string GetTeaKey()
        {
            return teakey;
        }

        public void SetTeaKey(string teaKey)
        {
            this.teakey = teaKey;
            byte[] x = Encoding.UTF8.GetBytes(teaKey);
            this.teakeyArr = StrConvert.StrToLongs(x, 0, 16);
        }

        public string Encrypt(string plainText)
        {
            if (String.IsNullOrEmpty(plainText)) return null;

            byte[] x = Encoding.UTF8.GetBytes(plainText);
            uint[] v = StrConvert.StrToLongs(x, 0, 0);

            return Convert.ToBase64String(EncryptBlock(v, teakeyArr));
        }

        public string Decrypt(string cipherText)
        {
            if (String.IsNullOrEmpty(cipherText)) return null;

            byte[] x = Convert.FromBase64String(cipherText);
            uint[] v = StrConvert.StrToLongs(x, 0, 0);

            return Encoding.UTF8.GetString(DecryptBlock(v, teakeyArr));
        }

        public sealed class StrConvert
        {
            public static byte HexToByte(char ch)
            {
                if (ch >= '0' && ch <= '9')
                    return (byte)(ch - '0');
                else if (ch >= 'a' && ch <= 'f')
                    return (byte)(ch - 'a' + 10);
                else if (ch >= 'A' && ch <= 'F')
                    return (byte)(ch - 'A' + 10);
                return 0;
            }

            public static byte HexToByte(char hch, char lch)
            {
                return (byte)(HexToByte(hch) << 4 | HexToByte(lch));
            }

            public static byte[] HexToByteArray(string hexString)
            {
                int byteLen = hexString.Length / 2;
                int modLen = hexString.Length % 2;
                byte[] retval = new byte[byteLen + modLen];
                char[] srcChars = hexString.ToCharArray();
                if (modLen > 0)
                    retval[0] = HexToByte(srcChars[0]);
                for (int i = 0; i < byteLen; i++)
                    retval[modLen + i] = HexToByte(srcChars[modLen + i * 2], srcChars[modLen + i * 2 + 1]);
                return retval;
            }

            public static string ByteArrayToHex(byte[] byteArray)
            {
                StringBuilder sb = new StringBuilder(byteArray.Length * 2);
                const string HexLit = "0123456789abcdef";

                foreach (byte b in byteArray)
                {
                    sb.Append(HexLit[(int)(b >> 4)]);
                    sb.Append(HexLit[(int)(b & 0xF)]);
                }

                return sb.ToString();
            }

            public static uint[] StrToLongs(byte[] s, int startIdx, int length)
            {
                if (length <= 0) length = s.Length;

                int fs = length / 4;
                int ls = length % 4;
                uint[] l = new uint[fs + ((ls > 0) ? 1 : 0)];
                int idx = startIdx;
                for (var i = 0; i < fs; i++)
                {
                    l[i] = (uint)s[idx++] |
                          ((uint)s[idx++] << 8) |
                          ((uint)s[idx++] << 16) |
                          ((uint)s[idx++] << 24);
                }
                if (ls > 0)
                {
                    // note running off the end of the string generates nulls since 
                    // bitwise operators treat NaN as 0
                    byte[] v = new byte[4] { 0, 0, 0, 0 };
                    for (var i = 0; i < ls; i++)
                    {
                        v[i] = s[fs * 4 + i];
                    }
                    l[fs] = BitConverter.ToUInt32(v, 0);
                }

                return l;
            }

            public static byte[] LongsToStr(uint[] l)
            {
                byte[] a = new byte[l.Length * 4];

                int idx = 0;
                for (var i = 0; i < l.Length; i++)
                {
                    a[idx++] = (byte)(l[i] & 0xFF);
                    a[idx++] = (byte)(l[i] >> 8 & 0xFF);
                    a[idx++] = (byte)(l[i] >> 16 & 0xFF);
                    a[idx++] = (byte)(l[i] >> 24 & 0xFF);
                }

                return a;
            }

        }
    }
}
