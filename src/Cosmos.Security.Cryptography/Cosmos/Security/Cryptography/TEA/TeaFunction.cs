using System;
using System.Text;
using System.Threading;
using Cosmos.Security.Cryptography.Core;
using Cosmos.Security.Cryptography.Core.SymmetricAlgorithmImpls;
using Cosmos.Security.Encryption.Core;

// ReSharper disable InconsistentNaming
// ReSharper disable CheckNamespace

namespace Cosmos.Security.Cryptography
{
    internal class TEAFunction : SymmetricCryptoFunction<TeaKey>, ITEA
    {
        private const uint DELTA = 0x9E3779B9;

        public TEAFunction(TeaKey key)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
        }

        public override TeaKey Key { get; }

        public override int KeySize => Key.Size;

        protected override ICryptoValue EncryptInternal(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var data = GetBytes(originalBytes);
            if (data.Length == 0)
                return CreateCryptoValue(data, data, CryptoMode.Encrypt);

            var v = StrConvert.StrToLongs(data, 0, 0);
            var k = StrConvert.StrToLongs(Key.GetKey(), 0, 16);

            var cipher = EncryptBlock(v, k);
            return CreateCryptoValue(data, cipher, CryptoMode.Encrypt);
        }

        protected override ICryptoValue DecryptInternal(ArraySegment<byte> cipherBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var cipher = GetBytes(cipherBytes);
            if (cipher.Length == 0)
                return CreateCryptoValue(cipher, cipher, CryptoMode.Decrypt);
            var v = StrConvert.StrToLongs(cipher, 0, 0);
            var k = StrConvert.StrToLongs(Key.GetKey(), 0, 16);

            var original = DecryptBlock(v, k);
            return CreateCryptoValue(original, cipher, CryptoMode.Decrypt,o=>o.TrimTerminatorWhenDecrypting=true);
        }

        private static byte[] EncryptBlock(uint[] v, uint[] k)
        {
            if (v == null || k == null) return null;

            int n = v.Length;
            if (n == 0) return null;
            if (n <= 1) return new byte[] {0}; // algorithm doesn't work for n<2 so fudge by adding a null

            uint q = (uint) (6 + 52 / n);

            n--;
            uint z = v[n], y = v[0];
            uint mx, e, sum = 0;

            while (q-- > 0)
            {
                // 6 + 52/n operations gives between 6 & 32 mixes on each word
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

        private static byte[] DecryptBlock(uint[] v, uint[] k)
        {
            if (v == null || k == null) return null;

            uint n = (uint) v.Length;
            if (n == 0) return null;
            if (n <= 1) return new byte[1] {0}; // algorithm doesn't work for n<2 so fudge by adding a null

            uint q = (uint) (6 + 52 / n);

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

        private sealed class StrConvert
        {
            public static byte HexToByte(char ch)
            {
                if (ch >= '0' && ch <= '9')
                    return (byte) (ch - '0');
                else if (ch >= 'a' && ch <= 'f')
                    return (byte) (ch - 'a' + 10);
                else if (ch >= 'A' && ch <= 'F')
                    return (byte) (ch - 'A' + 10);
                return 0;
            }

            public static byte HexToByte(char hch, char lch)
            {
                return (byte) (HexToByte(hch) << 4 | HexToByte(lch));
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
                var sb = new StringBuilder(byteArray.Length * 2);
                const string HexLit = "0123456789abcdef";

                foreach (byte b in byteArray)
                {
                    sb.Append(HexLit[(int) (b >> 4)]);
                    sb.Append(HexLit[(int) (b & 0xF)]);
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

            public static byte[] LongsToStr(uint[] l)
            {
                byte[] a = new byte[l.Length * 4];

                int idx = 0;
                for (var i = 0; i < l.Length; i++)
                {
                    a[idx++] = (byte) (l[i] & 0xFF);
                    a[idx++] = (byte) (l[i] >> 8 & 0xFF);
                    a[idx++] = (byte) (l[i] >> 16 & 0xFF);
                    a[idx++] = (byte) (l[i] >> 24 & 0xFF);
                }

                return a;
            }
        }
    }
}